#!/usr/bin/env python3
#
# Get a new certificate or renew existing one from an ICI ACME server.
#
# NOTE: This script uses a different JOSE implementation because this one
#       (josepy) is available as a Debian package (python3-josepy), and
#       this script has to run on every host that needs a certificate.
#       We don't run josepy everywhere since it does not currently support
#       signing tokens with ECDSA keys.
#

import os
import sys
import json
import argparse
import requests
import datetime

import logging
import logging.handlers

from base64 import b64encode
from typing import Mapping

import yaml
from OpenSSL import crypto as openssl_crypto
import josepy as jose

logger = logging.getLogger()

_defaults = {
    'syslog': False,
    'debug': False,
    'mode': 'renew',
    'url': 'http://localhost:8000/',
}


def parse_args(defaults: Mapping):
    parser = argparse.ArgumentParser(description='ICI ACME pre-auth client',
                                     add_help=True,
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter,
                                     )

    parser.add_argument('--debug',
                        dest='debug',
                        action='store_true', default=defaults['debug'],
                        help='Enable debug operation',
                        )
    parser.add_argument('--syslog',
                        dest='syslog',
                        action='store_true', default=defaults['syslog'],
                        help='Enable syslog output',
                        )
    parser.add_argument('--url',
                        dest='url',
                        type=str, default=defaults['url'],
                        help='API URL',
                        )

    parser.add_argument('--dehydrated_account_dir',
                        dest='dehydrated_account_dir',
                        type=str, required=True,
                        help='Account directory',
                        )
    #parser.add_argument('--mode',
    #                    dest='mode',
    #                    type=str, default=defaults['mode'],
    #                    help='Pre auth mode',
    #                    )

    subparsers = parser.add_subparsers(help='sub-commands')

    renew = subparsers.add_parser('renew', help='Renew a still valid certificate')
    renew.set_defaults(mode='renew')

    renew.add_argument('--cert',
                       dest='existing_cert',
                       type=str, required=False,
                       help='Path to existing certificate',
                       )
    renew.add_argument('--key',
                       dest='private_key',
                       type=str, required=False,
                       help='Path to existing private key',
                       )

    init = subparsers.add_parser('init', help='Request a new certificate')
    init.set_defaults(mode='init')
    init.add_argument('--token_file',
                      dest='token_file',
                      type=str, required=True, metavar='YAMLFILE',
                      help='Path to file with an ICI ACME pre-auth token (generated with ici-preauth-token.py)',
                      )

    args = parser.parse_args()
    return args


def _config_logger(args: argparse.Namespace, progname: str):
    # This is the root log level
    level = logging.INFO
    if args.debug:
        level = logging.DEBUG
    logging.basicConfig(level=level, stream=sys.stderr,
                        format='%(asctime)s: %(name)s: %(levelname)s %(message)s')
    logger.name = progname
    # If stderr is not a TTY, change the log level of the StreamHandler (stream = sys.stderr above) to WARNING
    if not sys.stderr.isatty() and not args.debug:
        for this_h in logging.getLogger('').handlers:
            this_h.setLevel(logging.WARNING)
    if args.syslog:
        syslog_h = logging.handlers.SysLogHandler()
        formatter = logging.Formatter('%(name)s: %(levelname)s %(message)s')
        syslog_h.setFormatter(formatter)
        logger.addHandler(syslog_h)


def load_private_key(path: str) -> jose.JWK:
    try:
        with open(path, 'rb') as fd:
            pem = fd.read(1024 * 1024)
            logger.info('PEM IS {!r}'.format(pem))
            return jose.JWK.load(pem)
            #if 'BEGIN EC' in pem:
            #    # TODO: need to parse the key to see if it is ES256 or some other curve
            #    return jwk.construct(pem, jose.constants.ALGORITHMS.ES256)
            #else:
            #    return jwk.construct(pem, jose.constants.ALGORITHMS.RS256)
    except TypeError:
        logger.exception(f'Could not load key from {path}')
        sys.exit(1)


def load_pem(path: str):
    try:
        with open(path, 'rb') as fd:
            return openssl_crypto.load_certificate(openssl_crypto.FILETYPE_PEM, fd.read())
    except TypeError:
        logger.exception(f'Could not load certificate from {path}')
        sys.exit(1)


class AcmeHeader(jose.jws.Header):
    url = jose.json_util.Field('url', omitempty=True)
    nonce = jose.json_util.Field('nonce', omitempty=True)


def dehydrated_account_sign(data: str, dehydrated_account_dir: str, directory: Mapping) -> jose.JWS:
    key = load_private_key(os.path.join(dehydrated_account_dir, 'account_key.pem'))
    with open(os.path.join(dehydrated_account_dir, 'registration_info.json'), 'r') as fd:
        reg_info = json.loads(fd.read())
    logger.debug(f'ACME account: {reg_info.get("id")}')
    headers = {'kid': str(reg_info['id']),
               'url': directory['newAuthz'],
               'nonce': get_acme_nonce(directory),
               }
    # because of bugs in the jose implementation in used, we must wrap the token in a Mapping
    # and use jwt.encode instead of just calling jws.sign(data, ...)
    claims = {'token': data}
    #_key = key.to_dict()
    #token = jwt.encode(claims, _key, headers=headers, algorithm=_key['alg'])
    jose.jws.Signature.header_cls = AcmeHeader
    token = jose.JWS.sign(payload=json.dumps(claims).encode(), key=key, alg=jose.RS256, include_jwk=False,
                          protect={'alg', 'url', 'nonce', 'kid'},
                          **headers)
    return token


def create_renew_pre_auth(directory: Mapping, args: argparse.Namespace) -> str:
    existing_certificate = load_pem(args.existing_cert)
    certificate = b64encode(openssl_crypto.dump_certificate(
        openssl_crypto.FILETYPE_ASN1, existing_certificate)).decode('utf-8')

    headers = {'x5c': [certificate],  # chain, one cert per element
               }

    key = load_private_key(args.private_key)
    _key = key.to_dict()

    now = datetime.datetime.utcnow()
    claims = {'renew': True,
              'exp': now + datetime.timedelta(seconds=300),
              'iat': datetime.datetime.utcnow(),
              'aud': directory['newAuthz'],
              'crit': ['exp'],
              }
    # token = jwt.encode(claims, _key, headers=headers, algorithm=_key['alg'])
    token = jose.JWS.sign(payload=claims, headers=headers, key=key, alg=jose.RS256)
    return token


def post_pre_auth(token: str, directory: Mapping, args: argparse.Namespace) -> bool:
    signed = dehydrated_account_sign(token, args.dehydrated_account_dir, directory)
    logger.debug(f'Signed data: {signed}')

    _elem = signed.to_compact().decode('utf-8').split('.')
    req_data = {'protected': _elem[0],
                'payload': _elem[1],
                'signature': _elem[2],
                }
    headers = {'content-type': 'application/jose+json'}

    r = requests.post(directory['newAuthz'], json=req_data, headers=headers)
    logger.debug('Response from server: {}\n{}\n'.format(r, r.text))
    if r.status_code != 201:
        logger.error(f'Error response from server (endpoint {directory["newAuthz"]}):\n{r} {r.text}')
        return False
    return True


def get_acme_directory(url: str) -> dict:
    r = requests.get(url)
    logger.debug(f'Fetched ACME directory from {url}: {r}')
    directory = r.json()
    if 'newNonce' not in directory:
        raise RuntimeError(f'No newNonce endpoint returned from ACME server at {url}')
    return r.json()


def get_acme_nonce(directory: Mapping) -> str:
    url = directory['newNonce']
    r = requests.head(url)
    nonce = r.headers.get('replay-nonce')
    if not nonce:
        raise RuntimeError(f'No nonce returned from newNonce endpoint at {url}')
    return nonce


def main():
    try:
        # initialize various components
        progname = os.path.basename(sys.argv[0])
        args = parse_args(_defaults)
        _config_logger(args, progname)
        directory = get_acme_directory(args.url)
        if args.mode == 'renew':
            token = create_renew_pre_auth(directory, args)
        elif args.mode == 'init':
            with open(args.token_file, 'r') as fd:
                data = yaml.safe_load(fd)
                token = data['token']
        res = post_pre_auth(token, directory, args)

        if res is True:
            sys.exit(0)
        if res is False:
            sys.exit(1)
        sys.exit(int(res))
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == '__main__':
    main()
