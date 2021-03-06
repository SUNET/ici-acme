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
# NOTE: This script should work with Python 3.5 for now, since 3.7 is not
#       available on e.g. Ubuntu 16.04.
#
import argparse
import base64
import datetime
import json
import logging
import logging.handlers
import os
import sys
from typing import Mapping, NewType, Optional

import OpenSSL
import josepy as jose
import requests
import yaml
from OpenSSL import crypto as openssl_crypto
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from josepy import JWASignature

logger = logging.getLogger()

_defaults = {
    'syslog': False,
    'debug': False,
    'mode': 'renew',
    'url': 'http://localhost:8000/',
}


Endpoints = NewType('EndPoints', dict)


#### BEGIN python-josepy EXTRAS
#
# All this code is here to overcome current shortcoming in python-josepy (v 1.1.0).
#
class AcmeHeader(jose.jws.Header):
    """Class to get extra headers into the JWT."""

    url = jose.json_util.Field('url', omitempty=True)
    nonce = jose.json_util.Field('nonce', omitempty=True)

    x5c = jose.json_util.Field('x5c', omitempty=True, default=())

    # The Header x5c encoder has an encoding bug in Python3. It returns bytes,
    # but then the JSON encoder fails saying it can't serialize bytes. This
    # is a copy of that function with ".decode('utf-8')" added.
    @x5c.encoder  # type: ignore
    def x5c(value):  # pylint: disable=missing-docstring,no-self-argument
        return [base64.b64encode(OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_ASN1, cert.wrapped)).decode('utf-8') for cert in value]


class ICI_ESKey(object):
    """Holder for an EC private key"""

    def __init__(self, pkey: OpenSSL.crypto.PKey):
        self.key = pkey


class ICI_JWAES(JWASignature):
    """ECDSA signing for josepy"""

    kty = ICI_ESKey

    def sign(self, key: OpenSSL.crypto.PKey, msg) -> bytes:
        logger.debug('EC SIGN {!r}'.format(msg))
        sig = openssl_crypto.sign(key, msg, 'sha256')
        r, s = decode_dss_signature(sig)
        return r.to_bytes(length = 256 // 8, byteorder='big') + \
               s.to_bytes(length = 256 // 8, byteorder='big')

    def verify(self, key, msg, sig):  # pragma: no cover
        raise NotImplementedError()


# Register our ES256 implementation
ICI_ES256 = JWASignature.register(ICI_JWAES('ES256'))


#### END python-josepy EXTRAS


def parse_args(defaults: Mapping, args=None):
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

    parser.set_defaults(mode=None)

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

    is_registered = subparsers.add_parser('is_registered',
                                          help='Check if a dehydrated account for the given URL exists')
    is_registered.set_defaults(mode='is_registered')

    args = parser.parse_args(args=args)
    if not args.mode:
        parser.print_help()

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


class DehydratedInfo(object):
    """Dehydrated account information."""

    def __init__(self, path: str, url_hint: str):
        self.path = path

        # Private key loaded on demand
        self._private_key = None  # type: Optional[jose.JWK]
        self.alg = None

        # Registration info from current dehydrated example:
        #   {"id": 1556180297, "status": "valid", "orders": "http://localhost:8000/accounts/1556180297/orders"}
        with open(os.path.join(path, 'registration_info.json'), 'r') as fd:
            self.reg_info = json.loads(fd.read())

        # This is really backwards, but since dehydrated doesn't save the URL to the
        # directory in the registration info, we need to assume it from the url_hint
        # if it matches, and otherwise leave it as None
        self.url = None
        if url_hint[-1] != '/':
            url_hint += '/'
        if 'orders' in self.reg_info:
            if self.reg_info['orders'].startswith(url_hint):
                self.url = url_hint

    @property
    def kid(self) -> Optional[str]:
        if 'id' in self.reg_info:
            return str(self.reg_info['id'])

    @property
    def private_key(self) -> Optional[jose.JWK]:
        if self._private_key is None:
            key_fn = os.path.join(self.path, 'account_key.pem')
            alg, key = load_private_key(key_fn)
            self.alg = alg
            self._private_key = key
        return self._private_key


def load_dehydrated_info(args: argparse.Namespace) -> Optional[DehydratedInfo]:
    """Locate a dehydrated account matching the specified URL, and return it's private key."""
    for this in os.listdir(args.dehydrated_account_dir):
        candidate = os.path.join(args.dehydrated_account_dir, this)
        if not os.path.isdir(candidate):
            continue
        logger.debug('Loading dehydrated info from directory'.format(candidate))
        info = DehydratedInfo(candidate, args.url)
        if info.url is not None:
            return info
        logger.debug('Account in directory {} is for another URL: {}'.format(candidate, info.url))
    logger.error('Could not find a dehydrated account for the specified URL ({}) in {}'.format(
        args.url, args.dehydrated_account_dir))


def load_pem(path: str):
    try:
        with open(path, 'rb') as fd:
            return openssl_crypto.load_certificate(openssl_crypto.FILETYPE_PEM, fd.read())
    except TypeError:
        logger.exception('Could not load certificate from {}'.format(path))
        sys.exit(1)


def load_private_key(path: str):
    try:
        with open(path, 'rb') as fd:
            pem = fd.read()
        if b'BEGIN RSA PRIVATE KEY' in pem:
            alg = jose.RS256
            key = jose.JWK.load(pem)  # type information is wrong for load(), it _needs_ bytes
        elif b'BEGIN EC PRIVATE KEY' in pem:
            alg = ICI_ES256
            _pkey = openssl_crypto.load_privatekey(openssl_crypto.FILETYPE_PEM, pem)
            key = ICI_ESKey(_pkey)
        else:
            raise RuntimeError('Failed loading {}: josepy only supports RSA keys'.format(path))
        logger.debug('Loaded private key ({}) from {}'.format(alg, path))
        return alg, key
    except TypeError:
        logger.exception('Could not load private key from {}'.format(path))
        sys.exit(1)


def dehydrated_account_sign(data: str, endpoints: Endpoints, args: argparse.Namespace, nonce=None) -> jose.JWS:
    info = load_dehydrated_info(args)
    if not info:
        sys.exit(1)

    if nonce is None:
        nonce = get_acme_nonce(endpoints)
    logger.debug('ACME account: {}'.format(info.kid))
    headers = {'kid': info.kid,
               'url': endpoints['newAuthz'],
               'nonce': nonce,
               }
    # because of bugs in the jose implementation used on the server side, we must wrap the token in a Mapping
    # and use jwt.encode instead of just calling jws.sign(data, ...)
    claims = {'token': data}
    jose.jws.Signature.header_cls = AcmeHeader
    token = jose.JWS.sign(payload=json.dumps(claims).encode(),
                          key=info.private_key, alg=info.alg, include_jwk=False,
                          protect={'alg', 'url', 'nonce', 'kid'},
                          **headers)
    return token


def create_renew_pre_auth(directory: Mapping, args: argparse.Namespace, expires=300) -> str:
    existing_certificate = load_pem(args.existing_cert)
    certificate = jose.util.ComparableX509(existing_certificate)

    headers = {'x5c': [certificate],  # chain, one cert per element
               }

    alg, private_key = load_private_key(args.private_key)

    logger.debug('Signing renew token with {} private key from {}'.format(alg, args.private_key))
    now = datetime.datetime.utcnow()
    claims = {'renew': True,
              'exp': (now + datetime.timedelta(seconds=expires)).timestamp(),
              'iat': datetime.datetime.utcnow().timestamp(),
              'aud': directory['newAuthz'],
              'crit': ['exp'],
              }
    jose.jws.Signature.header_cls = AcmeHeader
    token = jose.JWS.sign(payload=json.dumps(claims).encode(),
                          key=private_key, alg=alg, include_jwk=False,
                          protect={'alg', 'x5c'},
                          **headers)
    return token.to_compact().decode('utf-8')


def post_pre_auth(token: str, endpoints: Endpoints, args: argparse.Namespace) -> bool:
    signed = dehydrated_account_sign(token, endpoints, args)
    logger.debug('Signed data: {}\n'.format(signed))

    _elem = signed.to_compact().decode('utf-8').split('.')
    req_data = {'protected': _elem[0],
                'payload': _elem[1],
                'signature': _elem[2],
                }
    headers = {'content-type': 'application/jose+json'}

    r = requests.post(endpoints['newAuthz'], json=req_data, headers=headers)
    logger.debug('Response from server: {}\n{}\n'.format(r, r.text))
    if r.status_code != 201:
        logger.error('Error response from server (endpoint {}):\n{} {}'.format(endpoints["newAuthz"], r, r.text))
        return False
    logger.info('Pre-authenticated with endpoint {}: {} {}'.format(endpoints["newAuthz"], r, r.text))
    return True


def get_acme_endpoints(url: str) -> Endpoints:
    r = requests.get(url)
    logger.debug('Fetched ACME directory from {}: {}'.format(url, r))
    directory = r.json()
    if 'newNonce' not in directory:
        raise RuntimeError('No newNonce endpoint returned from ACME server at {}'.format(url))
    return r.json()


def get_acme_nonce(endpoints: Endpoints) -> str:
    url = endpoints['newNonce']
    r = requests.head(url)
    nonce = r.headers.get('replay-nonce')
    if not nonce:
        raise RuntimeError('No nonce returned from newNonce endpoint at {}'.format(url))
    return nonce


def main():
    try:
        # initialize various components
        res = False
        progname = os.path.basename(sys.argv[0])
        args = parse_args(_defaults)
        _config_logger(args, progname)
        directory = get_acme_endpoints(args.url)
        if args.mode == 'is_registered':
            info = load_dehydrated_info(args)
            if info and info.url is not None:
                # TODO: Verify account using newAccount with onlyReturnExisting=True.
                logger.debug('Dehydrated account for URL {} found'.format(info.url))
                res = True
        elif args.mode in ['renew', 'init']:
            if args.mode == 'renew':
                token = create_renew_pre_auth(directory, args)
            else:
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
