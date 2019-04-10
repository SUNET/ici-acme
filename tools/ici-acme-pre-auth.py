#!/usr/bin/env python3

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

from OpenSSL import crypto as openssl_crypto
import jose
import jose.constants
from jose import jwt, jwk, jws


logger = logging.getLogger()

_defaults = {
    'syslog': False,
    'debug': False,
    'mode': 'renew',
    'url': 'http://localhost:8000/ici-acme-preauth',
}

# _ALG = 'P11TOKEN'
_ALG = 'RS256'


def parse_args(defaults: Mapping):
    parser = argparse.ArgumentParser(description='ICI ACME pre-auth client',
                                     add_help=True,
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter,
                                     )

    # Positional arguments
    # Optional arguments
    parser.add_argument('--dehydrated_account_dir',
                        dest='dehydrated_account_dir',
                        type=str, required=True,
                        help='Account directory',
                        )
    parser.add_argument('--mode',
                        dest='mode',
                        type=str, default=defaults['mode'],
                        help='Pre auth mode',
                        )
    parser.add_argument('--cert',
                        dest='existing_cert',
                        type=str, required=False,
                        help='Path to existing certificate',
                        )
    parser.add_argument('--key',
                        dest='private_key',
                        type=str, required=False,
                        help='Path to existing private key',
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


def iciclient_sign(data, key=None, headers=None):
    orig_key = jwk.get_key(_ALG)
    try:
        jwk.register_key(_ALG, P11Key)
        res = jws.sign(data, key, algorithm=_ALG, headers=headers)
    except:
        raise
    finally:
        jwk.register_key(_ALG, orig_key)
    return res


def iciclient_verify(token, pem):
    # key = jwk.construct(pem, jwk.ALGORITHMS.RS256)
    key = pem
    return jws.verify(token, key, algorithms=[jwk.ALGORITHMS.RS256])


def load_private_key(path: str):
    try:
        with open(path, 'r') as fd:
            return jwk.construct(fd.read(), jose.constants.ALGORITHMS.RS256)
    except TypeError as e:
        logger.error(f'Could not load key from {path}')
        logger.error(e)
        sys.exit(1)


def load_pem(path: str):
    try:
        with open(path, 'rb') as fd:
            return openssl_crypto.load_certificate(openssl_crypto.FILETYPE_PEM, fd.read())
    except TypeError as e:
        logger.error(f'Could not load certificate from {path}')
        logger.error(e)
        sys.exit(1)


def dehydrated_account_sign(data: dict, dehydrated_account_dir: str):
    key = load_private_key(os.path.join(dehydrated_account_dir, 'account_key.pem'))
    with open(os.path.join(dehydrated_account_dir, 'registration_info.json'), 'r') as fd:
        reg_info = json.loads(fd.read())
    headers = {'kid': str(reg_info['id'])}
    token = jwt.encode(data, key.to_dict(), headers=headers, algorithm=jose.constants.ALGORITHMS.RS256)
    return token


def create_renew_pre_auth(existing_certificate_path: str, existing_key_path: str):

    existing_certificate = load_pem(existing_certificate_path)
    certificate = b64encode(openssl_crypto.dump_certificate(
        openssl_crypto.FILETYPE_ASN1, existing_certificate)).decode('utf-8')

    headers = {'x5c': [certificate]}
    payload = {'exp': str(datetime.datetime.utcnow() + datetime.timedelta(seconds=300))}

    key = load_private_key(existing_key_path)
    data = {'renew': jwt.encode(payload, key.to_dict(), headers=headers, algorithm=jose.constants.ALGORITHMS.RS256)}
    return data


def post_pre_auth(dehydrated_path: str, url: str, data: dict):

    signed = dehydrated_account_sign(data, dehydrated_path)
    logger.debug(f'Signed data: {signed}')

    _elem = signed.split('.')
    req_data = {'protected': _elem[0],
                'payload': _elem[1],
                'signature': _elem[2],
                }

    r = requests.post(url, json=req_data)
    logger.debug('Response from server: {}\n{}\n'.format(r, r.text))
    return True


def main():
    try:
        # initialize various components
        progname = os.path.basename(sys.argv[0])
        args = parse_args(_defaults)
        _config_logger(args, progname)
        res = False
        if args.mode == 'renew':
            pre_auth = create_renew_pre_auth(args.existing_cert, args.private_key)
            res = post_pre_auth(args.dehydrated_account_dir, args.url, pre_auth)

        if res is True:
            sys.exit(0)
        if res is False:
            sys.exit(1)
        sys.exit(int(res))
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == '__main__':
    main()
