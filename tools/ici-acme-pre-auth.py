#!/usr/bin/env python3

import os
import sys
import json
import argparse
import requests

import logging
import logging.handlers

from base64 import b64encode
from typing import Mapping

import jose
import jose.constants
from jose import jwt, jwk, jws


logger = None

_defaults = {'syslog': False,
             'debug': False,
             'module': '/path/to/p11-module',
             'pubkey_id': 'XXX',
             'cert': '/path/to/cert',
             'url': 'http://localhost:8000/ici-acme-preauth',
             }


def parse_args(defaults: Mapping):
    parser = argparse.ArgumentParser(description = 'ICI ACME pre-auth client',
                                     add_help = True,
                                     formatter_class = argparse.ArgumentDefaultsHelpFormatter,
    )

    # Positional arguments
    # Optional arguments
    parser.add_argument('--dehydrated_account_dir',
                        dest = 'dehydrated_account_dir',
                        type = str, required=True,
                        help = 'Account directory',
    )
    parser.add_argument('--debug',
                        dest = 'debug',
                        action = 'store_true', default = defaults['debug'],
                        help = 'Enable debug operation',
    )
    parser.add_argument('--syslog',
                        dest = 'syslog',
                        action = 'store_true', default = defaults['syslog'],
                        help = 'Enable syslog output',
    )
    parser.add_argument('--module',
                        dest = 'module',
                        type = str, default = defaults['module'],
                        help = 'PKCS#11 module',
    )
    parser.add_argument('--url',
                        dest = 'url',
                        type = str, default = defaults['url'],
                        help = 'API URL',
    )
    args = parser.parse_args()
    return args


def dehydrated_account_sign(data: dict, args: argparse.Namespace, logger: logging.Logger):
    with open(os.path.join(args.dehydrated_account_dir, 'account_key.pem'), 'r') as fd:
        key = jwk.construct(fd.read(), jose.constants.ALGORITHMS.RS256)

    with open(os.path.join(args.dehydrated_account_dir, 'registration_info.json'), 'r') as fd:
        reg_info = json.loads(fd.read())

    headers = {'kid': str(reg_info['id']),
               }
    token = jwt.encode(data, key.to_dict(), headers=headers, algorithm=jose.constants.ALGORITHMS.RS256)
    return token


def main(args: argparse.Namespace, logger: logging.Logger):
    #with open(args.certfile, 'rb') as fd:
    #    pem = fd.read()

    #signed = iciclient.sign({'pubkey': pem.decode('utf-8')}, args.pubkey_id)
    # Pass x5c" (X.509 Certificate Chain) Header Parameter

    #certificate = crypto.load_certificate(crypto.FILETYPE_PEM, pem)
    #headers = {'x5c': [b64encode(crypto.dump_certificate(crypto.FILETYPE_ASN1, certificate)).decode('utf-8')]}
    #signed = iciclient.sign({'csr': args.csr}, args.pubkey_id, headers=headers)
    #logger.debug('JWS: {}'.format(signed))
    data = {'identifier': [{'type': 'dns',
                            'value': 'test.test',
                            }],
            }

    signed = dehydrated_account_sign(data, args, logger)
    logger.debug(f'Signed data: {signed}')

    _elem = signed.split('.')
    req_data = {'protected': _elem[0],
                'payload': _elem[1],
                'signature': _elem[2],
                }
    if args.url:
        r = requests.post(args.url, json=req_data)
        logger.debug('Response from server: {}\n{}\n'.format(r, r.text))

    return True


def _get_logger(args: argparse.Namespace, progname: str) -> logging.Logger:
    # This is the root log level
    level = logging.INFO
    if args.debug:
        level = logging.DEBUG
    logging.basicConfig(level=level, stream=sys.stderr,
                        format='%(asctime)s: %(name)s: %(levelname)s %(message)s')
    logger = logging.getLogger(progname)
    # If stderr is not a TTY, change the log level of the StreamHandler (stream = sys.stderr above) to WARNING
    if not sys.stderr.isatty() and not args.debug:
        for this_h in logging.getLogger('').handlers:
            this_h.setLevel(logging.WARNING)
    if args.syslog:
        syslog_h = logging.handlers.SysLogHandler()
        formatter = logging.Formatter('%(name)s: %(levelname)s %(message)s')
        syslog_h.setFormatter(formatter)
        logger.addHandler(syslog_h)
    return logger


if __name__ == '__main__':
    try:
        # initialize various components
        progname = os.path.basename(sys.argv[0])
        args = parse_args(_defaults)
        logger = _get_logger(args, progname)

        res = main(args, logger)

        if res is True:
            sys.exit(0)
        if res is False:
            sys.exit(1)
        sys.exit(int(res))
    except KeyboardInterrupt:
        sys.exit(0)
