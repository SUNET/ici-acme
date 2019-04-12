#!/usr/bin/env python3
import argparse
import binascii
import hashlib
import logging
import logging.handlers
import os
import sys
from base64 import b64encode
from dataclasses import dataclass
from typing import Mapping, Optional

import pkcs11
from pkcs11 import Attribute, ObjectClass, KeyType
from OpenSSL import crypto
from jose import jwk, jws


@dataclass
class P11Params(object):
    module: str
    pin: Optional[str]
    token_label: Optional[str]
    label: str


# This global variable (sigh) will be filled with values after argument parsing.
# The P11Key class makes use of these values in the global variable (sigh) when
# the JOSE library instantiates them.
P11Key_params = P11Params(module='', pin=None, token_label=None, label='')


class P11Key(jwk.Key):

    def __init__(self, key, algorithm, p11: P11Params = P11Key_params):
        super().__init__(key, algorithm)
        #self._key = key
        self._algorithm = algorithm
        self._public_key = None
        self._private_key = None
        self._mechanism = None
        self.p11 = p11

        self.lib = pkcs11.lib(self.p11.module)
        self.token = self.lib.get_token(token_label=self.p11.token_label)

        logger.debug('Loaded module {} (key {}, alg {})'.format(self.lib, key, algorithm))

    def _load_key(self, session) -> None:
        if self._public_key is not None and self._private_key is not None:
            return
        #key = session.get_key(label=self.p11.label, key_type=pkcs11.ObjectClass.PRIVATE_KEY)
        attrs = {Attribute.KEY_TYPE: ObjectClass.PRIVATE_KEY,
                 Attribute.LABEL: self.p11.label,
                 }
        # SoftHSM2 returns both private and public keys
        for this in session.get_objects(attrs):
            if this.object_class == ObjectClass.PUBLIC_KEY:
                self._public_key = this
                p = this[Attribute.EC_POINT]
                logger.debug(f'Loaded EC_POINT {binascii.hexlify(p)}')
            elif this.object_class == ObjectClass.PRIVATE_KEY:
                self._private_key = this
            if this.key_type == KeyType.EC:
                # SoftHSM2 does not seem to support CKM_ECDSA_SHA256
                self._mechanism = pkcs11.Mechanism.ECDSA
                if this.object_class != ObjectClass.PUBLIC_KEY:
                    continue
            elif this.key_type == KeyType.RSA:
                self._mechanism = pkcs11.Mechanism.SHA256_RSA_PKCS_PSS

    def sign(self, msg: bytes) -> bytes:
        with self.token.open(user_pin=self.p11.pin) as session:
            self._load_key(session)
            logger.debug(f'Signing data: {msg}')
            if self._mechanism == pkcs11.Mechanism.ECDSA:
                msg = hashlib.sha256(msg).digest()
                logger.debug(f'SHA-256 hashed into new data: {binascii.hexlify(msg)}')
            signature = self._private_key.sign(msg, mechanism=self._mechanism)
            logger.debug(f'Signature: {binascii.hexlify(signature)}')
        return signature

    def verify(self, msg: bytes, sig: bytes) -> bool:
        with self.token.open(user_pin=self.p11.pin) as session:
            self._load_key(session)

            logger.debug(f'Verifying signature, data: {msg}')
            logger.debug(f'Signature: {binascii.hexlify(sig)}')
            if self._mechanism == pkcs11.Mechanism.ECDSA:
                msg = hashlib.sha256(msg).digest()
                logger.debug(f'SHA-256 hashed into new data: {binascii.hexlify(msg)}')

            if not self._public_key.verify(msg, sig, mechanism=self._mechanism):
                raise RuntimeError('Signature failed validation')
        return True

    def get_jwk_alg(self) -> str:
        with self.token.open(user_pin=self.p11.pin) as session:
            self._load_key(session)

            if self._public_key.key_type == KeyType.RSA:
                return 'RS256'
            elif self._public_key.key_type == KeyType.EC:
                return 'ES256'


_defaults = {'debug': False,
             'module': '/usr/lib/softhsm/libsofthsm2.so',
             }


def parse_args(defaults: Mapping):
    parser = argparse.ArgumentParser(description='ICI ACME pre-auth token generator',
                                     add_help=True,
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # Positional arguments
    parser.add_argument('names',
                        metavar='FQDN',
                        help='Names to put in token',
    )

    # Required arguments
    parser.add_argument('--cert',
                        dest='cert',
                        type=str, required=True,
                        help='Certificate to sign token with',
    )
    parser.add_argument('--label',
                        dest='label',
                        type=str, required=True,
                        help='PKCS#11 CKA_LABEL of key to use to sign token',
    )

    # Optional arguments
    parser.add_argument('--debug',
                        dest='debug',
                        action='store_true', default=defaults['debug'],
                        help='Enable debug operation',
    )
    parser.add_argument('--module',
                        dest='module',
                        type=str, default=defaults['module'],
                        help='PKCS#11 module',
    )
    parser.add_argument('--token-label',
                        dest='token',
                        type=str,
                        help='PKCS#11 token label where the key resides',
    )
    parser.add_argument('--pin',
                        dest='pin',
                        type=str,
                        help='PKCS#11 user-pin to access key',
    )

    args = parser.parse_args()
    global P11Key_params
    P11Key_params.module = args.module
    P11Key_params.token_label = args.token
    P11Key_params.label = args.label
    P11Key_params.pin = args.pin

    return args


def main(args: argparse.Namespace, logger: logging.Logger):
    with open(args.cert, 'rb') as fd:
        cert_pem = fd.read()

    certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
    headers = {'x5c': [b64encode(crypto.dump_certificate(crypto.FILETYPE_ASN1, certificate)).decode('utf-8')]}
    claims = {'names': args.names,
              'nonce': 'TODO: GET FROM ICI-ACME'
              }
    token = pkcs11_jws_sign(claims, args.label, headers=headers)
    logger.debug(f'JWS: {token}')

    verif = pkcs11_jws_verify(token)
    logger.debug(f'PKCS#11 verification result: {verif}')

    pubkey_pem = crypto.dump_publickey(crypto.FILETYPE_PEM, certificate.get_pubkey())
    verif = jws.verify(token, pubkey_pem.decode('utf-8'), [jwk.ALGORITHMS.ES256, jwk.ALGORITHMS.RS256])
    logger.debug(f'Verification result: {verif}')

    while token:
        print(token[:80])
        token = token[80:]
    return True


def pkcs11_jws_sign(data, key=None, headers=None) -> str:
    """
    Perform JWS Sign with a key stored in an PKCS#11 token.

    This requires some trickery - temporary switch out the key class for the algorithm
    to P11Key before calling jws.sign. It is not possible to just register a new algorithm,
    say ECP11, because the algorithm is included in the JWT and the consumer of the JWT
    would expect ES256 (or similar) and not know how to handle ECP11.

    :return: A signed JWT
    """
    global P11Key_params
    _p11key = P11Key('', '', P11Key_params)
    _alg = _p11key.get_jwk_alg()

    orig_key = jwk.get_key(_alg)
    try:
        jwk.register_key(_alg, P11Key)
        res = jws.sign(data, key, algorithm=_alg, headers=headers)
    except:
        raise
    finally:
        jwk.register_key(_alg, orig_key)
    return res


def pkcs11_jws_verify(token: str) -> str:
    """
    Perform JWS Sign with a key stored in an PKCS#11 token.

    This requires temporarily switching the key class for the algorithm in the token.
    See the documentation for pkcs11_jws_sign for more details.

    :return: The signed payload from the token
    """
    headers = jws.get_unverified_headers(token)
    _alg = headers['alg']
    orig_key = jwk.get_key(_alg)
    try:
        jwk.register_key(_alg, P11Key)
        res = jws.verify(token, '', algorithms=[jwk.ALGORITHMS.ES256, jwk.ALGORITHMS.RS256])
    except:
        raise
    finally:
        jwk.register_key(_alg, orig_key)
    return res



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
