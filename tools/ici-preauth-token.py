#!/usr/bin/env python3
import argparse
import binascii
import datetime
import hashlib
import logging
import logging.handlers
import os
import sys
from base64 import b64encode
from dataclasses import dataclass
from typing import Mapping, Optional

import pkcs11
import requests
import yaml
from pkcs11 import Attribute, ObjectClass, KeyType, UserNotLoggedIn
from OpenSSL import crypto
from jose import jwk, jws, JWSError

_defaults = {'debug': False,
             'module': '/usr/lib/softhsm/libsofthsm2.so',
             'url': 'http://localhost:8000/',
             }


@dataclass
class P11Params(object):
    module: str
    pin: Optional[str]
    token_label: Optional[str]
    label: str
    id: int


# This global variable (sigh) will be filled with values after argument parsing.
# The P11Key class makes use of these values in the global variable (sigh) when
# the JOSE library instantiates them.
P11Key_params = P11Params(module='', pin=None, token_label=None, label='', id=None)


class P11Key(jwk.Key):

    def __init__(self, key, algorithm, p11: P11Params = P11Key_params):
        super().__init__(key, algorithm)
        #self._key = key
        self._algorithm = algorithm
        self._public_key = None
        self._private_key = None
        self._mechanism = None
        self.p11 = p11

        logger.debug(f'Initialising PKCS#11 module: {self.p11.module}')
        self.lib = pkcs11.lib(self.p11.module)
        for _slot in self.lib.get_slots():
            logger.debug(f'Slot: {_slot}')

        logger.debug(f'Looking for token {repr(self.p11.token_label)}')
        self.token = self.lib.get_token(token_label=self.p11.token_label)

        logger.debug(f'Loaded module {self.lib} (key {key}, alg {algorithm})')

    def _load_key(self, session) -> None:
        if self._public_key is not None and self._private_key is not None:
            return

        if self._private_key is None:
            self._load_key2(session, key_type=ObjectClass.PRIVATE_KEY,
                            cka_label=self.p11.label, cka_id=self.p11.id)

        if self._public_key is None:
            self._load_key2(session, key_type=ObjectClass.PUBLIC_KEY,
                            cka_label=self.p11.label, cka_id=self.p11.id)

    def _load_key2(self, session, key_type, cka_label: Optional[str] = None, cka_id: Optional[int] = None):
        #key = session.get_key(label=self.p11.label, key_type=pkcs11.ObjectClass.PRIVATE_KEY)
        attrs = {Attribute.KEY_TYPE: key_type,
                 #Attribute.LABEL: self.p11.label,
                 }
        if cka_label is not None:
            attrs[Attribute.LABEL] = cka_label
        if cka_id is not None:
            attrs[Attribute.ID] = cka_id
        logger.debug(f'Looking for key {attrs} in session {session}')
        # SoftHSM2 returns both private and public keys
        for this in session.get_objects(attrs):
            logger.debug(f'Object: {this}')
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
        assert isinstance(self.token, pkcs11.Token)
        logger.info('Opening session with PIN')
        with self.token.open(user_pin=self.p11.pin) as session:
            logger.info(f'Session: {session}')
            self._load_key(session)

            if not self._private_key:
                raise RuntimeError('Could not load private key')

            logger.debug(f'Signing data: {msg}')
            if self._mechanism == pkcs11.Mechanism.ECDSA:
                msg = hashlib.sha256(msg).digest()
                logger.debug(f'SHA-256 hashed into new data: {binascii.hexlify(msg)}')
            logger.info(f'Signing using private key {self._private_key}')
            try:
                signature = self._private_key.sign(msg, mechanism=self._mechanism)
            except UserNotLoggedIn:
                logger.error("""

                Got UserNotLoggedIn from opensc. You need to add

                    app default {
                        framework pkcs15 {
                                pin_cache_ignore_user_consent = false;
                        }
                    }

                to /etc/opensc/opensc.conf, and not have a too old opensc (works with 0.20.0).
                """)
                return None
            logger.debug(f'Signature: {binascii.hexlify(signature)}')
        return signature

    def verify(self, msg: bytes, sig: bytes) -> bool:
        assert isinstance(self.token, pkcs11.Token)
        with self.token.open(user_pin=self.p11.pin) as session:
            self._load_key(session)

            if not self._public_key:
                raise RuntimeError('Could not load public key')

            logger.debug(f'Verifying signature, data: {msg}')
            logger.debug(f'Signature: {binascii.hexlify(sig)}')
            import pkcs11.util.ec
            logger.debug(f'Encoded signature: {binascii.hexlify(pkcs11.util.ec.encode_ecdsa_signature(sig))}')
            if self._mechanism == pkcs11.Mechanism.ECDSA:
                msg = hashlib.sha256(msg).digest()
                logger.debug(f'SHA-256 hashed into new data: {binascii.hexlify(msg)}')

            logger.debug(f'VERIFY msg {msg} SIG {sig} MECH {self._mechanism}')
            res = self._public_key.verify(msg, sig, mechanism=self._mechanism)
            logger.debug(f'Verify result: {res}')
            if not res:
                raise RuntimeError('Signature failed validation')
        return True

    def get_jwk_alg(self) -> str:
        with self.token.open(user_pin=self.p11.pin) as session:
            self._load_key(session)

            if not self._public_key:
                raise RuntimeError('Could not load public key')

            if self._public_key.key_type == KeyType.RSA:
                return 'RS256'
            elif self._public_key.key_type == KeyType.EC:
                return 'ES256'


def parse_args(defaults: Mapping):
    parser = argparse.ArgumentParser(description='ICI ACME pre-auth token generator',
                                     add_help=True,
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # Positional arguments
    parser.add_argument('names', nargs='+',
                        metavar='FQDN',
                        help='Names to put in token',
    )

    # Required arguments
    parser.add_argument('--cert',
                        dest='cert',
                        type=str, required=True,
                        help='Certificate to sign token with',
    )
    parser.add_argument('--token_label',
                        dest='token',
                        type=str, required=True,
                        help='PKCS#11 token label where the key resides',
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
    parser.add_argument('--pin',
                        dest='pin',
                        type=str,
                        help='PKCS#11 user-pin to access key',
    )
    parser.add_argument('--url',
                        dest='url',
                        type=str, default=defaults['url'],
                        help='ACME server URL (to the directory endpoint)',
    )
    parser.add_argument('--label',
                        dest='cka_label',
                        type=str, default=None,
                        help='PKCS#11 CKA_LABEL of key to use to sign token',
    )
    parser.add_argument('--cka_id',
                        dest='cka_id',
                        type=int, default=None,
                        help='PKCS#11 CKA_ID of key to use to sign token',
    )
    parser.add_argument('--output_file',
                        dest='output_file',
                        type=str, default=None, metavar='YAMLFILE',
                        help='Write generated token to this file',
    )

    args = parser.parse_args()
    global P11Key_params
    P11Key_params.module = args.module
    P11Key_params.token_label = args.token
    P11Key_params.label = args.cka_label
    P11Key_params.id = args.cka_id
    P11Key_params.pin = args.pin

    return args


def main(args: argparse.Namespace, logger: logging.Logger):
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    expire = now + datetime.timedelta(minutes=5)
    directory = get_acme_directory(args.url)

    logger.debug(f'Loading certificate from {args.cert}')
    with open(args.cert, 'rb') as fd:
        cert_pem = fd.read()

    certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
    logger.info(f'Including cert from file {args.cert}')
    logger.info(f'Requestor: {certificate.get_subject()} (serial {hex(certificate.get_serial_number())})')
    headers = {'x5c': [b64encode(crypto.dump_certificate(crypto.FILETYPE_ASN1, certificate)).decode('utf-8')],
               'url': directory['newAuthz'],
               }
    claims = {'names': args.names,
              'nonce': get_acme_nonce(directory),
              'aud': directory['newAuthz'],
              'iat': int(now.timestamp()),
              'exp': int(expire.timestamp()),
              'crit': ['exp'],
              }
    token = pkcs11_jws_sign(claims, args.cka_label, headers=headers)
    if not token:
        return False
    logger.debug(f'JWS: {token}')

    sig_verified = False

    try:
        # Verify token using PKCS#11. This step is not really necessary, but
        # the code seemed like it could be useful sometime somewhere so why not.
        verified = pkcs11_jws_verify(token)
        logger.debug(f'PKCS#11 verification result: {verified}')
        if verified:
            sig_verified = True
            logger.info('Signature validated by token using PKCS#11')
    except Exception:
        logger.exception('FAILED verifying signature using PKCS#11')

    # Verify the token by extracting the public key from the certificate, just like
    # the ICI ACME server this token will be passed to will do. This ensures the
    # certificate provided (in a file) matches the private key used (PKCS#11).
    pubkey_pem = crypto.dump_publickey(crypto.FILETYPE_PEM, certificate.get_pubkey())
    try:
        verified = jws.verify(token, pubkey_pem.decode('utf-8'), [jwk.ALGORITHMS.ES256, jwk.ALGORITHMS.RS256])
        logger.debug(f'Verification result: {verified}')
        if verified:
            sig_verified = True
            logger.info('Signature validated using software cryptography library')
    except Exception:
        logger.exception('FAILED verifying signature using cryptography')

    if not sig_verified:
        logger.error('The generated signature could not be validated')
        return False

    if args.output_file:
        # Write some extra info besides the token. The extra info should not be used
        # anywhere except by humans. All the extra info is already included in the
        # token, but then you have to parse the token to figure out the audience URL
        # for example.
        data = {'acme_url': args.url,
                'issue_ts': now,
                'expire_ts': expire,
                'token': token,
                'names': args.names,
                }
        with open(args.output_file, 'w') as fd:
            fd.write('---\n')
            yaml.safe_dump(data, fd)
        logger.info(f'Wrote ICI ACME token to file {args.output_file}')
    else:
        while token:
            print(token[:80])
            token = token[80:]
    return True


def get_acme_directory(url: str) -> dict:
    r = requests.get(url, json={})
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


def pkcs11_jws_verify(token: str) -> Optional[str]:
    """
    Perform JWS Sign with a key stored in an PKCS#11 token.

    This requires temporarily switching the key class for the algorithm in the token.
    See the documentation for pkcs11_jws_sign for more details.

    :return: The signed payload from the token, or None if verify is not supported
    """
    headers = jws.get_unverified_headers(token)
    _alg = headers['alg']

    # First, check if verify for this algorithm is supported by the token (current YubiKey can
    # sign with ECDSA, but not verify).
    # We have to do it in this hackish manner since the JOSE library will ignore any exceptions
    # from the verify method and just turn everything into an
    # JWSError('Signature verification failed.') exception.
    _p11key = P11Key('', _alg, P11Key_params)
    with _p11key.token.open(user_pin=_p11key.p11.pin) as session:
        _p11key._load_key(session)
        info = _p11key.token.slot.get_mechanism_info(_p11key._mechanism)
    logger.debug('Token mechanism info:\n{}'.format(info))
    if pkcs11.MechanismFlag.VERIFY not in info.flags:
        logger.info('Verify is not a supported operation for algorithm {} using the PKCS#11 token'.format(
            _p11key._algorithm))
        return None

    orig_key = jwk.get_key(_alg)
    try:
        # First check if verify is a supported operation using this al
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
