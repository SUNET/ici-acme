import json
import logging
from typing import Union, List

from OpenSSL import crypto
from jose import jws, jwt

from ici_acme.context import Context
from ici_acme.policy.x509 import is_valid_x509_cert
from ici_acme.utils import b64_decode

logger = logging.getLogger(__name__)


def is_valid_preauth_token(token: str, ca_path: str, context: Context, audience: str) -> Union[bool, List[str]]:
    """
    Check if a pre-auth token (probably for a new host) is valid, and return the host name(s).

    :param token: JWT
    :param ca_path: Path to CA store validating the x5c certificate in the token
    :param context: ICI ACME context
    :param audience: Expected JWS audience of token
    """
    headers = jwt.get_unverified_header(token)
    if not 'x5c' in headers:
        return False
    cert_der = b64_decode(headers['x5c'][0])

    if not is_valid_x509_cert(cert_der, ca_path):
        logger.warning(f'Certificate in preauth-token failed to validate with ca_path {ca_path}')
        logger.debug(f'Token: {token}')
        return False

    certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_der)
    pubkey = certificate.get_pubkey()
    pubkey_pem = crypto.dump_publickey(crypto.FILETYPE_PEM, pubkey)

    # work around bug in JOSE implementations _get_keys
    key_dict = {'keys': [pubkey_pem]}

    res = jws.verify(token, key_dict, algorithms=['RS256', 'ES256', 'ES384'])
    logger.debug(f'JWS verify result: {res}')
    if not res:
        logger.warning('Preauth-token failed signature validation')
        return False

    data = json.loads(res)
    for required in ['names', 'nonce', 'aud', 'iat', 'exp', 'crit']:
        if required not in data:
            logger.warning(f'Preauth-token did not contain required field "{required}": {data}')
            return False

    if 'exp' not in data['crit']:
        logger.warning(f'Preauth-token does not have "exp" in "crit": {data}')
        return False

    if data['aud'] != audience:
        logger.warning(f'Preauth-token has unknown audience: {data}')
        return False

    if not context.check_nonce(data['nonce']):
        logger.warning(f'Preauth-token does not contain a valid nonce: {data}')
        return False

    # Expiration checking should have been done by the JOSE implementation

    return data['names']
