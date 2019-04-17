import logging
from typing import Union, List

from OpenSSL import crypto

from ici_acme.context import Context
from ici_acme.policy import PreAuthToken
from ici_acme.policy.x509 import is_valid_x509_cert

logger = logging.getLogger(__name__)


def is_valid_preauth_token(preauth: PreAuthToken, ca_path: str, context: Context) -> Union[bool, List[str]]:
    """
    Check if a pre-auth token (probably for a new host) is valid, and return the host name(s).

    :param ca_path: Path to CA store validating the x5c certificate in the token
    :param context: ICI ACME context
    :param audience: Expected JWS audience of token
    """
    if not is_valid_x509_cert(preauth.cert, ca_path):
        logger.warning(f'Certificate in preauth-token failed to validate with ca_path {ca_path}')
        logger.debug(f'Token: {preauth}')
        return False

    if not context.check_nonce(preauth.claims['nonce']):
        logger.warning(f'Preauth-token does not contain a valid nonce: {preauth.claims}')
        return False

    for required in ['names', 'nonce']:
        if required not in preauth.claims:
            logger.warning(f'Preauth-token did not contain required field "{required}": {preauth.claims}')
            return False

    return preauth.claims['names']
