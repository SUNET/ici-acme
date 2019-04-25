import logging
from typing import List

from ici_acme.context import Context
from ici_acme.policy.data import PreAuthToken
from ici_acme.policy.token import is_valid_preauth_token
from ici_acme.policy.x509 import get_cert_info, is_valid_x509_cert

logger = logging.getLogger(__name__)


def get_authorized_names(preauth: PreAuthToken, context: Context) -> List[str]:
    requested_names = []
    if preauth.claims.get('renew') is True:
        if context.renew_ca_path:
            if not is_valid_x509_cert(preauth.cert, ca_path=context.renew_ca_path):
                context.logger.error(f'Certificate failed infra-cert validation')
                return []

            cert_info = get_cert_info(preauth.cert, der_encoded=True)
            requested_names = cert_info.names
    elif context.token_ca_path:
        names = is_valid_preauth_token(preauth, context.token_ca_path, context)
        if names is not False:
            requested_names = names

    preauth_domains = context.config.get('PREAUTH_DOMAINS', [])
    if not preauth_domains:
        logger.info(f'Pre-auth accepted for names {requested_names} (PREAUTH_DOMAINS not set)')
        return requested_names

    valid_names = []
    for name in requested_names:
        valid = False
        for domain in preauth_domains:
            if name.endswith(domain):
                valid = True
                break
        if not valid:
            logger.info(f'Requested name {name} not allowed by PREAUTH_DOMAINS whitelist')
        else:
            valid_names += [name]
    return valid_names
