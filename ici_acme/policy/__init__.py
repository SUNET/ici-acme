from typing import Iterable

from ici_acme.context import Context
from ici_acme.policy.data import PreAuthToken
from ici_acme.policy.token import is_valid_preauth_token
from ici_acme.policy.x509 import is_valid_x509_cert, get_cert_info


def get_authorized_names(preauth: PreAuthToken, context: Context) -> Iterable[str]:
    if preauth.claims.get('renew') is True:
        if context.renew_ca_path:
            if not is_valid_x509_cert(preauth.cert, ca_path=context.renew_ca_path):
                context.logger.error(f'Certificate failed infra-cert validation')
                return []

            cert_info = get_cert_info(preauth.cert, der_encoded=True)
            return cert_info.names
    elif context.token_ca_path:
        names = is_valid_preauth_token(preauth, context.token_ca_path, context)
        if names is not False:
            return names
    return []
