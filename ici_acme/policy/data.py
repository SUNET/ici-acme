from dataclasses import dataclass
from typing import Mapping

from OpenSSL.crypto import X509


@dataclass
class PreAuthToken(object):
    """
    Data class holding information about a validated pre-auth token.

    Validated means signed with the cert in header[x5c]) pre-auth token.
    The authority of the certificate is NOT checked.
    """
    claims: Mapping
    cert: X509
