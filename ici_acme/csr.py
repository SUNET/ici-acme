from typing import List, Mapping

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID

from ici_acme.context import Context
from ici_acme.data import Order


def validate(data: str, order: Order, context: Context) -> bool:
    """ Validate the CSR against this ACME servers policy. """
    csr_pem = f'-----BEGIN CERTIFICATE REQUEST-----\n' \
              f'{data}\n' \
              f'-----END CERTIFICATE REQUEST-----\n'.encode('utf-8')
    csr = x509.load_pem_x509_csr(csr_pem, default_backend())

    if not csr.is_signature_valid:
        context.logger.error(f'Order {order.id} CSR has invalid signature')
        return False

    subj_list = [x.rfc4514_string() for x in csr.subject]
    subj_str = '/'.join(subj_list)
    context.logger.info(f'Order {order.id} subject: "{subj_str}"')

    # Check the commonName
    cn = [x for x in subj_list if x.startswith('CN=')]
    if not cn:
        context.logger.error(f'Order {order.id} subject {subj_str} does not have a commonName')
        return False
    cn = cn[0][3:]

    if not _matches_identifiers(cn, order):
        context.logger.error(f'Order {order.id} commonName "{cn}"" does not match '
                             f'order identifiers {order.identifiers}')
        return False

    # Check all subjectAltNames and reject any other certificate extensions
    for ext in csr.extensions:
        if ext.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
            for san in ext.value:
                context.logger.info(f'Order {order.id} subjectAltName: "{san.value}"')
                if not _matches_identifiers(san.value, order):
                    context.logger.error(f'Order {order.id} subjectAltName "{san.value}"" does not match '
                                         f'order identifiers {order.identifiers}')
                    return False
        else:
            context.logger.error(f'Order {order.id} CSR has unknown extensions {ext.oid}')
            return False

    context.logger.info(f'Order {order.id} CSR validated OK')
    return True


def _matches_identifiers(name: str, order: Order) -> bool:
    for ident in order.identifiers:
        if ident['type'] == 'dns' and ident['value'] == name:
            return True
    return False
