from typing import List, Mapping

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID

from ici_acme.context import Context
from ici_acme.data import Order
from ici_acme.exceptions import BadCSR


def validate(data: str, order: Order, context: Context) -> bool:
    """ Validate the CSR against this ACME servers policy. """
    csr_pem = f'-----BEGIN CERTIFICATE REQUEST-----\n' \
              f'{data}\n' \
              f'-----END CERTIFICATE REQUEST-----\n'.encode('utf-8')
    csr = x509.load_pem_x509_csr(csr_pem, default_backend())

    if not csr.is_signature_valid:
        error_detail = f'Order {order.id} CSR has invalid signature'
        context.logger.error(error_detail)
        raise BadCSR(detail=error_detail)

    subj_list = [x.rfc4514_string() for x in csr.subject]
    subj_str = '/'.join(subj_list)
    context.logger.info(f'Order {order.id} subject: "{subj_str}"')

    # Check the commonName
    cn = [x for x in subj_list if x.startswith('CN=')]
    if not cn:
        error_detail = f'Order {order.id} subject {subj_str} does not have a commonName'
        context.logger.error(error_detail)
        raise BadCSR(detail=error_detail)
    cn = cn[0][3:]

    if not _matches_identifiers(cn, order):
        error_detail = f'Order {order.id} commonName "{cn}"" does not match '\
                       f'order identifiers {order.identifiers}'
        context.logger.error(error_detail)
        raise BadCSR(detail=error_detail)

    # Check all subjectAltNames and reject any other certificate extensions
    for ext in csr.extensions:
        if ext.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
            for san in ext.value:
                context.logger.info(f'Order {order.id} subjectAltName: "{san.value}"')
                if not _matches_identifiers(san.value, order):
                    error_detail = f'Order {order.id} subjectAltName "{san.value}"" does not match '\
                                   f'order identifiers {order.identifiers}'
                    context.logger.error(error_detail)
                    raise BadCSR(detail=error_detail)
        else:
            error_detail = f'Order {order.id} CSR has unknown extensions {ext.oid}'
            context.logger.error(error_detail)
            raise BadCSR(detail=error_detail)

    context.logger.info(f'Order {order.id} CSR validated OK')
    return True


def _matches_identifiers(name: str, order: Order) -> bool:
    for ident in order.identifiers:
        if ident['type'] == 'dns' and ident['value'] == name:
            return True
    return False
