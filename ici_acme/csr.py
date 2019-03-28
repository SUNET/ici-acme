from cryptography import x509
from cryptography.hazmat.backends import default_backend

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

    subj_str = '/'.join([x.rfc4514_string() for x in csr.subject])
    context.logger.info(f'Order {order.id} subject: {subj_str}')
    # Check that the subject is exactly a CN that is found in the orders identifiers
    subj_valid = False
    for ident in order.identifiers:
        if ident['type'] == 'dns' and subj_str == f'CN={ident["value"]}':
            subj_valid = True
            break
    if not subj_valid:
        context.logger.error(f'Order {order.id} subject {subj_str} does not match '
                             f'order identifiers {order.identifiers}')
        return False

    context.logger.info(f'Order {order.id} CSR validated OK')
    return True
