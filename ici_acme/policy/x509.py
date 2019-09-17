import glob
import logging
import os
from dataclasses import dataclass, field
from typing import Set

from OpenSSL import crypto
from OpenSSL.crypto import X509

logger = logging.getLogger(__name__)


@dataclass
class CertInfo(object):
    names: Set[str] = field(default=lambda: {})
    key_usage: Set[str] = field(default=lambda: {})


def _add_ca_cert(store, fn: str):
    with open(fn, 'rb') as fd:
        _ca = crypto.load_certificate(crypto.FILETYPE_PEM, fd.read())
        store.add_cert(_ca)
        logger.debug(f'Added CA cert from file {fn}: {_ca.get_subject()} (serial {_ca.get_serial_number()})')


def is_valid_x509_cert(client_cert: X509, ca_path: str) -> bool:
    if not ca_path:
        logger.info('No CA path provided, certificate treated as invalid')
        return False

    store = crypto.X509Store()

    if os.path.isfile(ca_path):
        _add_ca_cert(store, ca_path)
    elif os.path.isdir(ca_path):
        for fn in glob.glob(os.path.join(ca_path, '*.crt')):
            _add_ca_cert(store, fn)
    else:
        raise RuntimeError(f'CA path {repr(ca_path)} is not a file or directory')

    logger.debug(f'Validating certificate {client_cert.get_subject()} (serial {client_cert.get_serial_number()}), '
                 f'issued by {client_cert.get_issuer()}')
    ctx = crypto.X509StoreContext(store, client_cert)
    try:
        result = ctx.verify_certificate()
        # None means valid
        return result is None
    except crypto.X509StoreContextError as exc:
        logger.error(f'Certificate failed validation: {exc}')
    return False


def get_cert_info(cert: X509) -> CertInfo:
    names: Set[str] = set()
    key_usage: Set[str] = set()

    subj = cert.get_subject()
    names.add(subj.commonName)

    for i in range(cert.get_extension_count()):
        ext = cert.get_extension(i)
        if ext.get_short_name() == b'subjectAltName':
            for san in str(ext).split(','):
                san = san.strip()
                if san.startswith('DNS:'):
                    san = san[4:]
                names.add(san)
        elif ext.get_short_name() == b'extendedKeyUsage':
            key_usage.add(str(ext))

    return CertInfo(names=names, key_usage=key_usage)


def cert_der_to_pem(der: bytes) -> bytes:
    cert = crypto.load_certificate(crypto.FILETYPE_ASN1, der)
    return crypto.dump_certificate(crypto.FILETYPE_PEM, cert)

def decode_x5c_cert(cert_der: bytes) -> X509:
    return crypto.load_certificate(crypto.FILETYPE_ASN1, cert_der)

def get_public_key(cert: X509) -> str:
    return crypto.dump_publickey(crypto.FILETYPE_PEM, cert.get_pubkey()).decode('utf-8')
