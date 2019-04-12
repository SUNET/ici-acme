import glob
import os
import logging
from dataclasses import dataclass, field

from typing import Set

from OpenSSL import crypto


logger = logging.getLogger(__name__)


@dataclass
class CertInfo(object):
    names: Set[str] = field(default=lambda: {})
    key_usage: Set[str] = field(default=lambda: {})


def is_valid_infra_cert(cert_der, ca_path):
    return is_valid_x509_cert(cert_der, ca_path)


def is_valid_x509_cert(cert_der: bytes, ca_path: str) -> bool:
    client_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_der)
    store = crypto.X509Store()

    if os.path.isfile(ca_path):
        with open(ca_path, 'rb') as fd:
            _ca = crypto.load_certificate(crypto.FILETYPE_PEM, fd.read())
            store.add_cert(_ca)
    elif os.path.isdir(ca_path):
        for fn in glob.glob(os.path.join(ca_path, '*.crt')):
            _ca = crypto.load_certificate(crypto.FILETYPE_PEM, fn)
            store.add_cert(_ca)
    else:
        raise RuntimeError(f'CA path {repr(ca_path)} is not a file or directory')

    ctx = crypto.X509StoreContext(store, client_cert)
    try:
        result = ctx.verify_certificate()
        # None means valid
        return result is None
    except crypto.X509StoreContextError as exc:
        logger.error(f'Certificate failed validation: {exc}')
    return False


def get_cert_info(cert_data: bytes, der_encoded=False) -> CertInfo:
    if der_encoded:
        cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_data)
    else:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)

    names: Set[str] = set()
    key_usage: Set[str] = set()

    subj = cert.get_subject()
    names.add(subj.commonName)

    for i in range(cert.get_extension_count()):
        ext = cert.get_extension(i)
        #print(f'{ext.get_short_name()} == {str(ext)}')
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

def get_public_key(cert_der: bytes) -> str:
    cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_der)
    return crypto.dump_publickey(crypto.FILETYPE_PEM, cert.get_pubkey()).decode('utf-8')
