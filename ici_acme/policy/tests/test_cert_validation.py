""" Test validation of certs - not exactly parts of ici-acme, but... """
import unittest

from ici_acme.policy.x509 import get_cert_info
from ici_acme.utils import b64_decode

from OpenSSL import crypto


CA_CERT = b"""-----BEGIN CERTIFICATE-----
MIICSjCCAfGgAwIBAgIBADAKBggqhkjOPQQDAjAiMRMwEQYDVQQDDApNeSBSb290
IENBMQswCQYDVQQGEwJTRTAeFw0xOTA0MDUxMDQ3MjFaFw0xOTA1MDUxMDQ3MjFa
MCIxEzARBgNVBAMMCk15IFJvb3QgQ0ExCzAJBgNVBAYTAlNFMFkwEwYHKoZIzj0C
AQYIKoZIzj0DAQcDQgAEBcqDLeURtnpicJPd/JZ/OaeoLgH/vgSKC5i0VtBtTrl3
2EyYcVkms1k5rJGPu1bBb0jwv6h4Yc/c32K4y2CQ26OCARYwggESMB0GA1UdDgQW
BBRjOlyeIjBTdUOH5OXHNKZ+pB6uCDAfBgNVHSMEGDAWgBRjOlyeIjBTdUOH5OXH
NKZ+pB6uCDBdBggrBgEFBQcBAQRRME8wKAYIKwYBBQUHMAKGHGh0dHA6Ly9jYS5l
eGFtcGxlLmNvbS9jYS5jcnQwIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLmV4YW1w
bGUuY29tMC4GA1UdHwQnMCUwI6AhoB+GHWh0dHA6Ly9jYS5leGFtcGxlLmNvbS9j
cmwucGVtMCAGA1UdEgQZMBeGFWh0dHA6Ly9jYS5leGFtcGxlLmNvbTAPBgNVHRMB
Af8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAgNHADBEAiBZv3MR
LY/Dea1Mz8uteQF9Oq3UVL2gX+EDZby/b6ocYQIgNs0f57WwDbLQ95YD7Y4DZH9H
8BLh7NuTZrLAyofFbz8=
-----END CERTIFICATE-----
"""

XCLIENT_PUBKEY = b"""-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEB7AW1CXGl20rHL/2Ue83FQWBFL9B
fpoSb15blq+M7yvTucIAN8jVlSsc+Co2+ZSgl8IQflxKrlaZQfZMe8woyQ==
-----END PUBLIC KEY-----
"""

XCLIENT_PRIVATE_KEY = b"""-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIvWD6+mbKoCegcL2W9fK4ws0yEx8ziV1TsSVqG7yl/8oAoGCCqGSM49
AwEHoUQDQgAEB7AW1CXGl20rHL/2Ue83FQWBFL9BfpoSb15blq+M7yvTucIAN8jV
lSsc+Co2+ZSgl8IQflxKrlaZQfZMe8woyQ==
-----END EC PRIVATE KEY-----
"""

EXPIRED_CLIENT_CERT = b"""-----BEGIN CERTIFICATE-----
MIICUTCCAfagAwIBAgIIPp5Yk9ud4H4wCgYIKoZIzj0EAwIwIjETMBEGA1UEAwwK
TXkgUm9vdCBDQTELMAkGA1UEBhMCU0UwHhcNMTkwNDA1MTEzNzUzWhcNMTkwNDA2
MTEzNzUzWjAUMRIwEAYDVQQDDAl0ZXN0LnRlc3QwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAAQHsBbUJcaXbSscv/ZR7zcVBYEUv0F+mhJvXluWr4zvK9O5wgA3yNWV
Kxz4Kjb5lKCXwhB+XEquVplB9kx7zCjJo4IBIjCCAR4wHQYDVR0OBBYEFIuHYKB6
nELulqB5P2F91eZIvgS3MB8GA1UdIwQYMBaAFGM6XJ4iMFN1Q4fk5cc0pn6kHq4I
MF0GCCsGAQUFBwEBBFEwTzAoBggrBgEFBQcwAoYcaHR0cDovL2NhLmV4YW1wbGUu
Y29tL2NhLmNydDAjBggrBgEFBQcwAYYXaHR0cDovL29jc3AuZXhhbXBsZS5jb20w
LgYDVR0fBCcwJTAjoCGgH4YdaHR0cDovL2NhLmV4YW1wbGUuY29tL2NybC5wZW0w
IAYDVR0SBBkwF4YVaHR0cDovL2NhLmV4YW1wbGUuY29tMAkGA1UdEwQCMAAwCwYD
VR0PBAQDAgXgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAoGCCqGSM49BAMCA0kAMEYC
IQCo0iVPaGo+qU/CGiLRcVjRKCKTMNzhVo2D1KUtngfGtgIhAKYAKGNizAepEF4t
iFEqsZLnb5mjQlr8yH+Wt5KSGisP
-----END CERTIFICATE-----
"""

VALID_CLIENT_CERT = b"""-----BEGIN CERTIFICATE-----
MIICUzCCAfigAwIBAgIIDfaDI57Acl0wCgYIKoZIzj0EAwIwIjETMBEGA1UEAwwK
TXkgUm9vdCBDQTELMAkGA1UEBhMCU0UwIBcNMTkwNDA4MDczMzUyWhgPMjExOTAz
MTUwNzMzNTJaMBQxEjAQBgNVBAMMCXRlc3QudGVzdDBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABDehpb8zclpO8PHG2evZlcqc71Vs4J9X/UcMAJV71PEac2ZpWx9C
bXgBiHOL0mmcQdd8az9AYfXJ5L25cvx/roijggEiMIIBHjAdBgNVHQ4EFgQUksa3
OsIjSKH5r6md01O24ANrcnYwHwYDVR0jBBgwFoAUYzpcniIwU3VDh+TlxzSmfqQe
rggwXQYIKwYBBQUHAQEEUTBPMCgGCCsGAQUFBzAChhxodHRwOi8vY2EuZXhhbXBs
ZS5jb20vY2EuY3J0MCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5leGFtcGxlLmNv
bTAuBgNVHR8EJzAlMCOgIaAfhh1odHRwOi8vY2EuZXhhbXBsZS5jb20vY3JsLnBl
bTAgBgNVHRIEGTAXhhVodHRwOi8vY2EuZXhhbXBsZS5jb20wCQYDVR0TBAIwADAL
BgNVHQ8EBAMCBeAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwCgYIKoZIzj0EAwIDSQAw
RgIhAO0zBolnp0C5F+UG8saBdcCkaiD1VKo5pabpKde6zxL7AiEA4kIZP2JjJz83
5vtASsTVETvUwILikFRSSikjLst/ONE=
-----END CERTIFICATE-----
"""

VALID_CLIENT_CERT_SAN = b"""-----BEGIN CERTIFICATE-----
MIICeDCCAh6gAwIBAgIJAOnGRddxOQu3MAoGCCqGSM49BAMCMCIxEzARBgNVBAMM
Ck15IFJvb3QgQ0ExCzAJBgNVBAYTAlNFMCAXDTE5MDQxMTA5Mjk0MVoYDzIxMTkw
MzE4MDkyOTQxWjAUMRIwEAYDVQQDDAl0ZXN0LnRlc3QwWTATBgcqhkjOPQIBBggq
hkjOPQMBBwNCAAQmc6ysG+62Jwqq1UbN7R30KLkdW9QWvp8CcZzQOnYOwtSdEbbm
vE8zJ7FSc4zbLp9Z2ZjwQKQWh0KF1Z7c8H0so4IBRzCCAUMwHQYDVR0OBBYEFCsz
lVpYxzJUpTiKB9g3Bj+HTy6eMB8GA1UdIwQYMBaAFGM6XJ4iMFN1Q4fk5cc0pn6k
Hq4IMF0GCCsGAQUFBwEBBFEwTzAoBggrBgEFBQcwAoYcaHR0cDovL2NhLmV4YW1w
bGUuY29tL2NhLmNydDAjBggrBgEFBQcwAYYXaHR0cDovL29jc3AuZXhhbXBsZS5j
b20wLgYDVR0fBCcwJTAjoCGgH4YdaHR0cDovL2NhLmV4YW1wbGUuY29tL2NybC5w
ZW0wIAYDVR0SBBkwF4YVaHR0cDovL2NhLmV4YW1wbGUuY29tMCMGA1UdEQQcMBqC
CXRlc3QudGVzdIINdGVzdC1zYW4udGVzdDAJBgNVHRMEAjAAMAsGA1UdDwQEAwIF
4DATBgNVHSUEDDAKBggrBgEFBQcDATAKBggqhkjOPQQDAgNIADBFAiEA1xW0dpxm
BNlmXNUIqXp2hR1oz9W++NF286sTG/NYVrsCIEiW+aXN6HwwhjKxqN7S3HwamAFR
n7EtQKNJGBT0MB2s
-----END CERTIFICATE-----
"""

class Test_Validation(unittest.TestCase):

    def test_cert_validate_valid(self):
        """ Test cert chain validation """
        client_cert = crypto.load_certificate(crypto.FILETYPE_PEM, VALID_CLIENT_CERT)
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, CA_CERT)

        store = crypto.X509Store()
        store.add_cert(ca_cert)

        ctx = crypto.X509StoreContext(store, client_cert)
        result = ctx.verify_certificate()
        # None means valid
        self.assertIsNone(result)

    def test_cert_validate_expired(self):
        """ Test cert chain validation with expired certificate"""
        client_cert = crypto.load_certificate(crypto.FILETYPE_PEM, EXPIRED_CLIENT_CERT)
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, CA_CERT)

        store = crypto.X509Store()
        store.add_cert(ca_cert)

        ctx = crypto.X509StoreContext(store, client_cert)
        with self.assertRaises(crypto.X509StoreContextError) as exc:
            ctx.verify_certificate()
        self.assertIn('certificate has expired', str(exc.exception))

    def test_verify_signature(self):
        """ Test signature verification """
        message = b'test message'
        signature = b64_decode('MEYCIQDyC1uj19hztaKx_uMwxMNBYfFri4eEvOOPHp2Sea3X'
                               'BQIhAJ27RrZKIWHF3YJOt_WAJ28L-JB_41MsAy2xaCk7lYsp')

        client_cert = crypto.load_certificate(crypto.FILETYPE_PEM, EXPIRED_CLIENT_CERT)

        res = crypto.verify(client_cert, signature, message, 'sha256')
        self.assertIsNone(res)

    def test_get_cert_info(self):
        info = get_cert_info(VALID_CLIENT_CERT)
        self.assertEqual(info.names, {'test.test'})
        self.assertEqual(info.key_usage, {'TLS Web Server Authentication'})

    def test_get_cert_info_with_san(self):
        info = get_cert_info(VALID_CLIENT_CERT_SAN)
        self.assertEqual(info.names, {'test.test', 'test-san.test'})
        self.assertEqual(info.key_usage, {'TLS Web Server Authentication'})
