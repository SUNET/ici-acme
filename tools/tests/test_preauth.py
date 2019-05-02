import json
import os
import unittest
import pkg_resources

import ici_acme_pre_auth as preauth
from ici_acme.context import Context
from ici_acme.middleware import SUPPORTED_ALGORITHMS
from ici_acme.resources.preauth import validate_token_signature

from jose import jws


class FakeArgs(object):
    pass


class Test_PreauthRenew(unittest.TestCase):

    def setUp(self):
        self.data_dir = pkg_resources.resource_filename(__name__, 'data')
        #self.args = FakeArgs()
        #self.args.existing_cert = os.path.join(self.data_dir, 'ec_cert.pem')
        #self.args.private_key = os.path.join(self.data_dir, 'ec_cert.pem')
        args = ['--dehydrated_account_dir', os.path.join(self.data_dir, 'dehydrated_account'),
                'renew',
                '--cert', os.path.join(self.data_dir, 'ec_cert.pem'),
                '--key', os.path.join(self.data_dir, 'ec_private_key.pem'),
                ]
        self.args = preauth.parse_args(preauth._defaults, args)
        self.directory = preauth.Endpoints({'newAuthz': 'http://localhost:8000/newAuthz',
                                            })
        self.config={'STORE_PATH': '/tmp',
                     }
        self.context = Context(config=self.config)


    def test_renew(self):
        # have to use large expires to get around a double-UTC-bug here:
        #   https://github.com/mpdavis/python-jose/blob/deea7600eeea47aeb1bf5053a96de51cf2b9c639/jose/jwt.py#L318
        token = preauth.create_renew_pre_auth(self.directory, self.args, expires=86400)

        # validate it like the ICI ACME server will
        validated_token = validate_token_signature(token, self.directory['newAuthz'], self.context)

        # Put the preauth JWT inside the ACME JWT
        signed = preauth.dehydrated_account_sign(token, self.directory, self.args, nonce='test_nonce')

        with open(os.path.join(self.data_dir, 'account1_pubkey.pem'), 'rb') as fd:
            jwk = {'keys': [fd.read()]}

        # validate the ACME JWT like the ICI ACME middleware would (using another JOSE implementation for now)
        ret = jws.verify(signed.to_compact().decode(), jwk, algorithms=SUPPORTED_ALGORITHMS)
        verified_data = json.loads(ret)

        self.assertEqual(token, verified_data['token'])


