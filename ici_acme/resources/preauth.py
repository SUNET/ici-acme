import base64
import json
import datetime
import os
from typing import Iterable

import falcon

from falcon import Request, Response
import jose
from jose import jwk, jws, jwt

from ici_acme.base import BaseResource
from ici_acme.data import Challenge, Authorization
from ici_acme.policy.x509 import cert_der_to_pem, get_public_key, is_valid_infra_cert, get_cert_info
from ici_acme.utils import b64_encode


_MAX_ALLOWED_TIMEDIFF = 300


class FakeAuthResource(BaseResource):

    def on_get(self, req: Request, resp: Response, client_data):
        challenge_id = client_data.split('.')[0]
        challenge = self.context.store.load_challenge(challenge_id)
        self.context.logger.info(f'Processing challenge {challenge}')
        challenge.status = 'valid'
        challenge.validated = datetime.datetime.now(tz=datetime.timezone.utc)
        self.context.store.save('challenge', challenge.id, challenge.to_dict())
        resp.media = {
            'status': 'OK'
        }


class PreAuthResource(BaseResource):

    def on_post(self, req: Request, resp: Response):
        self.context.logger.info(f'Pre-authorization for account {req.context["account"].id}')
        data = req.context['jose_verified_data']

        # The JOSE implementation currently in use fails to sign string data, so we
        # put it in a dict in ici-acme-pre-auth.py.
        token = data
        try:
            _data = json.loads(data)
            if 'token' in _data:
                token = _data['token']
        except TypeError:
            pass

        _headers = jose.jws.get_unverified_header(token)
        # The certificate containing the public key corresponding to the
        # key used to digitally sign the JWS MUST be the first certificate
        first_cert = base64.b64decode(_headers['x5c'][0])
        pubkey = get_public_key(first_cert)

        claims = jose.jwt.decode(token, pubkey, algorithms=[jwk.ALGORITHMS.RS256,
                                                            jwk.ALGORITHMS.ES256,
                                                            jwk.ALGORITHMS.ES384,
                                                            ])

        # We are relying on the JOSE implementation to actually check 'exp'.
        # Remember this if changing from python-jose to something else in the future!
        if 'exp' not in _headers.get('crit', []):
            self.context.logger.error(f'Extension "exp" not in header "crit": {_headers}')
            raise falcon.HTTPBadRequest

        if 'exp' not in claims:
            self.context.logger.error(f'No expiration time in pre-auth request: {claims}')
            raise falcon.HTTPBadRequest

        if not is_valid_infra_cert(first_cert):
            self.context.logger.error(f'Certificate failed infra-cert validation')
            raise falcon.HTTPForbidden

        cert_info = get_cert_info(first_cert, der_encoded=True)

        # Create Authorization objects for each identifier, and add them to the
        # accounts preauth_ids so that they will be found in newOrder
        account = req.context['account']
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        for name in cert_info.names:
            ident = {'type': 'dns',
                     'value': name,
                     }
            authz = Authorization(id=b64_encode(os.urandom(128 // 8)),
                                  status='valid',
                                  created=now,
                                  expires=now + datetime.timedelta(minutes=5),
                                  identifier=ident,
                                  challenge_ids=[],
                                  )
            self.context.store.save('authorization', authz.id, authz.to_dict())
            self.context.logger.info(f'Created pre-authorization {authz}')
            account.preauth_ids += [{'id': authz.id,
                                     'expires': authz.expires,
                                     }]
        self.context.store.save('account', account.id, account.to_dict())
        resp.media = {
            'status': 'OK'
        }
