import base64
import datetime
import json
import os

import jose
from falcon import Request, Response, falcon
from jose import jwk, jws, jwt

from ici_acme.base import BaseResource
from ici_acme.context import Context
from ici_acme.data import Authorization, Challenge
from ici_acme.exceptions import BadRequest, RejectedIdentifier
from ici_acme.policy import PreAuthToken, get_authorized_names
from ici_acme.policy.x509 import get_public_key, decode_x5c_cert
from ici_acme.utils import b64_encode


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
        token = req.context['jose_verified_data']

        # The JOSE implementation currently in use fails to sign string data, so we
        # put it in a dict in ici-acme-pre-auth.py.
        try:
            _data = json.loads(token)
            if 'token' in _data:
                token = _data['token']
        except TypeError:
            pass

        audience = self.url_for('new-authz')

        preauth = validate_token_signature(token, audience, self.context)

        authorized_for_names = get_authorized_names(preauth, self.context)

        if not authorized_for_names:
            raise RejectedIdentifier

        # Create Authorization objects for each identifier, and add them to the
        # accounts preauth_ids so that they will be found in newOrder
        account = req.context['account']
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        authz = None
        chall = None
        for name in authorized_for_names:
            challenge_id = b64_encode(os.urandom(128 // 8))
            acme_method = self.context.config.get('ACME_PREAUTH_METHOD', 'x-sunet-01')
            chall = Challenge(id=challenge_id,
                              type=acme_method,
                              url=self.url_for('challenge', challenge_id),
                              status='valid',
                              created=now,
                              validated=now,
                              token=challenge_id if acme_method == 'http-01' else None,
                              )
            self.context.store.save('challenge', chall.id, chall.to_dict())

            ident = {'type': 'dns',
                     'value': name,
                     }
            authz = Authorization(id=b64_encode(os.urandom(128 // 8)),
                                  status='valid',
                                  created=now,
                                  expires=now + datetime.timedelta(minutes=5),
                                  identifier=ident,
                                  challenge_ids=[challenge_id],
                                  )
            self.context.store.save('authorization', authz.id, authz.to_dict())
            self.context.logger.info(f'Created pre-authorization {authz}')
            account.preauth_ids += [{'id': authz.id,
                                     'expires': authz.expires,
                                     }]
        self.context.store.save('account', account.id, account.to_dict())
        resp.status = falcon.HTTP_201
        if len(authorized_for_names) == 1 and authz:
            # RFC compliant response, when the request was RFC compliant (meaning a
            # preauth request for a single identifier)
            resp.set_header('Location', self.url_for('authz', authz.id))
            resp.media = authz.to_response(challenges=[chall.to_response()])
        else:
            # non-RFC compliant responses for non-compliant clients ;)
            resp.media = {
                'status': 'OK'
            }


def validate_token_signature(token: str, audience: str, context: Context) -> PreAuthToken:
    _headers = jose.jws.get_unverified_header(token)
    # The certificate containing the public key corresponding to the
    # key used to digitally sign the JWS MUST be the first certificate
    first_cert = decode_x5c_cert(base64.b64decode(_headers['x5c'][0]))

    context.logger.info(f'Pre-auth token x5c cert: {first_cert.get_subject()}, '
                        f'issued by {first_cert.get_issuer()}')
    # work around bug in JOSE implementations _get_keys
    key_dict = {'keys': [get_public_key(first_cert)]}

    claims = jose.jwt.decode(token, key_dict, audience=audience,
                             algorithms=[jwk.ALGORITHMS.RS256,
                                         jwk.ALGORITHMS.ES256,
                                         jwk.ALGORITHMS.ES384,
                                         ])
    # We are relying on the JOSE implementation to actually check 'exp'.
    # Remember this if changing from python-jose to something else in the future!
    if 'exp' not in claims.get('crit', []):
        error_msg = f'Extension "exp" not in pre-auth request "crit": {claims}'
        context.logger.error(error_msg)
        raise BadRequest(detail=error_msg)
    if 'exp' not in claims:
        error_msg = f'No expiration time in pre-auth request: {claims}'
        context.logger.error(error_msg)
        raise BadRequest(detail=error_msg)
    if 'iat' not in claims:
        error_msg = f'No issuance time in pre-auth request: {claims}'
        context.logger.error(error_msg)
        raise BadRequest(detail=error_msg)

    # Actual expiration checking should have been done by the JOSE implementation

    return PreAuthToken(claims=claims, cert=first_cert)
