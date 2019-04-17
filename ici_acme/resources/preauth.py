import base64
import datetime
import json
import os

import jose
from falcon import Request, Response
from jose import jwk, jws, jwt

from ici_acme.base import BaseResource
from ici_acme.context import Context
from ici_acme.data import Authorization
from ici_acme.exceptions import RejectedIdentifier, BadRequest
from ici_acme.policy import get_authorized_names, PreAuthToken
from ici_acme.policy.x509 import get_public_key
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
        for name in authorized_for_names:
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
        # TODO: The server allocates a new URL for this authorization and returns a
        #       201 (Created) response with the authorization URL in the Location
        #       header field and the JSON authorization object in the body.
        # resp.status = falcon.HTTP_201
        # resp.set_header('Location', self.url_for('authz', authz.id))
        # resp.media = authz.to_response(challenges=[])
        resp.media = {
            'status': 'OK'
        }


def validate_token_signature(token: str, audience: str, context: Context) -> PreAuthToken:
    _headers = jose.jws.get_unverified_header(token)
    # The certificate containing the public key corresponding to the
    # key used to digitally sign the JWS MUST be the first certificate
    first_cert = base64.b64decode(_headers['x5c'][0])

    pubkey_pem = get_public_key(first_cert)
    # work around bug in JOSE implementations _get_keys
    key_dict = {'keys': [pubkey_pem]}

    claims = jose.jwt.decode(token, key_dict, audience=audience,
                             algorithms=[jwk.ALGORITHMS.RS256,
                                         jwk.ALGORITHMS.ES256,
                                         jwk.ALGORITHMS.ES384,
                                         ])
    # We are relying on the JOSE implementation to actually check 'exp'.
    # Remember this if changing from python-jose to something else in the future!
    if 'exp' not in claims.get('crit', []):
        error_msg = f'Extension "exp" not in header "crit": {_headers}'
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
