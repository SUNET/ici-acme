import json
import datetime
import os
from typing import Iterable

import falcon
from falcon import Request, Response

from ici_acme.base import BaseResource
from ici_acme.data import Challenge, Authorization
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
        data = json.loads(req.context['jose_verified_data'])
        identifiers = data.get('identifier')
        if not identifiers:
            self.context.logger.error(f'No identifier in pre-auth request: {data}')
            raise falcon.HTTPBadRequest

        for ident in identifiers:
            if not self.is_allowed_identifiers(ident):
                raise falcon.HTTPForbidden

        # Create Authorization objects for each identifier, and add them to the
        # accounts preauth_ids so that they will be found in newOrder
        account = req.context['account']
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        for ident in identifiers:
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

    def is_allowed_identifiers(self, identifiers: Iterable) -> bool:
        self.context.logger.info(f'Accepting ANY identifiers for now: {identifiers}')
        return True
