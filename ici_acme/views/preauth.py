import datetime

from falcon import Request, Response

from ici_acme.base import BaseResource


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
