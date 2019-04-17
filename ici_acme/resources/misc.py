import falcon
from falcon import Request, Response

from ici_acme.base import BaseResource


class AuthorizationResource(BaseResource):
    """
    Representing an account's authorization to act for an identifier

    {
        'status': 'valid',  # required
        'expires': '2015-03-01T14:09:07.99Z',  # optional

        'identifier': {  # required
            'type': 'dns',  # required
            'value': 'www.example.org'  # required
        },

        'challenges': [  # required
            {
                'url': 'https://example.com/acme/chall/prV_B7yEyA4',
                'type': 'http-01',
                'status': 'valid',
                'token': 'DGyRejmCefe7v4NfDGDKfA',
                'validated': '2014-12-01T12:05:58.16Z'
            }
        ],

        'wildcard': False  # optional
    }

    """
    def on_post(self, req: Request, resp: Response, authz_id: str):
        authz = self.context.store.load_authorization(authz_id)
        self.context.logger.info(f'Processing authorization {authz}')
        challenges = []
        #{
        #        'url': f'{self.context.base_url}/challenge',
        #        'type': 'http-01',
        #        'status': 'pending',
        #        'token': 'DGyRejmCefe7v4NfDGDKfA',
        #        #'validated': '2014-12-01T12:05:58.16Z'
        #    }
        #]
        for _id in authz.challenge_ids:
            this = self.context.store.load_challenge(_id)
            challenges += [this.to_response()]

        resp.media = authz.to_response(challenges)


class ChallengeResource(BaseResource):
    """
    Representing a challenge to prove control of an identifier
    """

    def on_post(self, req: Request, resp: Response, challenge_id):
        challenge = self.context.store.load_challenge(challenge_id)
        self.context.logger.info(f'Processing challenge {challenge}')
        resp.media = challenge.to_response()


class CertificateResource(BaseResource):
    """
    Representing issued certificates
    """

    def on_post(self, req: Request, resp: Response, certificate_id):
        certificate = self.context.store.load_certificate(certificate_id)
        self.context.logger.info(f'Processing certificate {certificate}')
        if not certificate.certificate:
            resp.status = falcon.HTTP_404
            return
        resp.set_header('Content-Type', 'application/pem-certificate-chain')
        resp.body = certificate.certificate
        # TODO: add CA certificate after the issued certificate


class DirectoryResource(BaseResource):

    def on_get(self, req: Request, resp: Response):
        resp.media = {
            'newNonce': self.url_for('new-nonce'),
            'newAccount': self.url_for('new-account'),
            'newOrder': self.url_for('new-order'),
            #  (If the ACME server does not implement pre-authorization it MUST omit the 'newAuthz' field)
            'newAuthz': self.url_for('new-authz'),
            'revokeCert': self.url_for('revoke-cert'),
            'keyChange': self.url_for('key-change'),
            # meta optional
            # 'meta': {
                # 'termsOfService': 'https://example.com/acme/terms/2017-5-30',
                # 'website': 'https://www.example.com/',
                # 'caaIdentities': ['example.com'],
                # 'externalAccountRequired': False
            # }
        }


class NewNonceResource(BaseResource):

    def on_head(self, req: Request, resp: Response):
        resp.set_header('Replay-Nonce', self.context.new_nonce)
        resp.set_header('Cache-Control', 'no-store')

    def on_get(self, req: Request, resp: Response):
        self.on_head(req, resp)
        resp.status = falcon.HTTP_204


class RevokeCertResource(BaseResource):
    pass


class HealthCheckResource(BaseResource):
    pass
