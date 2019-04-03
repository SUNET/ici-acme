import falcon
from falcon import Request, Response

from ici_acme.base import BaseResource


class AccountResource(BaseResource):
    """
    Representing information about an account
    {
        'status': 'valid',  # required
        'contact': [  # optional
            'mailto:cert-admin@example.org',
            'mailto:admin@example.org'
        ],
        'termsOfServiceAgreed': true,  # optional
        'orders': 'https://example.com/acme/orders/rzGoeA'  # required
    }

    """
    pass


class NewAccountResource(BaseResource):

    def on_post(self, req: Request, resp: Response):
        jwk_data = req.context['jose_unverified_data']['protected']
        account = self.context.new_account(jwk_data)
        self.context.logger.info(f'Account {account} registered')
        resp.media = {
            'id': int(account.id),  # Dehydrated/Letsencrypt compatibility - not in RFC8555. *Must* be an integer here.
            'status': 'valid',
            'orders': self.url_for('accounts', account.id, 'orders'),
        }
        resp.set_header('Location', self.url_for('accounts', account.id))
        resp.status = falcon.HTTP_201


class KeyChangeResource(BaseResource):
    pass
