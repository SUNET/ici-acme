import falcon
from falcon import Request, Response

from ici_acme.base import BaseResource
from ici_acme.exceptions import AccountDoesNotExist, Unauthorized


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
    def on_post(self, req: Request, resp: Response, account_id: str):
        account = req.context['account']
        if account_id != account.id:
            raise Unauthorized(detail=f'Not authorized to view or update account with id {account_id}')
        # TODO: Update account with data from req.context['jose_verified_data']
        # The server MUST ignore any updates to the "orders" field, "termsOfServiceAgreed" field
        # (see Section 7.3.3), the "status" field (except as allowed by Section 7.3.6), or any other fields it does not
        # recognize.
        #
        # Section 7.3.3:
        # A client can indicate its agreement with the CA's terms of service by setting the "termsOfServiceAgreed"
        # field in its account object to "true".
        #
        # Section 7.3.6: A client can deactivate an account by posting a signed update to the
        # account URL with a status field of "deactivated".
        self.context.logger.info(f'Returning account {account}')
        resp.media = {
            # Dehydrated/Letsencrypt compatibility - not in RFC8555. *Must* be an integer here.
            'id': int(account.id),
            'status': account.status,
            'orders': self.url_for('accounts', account.id, 'orders'),
        }
        resp.set_header('Location', self.url_for('accounts', account.id))


class NewAccountResource(BaseResource):

    def on_post(self, req: Request, resp: Response):
        if req.context.get('account_creation') is True:
            jwk_data = req.context['jose_unverified_data']['protected']
            if jwk_data.get('onlyReturnExisting', False):
                raise AccountDoesNotExist
            account = self.context.new_account(jwk_data)
            self.context.logger.info(f'Account {account} registered')
            resp.status = falcon.HTTP_201
        else:
            # Existing account found in auth middleware
            account = req.context['account']

        resp.set_header('Location', self.url_for('accounts', account.id))
        resp.media = {
            'id': int(account.id),  # Dehydrated/Letsencrypt compatibility - not in RFC8555. *Must* be an integer here.
            'status': account.status,
            'orders': self.url_for('accounts', account.id, 'orders'),
        }


class KeyChangeResource(BaseResource):
    pass
