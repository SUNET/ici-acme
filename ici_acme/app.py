# -*- coding: utf-8 -*-

import falcon

import os
import json
import datetime

from falcon import Request, Response
from ici_acme.context import Context
from ici_acme.store import Store, Account, Order, Authorization
from ici_acme.middleware import HandleJOSE
from ici_acme.utils import b64_urlsafe

__author__ = 'lundberg'

#    Content-Type: application/json
#    Link: <https://example.com/acme/directory>;rel="index"

# gunicorn --reload ici_acme.app:api


class BaseResource(object):

    def __init__(self, context: Context):
        self.context = context


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


class OrderResource(BaseResource):
    """
    Representing an account's requests to issue certificates
    """

    def on_post(self, req: Request, resp: Response):
        if not req.media:
            # POST as GET, poll for status
            resp.media = {
                'orders': [
                    'https://example.com/acme/order/TOlocE8rfgo',
                    'https://example.com/acme/order/4E16bbL5iSw',
                    'https://example.com/acme/order/neBHYLfw0mg'
                ]
            }
        else:
            #  Order's finalize url
            resp.media = {
                'status': 'valid',  # required
                'expires': '2016-01-20T14:09:07.99Z',  # optional

                'identifiers': [  # required
                    {'type': 'dns', 'value': 'www.example.org'},
                    {'type': 'dns', 'value': 'example.org'}
                ],

                'notBefore': '2016-01-01T00:00:00Z',  # optional
                'notAfter': '2016-01-08T00:00:00Z',  # optional

                'authorizations': [  # required
                    'https://example.com/acme/authz/PAniVnsZcis',
                    'https://example.com/acme/authz/r4HqLzrSrpI'
                ],

                'finalize': 'https://example.com/acme/order/TOlocE8rfgo/finalize',  # required

                'certificate': 'https://example.com/acme/cert/mAt3xBGaobw'  # optional
            }
            

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
    pass


class ChallengeResource(BaseResource):
    """
    Representing a challenge to prove control of an identifier
    """

    def on_post(self, req: Request, resp: Response):
        if not req.media:
            # POST as GET, fetch challenges
            pass
        else:
            # Respond to challenges
            pass


class CertificateResource(BaseResource):
    """
    Representing issued certificates
    """

    def on_post(self, req: Request, resp: Response):
        if not req.media:
            # POST as GET, order's certificate url
            pass


class DirectoryResource(BaseResource):

    def on_get(self, req: Request, resp: Response):
        resp.media = {
            'newNonce': f'{self.context.base_url}/new-nonce',
            'newAccount': f'{self.context.base_url}/new-account',
            'newOrder': f'{self.context.base_url}/new-order',
            #  (If the ACME server does not implement pre-authorization it MUST omit the 'newAuthz' field)
            'newAuthz': f'{self.context.base_url}/new-authz',
            'revokeCert': f'{self.context.base_url}/revoke-cert',
            'keyChange': f'{self.context.base_url}/key-change',
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


class NewAccountResource(BaseResource):

    def on_post(self, req: Request, resp: Response):
        jwk_data = req.context['jose_unverified_data']['protected']
        account = self.context.new_account(jwk_data)
        self.context.logger.info(f'Account {account} registered')
        account_url = f'{self.context.base_url}/accounts/{account.id}'
        resp.set_header('Location', account_url)
        resp.media = {
            'id': int(account.id),  # Dehydrated/Letsencrypt compatibility - not in RFC8555. *Must* be an integer here.
            'status': 'valid',
            'orders': f'{account_url}/orders',
        }
        resp.set_header('Replay-Nonce', self.context.new_nonce)
        resp.status = falcon.HTTP_201


class NewOrderResource(BaseResource):

    def on_post(self, req: Request, resp: Response):
        self.context.logger.info(f'NEW ORDER')
        # Decode the clients order, e.g.
        #  {"identifiers": [{"type": "dns", "value": "test.test"}]}
        acme_request = json.loads(req.context['jose_verified_data'].decode('utf-8'))
        authz = Authorization(id=b64_urlsafe(os.urandom(128 // 8)),
                              created=datetime.datetime.now(tz=datetime.timezone.utc),
                              )
        order = Order(id=b64_urlsafe(os.urandom(128 // 8)),
                      created=datetime.datetime.now(tz=datetime.timezone.utc),
                      identifiers=acme_request['identifiers'],
                      authorizations=[authz.id],
                      )
        account = req.context['account']
        account.last_order = datetime.datetime.now(tz=datetime.timezone.utc)
        account.orders += [order.id]
        self.context.store.save('authorization', authz.id, authz.to_dict())
        self.context.store.save('order', order.id, order.to_dict())
        self.context.store.save('account', account.id, account.to_dict())
        resp.media = {
            'status': 'pending',
            'identifiers': order.identifiers,
            'authorizations': [f'{self.context.base_url}/authz/{this}' for this in order.authorizations],
            'finalize': f'{self.context.base_url}/order/{order.id}/finalize'
        }
        resp.set_header('Replay-Nonce', self.context.new_nonce)
        #resp.status = falcon.HTTP_500


class RevokeCertResource(BaseResource):
    pass


class KeyChangeResource(BaseResource):
    pass


class HealthCheckResource(BaseResource):
    pass


store = Store('data')
context = Context(store)
api = falcon.API(middleware=[HandleJOSE(context)])

context.logger.info('Starting api')
api.req_options.media_handlers['application/jose+json'] = api.req_options.media_handlers['application/json']
api.add_route('/directory', DirectoryResource(context=context))
api.add_route('/new-nonce', NewNonceResource(context=context))
api.add_route('/new-account', NewAccountResource(context=context))
api.add_route('/new-order', NewOrderResource(context=context))

