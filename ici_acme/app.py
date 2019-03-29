# -*- coding: utf-8 -*-
import random
import base64

import falcon

import os
import json
import datetime

from falcon import Request, Response
from ici_acme.context import Context
from ici_acme.csr import validate
from ici_acme.store import Store
from ici_acme.data import Account, Order, Authorization, Challenge, Certificate
from ici_acme.middleware import HandleJOSE, HandleReplayNonce
from ici_acme.utils import b64_encode, urlappend, b64_decode


__author__ = 'lundberg'

#    Content-Type: application/json
#    Link: <https://example.com/acme/directory>;rel="index"

# gunicorn --reload ici_acme.app:api


class BaseResource(object):

    def __init__(self, context: Context):
        self.context = context

    def url_for(self, *args) -> str:
        url = self.context.base_url
        for arg in args:
            url = urlappend(url, f'{arg}')
        return url


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


class OrderListResource(BaseResource):

    def on_post(self, req: Request, resp: Response):
        self.context.logger.info(f'Processing orderlist')
        account = req.context['account']
        assert isinstance(account, Account)
        resp.media = {
            'orders': [self.url_for('order', order_id) for order_id in account.order_ids]
        }


class OrderResource(BaseResource):
    """
    Representing an account's requests to issue certificates
    """

    def on_post(self, req: Request, resp: Response, order_id: str):
        order = self.context.store.load_order(order_id)
        self.context.logger.info(f'Processing order {order}')

        self.update_order_state(order)

        if order.status == 'processing':
            # certificate still not issued
            resp.set_header('Retry-After', 30 + random.randint(-5, 5))

        data = {
            'status': order.status,
            'identifiers': order.identifiers,
            #'notBefore': '2016-01-01T00:00:00Z',  # optional
            #'notAfter': '2016-01-08T00:00:00Z',  # optional
            'authorizations': [self.url_for('authz', authz_id) for authz_id in order.authorization_ids],
        }

        if order.status == 'ready':
            data['finalize'] = self.url_for('order', order.id, 'finalize')

        if order.status == 'valid':
            data['certificate'] = self.url_for('certificate', order.certificate_id)

        if order.status in ['pending', 'valid']:  # XXX more states than these perhaps?
            data['expires'] = str(order.expires)

        resp.media = data

    def update_order_state(self, order: Order):
        """ Implements the state machine changes described in RFC8555 section 7.4. """
        _old_status = order.status

        if order.status == 'invalid':
            return
        if order.status == 'pending':
            # check if any authorizations are now valid, in which case the order should
            # proceed to 'ready'
            for authz_id in order.authorization_ids:
                auth = self.context.store.load_authorization(authz_id)
                if auth.status == 'pending':
                    # check if authorization has now completed
                    for chall_id in auth.challenge_ids:
                        challenge = self.context.store.load_challenge(chall_id)
                        if challenge.status == 'valid':
                            auth.status = 'valid'
                            self.context.store.save('authorization', auth.id, auth.to_dict())
                if auth.status == 'valid':
                    order.status = 'ready'
                    break
                self.context.logger.info(f'Authorization {auth} still not valid')

        if order.status == 'ready':
            if order.certificate_id is not None:
                # a finalize request has been issued
                order.status = 'processing'

        if order.status == 'processing':
            cert = self.context.store.load_certificate(order.certificate_id)
            if cert.certificate is not None:
                order.status = 'valid'

        if order.status != _old_status:
            self.context.logger.info(f'Order changed from state {_old_status} to {order.status}')
            self.context.store.save('order', order.id, order.to_dict())
        else:
            self.context.logger.info(f'Order remained in state {order.status}')


class FinalizeOrderResource(OrderResource):

    def on_post(self, req: Request, resp: Response, order_id: str):
        order = self.context.store.load_order(order_id)
        self.context.logger.info(f'Finalizing order {order}')

        self.update_order_state(order)

        if order.status != 'ready':
            # If status is not ready MUST return a 403 (Forbidden) error with a problem document of type "orderNotReady"
            self.context.logger.error('Not allowed to call finalize, order not in "ready" state')
            resp.status = falcon.HTTP_403

        data = json.loads(req.context['jose_verified_data'].decode('utf-8'))
        # PEM format is plain base64 encoded
        csr = base64.b64encode(b64_decode(data['csr'])).decode('utf-8')
        if not validate(csr, order, context):
            return falcon.HTTPForbidden

        order.certificate_id = b64_encode(os.urandom(128 // 8))
        cert = Certificate(csr=data['csr'],
                           created=datetime.datetime.now(tz=datetime.timezone.utc),
                           )
        self.context.store.save('certificate', order.certificate_id, cert.to_dict())
        self.context.store.save('order', order.id, order.to_dict())

        super().on_post(req, resp, order.id)


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
    def on_post(self, req: Request, resp: Response, id: str):
        authz = self.context.store.load_authorization(id)
        self.context.logger.info(f'Processing authorization {authz}')
        challenges = []
        for _id in authz.challenge_ids:
            this = self.context.store.load_challenge(_id)
            challenges += [this.to_response()]

        resp.media = {
            'status': authz.status,
            #expires:
            'identifier': authz.identifier,
            'challenges': challenges,
        }


class ChallengeResource(BaseResource):
    """
    Representing a challenge to prove control of an identifier
    """

    def on_post(self, req: Request, resp: Response, id):
        challenge = self.context.store.load_challenge(id)
        self.context.logger.info(f'Processing challenge {challenge}')
        resp.media = challenge.to_response()


class CertificateResource(BaseResource):
    """
    Representing issued certificates
    """

    def on_post(self, req: Request, resp: Response, id):
        certificate = self.context.store.load_certificate(id)
        self.context.logger.info(f'Processing certificate {certificate}')
        if not certificate.certificate:
            resp.status = falcon.HTTP_404
            return
        resp.set_header('Content-Type', 'application/pem-certificate-chain')
        resp.media = certificate.certificate


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


class NewOrderResource(BaseResource):

    def on_post(self, req: Request, resp: Response):
        self.context.logger.info(f'Creating a new order for account {req.context["account"].id}')
        # Decode the clients order, e.g.
        #  {"identifiers": [{"type": "dns", "value": "test.test"}]}
        acme_request = json.loads(req.context['jose_verified_data'].decode('utf-8'))

        authorizations = []
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        for ident in acme_request['identifiers']:
            challenge_id = b64_encode(os.urandom(128 // 8))
            chall = Challenge(id=challenge_id,
                              type='x-sunet-01',
                              url=self.url_for('challenge', challenge_id),
                              status='pending',
                              created=now,
                              # token for type='http-01'
                              #token=b64_urlsafe(os.urandom(256 // 8)),
                              # token for type='x-sunet-01'
                              token=challenge_id,
                              )
            self.context.store.save('challenge', chall.id, chall.to_dict())
            authz = Authorization(id=b64_encode(os.urandom(128 // 8)),
                                  status='pending',
                                  created=now,
                                  expires=now + datetime.timedelta(minutes=5),
                                  identifier=ident,
                                  challenge_ids=[challenge_id],
                                  )
            self.context.store.save('authorization', authz.id, authz.to_dict())
            authorizations += [authz]

        order = Order(id=b64_encode(os.urandom(128 // 8)),
                      created=datetime.datetime.now(tz=datetime.timezone.utc),
                      identifiers=acme_request['identifiers'],
                      authorization_ids=[x.id for x in authorizations],
                      status='pending',
                      expires=now + datetime.timedelta(minutes=30),
                      )
        account = req.context['account']
        account.last_order = datetime.datetime.now(tz=datetime.timezone.utc)
        account.order_ids += [order.id]
        self.context.store.save('order', order.id, order.to_dict())
        self.context.store.save('account', account.id, account.to_dict())
        resp.media = {
            'status': 'pending',
            'identifiers': order.identifiers,
            'authorizations': [self.url_for('authz', authz_id) for authz_id in order.authorization_ids],
            'finalize': self.url_for('order', order.id, 'finalize')
        }
        resp.set_header('Location', self.url_for('order', order.id))
        resp.status = falcon.HTTP_201


class RevokeCertResource(BaseResource):
    pass


class KeyChangeResource(BaseResource):
    pass


class HealthCheckResource(BaseResource):
    pass


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


store = Store('data')
context = Context(store)
api = falcon.API(middleware=[HandleJOSE(context), HandleReplayNonce(context)])

context.logger.info('Starting api')
api.req_options.media_handlers['application/jose+json'] = api.req_options.media_handlers['application/json']
api.add_route('/directory', DirectoryResource(context=context))
api.add_route('/new-nonce', NewNonceResource(context=context))
api.add_route('/new-account', NewAccountResource(context=context))
api.add_route('/new-order', NewOrderResource(context=context))
api.add_route('/authz/{id}', AuthorizationResource(context=context))
api.add_route('/challenge/{id}', ChallengeResource(context=context))
api.add_route('/fakeauth/{client_data}', FakeAuthResource(context=context))
# OrderResource
api.add_route('/order', OrderListResource(context=context))
api.add_route('/order/{order_id}', OrderResource(context=context))
api.add_route('/order/{order_id}/finalize', FinalizeOrderResource(context=context))
#
api.add_route('/certificate/{id}', CertificateResource(context=context))
