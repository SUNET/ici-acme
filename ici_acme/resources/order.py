import base64
import datetime
import json
import os
import random

import falcon
from falcon import Request, Response

from ici_acme.base import BaseResource
from ici_acme.csr import validate
from ici_acme.data import Account, Order, Certificate, Challenge, Authorization
from ici_acme.utils import b64_decode, b64_encode
from ici_acme.exceptions import MissingParamMalformed


class OrderListResource(BaseResource):

    def on_post(self, req: Request, resp: Response):
        self.context.logger.info(f'Processing order list')
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
            if cert.certificate is None:
                self.context.logger.debug(f'Certificate {order.certificate_id} not completed')
            else:
                self.context.logger.debug(f'Certificate {order.certificate_id} is now completed')
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
            self.context.logger.error('Not allowed call to finalize, order not in "ready" state')
            raise falcon.HTTPForbidden

        data = json.loads(req.context['jose_verified_data'].decode('utf-8'))
        # PEM format is plain base64 encoded
        csr = base64.b64encode(b64_decode(data['csr'])).decode('utf-8')
        if not validate(csr, order, self.context):
            raise falcon.HTTPForbidden

        order.certificate_id = b64_encode(os.urandom(128 // 8))
        cert = Certificate(csr=csr,
                           created=datetime.datetime.now(tz=datetime.timezone.utc),
                           )
        self.context.store.save('certificate', order.certificate_id, cert.to_dict())
        self.context.store.save('order', order.id, order.to_dict())

        super().on_post(req, resp, order.id)


class NewOrderResource(BaseResource):

    def on_post(self, req: Request, resp: Response):
        self.context.logger.info(f'Creating a new order for account {req.context["account"].id}')
        # Decode the clients order, e.g.
        #  {"identifiers": [{"type": "dns", "value": "test.test"}]}
        acme_request = json.loads(req.context['jose_verified_data'].decode('utf-8'))
        if not acme_request.get('identifiers'):
            raise MissingParamMalformed(param_name='identifiers')

        authorizations = []
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        for ident in acme_request['identifiers']:
            challenge_id = b64_encode(os.urandom(128 // 8))
            chall = Challenge(id=challenge_id,
                              type='x-sunet-01',
                              url=self.url_for('challenge', challenge_id),
                              status='valid',
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
                                  challenge_ids=[chall.id],
                                  )
            self.context.store.save('authorization', authz.id, authz.to_dict())
            authorizations += [authz]

        order = Order(id=b64_encode(os.urandom(128 // 8)),
                      created=datetime.datetime.now(tz=datetime.timezone.utc),
                      identifiers=acme_request['identifiers'],
                      authorization_ids=[x.id for x in authorizations],
                      status='pending',
                      expires=now + datetime.timedelta(minutes=3),
                      )
        account = req.context['account']
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        account.last_order = now
        # remove any expired orders on this account
        for this in account.order_ids:
            expires = this['expires'].replace(tzinfo=datetime.timezone.utc)
            if expires < now:
                self.context.store.purge_order(this['id'])
                account.order_ids.remove(this)
                self.context.logger.info(f'Removed expired order {this["id"]}')
        # remove any expired preauths on this account
        for this in account.preauth_ids:
            expires = this['expires'].replace(tzinfo=datetime.timezone.utc)
            if expires < now:
                self.context.store.delete('authorization', this['id'])
                account.preauth_ids.remove(this)
                self.context.logger.info(f'Removed expired pre-auth {this["id"]}')
        account.order_ids += [{'id': order.id,
                               'expires': order.expires,
                               }]
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
