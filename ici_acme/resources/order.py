import base64
import datetime
import json
import os
import random
from typing import List, Mapping, Sequence

import falcon
from falcon import Request, Response

from ici_acme.base import BaseResource
from ici_acme.csr import validate
from ici_acme.data import Account, Authorization, Certificate, Order
from ici_acme.exceptions import MissingParamMalformed, OrderNotReady, RejectedIdentifier
from ici_acme.utils import b64_decode, b64_encode


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
            valid_count = 0
            for authz_id in order.authorization_ids:
                auth = self.context.store.load_authorization(authz_id)
                if auth.status == 'pending':
                    # check if authorization has now completed
                    for chall_id in auth.challenge_ids:
                        challenge = self.context.store.load_challenge(chall_id)
                        if challenge.status == 'valid':
                            self.context.logger.info(f'Challenge {chall_id} valid, setting authorization {auth.id} '
                                                     f'status to valid')
                            auth.status = 'valid'
                            self.context.logger.debug(f'Challenge: {challenge}')
                            self.context.logger.debug(f'Authorization: {auth}')
                            self.context.store.save('authorization', auth.id, auth.to_dict())
                if auth.status == 'valid':
                    valid_count += 1
                else:
                    self.context.logger.info(f'Authorization {auth} still not valid')
            if valid_count and valid_count == len(order.authorization_ids):
                self.context.logger.info(f'All {valid_count} authorizations are valid, marking order as ready')
                order.status = 'ready'

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
            self.context.logger.error('Not allowed call to finalize, order not in "ready" state')
            raise OrderNotReady

        data = json.loads(req.context['jose_verified_data'].decode('utf-8'))
        # PEM format is plain base64 encoded
        csr = base64.b64encode(b64_decode(data['csr'])).decode('utf-8')

        if validate(csr, order, self.context):
            order.certificate_id = b64_encode(os.urandom(128 // 8))
            cert = Certificate(csr=csr, created=datetime.datetime.now(tz=datetime.timezone.utc))
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

        now = datetime.datetime.now(tz=datetime.timezone.utc)
        account = req.context['account']
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

        authorizations = self._get_authorizations(acme_request['identifiers'], now, account)

        if not authorizations:
            raise RejectedIdentifier(detail='Pre-authorization required')

        order = Order(id=b64_encode(os.urandom(128 // 8)),
                      created=datetime.datetime.now(tz=datetime.timezone.utc),
                      identifiers=acme_request['identifiers'],
                      authorization_ids=[x.id for x in authorizations],
                      status='pending',
                      expires=now + datetime.timedelta(minutes=3),
                      )
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        account.last_order = now
        account.order_ids += [{'id': order.id,
                               'expires': order.expires,
                               }]
        self.context.store.save('order', order.id, order.to_dict())
        self.context.store.save('account', account.id, account.to_dict())
        self.context.logger.debug(f'Account: {account}')
        self.context.logger.debug(f'Order: {order}')
        resp.media = {
            'status': 'pending',
            'identifiers': order.identifiers,
            'authorizations': [self.url_for('authz', authz_id) for authz_id in order.authorization_ids],
            'finalize': self.url_for('order', order.id, 'finalize')
        }
        resp.set_header('Location', self.url_for('order', order.id))
        resp.status = falcon.HTTP_201

    def _get_authorizations(self, identifiers: Mapping, now: datetime, account: Account) -> Sequence[Authorization]:
        pre_auths: List[Authorization] = []
        for this in account.preauth_ids:
            _pre_auth = self.context.store.load_authorization(this['id'])
            pre_auths += [_pre_auth]

        res = []
        for ident in identifiers:
            # check if there exists a pre-authorization for this identifier, if so - use that one
            for pre_auth in pre_auths:
                if pre_auth.identifier == ident:
                    self.context.logger.info(f'Using pre-authorization {pre_auth.id} for identifier {ident}')
                    self.context.logger.debug(pre_auth)
                    self.context.store.save('authorization', pre_auth.id, pre_auth.to_dict())
                    res += [pre_auth]

                    # remove pre-auth from account when used (yes, this is full of race conditions)
                    account.preauth_ids = [x for x in account.preauth_ids if x['id'] != pre_auth.id]
                    self.context.store.save('account', account.id, account.to_dict())
                    self.context.logger.debug(f'Account after removing pre-auth {pre_auth}: {account}')

        return res

