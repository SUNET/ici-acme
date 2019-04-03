# -*- coding: utf-8 -*-

import falcon

from ici_acme import exceptions
from ici_acme.context import Context
from ici_acme.store import Store
from ici_acme.middleware import HandleJOSE, HandleReplayNonce
from ici_acme.resources.account import AccountResource, NewAccountResource
from ici_acme.resources.misc import AuthorizationResource, ChallengeResource, CertificateResource, DirectoryResource
from ici_acme.resources.misc import NewNonceResource
from ici_acme.resources.order import OrderListResource, OrderResource, FinalizeOrderResource, NewOrderResource
from ici_acme.resources.preauth import FakeAuthResource, PreAuthResource

__author__ = 'lundberg'

#    Content-Type: application/json
#    Link: <https://example.com/acme/directory>;rel="index"

# gunicorn --reload ici_acme.app:api


store = Store('data')
context = Context(store)
context.logger.info('Starting app')

api = falcon.API(middleware=[HandleJOSE(context), HandleReplayNonce(context)])
api.req_options.media_handlers['application/jose+json'] = api.req_options.media_handlers['application/json']
api.add_error_handler(exceptions.HTTPErrorDetail)

api.add_route('/directory', DirectoryResource(context=context))
api.add_route('/new-nonce', NewNonceResource(context=context))
api.add_route('/new-account', NewAccountResource(context=context))
api.add_route('/new-order', NewOrderResource(context=context))
api.add_route('/authz/{authz_id}', AuthorizationResource(context=context))
api.add_route('/challenge/{challenge_id}', ChallengeResource(context=context))
api.add_route('/fakeauth/{client_data}', FakeAuthResource(context=context))
api.add_route('/ici-acme-preauth', PreAuthResource(context=context))
# OrderResource
api.add_route('/order', OrderListResource(context=context))
api.add_route('/order/{order_id}', OrderResource(context=context))
api.add_route('/order/{order_id}/finalize', FinalizeOrderResource(context=context))
# CertificateResource
api.add_route('/certificate/{certificate_id}', CertificateResource(context=context))
# AccountResource
api.add_route('/account/{account_id}', AccountResource(context=context))
context.logger.info('app running..')
