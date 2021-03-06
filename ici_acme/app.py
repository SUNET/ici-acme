# -*- coding: utf-8 -*-

import sys
import yaml
import falcon
from os import environ

from ici_acme import exceptions
from ici_acme.context import Context
from ici_acme.middleware import HandleJOSE, HandleReplayNonce
from ici_acme.resources.account import AccountResource, NewAccountResource
from ici_acme.resources.misc import AuthorizationResource, ChallengeResource, CertificateResource, DirectoryResource
from ici_acme.resources.misc import NewNonceResource
from ici_acme.resources.order import OrderListResource, OrderResource, FinalizeOrderResource, NewOrderResource
from ici_acme.resources.preauth import FakeAuthResource, PreAuthResource

__author__ = 'lundberg'

# Read config
config_path = environ.get('ICI_ACME_CONFIG')
config = dict()
if config_path:
    try:
        with open(config_path) as f:
            config = yaml.safe_load(f)
    except FileNotFoundError as e:
        print(e)
        sys.exit(1)

context = Context(config)
context.logger.info('Starting app')

api = falcon.API(middleware=[HandleJOSE(context), HandleReplayNonce(context)])
api.req_options.media_handlers['application/jose+json'] = api.req_options.media_handlers['application/json']

# Error handlers tried in reversed declaration order
api.add_error_handler(Exception, exceptions.unexpected_error_handler)
api.add_error_handler(falcon.HTTPMethodNotAllowed, exceptions.method_not_allowed_handler)
api.add_error_handler(falcon.HTTPUnsupportedMediaType, exceptions.unsupported_media_type_handler)
api.add_error_handler(exceptions.HTTPErrorDetail)

api.add_route('/', DirectoryResource(context=context))
api.add_route('/new-nonce', NewNonceResource(context=context))
api.add_route('/new-account', NewAccountResource(context=context))
api.add_route('/new-order', NewOrderResource(context=context))
api.add_route('/new-authz', PreAuthResource(context=context))
api.add_route('/authz/{authz_id}', AuthorizationResource(context=context))
api.add_route('/challenge/{challenge_id}', ChallengeResource(context=context))
# OrderResource
api.add_route('/order', OrderListResource(context=context))
api.add_route('/order/{order_id}', OrderResource(context=context))
api.add_route('/order/{order_id}/finalize', FinalizeOrderResource(context=context))
# CertificateResource
api.add_route('/certificate/{certificate_id}', CertificateResource(context=context))
# AccountResource
api.add_route('/account/{account_id}', AccountResource(context=context))

context.logger.info('app running...')
