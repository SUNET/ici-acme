# -*- coding: utf-8 -*-

import base64
from jose import jws
import json
from falcon import Request, Response, HTTPForbidden
from ici_acme.utils import Context

__author__ = 'lundberg'


class HandleJOSE(object):

    def __init__(self, context: Context):
        self.context = context

    def process_request(self, req: Request, resp: Response):
        # TODO: The value of the "url" header parameter MUST be a string representing the target URL.
        self.context.logger.info('IN HANDLEJOSE')
        if req.method == 'POST':
            self.context.logger.info('IN POST')
            data = req.media
            token = f'{data["protected"]}.{data["payload"]}.{data["signature"]}'
            self.context.logger.info(token)
            if req.path.endswith('/new-account'):
                self.context.logger.info('IN NEW-ACCOUNT')
                protected = json.loads(base64.b64decode(data['protected']))
                jwk = protected['jwk']
                assert protected['alg'] == 'RS256'  # TODO
                req.context['account_creation'] = True
            else:
                self.context.logger.info(f'DATA: {data}')
            ret = jws.verify(token, jwk, algorithms='RS256')  # TODO
            self.context.logger.info(ret)
            req.context['jose_verified_data'] = data

