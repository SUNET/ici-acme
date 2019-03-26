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
        self.context.logger.info(f'IN HANDLEJOSE: {req.path}')
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
                self.context.logger.info(f'HEADERS: {jws.get_unverified_headers(token)}')
                self.context.logger.info(f'CLAIMS: {jws.get_unverified_claims(token)}')
                headers = jws.get_unverified_headers(token)
                kid = headers['kid']
                account = self.context.get_account_using_kid(kid)
                if not account:
                    raise HTTPForbidden('Account not found')
                self.context.logger.info(f'Authenticating request for account {account}')
                req.context['account'] = account
                protected = json.loads(base64.b64decode(account.protected))
                jwk = protected['jwk']
            ret = jws.verify(token, jwk, algorithms='RS256')  # TODO
            self.context.logger.info(f'Verified data: {ret}')
            req.context['jose_verified_data'] = ret
            req.context['jose_unverified_data'] = data

