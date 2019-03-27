# -*- coding: utf-8 -*-

import base64
from jose import jws
import json
from falcon import Request, Response, HTTPForbidden
from ici_acme.context import Context

__author__ = 'lundberg'


class HandleJOSE(object):

    def __init__(self, context: Context):
        self.context = context

    def process_request(self, req: Request, resp: Response):
        # TODO: The value of the "url" header parameter MUST be a string representing the target URL.
        self.context.logger.info(f'\n\n\nIN PROCESS_REQUEST: {req.method} {req.path}')
        if req.method == 'POST':
            data = req.media
            token = f'{data["protected"]}.{data["payload"]}.{data["signature"]}'
            # self.context.logger.info(f'TOKEN: {token}')
            # self.context.logger.info(f'DATA: {data}')
            self.context.logger.info(f'HEADERS: {jws.get_unverified_headers(token)}')
            self.context.logger.info(f'CLAIMS: {jws.get_unverified_claims(token)}')

            if req.path.endswith('/new-account') or req.path.endswith('/new-account/'):
                protected = json.loads(base64.b64decode(data['protected']))
                jwk = protected['jwk']
                assert protected['alg'] == 'RS256'  # TODO
                req.context['account_creation'] = True
            else:
                headers = jws.get_unverified_headers(token)
                kid = headers['kid']
                account = self.context.get_account_using_kid(kid)
                if not account:
                    self.context.logger.warning(f'Account not found using kid {kid}')
                    raise HTTPForbidden('Account not found')
                self.context.logger.info(f'Authenticating request for account {account}')
                req.context['account'] = account
                protected = json.loads(base64.b64decode(account.jwk_data))
                jwk = protected['jwk']
            ret = jws.verify(token, jwk, algorithms='RS256')  # TODO
            self.context.logger.info(f'Verified data: {ret}')
            req.context['jose_verified_data'] = ret
            req.context['jose_unverified_data'] = data

