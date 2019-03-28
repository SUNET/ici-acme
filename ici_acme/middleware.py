# -*- coding: utf-8 -*-

from jose import jws
import json
from falcon import Request, Response, HTTPForbidden
from ici_acme.context import Context
from ici_acme.utils import b64_decode

__author__ = 'lundberg'


class HandleJOSE(object):

    def __init__(self, context: Context):
        self.context = context

    def process_request(self, req: Request, resp: Response):
        # TODO: The value of the "url" header parameter MUST be a string representing the target URL.
        self.context.logger.info(f'\n\n\nIN HandleJose PROCESS_REQUEST: {req.method} {req.path}')
        if req.method == 'POST':
            data = req.media
            token = f'{data["protected"]}.{data["payload"]}.{data["signature"]}'
            # self.context.logger.info(f'TOKEN: {token}')
            # self.context.logger.info(f'DATA: {data}')
            self.context.logger.info(f'HEADERS: {jws.get_unverified_headers(token)}')
            self.context.logger.info(f'CLAIMS: {jws.get_unverified_claims(token)}')

            if req.path.endswith('/new-account') or req.path.endswith('/new-account/'):
                protected = json.loads(b64_decode(data['protected']))
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
                protected = json.loads(b64_decode(account.jwk_data))
                jwk = protected['jwk']
            ret = jws.verify(token, jwk, algorithms='RS256')  # TODO - support other algorithms
            self.context.logger.info(f'Verified data: {ret}')
            req.context['jose_verified_data'] = ret
            req.context['jose_unverified_data'] = data


class HandleReplayNonce(object):

    def __init__(self, context: Context):
        self.context = context

    def process_request(self, req: Request, resp: Response):
        self.context.logger.info(f'\n\n\nIN HandleReplayNonce PROCESS_REQUEST: {req.method} {req.path}')

        if req.method == 'POST':
            # TODO: verify the nonce
            # self.context.logger.info(f'jose_verified_data: {req.context.get("jose_verified_data", None)}')
            # self.context.logger.info(f'jose_unverified_data: {req.context.get("jose_unverified_data", None)}')
            pass

    # Can't import BaseResource from app for resource typing due to circular dependency
    def process_response(self, req: Request, resp: Response, resource, req_succeeded: bool):
        self.context.logger.info(f'\n\n\nIN HandleReplayNonce PROCESS_RESPONSE: {req.method} {req.path} - {resource} {req_succeeded}')
        if req.method == 'POST':
            resp.set_header('Replay-Nonce', self.context.new_nonce)

