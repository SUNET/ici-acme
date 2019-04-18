# -*- coding: utf-8 -*-

import json
from jose import jws
from jose.constants import Algorithms
from jose.exceptions import JOSEError
from falcon import Request, Response
from ici_acme.base import BaseResource
from ici_acme.context import Context
from ici_acme.utils import b64_decode
from ici_acme.exceptions import UnsupportedMediaTypeMalformed, Unauthorized, BadSignatureAlgorithm
from ici_acme.exceptions import ServerInternal, BadNonce

__author__ = 'lundberg'


class HandleJOSE(object):

    def __init__(self, context: Context):
        self.context = context

    def process_request(self, req: Request, resp: Response):
        self.context.logger.info(f'\n\n\nIN HandleJose PROCESS_REQUEST: {req.method} {req.path}')
        if req.method == 'POST':
            if req.content_type != 'application/jose+json':
                raise UnsupportedMediaTypeMalformed(detail=f'{req.content_type} is an unsupported media type')

            supported_algorithms = [Algorithms.RS256, Algorithms.ES256, Algorithms.ES384]
            data = req.media
            token = f'{data["protected"]}.{data["payload"]}.{data["signature"]}'
            self.context.logger.debug(f'HEADERS: {jws.get_unverified_headers(token)}')
            self.context.logger.debug(f'CLAIMS: {jws.get_unverified_claims(token)}')

            headers = jws.get_unverified_headers(token)
            protected = json.loads(b64_decode(data['protected']))

            if headers.get('kid') and protected.get('jwk'):
                raise Unauthorized(detail='The "jwk" and "kid" fields are mutually exclusive')

            if headers.get('url') != req.uri:
                raise Unauthorized(detail=f'JWS header URL ({headers.get("url")})'
                                          f' does not match requested URL ({req.uri})')
            # Existing account
            kid = headers.get('kid', None)
            account = self.context.get_account_using_kid(kid)
            if account:
                if account.status != 'valid':
                    self.context.logger.info(f'Account {account} deactivated')
                    raise Unauthorized(detail='Account deactivated')
                self.context.logger.info(f'Authenticating request for account {account}')
                req.context['account'] = account
                jwk = account.jwk
            # Account registration
            elif req.path.endswith('/new-account') or req.path.endswith('/new-account/'):
                jwk = protected['jwk']
                if protected['alg'] not in supported_algorithms:
                    raise BadSignatureAlgorithm(algorithms=supported_algorithms)
                req.context['account_creation'] = True
            else:
                self.context.logger.warning(f'Account not found using kid {kid}')
                raise Unauthorized(detail='Account not found')

            try:
                ret = jws.verify(token, jwk, algorithms=supported_algorithms)
            except JOSEError as e:
                self.context.logger.error(f'Exception while verifying token: {e}')
                raise ServerInternal(detail=f'{e}')

            self.context.logger.debug(f'Headers: {headers}')
            self.context.logger.debug(f'Verified data: {ret}')
            req.context['jose_verified_data'] = ret
            req.context['jose_headers'] = headers


class HandleReplayNonce(object):

    def __init__(self, context: Context):
        self.context = context

    def process_request(self, req: Request, resp: Response):
        self.context.logger.debug(f'\n\n\nIN HandleReplayNonce PROCESS_REQUEST: {req.method} {req.path}')

        if req.method == 'POST':
            nonce = req.context['jose_headers'].get('nonce')
            if not nonce or not self.context.check_nonce(nonce):
                self.context.logger.info(f'Nonce {nonce} was not found')
                raise BadNonce(new_nonce=self.context.new_nonce)

    def process_response(self, req: Request, resp: Response, resource: BaseResource, req_succeeded: bool):
        self.context.logger.debug(f'\n\n\nIN HandleReplayNonce PROCESS_RESPONSE: {req.method}'
                                  f' {req.path} - {resource} {req_succeeded}')
        if req.method == 'POST':
            resp.set_header('Replay-Nonce', self.context.new_nonce)

