# -*- coding: utf-8 -*-

import json
from jose import jws
from jose.exceptions import JOSEError
from falcon import Request, Response
from ici_acme.base import BaseResource
from ici_acme.context import Context
from ici_acme.utils import b64_decode
from ici_acme.exceptions import BadRequest, Unauthorized, BadSignatureAlgorithm, ServerInternal, BadNonce

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
            self.context.logger.debug(f'HEADERS: {jws.get_unverified_headers(token)}')
            self.context.logger.debug(f'CLAIMS: {jws.get_unverified_claims(token)}')

            headers = jws.get_unverified_headers(token)
            protected = json.loads(b64_decode(data['protected']))

            if headers.get('kid') and protected.get('jwk'):
                raise BadRequest(detail='The "jwk" and "kid" fields are mutually exclusive')

            kid = headers['kid']
            account = self.context.get_account_using_kid(kid)
            if account:
                if account.status != 'valid':
                    self.context.logger.info(f'Account {account} deactivated')
                    raise Unauthorized(detail='Account deactivated')
                self.context.logger.info(f'Authenticating request for account {account}')
                req.context['account'] = account
                jwk = account.jwk
            elif req.path.endswith('/new-account') or req.path.endswith('/new-account/'):
                jwk = protected['jwk']
                if not protected['alg'] == 'RS256':
                    # TODO:  An ACME server MUST implement the "ES256" signature algorithm [RFC7518] and SHOULD
                    #  implement the "EdDSA" signature algorithm using
                    #  the "Ed25519" variant (indicated by "crv") [RFC8037].
                    raise BadSignatureAlgorithm(algorithms=['RS256'])
                req.context['account_creation'] = True
            else:
                self.context.logger.warning(f'Account not found using kid {kid}')
                raise Unauthorized(detail='Account not found')

            try:
                ret = jws.verify(token, jwk, algorithms=['RS256', 'ES256', 'ES384'])
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

