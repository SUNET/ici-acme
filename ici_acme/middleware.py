# -*- coding: utf-8 -*-

from jose import jws
import json
from falcon import Request, Response, HTTPForbidden
from ici_acme.context import Context
from ici_acme.utils import b64_decode
from ici_acme.exceptions import BadRequest, Unauthorized, BadSignatureAlgorithm

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
                    raise Unauthorized(detail='Account deactivated')
                self.context.logger.info(f'Authenticating request for account {account}')
                req.context['account'] = account
                jwk = json.loads(b64_decode(account.jwk_data))['jwk']
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

            # The value of the "nonce" header parameter MUST be an octet string, encoded according to the base64url
            # encoding described in Section 2 of [RFC7515].  If the value of a "nonce" header parameter is not valid
            # according to this encoding, then the verifier MUST reject the JWS as malformed.

            # self.context.logger.info(f'jose_verified_data: {req.context.get("jose_verified_data", None)}')
            # self.context.logger.info(f'jose_unverified_data: {req.context.get("jose_unverified_data", None)}')
            pass

    # Can't import BaseResource from app for resource typing due to circular dependency
    def process_response(self, req: Request, resp: Response, resource, req_succeeded: bool):
        self.context.logger.info(f'\n\n\nIN HandleReplayNonce PROCESS_RESPONSE: {req.method} {req.path} - {resource} {req_succeeded}')
        if req.method == 'POST':
            resp.set_header('Replay-Nonce', self.context.new_nonce)

