# -*- coding: utf-8 -*-
from __future__ import annotations

import falcon
import json
import logging
import traceback
import uuid

from typing import Optional, Dict, List
from dataclasses import dataclass, asdict

from ici_acme.utils import filter_none

__author__ = 'lundberg'

logger = logging.getLogger(__name__)

# HTTP/1.1 403 Forbidden
# Content-Type: application/problem+json
# Link: <https://example.com/acme/directory>;rel="index"
#
# {
#     "type": "urn:ietf:params:acme:error:malformed",
#     "detail": "Some of the identifiers requested were rejected",
#     "subproblems": [
#         {
#             "type": "urn:ietf:params:acme:error:malformed",
#             "detail": "Invalid underscore in DNS name \"_example.org\"",
#             "identifier": {
#                 "type": "dns",
#                 "value": "_example.org"
#             }
#         },
#         {
#             "type": "urn:ietf:params:acme:error:rejectedIdentifier",
#             "detail": "This CA will not issue for \"example.net\"",
#             "identifier": {
#                 "type": "dns",
#                 "value": "example.net"
#             }
#         }
#     ]
# }


@dataclass
class ErrorDetail(object):
    type: str
    title: Optional[str] = None
    status: Optional[int] = None
    detail: Optional[str] = None
    instance: Optional[str] = None
    algorithms: Optional[list] = None
    subproblems: Optional[List[Subproblem]] = None


@dataclass
class Subproblem(object):
    type: str
    detail: Optional[str] = None
    identifier: Optional[Dict[str, str]] = None


# Catch and handle falcons default exceptions
def method_not_allowed_handler(ex: falcon.HTTPMethodNotAllowed, req: falcon.Request, resp: falcon.Response, params):
    orig_headers = ex.headers
    e = MethodNotAllowedMalformed(allowed_methods=orig_headers.get('Allow').split(','))
    e.extra_headers = orig_headers
    return e.handle(e, req, resp, params)


def unsupported_media_type_handler(ex: falcon.HTTPUnsupportedMediaType, req: falcon.Request, resp: falcon.Response,
                                   params):
    e = UnsupportedMediaTypeMalformed(detail=ex.description)
    return e.handle(e, req, resp, params)


def unexpected_error_handler(ex: Exception, req: falcon.Request, resp: falcon.Response, params):
    error_id = uuid.uuid4()
    logger.error(f'Unexpected error {error_id}: {ex}')
    logger.error(traceback.format_exc())
    e = ServerInternal()
    e.error_detail.detail = f'Please reference the error id {error_id} when reporting this issue'
    return e.handle(e, req, resp, params)


class HTTPErrorDetail(falcon.HTTPError):

    def __init__(self, **kwargs):
        typ = kwargs.pop('type')
        detail = kwargs.pop('detail', None)
        instance = kwargs.pop('instance', None)
        subproblems = kwargs.pop('subproblems', None)
        self._error_detail: Optional[ErrorDetail] = ErrorDetail(type=typ, detail=detail, instance=instance,
                                                                subproblems=subproblems)
        self._extra_headers: Optional[Dict] = None
        super().__init__(**kwargs)

    @property
    def error_detail(self):
        return self._error_detail

    @property
    def extra_headers(self):
        return self._extra_headers

    @extra_headers.setter
    def extra_headers(self, headers: Dict):
        self._extra_headers = headers

    def to_dict(self, obj_type=dict):
        result = super().to_dict(obj_type)
        result.update(filter_none(asdict(self._error_detail)))
        return result

    @staticmethod
    def handle(ex: HTTPErrorDetail, req: falcon.Request, resp: falcon.Response, params):
        resp.status = ex.status
        resp.content_type = 'application/problem+json'
        if not ex.error_detail.instance:
            ex.error_detail.instance = req.uri
        resp.body = json.dumps(ex.to_dict())
        if ex.extra_headers:
            for key, value in ex.extra_headers.items():
                resp.set_header(key, value)


class BadRequest(HTTPErrorDetail, falcon.HTTPBadRequest):
    def __init__(self, **kwargs):
        super().__init__(type='x-error:badRequest', **kwargs)
        if not self.error_detail.title:
            self.error_detail.title = 'Bad Request'


class AccountDoesNotExist(HTTPErrorDetail, falcon.HTTPBadRequest):

    def __init__(self, **kwargs):
        super().__init__(type='urn:ietf:params:acme:error:accountDoesNotExist', **kwargs)
        if not self.error_detail.title:
            self.error_detail.title = 'Account does not exist'
        if not self.error_detail.detail:
            self.error_detail.detail = 'Specified account does not exist and onlyReturnExisting=True requested'


class AlreadyRevoked(HTTPErrorDetail, falcon.HTTPBadRequest):

    def __init__(self, **kwargs):
        super().__init__(type='urn:ietf:params:acme:error:alreadyRevoked', **kwargs)
        if not self.error_detail.title:
            self.error_detail.title = 'Already revoked'
        if not self.error_detail.detail:
            self.error_detail.detail = 'Specified certificate to be revoked has already been revoked'


class BadCSR(HTTPErrorDetail, falcon.HTTPBadRequest):

    def __init__(self, **kwargs):
        super().__init__(type='urn:ietf:params:acme:error:badCSR', **kwargs)
        if not self.error_detail.title:
            self.error_detail.title = 'Bad CSR'
        if not self.error_detail.detail:
            self.error_detail.detail = 'The CSR is unacceptable'


class BadNonce(HTTPErrorDetail, falcon.HTTPBadRequest):

    def __init__(self, **kwargs):
        new_nonce = kwargs.pop('new_nonce', None)
        super().__init__(type='urn:ietf:params:acme:error:badNonce', **kwargs)
        if not self.error_detail.title:
            self.error_detail.title = 'Bad nonce'
        if not self.error_detail.detail:
            self.error_detail.detail = 'The client sent an unacceptable anti-replay nonce'
        if new_nonce:
            self.extra_headers = {
                'Replay-Nonce': new_nonce,
                'Cache-Control': 'no-store'
            }


class BadPublicKey(HTTPErrorDetail, falcon.HTTPBadRequest):

    def __init__(self, **kwargs):
        super().__init__(type='urn:ietf:params:acme:error:badPublicKey', **kwargs)
        if not self.error_detail.title:
            self.error_detail.title = 'Bad public key'
        if not self.error_detail.detail:
            self.error_detail.detail = 'The JWS was signed by a public key the server does not support'


class BadRevocationReason(HTTPErrorDetail, falcon.HTTPBadRequest):

    def __init__(self, **kwargs):
        super().__init__(type='urn:ietf:params:acme:error:badRevocationReason', **kwargs)
        if not self.error_detail.title:
            self.error_detail.title = 'Bad revocation reason'
        if not self.error_detail.detail:
            self.error_detail.detail = 'The revocation reason provided is not allowed by the server'


class BadSignatureAlgorithm(HTTPErrorDetail, falcon.HTTPBadRequest):

    def __init__(self, **kwargs):
        algorithms = kwargs.pop('algorithms')
        super().__init__(type='urn:ietf:params:acme:error:badSignatureAlgorithm', **kwargs)
        if not self.error_detail.title:
            self.error_detail.title = 'Bad signature algorithm'
        if not self.error_detail.detail:
            self.error_detail.detail = 'The JWS was signed with an algorithm the server does not support'
        if not self.error_detail.algorithms:
            self.error_detail.algorithms = algorithms


class CAAForbids(HTTPErrorDetail, falcon.HTTPBadRequest):

    def __init__(self, **kwargs):
        super().__init__(type='urn:ietf:params:acme:error:caa', **kwargs)
        if not self.error_detail.title:
            self.error_detail.title = 'CAA Forbids'
        if not self.error_detail.detail:
            self.error_detail.detail = 'Certification Authority Authorization (CAA) records forbid the CA from issuing\
             a certificate'


class CompoundException(HTTPErrorDetail, falcon.HTTPBadRequest):

    def __init__(self, **kwargs):
        super().__init__(type='urn:ietf:params:acme:error:compound', **kwargs)
        if not self.error_detail.title:
            self.error_detail.title = 'Compound problem'
        if not self.error_detail.detail:
            self.error_detail.detail = 'See subproblems for details'


class ConnectionException(HTTPErrorDetail, falcon.HTTPBadRequest):
    def __init__(self, **kwargs):
        super().__init__(type='urn:ietf:params:acme:error:connection', **kwargs)
        if not self.error_detail.title:
            self.error_detail.title = 'Connection problem'
        if not self.error_detail.detail:
            self.error_detail.detail = 'The server could not connect to validation target'


class DNSException(HTTPErrorDetail, falcon.HTTPBadRequest):
    def __init__(self, **kwargs):
        super().__init__(type='urn:ietf:params:acme:error:dns', **kwargs)
        if not self.error_detail.title:
            self.error_detail.title = 'DNS problem'
        if not self.error_detail.detail:
            self.error_detail.detail = 'There was a problem with a DNS query during identifier validation'


class ExternalAccountRequired(HTTPErrorDetail, falcon.HTTPBadRequest):
    def __init__(self, **kwargs):
        super().__init__(type='urn:ietf:params:acme:error:externalAccountRequired', **kwargs)
        if not self.error_detail.title:
            self.error_detail.title = 'External account required'
        if not self.error_detail.detail:
            self.error_detail.detail = 'The request must include a value for the "externalAccountBinding" field'


class IncorrectResponse(HTTPErrorDetail, falcon.HTTPUnauthorized):
    def __init__(self, **kwargs):
        super().__init__(type='urn:ietf:params:acme:error:incorrectResponse', **kwargs)
        if not self.error_detail.title:
            self.error_detail.title = 'Incorrect response'
        if not self.error_detail.detail:
            self.error_detail.detail = 'Response received did not match the challenge\'s requirements'


class InvalidContact(HTTPErrorDetail, falcon.HTTPBadRequest):
    def __init__(self, **kwargs):
        super().__init__(type='urn:ietf:params:acme:error:malformed', **kwargs)
        if not self.error_detail.title:
            self.error_detail.title = 'Invalid contact'
        if not self.error_detail.detail:
            self.error_detail.detail = 'A contact URL for an account was invalid'


class MethodNotAllowedMalformed(HTTPErrorDetail, falcon.HTTPMethodNotAllowed):
    def __init__(self, **kwargs):
        super().__init__(type='urn:ietf:params:acme:error:malformed', **kwargs)
        if not self.error_detail.title:
            self.error_detail.title = 'Method not allowed'
        if not self.error_detail.detail:
            allowed_methods = kwargs.get('allowed_methods')
            self.error_detail.detail = f'The used HTTP method is not allowed. Allowed methods: {allowed_methods}'


class MissingParamMalformed(HTTPErrorDetail, falcon.HTTPMissingParam):
    def __init__(self, **kwargs):
        super().__init__(type='urn:ietf:params:acme:error:malformed', **kwargs)
        if not self.error_detail.title:
            self.error_detail.title = 'Missing parameter'
        if not self.error_detail.detail:
            param_name = kwargs.get('param_name')
            self.error_detail.detail = f'The "{param_name}" parameter is required.'


class OrderNotReady(HTTPErrorDetail, falcon.HTTPForbidden):
    def __init__(self, **kwargs):
        super().__init__(type='urn:ietf:params:acme:error:orderNotReady', **kwargs)
        if not self.error_detail.title:
            self.error_detail.title = 'Order not ready'
        if not self.error_detail.detail:
            self.error_detail.detail = 'The request attempted to finalize an order that is not ready to be finalized'


class RateLimited(HTTPErrorDetail, falcon.HTTPServiceUnavailable):
    def __init__(self, **kwargs):
        retry_after = kwargs.pop('retry_after', None)
        super().__init__(type='urn:ietf:params:acme:error:rateLimited', **kwargs)
        if not self.error_detail.title:
            self.error_detail.title = 'Rate limited'
        if not self.error_detail.detail:
            self.error_detail.detail = 'The request exceeds a rate limit '
        if retry_after:
            self.extra_headers = {'Retry-After': retry_after}


class RejectedIdentifier(HTTPErrorDetail, falcon.HTTPForbidden):
    def __init__(self, **kwargs):
        super().__init__(type='urn:ietf:params:acme:error:rejectedIdentifier', **kwargs)
        if not self.error_detail.title:
            self.error_detail.title = 'Rejected identifier'
        if not self.error_detail.detail:
            self.error_detail.detail = 'The server will not issue certificates for the identifier'


class ServerInternal(HTTPErrorDetail, falcon.HTTPInternalServerError):
    def __init__(self, **kwargs):
        super().__init__(type='urn:ietf:params:acme:error:serverInternal', **kwargs)
        if not self.error_detail.title:
            self.error_detail.title = 'Internal server error'


class TLSException(HTTPErrorDetail, falcon.HTTPBadRequest):
    def __init__(self, **kwargs):
        super().__init__(type='urn:ietf:params:acme:error:tls', **kwargs)
        if not self.error_detail.title:
            self.error_detail.title = 'TLS problem'
        if not self.error_detail.detail:
            self.error_detail.detail = 'The server received a TLS error during validation'


class Unauthorized(HTTPErrorDetail, falcon.HTTPUnauthorized):
    def __init__(self, **kwargs):
        super().__init__(type='urn:ietf:params:acme:error:unauthorized', **kwargs)
        if not self.error_detail.title:
            self.error_detail.title = 'Unauthorized'
        if not self.error_detail.detail:
            self.error_detail.detail = 'Unauthorized request'


class UnsupportedContact(HTTPErrorDetail, falcon.HTTPBadRequest):
    def __init__(self, **kwargs):
        super().__init__(type='urn:ietf:params:acme:error:unsupportedContact', **kwargs)
        if not self.error_detail.title:
            self.error_detail.title = 'Unsupported contact'
        if not self.error_detail.detail:
            self.error_detail.detail = 'A contact URL for the account used an unsupported protocol scheme'


class UnsupportedMediaTypeMalformed(HTTPErrorDetail, falcon.HTTPUnsupportedMediaType):
    def __init__(self, **kwargs):
        super().__init__(type='urn:ietf:params:acme:error:malformed', **kwargs)
        if not self.error_detail.title:
            self.error_detail.title = 'Unsupported media type'
        if not self.error_detail.detail:
            self.error_detail.detail = 'Request was made with an unsupported media type'


class UnsupportedIdentifier(HTTPErrorDetail, falcon.HTTPBadRequest):
    def __init__(self, **kwargs):
        super().__init__(type='urn:ietf:params:acme:error:unsupportedIdentifier', **kwargs)
        if not self.error_detail.title:
            self.error_detail.title = 'Unsupported identifier'
        if not self.error_detail.detail:
            self.error_detail.detail = 'An identifier is of an unsupported type'


class UserActionRequired(HTTPErrorDetail, falcon.HTTPBadRequest):
    def __init__(self, **kwargs):
        super().__init__(type='urn:ietf:params:acme:error:userActionRequired', **kwargs)
        if not self.error_detail.title:
            self.error_detail.title = 'User action required'
        if not self.error_detail.detail:
            self.error_detail.detail = 'Visit the "instance" URL and take actions specified there'
