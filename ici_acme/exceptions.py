# -*- coding: utf-8 -*-
from __future__ import annotations

import falcon
import json

from typing import Optional, Union, Dict, List, Tuple
from dataclasses import dataclass, asdict

from ici_acme.utils import filter_none

__author__ = 'lundberg'


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


class HTTPErrorDetail(falcon.HTTPError):

    def __init__(self, **kwargs):
        typ = kwargs.pop('type')
        detail = kwargs.pop('detail', None)
        instance = kwargs.pop('instance', None)
        subproblems = kwargs.pop('subproblems', None)
        self._error_detail: Optional[ErrorDetail] = ErrorDetail(type=typ, detail=detail, instance=instance,
                                                                subproblems=subproblems)
        super().__init__(**kwargs)

    @property
    def error_detail(self):
        return self._error_detail

    def to_dict(self, obj_type=dict):
        result = super().to_dict(obj_type)
        result.update(filter_none(asdict(self._error_detail)))
        return result

    @staticmethod
    def handle(ex: HTTPErrorDetail, req: falcon.Request, resp: falcon.Response, params):
        resp.status = ex.status
        resp.content_type = 'application/problem+json'
        ex.error_detail.instance = req.uri
        resp.body = json.dumps(ex.to_dict())


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
        super().__init__(type='urn:ietf:params:acme:error:badNonce', **kwargs)
        if not self.error_detail.title:
            self.error_detail.title = 'Bad nonce'
        if not self.error_detail.detail:
            self.error_detail.detail = 'The client sent an unacceptable anti-replay nonce'


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
        super().__init__(type='urn:ietf:params:acme:error:badSignatureAlgorithm', **kwargs)
        if not self.error_detail.title:
            self.error_detail.title = 'Bad signature algorithm'
        if not self.error_detail.detail:
            self.error_detail.detail = 'The JWS was signed with an algorithm the server does not support'
        if not self.error_detail.algorithms:
            self.error_detail.algorithms = kwargs['algorithms']


class MethodNotAllowedMalformed(HTTPErrorDetail, falcon.HTTPMethodNotAllowed):
    def __init__(self, **kwargs):
        super().__init__(type='urn:ietf:params:acme:error:malformed', **kwargs)
        if not self.error_detail.title:
            self.error_detail.title = 'Method not allowed'
        if not self.error_detail.detail:
            self.error_detail.detail = 'The used HTTP method is not allowed'


class MissingParamMalformed(HTTPErrorDetail, falcon.HTTPMissingParam):
    def __init__(self, **kwargs):
        super().__init__(type='urn:ietf:params:acme:error:malformed', **kwargs)
        if not self.error_detail.title:
            self.error_detail.title = 'Missing parameter'
        if not self.error_detail.detail:
            param_name = kwargs.get('param_name')
            self.error_detail.detail = f'The "{param_name}" parameter is required.'


class ServerInternal(HTTPErrorDetail, falcon.HTTPInternalServerError):
    def __init__(self, **kwargs):
        super().__init__(type='urn:ietf:params:acme:error:serverInternal', **kwargs)
        if not self.error_detail.title:
            self.error_detail.title = 'Internal server error'


class Unauthorized(HTTPErrorDetail, falcon.HTTPUnauthorized):
    def __init__(self, **kwargs):
        super().__init__(type='urn:ietf:params:acme:error:unauthorized', **kwargs)
        if not self.error_detail.title:
            self.error_detail.title = 'Unauthorized'
        if not self.error_detail.detail:
            self.error_detail.detail = 'Unauthorized request'
