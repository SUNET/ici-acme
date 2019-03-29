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

