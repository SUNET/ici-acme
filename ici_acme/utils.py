# -*- coding: utf-8 -*-

import os
import sys
import base64
import logging
import hashlib

from typing import Dict

__author__ = 'lundberg'


def urlappend(base: str, path: str) -> str:
    """
    :param base: Base url
    :type base: six.string_types
    :param path: Path to join to base
    :type path: six.string_types
    :return: Joined url
    :rtype: six.string_types

    Used instead of urlparse.urljoin to append path to base in an obvious way.

    >>> urlappend('https://test.com/base-path', 'my-path')
    'https://test.com/base-path/my-path'
    >>> urlappend('https://test.com/base-path/', 'my-path')
    'https://test.com/base-path/my-path'
    >>> urlappend('https://test.com/base-path/', '/my-path')
    'https://test.com/base-path/my-path'
    >>> urlappend('https://test.com/base-path', '/my-path')
    'https://test.com/base-path/my-path'
    >>> urlappend('https://test.com/base-path', '/my-path/')
    'https://test.com/base-path/my-path/'
    """
    path = path.lstrip('/')
    if not base.endswith('/'):
        base = '{!s}/'.format(base)
    return '{!s}{!s}'.format(base, path)


def _b64_urlsafe(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode('utf-8').strip('=')


class Context(object):

    def __init__(self):
        self._nonces: Dict[str, bool] = {}
        self._accounts: Dict[str, str] = {}

        self.server_name: str = 'localhost:8000'
        self.application_root: str = ''

        self.logger = logging.getLogger(__name__)
        self.logger.addHandler(logging.StreamHandler(sys.stdout))
        self.logger.setLevel(logging.DEBUG)

    def check_nonce(self, nonce) -> bool:
        return self._nonces.pop(nonce, False)

    @property
    def new_nonce(self) -> str:
        nonce = _b64_urlsafe(os.urandom(128//8))
        self._nonces[nonce] = True
        return nonce

    @property
    def base_url(self) -> str:
        if self.application_root:
            return urlappend(self.server_name, self.application_root)
        return self.server_name

    def save_account(self, jwk: str) -> str:
        name = _b64_urlsafe(hashlib.sha256(jwk.encode()).digest())
        self._accounts[name] = jwk
        return name


