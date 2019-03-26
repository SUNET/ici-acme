# -*- coding: utf-8 -*-

import base64

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


def b64_urlsafe(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode('utf-8').strip('=')
