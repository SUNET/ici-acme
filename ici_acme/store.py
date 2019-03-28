import os
import yaml

from typing import Mapping, Union

from ici_acme.data import Account, Order, Authorization, Challenge, Certificate


class Store(object):

    def __init__(self, datadir: str):
        self._datadir = datadir

    def save(self, type_: str, name: str, data: Mapping) -> None:
        fn = self._get_filename(type_, name)
        _tmpfile = fn + '.tmp'
        with open(_tmpfile, 'w') as fd:
            fd.write(yaml.safe_dump(data, indent=True))
        os.rename(_tmpfile, fn)

    def load(self, type_: str, name: str) -> Union[Mapping, Account, Authorization, None]:
        fn = self._get_filename(type_, name)
        try:
            with open(fn, 'r') as fd:
                data = yaml.safe_load(fd)
        except FileNotFoundError:
            return None
        return data

    def load_order(self, name) -> Order:
        data = self.load('order', name)
        return Order.from_dict(data)

    def load_account(self, name) -> Account:
        data = self.load('account', name)
        return Account.from_dict(data)

    def load_authorization(self, name) -> Authorization:
        data = self.load('authorization', name)
        return Authorization.from_dict(data)

    def load_challenge(self, name) -> Challenge:
        data = self.load('challenge', name)
        return Challenge.from_dict(data)

    def load_certificate(self, name) -> Certificate:
        data = self.load('certificate', name)
        return Certificate.from_dict(data)

    def delete(self, type_: str, name: str) -> bool:
        fn = self._get_filename(type_, name)
        try:
            os.remove(fn)
            return True
        except FileNotFoundError:
            return False

    def _get_filename(self, type_: str, name: str) -> str:
        """ Construct filename and create directories as necessary. """
        if not os.path.isdir(self._datadir):
            os.mkdir(self._datadir, mode=0o700)

        type_dir = os.path.join(self._datadir, type_)
        if not os.path.isdir(type_dir):
            os.mkdir(type_dir, mode=0o700)

        fn = os.path.join(type_dir, name) + '.yaml'
        return fn
