import os
import yaml

from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Mapping, Union, List, Optional


@dataclass()
class Account(object):
    id: str
    jwk_data: Mapping = field(repr=False)
    last_order: Optional[datetime] = None
    orders: List[str] = field(default_factory=lambda: [])

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, data):
        return cls(**data)


@dataclass()
class Order(object):
    id: str
    created: datetime
    identifiers: str
    authorizations: List[str]

    def to_dict(self):
        return asdict(self)

@dataclass()
class Authorization(object):
    id: str
    created: datetime

    def to_dict(self):
        return asdict(self)


class Store(object):

    def __init__(self, datadir: str):
        self._datadir = datadir

    def save(self, type_: str, name: str, data: Mapping) -> None:
        fn = self._get_filename(type_, name)
        _tmpfile = fn + '.tmp'
        with open(_tmpfile, 'w') as fd:
            fd.write(yaml.safe_dump(data))
        os.rename(_tmpfile, fn)

    def load(self, type_: str, name: str) -> Union[Mapping, Account, None]:
        fn = self._get_filename(type_, name)
        try:
            with open(fn, 'r') as fd:
                data = yaml.safe_load(fd)
        except FileNotFoundError:
            return None
        if type_ == 'account':
            return Account.from_dict(data)
        return data

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
