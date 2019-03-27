import os
import yaml

from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Mapping, Union, List, Optional, Any


@dataclass()
class Account(object):
    id: str
    jwk_data: Mapping = field(repr=False)
    last_order: Optional[datetime] = None
    order_ids: List[str] = field(default_factory=lambda: [])

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, data):
        return cls(**data)


@dataclass()
class Order(object):
    id: str
    created: datetime
    identifiers: dict
    authorization_ids: List[str]
    status: str
    expires: Optional[datetime] = None


    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, data):
        return cls(**data)


@dataclass()
class Authorization(object):
    id: str
    status: str   # pending, valid, invalid (valid means completed)
    created: datetime
    expires: Optional[datetime]  # this one is set when status transitions to 'valid'
    identifier: dict
    challenge_ids: List[str]

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, data):
        return cls(**data)


@dataclass()
class Challenge(object):
    id: str
    type: str
    url: str
    status: str  # Possible values are "pending", "processing", "valid", and "invalid" (see Section 7.1.6).
    created: datetime
    validated: Optional[datetime] = None  # REQUIRED when status is 'valid'
    error: Optional[Any] = None  # when this is set, status MUST be 'invalid'
    # token is for http-01
    token: Optional[str] = None

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, data):
        return cls(**data)

    def to_response(self) -> Mapping:
        data = {
            'url': self.url,
            'type': self.type,
            'status': self.status,
        }
        if self.token is not None:
            data['token'] = self.token
        if self.status == 'valid':
            data['validated'] = str(self.validated)
        if self.status == 'invalid' and self.error is not None:
            data['error'] = self.error
        return data


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
