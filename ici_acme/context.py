import hashlib
import logging
import os
import sys
import time
import yaml
from dataclasses import dataclass, field, asdict
from typing import Dict, Optional

from ici_acme.utils import b64_urlsafe, urlappend

_ACCOUNTS_FILE = 'accounts.yaml'

@dataclass()
class Account(object):
    id: int
    digest: str
    protected: str = field(repr=False)

    @classmethod
    def from_dict(cls, data):
        return cls(**data)


class Context(object):

    def __init__(self):
        self._nonces: Dict[str, bool] = {}
        self._accounts: Dict[str, Account] = {}

        if os.path.isfile(_ACCOUNTS_FILE):
            with open(_ACCOUNTS_FILE) as fd:
                data = yaml.safe_load(fd)
                for k, v in data.items():
                    self._accounts[k] = Account.from_dict(v)

        self.server_name: str = 'localhost:8000'
        self.application_root: str = ''

        self.logger = logging.getLogger(__name__)
        self.logger.addHandler(logging.StreamHandler(sys.stdout))
        self.logger.setLevel(logging.DEBUG)

    def check_nonce(self, nonce) -> bool:
        return self._nonces.pop(nonce, False)

    @property
    def new_nonce(self) -> str:
        nonce = b64_urlsafe(os.urandom(128 // 8))
        self._nonces[nonce] = True
        return nonce

    @property
    def base_url(self) -> str:
        if self.application_root:
            return urlappend(self.server_name, self.application_root)
        return self.server_name

    def save_account(self, protected: str) -> Account:
        id = int(time.time())  # TODO: make sure there is no account with this ID already
        digest = b64_urlsafe(hashlib.sha256(protected.encode()).digest())
        account = Account(id=id, digest=digest, protected=protected)
        self._accounts[digest] = account
        _tmpfile = _ACCOUNTS_FILE + '.tmp'
        with open(_tmpfile, 'w') as fd:
            _ser = {}
            for k, v in self._accounts.items():
                _ser[k] = asdict(v)
            fd.write(yaml.safe_dump(_ser))
        os.rename(_tmpfile, _ACCOUNTS_FILE)
        return account

    def get_account_using_kid(self, kid) -> Optional[Account]:
        last_part = kid.split('/')[-1]
        try:
            # If last_part is an int, it looks like dehydrated in pre-RFC8555 mode,
            # so kid was not at all the Location: URL returned from new-account but
            # rather the new-account URL with the 'id' returned. Example:
            id = int(last_part)
            match = [x for x in self._accounts.values() if x.id == id]
            return match[0] if match else None
        except ValueError:
            pass
        # last_part is hopefully the digest at the end of the new-account Location: URL
        match = [x for x in self._accounts.values() if x.digest == last_part]
        return match[0] if match else None
