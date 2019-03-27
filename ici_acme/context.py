import os
import sys
import time
import logging

from typing import Dict, Optional, Mapping

from ici_acme.store import Account, Store
from ici_acme.utils import b64_urlsafe, urlappend


class Context(object):

    def __init__(self, store: Store):
        self.store = store
        self._nonces: Dict[str, bool] = {}

        self.protocol: str = 'http'
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
        base_url = f'{self.protocol}://{self.server_name}'
        if self.application_root:
            return urlappend(base_url, self.application_root)
        return base_url

    def new_account(self, jwk_data: Mapping) -> Account:
        # Use an integer account_id to be compatible with LetsEncrypt pre-RFC8555 'id' parameter
        id = str(int(time.time()))  # TODO: make sure there is no account with this ID already
        account = Account(id=id, jwk_data=jwk_data)
        self.store.save('account', str(id), account.to_dict())
        return account

    def get_account_using_kid(self, kid) -> Optional[Account]:
        last_part = kid.split('/')[-1]
        return self.store.load_account(last_part)

