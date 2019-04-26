import os
import sys
import time
import logging
import logging.config
from typing import Dict, Optional, Mapping

from ici_acme.store import Store
from ici_acme.data import Account
from ici_acme.utils import b64_encode, b64_decode, urlappend
from ici_acme.exceptions import BadNonce


class Context(object):

    def __init__(self, config: Mapping):
        self.config = config
        self.store = Store(self.config.get('STORE_PATH', './data'))
        self._nonces: Dict[str, bool] = {}

        self.schema: str = self.config.get('SCHEMA', 'http')
        self.server_name: str = self.config.get('SERVER_NAME', 'localhost:8000')
        self.application_root: str = self.config.get('APPLICATION_ROOT', '')

        self.token_ca_path: Optional[str] = self.config.get('TOKEN_CA_PATH', None)
        self.renew_ca_path = self.config.get('RENEW_CA_PATH', '/etc/ssl/certs/infra.crt')

        if self.config.get('LOGGING'):
            logging.config.dictConfig(self.config.get('LOGGING'))
            self.logger = logging.getLogger('ici_acme')
        else:
            self.logger = logging.getLogger('ici_acme')
            sh = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(module)s - %(levelname)s - %(message)s')
            sh.setFormatter(formatter)
            self.logger.addHandler(sh)
            self.logger.setLevel(logging.DEBUG)

    def _check_nonce_format(self, nonce):
        # The value of the "nonce" header parameter MUST be an octet string, encoded according to the base64url
        # encoding described in Section 2 of [RFC7515].  If the value of a "nonce" header parameter is not valid
        # according to this encoding, then the verifier MUST reject the JWS as malformed.
        try:
            decoded_nonce = b64_decode(nonce)  # Raises ValueError if decode fails
        except ValueError:
            self.logger.error(f'Nonce {nonce} failed urlsafe_b64decode')
            raise BadNonce(detail='Nonce failed base64 decode', new_nonce=self.new_nonce)
        if len(decoded_nonce) != 128 // 8:
            self.logger.error(f'Nonce {nonce} has incorrect length')
            raise BadNonce(detail='Nonce has incorrect length', new_nonce=self.new_nonce)

    def check_nonce(self, nonce) -> bool:
        self._check_nonce_format(nonce)
        return self._nonces.pop(nonce, False)

    @property
    def new_nonce(self) -> str:
        nonce = b64_encode(os.urandom(128 // 8))
        self._nonces[nonce] = True
        return nonce

    @property
    def base_url(self) -> str:
        base_url = f'{self.schema}://{self.server_name}'
        if self.application_root:
            return urlappend(base_url, self.application_root)
        return base_url

    def new_account(self, jwk: dict, alg: str) -> Account:
        # Use an integer account_id to be compatible with LetsEncrypt pre-RFC8555 'id' parameter
        account_id = str(int(time.time()))  # TODO: make sure there is no account with this ID already
        if self.get_account_using_kid(account_id) is not None:
            self.logger.warning(f'Account {account_id} already exists')
            raise RuntimeError(f'Was about to overwrite account {account_id}')
        account = Account(id=account_id, status='valid', jwk=jwk, alg=alg)
        self.store.save('account', str(account_id), account.to_dict())
        return account

    def get_account_using_kid(self, kid: Optional[str]) -> Optional[Account]:
        if kid:
            try:
                last_part = kid.split('/')[-1]
                return self.store.load_account(last_part)
            except TypeError:  # There is no such account
                pass
