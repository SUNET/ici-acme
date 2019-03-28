from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional, List, Any, Mapping


@dataclass()
class StoreObject(object):

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, data):
        return cls(**data)


@dataclass()
class Account(StoreObject):
    id: str
    jwk_data: str = field(repr=False)
    last_order: Optional[datetime] = None
    order_ids: List[str] = field(default_factory=lambda: [])


@dataclass()
class Order(StoreObject):
    id: str
    created: datetime
    identifiers: dict
    authorization_ids: List[str]
    status: str  # invalid, pending, ready, processing, valid
    expires: Optional[datetime] = None
    certificate_id: Optional[str] = None

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, data):
        return cls(**data)

@dataclass()
class Authorization(StoreObject):
    id: str
    status: str   # pending, valid, invalid (valid means completed)
    created: datetime
    expires: Optional[datetime]  # this one is set when status transitions to 'valid'
    identifier: dict
    challenge_ids: List[str]


@dataclass()
class Challenge(StoreObject):
    id: str
    type: str
    url: str
    status: str  # Possible values are "pending", "processing", "valid", and "invalid" (see Section 7.1.6).
    created: datetime
    validated: Optional[datetime] = None  # REQUIRED when status is 'valid'
    error: Optional[Any] = None  # when this is set, status MUST be 'invalid'
    # token is for http-01
    token: Optional[str] = None

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


@dataclass()
class Certificate(StoreObject):
    csr: str
    created: datetime
    certificate: Optional[str] = None
    expires: Optional[datetime] = None  # set when certificate is added