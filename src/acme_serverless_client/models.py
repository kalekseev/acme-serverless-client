import json
import typing

import josepy as jose
from acme import messages

from . import crypto


class Domain:
    def __init__(self, name: str, key: typing.Optional[bytes] = None) -> None:
        self.name = name
        self._key = key

    @property
    def key(self) -> bytes:
        if not self._key:
            self._key = crypto.generate_domain_key()
        return self._key


class Account:
    def __init__(
        self, key: jose.JWKRSA = None, regr: messages.RegistrationResource = None
    ) -> None:
        self._key = key
        self.regr = regr

    @property
    def key(self) -> jose.JWKRSA:
        if not self._key:
            self._key = crypto.generate_account_key()
        return self._key

    @staticmethod
    def json_loads(jstr: str) -> "Account":
        data = json.loads(jstr)
        return Account(
            key=jose.JWKRSA.from_json(data["key"]),
            regr=messages.RegistrationResource.from_json(data["regr"]),
        )

    def _to_json(self) -> typing.Mapping[str, typing.Any]:
        return {
            "key": json.loads(self.key.json_dumps()),
            "regr": json.loads(self.regr.json_dumps()),
        }

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Account) and self._to_json() == other._to_json()

    def json_dumps(self) -> str:
        return json.dumps(self._to_json())
