import json
import typing

import josepy as jose
from acme import messages

from . import crypto


class CertificateNotSet(Exception):
    pass


class Certificate:
    def __init__(self, domains: typing.Sequence[str], private_key: bytes) -> None:
        self.domains = list(domains)
        self.private_key = private_key
        self._certificate: typing.Optional[bytes] = None
        self._certificate_chain: typing.Optional[bytes] = None

    def __repr__(self) -> str:
        return f"Certificate<{self.domains}>"

    @classmethod
    def generate_private_key(self) -> bytes:
        return crypto.generate_private_key()

    @property
    def name(self) -> str:
        return self.domains[0]

    @property
    def certificate(self) -> bytes:
        if not self._certificate:
            raise CertificateNotSet()
        return self._certificate

    @property
    def certificate_chain(self) -> bytes:
        if not self._certificate_chain:
            raise CertificateNotSet()
        return self._certificate_chain

    @property
    def fullchain(self) -> bytes:
        return self.certificate + self.certificate_chain

    @property
    def is_fullchain_set(self) -> bool:
        try:
            self.certificate
        except CertificateNotSet:
            return False
        return True

    def set_fullchain(self, fullchain_pem: bytes) -> None:
        sep = "-----END CERTIFICATE-----\n"
        part1, part2, chain = fullchain_pem.decode().partition(sep)
        self._certificate = (part1 + part2).encode()
        self._certificate_chain = chain.lstrip().encode()


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
