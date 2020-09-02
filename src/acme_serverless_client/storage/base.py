import datetime
import typing

from ..models import Account, Domain


class BaseStorage:
    certificate_prefix = "certificates/"
    key_prefix = "keys/"

    def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
        pass

    @classmethod
    def _build_certificate_storage_key(self, domain_name: str) -> str:
        return f"{self.certificate_prefix}{domain_name}"

    @classmethod
    def _build_key_storage_key(self, domain_name: str) -> str:
        return f"{self.key_prefix}{domain_name}"

    def _get(self, name: str) -> typing.Optional[bytes]:
        raise NotImplementedError()

    def _set(self, name: str, data: bytes) -> None:
        raise NotImplementedError()

    def _del(self, name: str) -> None:
        raise NotImplementedError()

    def get_domain(self, name: str, **kwargs: typing.Any) -> Domain:
        key = self._get(self._build_key_storage_key(name))
        domain = Domain(name=name, key=key, **kwargs)
        if not key:
            self._set(self._build_key_storage_key(name), domain.key)
        return domain

    def list_certificates(
        self,
    ) -> typing.Iterator[typing.Tuple[str, datetime.datetime]]:
        raise NotImplementedError()

    def get_account(self) -> typing.Optional[Account]:
        data = self._get("account.json")
        if data:
            return Account.json_loads(data.decode())
        return None

    def set_account(self, account: Account) -> None:
        return self._set("account.json", account.json_dumps().encode())

    def get_certificate(self, domain: Domain) -> typing.Optional[bytes]:
        return self._get(self._build_certificate_storage_key(domain.name))

    def set_certificate(self, domain: Domain, fullchain_pem: bytes) -> None:
        self._set(self._build_certificate_storage_key(domain.name), fullchain_pem)

    def remove_domain(self, domain: Domain) -> None:
        self._del(self._build_certificate_storage_key(domain.name))
        self._del(self._build_key_storage_key(domain.name))
