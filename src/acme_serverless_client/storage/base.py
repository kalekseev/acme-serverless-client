import datetime
import typing

from ..models import Account, Domain


class BaseStorage:
    def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
        pass

    def _get(self, name: str) -> typing.Optional[bytes]:
        raise NotImplementedError()

    def _set(self, name: str, data: bytes) -> None:
        raise NotImplementedError()

    def _del(self, name: str) -> None:
        raise NotImplementedError()

    def _get_domain(
        self, name: str, key: typing.Optional[bytes] = None, **kwargs: typing.Any
    ) -> Domain:
        key = self._get(f"keys/{name}")
        domain = Domain(name=name, **kwargs)
        if not key:
            self._set(f"keys/{name}", domain.key)
        return domain

    def get_domain(self, name: str) -> Domain:
        return self._get_domain(name=name)

    def find_certificates(
        self, not_valid_on_date: datetime.datetime
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
        return self._get(f"certificates/{domain.name}")

    def set_certificate(self, domain: Domain, fullchain_pem: bytes) -> None:
        self._set(f"certificates/{domain.name}", fullchain_pem)

    def remove_certificate(self, domain: Domain) -> None:
        self._del(f"certificates/{domain.name}")
        self._del(f"keys/{domain.name}")

    def set_validation(self, key: str, value: bytes) -> None:
        if key.startswith("/"):
            key = key.lstrip("/")
        self._set(key, value)
