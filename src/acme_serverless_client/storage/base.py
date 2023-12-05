from __future__ import annotations

import datetime
import json
import typing
from typing import Protocol

from ..models import Account, Certificate


class ObserverEventsProtocol(Protocol):
    def save_certificate(self, certificate: Certificate) -> None:
        ...

    def remove_certificate(self, certificate: Certificate) -> None:
        ...


class AuthenticatorStorageProtocol(Protocol):
    def set_validation(self, key: str, value: bytes) -> None:
        ...

    def del_validation(self, key: str) -> None:
        ...


class StorageProtocol(ObserverEventsProtocol, Protocol):
    def get_account(self) -> Account | None:
        ...

    def set_account(self, account: Account) -> None:
        ...

    def list_certificates(
        self,
    ) -> typing.Iterator[tuple[str, datetime.datetime]]:
        ...

    def get_certificate(
        self,
        *,
        domains: typing.Sequence[str] | None = None,
        name: str | None = None,
    ) -> Certificate | None:
        ...


StorageEvent = typing.Literal["save_certificate", "remove_certificate"]


class StorageObserverProtocol(ObserverEventsProtocol, Protocol):
    def notify(
        self, event: StorageEvent, *args: typing.Any, **kwargs: typing.Any
    ) -> None:
        if event == "save_certificate":
            self.save_certificate(*args, **kwargs)
        elif event == "remove_certificate":
            self.remove_certificate(*args, **kwargs)


class BaseStorage:
    certificate_prefix = "certificates/"
    key_prefix = "keys/"
    config_prefix = "configs/"

    def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
        self._subscribers: set[StorageObserverProtocol] = set()

    @classmethod
    def _build_certificate_storage_key(cls, domain_name: str) -> str:
        return f"{cls.certificate_prefix}{domain_name}"

    @classmethod
    def _build_key_storage_key(cls, domain_name: str) -> str:
        return f"{cls.key_prefix}{domain_name}"

    @classmethod
    def _build_config_storage_key(cls, domain_name: str) -> str:
        return f"{cls.config_prefix}{domain_name}"

    def _get(self, name: str) -> bytes | None:
        raise NotImplementedError()

    def _set(self, name: str, data: bytes) -> None:
        raise NotImplementedError()

    def _del(self, name: str) -> None:
        raise NotImplementedError()

    def _notify(
        self, event: StorageEvent, *args: typing.Any, **kwargs: typing.Any
    ) -> None:
        for subscriber in self._subscribers:
            subscriber.notify(event, *args, **kwargs)

    def subscribe(self, observer: StorageObserverProtocol) -> None:
        self._subscribers.add(observer)

    def get_account(self) -> Account | None:
        data = self._get("account.json")
        if data:
            return Account.json_loads(data.decode())
        return None

    def set_account(self, account: Account) -> None:
        return self._set("account.json", account.json_dumps().encode())

    def list_certificates(
        self,
    ) -> typing.Iterator[tuple[str, datetime.datetime]]:
        raise NotImplementedError()

    def get_certificate(
        self,
        *,
        domains: typing.Sequence[str] | None = None,
        name: str | None = None,
    ) -> Certificate | None:
        assert domains or name, "domains or name is required."
        if domains:
            if name:
                assert (
                    domains[0] == name
                ), "first entry in domains must be equal to name."
            name = domains[0]
        assert name  # fix typing
        config_data = self._get(self._build_config_storage_key(name))
        if not config_data:
            return None
        config = json.loads(config_data)
        if domains is not None and config["domains"] != domains:
            return None
        private_key = self._get(self._build_key_storage_key(name))
        if not private_key:
            return None
        cert = Certificate(domains=config["domains"], private_key=private_key)
        fullchain_pem = self._get(self._build_certificate_storage_key(name))
        if fullchain_pem:
            cert.set_fullchain(fullchain_pem)
        return cert

    def save_certificate(self, certificate: Certificate) -> None:
        assert certificate.is_fullchain_set
        self._set(
            self._build_config_storage_key(certificate.name),
            json.dumps({"domains": certificate.domains}).encode(),
        )
        self._set(
            self._build_key_storage_key(certificate.name), certificate.private_key
        )
        self._set(
            self._build_certificate_storage_key(certificate.name), certificate.fullchain
        )
        self._notify("save_certificate", certificate)

    def remove_certificate(self, certconfig: Certificate) -> None:
        self._del(self._build_certificate_storage_key(certconfig.name))
        self._del(self._build_key_storage_key(certconfig.name))
        self._del(self._build_config_storage_key(certconfig.name))
        self._notify("remove_certificate", certconfig)
