import typing

from acme import challenges

from ..storage.base import AuthenticatorStorageProtocol
from .base import AuthenticatorProtocol


class HTTP01Authenticator(AuthenticatorProtocol):
    def __init__(self, storage: AuthenticatorStorageProtocol):
        self._storage = storage

    def is_supported(self, domain: str, challenge: typing.Any) -> bool:
        return isinstance(challenge, challenges.HTTP01)

    def perform(
        self, challs: typing.Iterable[typing.Tuple[typing.Any, str]], account_key: str
    ) -> None:
        for challb, _ in challs:
            self._storage.set_validation(
                challb.chall.path, challb.validation(account_key).encode()
            )

    def cleanup(
        self, challs: typing.Iterable[typing.Tuple[typing.Any, str]], account_key: str
    ) -> None:
        for challb, _ in challs:
            self._storage.del_validation(challb.chall.path)
