import typing


class AuthenticatorProtocol(typing.Protocol):
    def is_supported(self, domain: str, challenge: typing.Any) -> bool:
        ...

    def perform(
        self, challs: typing.Iterable[tuple[typing.Any, str]], account_key: str
    ) -> None:
        ...

    def cleanup(
        self, challs: typing.Iterable[tuple[typing.Any, str]], account_key: str
    ) -> None:
        ...
