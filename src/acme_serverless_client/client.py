"""ACME-v2 Client for HTTP-01 challenge.

Based on https://github.com/certbot/certbot/blob/859dc38cb9195de072bc46e30e3edc0dab04f84d/acme/examples/http01_example.py
"""

import typing

import acme.client
from acme import errors, messages

from . import crypto
from .authenticators.base import AuthenticatorProtocol
from .models import Account, Certificate

if typing.TYPE_CHECKING:
    from .storage.base import StorageProtocol

USER_AGENT = "acme-serverless-client"


def select_authenticator(
    authenticators: typing.Sequence[AuthenticatorProtocol],
    domain: str,
    challenges: typing.Iterable[typing.Any],
) -> tuple[AuthenticatorProtocol, typing.Any]:
    for authenticator in authenticators:
        for challb in challenges:
            if authenticator.is_supported(domain, challb.chall):
                return (authenticator, challb)
    raise Exception(f"Can't select challenge for domain: {domain}")


def select_challs(
    orderr: messages.OrderResource,
    authenticators: typing.Sequence[AuthenticatorProtocol],
) -> typing.Sequence[tuple[AuthenticatorProtocol, set[tuple[typing.Any, str]]]]:
    result: dict[AuthenticatorProtocol, set[tuple[typing.Any, str]]] = {}
    for authz in orderr.authorizations:
        # Skip already-valid authorizations (can happen with authz reuse)
        if authz.body.status.name == "valid":
            continue
        domain = authz.body.identifier.value
        challenges = authz.body.challenges
        authenticator, challb = select_authenticator(authenticators, domain, challenges)
        result.setdefault(authenticator, set()).add((challb, domain))
    return list(result.items())


def build_client(account: Account, directory_url: str) -> acme.client.ClientV2:
    net = acme.client.ClientNetwork(
        key=account.key, account=account.regr, user_agent=USER_AGENT
    )
    directory = acme.client.ClientV2.get_directory(directory_url, net)
    return acme.client.ClientV2(directory, net=net)


def setup_client(
    storage: "StorageProtocol", account_email: str, directory_url: str
) -> acme.client.ClientV2:
    account = storage.get_account()
    if account:
        client = build_client(account, directory_url)
    else:
        new_account = Account()
        client = build_client(new_account, directory_url)
        new_account.regr = client.new_account(
            messages.NewRegistration.from_data(
                email=account_email, terms_of_service_agreed=True
            )
        )
        storage.set_account(new_account)
    return client


def perform(
    certificate: Certificate,
    storage: "StorageProtocol",
    acme_account_email: str,
    acme_directory_url: str,
    authenticators: typing.Sequence[AuthenticatorProtocol],
) -> None:
    client = setup_client(
        storage=storage,
        directory_url=acme_directory_url,
        account_email=acme_account_email,
    )

    orderr = client.new_order(
        crypto.make_csr(certificate.private_key, certificate.domains)
    )
    auth_challs = select_challs(orderr, authenticators)
    account_key = client.net.key
    assert account_key is not None
    for authenticator, challs in auth_challs:
        authenticator.perform(challs, account_key)
        for challb, _ in challs:
            client.answer_challenge(challb, challb.response(account_key))
    try:
        finalized_orderr = client.poll_and_finalize(orderr)
        fullchain_pem = finalized_orderr.fullchain_pem.encode("utf8")
        certificate.set_fullchain(fullchain_pem)
        storage.save_certificate(certificate)
    finally:
        for authenticator, challs in auth_challs:
            authenticator.cleanup(challs, account_key)


def issue(
    *,
    domains: typing.Sequence[str],
    storage: "StorageProtocol",
    acme_account_email: str,
    acme_directory_url: str,
    authenticators: typing.Sequence[AuthenticatorProtocol],
) -> None:
    certificate = Certificate(
        domains=domains, private_key=Certificate.generate_private_key()
    )
    perform(
        certificate, storage, acme_account_email, acme_directory_url, authenticators
    )


def renew(
    *,
    certificate: Certificate,
    storage: "StorageProtocol",
    acme_account_email: str,
    acme_directory_url: str,
    authenticators: typing.Sequence[AuthenticatorProtocol],
) -> None:
    perform(
        certificate, storage, acme_account_email, acme_directory_url, authenticators
    )


def revoke(
    *,
    certificate: Certificate,
    storage: "StorageProtocol",
    acme_account_email: str,
    acme_directory_url: str,
) -> None:
    fullchain_com = crypto.load_certificate(certificate.fullchain)
    client = setup_client(
        storage=storage,
        directory_url=acme_directory_url,
        account_email=acme_account_email,
    )
    try:
        client.revoke(fullchain_com, rsn=0)
    except errors.ConflictError as exc:
        raise RuntimeError(
            f"[REVOKE] {certificate.name} certificate already revoked."
        ) from exc
    finally:
        storage.remove_certificate(certificate)
