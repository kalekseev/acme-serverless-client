"""ACME-v2 Client for HTTP-01 challenge.

Based on https://github.com/certbot/certbot/blob/859dc38cb9195de072bc46e30e3edc0dab04f84d/acme/examples/http01_example.py
"""

import typing

import acme.client
from acme import crypto_util, errors, messages

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
) -> typing.Tuple[AuthenticatorProtocol, typing.Any]:
    for authenticator in authenticators:
        for challb in challenges:
            if authenticator.is_supported(domain, challb.chall):
                return (authenticator, challb)
    raise Exception(f"Can't select challenge for domain: {domain}")


def select_challs(
    orderr: messages.OrderResource,
    authenticators: typing.Sequence[AuthenticatorProtocol],
) -> typing.Sequence[
    typing.Tuple[AuthenticatorProtocol, typing.Set[typing.Tuple[typing.Any, str]]]
]:
    result: typing.Dict[
        AuthenticatorProtocol, typing.Set[typing.Tuple[typing.Any, str]]
    ] = {}
    for authz in orderr.authorizations:
        domain = authz.body.identifier.value
        challenges = authz.body.challenges
        authenticator, challb = select_authenticator(authenticators, domain, challenges)
        result.setdefault(authenticator, set()).add((challb, domain))
    return list(result.items())


def build_client(account: Account, directory_url: str) -> acme.client.ClientV2:
    net = acme.client.ClientNetwork(
        key=account.key, account=account.regr, user_agent=USER_AGENT,
    )
    directory = messages.Directory.from_json(net.get(directory_url).json())
    return acme.client.ClientV2(directory, net=net)


def setup_client(
    storage: "StorageProtocol", account_email: str, directory_url: str,
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
    client_acme: acme.client.ClientV2,
    challs: typing.Iterable[typing.Tuple[typing.Any, str]],
    authenticator: AuthenticatorProtocol,
) -> None:
    account_key = client_acme.net.key
    authenticator.perform(challs, account_key)
    for challb, _ in challs:
        client_acme.answer_challenge(challb, challb.response(account_key))


def issue_or_renew(
    domains: typing.Sequence[str],
    storage: "StorageProtocol",
    acme_account_email: str,
    acme_directory_url: str,
    authenticators: typing.Sequence[AuthenticatorProtocol],
) -> None:
    certificate = storage.get_certificate(domains=domains) or Certificate(
        domains=domains, private_key=Certificate.generate_private_key()
    )
    client = setup_client(
        storage=storage,
        directory_url=acme_directory_url,
        account_email=acme_account_email,
    )

    orderr = client.new_order(
        crypto_util.make_csr(certificate.private_key, certificate.domains)
    )
    auth_challs = select_challs(orderr, authenticators)
    for authenticator, challs in auth_challs:
        perform(client, challs, authenticator)
    finalized_orderr = client.poll_and_finalize(orderr)
    fullchain_pem = typing.cast(bytes, finalized_orderr.fullchain_pem.encode("utf8"))
    certificate.set_fullchain(fullchain_pem)
    storage.save_certificate(certificate)


def revoke(
    domains: typing.Sequence[str],
    storage: "StorageProtocol",
    acme_account_email: str,
    acme_directory_url: str,
) -> None:
    certificate = storage.get_certificate(domains=domains)
    if not certificate:
        raise RuntimeError(f"[REVOKE] {domains} certificate not found.")
    fullchain_com = crypto.load_certificate(certificate.fullchain)
    client = setup_client(
        storage=storage,
        directory_url=acme_directory_url,
        account_email=acme_account_email,
    )
    try:
        client.revoke(fullchain_com, rsn=0)
    except errors.ConflictError:
        raise RuntimeError(f"[REVOKE] {domains} certificate already revoked.")
    finally:
        storage.remove_certificate(certificate)
