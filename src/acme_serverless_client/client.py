"""ACME-v2 Client for HTTP-01 challenge.

Based on https://github.com/certbot/certbot/blob/859dc38cb9195de072bc46e30e3edc0dab04f84d/acme/examples/http01_example.py
"""

import typing

import acme.client
from acme import challenges, crypto_util, errors, messages

from . import crypto
from .models import Account, Domain

if typing.TYPE_CHECKING:
    from .storage.base import BaseStorage


USER_AGENT = "aws-lambda-acme"


def select_http01_chall(orderr: messages.OrderResource) -> typing.Any:
    """Extract authorization resource from within order resource."""
    # Authorization Resource: authz.
    # This object holds the offered challenges by the server and their status.
    authz_list = orderr.authorizations

    for authz in authz_list:
        # Choosing challenge.
        # authz.body.challenges is a set of ChallengeBody objects.
        for i in authz.body.challenges:
            # Find the supported challenge.
            if isinstance(i.chall, challenges.HTTP01):
                return i

    raise Exception("HTTP-01 challenge was not offered by the CA server.")


ValidationCallback = typing.Callable[[str, bytes], None]


def perform_http01(
    client_acme: acme.client.ClientV2,
    challb: typing.Any,
    orderr: messages.OrderResource,
    validation_callback: ValidationCallback,
) -> bytes:
    """Set up standalone webserver and perform HTTP-01 challenge."""

    response, validation = challb.response_and_validation(client_acme.net.key)
    validation_callback(challb.chall.path, validation.encode())
    client_acme.answer_challenge(challb, response)
    finalized_orderr = client_acme.poll_and_finalize(orderr)

    return typing.cast(bytes, finalized_orderr.fullchain_pem.encode("utf8"))


def build_client(account: Account, directory_url: str) -> acme.client.ClientV2:
    net = acme.client.ClientNetwork(
        key=account.key, account=account.regr, user_agent=USER_AGENT,
    )
    directory = messages.Directory.from_json(net.get(directory_url).json())
    return acme.client.ClientV2(directory, net=net)


def setup_client(
    account: typing.Optional[Account],
    storage: "BaseStorage",
    account_email: str,
    directory_url: str,
) -> acme.client.ClientV2:
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


def issue_or_renew(
    domain_name: str,
    storage: "BaseStorage",
    acme_account_email: str,
    acme_directory_url: str,
    validation_callback: ValidationCallback,
) -> None:
    domain = storage.get_domain(name=domain_name)
    account = storage.get_account()
    client = setup_client(
        account,
        storage=storage,
        directory_url=acme_directory_url,
        account_email=acme_account_email,
    )

    orderr = client.new_order(crypto_util.make_csr(domain.key, [domain.name]))
    challb = select_http01_chall(orderr)
    fullchain_pem = perform_http01(client, challb, orderr, validation_callback)
    storage.set_certificate(domain, fullchain_pem)


def revoke(
    domain_name: str,
    storage: "BaseStorage",
    acme_account_email: str,
    acme_directory_url: str,
) -> None:
    # just check if we have cert for that domain
    fullchain_pem = storage.get_certificate(Domain(name=domain_name))
    if not fullchain_pem:
        raise RuntimeError(f"[REVOKE] {domain_name} certificate not found.")
    # now construct a real domain object
    domain = storage.get_domain(name=domain_name)
    storage.remove_domain(domain)
    fullchain_com = crypto.load_certificate(fullchain_pem)
    account = storage.get_account()
    client = setup_client(
        account,
        storage=storage,
        directory_url=acme_directory_url,
        account_email=acme_account_email,
    )
    try:
        client.revoke(fullchain_com, rsn=0)
    except errors.ConflictError:
        raise RuntimeError(f"[REVOKE] {domain_name} certificate already revoked.")
