"""ACME-v2 Client for HTTP-01 challenge.

Based on https://github.com/certbot/certbot/blob/859dc38cb9195de072bc46e30e3edc0dab04f84d/acme/examples/http01_example.py

Expected environment variables:

DIRECTORY_URL - ACME server directory url
ACCOUNT_EMAIL - email used to issue certificates
BUCKET - bucket name where certificates stored
SENTRY_DSN - optional, sentry dsn url
"""

import datetime
import json
import logging
import os
import typing

import acme.client
import urllib3
from acme import challenges, crypto_util, errors, messages
from dateutil.tz import tzutc

from . import crypto
from .models import Account, Domain
from .storage import AWSStorage, BaseStorage

logger = logging.getLogger("aws-lambda-acme")

USER_AGENT = "aws-lambda-acme"


if os.environ.get("SENTRY_DSN"):
    import sentry_sdk
    from sentry_sdk.integrations.aws_lambda import AwsLambdaIntegration
    from sentry_sdk.integrations.logging import LoggingIntegration

    sentry_sdk.init(
        dsn=os.environ["SENTRY_DSN"],
        integrations=[
            AwsLambdaIntegration(),
            LoggingIntegration(level=logging.INFO, event_level=logging.ERROR),
        ],
    )


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


def build_client(account: Account) -> acme.client.ClientV2:
    net = acme.client.ClientNetwork(
        key=account.key, account=account.regr, user_agent=USER_AGENT,
    )
    directory = messages.Directory.from_json(
        net.get(os.environ["DIRECTORY_URL"]).json()
    )
    return acme.client.ClientV2(directory, net=net)


def setup_client(
    account: typing.Optional[Account], storage: BaseStorage
) -> acme.client.ClientV2:
    if account:
        client = build_client(account)
    else:
        new_account = Account()
        client = build_client(new_account)
        new_account.regr = client.new_account(
            messages.NewRegistration.from_data(
                email=os.environ["ACCOUNT_EMAIL"], terms_of_service_agreed=True
            )
        )
        storage.set_account(new_account)
    return client


def issue_or_renew(domain_name: str, storage: BaseStorage) -> None:
    domain = storage.get_domain(name=domain_name)
    account = storage.get_account()
    client = setup_client(account, storage=storage)

    orderr = client.new_order(crypto_util.make_csr(domain.key, [domain.name]))
    challb = select_http01_chall(orderr)
    fullchain_pem = perform_http01(client, challb, orderr, storage.set_validation)
    storage.set_certificate(domain, fullchain_pem)


def revoke(domain_name: str, storage: BaseStorage) -> None:
    # just check if we have cert for that domain
    fullchain_pem = storage.get_certificate(Domain(name=domain_name))
    if not fullchain_pem:
        raise RuntimeError(f"[REVOKE] {domain_name} certificate not found.")
    # now construct a real domain object
    domain = storage.get_domain(name=domain_name)
    storage.remove_certificate(domain)
    fullchain_com = crypto.load_certificate(fullchain_pem)
    account = storage.get_account()
    client = setup_client(account, storage=storage)
    try:
        client.revoke(fullchain_com, rsn=0)
    except errors.ConflictError:
        raise RuntimeError(f"[REVOKE] {domain_name} certificate already revoked.")


def call_webhook(
    event: typing.Mapping[str, typing.Any],
    success: typing.List[str],
    failure: typing.List[str],
) -> None:
    http = urllib3.PoolManager()
    r = http.request(
        "POST",
        event["webhook"]["url"],
        body=json.dumps(
            {
                **event["webhook"].get("body", {}),
                "success_domains": success,
                "failure_domains": failure,
            }
        ).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    if r.status != 200:
        raise RuntimeError(f"Webhook response [{r.status}]:\n\n{r.data}")


def handler(event: typing.Any, context: typing.Any) -> typing.Mapping[str, typing.Any]:
    storage = AWSStorage.from_env()
    if event["action"] == "renew":
        now = datetime.datetime.utcnow().replace(tzinfo=tzutc())
        command = issue_or_renew
        domains = [
            domain
            for domain, _ in storage.find_certificates(
                not_valid_on_date=now + datetime.timedelta(days=30)
            )
        ]
    elif event["action"] == "issue":
        command = issue_or_renew
        domains = [event["domain"]]
    elif event["action"] == "revoke":
        command = revoke
        domains = [event["domain"]]

    success = []
    failure = []
    for domain in domains:
        try:
            command(domain, storage)
        except Exception as exc:
            logger.error(str(exc))
            failure.append(domain)
        else:
            success.append(domain)
    if not success:
        raise RuntimeError(f"All operations failed: {failure}")

    try:
        if "webhook" in event:
            call_webhook(event, success, failure)
    except Exception as exc:
        logger.error(str(exc))

    return {"statusCode": 200}
