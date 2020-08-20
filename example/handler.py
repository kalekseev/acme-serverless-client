import datetime
import json
import logging
import os
import typing

import urllib3
from dateutil.tz import tzutc

from acme_serverless_client import issue_or_renew, revoke
from acme_serverless_client.storage.aws import AWSStorage

logger = logging.getLogger("aws-lambda-acme")


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
