import logging
import os
import typing

import boto3

from acme_serverless_client import issue_or_renew, revoke
from acme_serverless_client.authenticators.http_storage import StorageAuthenticator
from acme_serverless_client.helpers import find_certificates_to_renew
from acme_serverless_client.storage.aws import S3Storage

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


def handler(event: typing.Any, context: typing.Any) -> typing.Mapping[str, typing.Any]:
    client = boto3.client("s3")
    storage = S3Storage(bucket=S3Storage.Bucket(os.environ["BUCKET"], client))
    params: typing.Any = {
        "acme_account_email": os.environ["ACME_ACCOUNT_EMAIL"],
        "acme_directory_url": os.environ["ACME_DIRECTORY_URL"],
        "storage": storage,
        "authenticators": [StorageAuthenticator(storage=storage)],
    }
    if event["action"] == "renew":
        domains = [domain for domain, _ in find_certificates_to_renew(storage)]
        failure = []
        for domain in domains:
            try:
                issue_or_renew(
                    domain, **params,
                )
            except Exception as exc:
                logger.error(str(exc))
                failure.append(domain)
        if len(failure) == len(domains):
            raise RuntimeError(f"All operations failed: {failure}")
    elif event["action"] == "issue":
        issue_or_renew(
            event["domain"], **params,
        )
    elif event["action"] == "revoke":
        revoke(event["domain"], storage, **params)

    return {"statusCode": 200}
