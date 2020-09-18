import logging
import os
import typing

import boto3

from acme_serverless_client import find_certificates_to_renew, issue, renew, revoke
from acme_serverless_client.authenticators.http import HTTP01Authenticator
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
    authenticators = [HTTP01Authenticator(storage=storage)]
    params: typing.Any = {
        "acme_account_email": os.environ["ACME_ACCOUNT_EMAIL"],
        "acme_directory_url": os.environ["ACME_DIRECTORY_URL"],
        "storage": storage,
    }
    if event["action"] == "renew":
        certificates = [
            certificate for certificate, _ in find_certificates_to_renew(storage)
        ]
        failure = []
        for certificate in certificates:
            try:
                renew(certificate=certificate, authenticators=authenticators, **params)
            except Exception as exc:
                logger.error(str(exc))
                failure.append(certificate.name)
        if len(failure) == len(certificates):
            raise RuntimeError(f"All renew operations failed: {failure}")
    elif event["action"] == "issue":
        issue(domains=[event["domain"]], authenticators=authenticators, **params)
    elif event["action"] == "revoke":
        cert = storage.get_certificate(name=event["domain"])
        assert cert
        revoke(certificate=cert, **params)

    return {"statusCode": 200}
