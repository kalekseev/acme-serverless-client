import urllib.request
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from acme_serverless_client import issue, renew, revoke
from acme_serverless_client.authenticators.dns_route_53 import Route53Authenticator
from acme_serverless_client.authenticators.http import HTTP01Authenticator
from acme_serverless_client.storage.aws import ACMStorageObserver, S3Storage


def test_load_balancer_redirect(minio_bucket, load_balancer, acm):
    storage = S3Storage(bucket=minio_bucket)
    storage.subscribe(ACMStorageObserver(acm=acm))
    storage.set_validation("/.well-known/acme-challenge/randomkey", b"secretstring")
    r = urllib.request.urlopen(
        load_balancer["url"] + "/.well-known/acme-challenge/randomkey"
    )
    assert r.status == 200
    assert r.read() == b"secretstring"


def test_acm_issue_renew_revoke(minio_bucket, full_infra, acm, acme_directory_url):
    storage = S3Storage(bucket=minio_bucket)
    observer = ACMStorageObserver(acm=acm)
    storage.subscribe(observer)
    domain_name = "my3.example.com"

    auth = HTTP01Authenticator(storage=storage)
    issue(
        domains=[domain_name],
        storage=storage,
        acme_directory_url=acme_directory_url,
        acme_account_email="fake@example.com",
        authenticators=[auth],
    )
    certificate = storage.get_certificate(domains=[domain_name])
    pem_data = certificate.fullchain
    assert pem_data
    cert = x509.load_pem_x509_certificate(pem_data, default_backend())
    # Modern certs (RFC 8555) use SANs, CN may be empty
    sans = cert.extensions.get_extension_for_class(
        x509.extensions.SubjectAlternativeName
    ).value
    assert domain_name in [x.value for x in sans]
    valid_from = cert.not_valid_before_utc
    assert datetime.now(timezone.utc) > valid_from

    acm_arn = observer._acm_arn_resolver.get(domain_name)
    assert acm_arn

    renew(
        certificate=certificate,
        storage=storage,
        acme_directory_url=acme_directory_url,
        acme_account_email="fake@example.com",
        authenticators=[auth],
    )
    pem_data = storage.get_certificate(domains=[domain_name]).fullchain
    assert pem_data
    cert = x509.load_pem_x509_certificate(pem_data, default_backend())
    sans = cert.extensions.get_extension_for_class(
        x509.extensions.SubjectAlternativeName
    ).value
    assert domain_name in [x.value for x in sans]
    assert cert.not_valid_before_utc > valid_from
    assert datetime.now(timezone.utc) > cert.not_valid_before_utc

    new_acm_arn = observer._acm_arn_resolver.get(domain_name)
    assert acm_arn == new_acm_arn

    revoke(
        certificate=certificate,
        storage=storage,
        acme_directory_url=acme_directory_url,
        acme_account_email="fake@example.com",
    )
    assert storage.get_certificate(domains=[domain_name]) is None


def test_san_mixed(
    get_dns_txt_records, acme_directory_url, minio_bucket, pebble, full_infra, r53
):
    storage = S3Storage(bucket=minio_bucket)
    domains = ["*.example.com", "fake.com", "www.fake.com", "my.com"]

    dns_auth = Route53Authenticator(
        r53, {"example.com": "ZONEID2", "www.fake.com": "ZONEID2"}
    )
    http_auth = HTTP01Authenticator(storage=storage)
    issue(
        domains=domains,
        storage=storage,
        acme_directory_url=acme_directory_url,
        acme_account_email="fake@example.com",
        authenticators=[dns_auth, http_auth],
    )
    pem_data = storage.get_certificate(domains=domains).fullchain
    assert pem_data
    cert = x509.load_pem_x509_certificate(pem_data, default_backend())
    # Modern certs (RFC 8555) use SANs, CN may be empty
    sans = cert.extensions.get_extension_for_class(
        x509.extensions.SubjectAlternativeName
    ).value
    assert [x.value for x in sans] == domains
    valid_from = cert.not_valid_before_utc
    assert datetime.now(timezone.utc) > valid_from
