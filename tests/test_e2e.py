import datetime
import urllib.request

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from acme_serverless_client import issue_or_renew, revoke
from acme_serverless_client.models import Domain
from acme_serverless_client.storage.aws import ACMStorage


def test_load_balancer_redirect(minio_bucket, load_balancer, acm):
    storage = ACMStorage(bucket=minio_bucket, acm=acm)
    storage.set_validation("/.well-known/acme-challenge/randomkey", b"secretstring")
    r = urllib.request.urlopen(
        load_balancer["url"] + "/.well-known/acme-challenge/randomkey"
    )
    assert r.status == 200
    assert r.read() == b"secretstring"


def test_acm_issue_renew_revoke(minio_bucket, full_infra, acm, acme_directory_url):
    storage = ACMStorage(bucket=minio_bucket, acm=acm)
    domain_name = "my3.example.com"

    issue_or_renew(
        domain_name,
        storage,
        acme_directory_url=acme_directory_url,
        acme_account_email="fake@example.com",
    )
    pem_data = storage.get_certificate(Domain(domain_name))
    assert pem_data
    cert = x509.load_pem_x509_certificate(pem_data, default_backend())
    assert cert.subject.rfc4514_string() == f"CN={domain_name}"
    valid_from = cert.not_valid_before
    assert datetime.datetime.now() > valid_from

    domain = storage.get_domain(domain_name)
    assert domain.acm_arn
    acm_arn = domain.acm_arn

    issue_or_renew(
        domain_name,
        storage,
        acme_directory_url=acme_directory_url,
        acme_account_email="fake@example.com",
    )
    pem_data = storage.get_certificate(Domain(domain_name))
    assert pem_data
    cert = x509.load_pem_x509_certificate(pem_data, default_backend())
    assert cert.subject.rfc4514_string() == f"CN={domain_name}"
    assert cert.not_valid_before > valid_from
    assert datetime.datetime.now() > cert.not_valid_before

    domain = storage.get_domain(domain_name)
    assert domain.acm_arn
    assert acm_arn == domain.acm_arn

    revoke(
        domain_name,
        storage,
        acme_directory_url=acme_directory_url,
        acme_account_email="fake@example.com",
    )
    assert storage.get_certificate(Domain(domain_name)) is None
