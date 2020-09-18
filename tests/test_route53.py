import datetime
import json

import acme
import urllib3
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from acme_serverless_client import issue
from acme_serverless_client.authenticators.dns_route_53 import Route53Authenticator
from acme_serverless_client.storage.aws import S3Storage


def test_route53_boto_proxy(get_dns_txt_records, r53):
    batch = {
        "Comment": "acme-serverless-client certificate validation UPSERT",
        "Changes": [
            {
                "Action": "UPSERT",
                "ResourceRecordSet": {
                    "Name": "example.org.",
                    "Type": "TXT",
                    "TTL": 10,
                    "ResourceRecords": [
                        {"Value": '"random1"'},
                        {"Value": '"random2"'},
                    ],
                },
            },
            {
                "Action": "UPSERT",
                "ResourceRecordSet": {
                    "Name": "example.net.",
                    "Type": "TXT",
                    "TTL": 10,
                    "ResourceRecords": [{"Value": '"text"'}],
                },
            },
        ],
    }
    r53.change_resource_record_sets(None, batch)
    records = get_dns_txt_records("example.org")
    assert records == ['"random1"', '"random2"']
    records = get_dns_txt_records("example.net")
    assert records == ['"text"']
    for change in batch["Changes"]:
        change["Action"] = "DELETE"
    r53.change_resource_record_sets(None, batch)
    records = get_dns_txt_records("example.org")
    assert not records
    records = get_dns_txt_records("example.net")
    assert not records


def test_txt_resolver(get_dns_txt_records):
    http = urllib3.PoolManager()
    data = {"host": "exmaple.com.", "value": "foo"}
    r = http.request(
        "POST",
        "http://localhost:8055/set-txt",
        body=json.dumps(data).encode(),
        headers={"Content-Type": "application/json"},
    )
    assert r.status == 200
    data = {"host": "exmaple.com.", "value": "bar"}
    r = http.request(
        "POST",
        "http://localhost:8055/set-txt",
        body=json.dumps(data).encode(),
        headers={"Content-Type": "application/json"},
    )
    assert r.status == 200
    records = get_dns_txt_records("exmaple.com")
    assert records == ['"foo"', '"bar"']
    r = http.request(
        "POST",
        "http://localhost:8055/clear-txt",
        body=json.dumps({"host": "exmaple.com."}).encode(),
        headers={"Content-Type": "application/json"},
    )
    assert r.status == 200
    assert records == ['"foo"', '"bar"']
    r = http.request(
        "POST",
        "http://localhost:8055/clear-txt",
        body=json.dumps({"host": "exmaple.com."}).encode(),
        headers={"Content-Type": "application/json"},
    )
    assert r.status == 200
    records = get_dns_txt_records("exmaple.com")
    assert not records


def test_authenticator_zones():
    auth = Route53Authenticator(
        None,
        {
            "my.example.com": "ZONEID1",
            "example.com": "ZONEID2",
            "my.example.org": "ZONEID0",
        },
    )
    chall = acme.challenges.DNS01()
    assert auth.is_supported("my.example.com", chall)
    assert auth.is_supported("xxx.my.example.com", chall)
    assert not auth.is_supported("example.net", chall)
    assert not auth.is_supported("com", chall)
    assert auth._get_zone_id("my.example.com") == "ZONEID1"
    assert auth._get_zone_id("xxx.my.example.com") == "ZONEID1"
    assert auth._get_zone_id("yyy.example.com") == "ZONEID2"
    assert auth._get_zone_id("example.com") == "ZONEID2"
    assert auth._get_zone_id("example.org") is None


def test_dns01(
    get_dns_txt_records, acme_directory_url, minio_bucket, pebble, disable_ssl, r53
):
    storage = S3Storage(bucket=minio_bucket)
    domain_name = "*.example.com"

    auth = Route53Authenticator(
        r53,
        {
            "my.example.com": "ZONEID1",
            "example.com": "ZONEID2",
            "my.example.org": "ZONEID0",
        },
    )
    issue(
        domains=[domain_name],
        storage=storage,
        acme_directory_url=acme_directory_url,
        acme_account_email="fake@example.com",
        authenticators=[auth],
    )
    pem_data = storage.get_certificate(domains=[domain_name]).fullchain
    assert pem_data
    cert = x509.load_pem_x509_certificate(pem_data, default_backend())
    assert cert.subject.rfc4514_string() == f"CN={domain_name}"
    valid_from = cert.not_valid_before
    assert datetime.datetime.now() > valid_from


def test_san_dns01(
    get_dns_txt_records, acme_directory_url, minio_bucket, pebble, full_infra, r53
):
    storage = S3Storage(bucket=minio_bucket)
    domains = ["*.example.com", "www.fake.com"]

    dns_auth = Route53Authenticator(
        r53, {"example.com": "ZONEID2", "www.fake.com": "ZONEID2"}
    )
    issue(
        domains=domains,
        storage=storage,
        acme_directory_url=acme_directory_url,
        acme_account_email="fake@example.com",
        authenticators=[dns_auth],
    )
    pem_data = storage.get_certificate(domains=domains).fullchain
    assert pem_data
    cert = x509.load_pem_x509_certificate(pem_data, default_backend())
    assert cert.subject.rfc4514_string() == f"CN={domains[0]}"
    sans = cert.extensions.get_extension_for_class(
        x509.extensions.SubjectAlternativeName
    ).value
    assert [x.value for x in sans] == domains
    valid_from = cert.not_valid_before
    assert datetime.datetime.now() > valid_from
