import datetime

import acme.messages
import pytest
import time_machine
from dateutil.tz import tzutc

from acme_serverless_client.helpers import find_certificates_to_renew
from acme_serverless_client.models import Account, Domain
from acme_serverless_client.storage.aws import (
    ACMStorageObserver,
    S3Storage,
    S3StorageMixin,
)
from acme_serverless_client.storage.base import BaseStorage


class FakeStorage(BaseStorage):
    def __init__(self, data=None):
        self._data = data or {}
        self._subscribers = set()

    def _get(self, key):
        return self._data.get(key)

    def _set(self, key, data, **kwargs):
        self._data[key] = data


@pytest.fixture(scope="module")
def moto_certs(read_fixture):
    return read_fixture("moto/private.key"), read_fixture("moto/fullchain.pem")


def test_account():
    storage = FakeStorage()
    assert storage.get_account() is None
    account = Account(
        regr=acme.messages.RegistrationResource(
            body=acme.messages.Registration.from_json({"a": "b"}),
            uri="http://127.0.0.1:1400/account/",
            terms_of_service=True,
        )
    )
    storage.set_account(account)
    assert storage.get_account() == account
    assert account.key


def test_domain():
    storage = FakeStorage()
    domain = storage.get_domain("*.my.com")
    assert domain
    assert domain.key


def test_domain_exist():
    storage = FakeStorage({"keys/*.my.com": b"randomprivatekey"})
    domain = storage.get_domain("*.my.com")
    assert domain
    assert domain.key == b"randomprivatekey"


def test_get_certificate():
    storage = FakeStorage()
    domain = Domain("my.com")
    assert storage.get_certificate(domain) is None
    storage.set_certificate(domain, b"cert bytes")
    assert storage.get_certificate(domain) == b"cert bytes"
    assert storage._data == {"certificates/my.com": b"cert bytes"}


def test_s3_bucket_ops(bucket):
    key = "path/to/object.txt"
    bucket.put(key, b"testx")
    assert bucket.get(key) == b"testx"
    objects = list(bucket.list())
    assert len(objects) == 1
    bucket.put("some/key", b"test2")
    objects = list(bucket.list())
    assert len(objects) == 2
    assert len(list(bucket.list(MaxKeys=1))) == 2


def test_s3_mixin_ops(bucket):
    storage = S3StorageMixin(bucket=bucket)
    key = "keys/example.com"
    assert storage._get(key) is None
    storage._set(key, b"mybytes")
    assert storage._get(key) == b"mybytes"


FULLCHAIN_PEM = b"""-----BEGIN CERTIFICATE-----
bytes
-----END CERTIFICATE-----

-----BEGIN CERTIFICATE-----
morebytes
-----END CERTIFICATE-----
"""


def test_acm_extract_certificate():

    cert = b"""-----BEGIN CERTIFICATE-----
bytes
-----END CERTIFICATE-----
"""
    chain = b"""-----BEGIN CERTIFICATE-----
morebytes
-----END CERTIFICATE-----
"""
    assert ACMStorageObserver._extract_certificate(FULLCHAIN_PEM) == (cert, chain)


def test_acm_set_certificate(acm, read_fixture, moto_certs):
    key_pem, fullchain_pem = moto_certs
    storage = FakeStorage()
    observer = ACMStorageObserver(acm=acm)
    storage.subscribe(observer)
    storage.set_certificate(Domain("*.moto.com"), fullchain_pem)
    resp = acm.list_certificates()
    assert len(resp["CertificateSummaryList"]) == 1

    assert (
        observer._acm_arn_resolver.get("*.moto.com")
        == resp["CertificateSummaryList"][0]["CertificateArn"]
    )
    assert resp["CertificateSummaryList"][0]["DomainName"] == "*.moto.com"


def test_s3_find_expired(bucket, acm, moto_certs):
    key_pem, fullchain_pem = moto_certs
    storage = S3Storage(bucket=bucket)
    storage.subscribe(ACMStorageObserver(acm=acm))
    storage.set_certificate(Domain("*.example.com", key=key_pem), fullchain_pem)
    now = datetime.datetime.utcnow().replace(tzinfo=tzutc())
    assert not list(find_certificates_to_renew(storage))
    with time_machine.travel(now + datetime.timedelta(days=59)):
        assert not list(find_certificates_to_renew(storage))
    with time_machine.travel(now - datetime.timedelta(days=10)):
        assert not list(find_certificates_to_renew(storage))
    with time_machine.travel(now + datetime.timedelta(days=61)):
        certs = list(find_certificates_to_renew(storage))
        assert len(certs) == 1
        assert certs[0][0] == "*.example.com"
    with time_machine.travel(now + datetime.timedelta(days=356)):
        certs = list(find_certificates_to_renew(storage))
        assert len(certs) == 1
        assert certs[0][0] == "*.example.com"
    with time_machine.travel(now + datetime.timedelta(days=90)):
        storage.set_certificate(Domain("new.example.com", key=key_pem), fullchain_pem)
        certs = list(find_certificates_to_renew(storage))
        assert len(certs) == 1
    with time_machine.travel(now + datetime.timedelta(days=180)):
        certs = list(find_certificates_to_renew(storage))
        assert len(certs) == 2
