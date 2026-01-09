import json
import os
import pathlib
import shutil
import socket
import subprocess
import time
import typing
import warnings
from http.server import BaseHTTPRequestHandler

import boto3
import pytest
import urllib3
from acme.standalone import BaseDualNetworkedServers, HTTPServer
from botocore.client import Config
from moto import mock_aws
from urllib3.exceptions import InsecureRequestWarning

from acme_serverless_client.storage.aws import S3Storage


# Patch moto's CertBundle to handle certificates without CN (modern certs use SANs only)
def _patch_moto_certbundle():
    from cryptography.x509.oid import NameOID
    from moto.acm import models as acm_models

    def new_init(
        self,
        account_id,
        certificate,
        private_key,
        chain=None,
        region="us-east-1",
        arn=None,
        cert_type="IMPORTED",
        cert_status="ISSUED",
        cert_authority_arn=None,
        cert_options=None,
    ):
        from moto.acm.models import AWS_ROOT_CA, TagHolder, make_arn_for_certificate

        self.created_at = acm_models.utcnow()
        self.cert = certificate
        self.key = private_key
        self.chain = chain + b"\n" + AWS_ROOT_CA if chain else AWS_ROOT_CA
        self.tags = TagHolder()
        self.type = cert_type
        self.status = cert_status
        self.cert_authority_arn = cert_authority_arn
        self.in_use_by = []
        self.cert_options = cert_options or {
            "CertificateTransparencyLoggingPreference": "ENABLED",
            "Export": "DISABLED",
        }

        self._key = self.validate_pk()
        self._cert = self.validate_certificate()

        # Handle certificates without CN (modern certs use SANs only)
        cn_attrs = self._cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attrs:
            self.common_name = cn_attrs[0].value
        else:
            # Fall back to first SAN DNS name
            try:
                from cryptography import x509

                san_ext = self._cert.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                )
                dns_names = san_ext.value.get_values_for_type(x509.DNSName)
                self.common_name = dns_names[0] if dns_names else "unknown"
            except Exception:
                self.common_name = "unknown"

        if chain is not None:
            self.validate_chain()

        self.arn = arn or make_arn_for_certificate(account_id, region)

    acm_models.CertBundle.__init__ = new_init


_patch_moto_certbundle()


@pytest.fixture(scope="session")
def minio_settings(tmpdir_factory):
    return {
        "ACCESS_KEY": "minio_test_access_key",
        "SECRET_KEY": "minio_test_secret_key",
        "DATA": str(tmpdir_factory.mktemp("minio")),
        "PORT": 9000,
        "BUCKET": "cert-test-bucket",
    }


@pytest.fixture(scope="session")
def pebble_settings(tmpdir_factory):
    return {"DIRECTORY_PORT": 14000, "HTTP_PORT": 5002, "DNS_PORT": 8053}


@pytest.fixture(scope="session")
def minio_boto3_settings(minio_settings):
    return {
        "endpoint_url": f"http://127.0.0.1:{minio_settings['PORT']}",
        "aws_access_key_id": minio_settings["ACCESS_KEY"],
        "aws_secret_access_key": minio_settings["SECRET_KEY"],
        "config": Config(signature_version="s3v4"),
    }


@pytest.fixture(autouse=True)
def moto_credentials(monkeypatch):
    """Mocked AWS Credentials for moto."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")


@pytest.fixture(scope="session")
def read_fixture():
    def read(path):
        d = pathlib.PosixPath(__file__) / "../../fixtures" / path.lstrip("/")
        return d.resolve().read_bytes()

    return read


@pytest.fixture(scope="function")
def s3(moto_credentials):
    with mock_aws():
        yield boto3.client("s3", region_name="ap-southeast-2")


@pytest.fixture(scope="function")
def acm(moto_credentials):
    with mock_aws():
        yield boto3.client("acm", region_name="ap-southeast-2")


@pytest.fixture(autouse=True)
def lambda_env(monkeypatch, pebble_settings, minio_settings) -> None:
    monkeypatch.setenv("AWS_REGION", "ap-southest-2")
    monkeypatch.setenv("BUCKET", minio_settings["BUCKET"])
    monkeypatch.setenv(
        "DIRECTORY_URL", f"https://127.0.0.1:{pebble_settings['DIRECTORY_PORT']}/dir"
    )
    monkeypatch.setenv("ACCOUNT_EMAIL", "fake@example.com")


@pytest.fixture
def acme_directory_url(pebble_settings):
    return f"https://127.0.0.1:{pebble_settings['DIRECTORY_PORT']}/dir"


@pytest.fixture(scope="session")
def pebble_config(tmpdir_factory, pebble_settings, read_fixture):
    d = tmpdir_factory.mktemp("pebble")
    config = d.join("pebble-config.json")
    cert = d.join("cert.pem")
    key = d.join("key.pem")
    cert.write(read_fixture("localhost/cert.pem"))
    key.write(read_fixture("localhost/key.pem"))
    config.write(
        json.dumps(
            {
                "pebble": {
                    "listenAddress": f"0.0.0.0:{pebble_settings['DIRECTORY_PORT']}",
                    "managementListenAddress": "0.0.0.0:15000",
                    "certificate": str(cert),
                    "privateKey": str(key),
                    "httpPort": pebble_settings["HTTP_PORT"],
                    "tlsPort": 5001,
                    "ocspResponderURL": "",
                    "externalAccountBindingRequired": False,
                }
            }
        )
    )
    return str(config)


@pytest.fixture
def disable_ssl(monkeypatch: typing.Any) -> typing.Iterator[None]:
    import acme.client

    net_cls = acme.client.ClientNetwork
    monkeypatch.setattr(
        "acme_serverless_client.client.acme.client.ClientNetwork",
        lambda *args, **kwargs: net_cls(*args, **{**kwargs, "verify_ssl": False}),
    )
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", InsecureRequestWarning)
        yield


@pytest.fixture(scope="session")
def load_balancer(pebble_settings, minio_boto3_settings, minio_settings):
    class RedirectHandler(BaseHTTPRequestHandler):
        def do_HEAD(self):
            self.send_response(301)
            if not self.path.startswith("/.well-known/acme-challenge/"):
                raise ValueError(f"Got invalid request. path: {self.path}")
            self.send_header(
                "Location",
                f"{minio_boto3_settings['endpoint_url']}/{minio_settings['BUCKET']}{self.path}",
            )
            self.end_headers()

        def do_GET(self):
            self.do_HEAD()

    port = pebble_settings["HTTP_PORT"]
    server = BaseDualNetworkedServers(HTTPServer, ("", port), RedirectHandler)
    server.serve_forever()
    try:
        await_port(port)
        yield {"url": f"http://127.0.0.1:{port}"}
    finally:
        server.shutdown_and_server_close()


def await_port(port: str | int, timeout=4):
    start = time.time()
    a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while a_socket.connect_ex(("127.0.0.1", int(port))):
        time.sleep(0.01)
        if time.time() - start > timeout:
            raise SystemError(f"Timeout reached waiting for port {port}.")
        a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


@pytest.fixture(scope="session")
def minio(minio_settings):
    os.environ["MINIO_ROOT_USER"] = minio_settings["ACCESS_KEY"]
    os.environ["MINIO_ROOT_PASSWORD"] = minio_settings["SECRET_KEY"]
    proc = subprocess.Popen(
        [
            "minio",
            "server",
            "--address",
            f"127.0.0.1:{minio_settings['PORT']}",
            minio_settings["DATA"],
        ]
    )
    try:
        await_port(minio_settings["PORT"])
        yield
    finally:
        proc.terminate()


@pytest.fixture(scope="session")
def _minio_bucket(minio, minio_boto3_settings, minio_settings):
    client = boto3.client("s3", **minio_boto3_settings)
    name = minio_settings["BUCKET"]
    client.create_bucket(Bucket=name)
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AddPerm",
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["s3:GetObject"],
                "Resource": [f"arn:aws:s3:::{name}/.well-known/acme-challenge/*"],
            }
        ],
    }
    client.put_bucket_policy(Bucket=name, Policy=json.dumps(policy))
    return S3Storage.Bucket(name, client)


@pytest.fixture
def minio_bucket(_minio_bucket, minio_settings) -> typing.Iterator[None]:
    tempdir = pathlib.Path(minio_settings["DATA"])
    yield _minio_bucket
    for file in os.scandir(tempdir / _minio_bucket.name):
        if file.is_dir():
            shutil.rmtree(file.path)
        else:
            os.unlink(file.path)


@pytest.fixture
def bucket(s3, minio_settings):
    name = minio_settings["BUCKET"]
    s3.create_bucket(
        Bucket=name, CreateBucketConfiguration={"LocationConstraint": "ap-southeast-2"}
    )
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AddPerm",
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["s3:GetObject"],
                "Resource": [
                    f"arn:aws:s3:::{name}/.well-known/acme-challenge/*",
                    f"arn:aws:s3:::{name}/certificates/*",
                    f"arn:aws:s3:::{name}/keys/*",
                    f"arn:aws:s3:::{name}/configs/*",
                ],
            }
        ],
    }
    s3.put_bucket_policy(Bucket=name, Policy=json.dumps(policy))
    return S3Storage.Bucket(name, s3)


@pytest.fixture()
def pebble(pebble_settings, pebble_config) -> typing.Iterator[None]:
    proc = subprocess.Popen(
        [
            "pebble",
            "-config",
            pebble_config,
            "-strict",
            "-dnsserver",
            f"127.0.0.1:{pebble_settings['DNS_PORT']}",
        ]
    )
    try:
        await_port(pebble_settings["DIRECTORY_PORT"])
        yield
    finally:
        proc.terminate()


@pytest.fixture(scope="session")
def challtestsrv(pebble_settings) -> typing.Iterator[None]:
    proc = subprocess.Popen(
        ["pebble-challtestsrv", "-http01", "''", "-https01", "''", "-tlsalpn01", "''"]
    )
    try:
        await_port(pebble_settings["DNS_PORT"])
        yield
    finally:
        proc.terminate()


@pytest.fixture()
def full_infra(pebble, challtestsrv, minio, load_balancer, acm, disable_ssl):
    pass


@pytest.fixture
def get_dns_txt_records(pebble_settings, challtestsrv):
    def f(domain):
        r = subprocess.check_output(
            [
                "dig",
                "+short",
                "-t",
                "txt",
                domain,
                "@127.0.0.1",
                "-p",
                str(pebble_settings["DNS_PORT"]),
            ]
        )
        return r.decode().strip().split()

    return f


class Route53BotoProxy:
    def __init__(self):
        self._zone_changes = {}

    def change_resource_record_sets(self, HostedZoneId, ChangeBatch):
        http = urllib3.PoolManager()
        for change in ChangeBatch["Changes"]:
            domain = change["ResourceRecordSet"]["Name"]
            data = {"host": domain}
            if change["Action"] == "UPSERT":
                for value in change["ResourceRecordSet"]["ResourceRecords"]:
                    data["value"] = value["Value"].strip('"')
                    r = http.request(
                        "POST",
                        "http://localhost:8055/set-txt",
                        body=json.dumps(data).encode(),
                        headers={"Content-Type": "application/json"},
                    )
                    assert r.status == 200
            elif change["Action"] == "DELETE":
                r = http.request(
                    "POST",
                    "http://localhost:8055/clear-txt",
                    body=json.dumps(data).encode(),
                    headers={"Content-Type": "application/json"},
                )
                assert r.status == 200
            else:
                raise ValueError(f"Unknown action: {change['Action']}")
        return {"ChangeInfo": {"Id": "random"}}

    def get_change(self, Id):
        return {"ChangeInfo": {"Status": "INSYNC"}}


@pytest.fixture
def r53():
    return Route53BotoProxy()
