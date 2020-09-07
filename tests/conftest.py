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
from acme.standalone import BaseDualNetworkedServers, HTTPServer
from botocore.client import Config
from moto import mock_acm, mock_s3
from urllib3.exceptions import InsecureRequestWarning

from acme_serverless_client.storage.aws import S3Storage


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
    with mock_s3():
        yield boto3.client("s3", region_name="ap-southeast-2")


@pytest.fixture(scope="function")
def acm(moto_credentials):
    with mock_acm():
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
        lambda *args, **kwargs: net_cls(verify_ssl=False, *args, **kwargs),
    )
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", InsecureRequestWarning)
        yield


@pytest.fixture(scope="session")
def load_balancer(pebble_settings, minio_boto3_settings, minio_settings):
    class RedirectHandler(BaseHTTPRequestHandler):
        def do_HEAD(s):
            s.send_response(301)
            if not s.path.startswith("/.well-known/acme-challenge/"):
                raise ValueError(f"Got invalid request. path: {s.path}")
            s.send_header(
                "Location",
                f"{minio_boto3_settings['endpoint_url']}/{minio_settings['BUCKET']}{s.path}",
            )
            s.end_headers()

        def do_GET(s):
            s.do_HEAD()

    port = pebble_settings["HTTP_PORT"]
    server = BaseDualNetworkedServers(HTTPServer, ("", port), RedirectHandler)
    server.serve_forever()
    try:
        await_port(port)
        yield {"url": f"http://127.0.0.1:{port}"}
    finally:
        server.shutdown_and_server_close()


def await_port(port: typing.Union[str, int], timeout=4):
    start = time.time()
    a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while a_socket.connect_ex(("127.0.0.1", int(port))):
        time.sleep(0.01)
        if time.time() - start > timeout:
            raise SystemError(f"Timeout reached waiting for port {port}.")
        a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


@pytest.fixture(scope="session")
def minio(minio_settings):
    os.environ["MINIO_ACCESS_KEY"] = minio_settings["ACCESS_KEY"]
    os.environ["MINIO_SECRET_KEY"] = minio_settings["SECRET_KEY"]
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
                "Resource": [f"arn:aws:s3:::{name}/.well-known/acme-challenge/*"],
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
