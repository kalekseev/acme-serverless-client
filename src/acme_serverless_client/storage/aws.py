import datetime
import io
import typing

import botocore.exceptions

from ..models import Domain
from .base import BaseStorage, StorageObserverProtocol


class S3Storage(BaseStorage):
    class Bucket:
        def __init__(self, name: str, client: typing.Any):
            self.name = name
            self.client = client

        def put(self, key: str, data: bytes) -> None:
            self.client.upload_fileobj(io.BytesIO(data), self.name, key)

        def get(self, key: str) -> typing.Optional[bytes]:
            obj = io.BytesIO()
            try:
                self.client.download_fileobj(self.name, key, obj)
            except botocore.exceptions.ClientError as exc:
                if exc.response["Error"]["Code"] == "404":
                    return None
                raise exc
            obj.seek(0)
            return obj.read()

        def list(
            self, **kwargs: typing.Any
        ) -> typing.Iterator[typing.Mapping[str, typing.Any]]:
            params = {
                **kwargs,
                "Bucket": self.name,
            }
            while True:
                response = self.client.list_objects_v2(**params)
                yield from response["Contents"]
                if not response["IsTruncated"]:
                    break
                params["ContinuationToken"] = response["NextContinuationToken"]

        def delete(self, key: str) -> None:
            self.client.delete_object(Bucket=self.name, Key=key)

    def __init__(self, bucket: Bucket, *args: typing.Any, **kwargs: typing.Any) -> None:
        self.bucket = bucket
        super().__init__(*args, **kwargs)

    def _get(self, key: str) -> typing.Optional[bytes]:
        return self.bucket.get(key)

    def _set(self, key: str, data: bytes) -> None:
        self.bucket.put(key, data)

    def _del(self, name: str) -> None:
        self.bucket.delete(name)

    def list_certificates(
        self,
    ) -> typing.Iterator[typing.Tuple[str, datetime.datetime]]:
        for obj in self.bucket.list(Prefix=self.certificate_prefix):
            domain_name = obj["Key"].rsplit("/", 1)[-1]
            valid_after = obj["LastModified"]
            yield (domain_name, valid_after)

    def set_validation(self, key: str, value: bytes) -> None:
        if key.startswith("/"):
            key = key.lstrip("/")
        self._set(key, value)

    def del_validation(self, key: str) -> None:
        self._del(key)


class ACMStorageObserver(StorageObserverProtocol):
    ACM_TAG = "acme-serverless-client"

    class ARNResolver:
        def __init__(self, client: typing.Any):
            self.client = client
            self._store: typing.Optional[typing.MutableMapping[str, str]] = None

        def get(self, domain_name: str) -> typing.Optional[str]:
            if self._store is None:
                self._store = self._fetch_acm_certificates()
            return self._store.get(domain_name)

        def set(self, domain_name: str, acm_arn: str) -> None:
            if self._store is None:
                self._store = self._fetch_acm_certificates()
            self._store[domain_name] = acm_arn

        def _fetch_acm_certificates(self) -> typing.MutableMapping[str, str]:
            params: typing.MutableMapping[str, str] = {}
            result = {}
            while True:
                resp = self.client.list_certificates(**params)
                for c in resp["CertificateSummaryList"]:
                    result[c["DomainName"]] = c["CertificateArn"]
                if "NextToken" not in resp:
                    return result
                params["NextToken"] = resp["NextToken"]

    def __init__(
        self, acm: typing.Any, *args: typing.Any, **kwargs: typing.Any
    ) -> None:
        self.acm = acm
        self._acm_arn_resolver = ACMStorageObserver.ARNResolver(client=acm)

    @staticmethod
    def _extract_certificate(fullchain_pem: bytes) -> typing.Tuple[bytes, bytes]:
        sep = "-----END CERTIFICATE-----\n"
        part1, part2, chain = fullchain_pem.decode().partition(sep)
        return (part1 + part2).encode(), chain.lstrip().encode()

    def set_certificate(self, domain: Domain, fullchain_pem: bytes) -> None:
        cert, chain = ACMStorageObserver._extract_certificate(fullchain_pem)
        kwargs = {
            "Certificate": cert,
            "PrivateKey": domain.key,
            "CertificateChain": chain,
            "Tags": [{"Key": self.ACM_TAG}],
        }
        acm_arn = self._acm_arn_resolver.get(domain.name)
        if acm_arn:
            kwargs["CertificateArn"] = acm_arn
        response = self.acm.import_certificate(**kwargs)
        if not acm_arn:
            self._acm_arn_resolver.set(domain.name, response["CertificateArn"])

    def remove_domain(self, domain: Domain) -> None:
        """
        Remove certificate from ACM.
        Will fail with ResourceInUseException if it in use.
        """
        acm_arn = self._acm_arn_resolver.get(domain.name)
        if acm_arn:
            self.acm.delete_certificate(CertificateArn=acm_arn)
