import datetime
import io
import typing

import botocore.exceptions

from ..models import Domain
from .base import BaseStorage

if typing.TYPE_CHECKING:
    BaseMixin = BaseStorage
else:
    BaseMixin = object


class S3StorageMixin(BaseMixin):
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


class ACMStorageMixin(BaseMixin):
    ACM_TAG = "lambda-acme"

    class ARNResolver:
        def __init__(self, client: typing.Any):
            self.client = client
            self._store: typing.Optional[typing.Mapping[str, str]] = None

        def get(self, domain_name: str) -> typing.Optional[str]:
            if self._store is None:
                self._store = self._fetch_acm_certificates()
            return self._store.get(domain_name)

        def _fetch_acm_certificates(self) -> typing.Mapping[str, str]:
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
        self._acm_arn_resolver = ACMStorageMixin.ARNResolver(client=acm)
        super().__init__(*args, **kwargs)

    @staticmethod
    def _extract_certificate(fullchain_pem: bytes) -> typing.Tuple[bytes, bytes]:
        sep = "-----END CERTIFICATE-----\n"
        part1, part2, chain = fullchain_pem.decode().partition(sep)
        return (part1 + part2).encode(), chain.lstrip().encode()

    def get_domain(self, name: str, **kwargs: typing.Any,) -> Domain:
        acm_arn = self._acm_arn_resolver.get(name)
        return super().get_domain(name=name, acm_arn=acm_arn, **kwargs)

    def set_certificate(self, domain: Domain, fullchain_pem: bytes) -> None:
        cert, chain = ACMStorageMixin._extract_certificate(fullchain_pem)
        kwargs = {
            "Certificate": cert,
            "PrivateKey": domain.key,
            "CertificateChain": chain,
            "Tags": [{"Key": self.ACM_TAG}],
        }
        if domain.acm_arn:
            kwargs["CertificateArn"] = domain.acm_arn
        domain.acm_arn = self.acm.import_certificate(**kwargs)["CertificateArn"]
        if "CertificateArn" not in kwargs and self._acm_arn_resolver._store is not None:
            self._acm_arn_resolver._store[domain.name] = domain.acm_arn  # type: ignore
        super().set_certificate(domain, fullchain_pem)

    def remove_domain(self, domain: Domain) -> None:
        """
        Remove certificate from ACM.
        Will fail with ResourceInUseException if it in use.
        """
        if domain.acm_arn:
            self.acm.delete_certificate(CertificateArn=domain.acm_arn)
        super().remove_domain(domain)


class S3Storage(S3StorageMixin, BaseStorage):
    pass


class ACMStorage(ACMStorageMixin, S3StorageMixin, BaseStorage):
    pass
