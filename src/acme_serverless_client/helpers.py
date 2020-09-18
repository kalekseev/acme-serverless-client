import datetime
import typing

from .models import Certificate
from .storage.base import StorageProtocol


def find_certificates_to_renew(
    storage: StorageProtocol, cert_fresh_days: int = 60
) -> typing.Iterator[typing.Tuple[Certificate, datetime.datetime]]:
    """Returns iterator of `domain name` and `valid after date` of stored certs."""
    now = datetime.datetime.now(datetime.timezone.utc)
    for cert_name, valid_after in storage.list_certificates():
        fresh_before = valid_after + datetime.timedelta(days=cert_fresh_days)
        if now > fresh_before:
            cert = storage.get_certificate(name=cert_name)
            assert cert
            yield (cert, valid_after)
