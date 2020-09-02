import datetime
import typing

from .storage.base import BaseStorage


def find_certificates_to_renew(
    storage: BaseStorage, cert_fresh_days: int = 60
) -> typing.Iterator[typing.Tuple[str, datetime.datetime]]:
    """Returns iterator of `domain name` and `valid after date` of stored certs."""
    now = datetime.datetime.now(datetime.timezone.utc)
    for domain_name, valid_after in storage.list_certificates():
        fresh_before = valid_after + datetime.timedelta(days=cert_fresh_days)
        if now > fresh_before:
            yield (domain_name, valid_after)
