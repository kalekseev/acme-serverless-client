# Modification of
# https://raw.githubusercontent.com/certbot/certbot/fc7e5e8e6060d9e0df2e704a20103d5c0f456925/certbot-dns-route53/certbot_dns_route53/_internal/dns_route53.py
# Apache 2.0 license

import collections
import logging
import time
import typing

from acme import challenges
from botocore.exceptions import ClientError, NoCredentialsError

from .base import AuthenticatorProtocol

logger = logging.getLogger(__name__)


class Route53Authenticator(AuthenticatorProtocol):
    ttl = 10

    def __init__(self, client: typing.Any, zones: typing.Dict[str, str]):
        self.r53 = client
        self.zones = {name.rstrip("."): id for name, id in zones.items()}
        self._resource_records: typing.Dict[
            str, typing.List[typing.Dict[str, str]]
        ] = collections.defaultdict(list)

    def is_supported(self, domain: str, challenge: typing.Any) -> bool:
        return isinstance(challenge, challenges.DNS01) and bool(
            self._get_zone_id(domain)
        )

    def _get_zone_id(self, domain: str) -> typing.Optional[str]:
        domain = domain.rstrip(".")
        while domain:
            if domain in self.zones:
                return self.zones[domain]
            _, _, domain = domain.partition(".")
        return None

    def perform(
        self, challs: typing.Iterable[typing.Tuple[typing.Any, str]], account_key: str
    ) -> None:
        batches = self._build_r53_change_batches("UPSERT", challs, account_key)
        change_ids = [
            self._change_txt_records(zone_id, batch) for zone_id, batch in batches
        ]
        for change_id in change_ids:
            self._wait_for_change(change_id)

    def cleanup(
        self, challs: typing.Iterable[typing.Tuple[typing.Any, str]], account_key: str
    ) -> None:
        batches = self._build_r53_change_batches("DELETE", challs, account_key)
        for zone_id, batch in batches:
            try:
                self._change_txt_records(zone_id, batch)
            except (NoCredentialsError, ClientError) as e:
                logger.debug("Encountered error during cleanup: %s", e, exc_info=True)

    def _build_r53_change_batches(
        self,
        action: typing.Literal["UPSERT", "DELETE"],
        challs: typing.Iterable[typing.Tuple[typing.Any, str]],
        account_key: str,
    ) -> typing.Iterable[typing.Tuple[str, dict]]:
        zone_domains: typing.Dict[str, typing.Dict[str, typing.List[str]]] = {}
        for (challb, domain) in challs:
            zone_id = self._get_zone_id(domain)
            assert zone_id, f"Hosted zone not found for domain {domain}"
            zone_domains.setdefault(zone_id, {}).setdefault(domain, []).append(
                challb.validation(account_key)
            )
        for zone_id, domain_info in zone_domains.items():
            batch = {
                "Comment": f"acme-serverless-client certificate validation {action}",
                "Changes": [
                    {
                        "Action": action,
                        "ResourceRecordSet": {
                            "Name": self._transform_domain_name(domain),
                            "Type": "TXT",
                            "TTL": self.ttl,
                            "ResourceRecords": [
                                {"Value": f'"{validation}"'} for validation in rrecords
                            ],
                        },
                    }
                    for domain, rrecords in domain_info.items()
                ],
            }
            yield zone_id, batch

    def _transform_domain_name(self, domain: str) -> str:
        if domain.startswith("*."):
            domain = domain[2:]
        if not domain.endswith("."):
            domain += "."
        return f"_acme-challenge.{domain}"

    def _change_txt_records(self, zone_id: str, batch: dict) -> str:
        response = self.r53.change_resource_record_sets(
            HostedZoneId=zone_id, ChangeBatch=batch
        )
        change_id: str = response["ChangeInfo"]["Id"]
        return change_id

    def _wait_for_change(self, change_id: str) -> None:
        """Wait for a change to be propagated to all Route53 DNS servers.
        https://docs.aws.amazon.com/Route53/latest/APIReference/API_GetChange.html
        """
        for _ in range(0, 120):
            response = self.r53.get_change(Id=change_id)
            if response["ChangeInfo"]["Status"] == "INSYNC":
                return
            time.sleep(5)
        raise RuntimeError(
            "Timed out waiting for Route53 change. Current status: %s"
            % response["ChangeInfo"]["Status"]
        )
