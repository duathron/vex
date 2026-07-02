"""Built-in Shodan secondary enricher plugin.

Augments InvestigateResult for IP-type IOCs with Shodan open-port list,
hostnames, organisation, and tags.

Requires a Shodan API key (VEX_SHODAN_API_KEY env var or
enrichment.shodan_api_key in config). Without a key the enricher is a
complete no-op — no network calls, no errors.
"""

from __future__ import annotations

import logging

import httpx

from ..config import Config
from ..enrichers.protocol import SecondaryEnricherProtocol
from ..models import InvestigateResult

logger = logging.getLogger("vex.plugins.shodan")

_SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}"


class ShodanPlugin:
    """Secondary enricher that adds Shodan data to IP investigate results."""

    @property
    def name(self) -> str:
        return "Shodan"

    @property
    def supported_ioc_types(self) -> list[str]:
        return ["ipv4", "ipv6"]

    def enrich(
        self,
        result: InvestigateResult,
        ioc: str,
        ioc_type: str,
        config: Config,
    ) -> None:
        """Augment *result* with Shodan data.

        Fail-open: any exception (network, parse, etc.) is caught and logged at
        DEBUG level. The method never raises out of itself.
        """
        key = config.shodan_api_key
        if not key:
            return

        try:
            response = httpx.get(
                _SHODAN_HOST_URL.format(ip=ioc),
                params={"key": key},
                timeout=5.0,
            )

            if response.status_code != 200:
                logger.debug("Shodan returned HTTP %d for %s", response.status_code, ioc)
                return

            data = response.json()
            result.shodan_ports = data.get("ports") or []
            result.shodan_hostnames = data.get("hostnames") or []
            result.shodan_org = data.get("org") or None
            result.shodan_tags = data.get("tags") or []

        except Exception as exc:
            logger.debug("Shodan enrichment failed for %s: %s", ioc, exc)


# Verify protocol compliance at import time
if not isinstance(ShodanPlugin(), SecondaryEnricherProtocol):
    raise TypeError("ShodanPlugin does not satisfy SecondaryEnricherProtocol")
