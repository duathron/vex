"""Built-in AbuseIPDB secondary enricher plugin.

Augments InvestigateResult for IP-type IOCs with AbuseIPDB abuse confidence
score, total reports, and last-reported timestamp.

Requires an AbuseIPDB API key (VEX_ABUSEIPDB_API_KEY env var or
enrichment.abuseipdb_api_key in config). Without a key the enricher is a
complete no-op — no network calls, no errors.
"""

from __future__ import annotations

import logging

import httpx

from ..config import Config
from ..enrichers.protocol import SecondaryEnricherProtocol
from ..models import InvestigateResult

logger = logging.getLogger("vex.plugins.abuseipdb")

_ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDBPlugin:
    """Secondary enricher that adds AbuseIPDB data to IP investigate results."""

    @property
    def name(self) -> str:
        return "AbuseIPDB"

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
        """Augment *result* with AbuseIPDB data.

        Fail-open: any exception (network, parse, etc.) is caught and logged at
        DEBUG level. The method never raises out of itself.
        """
        key = config.abuseipdb_api_key
        if not key:
            return

        try:
            response = httpx.get(
                _ABUSEIPDB_CHECK_URL,
                params={
                    "ipAddress": ioc,
                    "maxAgeInDays": config.enrichment.abuseipdb_max_age_days,
                },
                headers={"Key": key, "Accept": "application/json"},
                timeout=5.0,
            )

            if response.status_code != 200:
                logger.debug("AbuseIPDB returned HTTP %d for %s", response.status_code, ioc)
                return

            data = response.json().get("data", {})
            result.abuse_confidence = data.get("abuseConfidenceScore")
            result.abuse_total_reports = data.get("totalReports")
            result.abuse_last_reported = data.get("lastReportedAt")

        except Exception as exc:
            logger.debug("AbuseIPDB enrichment failed for %s: %s", ioc, exc)


# Verify protocol compliance at import time
if not isinstance(AbuseIPDBPlugin(), SecondaryEnricherProtocol):
    raise TypeError("AbuseIPDBPlugin does not satisfy SecondaryEnricherProtocol")
