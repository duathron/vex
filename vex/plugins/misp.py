"""Built-in MISP secondary enricher plugin.

Augments InvestigateResult for all IOC types with MISP attribute matches,
event IDs, TLP markings, and associated tags.

Requires both a MISP URL and an API key (MISP_URL / MISP_API_KEY env vars or
enrichment.misp_url / enrichment.misp_api_key in config). Without both values
the enricher is a complete no-op — no network calls, no errors.

TLP precedence (most restrictive wins): red > amber > green > clear/white.
TLS verification is ON by default and controlled via enrichment.misp_verify_tls.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import httpx

from ..config import Config
from ..enrichers.protocol import SecondaryEnricherProtocol
from ..models import InvestigateResult
from ..tlp import _tlp_rank
from ..tlp import most_restrictive_tlp as _shared_most_restrictive_tlp

logger = logging.getLogger("vex.plugins.misp")

_MISP_SEARCH_PATH = "/attributes/restSearch"


def _most_restrictive_tlp(tags: list[str]) -> str | None:
    """Return the most restrictive TLP level found in the tag list, or None.

    Delegates to the shared :func:`vex.tlp.most_restrictive_tlp` helper and
    uppercases the result to preserve the existing field contract
    (``misp_tlp`` stores e.g. ``"AMBER"``, ``"RED"``).
    """
    level = _shared_most_restrictive_tlp(tags)
    return level.upper() if level is not None else None


def _epoch_to_iso_date(timestamp_str: str) -> str:
    """Convert an epoch timestamp string to ISO date string (YYYY-MM-DD).

    Falls back to the original string if conversion fails.
    """
    try:
        epoch = int(timestamp_str)
        dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d")
    except (ValueError, TypeError, OSError):
        return timestamp_str


class MISPEnricher:
    """Secondary enricher that adds MISP attribute data to investigate results.

    Supports all IOC types — MISP indexes every kind of indicator.
    """

    @property
    def name(self) -> str:
        return "MISP"

    @property
    def supported_ioc_types(self) -> list[str]:
        return ["md5", "sha1", "sha256", "ipv4", "ipv6", "domain", "url"]

    def enrich(
        self,
        result: InvestigateResult,
        ioc: str,
        ioc_type: str,
        config: Config,
    ) -> None:
        """Augment *result* with MISP attribute data.

        Fail-open: any exception (network, parse, etc.) is caught and logged at
        DEBUG level. The method never raises out of itself.
        API key and MISP URL credentials are never written to logs.
        """
        url = config.misp_url
        key = config.misp_api_key
        if not url or not key:
            return

        try:
            search_url = url.rstrip("/") + _MISP_SEARCH_PATH
            response = httpx.post(
                search_url,
                json={"value": ioc, "limit": 25, "includeEventTags": True},
                headers={
                    "Authorization": key,
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                timeout=8.0,
                verify=config.enrichment.misp_verify_tls,
            )

            if response.status_code != 200:
                logger.debug("MISP returned HTTP %d for IOC lookup", response.status_code)
                return

            attributes = response.json().get("response", {}).get("Attribute", [])
            if not attributes:
                return

            result.misp_known = True

            # Collect unique event IDs (preserve order of first appearance)
            seen_event_ids: dict[str, None] = {}
            all_tags: list[str] = []

            max_ts: int | None = None

            for attr in attributes:
                event_id = str(attr.get("event_id", ""))
                if event_id and event_id not in seen_event_ids:
                    seen_event_ids[event_id] = None

                for tag_obj in attr.get("Tag", []):
                    tag_name = tag_obj.get("name", "")
                    if tag_name and tag_name not in all_tags:
                        all_tags.append(tag_name)

                ts_raw = attr.get("timestamp")
                if ts_raw is not None:
                    try:
                        ts_int = int(ts_raw)
                        if max_ts is None or ts_int > max_ts:
                            max_ts = ts_int
                    except (ValueError, TypeError):
                        pass

            result.misp_event_ids = list(seen_event_ids.keys())
            result.misp_tags = all_tags
            result.misp_tlp = _most_restrictive_tlp(all_tags)
            if max_ts is not None:
                result.misp_last_seen = _epoch_to_iso_date(str(max_ts))

        except Exception as exc:
            logger.debug("MISP enrichment failed for IOC lookup: %s", exc)

    def add_sighting(
        self,
        ioc: str,
        config: Config,
        *,
        source: str = "vex",
        source_tlp: str | None = None,
    ) -> bool:
        """Write a sighting for *ioc* back to MISP.

        Returns True on HTTP 200, False for any other outcome (no-config,
        marking-check blocked, HTTP error, network error).

        Marking-check: if ``source_tlp`` is more restrictive than
        ``config.enrichment.writeback_tlp`` (i.e. its rank is lower),
        the write is skipped to prevent cross-platform TLP-level leaks.

        The MISP API key is never written to logs.
        Fail-open: any exception returns False, never raises.
        """
        url = config.misp_url
        key = config.misp_api_key
        if not url or not key:
            return False

        # Marking-check: source stricter than ceiling → skip
        if source_tlp is not None:
            ceiling = config.enrichment.writeback_tlp
            if _tlp_rank(source_tlp) < _tlp_rank(ceiling):
                logger.debug(
                    "MISP sighting skipped: source TLP %s more restrictive than ceiling %s",
                    source_tlp,
                    ceiling,
                )
                return False

        try:
            sighting_url = url.rstrip("/") + "/sightings/add"
            response = httpx.post(
                sighting_url,
                json={"value": ioc, "source": source},
                headers={
                    "Authorization": key,
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                timeout=8.0,
                verify=config.enrichment.misp_verify_tls,
            )

            if response.status_code != 200:
                logger.debug("MISP sighting returned HTTP %d", response.status_code)
                return False

            return True

        except Exception as exc:
            logger.debug("MISP add_sighting failed: %s", exc)
            return False


# Verify protocol compliance at import time
if not isinstance(MISPEnricher(), SecondaryEnricherProtocol):
    raise TypeError("MISPEnricher does not satisfy SecondaryEnricherProtocol")
