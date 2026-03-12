"""Enrichment for IPv4 / IPv6 addresses."""

from __future__ import annotations

from typing import Any

from ..client import VTClient
from ..config import Config
from ..models import (
    InvestigateResult,
    PassiveDNSRecord,
    TriageResult,
    Verdict,
)
from .base import (
    _ts,
    compute_verdict,
    extract_flagging_engines,
    extract_malware_families,
    parse_related_files,
    parse_stats,
)


def _fetch_ip(ioc: str, client: VTClient) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Fetch IP data once, return (raw, attrs, results)."""
    raw = client.get_ip(ioc)
    if not raw:
        return raw, {}, {}
    attrs = raw.get("data", {}).get("attributes", {})
    results = attrs.get("last_analysis_results", {})
    return raw, attrs, results


def triage(ioc: str, ioc_type: str, client: VTClient, config: Config, from_cache: bool = False, _prefetched: tuple | None = None) -> TriageResult:
    if _prefetched:
        raw, attrs, results = _prefetched
    else:
        raw, attrs, results = _fetch_ip(ioc, client)

    if not raw:
        return TriageResult(
            ioc=ioc, ioc_type=ioc_type, verdict=Verdict.UNKNOWN,
            detection_stats=parse_stats({}),
            error="Not found in VirusTotal",
            from_cache=from_cache,
        )

    stats = parse_stats(attrs.get("last_analysis_stats", {}))

    categories = []
    for source, cats in attrs.get("categories", {}).items():
        categories.extend(cats if isinstance(cats, list) else [cats])

    return TriageResult(
        ioc=ioc,
        ioc_type=ioc_type,
        verdict=compute_verdict(stats, config),
        detection_stats=stats,
        malware_families=extract_malware_families(results),
        categories=list(set(categories)),
        tags=attrs.get("tags", []),
        last_analysis_date=_ts(attrs.get("last_analysis_date")),
        flagging_engines=extract_flagging_engines(results),
        reputation=attrs.get("reputation"),
        from_cache=from_cache,
    )


def investigate(ioc: str, ioc_type: str, client: VTClient, config: Config, from_cache: bool = False) -> InvestigateResult:
    raw, attrs, results = _fetch_ip(ioc, client)
    triage_result = triage(ioc, ioc_type, client, config, from_cache, _prefetched=(raw, attrs, results))
    if triage_result.error:
        return InvestigateResult(triage=triage_result)

    # Relationship calls
    resolutions_raw = client.get_ip_resolutions(ioc, limit=20).get("data", [])
    comm_files_raw = client.get_ip_communicating_files(ioc).get("data", [])
    dl_files_raw = client.get_ip_downloaded_files(ioc).get("data", [])

    passive_dns = []
    for item in resolutions_raw:
        item_attrs = item.get("attributes", {})
        passive_dns.append(PassiveDNSRecord(
            hostname=item_attrs.get("host_name"),
            ip_address=ioc,
            resolver=item_attrs.get("resolver"),
            last_resolved=_ts(item_attrs.get("date")),
        ))

    return InvestigateResult(
        triage=triage_result,
        asn=attrs.get("asn"),
        asn_owner=attrs.get("as_owner"),
        country=attrs.get("country"),
        continent=attrs.get("continent"),
        network=attrs.get("network"),
        passive_dns=passive_dns,
        communicating_files=parse_related_files(comm_files_raw),
        downloaded_files=parse_related_files(dl_files_raw),
    )
