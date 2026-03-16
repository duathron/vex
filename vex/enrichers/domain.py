"""Enrichment for domains."""

from __future__ import annotations

from typing import Any

from ..client import VTClient
from ..config import Config
from ..models import (
    InvestigateResult,
    PassiveDNSRecord,
    TriageResult,
    Verdict,
    WHOISInfo,
)
from .base import (
    _ts,
    compute_verdict,
    extract_flagging_engines,
    extract_malware_families,
    parse_related_files,
    parse_stats,
)


def _fetch_domain(ioc: str, client: VTClient) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Fetch domain data once, return (raw, attrs, results)."""
    raw = client.get_domain(ioc)
    if not raw:
        return raw, {}, {}
    attrs = raw.get("data", {}).get("attributes", {})
    results = attrs.get("last_analysis_results", {})
    return raw, attrs, results


def triage(ioc: str, ioc_type: str, client: VTClient, config: Config, from_cache: bool = False, _prefetched: tuple | None = None) -> TriageResult:
    if _prefetched:
        raw, attrs, results = _prefetched
    else:
        raw, attrs, results = _fetch_domain(ioc, client)

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
        first_seen=_ts(attrs.get("creation_date")),
        flagging_engines=extract_flagging_engines(results),
        reputation=attrs.get("reputation"),
        from_cache=from_cache,
    )


def investigate(ioc: str, ioc_type: str, client: VTClient, config: Config, from_cache: bool = False) -> InvestigateResult:
    raw, attrs, results = _fetch_domain(ioc, client)
    triage_result = triage(ioc, ioc_type, client, config, from_cache, _prefetched=(raw, attrs, results))
    if triage_result.error:
        return InvestigateResult(triage=triage_result)

    # Relationship calls
    resolutions_raw = client.get_domain_resolutions(ioc, limit=20).get("data", [])
    comm_files_raw = client.get_domain_communicating_files(ioc).get("data", []) if config.is_premium else []
    whois_raw = client.get_domain_whois(ioc).get("data", []) if config.is_premium else []

    # Passive DNS (domain resolved to which IPs)
    passive_dns = []
    for item in resolutions_raw:
        item_attrs = item.get("attributes", {})
        passive_dns.append(PassiveDNSRecord(
            hostname=ioc,
            ip_address=item_attrs.get("ip_address"),
            resolver=item_attrs.get("resolver"),
            last_resolved=_ts(item_attrs.get("date")),
        ))

    # WHOIS (take most recent entry)
    whois = None
    if whois_raw:
        latest = whois_raw[0].get("attributes", {}) if isinstance(whois_raw, list) else {}
        whois = WHOISInfo(
            registrar=latest.get("registrar"),
            creation_date=str(latest.get("creation_date", "")),
            expiration_date=str(latest.get("expiration_date", "")),
            updated_date=str(latest.get("updated_date", "")),
            name_servers=latest.get("name_servers", []),
            registrant_org=latest.get("registrant_organization"),
            registrant_country=latest.get("registrant_country"),
        )

    # DNS records from attributes (VT returns list of dicts with "type", "value", "ttl")
    dns_records = []
    raw_dns = attrs.get("last_dns_records", [])
    if isinstance(raw_dns, list):
        for rec in raw_dns:
            if isinstance(rec, dict):
                dns_records.append({
                    "type": rec.get("type", ""),
                    "value": rec.get("value", ""),
                    "ttl": rec.get("ttl"),
                })

    # Subdomains from attributes
    subdomains = attrs.get("subdomains", [])[:20]

    return InvestigateResult(
        triage=triage_result,
        passive_dns=passive_dns,
        communicating_files=parse_related_files(comm_files_raw),
        whois=whois,
        dns_records=dns_records,
        subdomains=subdomains,
    )
