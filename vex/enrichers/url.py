"""Enrichment for URLs."""

from __future__ import annotations

from typing import Any

from ..client import VTClient
from ..config import Config
from ..models import (
    InvestigateResult,
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


def _fetch_url(ioc: str, client: VTClient) -> dict[str, Any]:
    """Fetch URL data once."""
    return client.get_url(ioc)


def triage(ioc: str, ioc_type: str, client: VTClient, config: Config, from_cache: bool = False, _prefetched: dict | None = None) -> TriageResult:
    raw = _prefetched if _prefetched is not None else _fetch_url(ioc, client)

    if not raw:
        return TriageResult(
            ioc=ioc, ioc_type=ioc_type, verdict=Verdict.UNKNOWN,
            detection_stats=parse_stats({}),
            error="Not found or analysis pending in VirusTotal",
            from_cache=from_cache,
        )

    # Handle both /urls/{id} and /analyses/{id} response shapes
    data = raw.get("data", {})
    if data.get("type") == "analysis":
        attrs = data.get("attributes", {})
        stats = parse_stats(attrs.get("stats", {}))
        results = attrs.get("results", {})
        return TriageResult(
            ioc=ioc,
            ioc_type=ioc_type,
            verdict=compute_verdict(stats, config),
            detection_stats=stats,
            malware_families=extract_malware_families(results),
            flagging_engines=extract_flagging_engines(results),
            from_cache=from_cache,
        )

    attrs = data.get("attributes", {})
    stats = parse_stats(attrs.get("last_analysis_stats", {}))
    results = attrs.get("last_analysis_results", {})

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
    raw = _fetch_url(ioc, client)
    triage_result = triage(ioc, ioc_type, client, config, from_cache, _prefetched=raw)

    if not raw:
        return InvestigateResult(triage=triage_result)

    data = raw.get("data", {})
    attrs = data.get("attributes", {})

    related_files_raw = client.get_url_related_files(ioc).get("data", [])

    return InvestigateResult(
        triage=triage_result,
        final_url=attrs.get("last_final_url"),
        title=attrs.get("title"),
        related_files=parse_related_files(related_files_raw),
    )
