"""Enrichment for file hashes (MD5 / SHA1 / SHA256)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..client import VTClient
from ..config import Config
from ..models import (
    InvestigateResult,
    PEInfo,
    SandboxBehavior,
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


def _parse_pe_info(attrs: dict[str, Any]) -> PEInfo | None:
    pe = attrs.get("pe_info")
    if not pe:
        return None
    ts_raw = pe.get("timestamp")
    compilation_ts = None
    if ts_raw:
        try:
            compilation_ts = datetime.fromtimestamp(ts_raw, tz=timezone.utc)
        except (ValueError, OSError):
            pass

    sections = [
        {
            "name": s.get("name"),
            "entropy": s.get("entropy"),
            "raw_size": s.get("raw_size"),
            "virtual_size": s.get("virtual_size"),
        }
        for s in pe.get("sections", [])
    ]

    imports: list[str] = []
    for lib in pe.get("import_list", []):
        lib_name = lib.get("library_name", "")
        for fn in lib.get("imported_functions", [])[:5]:  # cap per lib
            imports.append(f"{lib_name}::{fn}")

    return PEInfo(
        compilation_timestamp=compilation_ts,
        entry_point=pe.get("entry_point"),
        target_machine=pe.get("machine_type"),
        sections=sections,
        imports=imports,
        exports=pe.get("exports_list", [])[:20],
    )


def _parse_sandbox(raw_list: list[dict[str, Any]]) -> list[SandboxBehavior]:
    behaviors = []
    for item in raw_list:
        attrs = item.get("attributes", {})
        behaviors.append(SandboxBehavior(
            sandbox_name=attrs.get("sandbox_name"),
            processes_created=[p.get("process_name", "") for p in attrs.get("processes_created", [])],
            files_written=[f.get("path", "") for f in attrs.get("files_written", [])[:20]],
            files_deleted=[f.get("path", "") for f in attrs.get("files_deleted", [])[:10]],
            registry_keys_set=[r.get("key", "") for r in attrs.get("registry_keys_set", [])[:20]],
            network_connections=[
                f"{c.get('destination_ip')}:{c.get('destination_port')}"
                for c in attrs.get("network_connections", [])[:20]
                if c.get("destination_ip")
            ],
            dns_lookups=[d.get("hostname", "") for d in attrs.get("dns_lookups", [])[:20]],
            mutexes=attrs.get("mutexes_created", [])[:10],
            verdict=attrs.get("verdict"),
        ))
    return behaviors


def _extract_threat_categories(classification: dict[str, Any] | None) -> list[str]:
    """Extract categories from VT popular_threat_classification."""
    if not classification:
        return []
    cats = []
    for entry in classification.get("popular_threat_category", []):
        if isinstance(entry, dict) and entry.get("value"):
            cats.append(entry["value"])
    label = classification.get("suggested_threat_label")
    if label and label not in cats:
        cats.append(label)
    return cats


def _fetch_file(ioc: str, client: VTClient) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Fetch file data once, return (raw, attrs, results)."""
    raw = client.get_file(ioc)
    if not raw:
        return raw, {}, {}
    attrs = raw.get("data", {}).get("attributes", {})
    results = attrs.get("last_analysis_results", {})
    return raw, attrs, results


def triage(ioc: str, ioc_type: str, client: VTClient, config: Config, from_cache: bool = False, _prefetched: tuple | None = None) -> TriageResult:
    if _prefetched:
        raw, attrs, results = _prefetched
    else:
        raw, attrs, results = _fetch_file(ioc, client)

    if not raw:
        return TriageResult(
            ioc=ioc, ioc_type=ioc_type, verdict=Verdict.UNKNOWN,
            detection_stats=parse_stats({}),
            error="Not found in VirusTotal",
            from_cache=from_cache,
        )

    stats = parse_stats(attrs.get("last_analysis_stats", {}))

    return TriageResult(
        ioc=ioc,
        ioc_type=ioc_type,
        verdict=compute_verdict(stats, config),
        detection_stats=stats,
        malware_families=extract_malware_families(results),
        categories=_extract_threat_categories(attrs.get("popular_threat_classification")),
        tags=attrs.get("tags", []),
        first_seen=_ts(attrs.get("first_submission_date")),
        last_seen=_ts(attrs.get("last_submission_date")),
        last_analysis_date=_ts(attrs.get("last_analysis_date")),
        flagging_engines=extract_flagging_engines(results),
        reputation=attrs.get("reputation"),
        from_cache=from_cache,
    )


def investigate(ioc: str, ioc_type: str, client: VTClient, config: Config, from_cache: bool = False) -> InvestigateResult:
    raw, attrs, results = _fetch_file(ioc, client)
    triage_result = triage(ioc, ioc_type, client, config, from_cache, _prefetched=(raw, attrs, results))
    if triage_result.error:
        return InvestigateResult(triage=triage_result)

    # Relationship calls
    sandbox_raw = client.get_file_behaviors(ioc, limit=3).get("data", []) if config.is_premium else []
    contacted_ips_raw = client.get_file_contacted_ips(ioc).get("data", [])
    contacted_domains_raw = client.get_file_contacted_domains(ioc).get("data", [])
    dropped_raw = client.get_file_dropped_files(ioc).get("data", [])

    return InvestigateResult(
        triage=triage_result,
        file_type=attrs.get("type_description") or attrs.get("type_tag"),
        file_size=attrs.get("size"),
        file_names=attrs.get("names", [])[:10],
        magic=attrs.get("magic"),
        ssdeep=attrs.get("ssdeep"),
        tlsh=attrs.get("tlsh"),
        pe_info=_parse_pe_info(attrs),
        sandbox_behaviors=_parse_sandbox(sandbox_raw),
        contacted_ips=[item.get("id", "") for item in contacted_ips_raw],
        contacted_domains=[item.get("id", "") for item in contacted_domains_raw],
        dropped_files=parse_related_files(dropped_raw),
        yara_hits=[r.get("rule_name", "") for r in attrs.get("crowdsourced_yara_results", [])[:10]],
        signature_info=attrs.get("signature_info"),
    )
