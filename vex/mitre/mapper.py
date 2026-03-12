"""Map VT enrichment results to MITRE ATT&CK techniques."""

from __future__ import annotations

from ..models import ATTACKMapping, InvestigateResult, SandboxBehavior, TriageResult
from .mapping import BEHAVIOR_MAP, TAG_MAP


def _scan_strings(strings: list[str], source_map: dict) -> list[ATTACKMapping]:
    """Scan a list of strings against a mapping dict (case-insensitive)."""
    hits: dict[str, ATTACKMapping] = {}
    for text in strings:
        text_lower = text.lower()
        for keyword, (tid, name, tactic) in source_map.items():
            if keyword in text_lower and tid not in hits:
                hits[tid] = ATTACKMapping(
                    technique_id=tid,
                    technique_name=name,
                    tactic=tactic,
                    evidence=text[:120],
                )
    return list(hits.values())


def _map_sandbox(behaviors: list[SandboxBehavior]) -> list[ATTACKMapping]:
    """Extract ATT&CK mappings from sandbox behavior data."""
    all_strings: list[str] = []
    for sb in behaviors:
        all_strings.extend(sb.processes_created)
        all_strings.extend(sb.files_written)
        all_strings.extend(sb.files_deleted)
        all_strings.extend(sb.registry_keys_set)
        all_strings.extend(sb.network_connections)
        all_strings.extend(sb.dns_lookups)
        all_strings.extend(sb.mutexes)
    return _scan_strings(all_strings, BEHAVIOR_MAP)


def _map_tags(tags: list[str]) -> list[ATTACKMapping]:
    """Map VT tags to ATT&CK techniques."""
    return _scan_strings(tags, TAG_MAP)


def map_to_attack(result: InvestigateResult) -> list[ATTACKMapping]:
    """Derive MITRE ATT&CK technique mappings from an investigate result.

    Combines evidence from:
    - VT tags and malware family names
    - Sandbox behaviors (processes, registry, network, files)
    - Contacted IPs/domains (network activity indicators)
    """
    seen: dict[str, ATTACKMapping] = {}

    # 1. Tags
    for m in _map_tags(result.triage.tags + result.triage.malware_families):
        if m.technique_id not in seen:
            seen[m.technique_id] = m

    # 2. Sandbox behaviors
    for m in _map_sandbox(result.sandbox_behaviors):
        if m.technique_id not in seen:
            seen[m.technique_id] = m

    # 3. Contacted domains/IPs → network activity
    net_strings = result.contacted_ips + result.contacted_domains
    for m in _scan_strings(net_strings, BEHAVIOR_MAP):
        if m.technique_id not in seen:
            seen[m.technique_id] = m

    # 4. YARA hits as evidence
    for m in _scan_strings(result.yara_hits, BEHAVIOR_MAP):
        if m.technique_id not in seen:
            seen[m.technique_id] = m
    for m in _scan_strings(result.yara_hits, TAG_MAP):
        if m.technique_id not in seen:
            seen[m.technique_id] = m

    return sorted(seen.values(), key=lambda m: m.technique_id)
