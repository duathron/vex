"""Prompt builder for AI-powered IOC explanations.

Input is sanitized at two levels:
  1. IOC strings are defanged (hxxp, [.] notation) to prevent accidental
     execution if the prompt is logged or shared.
  2. Attacker-influenced free-text fields (malware families, tags, categories,
     sandbox process/mutex/DNS names, file names, YARA hits, etc.) are run
     through PromptInjectionDetector.sanitize() before insertion.  Values
     that contain CRITICAL injection patterns are replaced with a redaction
     marker; WARNING-level findings are logged but the value is passed through.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Union

from ..defang import defang
from ..models import InvestigateResult, TriageResult
from .injection_detector import PromptInjectionDetector

if TYPE_CHECKING:
    from ..correlate import Cluster


def build_explain_prompt(result: Union[TriageResult, InvestigateResult]) -> str:
    """Build a structured prompt from enrichment results.

    Attacker-controlled free-text fields are injection-scanned before insertion.
    IOC/hash fields use is_ioc_field=True to skip the encoded-payload check
    (hashes legitimately look like base64/hex).
    """
    triage = result.triage if isinstance(result, InvestigateResult) else result
    detector = PromptInjectionDetector()

    def _safe(value: str, field: str, *, is_ioc: bool = False) -> str:
        """Sanitize a single field value before prompt insertion."""
        return detector.sanitize(value, field_name=field, is_ioc_field=is_ioc)

    def _safe_list(values: list[str], field: str, *, is_ioc: bool = False) -> list[str]:
        """Sanitize each element of a list field."""
        return [_safe(v, field, is_ioc=is_ioc) for v in values]

    sections: list[str] = [
        # IOC itself: already defanged; scan as IOC field (skip encoded_payload).
        f"IOC: {defang(_safe(triage.ioc, 'ioc', is_ioc=True))} (type: {triage.ioc_type})",
        f"Verdict: {triage.verdict.value}",
        f"Detections: {triage.detection_stats.malicious} malicious / "
        f"{triage.detection_stats.suspicious} suspicious / "
        f"{triage.detection_stats.total} total engines",
    ]

    # Attacker-controlled free-text — scan fully (no is_ioc exemption).
    if triage.malware_families:
        safe_families = _safe_list(triage.malware_families[:10], "malware_families")
        sections.append(f"Malware families: {', '.join(safe_families)}")
    if triage.categories:
        safe_cats = _safe_list(triage.categories[:8], "categories")
        sections.append(f"Categories: {', '.join(safe_cats)}")
    if triage.tags:
        safe_tags = _safe_list(triage.tags[:10], "tags")
        sections.append(f"Tags: {', '.join(safe_tags)}")
    if triage.reputation is not None:
        sections.append(f"Community reputation score: {triage.reputation}")
    if triage.first_seen:
        sections.append(f"First seen: {triage.first_seen.strftime('%Y-%m-%d')}")
    if triage.last_seen:
        sections.append(f"Last seen: {triage.last_seen.strftime('%Y-%m-%d')}")

    # Investigation-specific data
    if isinstance(result, InvestigateResult):
        if result.attack_mappings:
            mappings = [
                f"{m.technique_id} {m.technique_name} ({m.tactic})"
                for m in result.attack_mappings[:10]
            ]
            sections.append(f"MITRE ATT&CK: {'; '.join(mappings)}")

        if result.sandbox_behaviors:
            sb = result.sandbox_behaviors[0]
            if sb.processes_created:
                safe_procs = _safe_list(sb.processes_created[:5], "processes_created")
                sections.append(
                    f"Processes created: {', '.join(safe_procs)}"
                )
            if sb.dns_lookups:
                # DNS names can be attacker-controlled; scan as free text.
                safe_dns = _safe_list(sb.dns_lookups[:5], "dns_lookups")
                sections.append(
                    f"DNS lookups: {', '.join(safe_dns)}"
                )
            if sb.network_connections:
                safe_net = _safe_list(sb.network_connections[:5], "network_connections")
                sections.append(
                    f"Network connections: {', '.join(safe_net)}"
                )
            if sb.registry_keys_set:
                safe_reg = _safe_list(sb.registry_keys_set[:5], "registry_keys_set")
                sections.append(
                    f"Registry keys: {', '.join(safe_reg)}"
                )

        if result.contacted_ips:
            # IPs are IOC-like; skip encoded_payload check.
            safe_ips = _safe_list(result.contacted_ips[:5], "contacted_ips", is_ioc=True)
            sections.append(f"Contacted IPs: {', '.join(safe_ips)}")
        if result.contacted_domains:
            safe_domains = _safe_list(
                result.contacted_domains[:5], "contacted_domains", is_ioc=True
            )
            sections.append(f"Contacted domains: {', '.join(safe_domains)}")
        if result.asn:
            sections.append(
                f"ASN: AS{result.asn} {result.asn_owner or ''}"
            )
        if result.country:
            sections.append(f"Country: {result.country}")
        if result.whois and result.whois.registrar:
            safe_registrar = _safe(result.whois.registrar, "whois.registrar")
            sections.append(f"WHOIS registrar: {safe_registrar}")
        if result.yara_hits:
            safe_yara = _safe_list(result.yara_hits[:5], "yara_hits")
            sections.append(f"YARA hits: {', '.join(safe_yara)}")

        if result.file_names:
            safe_fnames = _safe_list(result.file_names[:5], "file_names")
            sections.append(f"File names: {', '.join(safe_fnames)}")

    data_block = "\n".join(sections)

    return (
        "You are a senior SOC analyst. Based on the following VirusTotal "
        "enrichment data, provide:\n"
        "1. A concise threat assessment (2-3 sentences)\n"
        "2. Key findings that matter for incident response\n"
        "3. Recommended next steps for the analyst\n"
        "\n"
        f"Data:\n{data_block}\n"
        "\n"
        "Be specific and actionable. Reference technique IDs where applicable. "
        "Do not repeat the raw data verbatim."
    )


def build_correlation_prompt(cluster: "Cluster") -> str:
    """Build a structured prompt for AI cluster correlation analysis.

    IOC strings are defanged so they cannot be accidentally clicked or
    executed if the prompt is logged or shared.  Cluster member labels and
    the shared attribute value are injection-scanned before insertion.
    """
    detector = PromptInjectionDetector()
    # Member IOCs: scan as IOC fields (skip encoded_payload check for hashes/IPs).
    defanged_members = [
        defang(detector.sanitize(m, field_name="cluster_member", is_ioc_field=True))
        for m in cluster.members
    ]
    members_str = ", ".join(defanged_members)

    # shared_attribute can be an attacker-influenced label — scan as free text.
    safe_shared_attr = detector.sanitize(
        cluster.shared_attribute, field_name="shared_attribute"
    )

    sections: list[str] = [
        f"Cluster ID: {cluster.cluster_id}",
        f"Shared attribute type: {cluster.attribute_type}",
        f"Shared attribute value: {safe_shared_attr}",
        f"Member IOC count: {cluster.member_count}",
        f"Member IOCs (defanged): {members_str}",
        f"Highest verdict in cluster: {cluster.max_verdict.value}",
    ]

    data_block = "\n".join(sections)

    return (
        "You are a senior SOC analyst performing batch IOC correlation analysis. "
        "Based on the following cluster data from VirusTotal enrichment, provide:\n"
        "1. A 2-3 sentence campaign-correlation assessment (shared infrastructure, "
        "likely common origin or threat actor)\n"
        "2. One concrete next investigative step for the analyst\n"
        "\n"
        f"Cluster data:\n{data_block}\n"
        "\n"
        "Be concise and actionable. Do not repeat the raw data verbatim. "
        "Focus on what the shared attribute implies about the threat campaign."
    )
