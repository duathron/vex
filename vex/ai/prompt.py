"""Prompt builder for AI-powered IOC explanations.

Input is sanitized: IOC strings are defanged, no raw user input
appears in the system section of the prompt.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Union

from ..defang import defang
from ..models import InvestigateResult, TriageResult

if TYPE_CHECKING:
    from ..correlate import Cluster


def build_explain_prompt(result: Union[TriageResult, InvestigateResult]) -> str:
    """Build a structured prompt from enrichment results."""
    triage = result.triage if isinstance(result, InvestigateResult) else result

    sections: list[str] = [
        f"IOC: {defang(triage.ioc)} (type: {triage.ioc_type})",
        f"Verdict: {triage.verdict.value}",
        f"Detections: {triage.detection_stats.malicious} malicious / "
        f"{triage.detection_stats.suspicious} suspicious / "
        f"{triage.detection_stats.total} total engines",
    ]

    if triage.malware_families:
        sections.append(
            f"Malware families: {', '.join(triage.malware_families[:10])}"
        )
    if triage.categories:
        sections.append(f"Categories: {', '.join(triage.categories[:8])}")
    if triage.tags:
        sections.append(f"Tags: {', '.join(triage.tags[:10])}")
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
                sections.append(
                    f"Processes created: {', '.join(sb.processes_created[:5])}"
                )
            if sb.dns_lookups:
                sections.append(
                    f"DNS lookups: {', '.join(sb.dns_lookups[:5])}"
                )
            if sb.network_connections:
                sections.append(
                    f"Network connections: {', '.join(sb.network_connections[:5])}"
                )
            if sb.registry_keys_set:
                sections.append(
                    f"Registry keys: {', '.join(sb.registry_keys_set[:5])}"
                )

        if result.contacted_ips:
            sections.append(
                f"Contacted IPs: {', '.join(result.contacted_ips[:5])}"
            )
        if result.contacted_domains:
            sections.append(
                f"Contacted domains: {', '.join(result.contacted_domains[:5])}"
            )
        if result.asn:
            sections.append(
                f"ASN: AS{result.asn} {result.asn_owner or ''}"
            )
        if result.country:
            sections.append(f"Country: {result.country}")
        if result.whois and result.whois.registrar:
            sections.append(f"WHOIS registrar: {result.whois.registrar}")
        if result.yara_hits:
            sections.append(f"YARA hits: {', '.join(result.yara_hits[:5])}")

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
    executed if the prompt is logged or shared.
    """
    defanged_members = [defang(m) for m in cluster.members]
    members_str = ", ".join(defanged_members)

    sections: list[str] = [
        f"Cluster ID: {cluster.cluster_id}",
        f"Shared attribute type: {cluster.attribute_type}",
        f"Shared attribute value: {cluster.shared_attribute}",
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
