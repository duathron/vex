"""Deterministic template-based explanation (no LLM required).

This is the fallback when no AI provider is configured. It produces
a structured text explanation from signals and verdict data alone.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Union

from ..models import InvestigateResult, TriageResult, Verdict

if TYPE_CHECKING:
    from ..correlate import Cluster


def template_explain(result: Union[TriageResult, InvestigateResult]) -> str:
    """Generate a template-based explanation from enrichment results."""
    triage = result.triage if isinstance(result, InvestigateResult) else result
    lines: list[str] = []

    # --- Threat assessment ---
    if triage.verdict == Verdict.MALICIOUS:
        lines.append(
            f"THREAT ASSESSMENT: {triage.ioc} is classified as MALICIOUS "
            f"with {triage.detection_stats.malicious}/{triage.detection_stats.total} "
            f"engine detections."
        )
    elif triage.verdict == Verdict.SUSPICIOUS:
        lines.append(
            f"THREAT ASSESSMENT: {triage.ioc} shows suspicious indicators "
            f"with {triage.detection_stats.malicious} malicious detection(s) "
            f"out of {triage.detection_stats.total} engines."
        )
    elif triage.verdict == Verdict.CLEAN:
        lines.append(
            f"THREAT ASSESSMENT: {triage.ioc} appears clean with 0 malicious "
            f"detections across {triage.detection_stats.total} engines."
        )
    else:
        lines.append(
            f"THREAT ASSESSMENT: {triage.ioc} has insufficient data for a "
            f"definitive verdict ({triage.detection_stats.total} engines scanned)."
        )

    # --- Key findings ---
    if triage.malware_families:
        families = ", ".join(triage.malware_families[:5])
        lines.append(f"KEY FINDING: Associated malware families: {families}.")

    if isinstance(result, InvestigateResult):
        if result.attack_mappings:
            tactics = sorted(set(m.tactic for m in result.attack_mappings))
            techniques = [
                f"{m.technique_id} ({m.technique_name})"
                for m in result.attack_mappings[:5]
            ]
            lines.append(
                f"KEY FINDING: MITRE ATT&CK coverage across "
                f"{len(tactics)} tactic(s): {', '.join(tactics)}. "
                f"Techniques: {', '.join(techniques)}."
            )

        if result.sandbox_behaviors:
            sb = result.sandbox_behaviors[0]
            if sb.processes_created:
                lines.append(
                    f"KEY FINDING: Sandbox observed process creation: "
                    f"{', '.join(sb.processes_created[:3])}."
                )
            if sb.dns_lookups:
                lines.append(
                    f"KEY FINDING: DNS lookups to: "
                    f"{', '.join(sb.dns_lookups[:3])}."
                )

        if result.contacted_ips:
            lines.append(
                f"KEY FINDING: Contacts {len(result.contacted_ips)} external "
                f"IP(s): {', '.join(result.contacted_ips[:3])}."
            )

    if triage.first_seen and triage.last_seen:
        lines.append(
            f"KEY FINDING: Active from {triage.first_seen.strftime('%Y-%m-%d')} "
            f"to {triage.last_seen.strftime('%Y-%m-%d')}."
        )

    # --- Next steps ---
    if triage.verdict == Verdict.MALICIOUS:
        lines.append(
            "NEXT STEPS: Block the IOC immediately in perimeter defenses "
            "(firewall, proxy, DNS sinkhole). Search SIEM for historical "
            "connections. Investigate related IOCs and check for lateral movement."
        )
    elif triage.verdict == Verdict.SUSPICIOUS:
        lines.append(
            "NEXT STEPS: Escalate for manual review. Check SIEM for "
            "historical connections. Consider blocking proactively while "
            "awaiting further analysis."
        )
    elif triage.verdict == Verdict.UNKNOWN:
        lines.append(
            "NEXT STEPS: Monitor the IOC. Re-check in 24-48 hours as more "
            "engines may have analyzed it. Search for related intelligence."
        )
    else:
        lines.append(
            "NEXT STEPS: No immediate action required. Continue monitoring."
        )

    return "\n".join(lines)


def template_correlation(cluster: "Cluster") -> str:
    """Generate a deterministic template narrative for a correlation cluster.

    Used as fallback when no AI provider is configured or when a provider
    call fails. No LLM required.
    """
    n = cluster.member_count
    attr = cluster.shared_attribute
    attr_type = cluster.attribute_type
    verdict = cluster.max_verdict.value

    # First sentence: state the observation
    line1 = (
        f"{n} IOC{'s' if n != 1 else ''} share {attr_type} attribute '{attr}' "
        f"with a highest verdict of {verdict}."
    )

    # Second sentence: interpretation based on attribute type
    _attr_interpretation: dict[str, str] = {
        "asn": "Shared ASN infrastructure suggests these IOCs may belong to the same hosting provider or threat actor.",
        "family": "Association with the same malware family indicates a coordinated campaign or shared tooling.",
        "ip": "Shared contacted IP indicates possible common C2 infrastructure.",
        "domain": "Shared contacted domain suggests common command-and-control or distribution infrastructure.",
        "network": "Shared network CIDR block points to a common hosting environment or actor-controlled IP range.",
    }
    line2 = _attr_interpretation.get(
        attr_type,
        "Shared infrastructure suggests a possible common origin or threat campaign.",
    )

    # Third sentence: recommended next step
    _attr_nextstep: dict[str, str] = {
        "asn": "Investigate other IOCs hosted on the same ASN and check for historical abuse reports.",
        "family": f"Cross-reference all {n} IOCs against threat intelligence feeds for this malware family.",
        "ip": "Block the shared IP at the perimeter and pivot on it in SIEM for historical connections.",
        "domain": "Block the shared domain and search SIEM logs for any historical resolution or connections.",
        "network": f"Review the full {attr} CIDR block for additional malicious hosts and apply network-level blocks.",
    }
    line3 = _attr_nextstep.get(
        attr_type,
        f"Investigate all {n} associated IOCs together and search for additional shared indicators.",
    )

    return f"{line1} {line2} {line3}"
