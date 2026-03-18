"""Deterministic template-based explanation (no LLM required).

This is the fallback when no AI provider is configured. It produces
a structured text explanation from signals and verdict data alone.
"""

from __future__ import annotations

from typing import Union

from ..models import InvestigateResult, TriageResult, Verdict


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
