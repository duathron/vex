"""Deterministic batch IOC correlation — pure logic, no I/O, no network.

v1.3.0 P0 feature: build_clusters groups IOCs by shared infrastructure
attributes (ASN, malware family, contacted IPs/domains, passive DNS, CIDR).
"""

from __future__ import annotations

from collections import defaultdict
from typing import Union

from pydantic import BaseModel

from .models import InvestigateResult, TriageResult, Verdict

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

class Cluster(BaseModel):
    cluster_id: str
    attribute_type: str  # "asn" | "family" | "ip" | "domain" | "network"
    shared_attribute: str  # human-readable label
    members: list[str]  # IOC strings, sorted alphabetically
    member_count: int
    max_verdict: Verdict


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _ioc_and_verdict(result: Union[TriageResult, InvestigateResult]) -> tuple[str, Verdict]:
    """Return (ioc_string, verdict) for either result type."""
    if isinstance(result, InvestigateResult):
        return result.triage.ioc, result.triage.verdict
    return result.ioc, result.verdict


def _extract_attributes(
    result: Union[TriageResult, InvestigateResult],
) -> list[tuple[tuple[str, str], str]]:
    """Return list of ((attr_type, attr_key), human_label) tuples for a result."""
    attrs: list[tuple[tuple[str, str], str]] = []

    # --- Family (available on both TriageResult and InvestigateResult.triage) ---
    triage: TriageResult
    if isinstance(result, InvestigateResult):
        triage = result.triage
    else:
        triage = result

    for fam in triage.malware_families:
        key = fam.lower()
        attrs.append((("family", key), f"family:{key}"))

    # --- InvestigateResult-only attributes ---
    if isinstance(result, InvestigateResult):
        inv: InvestigateResult = result

        # ASN
        if inv.asn is not None:
            asn_str = str(inv.asn)
            label = f"ASN {inv.asn}"
            if inv.asn_owner:
                label = f"ASN {inv.asn} ({inv.asn_owner})"
            attrs.append((("asn", asn_str), label))

        # Network CIDR
        if inv.network:
            attrs.append((("network", inv.network), f"network:{inv.network}"))

        # Contacted IPs
        for ip in inv.contacted_ips:
            if ip:
                attrs.append((("ip", ip), f"ip:{ip}"))

        # Contacted domains
        for domain in inv.contacted_domains:
            if domain:
                attrs.append((("domain", domain.lower()), f"domain:{domain.lower()}"))

        # Passive DNS
        for rec in inv.passive_dns:
            if rec.ip_address:
                attrs.append((("ip", rec.ip_address), f"ip:{rec.ip_address}"))
            if rec.hostname:
                attrs.append((("domain", rec.hostname.lower()), f"domain:{rec.hostname.lower()}"))

        # If the IOC itself is an IP, include it as an "ip" attribute so it
        # can be clustered with other IOCs that contacted it or share it via pdns.
        if triage.ioc_type in ("ipv4", "ipv6", "ip"):
            attrs.append((("ip", triage.ioc), f"ip:{triage.ioc}"))

    return attrs


def _max_verdict(verdicts: list[Verdict]) -> Verdict:
    """Return the highest-severity Verdict in the list."""
    return max(verdicts, key=lambda v: v.severity)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_clusters(
    results: list[Union[TriageResult, InvestigateResult]],
) -> list[Cluster]:
    """Cluster IOCs by shared infrastructure attributes.

    Returns a deterministically ordered list of Cluster objects.
    A cluster is only created when ≥ 2 distinct IOCs share the same attribute.
    cluster_id values are "C1", "C2", ... assigned after sorting.
    """
    if not results:
        return []

    # Build: attr_key -> set of member IOCs, and attr_key -> human label
    attr_members: dict[tuple[str, str], set[str]] = defaultdict(set)
    attr_label: dict[tuple[str, str], str] = {}
    # Track verdict per IOC for max_verdict computation
    ioc_verdict: dict[str, Verdict] = {}

    for result in results:
        ioc, verdict = _ioc_and_verdict(result)
        ioc_verdict[ioc] = verdict

        for (attr_key, label) in _extract_attributes(result):
            attr_members[attr_key].add(ioc)
            # Last-write wins for label; consistent because we iterate deterministically
            # and the label is derived from the attribute key anyway.
            attr_label[attr_key] = label

    # Build raw clusters — only those with ≥ 2 members
    raw_clusters: list[tuple[str, str, str, list[str], Verdict]] = []
    # (attr_type, shared_attribute, human_label, members_sorted, max_verdict)

    for (attr_type, attr_key), members_set in attr_members.items():
        if len(members_set) < 2:
            continue
        members_sorted = sorted(members_set)
        verdicts = [ioc_verdict[m] for m in members_sorted if m in ioc_verdict]
        mv = _max_verdict(verdicts) if verdicts else Verdict.UNKNOWN
        label = attr_label[(attr_type, attr_key)]
        raw_clusters.append((attr_type, attr_key, label, members_sorted, mv))

    # Sort: member_count desc, then attribute_type asc, then shared_attribute asc
    raw_clusters.sort(key=lambda x: (-len(x[3]), x[0], x[2]))

    # Assign stable cluster IDs
    clusters: list[Cluster] = []
    for i, (attr_type, _attr_key, label, members, mv) in enumerate(raw_clusters, start=1):
        clusters.append(
            Cluster(
                cluster_id=f"C{i}",
                attribute_type=attr_type,
                shared_attribute=label,
                members=members,
                member_count=len(members),
                max_verdict=mv,
            )
        )

    return clusters
