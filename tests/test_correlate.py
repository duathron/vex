"""Tests for vex.correlate.build_clusters — deterministic, no network."""

from __future__ import annotations

from vex.correlate import Cluster, build_clusters
from vex.models import (
    DetectionStats,
    InvestigateResult,
    PassiveDNSRecord,
    TriageResult,
    Verdict,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_STATS = DetectionStats(malicious=5, undetected=65)


def _triage(
    ioc: str,
    ioc_type: str = "domain",
    verdict: Verdict = Verdict.MALICIOUS,
    families: list[str] | None = None,
) -> TriageResult:
    return TriageResult(
        ioc=ioc,
        ioc_type=ioc_type,
        verdict=verdict,
        detection_stats=_STATS,
        malware_families=families or [],
    )


def _investigate(
    ioc: str,
    ioc_type: str = "domain",
    verdict: Verdict = Verdict.MALICIOUS,
    families: list[str] | None = None,
    asn: int | None = None,
    asn_owner: str | None = None,
    network: str | None = None,
    contacted_ips: list[str] | None = None,
    contacted_domains: list[str] | None = None,
    passive_dns: list[PassiveDNSRecord] | None = None,
) -> InvestigateResult:
    triage = _triage(ioc, ioc_type, verdict, families)
    return InvestigateResult(
        triage=triage,
        asn=asn,
        asn_owner=asn_owner,
        network=network,
        contacted_ips=contacted_ips or [],
        contacted_domains=contacted_domains or [],
        passive_dns=passive_dns or [],
    )


# ---------------------------------------------------------------------------
# Basic cases
# ---------------------------------------------------------------------------


def test_empty_input_returns_empty_list() -> None:
    assert build_clusters([]) == []


def test_single_result_returns_empty_list() -> None:
    r = _triage("evil.com")
    assert build_clusters([r]) == []


def test_no_shared_attributes_returns_empty_list() -> None:
    """Two IOCs with nothing in common — no clusters."""
    r1 = _triage("evil.com", families=["emotet"])
    r2 = _triage("bad.org", families=["trickbot"])
    assert build_clusters([r1, r2]) == []


# ---------------------------------------------------------------------------
# ASN clustering
# ---------------------------------------------------------------------------


def test_shared_asn_produces_one_cluster() -> None:
    r1 = _investigate("1.1.1.1", ioc_type="ipv4", asn=13335, asn_owner="CLOUDFLARENET")
    r2 = _investigate("1.0.0.1", ioc_type="ipv4", asn=13335, asn_owner="CLOUDFLARENET")
    clusters = build_clusters([r1, r2])
    assert len(clusters) == 1
    c = clusters[0]
    assert c.attribute_type == "asn"
    assert c.member_count == 2
    assert "13335" in c.shared_attribute
    assert "CLOUDFLARENET" in c.shared_attribute
    assert sorted(c.members) == ["1.0.0.1", "1.1.1.1"]


def test_asn_cluster_without_owner_label() -> None:
    r1 = _investigate("2.2.2.2", ioc_type="ipv4", asn=9999)
    r2 = _investigate("2.2.2.3", ioc_type="ipv4", asn=9999)
    clusters = build_clusters([r1, r2])
    asn_clusters = [c for c in clusters if c.attribute_type == "asn"]
    assert len(asn_clusters) == 1
    assert "9999" in asn_clusters[0].shared_attribute


def test_different_asns_no_cluster() -> None:
    r1 = _investigate("1.1.1.1", ioc_type="ipv4", asn=13335)
    r2 = _investigate("8.8.8.8", ioc_type="ipv4", asn=15169)
    clusters = build_clusters([r1, r2])
    asn_clusters = [c for c in clusters if c.attribute_type == "asn"]
    assert len(asn_clusters) == 0


# ---------------------------------------------------------------------------
# Malware family clustering
# ---------------------------------------------------------------------------


def test_shared_family_cluster() -> None:
    r1 = _triage("hash1", ioc_type="sha256", verdict=Verdict.MALICIOUS, families=["Emotet"])
    r2 = _triage("hash2", ioc_type="sha256", verdict=Verdict.SUSPICIOUS, families=["emotet"])
    clusters = build_clusters([r1, r2])
    fam_clusters = [c for c in clusters if c.attribute_type == "family"]
    assert len(fam_clusters) == 1
    c = fam_clusters[0]
    assert "emotet" in c.shared_attribute
    assert c.member_count == 2


def test_family_comparison_is_case_insensitive() -> None:
    """Families are lowercased for key comparison."""
    r1 = _triage("a.com", families=["TrickBot"])
    r2 = _triage("b.com", families=["trickbot"])
    clusters = build_clusters([r1, r2])
    assert len(clusters) == 1
    assert clusters[0].attribute_type == "family"


def test_singleton_family_excluded() -> None:
    r1 = _triage("a.com", families=["emotet"])
    r2 = _triage("b.com", families=["trickbot"])
    clusters = build_clusters([r1, r2])
    assert clusters == []


# ---------------------------------------------------------------------------
# Contacted IP clustering
# ---------------------------------------------------------------------------


def test_shared_contacted_ip_cluster() -> None:
    r1 = _investigate("a.com", contacted_ips=["192.168.1.1", "10.0.0.1"])
    r2 = _investigate("b.com", contacted_ips=["192.168.1.1", "172.16.0.1"])
    clusters = build_clusters([r1, r2])
    ip_clusters = [c for c in clusters if c.attribute_type == "ip"]
    assert len(ip_clusters) == 1
    assert "192.168.1.1" in ip_clusters[0].shared_attribute
    assert ip_clusters[0].member_count == 2


def test_no_shared_contacted_ips_no_cluster() -> None:
    r1 = _investigate("a.com", contacted_ips=["192.168.1.1"])
    r2 = _investigate("b.com", contacted_ips=["10.0.0.1"])
    clusters = build_clusters([r1, r2])
    ip_clusters = [c for c in clusters if c.attribute_type == "ip"]
    assert len(ip_clusters) == 0


# ---------------------------------------------------------------------------
# Contacted domain clustering
# ---------------------------------------------------------------------------


def test_shared_contacted_domain_cluster() -> None:
    r1 = _investigate("hash1", contacted_domains=["c2.evil.com", "update.evil.com"])
    r2 = _investigate("hash2", contacted_domains=["c2.evil.com", "other.com"])
    clusters = build_clusters([r1, r2])
    dom_clusters = [c for c in clusters if c.attribute_type == "domain"]
    assert len(dom_clusters) == 1
    assert "c2.evil.com" in dom_clusters[0].shared_attribute


def test_contacted_domain_case_insensitive() -> None:
    r1 = _investigate("a.com", contacted_domains=["C2.Evil.COM"])
    r2 = _investigate("b.com", contacted_domains=["c2.evil.com"])
    clusters = build_clusters([r1, r2])
    dom_clusters = [c for c in clusters if c.attribute_type == "domain"]
    assert len(dom_clusters) == 1


# ---------------------------------------------------------------------------
# Passive DNS clustering
# ---------------------------------------------------------------------------


def test_shared_passive_dns_ip() -> None:
    pdns1 = [PassiveDNSRecord(ip_address="5.5.5.5", hostname="ns1.evil.com")]
    pdns2 = [PassiveDNSRecord(ip_address="5.5.5.5", hostname="ns2.evil.com")]
    r1 = _investigate("evil.com", passive_dns=pdns1)
    r2 = _investigate("evil.net", passive_dns=pdns2)
    clusters = build_clusters([r1, r2])
    ip_clusters = [c for c in clusters if c.attribute_type == "ip"]
    assert len(ip_clusters) == 1
    assert "5.5.5.5" in ip_clusters[0].shared_attribute


def test_shared_passive_dns_hostname() -> None:
    pdns1 = [PassiveDNSRecord(hostname="ns1.shared.com", ip_address="1.2.3.4")]
    pdns2 = [PassiveDNSRecord(hostname="ns1.shared.com", ip_address="2.3.4.5")]
    r1 = _investigate("a.com", passive_dns=pdns1)
    r2 = _investigate("b.com", passive_dns=pdns2)
    clusters = build_clusters([r1, r2])
    dom_clusters = [c for c in clusters if c.attribute_type == "domain"]
    assert any("ns1.shared.com" in c.shared_attribute for c in dom_clusters)


def test_passive_dns_none_fields_skipped() -> None:
    """PassiveDNSRecord with None ip_address/hostname must not cause a cluster."""
    pdns1 = [PassiveDNSRecord(ip_address=None, hostname=None)]
    pdns2 = [PassiveDNSRecord(ip_address=None, hostname=None)]
    r1 = _investigate("a.com", passive_dns=pdns1)
    r2 = _investigate("b.com", passive_dns=pdns2)
    clusters = build_clusters([r1, r2])
    assert clusters == []


# ---------------------------------------------------------------------------
# Network CIDR clustering
# ---------------------------------------------------------------------------


def test_shared_network_cluster() -> None:
    r1 = _investigate("1.1.1.1", ioc_type="ipv4", network="1.1.1.0/24")
    r2 = _investigate("1.1.1.2", ioc_type="ipv4", network="1.1.1.0/24")
    clusters = build_clusters([r1, r2])
    net_clusters = [c for c in clusters if c.attribute_type == "network"]
    assert len(net_clusters) == 1
    assert "1.1.1.0/24" in net_clusters[0].shared_attribute


# ---------------------------------------------------------------------------
# max_verdict
# ---------------------------------------------------------------------------


def test_max_verdict_picks_highest_severity() -> None:
    r1 = _triage("a.com", verdict=Verdict.CLEAN, families=["emotet"])
    r2 = _triage("b.com", verdict=Verdict.MALICIOUS, families=["emotet"])
    clusters = build_clusters([r1, r2])
    assert len(clusters) == 1
    assert clusters[0].max_verdict == Verdict.MALICIOUS


def test_max_verdict_suspicious_over_unknown() -> None:
    r1 = _triage("a.com", verdict=Verdict.UNKNOWN, families=["loader"])
    r2 = _triage("b.com", verdict=Verdict.SUSPICIOUS, families=["loader"])
    clusters = build_clusters([r1, r2])
    assert clusters[0].max_verdict == Verdict.SUSPICIOUS


# ---------------------------------------------------------------------------
# Deterministic ordering and stable cluster IDs
# ---------------------------------------------------------------------------


def test_cluster_ids_are_stable_across_calls() -> None:
    r1 = _investigate("a.com", asn=100, contacted_ips=["1.1.1.1"])
    r2 = _investigate("b.com", asn=100, contacted_ips=["1.1.1.1"])
    result_a = build_clusters([r1, r2])
    result_b = build_clusters([r1, r2])
    assert [c.cluster_id for c in result_a] == [c.cluster_id for c in result_b]
    assert [c.shared_attribute for c in result_a] == [c.shared_attribute for c in result_b]


def test_members_are_sorted_alphabetically() -> None:
    r1 = _triage("zzz.com", families=["agent"])
    r2 = _triage("aaa.com", families=["agent"])
    clusters = build_clusters([r1, r2])
    assert clusters[0].members == ["aaa.com", "zzz.com"]


def test_sorting_larger_cluster_first() -> None:
    """The cluster with more members should be listed first (C1)."""
    # 3 IOCs share family "agent", 2 share family "loader"
    r1 = _triage("a.com", families=["agent", "loader"])
    r2 = _triage("b.com", families=["agent", "loader"])
    r3 = _triage("c.com", families=["agent"])
    clusters = build_clusters([r1, r2, r3])
    fam_clusters = [c for c in clusters if c.attribute_type == "family"]
    # "agent" has 3 members, "loader" has 2
    assert fam_clusters[0].member_count >= fam_clusters[1].member_count


def test_cluster_ids_sequential() -> None:
    r1 = _investigate("a.com", asn=1, contacted_ips=["1.1.1.1"])
    r2 = _investigate("b.com", asn=1, contacted_ips=["1.1.1.1"])
    clusters = build_clusters([r1, r2])
    for i, c in enumerate(clusters, start=1):
        assert c.cluster_id == f"C{i}"


# ---------------------------------------------------------------------------
# Mixed list of TriageResult + InvestigateResult
# ---------------------------------------------------------------------------


def test_mixed_triage_and_investigate() -> None:
    """TriageResult and InvestigateResult can be in the same list."""
    t = _triage("hash1", families=["qakbot"])
    inv = _investigate("evil.com", families=["qakbot"])
    clusters = build_clusters([t, inv])
    fam_clusters = [c for c in clusters if c.attribute_type == "family"]
    assert len(fam_clusters) == 1
    assert fam_clusters[0].member_count == 2
    assert "hash1" in fam_clusters[0].members
    assert "evil.com" in fam_clusters[0].members


def test_triage_only_exposes_family_attribute() -> None:
    """TriageResult has no ASN/network/IPs — only family clusters are possible."""
    r1 = _triage("a.com", families=["emotet"])
    r2 = _triage("b.com", families=["emotet"])
    clusters = build_clusters([r1, r2])
    for c in clusters:
        assert c.attribute_type == "family"


# ---------------------------------------------------------------------------
# Cluster model fields
# ---------------------------------------------------------------------------


def test_cluster_model_fields() -> None:
    r1 = _triage("a.com", families=["cobalt"])
    r2 = _triage("b.com", families=["cobalt"])
    clusters = build_clusters([r1, r2])
    assert len(clusters) == 1
    c = clusters[0]
    assert isinstance(c, Cluster)
    assert c.cluster_id == "C1"
    assert c.attribute_type == "family"
    assert c.member_count == 2
    assert c.max_verdict in list(Verdict)
    assert len(c.members) == c.member_count
