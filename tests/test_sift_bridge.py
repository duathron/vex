"""Tests for sift → vex pipeline bridge — deterministic, no network."""

from __future__ import annotations

import json

import pytest

from vex.pipeline.sift_bridge import extract_iocs_from_sift


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_report(clusters: list) -> str:
    """Wrap clusters in a full TriageReport JSON string."""
    return json.dumps({"clusters": clusters, "summary": {}})


def _make_bare(clusters: list) -> str:
    """Return a bare list-of-clusters JSON string."""
    return json.dumps(clusters)


# ---------------------------------------------------------------------------
# Representative full-report test
# ---------------------------------------------------------------------------

class TestExtractIocsFullReport:
    def test_representative_report_extracts_all_sources(self) -> None:
        """Covers cluster.iocs, alert.iocs, source_ip, and dest_ip — deduped."""
        report = {
            "clusters": [
                {
                    "id": "c1",
                    "label": "Beaconing cluster",
                    "priority": "P1",
                    "iocs": ["evil.com", "1.2.3.4", "deadbeef" * 8],
                    "alerts": [
                        {
                            "id": "a1",
                            "source_ip": "10.0.0.5",
                            "dest_ip": "1.2.3.4",          # dup of cluster ioc
                            "iocs": ["abc123" + "0" * 26, "evil.com"],  # evil.com dup
                        },
                        {
                            "id": "a2",
                            "source_ip": "10.0.0.6",
                            "dest_ip": "5.6.7.8",
                            "iocs": [],
                        },
                    ],
                },
                {
                    "id": "c2",
                    "label": "Lateral movement",
                    "priority": "P2",
                    "iocs": ["malware.example", "10.0.0.5"],  # 10.0.0.5 dup from alert
                    "alerts": [
                        {
                            "id": "a3",
                            "source_ip": "192.168.1.1",
                            "dest_ip": "malware.example",   # dup of cluster ioc
                            "iocs": ["newdomain.test"],
                        },
                    ],
                },
            ],
            "summary": {"total_alerts": 3},
        }
        result = extract_iocs_from_sift(json.dumps(report))

        # Order-preserving dedup: first-seen wins.
        # Within each alert: alert.iocs[] first, then source_ip, then dest_ip.
        expected = [
            "evil.com",             # c1.iocs[0]
            "1.2.3.4",              # c1.iocs[1]
            "deadbeef" * 8,         # c1.iocs[2]
            "abc123" + "0" * 26,    # a1.iocs[0]  (alert.iocs processed first)
            # evil.com already seen — skipped (a1.iocs[1])
            "10.0.0.5",             # a1.source_ip
            # 1.2.3.4 already seen — skipped (a1.dest_ip)
            "10.0.0.6",             # a2.source_ip
            "5.6.7.8",              # a2.dest_ip
            "malware.example",      # c2.iocs[0]
            # 10.0.0.5 already seen — skipped (c2.iocs[1])
            "newdomain.test",       # a3.iocs[0]  (alert.iocs processed first)
            "192.168.1.1",          # a3.source_ip
            # malware.example already seen — skipped (a3.dest_ip)
        ]
        assert result == expected

    def test_no_duplicates_in_output(self) -> None:
        report = {
            "clusters": [
                {
                    "iocs": ["dup.com", "dup.com"],
                    "alerts": [
                        {"source_ip": "dup.com", "dest_ip": "dup.com", "iocs": ["dup.com"]},
                    ],
                }
            ]
        }
        result = extract_iocs_from_sift(json.dumps(report))
        assert result == ["dup.com"]


# ---------------------------------------------------------------------------
# Bare list-of-clusters form
# ---------------------------------------------------------------------------

class TestBareListForm:
    def test_bare_list_accepted(self) -> None:
        clusters = [
            {
                "id": "c1",
                "iocs": ["1.1.1.1"],
                "alerts": [{"source_ip": "2.2.2.2", "dest_ip": "3.3.3.3", "iocs": []}],
            }
        ]
        result = extract_iocs_from_sift(_make_bare(clusters))
        assert result == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]

    def test_bare_empty_list(self) -> None:
        result = extract_iocs_from_sift("[]")
        assert result == []


# ---------------------------------------------------------------------------
# Tolerance for missing / null fields
# ---------------------------------------------------------------------------

class TestMissingAndNullFields:
    def test_cluster_without_iocs_key(self) -> None:
        clusters = [{"id": "c1", "alerts": []}]
        result = extract_iocs_from_sift(_make_bare(clusters))
        assert result == []

    def test_cluster_with_null_iocs(self) -> None:
        clusters = [{"iocs": None, "alerts": []}]
        result = extract_iocs_from_sift(_make_bare(clusters))
        assert result == []

    def test_alert_without_source_dest(self) -> None:
        clusters = [{"iocs": ["good.com"], "alerts": [{"iocs": ["alert-only.net"]}]}]
        result = extract_iocs_from_sift(_make_bare(clusters))
        assert result == ["good.com", "alert-only.net"]

    def test_alert_with_null_source_ip(self) -> None:
        clusters = [{"iocs": [], "alerts": [{"source_ip": None, "dest_ip": "4.4.4.4", "iocs": []}]}]
        result = extract_iocs_from_sift(_make_bare(clusters))
        assert result == ["4.4.4.4"]

    def test_alert_with_empty_string_iocs_skipped(self) -> None:
        clusters = [{"iocs": ["", "real.com", ""], "alerts": []}]
        result = extract_iocs_from_sift(_make_bare(clusters))
        assert result == ["real.com"]

    def test_empty_clusters_list(self) -> None:
        result = extract_iocs_from_sift(_make_report([]))
        assert result == []

    def test_missing_clusters_key(self) -> None:
        # Dict without "clusters" key — should return empty list gracefully
        result = extract_iocs_from_sift(json.dumps({"summary": {}}))
        assert result == []

    def test_alerts_with_empty_ioc_strings(self) -> None:
        clusters = [{"iocs": [], "alerts": [{"source_ip": "", "dest_ip": "", "iocs": []}]}]
        result = extract_iocs_from_sift(_make_bare(clusters))
        assert result == []

    def test_non_dict_cluster_skipped(self) -> None:
        # Mix of valid and invalid cluster entries
        raw = json.dumps({"clusters": ["not-a-dict", {"iocs": ["ok.com"], "alerts": []}]})
        result = extract_iocs_from_sift(raw)
        assert result == ["ok.com"]

    def test_non_dict_alert_skipped(self) -> None:
        clusters = [{"iocs": [], "alerts": ["bad-alert", {"iocs": ["good.com"]}]}]
        result = extract_iocs_from_sift(_make_bare(clusters))
        assert result == ["good.com"]


# ---------------------------------------------------------------------------
# Order-preserving dedup across clusters
# ---------------------------------------------------------------------------

class TestOrderPreservingDedup:
    def test_first_seen_wins_across_clusters(self) -> None:
        clusters = [
            {"iocs": ["a.com", "b.com"], "alerts": []},
            {"iocs": ["b.com", "c.com"], "alerts": []},
            {"iocs": ["a.com", "c.com", "d.com"], "alerts": []},
        ]
        result = extract_iocs_from_sift(_make_bare(clusters))
        assert result == ["a.com", "b.com", "c.com", "d.com"]

    def test_source_ip_order_relative_to_cluster_iocs(self) -> None:
        clusters = [
            {
                "iocs": ["cluster-first.com"],
                "alerts": [
                    {"source_ip": "10.0.0.1", "dest_ip": "cluster-first.com", "iocs": []}
                ],
            }
        ]
        result = extract_iocs_from_sift(_make_bare(clusters))
        # cluster-first.com appears first (from iocs), then source_ip
        assert result == ["cluster-first.com", "10.0.0.1"]

    def test_alert_iocs_before_source_dest(self) -> None:
        """Within a single alert: iocs[] is collected before source_ip/dest_ip."""
        clusters = [
            {
                "iocs": [],
                "alerts": [
                    {
                        "iocs": ["alert-ioc.com"],
                        "source_ip": "9.9.9.9",
                        "dest_ip": "8.8.8.8",
                    }
                ],
            }
        ]
        result = extract_iocs_from_sift(_make_bare(clusters))
        assert result == ["alert-ioc.com", "9.9.9.9", "8.8.8.8"]


# ---------------------------------------------------------------------------
# Invalid JSON → ValueError
# ---------------------------------------------------------------------------

class TestInvalidJson:
    def test_invalid_json_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="Invalid JSON from sift"):
            extract_iocs_from_sift("this is not json")

    def test_truncated_json_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="Invalid JSON from sift"):
            extract_iocs_from_sift('{"clusters": [')

    def test_empty_string_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="Invalid JSON from sift"):
            extract_iocs_from_sift("")


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_single_cluster_single_ioc(self) -> None:
        clusters = [{"iocs": ["only.com"], "alerts": []}]
        assert extract_iocs_from_sift(_make_bare(clusters)) == ["only.com"]

    def test_all_sources_populated(self) -> None:
        """Smoke test — all four IOC sources contribute unique values."""
        clusters = [
            {
                "iocs": ["cluster-ioc.com"],
                "alerts": [
                    {
                        "iocs": ["alert-ioc.net"],
                        "source_ip": "10.10.10.10",
                        "dest_ip": "20.20.20.20",
                    }
                ],
            }
        ]
        result = extract_iocs_from_sift(_make_bare(clusters))
        assert set(result) == {"cluster-ioc.com", "alert-ioc.net", "10.10.10.10", "20.20.20.20"}
        assert len(result) == 4
