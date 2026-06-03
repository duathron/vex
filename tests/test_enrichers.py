"""Tests for VT enrichers: ip, domain, hash, url.

All tests use a fake client stub — no network calls.
Tests cover triage(), investigate(), and the empty/not-found path.
"""

from __future__ import annotations

from datetime import timezone
from typing import Any
from unittest.mock import MagicMock

from vex.config import Config
from vex.models import (
    InvestigateResult,
    TriageResult,
    Verdict,
)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_config(
    malicious_min: int = 3,
    suspicious_min: int = 1,
    min_engines: int = 10,
    premium: bool = False,
    whois_enabled: bool = False,
) -> Config:
    cfg = Config()
    cfg.api.key = "fake-key-00000000"
    cfg.api.tier = "premium" if premium else "free"
    cfg.thresholds.malicious_min_detections = malicious_min
    cfg.thresholds.suspicious_min_detections = suspicious_min
    cfg.thresholds.min_engines_for_clean = min_engines
    cfg.enrichment.whois_enabled = whois_enabled
    return cfg


def _fake_client(**methods: Any) -> MagicMock:
    """Build a MagicMock VTClient pre-loaded with method return values."""
    client = MagicMock()
    for name, retval in methods.items():
        getattr(client, name).return_value = retval
    return client


def _analysis_stats(malicious: int = 0, suspicious: int = 0, undetected: int = 50) -> dict[str, int]:
    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "undetected": undetected,
        "harmless": 0,
        "timeout": 0,
    }


def _engine_results(
    *,
    malicious_engines: list[str] | None = None,
    family: str = "Emotet",
) -> dict[str, Any]:
    """Build last_analysis_results with the given malicious engines."""
    out: dict[str, Any] = {}
    for engine in malicious_engines or []:
        out[engine] = {"category": "malicious", "result": family}
    return out


def _vt_file_response(
    *,
    malicious: int = 5,
    suspicious: int = 0,
    undetected: int = 65,
    family: str = "Emotet",
    tags: list[str] | None = None,
    first_submission: int = 1_700_000_000,
    last_submission: int = 1_710_000_000,
    last_analysis_date: int = 1_710_000_000,
    reputation: int = -50,
    threat_label: str = "trojan.emotet",
) -> dict[str, Any]:
    engines = _engine_results(
        malicious_engines=["EngineA", "EngineB"] if malicious >= 2 else [],
        family=family,
    )
    return {
        "data": {
            "id": "abc123",
            "type": "file",
            "attributes": {
                "last_analysis_stats": _analysis_stats(malicious, suspicious, undetected),
                "last_analysis_results": engines,
                "tags": tags or ["trojan"],
                "first_submission_date": first_submission,
                "last_submission_date": last_submission,
                "last_analysis_date": last_analysis_date,
                "reputation": reputation,
                "popular_threat_classification": {
                    "suggested_threat_label": threat_label,
                    "popular_threat_category": [{"value": "trojan", "count": 10}],
                },
                "size": 102400,
                "type_description": "Win32 EXE",
                "names": ["malware.exe", "bad.bin"],
                "magic": "PE32 executable",
                "ssdeep": "3072:abc:def",
                "tlsh": "T1234",
            },
        }
    }


def _vt_ip_response(
    *,
    malicious: int = 5,
    asn: int = 12345,
    as_owner: str = "Evil ISP",
    country: str = "RU",
    continent: str = "EU",
    network: str = "1.2.3.0/24",
    reputation: int = -80,
    categories: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "data": {
            "id": "1.2.3.4",
            "type": "ip_address",
            "attributes": {
                "last_analysis_stats": _analysis_stats(malicious, 0, 50),
                "last_analysis_results": _engine_results(malicious_engines=["EngineA", "EngineB"]),
                "asn": asn,
                "as_owner": as_owner,
                "country": country,
                "continent": continent,
                "network": network,
                "reputation": reputation,
                "tags": [],
                "categories": categories or {"Webroot": "malicious"},
            },
        }
    }


def _vt_domain_response(
    *,
    malicious: int = 4,
    reputation: int = -60,
    categories: dict[str, Any] | None = None,
    last_dns_records: list[dict] | None = None,
    subdomains: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "data": {
            "id": "evil.com",
            "type": "domain",
            "attributes": {
                "last_analysis_stats": _analysis_stats(malicious, 0, 60),
                "last_analysis_results": _engine_results(malicious_engines=["EngineA", "EngineB"]),
                "reputation": reputation,
                "tags": ["phishing"],
                "creation_date": 1_600_000_000,
                "categories": categories or {"Webroot": "phishing"},
                "last_dns_records": last_dns_records or [{"type": "A", "value": "1.2.3.4", "ttl": 300}],
                "subdomains": subdomains or ["mail.evil.com"],
            },
        }
    }


def _vt_url_response(
    *,
    malicious: int = 3,
    reputation: int = -40,
    title: str = "Evil Page",
    final_url: str = "http://evil.com/landing",
    categories: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "data": {
            "id": "url_id_123",
            "type": "url",
            "attributes": {
                "last_analysis_stats": _analysis_stats(malicious, 0, 50),
                "last_analysis_results": _engine_results(malicious_engines=["EngineA", "EngineB"]),
                "reputation": reputation,
                "tags": [],
                "last_analysis_date": 1_710_000_000,
                "title": title,
                "last_final_url": final_url,
                "categories": categories or {"Webroot": "malware"},
            },
        }
    }


# ---------------------------------------------------------------------------
# Hash / file enricher tests
# ---------------------------------------------------------------------------


class TestHashEnricher:
    def test_triage_malicious_verdict(self) -> None:
        from vex.enrichers import hash as hash_enricher

        cfg = _make_config(malicious_min=3)
        resp = _vt_file_response(malicious=5)
        client = _fake_client(get_file=resp)
        result = hash_enricher.triage("abc123", "sha256", client, cfg)
        assert isinstance(result, TriageResult)
        assert result.verdict == Verdict.MALICIOUS
        assert result.ioc == "abc123"
        assert result.ioc_type == "sha256"

    def test_triage_clean_verdict(self) -> None:
        from vex.enrichers import hash as hash_enricher

        cfg = _make_config(malicious_min=3, min_engines=10)
        resp = _vt_file_response(malicious=0, undetected=70)
        # Remove malicious engines
        resp["data"]["attributes"]["last_analysis_results"] = _engine_results(malicious_engines=[])
        client = _fake_client(get_file=resp)
        result = hash_enricher.triage("abc123", "sha256", client, cfg)
        assert result.verdict == Verdict.CLEAN

    def test_triage_not_found_returns_unknown(self) -> None:
        from vex.enrichers import hash as hash_enricher

        cfg = _make_config()
        client = _fake_client(get_file={})
        result = hash_enricher.triage("abc123", "sha256", client, cfg)
        assert result.verdict == Verdict.UNKNOWN
        assert result.error is not None
        assert result.error != ""

    def test_triage_detection_stats_populated(self) -> None:
        from vex.enrichers import hash as hash_enricher

        cfg = _make_config()
        resp = _vt_file_response(malicious=5, undetected=65)
        client = _fake_client(get_file=resp)
        result = hash_enricher.triage("abc123", "sha256", client, cfg)
        assert result.detection_stats.malicious == 5
        assert result.detection_stats.undetected == 65

    def test_triage_categories_extracted(self) -> None:
        from vex.enrichers import hash as hash_enricher

        cfg = _make_config()
        resp = _vt_file_response()
        client = _fake_client(get_file=resp)
        result = hash_enricher.triage("abc123", "sha256", client, cfg)
        assert "trojan" in result.categories

    def test_triage_from_cache_flag(self) -> None:
        from vex.enrichers import hash as hash_enricher

        cfg = _make_config()
        resp = _vt_file_response()
        client = _fake_client(get_file=resp)
        result = hash_enricher.triage("abc123", "sha256", client, cfg, from_cache=True)
        assert result.from_cache is True

    def test_investigate_not_found_returns_invest_result(self) -> None:
        from vex.enrichers import hash as hash_enricher

        cfg = _make_config()
        client = _fake_client(get_file={})
        result = hash_enricher.investigate("abc123", "sha256", client, cfg)
        assert isinstance(result, InvestigateResult)
        assert result.triage.verdict == Verdict.UNKNOWN

    def test_investigate_populates_file_fields(self) -> None:
        from vex.enrichers import hash as hash_enricher

        cfg = _make_config()
        resp = _vt_file_response()
        client = _fake_client(
            get_file=resp,
            get_file_behaviors={"data": []},
            get_file_contacted_ips={"data": [{"id": "10.0.0.1"}]},
            get_file_contacted_domains={"data": [{"id": "c2.evil.com"}]},
            get_file_dropped_files={"data": []},
        )
        result = hash_enricher.investigate("abc123", "sha256", client, cfg)
        assert result.file_type == "Win32 EXE"
        assert result.file_size == 102400
        assert "malware.exe" in result.file_names
        assert result.magic == "PE32 executable"
        assert result.ssdeep == "3072:abc:def"
        assert result.tlsh == "T1234"
        assert "10.0.0.1" in result.contacted_ips
        assert "c2.evil.com" in result.contacted_domains

    def test_investigate_premium_fetches_sandbox(self) -> None:
        from vex.enrichers import hash as hash_enricher

        cfg = _make_config(premium=True)
        resp = _vt_file_response()
        sandbox_raw = {
            "data": [
                {
                    "attributes": {
                        "sandbox_name": "Cuckoo",
                        "verdict": "malicious",
                        "processes_created": [{"process_name": "cmd.exe"}],
                        "files_written": [{"path": "C:\\evil.txt"}],
                        "files_deleted": [],
                        "registry_keys_set": [],
                        "network_connections": [{"destination_ip": "1.2.3.4", "destination_port": 443}],
                        "dns_lookups": [{"hostname": "evil.com"}],
                        "mutexes_created": ["EvilMutex"],
                    }
                }
            ]
        }
        client = _fake_client(
            get_file=resp,
            get_file_behaviors=sandbox_raw,
            get_file_contacted_ips={"data": []},
            get_file_contacted_domains={"data": []},
            get_file_dropped_files={"data": []},
        )
        result = hash_enricher.investigate("abc123", "sha256", client, cfg)
        assert len(result.sandbox_behaviors) == 1
        sb = result.sandbox_behaviors[0]
        assert sb.sandbox_name == "Cuckoo"
        assert sb.verdict == "malicious"
        assert "cmd.exe" in sb.processes_created
        assert "C:\\evil.txt" in sb.files_written
        assert "1.2.3.4:443" in sb.network_connections
        assert "evil.com" in sb.dns_lookups
        assert "EvilMutex" in sb.mutexes

    def test_investigate_free_tier_skips_sandbox(self) -> None:
        from vex.enrichers import hash as hash_enricher

        cfg = _make_config(premium=False)
        resp = _vt_file_response()
        client = _fake_client(
            get_file=resp,
            get_file_contacted_ips={"data": []},
            get_file_contacted_domains={"data": []},
            get_file_dropped_files={"data": []},
        )
        result = hash_enricher.investigate("abc123", "sha256", client, cfg)
        assert result.sandbox_behaviors == []
        client.get_file_behaviors.assert_not_called()

    def test_triage_prefetched_skips_client_call(self) -> None:
        from vex.enrichers import hash as hash_enricher

        cfg = _make_config()
        resp = _vt_file_response()
        attrs = resp["data"]["attributes"]
        analysis_results = attrs["last_analysis_results"]
        # Use _prefetched to bypass client.get_file
        client_not_called = _fake_client()
        result = hash_enricher.triage(
            "abc123",
            "sha256",
            client_not_called,
            cfg,
            _prefetched=(resp, attrs, analysis_results),
        )
        client_not_called.get_file.assert_not_called()
        assert result.ioc == "abc123"


# ---------------------------------------------------------------------------
# IP enricher tests
# ---------------------------------------------------------------------------


class TestIPEnricher:
    def test_triage_malicious_verdict(self) -> None:
        from vex.enrichers import ip as ip_enricher

        cfg = _make_config(malicious_min=3)
        resp = _vt_ip_response(malicious=5)
        client = _fake_client(get_ip=resp)
        result = ip_enricher.triage("1.2.3.4", "ipv4", client, cfg)
        assert result.verdict == Verdict.MALICIOUS
        assert result.ioc == "1.2.3.4"

    def test_triage_not_found_returns_unknown(self) -> None:
        from vex.enrichers import ip as ip_enricher

        cfg = _make_config()
        client = _fake_client(get_ip={})
        result = ip_enricher.triage("1.2.3.4", "ipv4", client, cfg)
        assert result.verdict == Verdict.UNKNOWN
        assert result.error is not None

    def test_triage_reputation_populated(self) -> None:
        from vex.enrichers import ip as ip_enricher

        cfg = _make_config()
        resp = _vt_ip_response(reputation=-80)
        client = _fake_client(get_ip=resp)
        result = ip_enricher.triage("1.2.3.4", "ipv4", client, cfg)
        assert result.reputation == -80

    def test_triage_categories_collected(self) -> None:
        from vex.enrichers import ip as ip_enricher

        cfg = _make_config()
        resp = _vt_ip_response(categories={"Webroot": "malicious", "FortiGuard": "botnet"})
        client = _fake_client(get_ip=resp)
        result = ip_enricher.triage("1.2.3.4", "ipv4", client, cfg)
        assert "malicious" in result.categories or "botnet" in result.categories

    def test_investigate_not_found(self) -> None:
        from vex.enrichers import ip as ip_enricher

        cfg = _make_config()
        client = _fake_client(get_ip={})
        result = ip_enricher.investigate("1.2.3.4", "ipv4", client, cfg)
        assert isinstance(result, InvestigateResult)
        assert result.triage.verdict == Verdict.UNKNOWN

    def test_investigate_asn_country(self) -> None:
        from vex.enrichers import ip as ip_enricher

        cfg = _make_config()
        resp = _vt_ip_response(asn=12345, as_owner="Evil ISP", country="RU", continent="EU")
        client = _fake_client(
            get_ip=resp,
            get_ip_resolutions={"data": []},
            get_ip_communicating_files={"data": []},
            get_ip_downloaded_files={"data": []},
        )
        result = ip_enricher.investigate("1.2.3.4", "ipv4", client, cfg)
        assert result.asn == 12345
        assert result.asn_owner == "Evil ISP"
        assert result.country == "RU"
        assert result.continent == "EU"

    def test_investigate_passive_dns_parsed(self) -> None:
        from vex.enrichers import ip as ip_enricher

        cfg = _make_config()
        resp = _vt_ip_response()
        resolutions_raw = {
            "data": [
                {
                    "attributes": {
                        "host_name": "evil.com",
                        "resolver": "8.8.8.8",
                        "date": 1_710_000_000,
                    }
                }
            ]
        }
        client = _fake_client(
            get_ip=resp,
            get_ip_resolutions=resolutions_raw,
            get_ip_communicating_files={"data": []},
            get_ip_downloaded_files={"data": []},
        )
        result = ip_enricher.investigate("1.2.3.4", "ipv4", client, cfg)
        assert len(result.passive_dns) == 1
        dns = result.passive_dns[0]
        assert dns.hostname == "evil.com"
        assert dns.ip_address == "1.2.3.4"
        assert dns.resolver == "8.8.8.8"
        assert dns.last_resolved is not None
        assert dns.last_resolved.tzinfo == timezone.utc

    def test_investigate_premium_fetches_comm_files(self) -> None:
        from vex.enrichers import ip as ip_enricher

        cfg = _make_config(premium=True)
        resp = _vt_ip_response()
        comm_file = {
            "data": [
                {
                    "attributes": {
                        "sha256": "dead" * 16,
                        "names": ["payload.exe"],
                        "last_analysis_stats": {"malicious": 3, "undetected": 50},
                    }
                }
            ]
        }
        client = _fake_client(
            get_ip=resp,
            get_ip_resolutions={"data": []},
            get_ip_communicating_files=comm_file,
            get_ip_downloaded_files={"data": []},
        )
        result = ip_enricher.investigate("1.2.3.4", "ipv4", client, cfg)
        assert len(result.communicating_files) == 1
        assert result.communicating_files[0].sha256 == "dead" * 16

    def test_investigate_free_skips_comm_files(self) -> None:
        from vex.enrichers import ip as ip_enricher

        cfg = _make_config(premium=False)
        resp = _vt_ip_response()
        client = _fake_client(
            get_ip=resp,
            get_ip_resolutions={"data": []},
        )
        result = ip_enricher.investigate("1.2.3.4", "ipv4", client, cfg)
        assert result.communicating_files == []
        client.get_ip_communicating_files.assert_not_called()


# ---------------------------------------------------------------------------
# Domain enricher tests
# ---------------------------------------------------------------------------


class TestDomainEnricher:
    def test_triage_malicious_verdict(self) -> None:
        from vex.enrichers import domain as domain_enricher

        cfg = _make_config(malicious_min=3)
        resp = _vt_domain_response(malicious=4)
        client = _fake_client(get_domain=resp)
        result = domain_enricher.triage("evil.com", "domain", client, cfg)
        assert result.verdict == Verdict.MALICIOUS
        assert result.ioc == "evil.com"

    def test_triage_not_found_returns_unknown(self) -> None:
        from vex.enrichers import domain as domain_enricher

        cfg = _make_config()
        client = _fake_client(get_domain={})
        result = domain_enricher.triage("evil.com", "domain", client, cfg)
        assert result.verdict == Verdict.UNKNOWN
        assert result.error is not None

    def test_triage_categories_collected(self) -> None:
        from vex.enrichers import domain as domain_enricher

        cfg = _make_config()
        resp = _vt_domain_response(categories={"Webroot": "phishing"})
        client = _fake_client(get_domain=resp)
        result = domain_enricher.triage("evil.com", "domain", client, cfg)
        assert "phishing" in result.categories

    def test_triage_first_seen_parsed(self) -> None:
        from vex.enrichers import domain as domain_enricher

        cfg = _make_config()
        resp = _vt_domain_response()
        client = _fake_client(get_domain=resp)
        result = domain_enricher.triage("evil.com", "domain", client, cfg)
        assert result.first_seen is not None
        assert result.first_seen.tzinfo == timezone.utc

    def test_investigate_not_found(self) -> None:
        from vex.enrichers import domain as domain_enricher

        cfg = _make_config()
        client = _fake_client(get_domain={})
        result = domain_enricher.investigate("evil.com", "domain", client, cfg)
        assert isinstance(result, InvestigateResult)
        assert result.triage.verdict == Verdict.UNKNOWN

    def test_investigate_passive_dns_parsed(self) -> None:
        from vex.enrichers import domain as domain_enricher

        cfg = _make_config()
        resp = _vt_domain_response()
        resolutions_raw = {
            "data": [
                {
                    "attributes": {
                        "ip_address": "1.2.3.4",
                        "resolver": "8.8.8.8",
                        "date": 1_710_000_000,
                    }
                }
            ]
        }
        client = _fake_client(
            get_domain=resp,
            get_domain_resolutions=resolutions_raw,
            get_domain_communicating_files={"data": []},
            get_domain_whois={"data": []},
        )
        result = domain_enricher.investigate("evil.com", "domain", client, cfg)
        assert len(result.passive_dns) == 1
        dns = result.passive_dns[0]
        assert dns.hostname == "evil.com"
        assert dns.ip_address == "1.2.3.4"

    def test_investigate_dns_records_parsed(self) -> None:
        from vex.enrichers import domain as domain_enricher

        cfg = _make_config()
        resp = _vt_domain_response(
            last_dns_records=[
                {"type": "A", "value": "1.2.3.4", "ttl": 300},
                {"type": "MX", "value": "mail.evil.com", "ttl": 3600},
            ]
        )
        client = _fake_client(
            get_domain=resp,
            get_domain_resolutions={"data": []},
            get_domain_communicating_files={"data": []},
            get_domain_whois={"data": []},
        )
        result = domain_enricher.investigate("evil.com", "domain", client, cfg)
        assert len(result.dns_records) == 2
        types = {r["type"] for r in result.dns_records}
        assert "A" in types and "MX" in types

    def test_investigate_subdomains_populated(self) -> None:
        from vex.enrichers import domain as domain_enricher

        cfg = _make_config()
        resp = _vt_domain_response(subdomains=["mail.evil.com", "api.evil.com"])
        client = _fake_client(
            get_domain=resp,
            get_domain_resolutions={"data": []},
            get_domain_communicating_files={"data": []},
            get_domain_whois={"data": []},
        )
        result = domain_enricher.investigate("evil.com", "domain", client, cfg)
        assert "mail.evil.com" in result.subdomains

    def test_investigate_premium_whois_parsed(self) -> None:
        from vex.enrichers import domain as domain_enricher

        cfg = _make_config(premium=True)
        resp = _vt_domain_response()
        whois_raw = {
            "data": [
                {
                    "attributes": {
                        "registrar": "Evil Registrar LLC",
                        "creation_date": "2020-01-01",
                        "expiration_date": "2030-01-01",
                        "updated_date": "2023-06-01",
                        "name_servers": ["ns1.evil.com"],
                        "registrant_organization": "Evil Corp",
                        "registrant_country": "RU",
                    }
                }
            ]
        }
        client = _fake_client(
            get_domain=resp,
            get_domain_resolutions={"data": []},
            get_domain_communicating_files={"data": []},
            get_domain_whois=whois_raw,
        )
        result = domain_enricher.investigate("evil.com", "domain", client, cfg)
        assert result.whois is not None
        assert result.whois.registrar == "Evil Registrar LLC"
        assert result.whois.registrant_org == "Evil Corp"
        assert result.whois.registrant_country == "RU"

    def test_investigate_free_skips_whois_and_comm_files(self) -> None:
        from vex.enrichers import domain as domain_enricher

        cfg = _make_config(premium=False, whois_enabled=False)
        resp = _vt_domain_response()
        client = _fake_client(
            get_domain=resp,
            get_domain_resolutions={"data": []},
        )
        result = domain_enricher.investigate("evil.com", "domain", client, cfg)
        assert result.whois is None
        client.get_domain_communicating_files.assert_not_called()
        client.get_domain_whois.assert_not_called()


# ---------------------------------------------------------------------------
# URL enricher tests
# ---------------------------------------------------------------------------


class TestURLEnricher:
    def test_triage_malicious_verdict_url_shape(self) -> None:
        from vex.enrichers import url as url_enricher

        cfg = _make_config(malicious_min=3)
        resp = _vt_url_response(malicious=3)
        client = _fake_client(get_url=resp)
        result = url_enricher.triage("http://evil.com/malware", "url", client, cfg)
        assert result.verdict == Verdict.MALICIOUS
        assert result.ioc == "http://evil.com/malware"

    def test_triage_not_found_returns_unknown(self) -> None:
        from vex.enrichers import url as url_enricher

        cfg = _make_config()
        client = _fake_client(get_url={})
        result = url_enricher.triage("http://evil.com/malware", "url", client, cfg)
        assert result.verdict == Verdict.UNKNOWN
        assert result.error is not None

    def test_triage_analysis_shape_parsed(self) -> None:
        """Handles the /analyses/{id} response shape (type == 'analysis')."""
        from vex.enrichers import url as url_enricher

        cfg = _make_config(malicious_min=2)
        analysis_resp = {
            "data": {
                "id": "anal-001",
                "type": "analysis",
                "attributes": {
                    "stats": _analysis_stats(malicious=3),
                    "results": _engine_results(malicious_engines=["EngineA", "EngineB"]),
                },
            }
        }
        client = _fake_client(get_url=analysis_resp)
        result = url_enricher.triage("http://evil.com/malware", "url", client, cfg)
        assert result.verdict == Verdict.MALICIOUS
        assert result.detection_stats.malicious == 3

    def test_triage_categories_collected(self) -> None:
        from vex.enrichers import url as url_enricher

        cfg = _make_config()
        resp = _vt_url_response(categories={"Webroot": "malware"})
        client = _fake_client(get_url=resp)
        result = url_enricher.triage("http://evil.com/", "url", client, cfg)
        assert "malware" in result.categories

    def test_investigate_not_found(self) -> None:
        from vex.enrichers import url as url_enricher

        cfg = _make_config()
        client = _fake_client(get_url={})
        result = url_enricher.investigate("http://evil.com/", "url", client, cfg)
        assert isinstance(result, InvestigateResult)
        assert result.triage.verdict == Verdict.UNKNOWN

    def test_investigate_final_url_and_title(self) -> None:
        from vex.enrichers import url as url_enricher

        cfg = _make_config()
        resp = _vt_url_response(title="Evil Page", final_url="http://evil.com/landing")
        client = _fake_client(
            get_url=resp,
            get_url_related_files={"data": []},
        )
        result = url_enricher.investigate("http://evil.com/", "url", client, cfg)
        assert result.final_url == "http://evil.com/landing"
        assert result.title == "Evil Page"

    def test_investigate_premium_fetches_related_files(self) -> None:
        from vex.enrichers import url as url_enricher

        cfg = _make_config(premium=True)
        resp = _vt_url_response()
        related_files_raw = {
            "data": [
                {
                    "attributes": {
                        "sha256": "beef" * 16,
                        "names": ["dropper.exe"],
                        "last_analysis_stats": {"malicious": 5, "undetected": 60},
                    }
                }
            ]
        }
        client = _fake_client(
            get_url=resp,
            get_url_related_files=related_files_raw,
        )
        result = url_enricher.investigate("http://evil.com/", "url", client, cfg)
        assert len(result.related_files) == 1
        assert result.related_files[0].sha256 == "beef" * 16

    def test_investigate_free_skips_related_files(self) -> None:
        from vex.enrichers import url as url_enricher

        cfg = _make_config(premium=False)
        resp = _vt_url_response()
        client = _fake_client(get_url=resp)
        result = url_enricher.investigate("http://evil.com/", "url", client, cfg)
        assert result.related_files == []
        client.get_url_related_files.assert_not_called()

    def test_triage_prefetched_dict_skips_client(self) -> None:
        from vex.enrichers import url as url_enricher

        cfg = _make_config()
        resp = _vt_url_response()
        client = _fake_client()  # should not be called
        result = url_enricher.triage(
            "http://evil.com/",
            "url",
            client,
            cfg,
            _prefetched=resp,
        )
        client.get_url.assert_not_called()
        assert result.ioc == "http://evil.com/"
