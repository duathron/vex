"""Tests for MISP secondary enricher plugin.

All tests are offline — no real network calls are made.
httpx transport is mocked throughout.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import httpx

from vex.config import Config, EnrichmentConfig
from vex.enrichers.protocol import SecondaryEnricherProtocol
from vex.models import DetectionStats, InvestigateResult, TriageResult, Verdict
from vex.plugins.loader import load_plugins
from vex.plugins.misp import MISPEnricher

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_result(ioc: str = "1.2.3.4", ioc_type: str = "ipv4") -> InvestigateResult:
    """Build a minimal InvestigateResult with required nested TriageResult."""
    triage = TriageResult(
        ioc=ioc,
        ioc_type=ioc_type,
        verdict=Verdict.UNKNOWN,
        detection_stats=DetectionStats(),
    )
    return InvestigateResult(triage=triage)


def _config_with_creds(
    url: str = "https://misp.example.com",
    key: str = "test-misp-key-0000",
    verify_tls: bool = True,
) -> Config:
    cfg = Config()
    cfg.enrichment = EnrichmentConfig(misp_url=url, misp_api_key=key, misp_verify_tls=verify_tls)
    return cfg


def _config_no_url() -> Config:
    cfg = Config()
    cfg.enrichment = EnrichmentConfig(misp_url=None, misp_api_key="some-key")
    return cfg


def _config_no_key() -> Config:
    cfg = Config()
    cfg.enrichment = EnrichmentConfig(misp_url="https://misp.example.com", misp_api_key=None)
    return cfg


def _config_no_creds() -> Config:
    cfg = Config()
    cfg.enrichment = EnrichmentConfig(misp_url=None, misp_api_key=None)
    return cfg


# Realistic MISP response with two attributes across two events
_SAMPLE_RESPONSE = {
    "response": {
        "Attribute": [
            {
                "event_id": "123",
                "type": "ip-dst",
                "value": "1.2.3.4",
                "timestamp": "1690000000",
                "Tag": [
                    {"name": "tlp:amber"},
                    {"name": "malware:emotet"},
                ],
                "Event": {"id": "123", "info": "Emotet C2 campaign"},
            },
            {
                "event_id": "456",
                "type": "ip-dst",
                "value": "1.2.3.4",
                "timestamp": "1695000000",  # newer
                "Tag": [
                    {"name": "tlp:green"},
                    {"name": "misp-galaxy:threat-actor=Wizard Spider"},
                ],
                "Event": {"id": "456", "info": "Wizard Spider infrastructure"},
            },
        ]
    }
}

_EMPTY_RESPONSE = {"response": {"Attribute": []}}


# ---------------------------------------------------------------------------
# Protocol compliance
# ---------------------------------------------------------------------------


class TestMISPProtocol:
    def test_implements_secondary_enricher_protocol(self):
        assert isinstance(MISPEnricher(), SecondaryEnricherProtocol)

    def test_name(self):
        assert MISPEnricher().name == "MISP"

    def test_supported_ioc_types_contains_all_required(self):
        types = MISPEnricher().supported_ioc_types
        for expected in ["md5", "sha1", "sha256", "ipv4", "ipv6", "domain", "url"]:
            assert expected in types, f"Expected '{expected}' in supported_ioc_types"

    def test_supported_ioc_types_all_seven(self):
        assert len(MISPEnricher().supported_ioc_types) == 7


# ---------------------------------------------------------------------------
# No-config path: no network calls, no-op
# ---------------------------------------------------------------------------


class TestNoConfigPath:
    def test_no_url_returns_immediately_no_network(self, monkeypatch):
        """With no MISP URL, enrich must not make any network call."""
        enricher = MISPEnricher()
        result = _make_result()
        config = _config_no_url()

        post_calls = []
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: post_calls.append((a, kw)) or None)

        enricher.enrich(result, "1.2.3.4", "ipv4", config)

        assert len(post_calls) == 0
        assert result.misp_known is False

    def test_no_key_returns_immediately_no_network(self, monkeypatch):
        """With no API key, enrich must not make any network call."""
        enricher = MISPEnricher()
        result = _make_result()
        config = _config_no_key()

        post_calls = []
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: post_calls.append((a, kw)) or None)

        enricher.enrich(result, "1.2.3.4", "ipv4", config)

        assert len(post_calls) == 0
        assert result.misp_known is False

    def test_no_creds_zero_network_calls(self, monkeypatch):
        """Neither URL nor key → absolute zero network calls."""
        enricher = MISPEnricher()
        result = _make_result()
        config = _config_no_creds()

        called = []
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: called.append(1))

        enricher.enrich(result, "1.2.3.4", "ipv4", config)

        assert len(called) == 0

    def test_no_creds_fields_stay_default(self, monkeypatch):
        """All MISP fields stay at defaults when no credentials configured."""
        enricher = MISPEnricher()
        result = _make_result()
        config = _config_no_creds()
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: None)

        enricher.enrich(result, "1.2.3.4", "ipv4", config)

        assert result.misp_known is False
        assert result.misp_event_ids == []
        assert result.misp_tags == []
        assert result.misp_tlp is None
        assert result.misp_last_seen is None


# ---------------------------------------------------------------------------
# Happy path: 200 with attributes → all fields populated
# ---------------------------------------------------------------------------


class TestHappyPath:
    def test_200_sets_misp_known_true(self, monkeypatch):
        enricher = MISPEnricher()
        result = _make_result()
        config = _config_with_creds()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _SAMPLE_RESPONSE
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: mock_resp)

        enricher.enrich(result, "1.2.3.4", "ipv4", config)

        assert result.misp_known is True

    def test_200_populates_event_ids(self, monkeypatch):
        enricher = MISPEnricher()
        result = _make_result()
        config = _config_with_creds()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _SAMPLE_RESPONSE
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: mock_resp)

        enricher.enrich(result, "1.2.3.4", "ipv4", config)

        assert "123" in result.misp_event_ids
        assert "456" in result.misp_event_ids

    def test_200_collects_union_of_tags(self, monkeypatch):
        enricher = MISPEnricher()
        result = _make_result()
        config = _config_with_creds()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _SAMPLE_RESPONSE
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: mock_resp)

        enricher.enrich(result, "1.2.3.4", "ipv4", config)

        assert "tlp:amber" in result.misp_tags
        assert "malware:emotet" in result.misp_tags
        assert "tlp:green" in result.misp_tags
        assert "misp-galaxy:threat-actor=Wizard Spider" in result.misp_tags

    def test_200_derives_tlp_most_restrictive(self, monkeypatch):
        """amber is more restrictive than green → tlp should be AMBER."""
        enricher = MISPEnricher()
        result = _make_result()
        config = _config_with_creds()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _SAMPLE_RESPONSE
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: mock_resp)

        enricher.enrich(result, "1.2.3.4", "ipv4", config)

        assert result.misp_tlp == "AMBER"

    def test_200_last_seen_from_max_timestamp(self, monkeypatch):
        """misp_last_seen should be derived from the highest timestamp."""
        enricher = MISPEnricher()
        result = _make_result()
        config = _config_with_creds()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _SAMPLE_RESPONSE
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: mock_resp)

        enricher.enrich(result, "1.2.3.4", "ipv4", config)

        # 1695000000 epoch → 2023-09-18
        assert result.misp_last_seen is not None
        assert result.misp_last_seen.startswith("2023-")

    def test_200_uses_correct_url_headers_and_body(self, monkeypatch):
        """Request must use the correct endpoint, headers, and JSON body."""
        enricher = MISPEnricher()
        result = _make_result()
        config = _config_with_creds(url="https://misp.corp.example", key="my-secret-key")

        captured: dict = {}

        def fake_post(url, *, json=None, headers=None, timeout=None, verify=None):
            captured["url"] = url
            captured["json"] = json
            captured["headers"] = headers
            captured["timeout"] = timeout
            captured["verify"] = verify
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = _SAMPLE_RESPONSE
            return mock_resp

        monkeypatch.setattr(httpx, "post", fake_post)
        enricher.enrich(result, "1.2.3.4", "ipv4", config)

        assert captured["url"].endswith("/attributes/restSearch")
        assert "misp.corp.example" in captured["url"]
        assert captured["headers"]["Authorization"] == "my-secret-key"
        assert captured["headers"]["Accept"] == "application/json"
        assert captured["json"]["value"] == "1.2.3.4"
        assert captured["json"]["limit"] == 25
        assert captured["json"]["includeEventTags"] is True
        assert captured["timeout"] == 8.0


# ---------------------------------------------------------------------------
# Not found: empty Attribute list → misp_known stays False
# ---------------------------------------------------------------------------


class TestNotFound:
    def test_empty_attribute_list_known_stays_false(self, monkeypatch):
        enricher = MISPEnricher()
        result = _make_result()
        config = _config_with_creds()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _EMPTY_RESPONSE
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: mock_resp)

        enricher.enrich(result, "1.2.3.4", "ipv4", config)

        assert result.misp_known is False
        assert result.misp_event_ids == []
        assert result.misp_tags == []
        assert result.misp_tlp is None
        assert result.misp_last_seen is None

    def test_missing_response_key_known_stays_false(self, monkeypatch):
        enricher = MISPEnricher()
        result = _make_result()
        config = _config_with_creds()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {}
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: mock_resp)

        enricher.enrich(result, "1.2.3.4", "ipv4", config)

        assert result.misp_known is False


# ---------------------------------------------------------------------------
# Fail-open: errors, non-200, bad JSON
# ---------------------------------------------------------------------------


class TestFailOpen:
    def test_connect_error_does_not_raise(self, monkeypatch):
        enricher = MISPEnricher()
        result = _make_result()
        config = _config_with_creds()

        monkeypatch.setattr(
            httpx,
            "post",
            lambda *a, **kw: (_ for _ in ()).throw(httpx.ConnectError("refused")),
        )

        enricher.enrich(result, "1.2.3.4", "ipv4", config)

        assert result.misp_known is False

    def test_timeout_does_not_raise(self, monkeypatch):
        enricher = MISPEnricher()
        result = _make_result()
        config = _config_with_creds()

        def raise_timeout(*a, **kw):
            raise httpx.ReadTimeout("timed out")

        monkeypatch.setattr(httpx, "post", raise_timeout)
        enricher.enrich(result, "1.2.3.4", "ipv4", config)

        assert result.misp_known is False

    def test_non_200_response_does_not_raise(self, monkeypatch):
        enricher = MISPEnricher()
        config = _config_with_creds()

        for status_code in (400, 401, 403, 429, 500):
            result = _make_result()
            mock_resp = MagicMock()
            mock_resp.status_code = status_code
            monkeypatch.setattr(httpx, "post", lambda *a, **kw: mock_resp)

            enricher.enrich(result, "1.2.3.4", "ipv4", config)

            assert result.misp_known is False, f"Expected False for HTTP {status_code}"

    def test_bad_json_does_not_raise(self, monkeypatch):
        enricher = MISPEnricher()
        result = _make_result()
        config = _config_with_creds()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.side_effect = ValueError("bad json")
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: mock_resp)

        enricher.enrich(result, "1.2.3.4", "ipv4", config)

        assert result.misp_known is False

    def test_generic_exception_does_not_raise(self, monkeypatch):
        enricher = MISPEnricher()
        result = _make_result()
        config = _config_with_creds()

        def raise_generic(*a, **kw):
            raise RuntimeError("unexpected error")

        monkeypatch.setattr(httpx, "post", raise_generic)
        enricher.enrich(result, "1.2.3.4", "ipv4", config)

        assert result.misp_known is False


# ---------------------------------------------------------------------------
# TLP precedence
# ---------------------------------------------------------------------------


class TestTLPPrecedence:
    def _response_with_tlps(self, *tlp_names: str) -> dict:
        return {
            "response": {
                "Attribute": [
                    {
                        "event_id": "1",
                        "type": "ip-dst",
                        "value": "1.2.3.4",
                        "timestamp": "1690000000",
                        "Tag": [{"name": t} for t in tlp_names],
                        "Event": {"id": "1", "info": "test"},
                    }
                ]
            }
        }

    def test_red_beats_amber(self, monkeypatch):
        enricher = MISPEnricher()
        result = _make_result()
        config = _config_with_creds()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = self._response_with_tlps("tlp:amber", "tlp:red")
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: mock_resp)

        enricher.enrich(result, "1.2.3.4", "ipv4", config)

        assert result.misp_tlp == "RED"

    def test_amber_beats_green(self, monkeypatch):
        enricher = MISPEnricher()
        result = _make_result()
        config = _config_with_creds()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = self._response_with_tlps("tlp:green", "tlp:amber")
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: mock_resp)

        enricher.enrich(result, "1.2.3.4", "ipv4", config)

        assert result.misp_tlp == "AMBER"

    def test_green_beats_clear(self, monkeypatch):
        enricher = MISPEnricher()
        result = _make_result()
        config = _config_with_creds()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = self._response_with_tlps("tlp:clear", "tlp:green")
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: mock_resp)

        enricher.enrich(result, "1.2.3.4", "ipv4", config)

        assert result.misp_tlp == "GREEN"

    def test_clear_and_white_are_equivalent_least_restrictive(self, monkeypatch):
        enricher = MISPEnricher()
        result = _make_result()
        config = _config_with_creds()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = self._response_with_tlps("tlp:white", "tlp:clear")
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: mock_resp)

        enricher.enrich(result, "1.2.3.4", "ipv4", config)

        # Both white and clear are at equivalent rank — result is one of them
        assert result.misp_tlp in ("WHITE", "CLEAR")

    def test_no_tlp_tag_returns_none(self, monkeypatch):
        enricher = MISPEnricher()
        result = _make_result()
        config = _config_with_creds()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = self._response_with_tlps("malware:emotet", "actor:wizard-spider")
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: mock_resp)

        enricher.enrich(result, "1.2.3.4", "ipv4", config)

        assert result.misp_tlp is None

    def test_red_beats_all(self, monkeypatch):
        enricher = MISPEnricher()
        result = _make_result()
        config = _config_with_creds()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = self._response_with_tlps(
            "tlp:white", "tlp:clear", "tlp:green", "tlp:amber", "tlp:red"
        )
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: mock_resp)

        enricher.enrich(result, "1.2.3.4", "ipv4", config)

        assert result.misp_tlp == "RED"


# ---------------------------------------------------------------------------
# verify flag
# ---------------------------------------------------------------------------


class TestVerifyFlag:
    def test_verify_true_passed_to_httpx(self, monkeypatch):
        enricher = MISPEnricher()
        result = _make_result()
        config = _config_with_creds(verify_tls=True)

        captured: dict = {}

        def fake_post(url, *, json=None, headers=None, timeout=None, verify=None):
            captured["verify"] = verify
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = _EMPTY_RESPONSE
            return mock_resp

        monkeypatch.setattr(httpx, "post", fake_post)
        enricher.enrich(result, "1.2.3.4", "ipv4", config)

        assert captured["verify"] is True

    def test_verify_false_passed_to_httpx(self, monkeypatch):
        enricher = MISPEnricher()
        result = _make_result()
        config = _config_with_creds(verify_tls=False)

        captured: dict = {}

        def fake_post(url, *, json=None, headers=None, timeout=None, verify=None):
            captured["verify"] = verify
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = _EMPTY_RESPONSE
            return mock_resp

        monkeypatch.setattr(httpx, "post", fake_post)
        enricher.enrich(result, "1.2.3.4", "ipv4", config)

        assert captured["verify"] is False


# ---------------------------------------------------------------------------
# Registry integration
# ---------------------------------------------------------------------------


class TestRegistryIntegration:
    def test_get_secondary_ipv4_includes_misp(self):
        registry = load_plugins()
        names = [s.name for s in registry.get_secondary("ipv4")]
        assert "MISP" in names

    def test_get_secondary_md5_includes_misp(self):
        registry = load_plugins()
        names = [s.name for s in registry.get_secondary("md5")]
        assert "MISP" in names

    def test_get_secondary_sha256_includes_misp(self):
        registry = load_plugins()
        names = [s.name for s in registry.get_secondary("sha256")]
        assert "MISP" in names

    def test_get_secondary_domain_includes_misp(self):
        registry = load_plugins()
        names = [s.name for s in registry.get_secondary("domain")]
        assert "MISP" in names

    def test_get_secondary_url_includes_misp(self):
        registry = load_plugins()
        names = [s.name for s in registry.get_secondary("url")]
        assert "MISP" in names

    def test_get_secondary_sha1_includes_misp(self):
        registry = load_plugins()
        names = [s.name for s in registry.get_secondary("sha1")]
        assert "MISP" in names

    def test_get_secondary_ipv6_includes_misp(self):
        registry = load_plugins()
        names = [s.name for s in registry.get_secondary("ipv6")]
        assert "MISP" in names


# ---------------------------------------------------------------------------
# Config env-var override
# ---------------------------------------------------------------------------


class TestConfigEnvOverride:
    def test_misp_url_env_beats_config(self, monkeypatch):
        monkeypatch.setenv("MISP_URL", "https://env-misp.example.com")
        config = _config_with_creds(url="https://config-misp.example.com")

        assert config.misp_url == "https://env-misp.example.com"

    def test_misp_api_key_env_beats_config(self, monkeypatch):
        monkeypatch.setenv("MISP_API_KEY", "env-api-key-override")
        config = _config_with_creds(key="config-key-value")

        assert config.misp_api_key == "env-api-key-override"

    def test_config_url_used_when_env_absent(self, monkeypatch):
        monkeypatch.delenv("MISP_URL", raising=False)
        config = _config_with_creds(url="https://config-only.example.com")

        assert config.misp_url == "https://config-only.example.com"

    def test_config_key_used_when_env_absent(self, monkeypatch):
        monkeypatch.delenv("MISP_API_KEY", raising=False)
        config = _config_with_creds(key="config-key-only")

        assert config.misp_api_key == "config-key-only"

    def test_both_absent_returns_none(self, monkeypatch):
        monkeypatch.delenv("MISP_URL", raising=False)
        monkeypatch.delenv("MISP_API_KEY", raising=False)
        config = _config_no_creds()

        assert config.misp_url is None
        assert config.misp_api_key is None

    def test_env_key_used_in_request(self, monkeypatch):
        """The env-overridden key must be sent in the Authorization header."""
        monkeypatch.setenv("MISP_API_KEY", "env-key-in-request")
        monkeypatch.delenv("MISP_URL", raising=False)
        # Set URL via config, key via env
        config = Config()
        config.enrichment = EnrichmentConfig(
            misp_url="https://misp.example.com",
            misp_api_key="config-key-ignored",
        )

        enricher = MISPEnricher()
        result = _make_result()
        captured: dict = {}

        def fake_post(url, *, json=None, headers=None, timeout=None, verify=None):
            captured["headers"] = headers or {}
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = _EMPTY_RESPONSE
            return mock_resp

        monkeypatch.setattr(httpx, "post", fake_post)
        enricher.enrich(result, "1.2.3.4", "ipv4", config)

        assert captured["headers"].get("Authorization") == "env-key-in-request"

    def test_env_url_used_in_request(self, monkeypatch):
        """The env-overridden URL must be used to build the request URL."""
        monkeypatch.setenv("MISP_URL", "https://env-misp.example.com")
        monkeypatch.delenv("MISP_API_KEY", raising=False)
        config = Config()
        config.enrichment = EnrichmentConfig(
            misp_url="https://config-ignored.example.com",
            misp_api_key="some-key",
        )

        enricher = MISPEnricher()
        result = _make_result()
        captured: dict = {}

        def fake_post(url, *, json=None, headers=None, timeout=None, verify=None):
            captured["url"] = url
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = _EMPTY_RESPONSE
            return mock_resp

        monkeypatch.setattr(httpx, "post", fake_post)
        enricher.enrich(result, "1.2.3.4", "ipv4", config)

        assert "env-misp.example.com" in captured["url"]
