"""Tests for AbuseIPDB secondary enricher plugin.

All tests are offline — no real network calls are made.
httpx transport is mocked throughout.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import httpx
import pytest

from vex.config import Config, EnrichmentConfig
from vex.enrichers.protocol import SecondaryEnricherProtocol
from vex.models import InvestigateResult, TriageResult, Verdict, DetectionStats
from vex.plugins.abuseipdb import AbuseIPDBPlugin
from vex.plugins.loader import load_plugins
from vex.plugins.registry import PluginRegistry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_investigate_result() -> InvestigateResult:
    """Build a minimal InvestigateResult with required nested TriageResult."""
    triage = TriageResult(
        ioc="1.2.3.4",
        ioc_type="ipv4",
        verdict=Verdict.UNKNOWN,
        detection_stats=DetectionStats(),
    )
    return InvestigateResult(triage=triage)


def _config_with_key(key: str = "test-abuseipdb-key-0000") -> Config:
    cfg = Config()
    cfg.enrichment = EnrichmentConfig(abuseipdb_api_key=key, abuseipdb_max_age_days=90)
    return cfg


def _config_no_key() -> Config:
    cfg = Config()
    cfg.enrichment = EnrichmentConfig(abuseipdb_api_key=None, abuseipdb_max_age_days=90)
    return cfg


_SAMPLE_PAYLOAD = {
    "data": {
        "ipAddress": "1.2.3.4",
        "abuseConfidenceScore": 87,
        "totalReports": 42,
        "lastReportedAt": "2026-05-30T12:00:00+00:00",
    }
}


# ---------------------------------------------------------------------------
# Protocol compliance
# ---------------------------------------------------------------------------

class TestAbuseIPDBProtocol:
    def test_implements_secondary_enricher_protocol(self):
        plugin = AbuseIPDBPlugin()
        assert isinstance(plugin, SecondaryEnricherProtocol)

    def test_name(self):
        assert AbuseIPDBPlugin().name == "AbuseIPDB"

    def test_supported_ioc_types_contains_ip(self):
        types = AbuseIPDBPlugin().supported_ioc_types
        assert "ipv4" in types
        assert "ipv6" in types

    def test_supported_ioc_types_excludes_non_ip(self):
        types = AbuseIPDBPlugin().supported_ioc_types
        assert "md5" not in types
        assert "domain" not in types
        assert "url" not in types
        assert "sha256" not in types


# ---------------------------------------------------------------------------
# No-key path: no network calls, no-op
# ---------------------------------------------------------------------------

class TestNoKeyPath:
    def test_no_key_returns_immediately_no_network(self, monkeypatch):
        """With no API key, enrich must not make any network call and fields stay None."""
        plugin = AbuseIPDBPlugin()
        result = _make_investigate_result()
        config = _config_no_key()

        get_calls = []
        monkeypatch.setattr(httpx, "get", lambda *a, **kw: get_calls.append((a, kw)) or None)

        plugin.enrich(result, "1.2.3.4", "ipv4", config)

        assert len(get_calls) == 0
        assert result.abuse_confidence is None
        assert result.abuse_total_reports is None
        assert result.abuse_last_reported is None

    def test_env_var_not_set_no_key_in_config(self, monkeypatch):
        """Both env and config key absent → no-op."""
        monkeypatch.delenv("VEX_ABUSEIPDB_API_KEY", raising=False)
        plugin = AbuseIPDBPlugin()
        result = _make_investigate_result()
        config = _config_no_key()

        called = []
        monkeypatch.setattr(httpx, "get", lambda *a, **kw: called.append(1))

        plugin.enrich(result, "1.2.3.4", "ipv4", config)

        assert len(called) == 0
        assert result.abuse_confidence is None


# ---------------------------------------------------------------------------
# Happy path: 200 response, fields populated
# ---------------------------------------------------------------------------

class TestHappyPath:
    def test_200_populates_fields(self, monkeypatch):
        """A 200 response with valid data populates all three abuse fields."""
        plugin = AbuseIPDBPlugin()
        result = _make_investigate_result()
        config = _config_with_key()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = _SAMPLE_PAYLOAD

        monkeypatch.setattr(httpx, "get", lambda *a, **kw: mock_response)

        plugin.enrich(result, "1.2.3.4", "ipv4", config)

        assert result.abuse_confidence == 87
        assert result.abuse_total_reports == 42
        assert result.abuse_last_reported == "2026-05-30T12:00:00+00:00"

    def test_200_uses_correct_url_and_headers(self, monkeypatch):
        """Request must use the expected URL, params, and Key header."""
        plugin = AbuseIPDBPlugin()
        result = _make_investigate_result()
        config = _config_with_key("my-api-key-1234")

        captured = {}

        def fake_get(url, *, params=None, headers=None, timeout=None):
            captured["url"] = url
            captured["params"] = params
            captured["headers"] = headers
            captured["timeout"] = timeout
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = _SAMPLE_PAYLOAD
            return mock_response

        monkeypatch.setattr(httpx, "get", fake_get)
        plugin.enrich(result, "1.2.3.4", "ipv4", config)

        assert "abuseipdb.com" in captured["url"]
        assert captured["params"]["ipAddress"] == "1.2.3.4"
        assert captured["params"]["maxAgeInDays"] == 90
        assert captured["headers"]["Key"] == "my-api-key-1234"
        assert captured["headers"]["Accept"] == "application/json"
        assert captured["timeout"] == 5.0


# ---------------------------------------------------------------------------
# Fail-open: errors and non-200 responses
# ---------------------------------------------------------------------------

class TestFailOpen:
    def test_network_exception_does_not_raise(self, monkeypatch):
        """A network error must be swallowed — enrich must not raise."""
        plugin = AbuseIPDBPlugin()
        result = _make_investigate_result()
        config = _config_with_key()

        monkeypatch.setattr(httpx, "get", lambda *a, **kw: (_ for _ in ()).throw(httpx.ConnectError("timeout")))

        # Must not raise
        plugin.enrich(result, "1.2.3.4", "ipv4", config)

        assert result.abuse_confidence is None
        assert result.abuse_total_reports is None
        assert result.abuse_last_reported is None

    def test_timeout_exception_does_not_raise(self, monkeypatch):
        """A ReadTimeout must be swallowed."""
        plugin = AbuseIPDBPlugin()
        result = _make_investigate_result()
        config = _config_with_key()

        def raise_timeout(*a, **kw):
            raise httpx.ReadTimeout("timed out")

        monkeypatch.setattr(httpx, "get", raise_timeout)
        plugin.enrich(result, "1.2.3.4", "ipv4", config)

        assert result.abuse_confidence is None

    def test_non_200_response_fields_stay_none(self, monkeypatch):
        """A non-200 response must leave all abuse fields as None."""
        plugin = AbuseIPDBPlugin()
        config = _config_with_key()

        for status_code in (400, 401, 403, 429, 500):
            result2 = _make_investigate_result()
            mock_response = MagicMock()
            mock_response.status_code = status_code

            monkeypatch.setattr(httpx, "get", lambda *a, **kw: mock_response)
            plugin.enrich(result2, "1.2.3.4", "ipv4", config)

            assert result2.abuse_confidence is None, f"Expected None for HTTP {status_code}"

    def test_malformed_json_does_not_raise(self, monkeypatch):
        """If JSON parsing raises, enrich must not propagate the exception."""
        plugin = AbuseIPDBPlugin()
        result = _make_investigate_result()
        config = _config_with_key()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError("bad json")

        monkeypatch.setattr(httpx, "get", lambda *a, **kw: mock_response)
        plugin.enrich(result, "1.2.3.4", "ipv4", config)

        assert result.abuse_confidence is None


# ---------------------------------------------------------------------------
# Registry integration
# ---------------------------------------------------------------------------

class TestRegistryIntegration:
    def test_get_secondary_ipv4_includes_abuseipdb(self):
        """load_plugins() registry must include AbuseIPDB for ipv4."""
        registry = load_plugins()
        secondaries = registry.get_secondary("ipv4")
        names = [s.name for s in secondaries]
        assert "AbuseIPDB" in names

    def test_get_secondary_ipv6_includes_abuseipdb(self):
        """load_plugins() registry must include AbuseIPDB for ipv6."""
        registry = load_plugins()
        secondaries = registry.get_secondary("ipv6")
        names = [s.name for s in secondaries]
        assert "AbuseIPDB" in names

    def test_get_secondary_md5_excludes_abuseipdb(self):
        """AbuseIPDB must not appear for hash IOC types."""
        registry = load_plugins()
        secondaries = registry.get_secondary("md5")
        names = [s.name for s in secondaries]
        assert "AbuseIPDB" not in names

    def test_get_secondary_domain_excludes_abuseipdb(self):
        """AbuseIPDB must not appear for domain IOC type."""
        registry = load_plugins()
        secondaries = registry.get_secondary("domain")
        names = [s.name for s in secondaries]
        assert "AbuseIPDB" not in names

    def test_register_secondary_type_error_on_wrong_type(self):
        """register_secondary must raise TypeError for non-compliant objects."""
        registry = PluginRegistry()
        with pytest.raises(TypeError):
            registry.register_secondary(object())  # type: ignore[arg-type]

    def test_secondary_plugins_property(self):
        """secondary_plugins property returns a copy of the secondary list."""
        registry = PluginRegistry()
        plugin = AbuseIPDBPlugin()
        registry.register_secondary(plugin)
        assert plugin in registry.secondary_plugins
        # Mutation of the returned list must not affect the registry
        registry.secondary_plugins.clear()
        assert plugin in registry.secondary_plugins


# ---------------------------------------------------------------------------
# Config env-var override
# ---------------------------------------------------------------------------

class TestConfigEnvOverride:
    def test_env_var_beats_config_key(self, monkeypatch):
        """VEX_ABUSEIPDB_API_KEY env var must take precedence over config value."""
        monkeypatch.setenv("VEX_ABUSEIPDB_API_KEY", "env-key-override")
        config = _config_with_key("config-key-value")

        resolved_key = config.abuseipdb_api_key
        assert resolved_key == "env-key-override"

    def test_config_key_used_when_env_absent(self, monkeypatch):
        """When env var is absent, config value is used."""
        monkeypatch.delenv("VEX_ABUSEIPDB_API_KEY", raising=False)
        config = _config_with_key("config-key-only")

        assert config.abuseipdb_api_key == "config-key-only"

    def test_both_absent_returns_none(self, monkeypatch):
        """When both env and config key are absent, property returns None."""
        monkeypatch.delenv("VEX_ABUSEIPDB_API_KEY", raising=False)
        config = _config_no_key()

        assert config.abuseipdb_api_key is None

    def test_enrich_uses_env_key_for_request(self, monkeypatch):
        """The env-overridden key must be used in the actual HTTP request."""
        monkeypatch.setenv("VEX_ABUSEIPDB_API_KEY", "env-key-used-in-request")
        # Config has a different value — env must win
        config = _config_with_key("config-key-ignored")

        plugin = AbuseIPDBPlugin()
        result = _make_investigate_result()

        captured_headers = {}

        def fake_get(url, *, params=None, headers=None, timeout=None):
            captured_headers.update(headers or {})
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = _SAMPLE_PAYLOAD
            return mock_response

        monkeypatch.setattr(httpx, "get", fake_get)
        plugin.enrich(result, "1.2.3.4", "ipv4", config)

        assert captured_headers.get("Key") == "env-key-used-in-request"
