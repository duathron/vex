"""Tests for Shodan secondary enricher plugin.

All tests are offline — no real network calls are made.
httpx transport is mocked throughout.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import httpx

from vex.config import Config, EnrichmentConfig
from vex.enrichers.protocol import SecondaryEnricherProtocol
from vex.models import InvestigateResult, TriageResult, Verdict, DetectionStats
from vex.plugins.shodan import ShodanPlugin
from vex.plugins.loader import load_plugins


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_investigate_result(ioc: str = "1.2.3.4", ioc_type: str = "ipv4") -> InvestigateResult:
    """Build a minimal InvestigateResult with required nested TriageResult."""
    triage = TriageResult(
        ioc=ioc,
        ioc_type=ioc_type,
        verdict=Verdict.UNKNOWN,
        detection_stats=DetectionStats(),
    )
    return InvestigateResult(triage=triage)


def _config_with_key(key: str = "test-shodan-key-0000") -> Config:
    cfg = Config()
    cfg.enrichment = EnrichmentConfig(shodan_api_key=key)
    return cfg


def _config_no_key() -> Config:
    cfg = Config()
    cfg.enrichment = EnrichmentConfig(shodan_api_key=None)
    return cfg


_SAMPLE_PAYLOAD = {
    "ip_str": "1.2.3.4",
    "ports": [22, 80, 443],
    "hostnames": ["host.example.com", "mail.example.com"],
    "org": "Example Org Ltd",
    "tags": ["cdn", "self-signed"],
}


# ---------------------------------------------------------------------------
# Protocol compliance
# ---------------------------------------------------------------------------

class TestShodanProtocol:
    def test_implements_secondary_enricher_protocol(self):
        plugin = ShodanPlugin()
        assert isinstance(plugin, SecondaryEnricherProtocol)

    def test_name(self):
        assert ShodanPlugin().name == "Shodan"

    def test_supported_ioc_types_contains_ip(self):
        types = ShodanPlugin().supported_ioc_types
        assert "ipv4" in types
        assert "ipv6" in types

    def test_supported_ioc_types_excludes_non_ip(self):
        types = ShodanPlugin().supported_ioc_types
        assert "md5" not in types
        assert "domain" not in types
        assert "url" not in types
        assert "sha256" not in types


# ---------------------------------------------------------------------------
# No-key path: no network calls, no-op
# ---------------------------------------------------------------------------

class TestNoKeyPath:
    def test_no_key_returns_immediately_no_network(self, monkeypatch):
        """With no API key, enrich must not make any network call and fields stay defaults."""
        plugin = ShodanPlugin()
        result = _make_investigate_result()
        config = _config_no_key()

        get_calls = []
        monkeypatch.setattr(httpx, "get", lambda *a, **kw: get_calls.append((a, kw)) or None)

        plugin.enrich(result, "1.2.3.4", "ipv4", config)

        assert len(get_calls) == 0
        assert result.shodan_ports == []
        assert result.shodan_hostnames == []
        assert result.shodan_org is None
        assert result.shodan_tags == []

    def test_env_var_not_set_no_key_in_config(self, monkeypatch):
        """Both env and config key absent → no-op, zero network calls."""
        monkeypatch.delenv("VEX_SHODAN_API_KEY", raising=False)
        plugin = ShodanPlugin()
        result = _make_investigate_result()
        config = _config_no_key()

        called = []
        monkeypatch.setattr(httpx, "get", lambda *a, **kw: called.append(1))

        plugin.enrich(result, "1.2.3.4", "ipv4", config)

        assert len(called) == 0
        assert result.shodan_org is None


# ---------------------------------------------------------------------------
# Happy path: 200 response, fields populated
# ---------------------------------------------------------------------------

class TestHappyPath:
    def test_200_populates_all_fields(self, monkeypatch):
        """A 200 response with full payload populates all four shodan fields."""
        plugin = ShodanPlugin()
        result = _make_investigate_result()
        config = _config_with_key()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = _SAMPLE_PAYLOAD

        monkeypatch.setattr(httpx, "get", lambda *a, **kw: mock_response)

        plugin.enrich(result, "1.2.3.4", "ipv4", config)

        assert result.shodan_ports == [22, 80, 443]
        assert result.shodan_hostnames == ["host.example.com", "mail.example.com"]
        assert result.shodan_org == "Example Org Ltd"
        assert result.shodan_tags == ["cdn", "self-signed"]

    def test_200_missing_optional_fields_use_defaults(self, monkeypatch):
        """A 200 response with only ports populated leaves other fields as defaults."""
        plugin = ShodanPlugin()
        result = _make_investigate_result()
        config = _config_with_key()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"ip_str": "1.2.3.4", "ports": [8080]}

        monkeypatch.setattr(httpx, "get", lambda *a, **kw: mock_response)

        plugin.enrich(result, "1.2.3.4", "ipv4", config)

        assert result.shodan_ports == [8080]
        assert result.shodan_hostnames == []
        assert result.shodan_org is None
        assert result.shodan_tags == []

    def test_200_uses_correct_url_and_params(self, monkeypatch):
        """Request must hit the Shodan host endpoint with the key param and 5s timeout."""
        plugin = ShodanPlugin()
        result = _make_investigate_result()
        config = _config_with_key("my-shodan-key-9876")

        captured: dict = {}

        def fake_get(url, *, params=None, timeout=None, **kw):
            captured["url"] = url
            captured["params"] = params
            captured["timeout"] = timeout
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = _SAMPLE_PAYLOAD
            return mock_response

        monkeypatch.setattr(httpx, "get", fake_get)
        plugin.enrich(result, "1.2.3.4", "ipv4", config)

        assert "shodan.io" in captured["url"]
        assert "1.2.3.4" in captured["url"]
        assert captured["params"]["key"] == "my-shodan-key-9876"
        assert captured["timeout"] == 5.0

    def test_ipv6_ioc_uses_ioc_in_url(self, monkeypatch):
        """IPv6 IOCs must also hit the Shodan API with the correct address in URL."""
        plugin = ShodanPlugin()
        ipv6_addr = "2001:db8::1"
        result = _make_investigate_result(ioc=ipv6_addr, ioc_type="ipv6")
        config = _config_with_key()

        captured: dict = {}

        def fake_get(url, *, params=None, timeout=None, **kw):
            captured["url"] = url
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"ports": [443]}
            return mock_response

        monkeypatch.setattr(httpx, "get", fake_get)
        plugin.enrich(result, ipv6_addr, "ipv6", config)

        assert ipv6_addr in captured["url"]


# ---------------------------------------------------------------------------
# Fail-open: errors and non-200 responses
# ---------------------------------------------------------------------------

class TestFailOpen:
    def test_network_exception_does_not_raise(self, monkeypatch):
        """A network error must be swallowed — enrich must not raise."""
        plugin = ShodanPlugin()
        result = _make_investigate_result()
        config = _config_with_key()

        monkeypatch.setattr(
            httpx,
            "get",
            lambda *a, **kw: (_ for _ in ()).throw(httpx.ConnectError("connection refused")),
        )

        plugin.enrich(result, "1.2.3.4", "ipv4", config)

        assert result.shodan_ports == []
        assert result.shodan_org is None

    def test_timeout_exception_does_not_raise(self, monkeypatch):
        """A ReadTimeout must be swallowed."""
        plugin = ShodanPlugin()
        result = _make_investigate_result()
        config = _config_with_key()

        def raise_timeout(*a, **kw):
            raise httpx.ReadTimeout("timed out")

        monkeypatch.setattr(httpx, "get", raise_timeout)
        plugin.enrich(result, "1.2.3.4", "ipv4", config)

        assert result.shodan_org is None

    def test_non_200_response_fields_stay_defaults(self, monkeypatch):
        """Any non-200 response must leave all shodan fields as defaults."""
        plugin = ShodanPlugin()
        config = _config_with_key()

        for status_code in (400, 401, 403, 404, 429, 500):
            result = _make_investigate_result()
            mock_response = MagicMock()
            mock_response.status_code = status_code

            monkeypatch.setattr(httpx, "get", lambda *a, **kw: mock_response)
            plugin.enrich(result, "1.2.3.4", "ipv4", config)

            assert result.shodan_ports == [], f"Expected [] for HTTP {status_code}"
            assert result.shodan_org is None, f"Expected None for HTTP {status_code}"

    def test_malformed_json_does_not_raise(self, monkeypatch):
        """If JSON parsing raises, enrich must not propagate the exception."""
        plugin = ShodanPlugin()
        result = _make_investigate_result()
        config = _config_with_key()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError("bad json")

        monkeypatch.setattr(httpx, "get", lambda *a, **kw: mock_response)
        plugin.enrich(result, "1.2.3.4", "ipv4", config)

        assert result.shodan_ports == []
        assert result.shodan_org is None

    def test_arbitrary_exception_does_not_raise(self, monkeypatch):
        """Any unexpected exception inside enrich must be silently swallowed."""
        plugin = ShodanPlugin()
        result = _make_investigate_result()
        config = _config_with_key()

        def raise_random(*a, **kw):
            raise RuntimeError("unexpected")

        monkeypatch.setattr(httpx, "get", raise_random)
        plugin.enrich(result, "1.2.3.4", "ipv4", config)

        assert result.shodan_ports == []


# ---------------------------------------------------------------------------
# Registry integration
# ---------------------------------------------------------------------------

class TestRegistryIntegration:
    def test_get_secondary_ipv4_includes_shodan(self):
        """load_plugins() registry must include Shodan for ipv4."""
        registry = load_plugins()
        secondaries = registry.get_secondary("ipv4")
        names = [s.name for s in secondaries]
        assert "Shodan" in names

    def test_get_secondary_ipv6_includes_shodan(self):
        """load_plugins() registry must include Shodan for ipv6."""
        registry = load_plugins()
        secondaries = registry.get_secondary("ipv6")
        names = [s.name for s in secondaries]
        assert "Shodan" in names

    def test_get_secondary_md5_excludes_shodan(self):
        """Shodan must not appear for hash IOC types."""
        registry = load_plugins()
        secondaries = registry.get_secondary("md5")
        names = [s.name for s in secondaries]
        assert "Shodan" not in names

    def test_get_secondary_domain_excludes_shodan(self):
        """Shodan must not appear for domain IOC type."""
        registry = load_plugins()
        secondaries = registry.get_secondary("domain")
        names = [s.name for s in secondaries]
        assert "Shodan" not in names

    def test_abuseipdb_still_registered_alongside_shodan(self):
        """AbuseIPDB must remain in the registry after Shodan is added."""
        registry = load_plugins()
        secondaries = registry.get_secondary("ipv4")
        names = [s.name for s in secondaries]
        assert "AbuseIPDB" in names
        assert "Shodan" in names


# ---------------------------------------------------------------------------
# Config env-var override
# ---------------------------------------------------------------------------

class TestConfigEnvOverride:
    def test_env_var_beats_config_key(self, monkeypatch):
        """VEX_SHODAN_API_KEY env var must take precedence over config value."""
        monkeypatch.setenv("VEX_SHODAN_API_KEY", "env-key-override")
        config = _config_with_key("config-key-value")

        resolved_key = config.shodan_api_key
        assert resolved_key == "env-key-override"

    def test_config_key_used_when_env_absent(self, monkeypatch):
        """When env var is absent, config value is used."""
        monkeypatch.delenv("VEX_SHODAN_API_KEY", raising=False)
        config = _config_with_key("config-key-only")

        assert config.shodan_api_key == "config-key-only"

    def test_both_absent_returns_none(self, monkeypatch):
        """When both env and config key are absent, property returns None."""
        monkeypatch.delenv("VEX_SHODAN_API_KEY", raising=False)
        config = _config_no_key()

        assert config.shodan_api_key is None

    def test_enrich_uses_env_key_for_request(self, monkeypatch):
        """The env-overridden key must be used in the actual HTTP request."""
        monkeypatch.setenv("VEX_SHODAN_API_KEY", "env-key-used-in-request")
        config = _config_with_key("config-key-ignored")

        plugin = ShodanPlugin()
        result = _make_investigate_result()

        captured_params: dict = {}

        def fake_get(url, *, params=None, timeout=None, **kw):
            captured_params.update(params or {})
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = _SAMPLE_PAYLOAD
            return mock_response

        monkeypatch.setattr(httpx, "get", fake_get)
        plugin.enrich(result, "1.2.3.4", "ipv4", config)

        assert captured_params.get("key") == "env-key-used-in-request"
