"""Tests for OpenCTI secondary enricher plugin.

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
from vex.plugins.opencti import OpenCTIEnricher

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_result(ioc: str = "evil.com", ioc_type: str = "domain") -> InvestigateResult:
    """Build a minimal InvestigateResult with required nested TriageResult."""
    triage = TriageResult(
        ioc=ioc,
        ioc_type=ioc_type,
        verdict=Verdict.UNKNOWN,
        detection_stats=DetectionStats(),
    )
    return InvestigateResult(triage=triage)


def _config_with_creds(
    url: str = "https://opencti.example.com",
    token: str = "test-opencti-token-0000",
    verify_tls: bool = True,
) -> Config:
    cfg = Config()
    cfg.enrichment = EnrichmentConfig(opencti_url=url, opencti_token=token, opencti_verify_tls=verify_tls)
    return cfg


def _config_no_url() -> Config:
    cfg = Config()
    cfg.enrichment = EnrichmentConfig(opencti_url=None, opencti_token="some-token")
    return cfg


def _config_no_token() -> Config:
    cfg = Config()
    cfg.enrichment = EnrichmentConfig(opencti_url="https://opencti.example.com", opencti_token=None)
    return cfg


def _config_no_creds() -> Config:
    cfg = Config()
    cfg.enrichment = EnrichmentConfig(opencti_url=None, opencti_token=None)
    return cfg


# Realistic OpenCTI GraphQL response with a found observable
_SAMPLE_RESPONSE = {
    "data": {
        "stixCyberObservables": {
            "edges": [
                {
                    "node": {
                        "id": "observable--aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                        "observable_value": "evil.com",
                        "objectLabel": [
                            {"value": "malicious"},
                            {"value": "c2"},
                        ],
                        "objectMarking": [
                            {"definition": "TLP:AMBER"},
                        ],
                        "indicators": {
                            "edges": [
                                {"node": {"x_opencti_score": 80}},
                            ]
                        },
                    }
                }
            ]
        }
    }
}

# Response with no matching observables
_EMPTY_RESPONSE = {"data": {"stixCyberObservables": {"edges": []}}}


# ---------------------------------------------------------------------------
# Protocol compliance
# ---------------------------------------------------------------------------


class TestOpenCTIProtocol:
    def test_implements_secondary_enricher_protocol(self):
        assert isinstance(OpenCTIEnricher(), SecondaryEnricherProtocol)

    def test_name(self):
        assert OpenCTIEnricher().name == "OpenCTI"

    def test_supported_ioc_types_contains_all_required(self):
        types = OpenCTIEnricher().supported_ioc_types
        for expected in ["md5", "sha1", "sha256", "ipv4", "ipv6", "domain", "url"]:
            assert expected in types, f"Expected '{expected}' in supported_ioc_types"

    def test_supported_ioc_types_all_seven(self):
        assert len(OpenCTIEnricher().supported_ioc_types) == 7


# ---------------------------------------------------------------------------
# No-config path: no network calls, no-op
# ---------------------------------------------------------------------------


class TestNoConfigPath:
    def test_no_url_returns_immediately_no_network(self, monkeypatch):
        """With no OpenCTI URL, enrich must not make any network call."""
        enricher = OpenCTIEnricher()
        result = _make_result()
        config = _config_no_url()

        post_calls = []
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: post_calls.append((a, kw)) or None)

        enricher.enrich(result, "evil.com", "domain", config)

        assert len(post_calls) == 0
        assert result.opencti_known is False

    def test_no_token_returns_immediately_no_network(self, monkeypatch):
        """With no API token, enrich must not make any network call."""
        enricher = OpenCTIEnricher()
        result = _make_result()
        config = _config_no_token()

        post_calls = []
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: post_calls.append((a, kw)) or None)

        enricher.enrich(result, "evil.com", "domain", config)

        assert len(post_calls) == 0
        assert result.opencti_known is False

    def test_no_creds_zero_network_calls(self, monkeypatch):
        """Neither URL nor token → absolute zero network calls."""
        enricher = OpenCTIEnricher()
        result = _make_result()
        config = _config_no_creds()

        called = []
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: called.append(1))

        enricher.enrich(result, "evil.com", "domain", config)

        assert len(called) == 0

    def test_no_creds_fields_stay_default(self, monkeypatch):
        """All OpenCTI fields stay at defaults when no credentials configured."""
        enricher = OpenCTIEnricher()
        result = _make_result()
        config = _config_no_creds()
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: None)

        enricher.enrich(result, "evil.com", "domain", config)

        assert result.opencti_known is False
        assert result.opencti_id is None
        assert result.opencti_score is None
        assert result.opencti_labels == []
        assert result.opencti_tlp is None


# ---------------------------------------------------------------------------
# Happy path: 200 with a matching observable → all fields populated
# ---------------------------------------------------------------------------


class TestHappyPath:
    def test_200_sets_opencti_known_true(self, monkeypatch):
        enricher = OpenCTIEnricher()
        result = _make_result()
        config = _config_with_creds()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _SAMPLE_RESPONSE
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: mock_resp)

        enricher.enrich(result, "evil.com", "domain", config)

        assert result.opencti_known is True

    def test_200_populates_id(self, monkeypatch):
        enricher = OpenCTIEnricher()
        result = _make_result()
        config = _config_with_creds()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _SAMPLE_RESPONSE
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: mock_resp)

        enricher.enrich(result, "evil.com", "domain", config)

        assert result.opencti_id == "observable--aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

    def test_200_populates_labels(self, monkeypatch):
        enricher = OpenCTIEnricher()
        result = _make_result()
        config = _config_with_creds()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _SAMPLE_RESPONSE
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: mock_resp)

        enricher.enrich(result, "evil.com", "domain", config)

        assert "malicious" in result.opencti_labels
        assert "c2" in result.opencti_labels

    def test_200_populates_tlp(self, monkeypatch):
        enricher = OpenCTIEnricher()
        result = _make_result()
        config = _config_with_creds()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _SAMPLE_RESPONSE
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: mock_resp)

        enricher.enrich(result, "evil.com", "domain", config)

        assert result.opencti_tlp == "AMBER"

    def test_200_populates_score(self, monkeypatch):
        enricher = OpenCTIEnricher()
        result = _make_result()
        config = _config_with_creds()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _SAMPLE_RESPONSE
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: mock_resp)

        enricher.enrich(result, "evil.com", "domain", config)

        assert result.opencti_score == 80

    def test_200_uses_correct_url_headers_and_body(self, monkeypatch):
        """Request must use /graphql endpoint, Bearer token, and correct GraphQL body."""
        enricher = OpenCTIEnricher()
        result = _make_result()
        config = _config_with_creds(url="https://opencti.corp.example", token="my-secret-token")

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
        enricher.enrich(result, "evil.com", "domain", config)

        assert captured["url"].endswith("/graphql")
        assert "opencti.corp.example" in captured["url"]
        assert captured["headers"]["Authorization"] == "Bearer my-secret-token"
        assert captured["headers"]["Content-Type"] == "application/json"
        assert captured["json"]["variables"]["value"] == "evil.com"
        assert "stixCyberObservables" in captured["json"]["query"]
        assert captured["timeout"] == 8.0

    def test_token_not_in_debug_logs(self, monkeypatch, caplog):
        """The API token must never appear in log output."""
        import logging

        enricher = OpenCTIEnricher()
        result = _make_result()
        secret_token = "super-secret-token-abc123"
        config = _config_with_creds(token=secret_token)

        def raise_connect_error(*a, **kw):
            raise httpx.ConnectError("refused")

        monkeypatch.setattr(httpx, "post", raise_connect_error)

        with caplog.at_level(logging.DEBUG, logger="vex.plugins.opencti"):
            enricher.enrich(result, "evil.com", "domain", config)

        for record in caplog.records:
            assert secret_token not in record.getMessage()


# ---------------------------------------------------------------------------
# Not found: empty edges list → opencti_known stays False
# ---------------------------------------------------------------------------


class TestNotFound:
    def test_empty_edges_known_stays_false(self, monkeypatch):
        enricher = OpenCTIEnricher()
        result = _make_result()
        config = _config_with_creds()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _EMPTY_RESPONSE
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: mock_resp)

        enricher.enrich(result, "evil.com", "domain", config)

        assert result.opencti_known is False
        assert result.opencti_id is None
        assert result.opencti_score is None
        assert result.opencti_labels == []
        assert result.opencti_tlp is None

    def test_missing_data_key_known_stays_false(self, monkeypatch):
        enricher = OpenCTIEnricher()
        result = _make_result()
        config = _config_with_creds()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {}
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: mock_resp)

        enricher.enrich(result, "evil.com", "domain", config)

        assert result.opencti_known is False

    def test_missing_stixcyberobservables_key_known_stays_false(self, monkeypatch):
        enricher = OpenCTIEnricher()
        result = _make_result()
        config = _config_with_creds()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": {}}
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: mock_resp)

        enricher.enrich(result, "evil.com", "domain", config)

        assert result.opencti_known is False


# ---------------------------------------------------------------------------
# Fail-open: errors, non-200, bad JSON, unexpected shape
# ---------------------------------------------------------------------------


class TestFailOpen:
    def test_connect_error_does_not_raise(self, monkeypatch):
        enricher = OpenCTIEnricher()
        result = _make_result()
        config = _config_with_creds()

        monkeypatch.setattr(
            httpx,
            "post",
            lambda *a, **kw: (_ for _ in ()).throw(httpx.ConnectError("refused")),
        )

        enricher.enrich(result, "evil.com", "domain", config)

        assert result.opencti_known is False

    def test_timeout_does_not_raise(self, monkeypatch):
        enricher = OpenCTIEnricher()
        result = _make_result()
        config = _config_with_creds()

        def raise_timeout(*a, **kw):
            raise httpx.ReadTimeout("timed out")

        monkeypatch.setattr(httpx, "post", raise_timeout)
        enricher.enrich(result, "evil.com", "domain", config)

        assert result.opencti_known is False

    def test_non_200_response_does_not_raise(self, monkeypatch):
        enricher = OpenCTIEnricher()
        config = _config_with_creds()

        for status_code in (400, 401, 403, 429, 500):
            result = _make_result()
            mock_resp = MagicMock()
            mock_resp.status_code = status_code
            monkeypatch.setattr(httpx, "post", lambda *a, **kw: mock_resp)

            enricher.enrich(result, "evil.com", "domain", config)

            assert result.opencti_known is False, f"Expected False for HTTP {status_code}"

    def test_bad_json_does_not_raise(self, monkeypatch):
        enricher = OpenCTIEnricher()
        result = _make_result()
        config = _config_with_creds()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.side_effect = ValueError("bad json")
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: mock_resp)

        enricher.enrich(result, "evil.com", "domain", config)

        assert result.opencti_known is False

    def test_unexpected_shape_does_not_raise(self, monkeypatch):
        """Completely unexpected response body must not raise (schema tolerance)."""
        enricher = OpenCTIEnricher()
        result = _make_result()
        config = _config_with_creds()

        # Return a list instead of dict — completely wrong shape
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [{"unexpected": "shape"}]
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: mock_resp)

        enricher.enrich(result, "evil.com", "domain", config)

        assert result.opencti_known is False

    def test_node_missing_fields_does_not_raise(self, monkeypatch):
        """A node with no optional fields must not raise — defensive .get() everywhere."""
        enricher = OpenCTIEnricher()
        result = _make_result()
        config = _config_with_creds()

        sparse_response = {"data": {"stixCyberObservables": {"edges": [{"node": {"id": "observable--sparse"}}]}}}

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = sparse_response
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: mock_resp)

        enricher.enrich(result, "evil.com", "domain", config)

        assert result.opencti_known is True
        assert result.opencti_id == "observable--sparse"
        assert result.opencti_labels == []
        assert result.opencti_tlp is None
        assert result.opencti_score is None

    def test_generic_exception_does_not_raise(self, monkeypatch):
        enricher = OpenCTIEnricher()
        result = _make_result()
        config = _config_with_creds()

        def raise_generic(*a, **kw):
            raise RuntimeError("unexpected error")

        monkeypatch.setattr(httpx, "post", raise_generic)
        enricher.enrich(result, "evil.com", "domain", config)

        assert result.opencti_known is False


# ---------------------------------------------------------------------------
# TLP precedence
# ---------------------------------------------------------------------------


class TestTLPPrecedence:
    def _response_with_markings(self, *definitions: str) -> dict:
        return {
            "data": {
                "stixCyberObservables": {
                    "edges": [
                        {
                            "node": {
                                "id": "observable--test",
                                "observable_value": "evil.com",
                                "objectLabel": [],
                                "objectMarking": [{"definition": d} for d in definitions],
                                "indicators": {"edges": []},
                            }
                        }
                    ]
                }
            }
        }

    def test_red_beats_amber(self, monkeypatch):
        enricher = OpenCTIEnricher()
        result = _make_result()
        config = _config_with_creds()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = self._response_with_markings("TLP:AMBER", "TLP:RED")
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: mock_resp)

        enricher.enrich(result, "evil.com", "domain", config)

        assert result.opencti_tlp == "RED"

    def test_amber_beats_green(self, monkeypatch):
        enricher = OpenCTIEnricher()
        result = _make_result()
        config = _config_with_creds()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = self._response_with_markings("TLP:GREEN", "TLP:AMBER")
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: mock_resp)

        enricher.enrich(result, "evil.com", "domain", config)

        assert result.opencti_tlp == "AMBER"

    def test_green_beats_clear(self, monkeypatch):
        enricher = OpenCTIEnricher()
        result = _make_result()
        config = _config_with_creds()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = self._response_with_markings("TLP:CLEAR", "TLP:GREEN")
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: mock_resp)

        enricher.enrich(result, "evil.com", "domain", config)

        assert result.opencti_tlp == "GREEN"

    def test_clear_and_white_equivalent(self, monkeypatch):
        enricher = OpenCTIEnricher()
        result = _make_result()
        config = _config_with_creds()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = self._response_with_markings("TLP:WHITE", "TLP:CLEAR")
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: mock_resp)

        enricher.enrich(result, "evil.com", "domain", config)

        assert result.opencti_tlp in ("WHITE", "CLEAR")

    def test_no_tlp_marking_returns_none(self, monkeypatch):
        enricher = OpenCTIEnricher()
        result = _make_result()
        config = _config_with_creds()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = self._response_with_markings("PAP:WHITE")
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: mock_resp)

        enricher.enrich(result, "evil.com", "domain", config)

        assert result.opencti_tlp is None

    def test_red_beats_all(self, monkeypatch):
        enricher = OpenCTIEnricher()
        result = _make_result()
        config = _config_with_creds()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = self._response_with_markings(
            "TLP:WHITE", "TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:RED"
        )
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: mock_resp)

        enricher.enrich(result, "evil.com", "domain", config)

        assert result.opencti_tlp == "RED"


# ---------------------------------------------------------------------------
# verify flag
# ---------------------------------------------------------------------------


class TestVerifyFlag:
    def test_verify_true_passed_to_httpx(self, monkeypatch):
        enricher = OpenCTIEnricher()
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
        enricher.enrich(result, "evil.com", "domain", config)

        assert captured["verify"] is True

    def test_verify_false_passed_to_httpx(self, monkeypatch):
        enricher = OpenCTIEnricher()
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
        enricher.enrich(result, "evil.com", "domain", config)

        assert captured["verify"] is False


# ---------------------------------------------------------------------------
# Registry integration
# ---------------------------------------------------------------------------


class TestRegistryIntegration:
    def test_get_secondary_ipv4_includes_opencti(self):
        registry = load_plugins()
        names = [s.name for s in registry.get_secondary("ipv4")]
        assert "OpenCTI" in names

    def test_get_secondary_md5_includes_opencti(self):
        registry = load_plugins()
        names = [s.name for s in registry.get_secondary("md5")]
        assert "OpenCTI" in names

    def test_get_secondary_sha256_includes_opencti(self):
        registry = load_plugins()
        names = [s.name for s in registry.get_secondary("sha256")]
        assert "OpenCTI" in names

    def test_get_secondary_domain_includes_opencti(self):
        registry = load_plugins()
        names = [s.name for s in registry.get_secondary("domain")]
        assert "OpenCTI" in names

    def test_get_secondary_url_includes_opencti(self):
        registry = load_plugins()
        names = [s.name for s in registry.get_secondary("url")]
        assert "OpenCTI" in names

    def test_get_secondary_sha1_includes_opencti(self):
        registry = load_plugins()
        names = [s.name for s in registry.get_secondary("sha1")]
        assert "OpenCTI" in names

    def test_get_secondary_ipv6_includes_opencti(self):
        registry = load_plugins()
        names = [s.name for s in registry.get_secondary("ipv6")]
        assert "OpenCTI" in names


# ---------------------------------------------------------------------------
# All IOC types handled (no crash for any of the 7 types)
# ---------------------------------------------------------------------------


class TestAllIOCTypes:
    def test_all_seven_ioc_types_no_error(self, monkeypatch):
        """enrich must not raise for any of the 7 supported IOC types."""
        enricher = OpenCTIEnricher()
        config = _config_with_creds()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _EMPTY_RESPONSE
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: mock_resp)

        ioc_type_samples = [
            ("1.2.3.4", "ipv4"),
            ("2001:db8::1", "ipv6"),
            ("evil.com", "domain"),
            ("http://evil.com/malware", "url"),
            ("44d88612fea8a8f36de82e1278abb02f", "md5"),
            ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1"),
            ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256"),
        ]

        for ioc, ioc_type in ioc_type_samples:
            result = _make_result(ioc=ioc, ioc_type=ioc_type)
            enricher.enrich(result, ioc, ioc_type, config)  # must not raise
            assert result.opencti_known is False  # no match in empty response


# ---------------------------------------------------------------------------
# Config env-var override
# ---------------------------------------------------------------------------


class TestConfigEnvOverride:
    def test_opencti_url_env_beats_config(self, monkeypatch):
        monkeypatch.setenv("OPENCTI_URL", "https://env-opencti.example.com")
        config = _config_with_creds(url="https://config-opencti.example.com")

        assert config.opencti_url == "https://env-opencti.example.com"

    def test_opencti_token_env_beats_config(self, monkeypatch):
        monkeypatch.setenv("OPENCTI_TOKEN", "env-token-override")
        config = _config_with_creds(token="config-token-value")

        assert config.opencti_token == "env-token-override"

    def test_config_url_used_when_env_absent(self, monkeypatch):
        monkeypatch.delenv("OPENCTI_URL", raising=False)
        config = _config_with_creds(url="https://config-only.example.com")

        assert config.opencti_url == "https://config-only.example.com"

    def test_config_token_used_when_env_absent(self, monkeypatch):
        monkeypatch.delenv("OPENCTI_TOKEN", raising=False)
        config = _config_with_creds(token="config-token-only")

        assert config.opencti_token == "config-token-only"

    def test_both_absent_returns_none(self, monkeypatch):
        monkeypatch.delenv("OPENCTI_URL", raising=False)
        monkeypatch.delenv("OPENCTI_TOKEN", raising=False)
        config = _config_no_creds()

        assert config.opencti_url is None
        assert config.opencti_token is None

    def test_env_token_used_in_request(self, monkeypatch):
        """The env-overridden token must be sent in the Authorization header."""
        monkeypatch.setenv("OPENCTI_TOKEN", "env-token-in-request")
        monkeypatch.delenv("OPENCTI_URL", raising=False)
        # Set URL via config, token via env
        config = Config()
        config.enrichment = EnrichmentConfig(
            opencti_url="https://opencti.example.com",
            opencti_token="config-token-ignored",
        )

        enricher = OpenCTIEnricher()
        result = _make_result()
        captured: dict = {}

        def fake_post(url, *, json=None, headers=None, timeout=None, verify=None):
            captured["headers"] = headers or {}
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = _EMPTY_RESPONSE
            return mock_resp

        monkeypatch.setattr(httpx, "post", fake_post)
        enricher.enrich(result, "evil.com", "domain", config)

        assert captured["headers"].get("Authorization") == "Bearer env-token-in-request"

    def test_env_url_used_in_request(self, monkeypatch):
        """The env-overridden URL must be used to build the request URL."""
        monkeypatch.setenv("OPENCTI_URL", "https://env-opencti.example.com")
        monkeypatch.delenv("OPENCTI_TOKEN", raising=False)
        config = Config()
        config.enrichment = EnrichmentConfig(
            opencti_url="https://config-ignored.example.com",
            opencti_token="some-token",
        )

        enricher = OpenCTIEnricher()
        result = _make_result()
        captured: dict = {}

        def fake_post(url, *, json=None, headers=None, timeout=None, verify=None):
            captured["url"] = url
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = _EMPTY_RESPONSE
            return mock_resp

        monkeypatch.setattr(httpx, "post", fake_post)
        enricher.enrich(result, "evil.com", "domain", config)

        assert "env-opencti.example.com" in captured["url"]


# ---------------------------------------------------------------------------
# Write-back: add_observable
# ---------------------------------------------------------------------------


class TestOpenCTIAddObservable:
    """Tests for OpenCTIEnricher.add_observable()."""

    def _config_with_writeback(
        self,
        writeback_tlp: str = "green",
        writeback_enabled: bool = True,
    ) -> Config:
        cfg = Config()
        cfg.enrichment = EnrichmentConfig(
            opencti_url="https://opencti.example.com",
            opencti_token="test-token",
            opencti_verify_tls=True,
            writeback_enabled=writeback_enabled,
            writeback_tlp=writeback_tlp,
        )
        return cfg

    def _success_response(self, obs_id: str = "observable--new-12345") -> dict:
        return {"data": {"stixCyberObservableAdd": {"id": obs_id}}}

    def test_success_200_valid_body_returns_true(self, monkeypatch):
        enricher = OpenCTIEnricher()
        config = self._config_with_writeback()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = self._success_response()
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: mock_resp)
        result = enricher.add_observable("evil.com", "domain", config)
        assert result is True

    def test_graphql_errors_in_body_returns_false(self, monkeypatch):
        enricher = OpenCTIEnricher()
        config = self._config_with_writeback()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"errors": [{"message": "access denied"}], "data": None}
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: mock_resp)
        result = enricher.add_observable("evil.com", "domain", config)
        assert result is False

    def test_unknown_ioc_type_returns_false_no_network(self, monkeypatch):
        enricher = OpenCTIEnricher()
        config = self._config_with_writeback()
        called = []
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: called.append(1))
        result = enricher.add_observable("something", "certificate", config)
        assert result is False
        assert len(called) == 0

    def test_no_url_no_network_returns_false(self, monkeypatch):
        enricher = OpenCTIEnricher()
        cfg = Config()
        cfg.enrichment = EnrichmentConfig(opencti_url=None, opencti_token="tok")
        called = []
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: called.append(1))
        result = enricher.add_observable("evil.com", "domain", cfg)
        assert result is False
        assert len(called) == 0

    def test_no_token_no_network_returns_false(self, monkeypatch):
        enricher = OpenCTIEnricher()
        cfg = Config()
        cfg.enrichment = EnrichmentConfig(opencti_url="https://opencti.example.com", opencti_token=None)
        called = []
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: called.append(1))
        result = enricher.add_observable("evil.com", "domain", cfg)
        assert result is False
        assert len(called) == 0

    def test_exception_fail_open_returns_false(self, monkeypatch):
        enricher = OpenCTIEnricher()
        config = self._config_with_writeback()

        def raise_err(*a, **kw):
            raise RuntimeError("network error")

        monkeypatch.setattr(httpx, "post", raise_err)
        result = enricher.add_observable("evil.com", "domain", config)
        assert result is False

    def test_marking_check_source_stricter_skips_no_post(self, monkeypatch):
        """source_tlp=red more restrictive than writeback_tlp=green → skip."""
        enricher = OpenCTIEnricher()
        config = self._config_with_writeback(writeback_tlp="green")
        called = []
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: called.append(1))
        result = enricher.add_observable("evil.com", "domain", config, source_tlp="red")
        assert result is False
        assert len(called) == 0

    def test_marking_check_source_same_as_ceiling_allows(self, monkeypatch):
        """source_tlp=green == writeback_tlp=green → allow."""
        enricher = OpenCTIEnricher()
        config = self._config_with_writeback(writeback_tlp="green")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = self._success_response()
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: mock_resp)
        result = enricher.add_observable("evil.com", "domain", config, source_tlp="green")
        assert result is True

    def test_type_mapping_domain_uses_domain_name(self, monkeypatch):
        """domain IOC type → 'Domain-Name' in GraphQL variables."""
        enricher = OpenCTIEnricher()
        config = self._config_with_writeback()
        captured: dict = {}

        def fake_post(url, *, json=None, headers=None, timeout=None, verify=None):
            captured["json"] = json
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {"data": {"stixCyberObservableAdd": {"id": "x"}}}
            return mock_resp

        monkeypatch.setattr(httpx, "post", fake_post)
        enricher.add_observable("evil.com", "domain", config)
        assert captured["json"]["variables"]["type"] == "Domain-Name"
        assert captured["json"]["variables"]["value"] == "evil.com"

    def test_type_mapping_ipv4_uses_ipv4_addr(self, monkeypatch):
        enricher = OpenCTIEnricher()
        config = self._config_with_writeback()
        captured: dict = {}

        def fake_post(url, *, json=None, headers=None, timeout=None, verify=None):
            captured["json"] = json
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {"data": {"stixCyberObservableAdd": {"id": "x"}}}
            return mock_resp

        monkeypatch.setattr(httpx, "post", fake_post)
        enricher.add_observable("1.2.3.4", "ipv4", config)
        assert captured["json"]["variables"]["type"] == "IPv4-Addr"

    def test_type_mapping_sha256_uses_stixfile(self, monkeypatch):
        enricher = OpenCTIEnricher()
        config = self._config_with_writeback()
        captured: dict = {}

        def fake_post(url, *, json=None, headers=None, timeout=None, verify=None):
            captured["json"] = json
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {"data": {"stixCyberObservableAdd": {"id": "x"}}}
            return mock_resp

        monkeypatch.setattr(httpx, "post", fake_post)
        enricher.add_observable(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256", config
        )
        assert captured["json"]["variables"]["type"] == "StixFile"

    def test_missing_id_in_response_returns_false(self, monkeypatch):
        """Response with data.stixCyberObservableAdd but no id → False."""
        enricher = OpenCTIEnricher()
        config = self._config_with_writeback()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": {"stixCyberObservableAdd": {}}}
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: mock_resp)
        result = enricher.add_observable("evil.com", "domain", config)
        assert result is False

    def test_correct_graphql_endpoint(self, monkeypatch):
        """Must POST to /graphql."""
        enricher = OpenCTIEnricher()
        config = self._config_with_writeback()
        captured: dict = {}

        def fake_post(url, *, json=None, headers=None, timeout=None, verify=None):
            captured["url"] = url
            captured["headers"] = headers
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {"data": {"stixCyberObservableAdd": {"id": "x"}}}
            return mock_resp

        monkeypatch.setattr(httpx, "post", fake_post)
        enricher.add_observable("evil.com", "domain", config)
        assert captured["url"].endswith("/graphql")
        assert captured["headers"]["Authorization"] == "Bearer test-token"
        assert captured["headers"]["Content-Type"] == "application/json"
