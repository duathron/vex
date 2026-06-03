"""Tests for vex.doctor — service config/connectivity diagnostics.

No real network is performed: all probe paths patch ``vex.doctor.httpx`` and
the Ollama provider's ``is_available``. Verifies config-only mode, defensive
probe handling (no crash on unreachable), and that secrets never leak into any
detail string.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from vex.config import Config
from vex.doctor import ServiceStatus, run_doctor

# Secrets used across tests — asserted to never appear in any detail.
VT_KEY = "VTSECRET_vt_0001"
ABUSE_KEY = "ABUSESECRET_0002"
SHODAN_KEY = "SHODANSECRET_0003"
MISP_KEY = "MISPSECRET_0004"
OPENCTI_TOKEN = "OPENCTISECRET_0005"

ALL_SECRETS = [VT_KEY, ABUSE_KEY, SHODAN_KEY, MISP_KEY, OPENCTI_TOKEN]


def _full_config() -> Config:
    """Config with every service configured."""
    cfg = Config()
    cfg.api.key = VT_KEY
    cfg.ai.provider = "ollama"
    cfg.ai.local_only = True
    cfg.enrichment.abuseipdb_api_key = ABUSE_KEY
    cfg.enrichment.shodan_api_key = SHODAN_KEY
    cfg.enrichment.misp_url = "https://misp.example.com"
    cfg.enrichment.misp_api_key = MISP_KEY
    cfg.enrichment.opencti_url = "https://opencti.example.com"
    cfg.enrichment.opencti_token = OPENCTI_TOKEN
    return cfg


def _empty_config() -> Config:
    """Config with nothing configured."""
    return Config()  # ai.provider defaults to "none"


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    """Ensure env-var overrides never leak real credentials into tests."""
    for var in (
        "VT_API_KEY",
        "VEX_ABUSEIPDB_API_KEY",
        "VEX_SHODAN_API_KEY",
        "MISP_URL",
        "MISP_API_KEY",
        "OPENCTI_URL",
        "OPENCTI_TOKEN",
        "VEX_AI_API_KEY",
    ):
        monkeypatch.delenv(var, raising=False)


def _by_name(statuses: list[ServiceStatus]) -> dict[str, ServiceStatus]:
    return {s.name: s for s in statuses}


def _assert_no_secrets(statuses: list[ServiceStatus]) -> None:
    for s in statuses:
        for secret in ALL_SECRETS:
            assert secret not in s.detail, f"secret leaked in {s.name}: {s.detail}"


# ---------------------------------------------------------------------------
# Config-only mode (no network)
# ---------------------------------------------------------------------------


def test_config_only_all_configured():
    statuses = run_doctor(_full_config(), probe=False)
    by = _by_name(statuses)

    for name in ("VirusTotal", "AI provider", "AbuseIPDB", "Shodan", "MISP", "OpenCTI"):
        assert by[name].configured is True, name
        assert by[name].reachable is None, name

    _assert_no_secrets(statuses)


def test_config_only_none_configured():
    statuses = run_doctor(_empty_config(), probe=False)
    by = _by_name(statuses)

    for name in ("VirusTotal", "AI provider", "AbuseIPDB", "Shodan", "MISP", "OpenCTI"):
        assert by[name].configured is False, name
        assert by[name].reachable is None, name


def test_vt_missing_key_does_not_crash():
    # Empty config => config.api_key raises; doctor must handle it.
    statuses = run_doctor(_empty_config(), probe=False)
    vt = _by_name(statuses)["VirusTotal"]
    assert vt.configured is False
    assert vt.reachable is None


def test_misp_partial_config_not_configured():
    cfg = Config()
    cfg.enrichment.misp_url = "https://misp.example.com"
    # missing api_key
    statuses = run_doctor(cfg, probe=False)
    misp = _by_name(statuses)["MISP"]
    assert misp.configured is False
    assert "misp_api_key" in misp.detail


# ---------------------------------------------------------------------------
# Probe mode — MISP (mocked httpx)
# ---------------------------------------------------------------------------


def _mock_response(status_code: int, json_data) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data
    return resp


def test_probe_misp_reachable():
    cfg = _full_config()
    cfg.ai.provider = "none"  # isolate MISP path
    with patch("vex.doctor.httpx") as mock_httpx:
        mock_httpx.get.return_value = _mock_response(200, {"version": "2.4.180"})
        statuses = run_doctor(cfg, probe=True)
    misp = _by_name(statuses)["MISP"]
    assert misp.reachable is True
    assert "2.4.180" in misp.detail
    _assert_no_secrets(statuses)


def test_probe_misp_connect_error_no_raise():
    cfg = _full_config()
    cfg.ai.provider = "none"
    with patch("vex.doctor.httpx") as mock_httpx:
        mock_httpx.get.side_effect = httpx.ConnectError("connection refused")
        statuses = run_doctor(cfg, probe=True)  # must not raise
    misp = _by_name(statuses)["MISP"]
    assert misp.reachable is False
    assert "connection refused" in misp.detail
    _assert_no_secrets(statuses)


def test_probe_misp_non_200():
    cfg = _full_config()
    cfg.ai.provider = "none"
    with patch("vex.doctor.httpx") as mock_httpx:
        mock_httpx.get.return_value = _mock_response(403, {})
        statuses = run_doctor(cfg, probe=True)
    misp = _by_name(statuses)["MISP"]
    assert misp.reachable is False
    assert "403" in misp.detail
    _assert_no_secrets(statuses)


def test_probe_misp_sends_auth_header_with_key_but_key_not_in_detail():
    cfg = _full_config()
    cfg.ai.provider = "none"
    with patch("vex.doctor.httpx") as mock_httpx:
        mock_httpx.get.return_value = _mock_response(200, {"version": "2.4.0"})
        run_doctor(cfg, probe=True)
        # Key is used in the request header...
        _, kwargs = mock_httpx.get.call_args
        assert kwargs["headers"]["Authorization"] == MISP_KEY
        assert kwargs["verify"] is True


# ---------------------------------------------------------------------------
# Probe mode — OpenCTI (mocked httpx)
# ---------------------------------------------------------------------------


def test_probe_opencti_reachable():
    cfg = _full_config()
    cfg.ai.provider = "none"
    with patch("vex.doctor.httpx") as mock_httpx:
        mock_httpx.post.return_value = _mock_response(200, {"data": {"about": {"version": "6.2.1"}}})
        statuses = run_doctor(cfg, probe=True)
    octi = _by_name(statuses)["OpenCTI"]
    assert octi.reachable is True
    assert "6.2.1" in octi.detail
    _assert_no_secrets(statuses)


def test_probe_opencti_connect_error_no_raise():
    cfg = _full_config()
    cfg.ai.provider = "none"
    with patch("vex.doctor.httpx") as mock_httpx:
        mock_httpx.post.side_effect = httpx.ConnectError("name resolution failed")
        statuses = run_doctor(cfg, probe=True)
    octi = _by_name(statuses)["OpenCTI"]
    assert octi.reachable is False
    assert "name resolution failed" in octi.detail
    _assert_no_secrets(statuses)


def test_probe_opencti_non_200():
    cfg = _full_config()
    cfg.ai.provider = "none"
    with patch("vex.doctor.httpx") as mock_httpx:
        mock_httpx.post.return_value = _mock_response(401, {})
        statuses = run_doctor(cfg, probe=True)
    octi = _by_name(statuses)["OpenCTI"]
    assert octi.reachable is False
    assert "401" in octi.detail


def test_probe_opencti_uses_bearer_token_not_in_detail():
    cfg = _full_config()
    cfg.ai.provider = "none"
    with patch("vex.doctor.httpx") as mock_httpx:
        mock_httpx.post.return_value = _mock_response(200, {"data": {"about": {"version": "6.0"}}})
        run_doctor(cfg, probe=True)
        _, kwargs = mock_httpx.post.call_args
        assert kwargs["headers"]["Authorization"] == f"Bearer {OPENCTI_TOKEN}"
        assert kwargs["verify"] is True


# ---------------------------------------------------------------------------
# Probe mode — AI / Ollama (mocked is_available)
# ---------------------------------------------------------------------------


def test_probe_ollama_available():
    cfg = _full_config()  # ai.provider = ollama
    with patch("vex.ai.ollama.OllamaProvider.is_available", return_value=True):
        statuses = run_doctor(cfg, probe=True)
    ai = _by_name(statuses)["AI provider"]
    assert ai.reachable is True


def test_probe_ollama_unavailable_no_raise():
    cfg = _full_config()
    with patch("vex.ai.ollama.OllamaProvider.is_available", return_value=False):
        statuses = run_doctor(cfg, probe=True)
    ai = _by_name(statuses)["AI provider"]
    assert ai.reachable is False


def test_probe_cloud_ai_not_probed():
    cfg = _full_config()
    cfg.ai.provider = "anthropic"
    cfg.ai.local_only = False
    statuses = run_doctor(cfg, probe=True)  # no network call expected
    ai = _by_name(statuses)["AI provider"]
    assert ai.configured is True
    assert ai.reachable is None
    assert "not probed" in ai.detail


# ---------------------------------------------------------------------------
# Probe mode — quota-protected services not probed
# ---------------------------------------------------------------------------


def test_probe_abuseipdb_and_shodan_not_probed():
    cfg = _full_config()
    cfg.ai.provider = "none"
    with patch("vex.doctor.httpx") as mock_httpx:
        mock_httpx.get.return_value = _mock_response(200, {"version": "x"})
        statuses = run_doctor(cfg, probe=True)
    by = _by_name(statuses)
    assert by["AbuseIPDB"].reachable is None
    assert by["Shodan"].reachable is None
    assert by["AbuseIPDB"].configured is True
    assert by["Shodan"].configured is True


def test_secrets_never_in_any_detail_full_probe():
    cfg = _full_config()
    cfg.ai.provider = "ollama"
    with patch("vex.doctor.httpx") as mock_httpx, patch("vex.ai.ollama.OllamaProvider.is_available", return_value=True):
        mock_httpx.get.return_value = _mock_response(200, {"version": "2.4"})
        mock_httpx.post.return_value = _mock_response(200, {"data": {"about": {"version": "6.0"}}})
        statuses = run_doctor(cfg, probe=True)
    _assert_no_secrets(statuses)
