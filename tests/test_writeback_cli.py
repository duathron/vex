"""Tests for write-back CLI wiring (_run_writeback helper).

All tests are offline — no real network calls are made.
Writers (MISPEnricher.add_sighting, OpenCTIEnricher.add_observable) are
monkeypatched throughout.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from vex.config import Config, EnrichmentConfig
from vex.models import DetectionStats, InvestigateResult, TriageResult, Verdict


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_investigate_result(
    ioc: str = "1.2.3.4",
    ioc_type: str = "ipv4",
    verdict: Verdict = Verdict.MALICIOUS,
    misp_tlp: str | None = None,
    opencti_tlp: str | None = None,
) -> InvestigateResult:
    triage = TriageResult(
        ioc=ioc,
        ioc_type=ioc_type,
        verdict=verdict,
        detection_stats=DetectionStats(),
    )
    result = InvestigateResult(triage=triage)
    result.misp_tlp = misp_tlp
    result.opencti_tlp = opencti_tlp
    return result


def _config_writeback_enabled(
    writeback_tlp: str = "green",
    writeback_min_verdict: str = "SUSPICIOUS",
) -> Config:
    cfg = Config()
    cfg.enrichment = EnrichmentConfig(
        misp_url="https://misp.example.com",
        misp_api_key="test-misp-key",
        opencti_url="https://opencti.example.com",
        opencti_token="test-opencti-token",
        writeback_enabled=True,
        writeback_tlp=writeback_tlp,
        writeback_min_verdict=writeback_min_verdict,
    )
    return cfg


def _config_writeback_disabled() -> Config:
    cfg = Config()
    cfg.enrichment = EnrichmentConfig(
        misp_url="https://misp.example.com",
        misp_api_key="test-misp-key",
        writeback_enabled=False,
    )
    return cfg


# ---------------------------------------------------------------------------
# Import the helper under test
# ---------------------------------------------------------------------------


from vex.main import _run_writeback  # noqa: E402


# ---------------------------------------------------------------------------
# dry-run: no network calls, fields set to None
# ---------------------------------------------------------------------------


class TestDryRunWriteback:
    def test_dry_run_no_network_calls(self, monkeypatch):
        """--dry-run-sight must not call add_sighting or add_observable."""
        results = [_make_investigate_result(verdict=Verdict.MALICIOUS)]
        config = _config_writeback_enabled()

        sighting_calls = []
        observable_calls = []

        monkeypatch.setattr(
            "vex.plugins.misp.MISPEnricher.add_sighting",
            lambda self, *a, **kw: sighting_calls.append(1) or True,
        )
        monkeypatch.setattr(
            "vex.plugins.opencti.OpenCTIEnricher.add_observable",
            lambda self, *a, **kw: observable_calls.append(1) or True,
        )

        _run_writeback(results, config, sight=False, dry_run_sight=True)

        assert len(sighting_calls) == 0
        assert len(observable_calls) == 0

    def test_dry_run_sets_writeback_fields_none(self, monkeypatch):
        """--dry-run-sight must leave writeback fields as None (not attempted)."""
        result = _make_investigate_result(verdict=Verdict.MALICIOUS)
        config = _config_writeback_enabled()

        monkeypatch.setattr(
            "vex.plugins.misp.MISPEnricher.add_sighting",
            lambda self, *a, **kw: True,
        )
        monkeypatch.setattr(
            "vex.plugins.opencti.OpenCTIEnricher.add_observable",
            lambda self, *a, **kw: True,
        )

        _run_writeback([result], config, sight=False, dry_run_sight=True)

        assert result.writeback_misp is None
        assert result.writeback_opencti is None


# ---------------------------------------------------------------------------
# --sight without writeback_enabled: warning, no writes
# ---------------------------------------------------------------------------


class TestSightWithoutWritebackEnabled:
    def test_no_writes_when_disabled(self, monkeypatch):
        """--sight without writeback_enabled must print warning, make no writes."""
        result = _make_investigate_result(verdict=Verdict.MALICIOUS)
        config = _config_writeback_disabled()

        sighting_calls = []
        monkeypatch.setattr(
            "vex.plugins.misp.MISPEnricher.add_sighting",
            lambda self, *a, **kw: sighting_calls.append(1) or True,
        )

        _run_writeback([result], config, sight=True, dry_run_sight=False)

        assert len(sighting_calls) == 0
        # writeback fields stay None since nothing was attempted
        assert result.writeback_misp is None


# ---------------------------------------------------------------------------
# --sight with writeback_enabled: writes only above floor
# ---------------------------------------------------------------------------


class TestSightAboveFloor:
    def test_malicious_written_suspicious_written_clean_skipped(self, monkeypatch):
        """Floor=SUSPICIOUS: MALICIOUS written, SUSPICIOUS written, CLEAN skipped."""
        malicious_result = _make_investigate_result(ioc="1.2.3.4", verdict=Verdict.MALICIOUS)
        suspicious_result = _make_investigate_result(ioc="2.3.4.5", verdict=Verdict.SUSPICIOUS)
        clean_result = _make_investigate_result(ioc="8.8.8.8", verdict=Verdict.CLEAN)

        config = _config_writeback_enabled(writeback_min_verdict="SUSPICIOUS")

        sighting_calls: list[str] = []
        observable_calls: list[str] = []

        def fake_sighting(self, ioc, cfg, **kw):
            sighting_calls.append(ioc)
            return True

        def fake_observable(self, ioc, ioc_type, cfg, **kw):
            observable_calls.append(ioc)
            return True

        monkeypatch.setattr("vex.plugins.misp.MISPEnricher.add_sighting", fake_sighting)
        monkeypatch.setattr("vex.plugins.opencti.OpenCTIEnricher.add_observable", fake_observable)

        _run_writeback(
            [malicious_result, suspicious_result, clean_result],
            config,
            sight=True,
            dry_run_sight=False,
        )

        assert "1.2.3.4" in sighting_calls
        assert "2.3.4.5" in sighting_calls
        assert "8.8.8.8" not in sighting_calls

    def test_writeback_fields_populated(self, monkeypatch):
        """After --sight, writeback_misp and writeback_opencti are True when writers succeed."""
        result = _make_investigate_result(verdict=Verdict.MALICIOUS)
        config = _config_writeback_enabled()

        monkeypatch.setattr("vex.plugins.misp.MISPEnricher.add_sighting", lambda self, *a, **kw: True)
        monkeypatch.setattr(
            "vex.plugins.opencti.OpenCTIEnricher.add_observable", lambda self, *a, **kw: True
        )

        _run_writeback([result], config, sight=True, dry_run_sight=False)

        assert result.writeback_misp is True
        assert result.writeback_opencti is True

    def test_no_flags_returns_immediately(self, monkeypatch):
        """Neither --sight nor --dry-run-sight → no work done, no fields set."""
        result = _make_investigate_result(verdict=Verdict.MALICIOUS)
        config = _config_writeback_enabled()

        sighting_calls = []
        monkeypatch.setattr(
            "vex.plugins.misp.MISPEnricher.add_sighting",
            lambda self, *a, **kw: sighting_calls.append(1) or True,
        )

        _run_writeback([result], config, sight=False, dry_run_sight=False)

        assert len(sighting_calls) == 0
        assert result.writeback_misp is None
