"""Tests for vex.batch: batch_triage, batch_investigate, _process_single_*.

All tests are offline.
- A fake PluginRegistry + fake plugin replaces load_plugins().
- A real (enabled) Cache backed by a tmp_path SQLite DB is used for cache tests.
- Fake Cache (disabled) is used for no-cache paths.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from vex.batch import (
    _process_single_investigate,
    _process_single_triage,
    batch_investigate,
    batch_triage,
)
from vex.cache import Cache
from vex.config import Config
from vex.models import (
    DetectionStats,
    InvestigateResult,
    TriageResult,
    Verdict,
)
from vex.plugins.registry import PluginRegistry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config() -> Config:
    cfg = Config()
    cfg.api.key = "fake-key-00000000"
    cfg.cache.enabled = False  # batch tests override per test
    return cfg


def _make_triage_result(ioc: str = "1.2.3.4", ioc_type: str = "ipv4") -> TriageResult:
    return TriageResult(
        ioc=ioc,
        ioc_type=ioc_type,
        verdict=Verdict.MALICIOUS,
        detection_stats=DetectionStats(malicious=5, undetected=65),
    )


def _make_investigate_result(ioc: str = "1.2.3.4", ioc_type: str = "ipv4") -> InvestigateResult:
    triage = _make_triage_result(ioc, ioc_type)
    return InvestigateResult(triage=triage)


def _make_fake_plugin(
    triage_return: TriageResult | None = None,
    investigate_return: InvestigateResult | None = None,
    raise_on_triage: Exception | None = None,
    raise_on_investigate: Exception | None = None,
) -> MagicMock:
    """Build a MagicMock plugin that returns real Pydantic model instances.

    Real TriageResult / InvestigateResult objects are used so that
    model_dump(mode='json') works correctly when the batch functions
    attempt to cache results.
    """
    plugin = MagicMock()
    plugin.name = "FakePlugin"
    plugin.supported_ioc_types = ["ipv4", "ipv6", "domain", "md5", "sha1", "sha256", "url"]
    if raise_on_triage:
        plugin.triage.side_effect = raise_on_triage
    else:
        plugin.triage.return_value = triage_return or _make_triage_result()
    if raise_on_investigate:
        plugin.investigate.side_effect = raise_on_investigate
    else:
        plugin.investigate.return_value = investigate_return or _make_investigate_result()
    return plugin


def _make_fake_registry(
    plugin: MagicMock | None = None,
    secondaries: list | None = None,
) -> MagicMock:
    registry = MagicMock(spec=PluginRegistry)
    registry.__enter__ = MagicMock(return_value=registry)
    registry.__exit__ = MagicMock(return_value=False)
    registry.get_plugin.return_value = plugin
    registry.get_secondary.return_value = secondaries or []
    return registry


# ---------------------------------------------------------------------------
# _process_single_triage unit tests
# ---------------------------------------------------------------------------

class TestProcessSingleTriage:
    def test_known_ioc_returns_triage_result(self, tmp_path: Path) -> None:
        cfg = _make_config()
        plugin = _make_fake_plugin()
        registry = _make_fake_registry(plugin=plugin)
        with Cache(tmp_path / "c.db", enabled=True) as cache:
            result = _process_single_triage("1.2.3.4", registry, cfg, cache, no_cache=True)
        assert result is not None
        assert result.verdict == Verdict.MALICIOUS

    def test_unknown_ioc_returns_none(self, tmp_path: Path) -> None:
        cfg = _make_config()
        registry = _make_fake_registry()
        with Cache(tmp_path / "c.db", enabled=False) as cache:
            result = _process_single_triage("not-an-ioc-$$$$", registry, cfg, cache, no_cache=True)
        assert result is None

    def test_no_plugin_returns_none(self, tmp_path: Path) -> None:
        cfg = _make_config()
        registry = _make_fake_registry(plugin=None)
        with Cache(tmp_path / "c.db", enabled=False) as cache:
            result = _process_single_triage("1.2.3.4", registry, cfg, cache, no_cache=True)
        assert result is None

    def test_plugin_exception_returns_none(self, tmp_path: Path) -> None:
        cfg = _make_config()
        plugin = _make_fake_plugin(raise_on_triage=RuntimeError("VT exploded"))
        registry = _make_fake_registry(plugin=plugin)
        with Cache(tmp_path / "c.db", enabled=False) as cache:
            result = _process_single_triage("1.2.3.4", registry, cfg, cache, no_cache=True)
        assert result is None

    def test_cache_hit_returns_from_cache(self, tmp_path: Path) -> None:
        cfg = _make_config()
        plugin = _make_fake_plugin()
        registry = _make_fake_registry(plugin=plugin)
        cached_data = {
            "ioc": "1.2.3.4", "ioc_type": "ipv4", "verdict": "MALICIOUS",
            "detection_stats": {"malicious": 5, "suspicious": 0, "undetected": 65,
                                "harmless": 0, "timeout": 0, "type_unsupported": 0,
                                "confirmed_timeout": 0, "failure": 0},
            "malware_families": [], "categories": [], "tags": [],
            "first_seen": None, "last_seen": None, "last_analysis_date": None,
            "flagging_engines": [], "reputation": None, "from_cache": False,
            "error": None, "local_tags": [], "local_notes": [], "watchlists": [],
        }
        with Cache(tmp_path / "c.db", ttl_hours=24, enabled=True) as cache:
            cache.set("triage:ipv4:1.2.3.4", cached_data)
            result = _process_single_triage("1.2.3.4", registry, cfg, cache, no_cache=False)
        assert result is not None
        assert result.from_cache is True
        plugin.triage.assert_not_called()

    def test_no_cache_bypasses_cache(self, tmp_path: Path) -> None:
        cfg = _make_config()
        plugin = _make_fake_plugin()
        registry = _make_fake_registry(plugin=plugin)
        cached_data = {
            "ioc": "1.2.3.4", "ioc_type": "ipv4", "verdict": "CLEAN",
            "detection_stats": {"malicious": 0, "suspicious": 0, "undetected": 70,
                                "harmless": 0, "timeout": 0, "type_unsupported": 0,
                                "confirmed_timeout": 0, "failure": 0},
            "malware_families": [], "categories": [], "tags": [],
            "first_seen": None, "last_seen": None, "last_analysis_date": None,
            "flagging_engines": [], "reputation": None, "from_cache": False,
            "error": None, "local_tags": [], "local_notes": [], "watchlists": [],
        }
        with Cache(tmp_path / "c.db", ttl_hours=24, enabled=True) as cache:
            cache.set("triage:ipv4:1.2.3.4", cached_data)
            result = _process_single_triage("1.2.3.4", registry, cfg, cache, no_cache=True)
        assert result is not None
        # Plugin was called (bypassed cache)
        plugin.triage.assert_called_once()
        # Result comes from plugin, not the CLEAN cached value
        assert result.verdict == Verdict.MALICIOUS


# ---------------------------------------------------------------------------
# _process_single_investigate unit tests
# ---------------------------------------------------------------------------

class TestProcessSingleInvestigate:
    def test_known_ioc_returns_investigate_result(self, tmp_path: Path) -> None:
        cfg = _make_config()
        plugin = _make_fake_plugin()
        registry = _make_fake_registry(plugin=plugin)
        with Cache(tmp_path / "c.db", enabled=False) as cache:
            result = _process_single_investigate("1.2.3.4", registry, cfg, cache, no_cache=True)
        assert result is not None
        assert isinstance(result, InvestigateResult)
        assert result.triage.verdict == Verdict.MALICIOUS

    def test_unknown_ioc_returns_none(self, tmp_path: Path) -> None:
        cfg = _make_config()
        registry = _make_fake_registry()
        with Cache(tmp_path / "c.db", enabled=False) as cache:
            result = _process_single_investigate("$$bad$$", registry, cfg, cache, no_cache=True)
        assert result is None

    def test_plugin_exception_returns_none(self, tmp_path: Path) -> None:
        cfg = _make_config()
        plugin = _make_fake_plugin(raise_on_investigate=RuntimeError("network error"))
        registry = _make_fake_registry(plugin=plugin)
        with Cache(tmp_path / "c.db", enabled=False) as cache:
            result = _process_single_investigate("1.2.3.4", registry, cfg, cache, no_cache=True)
        assert result is None

    def test_cache_hit_returns_from_cache(self, tmp_path: Path) -> None:
        cfg = _make_config()
        plugin = _make_fake_plugin()
        registry = _make_fake_registry(plugin=plugin)
        cached_data = {
            "triage": {
                "ioc": "1.2.3.4", "ioc_type": "ipv4", "verdict": "SUSPICIOUS",
                "detection_stats": {"malicious": 1, "suspicious": 1, "undetected": 65,
                                    "harmless": 0, "timeout": 0, "type_unsupported": 0,
                                    "confirmed_timeout": 0, "failure": 0},
                "malware_families": [], "categories": [], "tags": [],
                "first_seen": None, "last_seen": None, "last_analysis_date": None,
                "flagging_engines": [], "reputation": None, "from_cache": False,
                "error": None, "local_tags": [], "local_notes": [], "watchlists": [],
            },
            "attack_mappings": [],
            "file_type": None, "file_size": None, "file_names": [],
            "magic": None, "ssdeep": None, "tlsh": None,
            "pe_info": None, "sandbox_behaviors": [],
            "contacted_ips": [], "contacted_domains": [], "dropped_files": [],
            "yara_hits": [], "signature_info": None,
            "asn": None, "asn_owner": None, "country": None,
            "continent": None, "network": None,
            "abuse_confidence": None, "abuse_total_reports": None, "abuse_last_reported": None,
            "shodan_ports": [], "shodan_hostnames": [], "shodan_org": None, "shodan_tags": [],
            "misp_known": False, "misp_event_ids": [], "misp_tags": [], "misp_tlp": None,
            "misp_last_seen": None, "opencti_known": False, "opencti_id": None,
            "opencti_score": None, "opencti_labels": [], "opencti_tlp": None,
            "passive_dns": [], "communicating_files": [], "downloaded_files": [],
            "whois": None, "dns_records": [], "subdomains": [],
            "final_url": None, "title": None, "related_files": [],
        }
        with Cache(tmp_path / "c.db", ttl_hours=24, enabled=True) as cache:
            cache.set("investigate:ipv4:1.2.3.4", cached_data)
            result = _process_single_investigate("1.2.3.4", registry, cfg, cache, no_cache=False)
        assert result is not None
        assert result.triage.from_cache is True
        plugin.investigate.assert_not_called()

    def test_secondary_enrichers_called(self, tmp_path: Path) -> None:
        cfg = _make_config()
        plugin = _make_fake_plugin()
        secondary = MagicMock()
        secondary.supported_ioc_types = ["ipv4"]
        secondary.enrich = MagicMock()
        registry = _make_fake_registry(plugin=plugin, secondaries=[secondary])
        with Cache(tmp_path / "c.db", enabled=False) as cache:
            result = _process_single_investigate("1.2.3.4", registry, cfg, cache, no_cache=True)
        assert result is not None
        secondary.enrich.assert_called_once()

    def test_secondary_enricher_exception_does_not_abort(self, tmp_path: Path) -> None:
        cfg = _make_config()
        plugin = _make_fake_plugin()
        secondary = MagicMock()
        secondary.supported_ioc_types = ["ipv4"]
        secondary.enrich.side_effect = RuntimeError("secondary failed")
        registry = _make_fake_registry(plugin=plugin, secondaries=[secondary])
        with Cache(tmp_path / "c.db", enabled=False) as cache:
            result = _process_single_investigate("1.2.3.4", registry, cfg, cache, no_cache=True)
        # Must still return a result; secondary failure is swallowed
        assert result is not None


# ---------------------------------------------------------------------------
# batch_triage — sequential path
# ---------------------------------------------------------------------------

class TestBatchTriageSequential:
    def _run(
        self,
        iocs: list[str],
        plugin: MagicMock,
        tmp_path: Path,
    ) -> tuple[list[TriageResult], int]:
        cfg = _make_config()
        cfg.cache.enabled = False
        cfg.cache.db_path = str(tmp_path / "c.db")
        registry = _make_fake_registry(plugin=plugin)
        with patch("vex.batch.load_plugins", return_value=registry):
            results, failed = batch_triage(iocs, cfg, no_cache=True, show_progress=False)
        return results, failed

    def test_all_success(self, tmp_path: Path) -> None:
        plugin = _make_fake_plugin()
        results, failed = self._run(["1.2.3.4", "2.3.4.5"], plugin, tmp_path)
        assert failed == 0
        assert len(results) == 2

    def test_one_unknown_ioc_counted_as_failed(self, tmp_path: Path) -> None:
        plugin = _make_fake_plugin()
        results, failed = self._run(["1.2.3.4", "$$not-an-ioc$$"], plugin, tmp_path)
        assert failed == 1
        assert len(results) == 1

    def test_plugin_exception_counted_as_failed(self, tmp_path: Path) -> None:
        plugin = _make_fake_plugin(raise_on_triage=RuntimeError("explode"))
        results, failed = self._run(["1.2.3.4"], plugin, tmp_path)
        assert failed == 1
        assert results == []

    def test_empty_ioc_list(self, tmp_path: Path) -> None:
        plugin = _make_fake_plugin()
        results, failed = self._run([], plugin, tmp_path)
        assert results == []
        assert failed == 0

    def test_returns_correct_failed_count_formula(self, tmp_path: Path) -> None:
        """failed_count = len(iocs) - len(results)."""
        plugin = _make_fake_plugin()
        # 3 IOCs, 1 bad → 2 results, 1 failed
        results, failed = self._run(["1.2.3.4", "2.3.4.5", "$$bad$$"], plugin, tmp_path)
        assert len(results) + failed == 3


# ---------------------------------------------------------------------------
# batch_triage — thread-pool path (show_progress=False but max_workers>1)
# ---------------------------------------------------------------------------

class TestBatchTriageThreadPool:
    """The parallel path is exercised by patching show_progress path to use pool."""

    def _run_parallel(
        self,
        iocs: list[str],
        plugin: MagicMock,
        tmp_path: Path,
        max_workers: int = 2,
    ) -> tuple[list[TriageResult], int]:
        cfg = _make_config()
        cfg.cache.enabled = False
        cfg.cache.db_path = str(tmp_path / "c.db")
        registry = _make_fake_registry(plugin=plugin)
        with patch("vex.batch.load_plugins", return_value=registry):
            # show_progress=True triggers the ThreadPoolExecutor path
            # We suppress Rich's Progress output by patching it
            with patch("vex.batch.Progress") as mock_progress_cls:
                mock_progress = MagicMock()
                mock_progress.__enter__ = MagicMock(return_value=mock_progress)
                mock_progress.__exit__ = MagicMock(return_value=False)
                mock_progress.add_task.return_value = 0
                mock_progress_cls.return_value = mock_progress
                results, failed = batch_triage(
                    iocs, cfg, no_cache=True, show_progress=True, max_workers=max_workers
                )
        return results, failed

    def test_parallel_all_success(self, tmp_path: Path) -> None:
        plugin = _make_fake_plugin()
        results, failed = self._run_parallel(["1.2.3.4", "2.3.4.5", "3.4.5.6"], plugin, tmp_path)
        assert failed == 0
        assert len(results) == 3

    def test_parallel_with_bad_ioc(self, tmp_path: Path) -> None:
        plugin = _make_fake_plugin()
        results, failed = self._run_parallel(["1.2.3.4", "$$bad$$"], plugin, tmp_path)
        assert failed == 1
        assert len(results) == 1

    def test_parallel_plugin_exception_counted(self, tmp_path: Path) -> None:
        plugin = _make_fake_plugin(raise_on_triage=RuntimeError("boom"))
        results, failed = self._run_parallel(["1.2.3.4"], plugin, tmp_path)
        assert failed == 1
        assert results == []


# ---------------------------------------------------------------------------
# batch_triage — cache hit path
# ---------------------------------------------------------------------------

class TestBatchTriageCache:
    def test_cache_hit_served_without_plugin_call(self, tmp_path: Path) -> None:
        cfg = _make_config()
        cfg.cache.enabled = True
        cfg.cache.db_path = str(tmp_path / "c.db")
        plugin = _make_fake_plugin()
        registry = _make_fake_registry(plugin=plugin)

        cached_data = {
            "ioc": "1.2.3.4", "ioc_type": "ipv4", "verdict": "SUSPICIOUS",
            "detection_stats": {"malicious": 1, "suspicious": 1, "undetected": 65,
                                "harmless": 0, "timeout": 0, "type_unsupported": 0,
                                "confirmed_timeout": 0, "failure": 0},
            "malware_families": [], "categories": [], "tags": [],
            "first_seen": None, "last_seen": None, "last_analysis_date": None,
            "flagging_engines": [], "reputation": None, "from_cache": False,
            "error": None, "local_tags": [], "local_notes": [], "watchlists": [],
        }

        # Pre-populate cache
        with Cache(tmp_path / "c.db", ttl_hours=24, enabled=True) as seed_cache:
            seed_cache.set("triage:ipv4:1.2.3.4", cached_data)

        with patch("vex.batch.load_plugins", return_value=registry):
            results, failed = batch_triage(
                ["1.2.3.4"], cfg, no_cache=False, show_progress=False
            )

        assert failed == 0
        assert len(results) == 1
        assert results[0].from_cache is True
        # Plugin must not have been invoked
        plugin.triage.assert_not_called()


# ---------------------------------------------------------------------------
# batch_investigate — sequential path
# ---------------------------------------------------------------------------

class TestBatchInvestigateSequential:
    def _run(
        self,
        iocs: list[str],
        plugin: MagicMock,
        tmp_path: Path,
    ) -> tuple[list[InvestigateResult], int]:
        cfg = _make_config()
        cfg.cache.enabled = False
        cfg.cache.db_path = str(tmp_path / "c.db")
        registry = _make_fake_registry(plugin=plugin)
        with patch("vex.batch.load_plugins", return_value=registry):
            results, failed = batch_investigate(iocs, cfg, no_cache=True, show_progress=False)
        return results, failed

    def test_all_success(self, tmp_path: Path) -> None:
        plugin = _make_fake_plugin()
        results, failed = self._run(["1.2.3.4", "evil.com"], plugin, tmp_path)
        assert failed == 0
        assert len(results) == 2

    def test_unknown_ioc_counted_as_failed(self, tmp_path: Path) -> None:
        plugin = _make_fake_plugin()
        results, failed = self._run(["1.2.3.4", "$$bad$$"], plugin, tmp_path)
        assert failed == 1
        assert len(results) == 1

    def test_plugin_exception_counted_as_failed(self, tmp_path: Path) -> None:
        plugin = _make_fake_plugin(raise_on_investigate=RuntimeError("down"))
        results, failed = self._run(["1.2.3.4"], plugin, tmp_path)
        assert failed == 1
        assert results == []

    def test_empty_ioc_list(self, tmp_path: Path) -> None:
        plugin = _make_fake_plugin()
        results, failed = self._run([], plugin, tmp_path)
        assert results == []
        assert failed == 0


# ---------------------------------------------------------------------------
# batch_investigate — thread-pool path
# ---------------------------------------------------------------------------

class TestBatchInvestigateThreadPool:
    def _run_parallel(
        self,
        iocs: list[str],
        plugin: MagicMock,
        tmp_path: Path,
    ) -> tuple[list[InvestigateResult], int]:
        cfg = _make_config()
        cfg.cache.enabled = False
        cfg.cache.db_path = str(tmp_path / "c.db")
        registry = _make_fake_registry(plugin=plugin)
        with patch("vex.batch.load_plugins", return_value=registry):
            with patch("vex.batch.Progress") as mock_progress_cls:
                mock_progress = MagicMock()
                mock_progress.__enter__ = MagicMock(return_value=mock_progress)
                mock_progress.__exit__ = MagicMock(return_value=False)
                mock_progress.add_task.return_value = 0
                mock_progress_cls.return_value = mock_progress
                results, failed = batch_investigate(
                    iocs, cfg, no_cache=True, show_progress=True, max_workers=2
                )
        return results, failed

    def test_parallel_all_success(self, tmp_path: Path) -> None:
        plugin = _make_fake_plugin()
        results, failed = self._run_parallel(["1.2.3.4", "evil.com", "2.3.4.5"], plugin, tmp_path)
        assert failed == 0
        assert len(results) == 3

    def test_parallel_with_bad_ioc(self, tmp_path: Path) -> None:
        plugin = _make_fake_plugin()
        results, failed = self._run_parallel(["1.2.3.4", "$$bad$$"], plugin, tmp_path)
        assert failed == 1
        assert len(results) == 1

    def test_parallel_exception_counted(self, tmp_path: Path) -> None:
        plugin = _make_fake_plugin(raise_on_investigate=RuntimeError("boom"))
        results, failed = self._run_parallel(["1.2.3.4"], plugin, tmp_path)
        assert failed == 1
        assert results == []


# ---------------------------------------------------------------------------
# batch_investigate — cache hit path
# ---------------------------------------------------------------------------

class TestBatchInvestigateCache:
    def test_cache_hit_served_without_plugin_call(self, tmp_path: Path) -> None:
        cfg = _make_config()
        cfg.cache.enabled = True
        cfg.cache.db_path = str(tmp_path / "c.db")
        plugin = _make_fake_plugin()
        registry = _make_fake_registry(plugin=plugin)

        cached_data = {
            "triage": {
                "ioc": "1.2.3.4", "ioc_type": "ipv4", "verdict": "MALICIOUS",
                "detection_stats": {"malicious": 5, "suspicious": 0, "undetected": 65,
                                    "harmless": 0, "timeout": 0, "type_unsupported": 0,
                                    "confirmed_timeout": 0, "failure": 0},
                "malware_families": [], "categories": [], "tags": [],
                "first_seen": None, "last_seen": None, "last_analysis_date": None,
                "flagging_engines": [], "reputation": None, "from_cache": False,
                "error": None, "local_tags": [], "local_notes": [], "watchlists": [],
            },
            "attack_mappings": [],
            "file_type": None, "file_size": None, "file_names": [],
            "magic": None, "ssdeep": None, "tlsh": None,
            "pe_info": None, "sandbox_behaviors": [],
            "contacted_ips": [], "contacted_domains": [], "dropped_files": [],
            "yara_hits": [], "signature_info": None,
            "asn": None, "asn_owner": None, "country": None,
            "continent": None, "network": None,
            "abuse_confidence": None, "abuse_total_reports": None, "abuse_last_reported": None,
            "shodan_ports": [], "shodan_hostnames": [], "shodan_org": None, "shodan_tags": [],
            "misp_known": False, "misp_event_ids": [], "misp_tags": [], "misp_tlp": None,
            "misp_last_seen": None, "opencti_known": False, "opencti_id": None,
            "opencti_score": None, "opencti_labels": [], "opencti_tlp": None,
            "passive_dns": [], "communicating_files": [], "downloaded_files": [],
            "whois": None, "dns_records": [], "subdomains": [],
            "final_url": None, "title": None, "related_files": [],
        }

        with Cache(tmp_path / "c.db", ttl_hours=24, enabled=True) as seed_cache:
            seed_cache.set("investigate:ipv4:1.2.3.4", cached_data)

        with patch("vex.batch.load_plugins", return_value=registry):
            results, failed = batch_investigate(
                ["1.2.3.4"], cfg, no_cache=False, show_progress=False
            )

        assert failed == 0
        assert len(results) == 1
        assert results[0].triage.from_cache is True
        plugin.investigate.assert_not_called()
