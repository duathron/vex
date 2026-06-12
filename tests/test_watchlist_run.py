"""Tests for V2: vex watchlist run <name> — one-shot watchlist re-triage.

All tests are offline. Network calls and triage logic are mocked throughout.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from vex.knowledge.db import KnowledgeDB
from vex.main import app
from vex.models import DetectionStats, TriageResult, Verdict
from vex.watchlist_runner import WatchlistRunResult, retriage_watchlist

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_triage(ioc: str, verdict: Verdict, from_cache: bool = False) -> TriageResult:
    return TriageResult(
        ioc=ioc,
        ioc_type="ipv4",
        verdict=verdict,
        detection_stats=DetectionStats(malicious=0, suspicious=0, undetected=10, harmless=0),
        from_cache=from_cache,
    )


def _cache_result(cache, ioc: str, verdict: Verdict) -> None:
    """Write a prior verdict into the Cache for the given ioc."""
    result = _make_triage(ioc, verdict)
    cache.set(f"triage:ipv4:{ioc}", result.model_dump(mode="json"))


# ---------------------------------------------------------------------------
# Core logic tests (retriage_watchlist helper)
# ---------------------------------------------------------------------------


class TestRetriagedLogic:
    def test_no_change_returns_empty_diffs(self, tmp_path: Path) -> None:
        """If all IOC verdicts are unchanged, diffs list is empty."""
        db = KnowledgeDB(db_path=tmp_path / "k.db")
        db.add_to_watchlist("test", "1.2.3.4")

        from vex.cache import Cache

        with Cache(tmp_path / "cache.db", ttl_hours=24) as cache:
            _cache_result(cache, "1.2.3.4", Verdict.CLEAN)

            # Patch triage to return same verdict
            fresh = _make_triage("1.2.3.4", Verdict.CLEAN)

            with patch("vex.watchlist_runner._triage_ioc", return_value=fresh):
                from vex.config import Config

                result = retriage_watchlist("test", db, cache, Config())

        assert result.diffs == []
        assert result.unchanged == 1

    def test_worsened_verdict_appears_in_diffs(self, tmp_path: Path) -> None:
        """CLEAN → MALICIOUS worsening must appear in diffs."""
        db = KnowledgeDB(db_path=tmp_path / "k.db")
        db.add_to_watchlist("test", "1.2.3.4")

        from vex.cache import Cache

        with Cache(tmp_path / "cache.db", ttl_hours=24) as cache:
            _cache_result(cache, "1.2.3.4", Verdict.CLEAN)

            fresh = _make_triage("1.2.3.4", Verdict.MALICIOUS)
            with patch("vex.watchlist_runner._triage_ioc", return_value=fresh):
                from vex.config import Config

                result = retriage_watchlist("test", db, cache, Config())

        assert len(result.diffs) == 1
        diff = result.diffs[0]
        assert diff["ioc"] == "1.2.3.4"
        assert diff["old_verdict"] == Verdict.CLEAN
        assert diff["new_verdict"] == Verdict.MALICIOUS

    def test_improved_verdict_does_not_appear_in_diffs(self, tmp_path: Path) -> None:
        """MALICIOUS → CLEAN improvement is NOT flagged as a diff (only worsening)."""
        db = KnowledgeDB(db_path=tmp_path / "k.db")
        db.add_to_watchlist("test", "1.2.3.4")

        from vex.cache import Cache

        with Cache(tmp_path / "cache.db", ttl_hours=24) as cache:
            _cache_result(cache, "1.2.3.4", Verdict.MALICIOUS)

            fresh = _make_triage("1.2.3.4", Verdict.CLEAN)
            with patch("vex.watchlist_runner._triage_ioc", return_value=fresh):
                from vex.config import Config

                result = retriage_watchlist("test", db, cache, Config())

        # Improvement tracked but not flagged as worsening
        assert result.diffs == []

    def test_cache_miss_uses_fresh_lookup_verdict(self, tmp_path: Path) -> None:
        """When no prior cache entry exists, the new verdict is treated as new (no prior)."""
        db = KnowledgeDB(db_path=tmp_path / "k.db")
        db.add_to_watchlist("test", "1.2.3.4")

        from vex.cache import Cache

        with Cache(tmp_path / "cache.db", ttl_hours=24) as cache:
            # No prior entry in cache
            fresh = _make_triage("1.2.3.4", Verdict.MALICIOUS)
            with patch("vex.watchlist_runner._triage_ioc", return_value=fresh):
                from vex.config import Config

                result = retriage_watchlist("test", db, cache, Config())

        # Cache-miss → no prior verdict → treated as new, not a "worsening"
        assert result.diffs == []
        assert result.cache_misses == 1

    def test_multiple_iocs_mixed_verdicts(self, tmp_path: Path) -> None:
        """Mixed watchlist: one worsened, one unchanged."""
        db = KnowledgeDB(db_path=tmp_path / "k.db")
        db.add_to_watchlist("test", "1.2.3.4")
        db.add_to_watchlist("test", "5.6.7.8")

        from vex.cache import Cache

        with Cache(tmp_path / "cache.db", ttl_hours=24) as cache:
            _cache_result(cache, "1.2.3.4", Verdict.CLEAN)
            _cache_result(cache, "5.6.7.8", Verdict.CLEAN)

            def _mock_triage(ioc, *args, **kwargs):
                if ioc == "1.2.3.4":
                    return _make_triage("1.2.3.4", Verdict.MALICIOUS)
                return _make_triage("5.6.7.8", Verdict.CLEAN)

            with patch("vex.watchlist_runner._triage_ioc", side_effect=_mock_triage):
                from vex.config import Config

                result = retriage_watchlist("test", db, cache, Config())

        assert len(result.diffs) == 1
        assert result.unchanged == 1


# ---------------------------------------------------------------------------
# CLI tests  — `vex watchlist run <name>`
# ---------------------------------------------------------------------------


def _mock_run_result_no_change(name: str, *args, **kwargs) -> WatchlistRunResult:
    r = WatchlistRunResult(watchlist_name=name, total=1, unchanged=1)
    return r


def _mock_run_result_worsened(name: str, *args, **kwargs) -> WatchlistRunResult:
    r = WatchlistRunResult(watchlist_name=name, total=1, worsened=1)
    r.diffs = [{"ioc": "1.2.3.4", "old_verdict": Verdict.CLEAN, "new_verdict": Verdict.MALICIOUS}]
    return r


def _mock_run_result_empty(name: str, *args, **kwargs) -> WatchlistRunResult:
    return WatchlistRunResult(watchlist_name=name, total=0)


class TestWatchlistRunCLI:
    def test_unknown_watchlist_exits_zero(self) -> None:
        """An empty/unknown watchlist exits 0 with a clean message."""
        with patch("vex.main.retriage_watchlist", side_effect=_mock_run_result_empty):
            with patch("vex.main.KnowledgeDB"):
                with patch("vex.main.Cache"):
                    result = runner.invoke(app, ["watchlist", "run", "nonexistent"])
        assert result.exit_code == 0

    def test_no_change_exits_zero(self) -> None:
        """All IOCs unchanged → exit 0."""
        with patch("vex.main.retriage_watchlist", side_effect=_mock_run_result_no_change):
            with patch("vex.main.KnowledgeDB"):
                with patch("vex.main.Cache"):
                    result = runner.invoke(app, ["watchlist", "run", "mylist"])
        assert result.exit_code == 0

    def test_worsened_verdict_exits_nonzero(self) -> None:
        """At least one worsened verdict → exit non-zero."""
        with patch("vex.main.retriage_watchlist", side_effect=_mock_run_result_worsened):
            with patch("vex.main.KnowledgeDB"):
                with patch("vex.main.Cache"):
                    result = runner.invoke(app, ["watchlist", "run", "mylist"])
        assert result.exit_code != 0

    def test_worsened_verdict_listed_in_output(self) -> None:
        """The diff table must include the IOC and old/new verdicts."""
        with patch("vex.main.retriage_watchlist", side_effect=_mock_run_result_worsened):
            with patch("vex.main.KnowledgeDB"):
                with patch("vex.main.Cache"):
                    result = runner.invoke(app, ["watchlist", "run", "mylist"])
        output = result.output
        assert "1.2.3.4" in output
        assert "CLEAN" in output
        assert "MALICIOUS" in output

    def test_json_output_is_valid(self) -> None:
        """--output json produces parseable JSON with a 'diffs' key."""
        with patch("vex.main.retriage_watchlist", side_effect=_mock_run_result_worsened):
            with patch("vex.main.KnowledgeDB"):
                with patch("vex.main.Cache"):
                    with patch("vex.main._build_quota_tracker", return_value=None):
                        result = runner.invoke(app, ["watchlist", "run", "mylist", "--output", "json"])
        data = json.loads(result.output)
        assert "diffs" in data
        assert "unchanged" in data

    def test_watchlist_run_help_exits_zero(self) -> None:
        """`vex watchlist run --help` exits 0."""
        result = runner.invoke(app, ["watchlist", "run", "--help"])
        assert result.exit_code == 0

    def test_original_watchlist_manage_help_still_works(self) -> None:
        """Backward compat: `vex watchlist --help` still works."""
        result = runner.invoke(app, ["watchlist", "--help"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Regression tests — original flat watchlist shape (Skeptic Fix 1)
# ---------------------------------------------------------------------------


class TestOriginalFlatWatchlistShape:
    """Regression suite: vex watchlist <name> [--add IOC] [--list] must work
    exactly as it did before the V2 sub-app refactor."""

    def test_original_flat_watchlist_still_works(self, tmp_path: Path) -> None:
        """`vex watchlist <name> --add <ioc>` adds an IOC (exit 0, confirms in output)."""
        from unittest.mock import MagicMock, patch

        mock_db = MagicMock()
        mock_db.__enter__ = MagicMock(return_value=mock_db)
        mock_db.__exit__ = MagicMock(return_value=False)
        mock_db.add_to_watchlist = MagicMock()
        mock_db.get_watchlist = MagicMock(return_value=["8.8.8.8"])

        with patch("vex.main.KnowledgeDB", return_value=mock_db):
            result = runner.invoke(app, ["watchlist", "priority", "--add", "8.8.8.8"])

        assert result.exit_code == 0, f"exit {result.exit_code}: {result.output}"
        mock_db.add_to_watchlist.assert_called_once_with("priority", "8.8.8.8")

    def test_original_flat_watchlist_list_flag(self, tmp_path: Path) -> None:
        """`vex watchlist <name> --list` lists the watchlist IOCs."""
        from unittest.mock import MagicMock, patch

        mock_db = MagicMock()
        mock_db.__enter__ = MagicMock(return_value=mock_db)
        mock_db.__exit__ = MagicMock(return_value=False)
        mock_db.add_to_watchlist = MagicMock()
        mock_db.get_watchlist = MagicMock(return_value=["8.8.8.8"])

        with patch("vex.main.KnowledgeDB", return_value=mock_db):
            result = runner.invoke(app, ["watchlist", "priority", "--add", "8.8.8.8", "--list"])

        assert result.exit_code == 0, f"exit {result.exit_code}: {result.output}"
        # Output should show the add confirmation and list
        assert "8.8.8.8" in result.output

    def test_original_flat_watchlist_name_only_shows_list(self) -> None:
        """`vex watchlist <name>` with no --add/--remove shows the watchlist contents."""
        from unittest.mock import MagicMock, patch

        mock_db = MagicMock()
        mock_db.__enter__ = MagicMock(return_value=mock_db)
        mock_db.__exit__ = MagicMock(return_value=False)
        mock_db.get_watchlist = MagicMock(return_value=[])

        with patch("vex.main.KnowledgeDB", return_value=mock_db):
            result = runner.invoke(app, ["watchlist", "evil.com"])

        assert result.exit_code == 0, f"exit {result.exit_code}: {result.output}"
        mock_db.get_watchlist.assert_called_once_with("evil.com")

    def test_flat_and_run_coexist(self) -> None:
        """The flat shape and `vex watchlist run` must coexist — run help exits 0."""
        result = runner.invoke(app, ["watchlist", "run", "--help"])
        assert result.exit_code == 0

    def test_bare_watchlist_shows_help(self) -> None:
        """`vex watchlist` with no args shows help (exits 0)."""
        result = runner.invoke(app, ["watchlist"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Quota tracker integration with watchlist run (Skeptic Fix 3)
# ---------------------------------------------------------------------------


class TestWatchlistRunQuotaTracking:
    """Watchlist re-triage must increment QuotaTracker for fresh (non-cached) lookups."""

    def test_watchlist_run_increments_quota_on_fresh_lookup(self, tmp_path: Path) -> None:
        """Each fresh VT lookup in retriage_watchlist increments the quota counter."""
        from vex.cache import Cache
        from vex.config import Config
        from vex.quota_tracker import QuotaTracker

        db = KnowledgeDB(db_path=tmp_path / "k.db")
        db.add_to_watchlist("test", "1.2.3.4")
        db.add_to_watchlist("test", "5.6.7.8")

        state_path = tmp_path / "quota.json"
        tracker = QuotaTracker(state_path=state_path, daily_limit=500)

        fresh_1 = _make_triage("1.2.3.4", Verdict.CLEAN)
        fresh_2 = _make_triage("5.6.7.8", Verdict.CLEAN)

        def _mock_triage(ioc, *args, **kwargs):
            return fresh_1 if ioc == "1.2.3.4" else fresh_2

        with Cache(tmp_path / "cache.db", ttl_hours=24) as cache:
            with patch("vex.watchlist_runner._triage_ioc", side_effect=_mock_triage):
                retriage_watchlist("test", db, cache, Config(), quota_tracker=tracker)

        assert tracker.used_today() == 2

    def test_watchlist_run_no_increment_without_tracker(self, tmp_path: Path) -> None:
        """retriage_watchlist with quota_tracker=None must not crash."""
        from vex.cache import Cache
        from vex.config import Config

        db = KnowledgeDB(db_path=tmp_path / "k.db")
        db.add_to_watchlist("test", "1.2.3.4")

        fresh = _make_triage("1.2.3.4", Verdict.CLEAN)

        with Cache(tmp_path / "cache.db", ttl_hours=24) as cache:
            with patch("vex.watchlist_runner._triage_ioc", return_value=fresh):
                result = retriage_watchlist("test", db, cache, Config(), quota_tracker=None)

        assert result.total == 1

    def test_watchlist_run_does_not_increment_on_triage_failure(self, tmp_path: Path) -> None:
        """Quota must not increment when _triage_ioc returns None (lookup failure)."""
        from vex.cache import Cache
        from vex.config import Config
        from vex.quota_tracker import QuotaTracker

        db = KnowledgeDB(db_path=tmp_path / "k.db")
        db.add_to_watchlist("test", "1.2.3.4")

        state_path = tmp_path / "quota.json"
        tracker = QuotaTracker(state_path=state_path, daily_limit=500)

        with Cache(tmp_path / "cache.db", ttl_hours=24) as cache:
            with patch("vex.watchlist_runner._triage_ioc", return_value=None):
                retriage_watchlist("test", db, cache, Config(), quota_tracker=tracker)

        assert tracker.used_today() == 0
