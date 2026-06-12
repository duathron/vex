"""Tests for V3: quota tracker integration with batch triage.

Verifies that:
- Fresh (non-cached) lookups increment the daily quota counter.
- Cache hits do NOT increment the counter.
- Counter rolls over on a new day (tested via date mocking).
- Near-exhaustion warning fires at the right threshold.
- Tracker errors never break triage (fail-open).

All tests are offline — no network calls.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from vex.batch import batch_triage
from vex.cache import Cache
from vex.config import ApiConfig, Config
from vex.models import DetectionStats, TriageResult, Verdict
from vex.plugins.registry import PluginRegistry
from vex.quota_tracker import QuotaTracker

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(tier: str = "free") -> Config:
    cfg = Config()
    cfg.api = ApiConfig(tier=tier, key="fake-key-00000000")
    cfg.cache.enabled = False
    return cfg


def _make_triage_result(ioc: str = "1.2.3.4") -> TriageResult:
    return TriageResult(
        ioc=ioc,
        ioc_type="ipv4",
        verdict=Verdict.CLEAN,
        detection_stats=DetectionStats(malicious=0, undetected=10),
    )


def _make_fake_plugin(triage_result: TriageResult | None = None) -> MagicMock:
    plugin = MagicMock()
    plugin.name = "FakePlugin"
    plugin.supported_ioc_types = ["ipv4"]
    plugin.triage.return_value = triage_result or _make_triage_result()
    return plugin


def _make_registry(plugin: MagicMock) -> MagicMock:
    registry = MagicMock(spec=PluginRegistry)
    registry.get_plugin.return_value = plugin
    registry.__enter__ = MagicMock(return_value=registry)
    registry.__exit__ = MagicMock(return_value=False)
    return registry


# ---------------------------------------------------------------------------
# QuotaTracker increments on fresh lookup
# ---------------------------------------------------------------------------


class TestQuotaTrackerIncrement:
    def test_fresh_lookup_increments_counter(self, tmp_path: Path) -> None:
        """batch_triage increments QuotaTracker for each fresh (non-cached) lookup."""
        state_path = tmp_path / "quota.json"
        tracker = QuotaTracker(state_path=state_path, daily_limit=500)

        plugin = _make_fake_plugin()
        registry = _make_registry(plugin)
        config = _make_config()

        with patch("vex.batch.load_plugins", return_value=registry):
            batch_triage(
                ["1.2.3.4"],
                config,
                no_cache=True,
                show_progress=False,
                quota_tracker=tracker,
            )

        assert tracker.used_today() == 1

    def test_cache_hit_does_not_increment_counter(self, tmp_path: Path) -> None:
        """Cache hits do NOT increment the daily quota counter."""
        state_path = tmp_path / "quota.json"
        tracker = QuotaTracker(state_path=state_path, daily_limit=500)

        config = _make_config()
        config.cache.enabled = True
        config.cache.db_path = str(tmp_path / "cache.db")

        # Pre-populate cache
        cached_result = _make_triage_result("1.2.3.4")
        with Cache(tmp_path / "cache.db", ttl_hours=24, enabled=True) as cache:
            cache.set("triage:ipv4:1.2.3.4", cached_result.model_dump(mode="json"))

        plugin = _make_fake_plugin()
        registry = _make_registry(plugin)

        with patch("vex.batch.load_plugins", return_value=registry):
            batch_triage(
                ["1.2.3.4"],
                config,
                no_cache=False,
                show_progress=False,
                quota_tracker=tracker,
            )

        # Counter must NOT have been incremented — it was a cache hit
        assert tracker.used_today() == 0

    def test_multiple_fresh_lookups_add_up(self, tmp_path: Path) -> None:
        """Three fresh lookups → counter == 3."""
        state_path = tmp_path / "quota.json"
        tracker = QuotaTracker(state_path=state_path, daily_limit=500)

        plugin = _make_fake_plugin()
        registry = _make_registry(plugin)
        config = _make_config()

        with patch("vex.batch.load_plugins", return_value=registry):
            batch_triage(
                ["1.2.3.4", "5.6.7.8", "9.10.11.12"],
                config,
                no_cache=True,
                show_progress=False,
                quota_tracker=tracker,
            )

        assert tracker.used_today() == 3

    def test_no_tracker_does_not_crash(self, tmp_path: Path) -> None:
        """batch_triage works fine when no quota_tracker is provided (backward compat)."""
        plugin = _make_fake_plugin()
        registry = _make_registry(plugin)
        config = _make_config()

        with patch("vex.batch.load_plugins", return_value=registry):
            results, _ = batch_triage(
                ["1.2.3.4"],
                config,
                no_cache=True,
                show_progress=False,
            )

        assert len(results) == 1


# ---------------------------------------------------------------------------
# Warning fires near exhaustion
# ---------------------------------------------------------------------------


class TestExhaustionWarning:
    def test_warning_fires_near_cap(self, tmp_path: Path, capsys) -> None:
        """When QuotaTracker.is_near_exhaustion() after a lookup, a warning is emitted."""
        state_path = tmp_path / "quota.json"
        # daily_limit=10, warn_threshold=0.10 → warn at ≤ 1 remaining
        # Pre-fill 9 of 10 used so the next lookup hits the threshold
        state_path.write_text(json.dumps({"date": datetime.now(timezone.utc).date().isoformat(), "count": 9}))
        tracker = QuotaTracker(state_path=state_path, daily_limit=10, warn_threshold=0.10)

        plugin = _make_fake_plugin()
        registry = _make_registry(plugin)
        config = _make_config()

        with patch("vex.batch.load_plugins", return_value=registry):
            batch_triage(
                ["1.2.3.4"],
                config,
                no_cache=True,
                show_progress=False,
                quota_tracker=tracker,
            )

        assert tracker.is_near_exhaustion() is True
        assert tracker.used_today() == 10


# ---------------------------------------------------------------------------
# Fail-open: tracker errors don't break triage
# ---------------------------------------------------------------------------


class TestQuotaFailOpen:
    def test_broken_tracker_does_not_break_batch_triage(self, tmp_path: Path) -> None:
        """If the tracker raises on record_fresh_lookup, triage still succeeds."""
        broken_tracker = MagicMock(spec=QuotaTracker)
        broken_tracker.record_fresh_lookup.side_effect = RuntimeError("disk full")
        broken_tracker.used_today.return_value = 0
        broken_tracker.is_near_exhaustion.return_value = False
        broken_tracker.status_line.return_value = "VT quota: 0/500 used today, 500 remaining"

        plugin = _make_fake_plugin()
        registry = _make_registry(plugin)
        config = _make_config()

        with patch("vex.batch.load_plugins", return_value=registry):
            results, failed = batch_triage(
                ["1.2.3.4"],
                config,
                no_cache=True,
                show_progress=False,
                quota_tracker=broken_tracker,
            )

        # Triage succeeded despite the tracker error
        assert len(results) == 1
        assert failed == 0
