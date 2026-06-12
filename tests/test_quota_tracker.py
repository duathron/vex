"""Tests for V3: vex.quota_tracker — persistent daily VT quota counter.

All tests are deterministic and filesystem-safe (tmp_path).
No network calls.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from vex.quota_tracker import QuotaTracker

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _today_str() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def _other_day_str() -> str:
    """A date clearly in the past (not today)."""
    return "2000-01-01"


# ---------------------------------------------------------------------------
# Basic increment behaviour
# ---------------------------------------------------------------------------


class TestIncrement:
    def test_initial_count_is_zero(self, tmp_path: Path) -> None:
        qt = QuotaTracker(state_path=tmp_path / "quota.json")
        assert qt.used_today() == 0

    def test_increment_once(self, tmp_path: Path) -> None:
        qt = QuotaTracker(state_path=tmp_path / "quota.json")
        qt.record_fresh_lookup()
        assert qt.used_today() == 1

    def test_increment_multiple_times(self, tmp_path: Path) -> None:
        qt = QuotaTracker(state_path=tmp_path / "quota.json")
        for _ in range(5):
            qt.record_fresh_lookup()
        assert qt.used_today() == 5

    def test_used_today_persists_across_instances(self, tmp_path: Path) -> None:
        path = tmp_path / "quota.json"
        qt1 = QuotaTracker(state_path=path)
        qt1.record_fresh_lookup()
        qt1.record_fresh_lookup()
        qt2 = QuotaTracker(state_path=path)
        assert qt2.used_today() == 2


# ---------------------------------------------------------------------------
# Date rollover
# ---------------------------------------------------------------------------


class TestRollover:
    def test_count_resets_on_new_day(self, tmp_path: Path) -> None:
        """If the stored date is different from today, the counter resets."""
        path = tmp_path / "quota.json"
        # Manually write a stale entry
        path.write_text(json.dumps({"date": _other_day_str(), "count": 99}))
        qt = QuotaTracker(state_path=path)
        # Loading should reset because date != today
        assert qt.used_today() == 0

    def test_increment_after_rollover(self, tmp_path: Path) -> None:
        path = tmp_path / "quota.json"
        path.write_text(json.dumps({"date": _other_day_str(), "count": 999}))
        qt = QuotaTracker(state_path=path)
        qt.record_fresh_lookup()
        assert qt.used_today() == 1

    def test_today_count_preserved_when_same_day(self, tmp_path: Path) -> None:
        path = tmp_path / "quota.json"
        path.write_text(json.dumps({"date": _today_str(), "count": 42}))
        qt = QuotaTracker(state_path=path)
        assert qt.used_today() == 42


# ---------------------------------------------------------------------------
# Remaining / warning
# ---------------------------------------------------------------------------


class TestRemaining:
    def test_remaining_is_limit_minus_used(self, tmp_path: Path) -> None:
        qt = QuotaTracker(state_path=tmp_path / "quota.json", daily_limit=500)
        qt.record_fresh_lookup()
        qt.record_fresh_lookup()
        assert qt.remaining_today() == 498

    def test_remaining_does_not_go_below_zero(self, tmp_path: Path) -> None:
        qt = QuotaTracker(state_path=tmp_path / "quota.json", daily_limit=2)
        for _ in range(10):
            qt.record_fresh_lookup()
        assert qt.remaining_today() == 0

    def test_near_exhaustion_true_when_remaining_below_threshold(self, tmp_path: Path) -> None:
        """is_near_exhaustion() returns True when remaining < warn_threshold."""
        qt = QuotaTracker(state_path=tmp_path / "quota.json", daily_limit=100, warn_threshold=0.10)
        # Use 92 out of 100 → 8 remaining (< 10 % of 100)
        for _ in range(92):
            qt.record_fresh_lookup()
        assert qt.is_near_exhaustion() is True

    def test_near_exhaustion_false_when_plenty_remaining(self, tmp_path: Path) -> None:
        qt = QuotaTracker(state_path=tmp_path / "quota.json", daily_limit=100, warn_threshold=0.10)
        qt.record_fresh_lookup()  # 1 used, 99 remaining
        assert qt.is_near_exhaustion() is False

    def test_near_exhaustion_true_at_exact_threshold(self, tmp_path: Path) -> None:
        """Boundary: exactly at threshold → warning fires."""
        qt = QuotaTracker(state_path=tmp_path / "quota.json", daily_limit=100, warn_threshold=0.10)
        # Use 90 → 10 remaining == 10 % → still at threshold, warn
        for _ in range(90):
            qt.record_fresh_lookup()
        assert qt.is_near_exhaustion() is True


# ---------------------------------------------------------------------------
# Corrupt / missing state — fail-open
# ---------------------------------------------------------------------------


class TestFailOpen:
    def test_missing_file_starts_clean(self, tmp_path: Path) -> None:
        path = tmp_path / "nonexistent_dir" / "quota.json"
        qt = QuotaTracker(state_path=path)
        assert qt.used_today() == 0

    def test_corrupt_json_starts_clean_no_crash(self, tmp_path: Path) -> None:
        path = tmp_path / "quota.json"
        path.write_text("{this is not: json!!!")
        qt = QuotaTracker(state_path=path)
        assert qt.used_today() == 0

    def test_corrupt_json_increments_cleanly(self, tmp_path: Path) -> None:
        path = tmp_path / "quota.json"
        path.write_text("null")
        qt = QuotaTracker(state_path=path)
        qt.record_fresh_lookup()
        assert qt.used_today() == 1

    def test_missing_keys_in_json_starts_clean(self, tmp_path: Path) -> None:
        path = tmp_path / "quota.json"
        path.write_text(json.dumps({"unexpected_key": "value"}))
        qt = QuotaTracker(state_path=path)
        assert qt.used_today() == 0

    def test_counter_error_does_not_raise(self, tmp_path: Path) -> None:
        """record_fresh_lookup must never raise, even on write failure."""
        # Simulate a write failure by making the path a directory
        state_path = tmp_path / "quota_dir"
        state_path.mkdir()
        qt2 = QuotaTracker(state_path=state_path)
        # Should not raise
        qt2.record_fresh_lookup()

    def test_used_today_returns_zero_on_read_error(self, tmp_path: Path) -> None:
        state_path = tmp_path / "quota_dir"
        state_path.mkdir()
        qt = QuotaTracker(state_path=state_path)
        assert qt.used_today() == 0


# ---------------------------------------------------------------------------
# Status string
# ---------------------------------------------------------------------------


class TestStatusString:
    def test_status_string_contains_used_and_limit(self, tmp_path: Path) -> None:
        qt = QuotaTracker(state_path=tmp_path / "quota.json", daily_limit=500)
        qt.record_fresh_lookup()
        status = qt.status_line()
        assert "1" in status
        assert "500" in status

    def test_status_string_contains_remaining(self, tmp_path: Path) -> None:
        qt = QuotaTracker(state_path=tmp_path / "quota.json", daily_limit=500)
        for _ in range(10):
            qt.record_fresh_lookup()
        status = qt.status_line()
        assert "490" in status
