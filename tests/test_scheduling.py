"""Tests for vex.scheduling — rate-limit-aware scheduling helpers (v1.4.0).

All tests are deterministic and network-free.
"""

from __future__ import annotations

from typing import Any

from vex.config import ApiConfig, Config
from vex.models import DetectionStats, InvestigateResult, TriageResult, Verdict
from vex.scheduling import (
    count_cache_hits,
    estimate_eta,
    format_batch_summary,
    partition_by_cache,
)


# ---------------------------------------------------------------------------
# Helpers / Factories
# ---------------------------------------------------------------------------

def _make_config(tier: str = "free") -> Config:
    """Build a Config with the given tier, no filesystem side-effects."""
    cfg = Config()
    cfg.api = ApiConfig(tier=tier)
    return cfg


def _make_triage_result(ioc: str = "1.2.3.4", from_cache: bool = False) -> TriageResult:
    return TriageResult(
        ioc=ioc,
        ioc_type="ipv4",
        verdict=Verdict.CLEAN,
        detection_stats=DetectionStats(malicious=0, suspicious=0, undetected=10, harmless=0),
        from_cache=from_cache,
    )


def _make_investigate_result(ioc: str = "1.2.3.4", from_cache: bool = False) -> InvestigateResult:
    triage = _make_triage_result(ioc=ioc, from_cache=from_cache)
    return InvestigateResult(triage=triage)


# ---------------------------------------------------------------------------
# Part A — estimate_eta
# ---------------------------------------------------------------------------

class TestEstimateEta:
    def test_free_tier_small_n(self) -> None:
        """8 IOCs at 4 req/min → 2 minutes."""
        cfg = _make_config("free")
        result = estimate_eta(8, cfg)
        assert "8 IOCs" in result
        assert "free" in result
        assert "4 req/min" in result
        assert "2m" in result

    def test_free_tier_large_n(self) -> None:
        """420 IOCs at 4 req/min → 105 minutes = 1h45m."""
        cfg = _make_config("free")
        result = estimate_eta(420, cfg)
        assert "420 IOCs" in result
        assert "1h45m" in result

    def test_free_tier_exact_hour(self) -> None:
        """240 IOCs at 4 req/min → exactly 60 minutes = 1h."""
        cfg = _make_config("free")
        result = estimate_eta(240, cfg)
        assert "1h" in result
        # Should NOT show 1h00m — we show ≤ 1h when mins==0
        assert "1h00m" not in result

    def test_premium_tier_large_n(self) -> None:
        """1000 IOCs at 1000 req/min → 1 minute."""
        cfg = _make_config("premium")
        result = estimate_eta(1000, cfg)
        assert "premium" in result
        assert "1000 req/min" in result
        assert "≤ 1m" in result

    def test_premium_tier_small_n(self) -> None:
        """50 IOCs at 1000 req/min → less than 1 minute (rounds up to 1m)."""
        cfg = _make_config("premium")
        result = estimate_eta(50, cfg)
        assert "premium" in result
        assert "≤ 1m" in result

    def test_includes_cache_hint(self) -> None:
        """ETA string must mention cache hits reduce the time."""
        cfg = _make_config("free")
        result = estimate_eta(10, cfg)
        assert "cache hits reduce this" in result

    def test_free_tier_fractional_rounds_up(self) -> None:
        """5 IOCs at 4 req/min → 1.25 minutes → rounds up to 2m."""
        cfg = _make_config("free")
        result = estimate_eta(5, cfg)
        assert "≤ 2m" in result

    def test_free_tier_90_minutes(self) -> None:
        """360 IOCs at 4 req/min → 90 minutes = 1h30m."""
        cfg = _make_config("free")
        result = estimate_eta(360, cfg)
        assert "1h30m" in result


# ---------------------------------------------------------------------------
# Part B — count_cache_hits / format_batch_summary
# ---------------------------------------------------------------------------

class TestCountCacheHits:
    def test_all_fresh_triage(self) -> None:
        results = [_make_triage_result(from_cache=False) for _ in range(5)]
        fresh, cached = count_cache_hits(results)
        assert fresh == 5
        assert cached == 0

    def test_all_cached_triage(self) -> None:
        results = [_make_triage_result(from_cache=True) for _ in range(5)]
        fresh, cached = count_cache_hits(results)
        assert fresh == 0
        assert cached == 5

    def test_mixed_triage(self) -> None:
        results = (
            [_make_triage_result(from_cache=True) for _ in range(3)]
            + [_make_triage_result(from_cache=False) for _ in range(7)]
        )
        fresh, cached = count_cache_hits(results)
        assert fresh == 7
        assert cached == 3

    def test_mixed_investigate(self) -> None:
        results = (
            [_make_investigate_result(from_cache=True) for _ in range(2)]
            + [_make_investigate_result(from_cache=False) for _ in range(3)]
        )
        fresh, cached = count_cache_hits(results)
        assert fresh == 3
        assert cached == 2

    def test_empty_list(self) -> None:
        fresh, cached = count_cache_hits([])
        assert fresh == 0
        assert cached == 0


class TestFormatBatchSummary:
    def test_no_failures(self) -> None:
        line = format_batch_summary(420, 0, 380, 40)
        assert "420 processed" in line
        assert "380 from API" in line
        assert "40 cached" in line
        # No "failed" when there are none
        assert "failed" not in line

    def test_with_failures(self) -> None:
        line = format_batch_summary(420, 3, 380, 37)
        assert "420 processed" in line
        assert "3 failed" in line

    def test_all_cached(self) -> None:
        line = format_batch_summary(10, 0, 0, 10)
        assert "0 from API" in line
        assert "10 cached" in line


# ---------------------------------------------------------------------------
# Part C — partition_by_cache
# ---------------------------------------------------------------------------

class FakeCache:
    """Minimal in-memory cache stub for partition tests."""

    def __init__(self, cached_keys: set[str]):
        self._cached = cached_keys

    def get(self, key: str):
        return {"stub": True} if key in self._cached else None

    def set(self, key: str, value: Any) -> None:  # noqa: ARG002
        pass

    def close(self) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class TestPartitionByCache:
    """Tests for partition_by_cache — no network, uses FakeCache."""

    # IOCs used across tests (valid types that detect() recognises)
    _IPV4S = [f"10.0.0.{i}" for i in range(1, 11)]  # 10 IOCs

    def _cache_keys_for(self, iocs: list[str], mode: str) -> set[str]:
        """Compute the exact cache keys the partition helper would use."""
        from vex.ioc_detector import detect as _detect
        keys = set()
        for raw in iocs:
            ioc_type, norm = _detect(raw)
            keys.add(f"{mode}:{ioc_type.value}:{norm}")
        return keys

    # --- basic partition ---

    def test_all_uncached_no_quota(self) -> None:
        cache = FakeCache(set())
        cached, quota, skipped = partition_by_cache(
            self._IPV4S, cache, "triage", False, None
        )
        assert len(cached) == 0
        assert len(quota) == 10
        assert len(skipped) == 0

    def test_all_cached_no_quota(self) -> None:
        keys = self._cache_keys_for(self._IPV4S, "triage")
        cache = FakeCache(keys)
        cached, quota, skipped = partition_by_cache(
            self._IPV4S, cache, "triage", False, None
        )
        assert len(cached) == 10
        assert len(quota) == 0
        assert len(skipped) == 0

    def test_mixed_no_quota(self) -> None:
        first_5 = self._IPV4S[:5]
        keys = self._cache_keys_for(first_5, "triage")
        cache = FakeCache(keys)
        cached, quota, skipped = partition_by_cache(
            self._IPV4S, cache, "triage", False, None
        )
        assert len(cached) == 5
        assert len(quota) == 5
        assert len(skipped) == 0

    # --- max_quota enforcement ---

    def test_max_quota_caps_uncached(self) -> None:
        """With 10 uncached IOCs and max_quota=3, only 3 get quota, 7 are skipped."""
        cache = FakeCache(set())
        cached, quota, skipped = partition_by_cache(
            self._IPV4S, cache, "triage", False, 3
        )
        assert len(cached) == 0
        assert len(quota) == 3
        assert len(skipped) == 7

    def test_cached_always_served_with_quota(self) -> None:
        """Cached IOCs bypass the quota: they are always in the cached bucket."""
        first_6 = self._IPV4S[:6]
        keys = self._cache_keys_for(first_6, "triage")
        cache = FakeCache(keys)
        cached, quota, skipped = partition_by_cache(
            self._IPV4S, cache, "triage", False, 2
        )
        # 6 cached, 2 out of 4 uncached go to quota, 2 skipped
        assert len(cached) == 6
        assert len(quota) == 2
        assert len(skipped) == 2

    def test_max_quota_zero_skips_all_uncached(self) -> None:
        cache = FakeCache(set())
        cached, quota, skipped = partition_by_cache(
            self._IPV4S, cache, "triage", False, 0
        )
        assert len(cached) == 0
        assert len(quota) == 0
        assert len(skipped) == 10

    def test_max_quota_larger_than_uncached(self) -> None:
        """max_quota > uncached count → all uncached go to quota, none skipped."""
        cache = FakeCache(set())
        cached, quota, skipped = partition_by_cache(
            self._IPV4S, cache, "triage", False, 100
        )
        assert len(quota) == 10
        assert len(skipped) == 0

    # --- no_cache flag ---

    def test_no_cache_treats_all_as_uncached(self) -> None:
        """When no_cache=True, even keys that exist in cache are treated as uncached."""
        keys = self._cache_keys_for(self._IPV4S, "triage")
        cache = FakeCache(keys)
        cached, quota, skipped = partition_by_cache(
            self._IPV4S, cache, "triage", True, None
        )
        # no_cache=True: nothing should appear as cached
        assert len(cached) == 0
        assert len(quota) == 10

    def test_no_cache_quota_applies_to_all(self) -> None:
        """With no_cache=True and max_quota=3, first 3 get quota, 7 skipped."""
        keys = self._cache_keys_for(self._IPV4S, "triage")
        cache = FakeCache(keys)
        cached, quota, skipped = partition_by_cache(
            self._IPV4S, cache, "triage", True, 3
        )
        assert len(cached) == 0
        assert len(quota) == 3
        assert len(skipped) == 7

    # --- investigate mode ---

    def test_investigate_mode_uses_correct_cache_key(self) -> None:
        """partition_by_cache works correctly with mode='investigate'."""
        iocs = ["8.8.8.8"]
        from vex.ioc_detector import detect as _detect
        ioc_type, norm = _detect("8.8.8.8")
        key = f"investigate:{ioc_type.value}:{norm}"
        cache_hit = FakeCache({key})
        cache_miss = FakeCache(set())

        cached_h, quota_h, _ = partition_by_cache(iocs, cache_hit, "investigate", False, None)
        cached_m, quota_m, _ = partition_by_cache(iocs, cache_miss, "investigate", False, None)

        assert len(cached_h) == 1 and len(quota_h) == 0
        assert len(cached_m) == 0 and len(quota_m) == 1

    # --- empty list ---

    def test_empty_ioc_list(self) -> None:
        cache = FakeCache(set())
        cached, quota, skipped = partition_by_cache([], cache, "triage", False, 10)
        assert cached == []
        assert quota == []
        assert skipped == []
