"""Tests for run_secondary_enrichers — parallel dispatch helper.

All tests are offline (no network calls). Fake secondaries use time.sleep
to simulate I/O latency so we can assert that wall-clock time is ~1 delay,
not N×delay, when run in parallel.
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock

from vex.batch import run_secondary_enrichers
from vex.config import Config
from vex.models import DetectionStats, InvestigateResult, TriageResult, Verdict


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SLEEP_DELAY = 0.15  # seconds — small enough for a fast test suite


def _make_result() -> InvestigateResult:
    triage = TriageResult(
        ioc="1.2.3.4",
        ioc_type="ipv4",
        verdict=Verdict.MALICIOUS,
        detection_stats=DetectionStats(malicious=5, undetected=65),
    )
    return InvestigateResult(triage=triage)


def _make_config() -> Config:
    cfg = Config()
    cfg.api.key = "fake-key"
    return cfg


def _make_sleeping_secondary(marker_field: str, delay: float = _SLEEP_DELAY) -> MagicMock:
    """Return a fake secondary whose enrich() sleeps *delay* seconds then sets result.<marker_field>."""

    def _enrich(result: InvestigateResult, ioc: str, ioc_type: str, config: Config) -> None:
        time.sleep(delay)
        setattr(result, marker_field, True)

    sec = MagicMock()
    sec.name = marker_field
    sec.supported_ioc_types = ["ipv4"]
    sec.enrich = MagicMock(side_effect=_enrich)
    return sec


def _make_raising_secondary(marker_field: str) -> MagicMock:
    """Return a fake secondary whose enrich() always raises, writing nothing."""

    sec = MagicMock()
    sec.name = marker_field
    sec.supported_ioc_types = ["ipv4"]
    sec.enrich = MagicMock(side_effect=RuntimeError("secondary exploded"))
    return sec


# ---------------------------------------------------------------------------
# Edge cases: 0 and 1 secondary (no thread pool)
# ---------------------------------------------------------------------------

class TestRunSecondaryEnrichersEdgeCases:
    def test_zero_secondaries_is_noop(self) -> None:
        result = _make_result()
        cfg = _make_config()
        # Must not raise and result stays unchanged
        run_secondary_enrichers(result, "1.2.3.4", "ipv4", cfg, [])
        # Nothing was mutated; absence of error is the assertion
        assert result.abuse_confidence is None

    def test_one_secondary_runs_inline(self) -> None:
        result = _make_result()
        cfg = _make_config()
        sec = _make_sleeping_secondary("abuse_confidence")

        # abuse_confidence is normally an int; we set True here just as a marker
        # that the enricher ran.  It is Optional[int] so pydantic accepts None;
        # we bypass model validation by mutating the object attribute directly.
        run_secondary_enrichers(result, "1.2.3.4", "ipv4", cfg, [sec])

        assert getattr(result, "abuse_confidence") is True
        sec.enrich.assert_called_once()

    def test_one_secondary_raising_does_not_propagate(self) -> None:
        result = _make_result()
        cfg = _make_config()
        sec = _make_raising_secondary("abuse_confidence")

        # Must not raise
        run_secondary_enrichers(result, "1.2.3.4", "ipv4", cfg, [sec])

        # Marker was never set (enricher failed)
        assert result.abuse_confidence is None


# ---------------------------------------------------------------------------
# Parallel execution: N secondaries, wall-time ≈ 1 delay (not N×delay)
# ---------------------------------------------------------------------------

class TestRunSecondaryEnrichersParallel:
    def test_all_markers_set_when_parallel(self) -> None:
        """All N enrichers must run and write their markers."""
        result = _make_result()
        cfg = _make_config()

        # Use extra model fields that accept any assignment via __dict__
        # (Pydantic v2 models allow extra attribute writes on the object).
        # We use the four real secondary-enricher marker fields from InvestigateResult.
        secondaries = [
            _make_sleeping_secondary("abuse_confidence"),   # abuse_*
            _make_sleeping_secondary("shodan_org"),         # shodan_*
            _make_sleeping_secondary("misp_known"),         # misp_*
            _make_sleeping_secondary("opencti_known"),      # opencti_*
        ]

        run_secondary_enrichers(result, "1.2.3.4", "ipv4", cfg, secondaries)

        assert getattr(result, "abuse_confidence") is True
        assert getattr(result, "shodan_org") is True
        assert getattr(result, "misp_known") is True
        assert getattr(result, "opencti_known") is True

    def test_parallel_is_faster_than_sequential(self) -> None:
        """Wall-clock time must be closer to 1×delay than N×delay.

        With N=4 secondaries each sleeping SLEEP_DELAY seconds:
          Sequential: ~4 × SLEEP_DELAY
          Parallel:   ~1 × SLEEP_DELAY  (bounded by the slowest single call)

        Assertion: elapsed < (N-1) × delay  — proves concurrency.
        """
        n = 4
        delay = _SLEEP_DELAY
        result = _make_result()
        cfg = _make_config()

        secondaries = [
            _make_sleeping_secondary("abuse_confidence"),
            _make_sleeping_secondary("shodan_org"),
            _make_sleeping_secondary("misp_known"),
            _make_sleeping_secondary("opencti_known"),
        ]

        t0 = time.perf_counter()
        run_secondary_enrichers(result, "1.2.3.4", "ipv4", cfg, secondaries)
        elapsed = time.perf_counter() - t0

        sequential_lower_bound = (n - 1) * delay  # ~0.45 s for n=4, delay=0.15
        assert elapsed < sequential_lower_bound, (
            f"Expected parallel elapsed ({elapsed:.3f}s) < "
            f"(N-1)×delay ({sequential_lower_bound:.3f}s). "
            f"Secondaries appear to be running sequentially."
        )

    def test_one_failing_does_not_stop_others(self) -> None:
        """A raising secondary must not prevent the rest from completing."""
        result = _make_result()
        cfg = _make_config()

        secondaries = [
            _make_sleeping_secondary("abuse_confidence"),
            _make_raising_secondary("shodan_org"),      # raises — should be swallowed
            _make_sleeping_secondary("misp_known"),
            _make_sleeping_secondary("opencti_known"),
        ]

        # Must not raise
        run_secondary_enrichers(result, "1.2.3.4", "ipv4", cfg, secondaries)

        # The three non-raising enrichers must have run
        assert getattr(result, "abuse_confidence") is True
        assert getattr(result, "misp_known") is True
        assert getattr(result, "opencti_known") is True
        # The raising enricher's marker was never written
        assert result.shodan_org is None

    def test_all_raising_returns_cleanly(self) -> None:
        """If every secondary raises the helper must still return without error."""
        result = _make_result()
        cfg = _make_config()

        secondaries = [
            _make_raising_secondary("abuse_confidence"),
            _make_raising_secondary("shodan_org"),
            _make_raising_secondary("misp_known"),
        ]

        run_secondary_enrichers(result, "1.2.3.4", "ipv4", cfg, secondaries)

        # Nothing mutated
        assert result.abuse_confidence is None
        assert result.shodan_org is None
        assert result.misp_known is False  # model default
