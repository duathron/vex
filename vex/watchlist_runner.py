"""Watchlist re-triage logic (V2).

Provides ``retriage_watchlist`` — compares each IOC in a named watchlist
against its cached prior verdict and reports verdict *worsening* diffs.
Quota-thrifty: uses the existing cache; only re-looks-up the watchlist-sized set.
Fail-open: triage errors per IOC are swallowed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

from .cache import Cache
from .config import Config
from .ioc_detector import IOCType, detect
from .knowledge.db import KnowledgeDB
from .models import TriageResult, Verdict

if TYPE_CHECKING:
    from .quota_tracker import QuotaTracker

logger = logging.getLogger("vex.watchlist_runner")


@dataclass
class VerdictDiff:
    """A single IOC whose verdict worsened between runs."""

    ioc: str
    old_verdict: Verdict
    new_verdict: Verdict

    def as_dict(self) -> dict:
        return {
            "ioc": self.ioc,
            "old_verdict": self.old_verdict,
            "new_verdict": self.new_verdict,
        }


@dataclass
class WatchlistRunResult:
    """Aggregated outcome of ``retriage_watchlist``."""

    watchlist_name: str
    total: int = 0
    unchanged: int = 0
    worsened: int = 0
    improved: int = 0
    cache_misses: int = 0
    errors: int = 0
    diffs: list[dict] = field(default_factory=list)

    @property
    def has_worsening(self) -> bool:
        return self.worsened > 0


def _triage_ioc(ioc: str, config: Config) -> Optional[TriageResult]:
    """Run a fresh VT triage lookup for one IOC.  Returns None on failure.

    NOTE: This function is the seam for mocking in tests.
    """
    from .plugins.loader import load_plugins

    ioc_type, normalised_ioc = detect(ioc)
    if ioc_type == IOCType.UNKNOWN:
        return None

    try:
        with load_plugins() as registry:
            plugin = registry.get_plugin(ioc_type.value)
            if plugin is None:
                return None
            return plugin.triage(normalised_ioc, ioc_type.value, config)
    except Exception as exc:
        logger.debug("watchlist_runner: triage failed for %s: %s", ioc, exc)
        return None


def retriage_watchlist(
    name: str,
    db: KnowledgeDB,
    cache: Cache,
    config: Config,
    quota_tracker: Optional["QuotaTracker"] = None,
) -> WatchlistRunResult:
    """Re-triage every IOC in *name* and return a ``WatchlistRunResult``.

    For each IOC:
    1. Read prior verdict from cache (if present).
    2. Run a fresh triage (goes to VT; the caller is responsible for
       opening the Cache with the right ttl/enabled settings).
    3. Compare old vs new verdict.  Worsening = new.severity > old.severity.
    4. Update the cache with the fresh result.

    Fail-open per IOC: exceptions are logged at DEBUG level and counted
    in ``result.errors``.
    """
    result = WatchlistRunResult(watchlist_name=name)
    iocs = db.get_watchlist(name)
    result.total = len(iocs)

    for ioc in iocs:
        try:
            ioc_type, normalised_ioc = detect(ioc)
            if ioc_type == IOCType.UNKNOWN:
                result.errors += 1
                continue

            cache_key = f"triage:{ioc_type.value}:{normalised_ioc}"

            # Read prior verdict from cache
            prior_data = cache.get(cache_key)
            prior_verdict: Optional[Verdict] = None
            if prior_data:
                try:
                    prior_result = TriageResult.model_validate(prior_data)
                    prior_verdict = prior_result.verdict
                except Exception:
                    pass

            # Fresh lookup (bypasses cache via _triage_ioc which doesn't read cache)
            fresh = _triage_ioc(normalised_ioc, config)
            if fresh is None:
                result.errors += 1
                continue

            # Record fresh VT lookup against the daily quota counter (fail-open).
            if quota_tracker is not None:
                try:
                    quota_tracker.record_fresh_lookup()
                except Exception:
                    pass

            # Store fresh result in cache (overwrites prior)
            cache.set(cache_key, fresh.model_dump(mode="json"))

            if prior_verdict is None:
                # No prior data → this is a new entry, count as cache miss
                result.cache_misses += 1
                continue

            old_sev = prior_verdict.severity
            new_sev = fresh.verdict.severity

            if new_sev > old_sev:
                result.worsened += 1
                result.diffs.append(
                    {
                        "ioc": ioc,
                        "old_verdict": prior_verdict,
                        "new_verdict": fresh.verdict,
                    }
                )
            elif new_sev < old_sev:
                result.improved += 1
            else:
                result.unchanged += 1

        except Exception as exc:
            logger.debug("watchlist_runner: error processing %s: %s", ioc, exc)
            result.errors += 1

    return result
