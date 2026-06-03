"""Rate-limit-aware scheduling helpers (v1.4.0).

Provides:
- estimate_eta: human-readable worst-case ETA before a batch run
- count_cache_hits: split a finished result list into cached/fresh counts
- partition_by_cache: pre-check which IOCs are already cached to enforce --max-quota
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Union

from .cache import Cache
from .config import Config
from .ioc_detector import IOCType, detect
from .models import InvestigateResult, TriageResult

if TYPE_CHECKING:
    pass


# ---------------------------------------------------------------------------
# Part A — Up-front ETA
# ---------------------------------------------------------------------------


def estimate_eta(n_iocs: int, config: Config) -> str:
    """Return a human-readable worst-case ETA string for a batch run.

    Assumes all IOCs require fresh API calls (cache hits reduce the actual time).
    Example output: "420 IOCs · tier: free (4 req/min) · est. ≤ 1h45m (cache hits reduce this)"
    """
    tier = config.rate_limit
    rpm = tier.requests_per_minute
    tier_name = "premium" if config.is_premium else "free"

    worst_case_minutes = n_iocs / rpm  # float

    # Format the duration compactly
    if worst_case_minutes < 60:
        # Round up to nearest minute, minimum 1 minute display
        minutes_int = max(1, int(worst_case_minutes + 0.999))
        duration = f"≤ {minutes_int}m"
    else:
        total_minutes = int(worst_case_minutes + 0.999)
        hours = total_minutes // 60
        mins = total_minutes % 60
        if mins == 0:
            duration = f"≤ {hours}h"
        else:
            duration = f"≤ {hours}h{mins:02d}m"

    return f"{n_iocs} IOCs · tier: {tier_name} ({rpm} req/min) · est. {duration} (cache hits reduce this)"


# ---------------------------------------------------------------------------
# Part B — Cache vs fresh counters
# ---------------------------------------------------------------------------


def count_cache_hits(
    results: list[Union[TriageResult, InvestigateResult]],
) -> tuple[int, int]:
    """Return (from_api_count, from_cache_count) for a list of results.

    Works for both TriageResult and InvestigateResult (which nests triage).
    """
    cached = 0
    for r in results:
        if isinstance(r, InvestigateResult):
            if r.triage.from_cache:
                cached += 1
        else:
            if r.from_cache:  # type: ignore[union-attr]
                cached += 1
    fresh = len(results) - cached
    return fresh, cached


def format_batch_summary(
    processed: int,
    failed_count: int,
    from_api: int,
    from_cache: int,
) -> str:
    """Build the post-batch stderr summary line.

    Example: "420 processed (380 from API, 40 cached), 3 failed"
    """
    parts = f"{processed} processed ({from_api} from API, {from_cache} cached)"
    if failed_count:
        parts += f", {failed_count} failed"
    return parts


# ---------------------------------------------------------------------------
# Part C — --max-quota partition
# ---------------------------------------------------------------------------


def partition_by_cache(
    iocs: list[str],
    cache: Cache,
    mode: str,  # "triage" or "investigate"
    no_cache: bool,
    max_quota: int | None,
) -> tuple[list[str], list[str], list[str]]:
    """Split IOCs into three buckets for --max-quota enforcement.

    Returns:
        (cached_iocs, quota_iocs, skipped_iocs)

        cached_iocs  — already in cache; always served (no quota cost)
        quota_iocs   — not cached; will be processed (up to max_quota)
        skipped_iocs — not cached; exceed max_quota budget; NOT processed

    When max_quota is None all uncached IOCs go to quota_iocs and
    skipped_iocs is empty (same behaviour as today, but with pre-check).

    When no_cache is True nothing counts as cached (quota covers everything).
    """
    cached_iocs: list[str] = []
    uncached_iocs: list[str] = []

    for raw_ioc in iocs:
        ioc_type, normalised_ioc = detect(raw_ioc)
        if ioc_type == IOCType.UNKNOWN:
            # Unknown IOCs will just fail during processing — put in uncached
            uncached_iocs.append(raw_ioc)
            continue

        if no_cache:
            uncached_iocs.append(raw_ioc)
            continue

        cache_key = f"{mode}:{ioc_type.value}:{normalised_ioc}"
        hit = cache.get(cache_key)
        if hit is not None:
            cached_iocs.append(raw_ioc)
        else:
            uncached_iocs.append(raw_ioc)

    if max_quota is None:
        return cached_iocs, uncached_iocs, []

    # Apply quota cap to uncached IOCs
    quota_iocs = uncached_iocs[:max_quota]
    skipped_iocs = uncached_iocs[max_quota:]
    return cached_iocs, quota_iocs, skipped_iocs
