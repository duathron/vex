"""Parallel batch processing for multiple IOCs.

Uses ThreadPoolExecutor for concurrent lookups while respecting rate limits.
Falls back to sequential processing if concurrency is not needed.
"""

from __future__ import annotations

import concurrent.futures
import logging
from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from .enrichers.protocol import SecondaryEnricherProtocol

from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from .cache import Cache
from .config import Config
from .ioc_detector import IOCType, detect
from .mitre.mapper import map_to_attack
from .models import InvestigateResult, TriageResult
from .plugins.loader import load_plugins
from .plugins.registry import PluginRegistry

T = TypeVar("T", TriageResult, InvestigateResult)

logger = logging.getLogger("vex.batch")

_MAX_SECONDARY_WORKERS = 8


def run_secondary_enrichers(
    result: InvestigateResult,
    ioc: str,
    ioc_type: str,
    config: Config,
    secondaries: list[SecondaryEnricherProtocol],
) -> None:
    """Run secondary enrichers concurrently, fail-open per enricher.

    Each secondary writes its own distinct fields on *result* (e.g.
    ``abuse_*``, ``shodan_*``, ``misp_*``, ``opencti_*``), so concurrent
    in-place mutation is safe — there is no shared mutable state beyond
    the result object itself.

    With 0 or 1 secondaries the pool is skipped entirely to avoid overhead.
    With 2+ secondaries all calls are dispatched in parallel; one failure
    never prevents the others from running.
    """
    if not secondaries:
        return

    if len(secondaries) == 1:
        try:
            secondaries[0].enrich(result, ioc, ioc_type, config)
        except Exception:
            pass
        return

    workers = min(len(secondaries), _MAX_SECONDARY_WORKERS)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_enrich_one, sec, result, ioc, ioc_type, config): sec for sec in secondaries}
        for future in concurrent.futures.as_completed(futures):
            # Exceptions are already swallowed inside _enrich_one;
            # calling result() here surfaces any unexpected propagation.
            try:
                future.result()
            except Exception:
                pass


def _enrich_one(
    sec: SecondaryEnricherProtocol,
    result: InvestigateResult,
    ioc: str,
    ioc_type: str,
    config: Config,
) -> None:
    """Call one secondary enricher, swallowing any exception (fail-open)."""
    try:
        sec.enrich(result, ioc, ioc_type, config)
    except Exception:
        pass


def _process_single_triage(
    raw_ioc: str,
    registry: PluginRegistry,
    config: Config,
    cache: Cache,
    no_cache: bool,
) -> TriageResult | None:
    """Process one IOC for triage (sync, used by thread pool)."""
    ioc_type, normalised_ioc = detect(raw_ioc)
    if ioc_type == IOCType.UNKNOWN:
        return None

    cache_key = f"triage:{ioc_type.value}:{normalised_ioc}"
    cached = cache.get(cache_key)

    if cached and not no_cache:
        result = TriageResult.model_validate(cached)
        result.from_cache = True
        return result

    plugin = registry.get_plugin(ioc_type.value)
    if plugin is None:
        return None

    try:
        result = plugin.triage(normalised_ioc, ioc_type.value, config)
        cache.set(cache_key, result.model_dump(mode="json"))
        return result
    except Exception as e:
        logger.warning("Failed to process %s: %s", raw_ioc, e)
        return None


def _process_single_investigate(
    raw_ioc: str,
    registry: PluginRegistry,
    config: Config,
    cache: Cache,
    no_cache: bool,
) -> InvestigateResult | None:
    """Process one IOC for investigation (sync, used by thread pool)."""
    ioc_type, normalised_ioc = detect(raw_ioc)
    if ioc_type == IOCType.UNKNOWN:
        return None

    cache_key = f"investigate:{ioc_type.value}:{normalised_ioc}"
    cached = cache.get(cache_key)

    if cached and not no_cache:
        result = InvestigateResult.model_validate(cached)
        result.triage.from_cache = True
        return result

    plugin = registry.get_plugin(ioc_type.value)
    if plugin is None:
        return None

    try:
        result = plugin.investigate(normalised_ioc, ioc_type.value, config)
        result.attack_mappings = map_to_attack(result)
        # Secondary enrichers — run in parallel, fail-open per enricher
        run_secondary_enrichers(
            result,
            normalised_ioc,
            ioc_type.value,
            config,
            registry.get_secondary(ioc_type.value),
        )
        cache.set(cache_key, result.model_dump(mode="json"))
        return result
    except Exception as e:
        logger.warning("Failed to process %s: %s", raw_ioc, e)
        return None


def batch_triage(
    iocs: list[str],
    config: Config,
    no_cache: bool = False,
    max_workers: int = 4,
    show_progress: bool = True,
) -> tuple[list[TriageResult], int]:
    """Run triage on multiple IOCs with optional parallelism + progress bar.

    Returns (results, failed_count).
    """
    results: list[TriageResult] = []

    with Cache(config.cache_db_path, config.cache.ttl_hours, config.cache.enabled and not no_cache) as cache:
        with load_plugins() as registry:
            if show_progress:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("{task.completed}/{task.total}"),
                    TimeElapsedColumn(),
                ) as progress:
                    task = progress.add_task("Triaging IOCs…", total=len(iocs))
                    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
                        futures = {
                            pool.submit(_process_single_triage, ioc, registry, config, cache, no_cache): ioc
                            for ioc in iocs
                        }
                        for future in concurrent.futures.as_completed(futures):
                            result = future.result()
                            if result is not None:
                                results.append(result)
                            progress.advance(task)
            else:
                for ioc in iocs:
                    result = _process_single_triage(ioc, registry, config, cache, no_cache)
                    if result is not None:
                        results.append(result)

    return results, len(iocs) - len(results)


def batch_investigate(
    iocs: list[str],
    config: Config,
    no_cache: bool = False,
    max_workers: int = 4,
    show_progress: bool = True,
) -> tuple[list[InvestigateResult], int]:
    """Run investigation on multiple IOCs with optional parallelism + progress bar.

    Returns (results, failed_count).
    """
    results: list[InvestigateResult] = []

    with Cache(config.cache_db_path, config.cache.ttl_hours, config.cache.enabled and not no_cache) as cache:
        with load_plugins() as registry:
            if show_progress:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("{task.completed}/{task.total}"),
                    TimeElapsedColumn(),
                ) as progress:
                    task = progress.add_task("Investigating IOCs…", total=len(iocs))
                    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
                        futures = {
                            pool.submit(_process_single_investigate, ioc, registry, config, cache, no_cache): ioc
                            for ioc in iocs
                        }
                        for future in concurrent.futures.as_completed(futures):
                            result = future.result()
                            if result is not None:
                                results.append(result)
                            progress.advance(task)
            else:
                for ioc in iocs:
                    result = _process_single_investigate(ioc, registry, config, cache, no_cache)
                    if result is not None:
                        results.append(result)

    return results, len(iocs) - len(results)
