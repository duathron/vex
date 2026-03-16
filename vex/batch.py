"""Parallel batch processing for multiple IOCs.

Uses ThreadPoolExecutor for concurrent lookups while respecting rate limits.
Falls back to sequential processing if concurrency is not needed.
"""

from __future__ import annotations

import concurrent.futures
import logging
from typing import TypeVar

from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from .cache import Cache
from .client import VTClient
from .config import Config
from .ioc_detector import IOCType, detect, is_hash
from .mitre.mapper import map_to_attack
from .models import InvestigateResult, TriageResult

T = TypeVar("T", TriageResult, InvestigateResult)

logger = logging.getLogger("vex.batch")


def _resolve_enricher(ioc_type: IOCType):
    """Return the correct enricher module for an IOC type."""
    from .enrichers import (
        domain as domain_enricher,
        hash as hash_enricher,
        ip as ip_enricher,
        url as url_enricher,
    )
    if is_hash(ioc_type):
        return hash_enricher
    if ioc_type in (IOCType.IPV4, IOCType.IPV6):
        return ip_enricher
    if ioc_type == IOCType.DOMAIN:
        return domain_enricher
    if ioc_type == IOCType.URL:
        return url_enricher
    return None


def _process_single_triage(
    raw_ioc: str,
    client: VTClient,
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

    enricher = _resolve_enricher(ioc_type)
    if enricher is None:
        return None

    try:
        result = enricher.triage(normalised_ioc, ioc_type.value, client, config)
        cache.set(cache_key, result.model_dump(mode="json"))
        return result
    except Exception as e:
        logger.warning("Failed to process %s: %s", raw_ioc, e)
        return None


def _process_single_investigate(
    raw_ioc: str,
    client: VTClient,
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

    enricher = _resolve_enricher(ioc_type)
    if enricher is None:
        return None

    try:
        result = enricher.investigate(normalised_ioc, ioc_type.value, client, config)
        result.attack_mappings = map_to_attack(result)
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
        with VTClient(config) as client:
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
                            pool.submit(_process_single_triage, ioc, client, config, cache, no_cache): ioc
                            for ioc in iocs
                        }
                        for future in concurrent.futures.as_completed(futures):
                            result = future.result()
                            if result is not None:
                                results.append(result)
                            progress.advance(task)
            else:
                for ioc in iocs:
                    result = _process_single_triage(ioc, client, config, cache, no_cache)
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
        with VTClient(config) as client:
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
                            pool.submit(_process_single_investigate, ioc, client, config, cache, no_cache): ioc
                            for ioc in iocs
                        }
                        for future in concurrent.futures.as_completed(futures):
                            result = future.result()
                            if result is not None:
                                results.append(result)
                            progress.advance(task)
            else:
                for ioc in iocs:
                    result = _process_single_investigate(ioc, client, config, cache, no_cache)
                    if result is not None:
                        results.append(result)

    return results, len(iocs) - len(results)
