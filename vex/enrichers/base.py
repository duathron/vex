"""Shared helpers for parsing VT API responses."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from ..config import Config
from ..models import (
    DetectionStats,
    EngineResult,
    RelatedFile,
    Verdict,
)


def safe_timestamp(value: object) -> Optional[datetime]:
    """Return a UTC datetime from a unix timestamp, or None if value isn't a sane number."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc)
    except (ValueError, OSError, OverflowError):
        return None


def safe_int(value: object) -> Optional[int]:
    """Return int from value, or None if it cannot be coerced (never raises)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _ts(unix: object) -> Optional[datetime]:
    return safe_timestamp(unix)


def parse_stats(raw: dict[str, Any]) -> DetectionStats:
    return DetectionStats(
        malicious=safe_int(raw.get("malicious")) or 0,
        suspicious=safe_int(raw.get("suspicious")) or 0,
        undetected=safe_int(raw.get("undetected")) or 0,
        harmless=safe_int(raw.get("harmless")) or 0,
        timeout=safe_int(raw.get("timeout")) or 0,
        type_unsupported=safe_int(raw.get("type-unsupported")) or 0,
        confirmed_timeout=safe_int(raw.get("confirmed-timeout")) or 0,
        failure=safe_int(raw.get("failure")) or 0,
    )


def compute_verdict(stats: DetectionStats, config: Config) -> Verdict:
    thr = config.thresholds
    if stats.malicious >= thr.malicious_min_detections:
        return Verdict.MALICIOUS
    if stats.malicious >= thr.suspicious_min_detections or stats.suspicious >= thr.suspicious_min_detections:
        return Verdict.SUSPICIOUS
    if stats.total < thr.min_engines_for_clean:
        return Verdict.UNKNOWN
    return Verdict.CLEAN


def extract_malware_families(results: dict[str, Any]) -> list[str]:
    """Collect malware family names from engine results (majority vote)."""
    names: dict[str, int] = {}
    for engine_data in results.values():
        result = engine_data.get("result")
        if result and engine_data.get("category") in ("malicious", "suspicious"):
            # Normalize: take last part after "/" or "." for family name
            family = result.strip()
            names[family] = names.get(family, 0) + 1
    # Return top names (≥2 engines agree, sorted by count)
    return [name for name, count in sorted(names.items(), key=lambda x: -x[1]) if count >= 2]


def extract_flagging_engines(results: dict[str, Any], limit: int = 10) -> list[EngineResult]:
    """Return engines that flagged as malicious or suspicious."""
    flagging = []
    for engine, data in results.items():
        category = data.get("category", "")
        if category in ("malicious", "suspicious"):
            flagging.append(
                EngineResult(
                    engine=engine,
                    category=category,
                    result=data.get("result"),
                )
            )
    return sorted(flagging, key=lambda e: e.category)[:limit]


def parse_related_files(data: list[dict[str, Any]]) -> list[RelatedFile]:
    files = []
    for item in data:
        attrs = item.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        mal = stats.get("malicious", 0)
        total = sum(stats.values()) if stats else 0
        files.append(
            RelatedFile(
                sha256=attrs.get("sha256", item.get("id", "")),
                name=(attrs.get("names") or [None])[0],
                detection_ratio=f"{mal}/{total}" if total else None,
            )
        )
    return files
