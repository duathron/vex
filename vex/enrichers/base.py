"""Shared helpers for parsing VT API responses."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from ..models import (
    DetectionStats,
    EngineResult,
    RelatedFile,
    Verdict,
)
from ..config import Config


def _ts(unix: Optional[int]) -> Optional[datetime]:
    if unix is None:
        return None
    return datetime.fromtimestamp(unix, tz=timezone.utc)


def parse_stats(raw: dict[str, Any]) -> DetectionStats:
    return DetectionStats(
        malicious=raw.get("malicious", 0),
        suspicious=raw.get("suspicious", 0),
        undetected=raw.get("undetected", 0),
        harmless=raw.get("harmless", 0),
        timeout=raw.get("timeout", 0),
        type_unsupported=raw.get("type-unsupported", 0),
        confirmed_timeout=raw.get("confirmed-timeout", 0),
        failure=raw.get("failure", 0),
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
            flagging.append(EngineResult(
                engine=engine,
                category=category,
                result=data.get("result"),
            ))
    return sorted(flagging, key=lambda e: e.category)[:limit]


def parse_related_files(data: list[dict[str, Any]]) -> list[RelatedFile]:
    files = []
    for item in data:
        attrs = item.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        mal = stats.get("malicious", 0)
        total = sum(stats.values()) if stats else 0
        files.append(RelatedFile(
            sha256=attrs.get("sha256", item.get("id", "")),
            name=(attrs.get("names") or [None])[0],
            detection_ratio=f"{mal}/{total}" if total else None,
        ))
    return files
