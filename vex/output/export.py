"""JSON and CSV export of enrichment results."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from typing import Any, Union

from ..models import InvestigateResult, TriageResult


def _default(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def to_json(result: Union[TriageResult, InvestigateResult], indent: int = 2) -> str:
    data = result.model_dump(mode="json")
    return json.dumps(data, indent=indent, default=_default, ensure_ascii=False)


def to_json_list(results: list[Union[TriageResult, InvestigateResult]], indent: int = 2) -> str:
    data = [r.model_dump(mode="json") for r in results]
    return json.dumps(data, indent=indent, default=_default, ensure_ascii=False)


def to_csv_triage(results: list[TriageResult]) -> str:
    """Flatten triage results to CSV."""
    out = io.StringIO()
    fields = [
        "ioc", "ioc_type", "verdict",
        "malicious", "suspicious", "undetected", "total",
        "ratio", "malware_families", "categories", "tags",
        "first_seen", "last_seen", "last_analysis_date",
        "reputation", "from_cache", "error",
    ]
    writer = csv.DictWriter(out, fieldnames=fields)
    writer.writeheader()
    for r in results:
        writer.writerow({
            "ioc": r.ioc,
            "ioc_type": r.ioc_type,
            "verdict": r.verdict.value,
            "malicious": r.detection_stats.malicious,
            "suspicious": r.detection_stats.suspicious,
            "undetected": r.detection_stats.undetected,
            "total": r.detection_stats.total,
            "ratio": r.detection_stats.ratio_str,
            "malware_families": "|".join(r.malware_families),
            "categories": "|".join(r.categories),
            "tags": "|".join(r.tags),
            "first_seen": r.first_seen.isoformat() if r.first_seen else "",
            "last_seen": r.last_seen.isoformat() if r.last_seen else "",
            "last_analysis_date": r.last_analysis_date.isoformat() if r.last_analysis_date else "",
            "reputation": r.reputation if r.reputation is not None else "",
            "from_cache": r.from_cache,
            "error": r.error or "",
        })
    return out.getvalue()
