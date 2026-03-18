"""barb → vex pipeline bridge.

Parses barb JSON output (single result or array) into BarbContext objects,
which vex uses to display barb pre-scan context alongside VT enrichment.

Typical usage::

    barb analyze https://evil.com -o json | vex triage --from-barb
    barb analyze https://evil.com -o json | vex investigate --from-barb -o rich
"""

from __future__ import annotations

import json
import logging
from typing import Optional

from pydantic import BaseModel

logger = logging.getLogger("vex.pipeline")


class BarbSignal(BaseModel):
    """A single heuristic signal from barb."""

    analyzer: str
    severity: str  # INFO / LOW / MEDIUM / HIGH / CRITICAL
    label: str
    detail: str
    weight: float = 1.0


class BarbContext(BaseModel):
    """Lightweight barb result passed through to the formatter."""

    url: str
    verdict: str        # barb RiskVerdict: SAFE / LOW_RISK / SUSPICIOUS / HIGH_RISK / PHISHING
    risk_score: float
    signals: list[BarbSignal] = []
    defanged_url: Optional[str] = None
    explanation: Optional[str] = None

    @property
    def top_signals(self) -> list[BarbSignal]:
        """Return up to 5 signals sorted by severity (highest first)."""
        _order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        return sorted(
            self.signals,
            key=lambda s: _order.get(s.severity.upper(), 0),
            reverse=True,
        )[:5]


def parse_barb_json(raw: str) -> list[BarbContext]:
    """Parse barb JSON output (single result or array) into list[BarbContext].

    Accepts both single-object and array formats::

        {"url": "https://evil.com", "verdict": "PHISHING", ...}
        [{"url": ..., "verdict": ...}, ...]

    Entries that cannot be parsed are skipped with a warning.
    """
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON from barb: {e}") from e

    items = data if isinstance(data, list) else [data]
    results: list[BarbContext] = []

    for item in items:
        if not isinstance(item, dict):
            logger.warning("Skipping non-dict barb entry: %r", item)
            continue
        try:
            raw_signals = item.get("signals", [])
            signals = []
            for s in raw_signals:
                try:
                    signals.append(BarbSignal(
                        analyzer=s.get("analyzer", ""),
                        severity=s.get("severity", "INFO"),
                        label=s.get("label", ""),
                        detail=s.get("detail", ""),
                        weight=float(s.get("weight", 1.0)),
                    ))
                except Exception as se:
                    logger.debug("Skipping barb signal: %s", se)

            results.append(BarbContext(
                url=item["url"],
                verdict=str(item.get("verdict", "UNKNOWN")),
                risk_score=float(item.get("risk_score", 0.0)),
                signals=signals,
                defanged_url=item.get("defanged_url"),
                explanation=item.get("explanation"),
            ))
        except (KeyError, ValueError) as e:
            logger.warning("Skipping invalid barb entry: %s", e)

    return results
