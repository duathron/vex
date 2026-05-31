"""sift → vex pipeline bridge.

Parses sift JSON output (TriageReport or bare cluster list) and extracts all
IOCs for enrichment by vex.

Typical usage::

    sift triage alerts.json -o json | vex triage --from-sift
    sift triage alerts.json -o json | vex investigate --from-sift -o rich
"""

from __future__ import annotations

import json
import logging

logger = logging.getLogger("vex.pipeline")


def extract_iocs_from_sift(raw: str) -> list[str]:
    """Parse sift JSON output and return a deduped, order-preserving list of IOCs.

    Accepts two formats::

        # Full TriageReport (recommended)
        {"clusters": [...], "summary": {...}}

        # Bare list of clusters
        [{"id": "...", "iocs": [...], "alerts": [...]}, ...]

    For each cluster, collects:
    - ``cluster.iocs[]``
    - ``cluster.alerts[].iocs[]``
    - ``cluster.alerts[].source_ip``
    - ``cluster.alerts[].dest_ip``

    Missing or null fields are skipped gracefully. Empty strings are skipped.
    Duplicates are removed while preserving first-seen order.

    Raises:
        ValueError: If *raw* is not valid JSON.
    """
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON from sift: {e}") from e

    # Accept full TriageReport (dict with "clusters") or bare list of clusters.
    if isinstance(data, dict):
        clusters = data.get("clusters") or []
    elif isinstance(data, list):
        clusters = data
    else:
        logger.warning("Unexpected sift JSON root type %r — expected dict or list", type(data).__name__)
        clusters = []

    seen: set[str] = set()
    result: list[str] = []

    def _add(value: object) -> None:
        if not isinstance(value, str) or not value.strip():
            return
        ioc = value.strip()
        if ioc not in seen:
            seen.add(ioc)
            result.append(ioc)

    for cluster in clusters:
        if not isinstance(cluster, dict):
            logger.warning("Skipping non-dict cluster entry: %r", cluster)
            continue

        # cluster-level IOC list
        for ioc in cluster.get("iocs") or []:
            _add(ioc)

        # per-alert fields
        for alert in cluster.get("alerts") or []:
            if not isinstance(alert, dict):
                logger.warning("Skipping non-dict alert entry: %r", alert)
                continue

            for ioc in alert.get("iocs") or []:
                _add(ioc)

            _add(alert.get("source_ip"))
            _add(alert.get("dest_ip"))

    return result
