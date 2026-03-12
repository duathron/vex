"""STIX 2.1 bundle generation from vex enrichment results.

Generates valid STIX 2.1 JSON bundles without requiring the heavy ``stix2``
library.  Each IOC becomes a STIX ``indicator`` with an appropriate pattern,
malware families become ``malware`` SDOs, ATT&CK mappings become
``attack-pattern`` SDOs, and relationships tie them together.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from ..models import ATTACKMapping, InvestigateResult, TriageResult, Verdict

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NAMESPACE = uuid.UUID("a0d55a84-4d1e-4cfe-889f-6f3b02e5b76d")  # vex namespace


def _deterministic_id(sdo_type: str, *parts: str) -> str:
    """Create a deterministic STIX ID from type + parts (UUID-5)."""
    seed = ":".join(parts)
    return f"{sdo_type}--{uuid.uuid5(_NAMESPACE, seed)}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _make_indicator_pattern(ioc: str, ioc_type: str) -> str:
    """Map IOC type to STIX indicator pattern."""
    safe = ioc.replace("\\", "\\\\").replace("'", "\\'")
    ioc_type_lower = ioc_type.lower()
    if ioc_type_lower == "sha256":
        return f"[file:hashes.'SHA-256' = '{safe}']"
    if ioc_type_lower == "sha1":
        return f"[file:hashes.'SHA-1' = '{safe}']"
    if ioc_type_lower == "md5":
        return f"[file:hashes.MD5 = '{safe}']"
    if ioc_type_lower in ("ipv4", "ipv6"):
        return f"[ipv4-addr:value = '{safe}']" if ioc_type_lower == "ipv4" else f"[ipv6-addr:value = '{safe}']"
    if ioc_type_lower == "domain":
        return f"[domain-name:value = '{safe}']"
    if ioc_type_lower == "url":
        return f"[url:value = '{safe}']"
    return f"[artifact:payload_bin = '{safe}']"


def _verdict_to_labels(verdict: Verdict) -> list[str]:
    return [f"verdict:{verdict.value.lower()}"]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def to_stix_bundle(
    results: list[TriageResult | InvestigateResult],
) -> str:
    """Convert enrichment results to a STIX 2.1 JSON bundle string."""
    now = _now_iso()
    objects: list[dict[str, Any]] = []

    for result in results:
        triage = result.triage if isinstance(result, InvestigateResult) else result
        is_investigate = isinstance(result, InvestigateResult)

        # 1. Indicator SDO
        indicator_id = _deterministic_id("indicator", triage.ioc, triage.ioc_type)
        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": now,
            "modified": now,
            "name": f"VEX: {triage.ioc}",
            "description": (
                f"VirusTotal verdict: {triage.verdict.value}. "
                f"Detections: {triage.detection_stats.ratio_str}."
            ),
            "pattern": _make_indicator_pattern(triage.ioc, triage.ioc_type),
            "pattern_type": "stix",
            "valid_from": (
                triage.first_seen.strftime("%Y-%m-%dT%H:%M:%S.000Z")
                if triage.first_seen
                else now
            ),
            "labels": _verdict_to_labels(triage.verdict),
            "confidence": min(100, triage.detection_stats.malicious * 10),
        }
        objects.append(indicator)

        # 2. Malware SDOs for each family
        for family in triage.malware_families:
            malware_id = _deterministic_id("malware", family.lower())
            malware_sdo = {
                "type": "malware",
                "spec_version": "2.1",
                "id": malware_id,
                "created": now,
                "modified": now,
                "name": family,
                "is_family": True,
                "malware_types": ["unknown"],
            }
            objects.append(malware_sdo)

            # Relationship: indicator → indicates → malware
            rel_id = _deterministic_id("relationship", indicator_id, "indicates", malware_id)
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": rel_id,
                "created": now,
                "modified": now,
                "relationship_type": "indicates",
                "source_ref": indicator_id,
                "target_ref": malware_id,
            })

        # 3. ATT&CK patterns (investigate mode only)
        if is_investigate:
            for mapping in result.attack_mappings:
                ap_id = _deterministic_id("attack-pattern", mapping.technique_id)
                ap_sdo = {
                    "type": "attack-pattern",
                    "spec_version": "2.1",
                    "id": ap_id,
                    "created": now,
                    "modified": now,
                    "name": f"{mapping.technique_id}: {mapping.technique_name}",
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": mapping.technique_id,
                            "url": f"https://attack.mitre.org/techniques/{mapping.technique_id.replace('.', '/')}/",
                        }
                    ],
                }
                objects.append(ap_sdo)

                rel_id = _deterministic_id("relationship", indicator_id, "uses", ap_id)
                objects.append({
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": rel_id,
                    "created": now,
                    "modified": now,
                    "relationship_type": "uses",
                    "source_ref": indicator_id,
                    "target_ref": ap_id,
                })

    # Deduplicate by ID
    seen_ids: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for obj in objects:
        if obj["id"] not in seen_ids:
            seen_ids.add(obj["id"])
            deduped.append(obj)

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": deduped,
    }
    return json.dumps(bundle, indent=2, default=str)
