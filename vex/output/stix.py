"""STIX 2.1 bundle generation from vex enrichment results.

Generates valid STIX 2.1 JSON bundles without requiring the heavy ``stix2``
library.  Each IOC becomes a STIX ``indicator`` with an appropriate pattern,
malware families become ``malware`` SDOs, ATT&CK mappings become
``attack-pattern`` SDOs, and relationships tie them together.

OpenCTI hardening (v1.5.0):
- ``identity`` SDO for source attribution (created_by_ref on all SDOs).
- TLP ``marking-definition`` objects + ``object_marking_refs`` per result.
- Cyber-observable SCOs (domain-name / ipv4-addr / ipv6-addr / url / file)
  with ``indicator → based-on → <observable>`` relationships.
- ``external_references`` on ``attack-pattern`` SDOs for ATT&CK alignment.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from ..config import Config
from ..models import InvestigateResult, TriageResult, Verdict

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
# Identity SDO (vex system identity — fixed, deterministic)
# ---------------------------------------------------------------------------

_VEX_IDENTITY_ID = _deterministic_id("identity", "vex", "system")

_VEX_IDENTITY: dict[str, Any] = {
    "type": "identity",
    "spec_version": "2.1",
    "id": _VEX_IDENTITY_ID,
    "created": "2024-01-01T00:00:00.000Z",
    "modified": "2024-01-01T00:00:00.000Z",
    "name": "vex",
    "identity_class": "system",
    "description": "vex — VirusTotal IOC Enrichment Tool for SOC/DFIR workflows.",
}

# ---------------------------------------------------------------------------
# TLP marking-definitions (canonical STIX 2.1 ids — do not change)
# ---------------------------------------------------------------------------

_TLP_MARKING_IDS: dict[str, str] = {
    "white": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "clear": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "green": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "amber": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "red": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}

_TLP_MARKING_DEFS: dict[str, dict[str, Any]] = {
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "name": "TLP:WHITE",
        "definition": {"tlp": "white"},
    },
    "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "name": "TLP:GREEN",
        "definition": {"tlp": "green"},
    },
    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "name": "TLP:AMBER",
        "definition": {"tlp": "amber"},
    },
    "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed": {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "name": "TLP:RED",
        "definition": {"tlp": "red"},
    },
}


# ---------------------------------------------------------------------------
# TLP 2.0 marking-definitions (FIRST TLP 2.0 canonical ids)
# ---------------------------------------------------------------------------

_TLP2_MARKING_IDS: dict[str, str] = {
    "clear": "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "white": "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",  # alias
    "green": "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
    "amber": "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421",
    "red": "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1",
}

_TLP2_MARKING_DEFS: dict[str, dict[str, Any]] = {
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487": {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "created": "2022-10-01T00:00:00.000Z",
        "definition_type": "tlp",
        "name": "TLP:CLEAR",
        "definition": {"tlp": "clear"},
    },
    "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb": {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
        "created": "2022-10-01T00:00:00.000Z",
        "definition_type": "tlp",
        "name": "TLP:GREEN",
        "definition": {"tlp": "green"},
    },
    "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421": {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421",
        "created": "2022-10-01T00:00:00.000Z",
        "definition_type": "tlp",
        "name": "TLP:AMBER",
        "definition": {"tlp": "amber"},
    },
    "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1": {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1",
        "created": "2022-10-01T00:00:00.000Z",
        "definition_type": "tlp",
        "name": "TLP:RED",
        "definition": {"tlp": "red"},
    },
}


def _tlp_marking_id(misp_tlp: str, tlp_version: str = "1.0") -> str | None:
    """Return the canonical TLP marking-definition id for a misp_tlp string.

    *tlp_version* selects which id set to use: ``"1.0"`` (default, unchanged
    behaviour) or ``"2.0"`` (TLP 2.0 canonical ids).
    """
    if not misp_tlp:
        return None
    key = misp_tlp.lower()
    if tlp_version == "2.0":
        return _TLP2_MARKING_IDS.get(key)
    return _TLP_MARKING_IDS.get(key)


# ---------------------------------------------------------------------------
# SCO (Cyber Observable Object) helpers
# ---------------------------------------------------------------------------


def _make_sco(ioc: str, ioc_type: str) -> dict[str, Any] | None:
    """Return a STIX SCO dict for the given IOC, or None if unmapped."""
    t = ioc_type.lower()
    if t == "domain":
        return {
            "type": "domain-name",
            "spec_version": "2.1",
            "id": _deterministic_id("domain-name", ioc),
            "value": ioc,
        }
    if t == "ipv4":
        return {
            "type": "ipv4-addr",
            "spec_version": "2.1",
            "id": _deterministic_id("ipv4-addr", ioc),
            "value": ioc,
        }
    if t == "ipv6":
        return {
            "type": "ipv6-addr",
            "spec_version": "2.1",
            "id": _deterministic_id("ipv6-addr", ioc),
            "value": ioc,
        }
    if t == "url":
        return {
            "type": "url",
            "spec_version": "2.1",
            "id": _deterministic_id("url", ioc),
            "value": ioc,
        }
    if t == "sha256":
        return {
            "type": "file",
            "spec_version": "2.1",
            "id": _deterministic_id("file", "sha256", ioc),
            "hashes": {"SHA-256": ioc},
        }
    if t == "sha1":
        return {
            "type": "file",
            "spec_version": "2.1",
            "id": _deterministic_id("file", "sha1", ioc),
            "hashes": {"SHA-1": ioc},
        }
    if t == "md5":
        return {
            "type": "file",
            "spec_version": "2.1",
            "id": _deterministic_id("file", "md5", ioc),
            "hashes": {"MD5": ioc},
        }
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def to_stix_bundle(
    results: list[TriageResult | InvestigateResult],
    config: Config | None = None,
) -> str:
    """Convert enrichment results to a STIX 2.1 JSON bundle string.

    *config* is optional for backwards compatibility.  When provided,
    ``config.enrichment.stix_tlp_version`` selects which TLP marking-definition
    id set is used (``"1.0"`` default, ``"2.0"`` for TLP 2.0 ids).  When
    *config* is ``None`` the behaviour is identical to v1.0 (byte-for-byte).
    """
    tlp_version = config.enrichment.stix_tlp_version if config is not None else "1.0"

    # Select the appropriate marking-definition lookup table for building objects
    marking_def_map = _TLP2_MARKING_DEFS if tlp_version == "2.0" else _TLP_MARKING_DEFS

    now = _now_iso()
    objects: list[dict[str, Any]] = []

    # Always include the vex identity SDO first
    objects.append(_VEX_IDENTITY)

    # Track which TLP marking-definitions are needed
    used_tlp_marking_ids: set[str] = set()

    for result in results:
        triage = result.triage if isinstance(result, InvestigateResult) else result
        is_investigate = isinstance(result, InvestigateResult)

        # Resolve TLP marking for this result
        misp_tlp: str | None = result.misp_tlp if is_investigate else None
        tlp_id: str | None = _tlp_marking_id(misp_tlp, tlp_version) if misp_tlp else None
        if tlp_id:
            used_tlp_marking_ids.add(tlp_id)

        object_marking_refs: list[str] = [tlp_id] if tlp_id else []

        # 1. Indicator SDO
        indicator_id = _deterministic_id("indicator", triage.ioc, triage.ioc_type)
        indicator: dict[str, Any] = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": now,
            "modified": now,
            "created_by_ref": _VEX_IDENTITY_ID,
            "name": f"VEX: {triage.ioc}",
            "description": (
                f"VirusTotal verdict: {triage.verdict.value}. Detections: {triage.detection_stats.ratio_str}."
            ),
            "pattern": _make_indicator_pattern(triage.ioc, triage.ioc_type),
            "pattern_type": "stix",
            "valid_from": (triage.first_seen.strftime("%Y-%m-%dT%H:%M:%S.000Z") if triage.first_seen else now),
            "labels": _verdict_to_labels(triage.verdict),
            "confidence": min(100, triage.detection_stats.malicious * 10),
        }
        if object_marking_refs:
            indicator["object_marking_refs"] = object_marking_refs
        objects.append(indicator)

        # 2. SCO observable + based-on relationship
        sco = _make_sco(triage.ioc, triage.ioc_type)
        if sco is not None:
            if object_marking_refs:
                sco["object_marking_refs"] = object_marking_refs
            objects.append(sco)

            based_on_id = _deterministic_id("relationship", indicator_id, "based-on", sco["id"])
            based_on_rel: dict[str, Any] = {
                "type": "relationship",
                "spec_version": "2.1",
                "id": based_on_id,
                "created": now,
                "modified": now,
                "created_by_ref": _VEX_IDENTITY_ID,
                "relationship_type": "based-on",
                "source_ref": indicator_id,
                "target_ref": sco["id"],
            }
            if object_marking_refs:
                based_on_rel["object_marking_refs"] = object_marking_refs
            objects.append(based_on_rel)

        # 3. Malware SDOs for each family
        for family in triage.malware_families:
            malware_id = _deterministic_id("malware", family.lower())
            malware_sdo: dict[str, Any] = {
                "type": "malware",
                "spec_version": "2.1",
                "id": malware_id,
                "created": now,
                "modified": now,
                "created_by_ref": _VEX_IDENTITY_ID,
                "name": family,
                "is_family": True,
                "malware_types": ["unknown"],
            }
            if object_marking_refs:
                malware_sdo["object_marking_refs"] = object_marking_refs
            objects.append(malware_sdo)

            # Relationship: indicator → indicates → malware
            rel_id = _deterministic_id("relationship", indicator_id, "indicates", malware_id)
            indicates_rel: dict[str, Any] = {
                "type": "relationship",
                "spec_version": "2.1",
                "id": rel_id,
                "created": now,
                "modified": now,
                "created_by_ref": _VEX_IDENTITY_ID,
                "relationship_type": "indicates",
                "source_ref": indicator_id,
                "target_ref": malware_id,
            }
            if object_marking_refs:
                indicates_rel["object_marking_refs"] = object_marking_refs
            objects.append(indicates_rel)

        # 4. ATT&CK patterns (investigate mode only)
        if is_investigate:
            for mapping in result.attack_mappings:
                ap_id = _deterministic_id("attack-pattern", mapping.technique_id)
                ap_sdo: dict[str, Any] = {
                    "type": "attack-pattern",
                    "spec_version": "2.1",
                    "id": ap_id,
                    "created": now,
                    "modified": now,
                    "created_by_ref": _VEX_IDENTITY_ID,
                    "name": f"{mapping.technique_id}: {mapping.technique_name}",
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": mapping.technique_id,
                            "url": f"https://attack.mitre.org/techniques/{mapping.technique_id.replace('.', '/')}/",
                        }
                    ],
                }
                if object_marking_refs:
                    ap_sdo["object_marking_refs"] = object_marking_refs
                objects.append(ap_sdo)

                uses_rel_id = _deterministic_id("relationship", indicator_id, "uses", ap_id)
                uses_rel: dict[str, Any] = {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": uses_rel_id,
                    "created": now,
                    "modified": now,
                    "created_by_ref": _VEX_IDENTITY_ID,
                    "relationship_type": "uses",
                    "source_ref": indicator_id,
                    "target_ref": ap_id,
                }
                if object_marking_refs:
                    uses_rel["object_marking_refs"] = object_marking_refs
                objects.append(uses_rel)

    # Prepend referenced TLP marking-definition objects (before other objects,
    # after identity — stable order for deterministic output)
    tlp_objects: list[dict[str, Any]] = [
        marking_def_map[mid] for mid in sorted(used_tlp_marking_ids) if mid in marking_def_map
    ]

    # Deduplicate by ID (identity first, then tlp markings, then rest)
    seen_ids: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for obj in tlp_objects + objects:
        if obj["id"] not in seen_ids:
            seen_ids.add(obj["id"])
            deduped.append(obj)

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": deduped,
    }
    return json.dumps(bundle, indent=2, default=str)
