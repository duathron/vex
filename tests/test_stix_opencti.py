"""Tests for OpenCTI-hardened STIX 2.1 bundle generation (v1.5.0).

All tests are offline/no-network. They parse the JSON bundle output of
``to_stix_bundle`` and assert OpenCTI ingestion requirements:
- identity SDO present; created_by_ref set on all SDOs
- TLP marking-definitions present + object_marking_refs on objects when misp_tlp given
- Correct canonical TLP marking-definition id per TLP level
- No marking when misp_tlp is None
- SCO observable + based-on relationship present per indicator
- attack-pattern has mitre-attack external_references
- Bundle shape valid
- Deterministic IDs: two exports of same input produce identical ids
"""

from __future__ import annotations

import json

import pytest

from vex.config import Config, EnrichmentConfig
from vex.models import ATTACKMapping, DetectionStats, InvestigateResult, TriageResult, Verdict
from vex.output.stix import (
    _TLP2_MARKING_IDS,
    _TLP_MARKING_IDS,
    _VEX_IDENTITY_ID,
    to_stix_bundle,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CANONICAL_TLP = {
    "white": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "clear": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "green": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "amber": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "red": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}

_STATS = DetectionStats(malicious=10, suspicious=2, undetected=60)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _triage(
    ioc: str = "evil.com",
    ioc_type: str = "domain",
    verdict: Verdict = Verdict.MALICIOUS,
    malware_families: list[str] | None = None,
) -> TriageResult:
    return TriageResult(
        ioc=ioc,
        ioc_type=ioc_type,
        verdict=verdict,
        detection_stats=_STATS,
        malware_families=malware_families or [],
    )


def _investigate(
    ioc: str = "evil.com",
    ioc_type: str = "domain",
    verdict: Verdict = Verdict.MALICIOUS,
    misp_tlp: str | None = None,
    attack_mappings: list[ATTACKMapping] | None = None,
    malware_families: list[str] | None = None,
) -> InvestigateResult:
    return InvestigateResult(
        triage=_triage(
            ioc=ioc,
            ioc_type=ioc_type,
            verdict=verdict,
            malware_families=malware_families or [],
        ),
        misp_tlp=misp_tlp,
        attack_mappings=attack_mappings or [],
    )


def _bundle(results: list[TriageResult | InvestigateResult]) -> dict:
    raw = to_stix_bundle(results)
    return json.loads(raw)


def _objects_by_type(bundle: dict, obj_type: str) -> list[dict]:
    return [o for o in bundle["objects"] if o["type"] == obj_type]


def _obj_by_id(bundle: dict, obj_id: str) -> dict | None:
    for o in bundle["objects"]:
        if o["id"] == obj_id:
            return o
    return None


# ---------------------------------------------------------------------------
# Bundle shape
# ---------------------------------------------------------------------------

class TestBundleShape:
    def test_type_is_bundle(self) -> None:
        b = _bundle([_triage()])
        assert b["type"] == "bundle"

    def test_bundle_has_id(self) -> None:
        b = _bundle([_triage()])
        assert b["id"].startswith("bundle--")

    def test_bundle_has_objects_list(self) -> None:
        b = _bundle([_triage()])
        assert isinstance(b["objects"], list)
        assert len(b["objects"]) > 0

    def test_no_spec_version_on_bundle(self) -> None:
        """STIX 2.1 spec_version is on SDOs, not required on bundle."""
        b = _bundle([_triage()])
        # spec_version may or may not appear on bundle — the key requirement
        # is that SDOs carry it; we just verify objects carry spec_version
        indicators = _objects_by_type(b, "indicator")
        assert all(o["spec_version"] == "2.1" for o in indicators)

    def test_all_sdos_have_spec_version(self) -> None:
        b = _bundle([_investigate(attack_mappings=[
            ATTACKMapping(technique_id="T1566", technique_name="Phishing", tactic="initial-access")
        ])])
        for obj in b["objects"]:
            if obj["type"] not in ("bundle",):
                assert obj.get("spec_version") == "2.1", f"Missing spec_version on {obj['type']}"


# ---------------------------------------------------------------------------
# Identity SDO
# ---------------------------------------------------------------------------

class TestIdentitySDO:
    def test_identity_present_in_bundle(self) -> None:
        b = _bundle([_triage()])
        identities = _objects_by_type(b, "identity")
        assert len(identities) == 1

    def test_identity_has_correct_id(self) -> None:
        b = _bundle([_triage()])
        identity = _objects_by_type(b, "identity")[0]
        assert identity["id"] == _VEX_IDENTITY_ID

    def test_identity_name_is_vex(self) -> None:
        b = _bundle([_triage()])
        identity = _objects_by_type(b, "identity")[0]
        assert identity["name"] == "vex"

    def test_identity_class_is_system(self) -> None:
        b = _bundle([_triage()])
        identity = _objects_by_type(b, "identity")[0]
        assert identity["identity_class"] == "system"

    def test_only_one_identity_across_multiple_results(self) -> None:
        results = [_triage(ioc=f"ioc{i}.com") for i in range(5)]
        b = _bundle(results)
        identities = _objects_by_type(b, "identity")
        assert len(identities) == 1

    def test_identity_id_is_deterministic(self) -> None:
        b1 = _bundle([_triage()])
        b2 = _bundle([_triage()])
        id1 = _objects_by_type(b1, "identity")[0]["id"]
        id2 = _objects_by_type(b2, "identity")[0]["id"]
        assert id1 == id2


# ---------------------------------------------------------------------------
# created_by_ref on SDOs
# ---------------------------------------------------------------------------

class TestCreatedByRef:
    def test_indicator_has_created_by_ref(self) -> None:
        b = _bundle([_triage()])
        indicator = _objects_by_type(b, "indicator")[0]
        assert indicator.get("created_by_ref") == _VEX_IDENTITY_ID

    def test_malware_has_created_by_ref(self) -> None:
        b = _bundle([_triage(malware_families=["Emotet"])])
        malware = _objects_by_type(b, "malware")[0]
        assert malware.get("created_by_ref") == _VEX_IDENTITY_ID

    def test_attack_pattern_has_created_by_ref(self) -> None:
        b = _bundle([_investigate(attack_mappings=[
            ATTACKMapping(technique_id="T1059", technique_name="Command and Scripting Interpreter", tactic="execution")
        ])])
        ap = _objects_by_type(b, "attack-pattern")[0]
        assert ap.get("created_by_ref") == _VEX_IDENTITY_ID

    def test_relationship_has_created_by_ref(self) -> None:
        b = _bundle([_investigate(malware_families=["Emotet"])])
        rels = _objects_by_type(b, "relationship")
        assert all(r.get("created_by_ref") == _VEX_IDENTITY_ID for r in rels)


# ---------------------------------------------------------------------------
# TLP marking-definitions
# ---------------------------------------------------------------------------

class TestTLPMarkings:
    @pytest.mark.parametrize("tlp_level,expected_id", list(_CANONICAL_TLP.items()))
    def test_correct_canonical_id_per_tlp_level(self, tlp_level: str, expected_id: str) -> None:
        assert _TLP_MARKING_IDS.get(tlp_level) == expected_id

    def test_marking_def_added_to_bundle_when_tlp_set(self) -> None:
        b = _bundle([_investigate(misp_tlp="amber")])
        markings = _objects_by_type(b, "marking-definition")
        assert len(markings) == 1
        assert markings[0]["id"] == _CANONICAL_TLP["amber"]

    def test_no_marking_def_when_tlp_none(self) -> None:
        b = _bundle([_investigate(misp_tlp=None)])
        markings = _objects_by_type(b, "marking-definition")
        assert len(markings) == 0

    def test_indicator_has_object_marking_refs_when_tlp_set(self) -> None:
        b = _bundle([_investigate(misp_tlp="green")])
        indicator = _objects_by_type(b, "indicator")[0]
        assert "object_marking_refs" in indicator
        assert _CANONICAL_TLP["green"] in indicator["object_marking_refs"]

    def test_indicator_no_marking_refs_when_tlp_none(self) -> None:
        b = _bundle([_investigate(misp_tlp=None)])
        indicator = _objects_by_type(b, "indicator")[0]
        assert "object_marking_refs" not in indicator

    @pytest.mark.parametrize("tlp_level", ["white", "clear", "green", "amber", "red"])
    def test_marking_def_in_bundle_for_each_level(self, tlp_level: str) -> None:
        b = _bundle([_investigate(misp_tlp=tlp_level)])
        markings = _objects_by_type(b, "marking-definition")
        marking_ids = [m["id"] for m in markings]
        assert _CANONICAL_TLP[tlp_level] in marking_ids

    def test_white_and_clear_use_same_id(self) -> None:
        b_white = _bundle([_investigate(misp_tlp="white")])
        b_clear = _bundle([_investigate(misp_tlp="clear")])
        white_ids = [m["id"] for m in _objects_by_type(b_white, "marking-definition")]
        clear_ids = [m["id"] for m in _objects_by_type(b_clear, "marking-definition")]
        assert white_ids == clear_ids

    def test_only_one_marking_def_per_level_across_multiple_results(self) -> None:
        results = [_investigate(ioc=f"{i}.com", misp_tlp="amber") for i in range(3)]
        b = _bundle(results)
        markings = _objects_by_type(b, "marking-definition")
        amber_markings = [m for m in markings if m["id"] == _CANONICAL_TLP["amber"]]
        assert len(amber_markings) == 1

    def test_marking_def_has_definition_type_tlp(self) -> None:
        b = _bundle([_investigate(misp_tlp="red")])
        markings = _objects_by_type(b, "marking-definition")
        assert all(m.get("definition_type") == "tlp" for m in markings)

    def test_triage_result_no_tlp(self) -> None:
        """TriageResult has no misp_tlp — no markings should be added."""
        b = _bundle([_triage()])
        markings = _objects_by_type(b, "marking-definition")
        assert len(markings) == 0

    def test_malware_sdo_has_marking_when_tlp_set(self) -> None:
        b = _bundle([_investigate(misp_tlp="amber", malware_families=["Emotet"])])
        malware = _objects_by_type(b, "malware")[0]
        assert _CANONICAL_TLP["amber"] in malware.get("object_marking_refs", [])


# ---------------------------------------------------------------------------
# SCO observables + based-on relationships
# ---------------------------------------------------------------------------

class TestSCOAndBasedOn:
    def test_domain_sco_present(self) -> None:
        b = _bundle([_triage(ioc="evil.com", ioc_type="domain")])
        domains = _objects_by_type(b, "domain-name")
        assert len(domains) == 1
        assert domains[0]["value"] == "evil.com"

    def test_ipv4_sco_present(self) -> None:
        b = _bundle([_triage(ioc="1.2.3.4", ioc_type="ipv4")])
        ipv4s = _objects_by_type(b, "ipv4-addr")
        assert len(ipv4s) == 1
        assert ipv4s[0]["value"] == "1.2.3.4"

    def test_ipv6_sco_present(self) -> None:
        b = _bundle([_triage(ioc="2001:db8::1", ioc_type="ipv6")])
        ipv6s = _objects_by_type(b, "ipv6-addr")
        assert len(ipv6s) == 1
        assert ipv6s[0]["value"] == "2001:db8::1"

    def test_url_sco_present(self) -> None:
        b = _bundle([_triage(ioc="https://evil.com/malware", ioc_type="url")])
        urls = _objects_by_type(b, "url")
        assert len(urls) == 1
        assert urls[0]["value"] == "https://evil.com/malware"

    def test_sha256_sco_present(self) -> None:
        sha = "a" * 64
        b = _bundle([_triage(ioc=sha, ioc_type="sha256")])
        files = _objects_by_type(b, "file")
        assert len(files) == 1
        assert files[0]["hashes"]["SHA-256"] == sha

    def test_sha1_sco_present(self) -> None:
        sha = "b" * 40
        b = _bundle([_triage(ioc=sha, ioc_type="sha1")])
        files = _objects_by_type(b, "file")
        assert len(files) == 1
        assert files[0]["hashes"]["SHA-1"] == sha

    def test_md5_sco_present(self) -> None:
        md5 = "c" * 32
        b = _bundle([_triage(ioc=md5, ioc_type="md5")])
        files = _objects_by_type(b, "file")
        assert len(files) == 1
        assert files[0]["hashes"]["MD5"] == md5

    def test_based_on_relationship_present(self) -> None:
        b = _bundle([_triage(ioc="evil.com", ioc_type="domain")])
        rels = _objects_by_type(b, "relationship")
        based_on_rels = [r for r in rels if r["relationship_type"] == "based-on"]
        assert len(based_on_rels) == 1

    def test_based_on_source_is_indicator(self) -> None:
        b = _bundle([_triage(ioc="evil.com", ioc_type="domain")])
        indicator = _objects_by_type(b, "indicator")[0]
        rels = _objects_by_type(b, "relationship")
        based_on = [r for r in rels if r["relationship_type"] == "based-on"][0]
        assert based_on["source_ref"] == indicator["id"]

    def test_based_on_target_is_sco(self) -> None:
        b = _bundle([_triage(ioc="evil.com", ioc_type="domain")])
        domain = _objects_by_type(b, "domain-name")[0]
        rels = _objects_by_type(b, "relationship")
        based_on = [r for r in rels if r["relationship_type"] == "based-on"][0]
        assert based_on["target_ref"] == domain["id"]

    def test_sco_has_deterministic_id(self) -> None:
        b1 = _bundle([_triage(ioc="evil.com", ioc_type="domain")])
        b2 = _bundle([_triage(ioc="evil.com", ioc_type="domain")])
        id1 = _objects_by_type(b1, "domain-name")[0]["id"]
        id2 = _objects_by_type(b2, "domain-name")[0]["id"]
        assert id1 == id2

    def test_sco_has_marking_when_tlp_set(self) -> None:
        b = _bundle([_investigate(ioc="evil.com", ioc_type="domain", misp_tlp="amber")])
        domain = _objects_by_type(b, "domain-name")[0]
        assert _CANONICAL_TLP["amber"] in domain.get("object_marking_refs", [])

    def test_sco_no_marking_when_tlp_none(self) -> None:
        b = _bundle([_triage(ioc="evil.com", ioc_type="domain")])
        domain = _objects_by_type(b, "domain-name")[0]
        assert "object_marking_refs" not in domain


# ---------------------------------------------------------------------------
# ATT&CK external_references on attack-pattern SDOs
# ---------------------------------------------------------------------------

class TestATTACKExternalReferences:
    def test_attack_pattern_has_external_references(self) -> None:
        b = _bundle([_investigate(attack_mappings=[
            ATTACKMapping(technique_id="T1566", technique_name="Phishing", tactic="initial-access")
        ])])
        ap = _objects_by_type(b, "attack-pattern")[0]
        assert "external_references" in ap
        assert len(ap["external_references"]) >= 1

    def test_external_reference_source_name_mitre_attack(self) -> None:
        b = _bundle([_investigate(attack_mappings=[
            ATTACKMapping(technique_id="T1566", technique_name="Phishing", tactic="initial-access")
        ])])
        ap = _objects_by_type(b, "attack-pattern")[0]
        ext_refs = ap["external_references"]
        mitre_refs = [r for r in ext_refs if r.get("source_name") == "mitre-attack"]
        assert len(mitre_refs) == 1

    def test_external_reference_has_correct_external_id(self) -> None:
        b = _bundle([_investigate(attack_mappings=[
            ATTACKMapping(technique_id="T1566", technique_name="Phishing", tactic="initial-access")
        ])])
        ap = _objects_by_type(b, "attack-pattern")[0]
        mitre_ref = next(r for r in ap["external_references"] if r["source_name"] == "mitre-attack")
        assert mitre_ref["external_id"] == "T1566"

    def test_external_reference_url(self) -> None:
        b = _bundle([_investigate(attack_mappings=[
            ATTACKMapping(technique_id="T1566", technique_name="Phishing", tactic="initial-access")
        ])])
        ap = _objects_by_type(b, "attack-pattern")[0]
        mitre_ref = next(r for r in ap["external_references"] if r["source_name"] == "mitre-attack")
        assert "attack.mitre.org" in mitre_ref["url"]
        assert "T1566" in mitre_ref["url"]

    def test_subtechnique_url_uses_slash(self) -> None:
        b = _bundle([_investigate(attack_mappings=[
            ATTACKMapping(technique_id="T1566.001", technique_name="Spearphishing Attachment", tactic="initial-access")
        ])])
        ap = _objects_by_type(b, "attack-pattern")[0]
        mitre_ref = next(r for r in ap["external_references"] if r["source_name"] == "mitre-attack")
        assert "T1566/001" in mitre_ref["url"]

    def test_multiple_attack_patterns_all_have_refs(self) -> None:
        b = _bundle([_investigate(attack_mappings=[
            ATTACKMapping(technique_id="T1059", technique_name="Command Interpreter", tactic="execution"),
            ATTACKMapping(technique_id="T1055", technique_name="Process Injection", tactic="defense-evasion"),
        ])])
        aps = _objects_by_type(b, "attack-pattern")
        assert len(aps) == 2
        for ap in aps:
            ext_refs = ap.get("external_references", [])
            mitre_refs = [r for r in ext_refs if r.get("source_name") == "mitre-attack"]
            assert len(mitre_refs) == 1


# ---------------------------------------------------------------------------
# Deterministic IDs (idempotent export)
# ---------------------------------------------------------------------------

class TestDeterministicIDs:
    def test_indicator_id_stable_across_runs(self) -> None:
        r = _triage(ioc="evil.com", ioc_type="domain")
        b1 = _bundle([r])
        b2 = _bundle([r])
        id1 = _objects_by_type(b1, "indicator")[0]["id"]
        id2 = _objects_by_type(b2, "indicator")[0]["id"]
        assert id1 == id2

    def test_malware_id_stable_across_runs(self) -> None:
        r = _triage(malware_families=["Emotet"])
        b1 = _bundle([r])
        b2 = _bundle([r])
        id1 = _objects_by_type(b1, "malware")[0]["id"]
        id2 = _objects_by_type(b2, "malware")[0]["id"]
        assert id1 == id2

    def test_relationship_id_stable_across_runs(self) -> None:
        r = _triage(malware_families=["Emotet"])
        b1 = _bundle([r])
        b2 = _bundle([r])
        rels1 = {rel["id"] for rel in _objects_by_type(b1, "relationship")}
        rels2 = {rel["id"] for rel in _objects_by_type(b2, "relationship")}
        assert rels1 == rels2

    def test_all_non_bundle_ids_stable(self) -> None:
        r = _investigate(
            ioc="1.2.3.4",
            ioc_type="ipv4",
            misp_tlp="amber",
            malware_families=["Emotet"],
            attack_mappings=[
                ATTACKMapping(technique_id="T1059", technique_name="Command Interpreter", tactic="execution")
            ],
        )
        b1 = _bundle([r])
        b2 = _bundle([r])
        ids1 = {o["id"] for o in b1["objects"]}
        ids2 = {o["id"] for o in b2["objects"]}
        assert ids1 == ids2

    def test_bundle_id_differs_across_runs(self) -> None:
        """Bundle itself uses uuid4 — allowed to differ (no dedup needed for bundles)."""
        r = _triage()
        b1 = _bundle([r])
        b2 = _bundle([r])
        # bundle IDs may differ — this is expected per spec
        assert b1["id"].startswith("bundle--")
        assert b2["id"].startswith("bundle--")


# ---------------------------------------------------------------------------
# Existing behavior preserved (regression)
# ---------------------------------------------------------------------------

class TestExistingBehaviorPreserved:
    def test_indicator_pattern_domain(self) -> None:
        b = _bundle([_triage(ioc="evil.com", ioc_type="domain")])
        indicator = _objects_by_type(b, "indicator")[0]
        assert "domain-name:value" in indicator["pattern"]

    def test_indicator_pattern_sha256(self) -> None:
        sha = "a" * 64
        b = _bundle([_triage(ioc=sha, ioc_type="sha256")])
        indicator = _objects_by_type(b, "indicator")[0]
        assert "SHA-256" in indicator["pattern"]

    def test_indicator_pattern_ipv4(self) -> None:
        b = _bundle([_triage(ioc="1.2.3.4", ioc_type="ipv4")])
        indicator = _objects_by_type(b, "indicator")[0]
        assert "ipv4-addr:value" in indicator["pattern"]

    def test_indicator_pattern_ipv6(self) -> None:
        b = _bundle([_triage(ioc="2001:db8::1", ioc_type="ipv6")])
        indicator = _objects_by_type(b, "indicator")[0]
        assert "ipv6-addr:value" in indicator["pattern"]

    def test_malware_sdo_emitted_for_family(self) -> None:
        b = _bundle([_triage(malware_families=["Emotet", "TrickBot"])])
        malwares = _objects_by_type(b, "malware")
        names = {m["name"] for m in malwares}
        assert "Emotet" in names
        assert "TrickBot" in names

    def test_indicates_relationship_present(self) -> None:
        b = _bundle([_triage(malware_families=["Emotet"])])
        rels = _objects_by_type(b, "relationship")
        types = {r["relationship_type"] for r in rels}
        assert "indicates" in types

    def test_uses_relationship_present_for_attack_pattern(self) -> None:
        b = _bundle([_investigate(attack_mappings=[
            ATTACKMapping(technique_id="T1059", technique_name="Command Interpreter", tactic="execution")
        ])])
        rels = _objects_by_type(b, "relationship")
        types = {r["relationship_type"] for r in rels}
        assert "uses" in types

    def test_verdict_label_present(self) -> None:
        b = _bundle([_triage(verdict=Verdict.MALICIOUS)])
        indicator = _objects_by_type(b, "indicator")[0]
        assert "verdict:malicious" in indicator["labels"]

    def test_confidence_capped_at_100(self) -> None:
        stats = DetectionStats(malicious=999)
        r = TriageResult(ioc="evil.com", ioc_type="domain", verdict=Verdict.MALICIOUS, detection_stats=stats)
        b = _bundle([r])
        indicator = _objects_by_type(b, "indicator")[0]
        assert indicator["confidence"] <= 100

    def test_dedup_malware_across_results(self) -> None:
        """Same malware family referenced by two indicators → one malware SDO."""
        r1 = _triage(ioc="evil1.com", malware_families=["Emotet"])
        r2 = _triage(ioc="evil2.com", malware_families=["Emotet"])
        b = _bundle([r1, r2])
        malwares = _objects_by_type(b, "malware")
        assert len(malwares) == 1


# ---------------------------------------------------------------------------
# Helpers for TLP 2.0 tests
# ---------------------------------------------------------------------------

def _config_v2() -> Config:
    cfg = Config()
    cfg.enrichment = EnrichmentConfig(stix_tlp_version="2.0")
    return cfg


def _config_v1() -> Config:
    cfg = Config()
    cfg.enrichment = EnrichmentConfig(stix_tlp_version="1.0")
    return cfg


def _bundle_v2(results: list[TriageResult | InvestigateResult]) -> dict:
    raw = to_stix_bundle(results, config=_config_v2())
    return json.loads(raw)


def _bundle_v1(results: list[TriageResult | InvestigateResult]) -> dict:
    raw = to_stix_bundle(results, config=_config_v1())
    return json.loads(raw)


# ---------------------------------------------------------------------------
# TLP 2.0 config — stix_tlp_version="2.0"
# ---------------------------------------------------------------------------

_TLP2_CANONICAL = {
    "clear": "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "green": "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
    "amber": "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421",
    "red": "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1",
}


class TestStixTlpVersion2:
    def test_amber_emits_tlp2_marking_id(self) -> None:
        """With stix_tlp_version='2.0', amber must use the TLP 2.0 id."""
        b = _bundle_v2([_investigate(misp_tlp="amber")])
        markings = _objects_by_type(b, "marking-definition")
        assert len(markings) == 1
        assert markings[0]["id"] == _TLP2_CANONICAL["amber"]

    def test_amber_object_marking_refs_use_tlp2_id(self) -> None:
        b = _bundle_v2([_investigate(ioc="evil.com", ioc_type="domain", misp_tlp="amber")])
        indicator = _objects_by_type(b, "indicator")[0]
        assert _TLP2_CANONICAL["amber"] in indicator.get("object_marking_refs", [])

    def test_indicator_does_not_have_tlp1_id_in_v2_mode(self) -> None:
        b = _bundle_v2([_investigate(misp_tlp="amber")])
        indicator = _objects_by_type(b, "indicator")[0]
        tlp1_amber = _TLP_MARKING_IDS["amber"]
        assert tlp1_amber not in indicator.get("object_marking_refs", [])

    @pytest.mark.parametrize("tlp_level", ["clear", "green", "amber", "red"])
    def test_correct_tlp2_id_per_level(self, tlp_level: str) -> None:
        b = _bundle_v2([_investigate(misp_tlp=tlp_level)])
        markings = _objects_by_type(b, "marking-definition")
        marking_ids = [m["id"] for m in markings]
        assert _TLP2_CANONICAL[tlp_level] in marking_ids

    def test_tlp2_ids_differ_from_tlp1_ids(self) -> None:
        """Sanity: TLP 2.0 ids must be different from TLP 1.0 ids."""
        for level in ("clear", "green", "amber", "red"):
            assert _TLP2_MARKING_IDS[level] != _TLP_MARKING_IDS.get(level), (
                f"TLP 2.0 id for {level} must differ from TLP 1.0 id"
            )

    def test_no_marking_when_tlp_none_in_v2(self) -> None:
        b = _bundle_v2([_investigate(misp_tlp=None)])
        markings = _objects_by_type(b, "marking-definition")
        assert len(markings) == 0

    def test_marking_def_has_definition_type_tlp_in_v2(self) -> None:
        b = _bundle_v2([_investigate(misp_tlp="red")])
        markings = _objects_by_type(b, "marking-definition")
        assert all(m.get("definition_type") == "tlp" for m in markings)

    def test_sco_has_v2_marking(self) -> None:
        b = _bundle_v2([_investigate(ioc="evil.com", ioc_type="domain", misp_tlp="green")])
        domain = _objects_by_type(b, "domain-name")[0]
        assert _TLP2_CANONICAL["green"] in domain.get("object_marking_refs", [])


# ---------------------------------------------------------------------------
# Default (no config / config v1.0) — 1.0 ids unchanged (regression)
# ---------------------------------------------------------------------------

class TestStixTlpVersionDefault:
    def test_no_config_uses_tlp1_amber_id(self) -> None:
        """Calling to_stix_bundle without config must produce TLP 1.0 ids."""
        b = json.loads(to_stix_bundle([_investigate(misp_tlp="amber")]))
        markings = _objects_by_type(b, "marking-definition")
        assert markings[0]["id"] == _TLP_MARKING_IDS["amber"]

    def test_explicit_v1_config_uses_tlp1_amber_id(self) -> None:
        b = _bundle_v1([_investigate(misp_tlp="amber")])
        markings = _objects_by_type(b, "marking-definition")
        assert markings[0]["id"] == _TLP_MARKING_IDS["amber"]

    def test_no_config_result_identical_to_v1_result(self) -> None:
        """No-config and explicit v1.0 must produce the same marking ids."""
        r = _investigate(misp_tlp="green")
        b_none = json.loads(to_stix_bundle([r]))
        b_v1 = _bundle_v1([r])
        ids_none = {m["id"] for m in _objects_by_type(b_none, "marking-definition")}
        ids_v1 = {m["id"] for m in _objects_by_type(b_v1, "marking-definition")}
        assert ids_none == ids_v1
