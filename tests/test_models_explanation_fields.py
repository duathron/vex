"""Tests for the F2 cut-1 additive explanation marker fields on TriageResult.

2026-07-03 MeetUp — 2026-07-03-f2-llm-failure-posture.md. Additive fields
(no reshape of existing fields) so a REQUESTED LLM provider failure can be
machine-marked without disturbing any existing JSON consumer.
"""

from __future__ import annotations

from vex.models import DetectionStats, InvestigateResult, TriageResult, Verdict


def _triage(**overrides):
    defaults = dict(
        ioc="1.2.3.4",
        ioc_type="ip",
        verdict=Verdict.SUSPICIOUS,
        detection_stats=DetectionStats(malicious=2, undetected=60),
    )
    defaults.update(overrides)
    return TriageResult(**defaults)


def test_triage_result_explanation_fields_default_none_and_false():
    result = _triage()
    assert result.explanation is None
    assert result.explanation_degraded is False
    assert result.explanation_provider is None


def test_triage_result_explanation_fields_settable():
    result = _triage()
    result.explanation = None
    result.explanation_degraded = True
    result.explanation_provider = "anthropic"
    assert result.explanation_degraded is True
    assert result.explanation_provider == "anthropic"


def test_triage_result_explanation_fields_flow_into_json():
    result = _triage()
    result.explanation_degraded = True
    result.explanation_provider = "ollama"
    dumped = result.model_dump(mode="json")
    assert dumped["explanation"] is None
    assert dumped["explanation_degraded"] is True
    assert dumped["explanation_provider"] == "ollama"


def test_investigate_result_exposes_explanation_fields_via_nested_triage():
    """InvestigateResult has no separate explanation fields of its own — the
    marker lives on the nested `.triage` (TriageResult), matching the existing
    isinstance-and-delegate pattern used by template_explain/build_explain_prompt."""
    inv = InvestigateResult(triage=_triage())
    inv.triage.explanation_degraded = True
    inv.triage.explanation_provider = "openai"
    dumped = inv.model_dump(mode="json")
    assert dumped["triage"]["explanation_degraded"] is True
    assert dumped["triage"]["explanation_provider"] == "openai"


def test_existing_triage_result_fields_unreshaped():
    """Sanity check: adding the 3 new fields does not disturb existing fields."""
    result = _triage()
    dumped = result.model_dump(mode="json")
    assert dumped["ioc"] == "1.2.3.4"
    assert dumped["verdict"] == "SUSPICIOUS"
    assert "detection_stats" in dumped
