"""Tests for NDJSON export — deterministic, no network."""

from __future__ import annotations

import json

from vex.defang import defang as defang_ioc
from vex.models import DetectionStats, InvestigateResult, TriageResult, Verdict
from vex.output.export import to_ndjson


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_STATS = DetectionStats(malicious=10, suspicious=2, undetected=60)


def _triage(
    ioc: str = "evil.com",
    ioc_type: str = "domain",
    verdict: Verdict = Verdict.MALICIOUS,
) -> TriageResult:
    return TriageResult(
        ioc=ioc,
        ioc_type=ioc_type,
        verdict=verdict,
        detection_stats=_STATS,
    )


def _investigate(
    ioc: str = "evil.com",
    ioc_type: str = "domain",
    verdict: Verdict = Verdict.MALICIOUS,
) -> InvestigateResult:
    return InvestigateResult(triage=_triage(ioc=ioc, ioc_type=ioc_type, verdict=verdict))


# ---------------------------------------------------------------------------
# to_ndjson: single result → valid one-line JSON
# ---------------------------------------------------------------------------

class TestToNdjson:
    def test_produces_valid_json(self) -> None:
        result = _triage()
        line = to_ndjson(result)
        parsed = json.loads(line)
        assert isinstance(parsed, dict)

    def test_no_embedded_newlines(self) -> None:
        """A single NDJSON line must not contain literal newlines."""
        line = to_ndjson(_triage())
        assert "\n" not in line
        assert "\r" not in line

    def test_ioc_field_present(self) -> None:
        result = _triage(ioc="8.8.8.8", ioc_type="ip")
        parsed = json.loads(to_ndjson(result))
        assert parsed["ioc"] == "8.8.8.8"

    def test_verdict_field_present(self) -> None:
        result = _triage(verdict=Verdict.SUSPICIOUS)
        parsed = json.loads(to_ndjson(result))
        assert parsed["verdict"] == "SUSPICIOUS"

    def test_ioc_type_field_present(self) -> None:
        result = _triage(ioc_type="hash")
        parsed = json.loads(to_ndjson(result))
        assert parsed["ioc_type"] == "hash"

    def test_real_ioc_by_default(self) -> None:
        """Real IOC must appear unchanged — no defanging unless caller requests it."""
        result = _triage(ioc="https://evil.com/malware")
        parsed = json.loads(to_ndjson(result))
        assert parsed["ioc"] == "https://evil.com/malware"

    def test_defanged_when_caller_applies_defang(self) -> None:
        """Caller must apply defanging to the result BEFORE calling to_ndjson."""
        result = _triage(ioc="https://evil.com/malware")
        result.ioc = defang_ioc(result.ioc)
        parsed = json.loads(to_ndjson(result))
        assert parsed["ioc"] == "hxxps[://]evil[.]com/malware"

    def test_works_with_investigate_result(self) -> None:
        result = _investigate(ioc="deadbeef" * 8)
        line = to_ndjson(result)
        parsed = json.loads(line)
        assert "triage" in parsed
        assert parsed["triage"]["ioc"] == "deadbeef" * 8

    def test_investigate_real_ioc_by_default(self) -> None:
        result = _investigate(ioc="1.2.3.4", ioc_type="ip")
        parsed = json.loads(to_ndjson(result))
        assert parsed["triage"]["ioc"] == "1.2.3.4"

    def test_investigate_defanged_when_caller_applies_defang(self) -> None:
        result = _investigate(ioc="evil.example.com", ioc_type="domain")
        result.triage.ioc = defang_ioc(result.triage.ioc)
        parsed = json.loads(to_ndjson(result))
        assert "[.]" in parsed["triage"]["ioc"]


# ---------------------------------------------------------------------------
# Multiple results → N lines
# ---------------------------------------------------------------------------

class TestNdjsonList:
    def test_n_results_produce_n_lines(self) -> None:
        results = [_triage(ioc=f"ioc{i}.com") for i in range(5)]
        lines = [to_ndjson(r) for r in results]
        assert len(lines) == 5

    def test_each_line_is_valid_json(self) -> None:
        results = [_triage(ioc=f"{i}.{i}.{i}.{i}", ioc_type="ip") for i in range(1, 4)]
        for r in results:
            line = to_ndjson(r)
            parsed = json.loads(line)
            assert isinstance(parsed, dict)

    def test_each_line_has_correct_ioc(self) -> None:
        iocs = ["a.com", "b.com", "c.com"]
        results = [_triage(ioc=ioc) for ioc in iocs]
        parsed_iocs = [json.loads(to_ndjson(r))["ioc"] for r in results]
        assert parsed_iocs == iocs

    def test_no_surrounding_array(self) -> None:
        """NDJSON is NOT a JSON array — each line must be a bare object."""
        results = [_triage(ioc=f"host{i}.com") for i in range(3)]
        for r in results:
            line = to_ndjson(r)
            assert not line.startswith("[")

    def test_round_trip_key_fields(self) -> None:
        """Key fields survive a model_dump → JSON → parse round-trip."""
        result = _triage(ioc="evil.com", ioc_type="domain", verdict=Verdict.MALICIOUS)
        parsed = json.loads(to_ndjson(result))
        assert parsed["ioc"] == "evil.com"
        assert parsed["ioc_type"] == "domain"
        assert parsed["verdict"] == "MALICIOUS"
        assert parsed["detection_stats"]["malicious"] == 10
        assert parsed["detection_stats"]["suspicious"] == 2

    def test_single_ioc_produces_one_line(self) -> None:
        result = _triage(ioc="single.com")
        line = to_ndjson(result)
        # Exactly one JSON object, parseable
        parsed = json.loads(line)
        assert parsed["ioc"] == "single.com"
