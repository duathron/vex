"""Tests for vex.timeline.build_timeline — deterministic, no network."""

from __future__ import annotations

from datetime import datetime, timezone

from vex.models import (
    DetectionStats,
    InvestigateResult,
    PassiveDNSRecord,
    PEInfo,
    SandboxBehavior,
    TriageResult,
    Verdict,
    WHOISInfo,
)
from vex.timeline import build_timeline

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_triage(
    ioc: str = "evil.com",
    ioc_type: str = "domain",
    verdict: Verdict = Verdict.MALICIOUS,
    first_seen: datetime | None = None,
    last_seen: datetime | None = None,
    last_analysis_date: datetime | None = None,
) -> TriageResult:
    return TriageResult(
        ioc=ioc,
        ioc_type=ioc_type,
        verdict=verdict,
        detection_stats=DetectionStats(malicious=5, undetected=65),
        first_seen=first_seen,
        last_seen=last_seen,
        last_analysis_date=last_analysis_date,
    )


def _make_result(**triage_kwargs) -> InvestigateResult:
    return InvestigateResult(triage=_make_triage(**triage_kwargs))


_T_EARLY = datetime(2023, 1, 1, tzinfo=timezone.utc)
_T_MID = datetime(2023, 6, 1, tzinfo=timezone.utc)
_T_LATE = datetime(2024, 1, 1, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Basic behaviour
# ---------------------------------------------------------------------------


class TestBuildTimelineBasic:
    def test_empty_result_produces_empty_timeline(self) -> None:
        result = _make_result()
        tl = build_timeline(result)
        assert tl.events == []
        assert tl.earliest is None
        assert tl.latest is None

    def test_ioc_preserved_in_result(self) -> None:
        result = _make_result(ioc="192.168.1.1")
        tl = build_timeline(result)
        assert tl.ioc == "192.168.1.1"

    def test_first_seen_produces_event(self) -> None:
        result = _make_result(first_seen=_T_EARLY)
        tl = build_timeline(result)
        types = [e.event_type for e in tl.events]
        assert "first_seen" in types

    def test_last_seen_produces_event(self) -> None:
        result = _make_result(last_seen=_T_LATE)
        tl = build_timeline(result)
        types = [e.event_type for e in tl.events]
        assert "last_seen" in types

    def test_last_analysis_date_produces_event(self) -> None:
        result = _make_result(last_analysis_date=_T_MID)
        tl = build_timeline(result)
        types = [e.event_type for e in tl.events]
        assert "analysis" in types

    def test_three_triage_timestamps_produce_three_events(self) -> None:
        result = _make_result(
            first_seen=_T_EARLY,
            last_seen=_T_LATE,
            last_analysis_date=_T_MID,
        )
        tl = build_timeline(result)
        assert len(tl.events) == 3


# ---------------------------------------------------------------------------
# Chronological ordering
# ---------------------------------------------------------------------------


class TestChronologicalOrder:
    def test_events_sorted_ascending(self) -> None:
        result = _make_result(
            first_seen=_T_LATE,
            last_seen=_T_EARLY,
            last_analysis_date=_T_MID,
        )
        tl = build_timeline(result)
        timestamps = [e.timestamp for e in tl.events]
        assert timestamps == sorted(timestamps)

    def test_earliest_and_latest_set_correctly(self) -> None:
        result = _make_result(
            first_seen=_T_EARLY,
            last_seen=_T_LATE,
            last_analysis_date=_T_MID,
        )
        tl = build_timeline(result)
        assert tl.earliest == _T_EARLY
        assert tl.latest == _T_LATE


# ---------------------------------------------------------------------------
# Naive datetime treated as UTC
# ---------------------------------------------------------------------------


class TestNaiveDatetimeAsUTC:
    def test_naive_timestamp_becomes_utc_aware(self) -> None:
        naive_dt = datetime(2023, 3, 15, 12, 0, 0)  # no tzinfo
        result = _make_result(first_seen=naive_dt)
        tl = build_timeline(result)
        assert tl.events[0].timestamp.tzinfo is not None
        assert tl.events[0].timestamp.tzinfo == timezone.utc

    def test_naive_and_aware_timestamps_sort_together(self) -> None:
        naive_early = datetime(2022, 1, 1, 0, 0, 0)  # naive, treated as UTC
        aware_late = datetime(2023, 1, 1, tzinfo=timezone.utc)
        result = _make_result(first_seen=naive_early, last_seen=aware_late)
        tl = build_timeline(result)
        assert tl.events[0].timestamp < tl.events[1].timestamp


# ---------------------------------------------------------------------------
# PE Info
# ---------------------------------------------------------------------------


class TestPEInfo:
    def test_pe_compilation_timestamp_produces_event(self) -> None:
        result = InvestigateResult(
            triage=_make_triage(),
            pe_info=PEInfo(
                compilation_timestamp=_T_EARLY,
                target_machine="x86",
            ),
        )
        tl = build_timeline(result)
        types = [e.event_type for e in tl.events]
        assert "compiled" in types

    def test_pe_event_source_is_pe_header(self) -> None:
        result = InvestigateResult(
            triage=_make_triage(),
            pe_info=PEInfo(compilation_timestamp=_T_EARLY),
        )
        tl = build_timeline(result)
        pe_events = [e for e in tl.events if e.event_type == "compiled"]
        assert pe_events[0].source == "PE Header"

    def test_no_pe_info_produces_no_compiled_event(self) -> None:
        result = _make_result()
        tl = build_timeline(result)
        assert all(e.event_type != "compiled" for e in tl.events)


# ---------------------------------------------------------------------------
# Signature info
# ---------------------------------------------------------------------------


class TestSignatureInfo:
    def test_signing_date_produces_signed_event(self) -> None:
        result = InvestigateResult(
            triage=_make_triage(),
            signature_info={
                "signing date": "2023-06-15T10:00:00",
                "subject": "Evil Corp",
            },
        )
        tl = build_timeline(result)
        types = [e.event_type for e in tl.events]
        assert "signed" in types

    def test_invalid_signing_date_is_skipped(self) -> None:
        result = InvestigateResult(
            triage=_make_triage(),
            signature_info={"signing date": "not-a-date"},
        )
        tl = build_timeline(result)
        assert all(e.event_type != "signed" for e in tl.events)

    def test_missing_signing_date_produces_no_signed_event(self) -> None:
        result = InvestigateResult(
            triage=_make_triage(),
            signature_info={"subject": "Someone"},
        )
        tl = build_timeline(result)
        assert all(e.event_type != "signed" for e in tl.events)


# ---------------------------------------------------------------------------
# WHOIS
# ---------------------------------------------------------------------------


class TestWHOIS:
    def test_creation_date_produces_whois_event(self) -> None:
        result = InvestigateResult(
            triage=_make_triage(),
            whois=WHOISInfo(creation_date="2020-01-01T00:00:00"),
        )
        tl = build_timeline(result)
        types = [e.event_type for e in tl.events]
        assert "whois" in types

    def test_expiration_date_produces_whois_event(self) -> None:
        result = InvestigateResult(
            triage=_make_triage(),
            whois=WHOISInfo(expiration_date="2030-01-01T00:00:00"),
        )
        tl = build_timeline(result)
        types = [e.event_type for e in tl.events]
        assert "whois" in types

    def test_multiple_whois_dates_produce_multiple_events(self) -> None:
        result = InvestigateResult(
            triage=_make_triage(),
            whois=WHOISInfo(
                creation_date="2020-01-01T00:00:00",
                updated_date="2022-06-01T00:00:00",
                expiration_date="2030-01-01T00:00:00",
            ),
        )
        tl = build_timeline(result)
        whois_events = [e for e in tl.events if e.event_type == "whois"]
        assert len(whois_events) == 3

    def test_invalid_whois_date_is_skipped(self) -> None:
        result = InvestigateResult(
            triage=_make_triage(),
            whois=WHOISInfo(creation_date="not-a-date"),
        )
        tl = build_timeline(result)
        assert all(e.event_type != "whois" for e in tl.events)


# ---------------------------------------------------------------------------
# Passive DNS
# ---------------------------------------------------------------------------


class TestPassiveDNS:
    def test_passive_dns_record_produces_event(self) -> None:
        result = InvestigateResult(
            triage=_make_triage(),
            passive_dns=[
                PassiveDNSRecord(
                    hostname="evil.com",
                    ip_address="1.2.3.4",
                    last_resolved=_T_MID,
                )
            ],
        )
        tl = build_timeline(result)
        types = [e.event_type for e in tl.events]
        assert "dns_resolution" in types

    def test_passive_dns_without_last_resolved_skipped(self) -> None:
        result = InvestigateResult(
            triage=_make_triage(),
            passive_dns=[PassiveDNSRecord(hostname="evil.com", ip_address="1.2.3.4")],
        )
        tl = build_timeline(result)
        assert all(e.event_type != "dns_resolution" for e in tl.events)

    def test_passive_dns_capped_at_20(self) -> None:
        records = [
            PassiveDNSRecord(
                hostname=f"host{i}.com",
                ip_address="1.2.3.4",
                last_resolved=_T_MID,
            )
            for i in range(30)
        ]
        result = InvestigateResult(triage=_make_triage(), passive_dns=records)
        tl = build_timeline(result)
        dns_events = [e for e in tl.events if e.event_type == "dns_resolution"]
        assert len(dns_events) == 20


# ---------------------------------------------------------------------------
# Sandbox behaviors
# ---------------------------------------------------------------------------


class TestSandboxBehaviors:
    def test_sandbox_with_dns_lookups_and_analysis_date_produces_event(self) -> None:
        result = InvestigateResult(
            triage=_make_triage(last_analysis_date=_T_LATE),
            sandbox_behaviors=[
                SandboxBehavior(
                    sandbox_name="CAPESandbox",
                    dns_lookups=["evil.com", "c2.evil.com"],
                )
            ],
        )
        tl = build_timeline(result)
        types = [e.event_type for e in tl.events]
        assert "sandbox" in types

    def test_sandbox_without_analysis_date_no_event(self) -> None:
        result = InvestigateResult(
            triage=_make_triage(),  # last_analysis_date=None
            sandbox_behaviors=[
                SandboxBehavior(
                    sandbox_name="MySandbox",
                    dns_lookups=["evil.com"],
                )
            ],
        )
        tl = build_timeline(result)
        assert all(e.event_type != "sandbox" for e in tl.events)

    def test_sandbox_without_dns_lookups_no_event(self) -> None:
        result = InvestigateResult(
            triage=_make_triage(last_analysis_date=_T_LATE),
            sandbox_behaviors=[
                SandboxBehavior(
                    sandbox_name="MySandbox",
                    dns_lookups=[],  # empty
                )
            ],
        )
        tl = build_timeline(result)
        assert all(e.event_type != "sandbox" for e in tl.events)


# ---------------------------------------------------------------------------
# Event field content
# ---------------------------------------------------------------------------


class TestEventFields:
    def test_first_seen_source_is_virustotal(self) -> None:
        result = _make_result(first_seen=_T_EARLY)
        tl = build_timeline(result)
        ev = next(e for e in tl.events if e.event_type == "first_seen")
        assert ev.source == "VirusTotal"

    def test_first_seen_description_contains_ioc_type(self) -> None:
        result = _make_result(first_seen=_T_EARLY, ioc_type="hash")
        tl = build_timeline(result)
        ev = next(e for e in tl.events if e.event_type == "first_seen")
        assert "hash" in ev.description

    def test_analysis_description_contains_ratio(self) -> None:
        result = _make_result(last_analysis_date=_T_MID)
        tl = build_timeline(result)
        ev = next(e for e in tl.events if e.event_type == "analysis")
        # ratio_str format: "malicious/total" — must be present
        assert "/" in ev.description
