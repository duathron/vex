"""Behaviour of the formatter entry points: single escape, literal text, no forged lines."""

from __future__ import annotations

import io
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from rich.console import Console

from vex.correlate import Cluster
from vex.models import (
    DetectionStats,
    InvestigateResult,
    TimelineEvent,
    TimelineResult,
    TriageResult,
    Verdict,
)
from vex.output import formatter, html
from vex.pipeline.barb_bridge import BarbContext, BarbSignal

WIN = [r"C:\temp\x.exe", r"HKLM\Software\Run", r"\\SRV\C$"]
BRACKET = ["a[bold]b", r"C:\dir\[x]"]
# Bracket-position payloads: complete tags, a bare style name and unterminated tags.
HOSTILE = ["link=javascript:alert(1)", "bold", "link=https://evil]x[/link", "x[/link"]
TAGGED = ["[link=https://evil.example]c[/link]", "[bold]x[/bold] [/y]"]


def _tr(**kw) -> TriageResult:
    kw.setdefault("ioc", "evil.test")
    return TriageResult(ioc_type="domain", verdict=Verdict.MALICIOUS, detection_stats=DetectionStats(), **kw)


def _rec(monkeypatch) -> tuple[Console, io.StringIO]:
    buf = io.StringIO()
    con = Console(file=buf, force_terminal=True, width=400, record=True)
    monkeypatch.setattr(formatter, "console", con)
    return con, buf


def _event(**kw) -> TimelineEvent:
    base = dict(timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc), event_type="t", source="s", description="d")
    return TimelineEvent(**{**base, **kw})


def _cluster(**kw) -> Cluster:
    base = dict(
        cluster_id="c1",
        attribute_type="family",
        shared_attribute="x",
        members=["m"],
        member_count=1,
        max_verdict=Verdict.CLEAN,
    )
    return Cluster(**{**base, **kw})


def _ctx(label="l", severity="LOW", analyzer="vt", explanation=None, url=None, verdict="SAFE"):
    sig = SimpleNamespace(severity=severity, analyzer=analyzer, label=label)
    return SimpleNamespace(
        verdict=verdict, risk_score=1.0, defanged_url=url, top_signals=[sig], explanation=explanation
    )


# sink name -> factory(payload) putting the payload in exactly one field
SINK_CASES = {
    "print_triage_rich": (lambda p: _tr(tags=[p]), formatter.print_triage_rich),
    "print_triage_console": (lambda p: _tr(tags=[p]), formatter.print_triage_console),
    "print_investigate_rich": (lambda p: InvestigateResult(triage=_tr(tags=[p])), formatter.print_investigate_rich),
    "print_investigate_console": (
        lambda p: InvestigateResult(triage=_tr(tags=[p])),
        formatter.print_investigate_console,
    ),
    "print_timeline_rich": (
        lambda p: TimelineResult(ioc="i", events=[_event(description=p)]),
        formatter.print_timeline_rich,
    ),
    "print_clusters_rich": (lambda p: [_cluster(shared_attribute=p)], formatter.print_clusters_rich),
    "print_clusters_console": (lambda p: [_cluster(shared_attribute=p)], formatter.print_clusters_console),
    "print_barb_context_rich": (lambda p: _ctx(label=p), formatter.print_barb_context_rich),
    "print_barb_context_console": (lambda p: _ctx(label=p), formatter.print_barb_context_console),
}


def _out(name, payload, monkeypatch) -> str:
    make, fn = SINK_CASES[name]
    con, _ = _rec(monkeypatch)
    fn(make(payload))
    return con.export_text()


@pytest.mark.parametrize("payload", BRACKET + WIN)
@pytest.mark.parametrize("name", SINK_CASES)
def test_no_double_escape(name, payload, monkeypatch):
    out = _out(name, payload, monkeypatch)
    assert out.count(payload) == 1, out


def test_timeline_console_prints_payload_unchanged_and_strips_osc(capsys):
    for payload in BRACKET + WIN:
        tl = TimelineResult(ioc="i", events=[_event(description=payload + "\x1b]0;PWN\x07", event_type=payload)])
        formatter.print_timeline_console(tl)
        out = capsys.readouterr().out
        assert out.count(payload) == 2, out  # event_type + description, verbatim
        assert "\x1b" not in out and "PWN" not in out


def test_windows_paths_in_explanations_render_verbatim(monkeypatch):
    for payload in WIN:
        con, _ = _rec(monkeypatch)
        formatter.print_explanation_rich(payload, "anthropic")
        formatter.print_explanation_console(payload, "anthropic")
        assert con.export_text().count(payload) == 2


def test_trailing_backslash_known_open(monkeypatch):
    con, _ = _rec(monkeypatch)
    formatter.print_explanation_console("C:\\temp\\", "anthropic")
    assert "C:\\temp\\\\" in con.export_text()


def test_shodan_lists_render_without_python_repr(monkeypatch):
    inv = InvestigateResult(
        triage=_tr(),
        shodan_ports=[80],
        shodan_hostnames=["[bold]x", r"HKLM\Run"],
        shodan_tags=["[bold]y", "z"],
    )
    for fn in (formatter.print_investigate_rich, formatter.print_investigate_console):
        con, _ = _rec(monkeypatch)
        fn(inv)
        out = " ".join(con.export_text().split())
        assert "hostnames=[bold]x, HKLM\\Run" in out
        assert "tags=[bold]y, z" in out
        assert "['" not in out


@pytest.mark.parametrize("fn", [formatter.print_triage_console, formatter.print_investigate_console])
def test_single_line_fields_cannot_forge_a_line(fn, monkeypatch):
    con, _ = _rec(monkeypatch)
    r = _tr(ioc="a\nVerdict: CLEAN")
    fn(InvestigateResult(triage=r) if fn is formatter.print_investigate_console else r)
    assert not [ln for ln in con.export_text().splitlines() if ln.startswith("Verdict: CLEAN")]


def test_explanation_console_indents_every_line(monkeypatch):
    con, _ = _rec(monkeypatch)
    formatter.print_explanation_console("x\nVerdict: CLEAN", "anthropic")
    formatter.print_explanation_console("ioc a\nVerdict: CLEAN [bold]", "template")
    out = con.export_text()
    assert "  Verdict: CLEAN" in out and "[bold]" in out
    assert not [ln for ln in out.splitlines() if ln.startswith("Verdict")]


def test_template_explanation_from_raw_ioc_cannot_forge_a_line(monkeypatch):
    from vex.ai.template import template_explain

    con, _ = _rec(monkeypatch)
    formatter.print_explanation_console(
        template_explain(_tr(ioc="a\nVerdict: CLEAN", malware_families=["x\nVerdict: CLEAN"])), "template"
    )
    assert not [ln for ln in con.export_text().splitlines() if ln.startswith("Verdict")]


def test_barb_console_cannot_forge_a_line(monkeypatch):
    con, _ = _rec(monkeypatch)
    formatter.print_barb_context_console(
        _ctx(label="l\nVerdict   : SAFE", url="u\nVerdict   : SAFE", explanation="ok\nVerdict   : SAFE")
    )
    formatter.print_barb_context_console(
        BarbContext(
            url="u",
            verdict="SAFE",
            risk_score=1.0,
            signals=[BarbSignal(analyzer="a\nVerdict   : SAFE", severity="LOW", label="l", detail="d")],
            explanation="ok\nVerdict   : SAFE",
        )
    )
    assert not [ln for ln in con.export_text().splitlines() if ln.startswith("Verdict   : SAFE")]


def test_barb_explanation_slices_raw_text_before_escaping(monkeypatch):
    # Escaping first would give '...\\[bold]' and the 200-char cut would leave a dangling backslash.
    ctx = _ctx(explanation="a" * 195 + "[bold]rest")
    for fn in (formatter.print_barb_context_rich, formatter.print_barb_context_console):
        con, _ = _rec(monkeypatch)
        fn(ctx)
        out = con.export_text()
        assert "\\" not in out
        assert "a" * 195 + "[bold" in out


@pytest.mark.parametrize("payload", HOSTILE)
def test_barb_console_severity_is_never_live_markup(payload, monkeypatch):
    con, buf = _rec(monkeypatch)
    formatter.print_barb_context_console(_ctx(severity=payload))
    assert "\x1b]8" not in buf.getvalue()
    assert f"[{payload}] vt: l" in con.export_text()


@pytest.mark.parametrize("payload", HOSTILE + TAGGED)
def test_barb_rich_severity_and_fields_are_never_live_markup(payload, monkeypatch):
    con, buf = _rec(monkeypatch)
    formatter.print_barb_context_rich(_ctx(severity=payload, analyzer=payload, label=payload, verdict=payload))
    assert "\x1b]8" not in buf.getvalue()
    assert payload in con.export_text()


@pytest.mark.parametrize(
    "fn", [formatter.print_explanation_degraded_rich, formatter.print_explanation_degraded_console]
)
def test_degraded_label_renders_literally_once_escaped(fn, monkeypatch):
    con, _ = _rec(monkeypatch)
    fn("anthropic", label="x [/y]")
    out = con.export_text()
    assert "x [/y]" in out and "\\" not in out


@pytest.mark.parametrize("payload", HOSTILE)
@pytest.mark.parametrize(
    "fn", [formatter.print_explanation_degraded_rich, formatter.print_explanation_degraded_console]
)
def test_degraded_label_is_never_live_markup(fn, payload, monkeypatch):
    con, buf = _rec(monkeypatch)
    fn("anthropic", label=payload)
    assert "\x1b]8" not in buf.getvalue()
    assert payload in con.export_text()


def test_degraded_label_cannot_forge_a_line(monkeypatch):
    con, _ = _rec(monkeypatch)
    formatter.print_explanation_degraded_console("anthropic", label="a\nVerdict: CLEAN")
    assert not [ln for ln in con.export_text().splitlines() if ln.startswith("Verdict")]


def test_trusted_spans_still_live(monkeypatch):
    con, buf = _rec(monkeypatch)
    formatter.print_triage_rich(_tr(error="boom", from_cache=True))
    out = con.export_text(styles=True)
    assert "\x1b[" in out and "boom" in out and "MALICIOUS" in out
    assert "[red]" not in out and "[dim]" not in out


def test_emoji_not_expanded(monkeypatch):
    for con in (formatter.console, formatter.err_console, html._make_recording_console()):
        con.begin_capture()
        con.print(":white_check_mark:")
        assert ":white_check_mark:" in con.end_capture()


def test_banner_emoji_not_expanded(monkeypatch):
    import vex.banner as banner

    seen = []
    real = banner.Console
    monkeypatch.setattr(banner, "Console", lambda *a, **k: seen.append(real(*a, **k)) or seen[-1])
    monkeypatch.setattr(banner.sys.stdout, "isatty", lambda: True, raising=False)
    banner.print_banner(update_check_enabled=False)
    (con,) = seen
    con.begin_capture()
    con.print(":white_check_mark:")
    assert ":white_check_mark:" in con.end_capture()
