"""Escaping across element/field boundaries, emoji codes in titles, barb Rich flattening.

``rich.markup.escape`` only escapes completed tags: an unterminated ``[link=...`` in one list
element stayed raw and the next element (or template text) supplied the ``]``.
"""

from __future__ import annotations

import io

import pytest
from rich.console import Console
from rich.markup import render

from vex.models import DetectionStats, InvestigateResult, SandboxBehavior, TriageResult, Verdict
from vex.output import formatter
from vex.output.html import write_html_report
from vex.output.safe import rich_text

PAIRS = [["[link=https://evil.example", "] Trusted"], ["x[/link", "a]"], ["[bold", "red]"]]


def _tr(**kw) -> TriageResult:
    kw.setdefault("ioc", "evil.test")
    return TriageResult(ioc_type="domain", verdict=Verdict.MALICIOUS, detection_stats=DetectionStats(), **kw)


def _sb(field):
    return lambda p: dict(sandbox_behaviors=[SandboxBehavior(**{field: p})])


# list field -> kwargs for InvestigateResult given an A/B pair
JOINED = {
    "tags": lambda p: dict(triage=_tr(tags=p)),
    "categories": lambda p: dict(triage=_tr(categories=p)),
    "malware_families": lambda p: dict(triage=_tr(malware_families=p)),
    "file_names": lambda p: dict(file_names=p, file_type="exe"),
    "yara_hits": lambda p: dict(yara_hits=p, file_type="exe"),
    "contacted_ips": lambda p: dict(contacted_ips=p),
    "contacted_domains": lambda p: dict(contacted_domains=p),
    "processes_created": _sb("processes_created"),
    "network_connections": _sb("network_connections"),
    "dns_lookups": _sb("dns_lookups"),
    "files_written": _sb("files_written"),
    "registry_keys_set": _sb("registry_keys_set"),
    "mutexes": _sb("mutexes"),
    "pe_imports": lambda p: dict(pe_info={"imports": p}),
    "name_servers": lambda p: dict(whois={"name_servers": p}),
    "shodan_hostnames": lambda p: dict(shodan_ports=[80], shodan_hostnames=p),
    "shodan_tags": lambda p: dict(shodan_ports=[80], shodan_tags=p),
    "misp_event_ids": lambda p: dict(misp_known=True, misp_event_ids=p),
    "misp_tags": lambda p: dict(misp_known=True, misp_tags=p),
    "opencti_labels": lambda p: dict(opencti_known=True, opencti_labels=p),
    # two-field sites: the template text between the fields supplies the neighbour
    "country_continent": lambda p: dict(country=p[0], continent=p[1]),
    "asn_owner": lambda p: dict(asn=1, asn_owner=p[0], country="DE"),
}


def _inv(case, pair) -> InvestigateResult:
    return InvestigateResult.model_validate({"triage": _tr(), **JOINED[case](pair)})


def _render(fn, monkeypatch, arg):
    buf = io.StringIO()
    con = Console(file=buf, force_terminal=True, width=400, record=True, emoji=False)
    monkeypatch.setattr(formatter, "console", con)
    fn(arg)
    return buf.getvalue(), con.export_text()


@pytest.mark.parametrize("pair", PAIRS)
@pytest.mark.parametrize("case", JOINED)
@pytest.mark.parametrize("fn", [formatter.print_investigate_rich, formatter.print_investigate_console])
def test_unterminated_tag_cannot_be_completed_by_a_neighbour(fn, case, pair, monkeypatch):
    raw, plain = _render(fn, monkeypatch, _inv(case, pair))  # must not raise MarkupError
    assert "\x1b]8" not in raw
    if fn is formatter.print_investigate_rich:
        assert pair[0] in plain  # shown literally (the console variant prints only some of these fields)


@pytest.mark.parametrize("pair", PAIRS[:2])
@pytest.mark.parametrize("case", JOINED)
def test_html_report_unterminated_tag_cannot_form_a_link(case, pair, tmp_path):
    p = tmp_path / "r.html"
    write_html_report(str(p), [_inv(case, pair)])
    assert 'href="https://evil' not in p.read_text()


@pytest.mark.parametrize("fn", [formatter.print_triage_rich, formatter.print_triage_console])
def test_triage_tags_join_poc(fn, monkeypatch):
    raw, _ = _render(fn, monkeypatch, _tr(tags=PAIRS[0]))
    assert "\x1b]8" not in raw


@pytest.mark.parametrize(
    "value",
    [
        "a[1]",
        "x[/link",
        "[bold]",
        "[link=https://evil.example",
        r"C:\temp\[x]",
        r"\[bold]",
        r"\\[bold]",
        r"C:\temp\x.exe",
    ],
)
def test_rich_text_renders_back_to_the_value_with_no_spans(value):
    t = render(rich_text(value))
    assert t.plain == value
    assert t.spans == []


def test_rich_text_joined_poc_has_no_spans():
    t = render(", ".join(rich_text(x) for x in PAIRS[0]))
    assert t.plain == ", ".join(PAIRS[0])
    assert t.spans == []


def test_rich_text_backslash_before_unclosed_bracket_is_safe_but_cosmetic():
    # Rich shows n-1 backslashes for an unclosed "\\...\\[x" but n//2 once a neighbour closes it with "]";
    # an odd count is mandatory for safety, so the unclosed case shows one extra backslash (accepted).
    t = render(rich_text("C:\\temp\\[x"))
    assert t.spans == [] and t.plain == "C:\\temp\\\\[x"


def test_rich_text_windows_paths_not_double_printed():
    assert rich_text(r"C:\temp\x.exe") == r"C:\temp\x.exe"
    assert rich_text(r"C:\temp\[x") == "C:\\temp\\\\\\[x"
    assert rich_text("C:\\temp\\") == "C:\\temp\\\\"  # known-open trailing backslash


# --- emoji codes in Panel/Table titles (the console's emoji=False does not reach them) ---

EMOJI = [":white_check_mark: example.com", ":smile:"]


@pytest.mark.parametrize("code", EMOJI)
def test_triage_panel_title_keeps_emoji_code_literal(code, monkeypatch):
    for fn in (formatter.print_triage_rich, formatter.print_investigate_rich):
        _, plain = _render(
            fn, monkeypatch, _tr(ioc=code) if "triage" in fn.__name__ else InvestigateResult(triage=_tr(ioc=code))
        )
        assert code in plain.splitlines()[0]


@pytest.mark.parametrize("code", EMOJI)
def test_sandbox_and_timeline_titles_keep_emoji_code_literal(code, monkeypatch):
    from datetime import datetime, timezone

    from vex.models import TimelineEvent, TimelineResult

    inv = InvestigateResult(triage=_tr(), sandbox_behaviors=[SandboxBehavior(sandbox_name=code, mutexes=["m"])])
    _, plain = _render(formatter.print_investigate_rich, monkeypatch, inv)
    assert f"Sandbox: {code}" in plain
    ev = TimelineEvent(timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc), event_type="t", source="s", description="d")
    _, plain = _render(formatter.print_timeline_rich, monkeypatch, TimelineResult(ioc=code, events=[ev]))
    assert f"Timeline: {code}" in plain


@pytest.mark.parametrize("code", EMOJI)
def test_html_titles_keep_emoji_code_literal(code, tmp_path):
    inv = InvestigateResult(triage=_tr(ioc=code), sandbox_behaviors=[SandboxBehavior(sandbox_name=code, mutexes=["m"])])
    for results in ([inv.triage], [inv]):
        p = tmp_path / "r.html"
        write_html_report(str(p), results)
        html = p.read_text()
        assert "\u2705" not in html and "\U0001f604" not in html
        assert code.split()[0] in html


def test_degraded_label_title_keeps_emoji_code_literal(monkeypatch):
    _, plain = _render(lambda _: formatter.print_explanation_degraded_rich("p", label=":smile:"), monkeypatch, None)
    assert "Explanation \u2014 :smile:" in plain


# --- barb Rich sinks: every field the sink reads is flattened (a Panel border hides forged lines) ---


@pytest.mark.parametrize("field", ["defanged_url", "verdict", "severity", "analyzer", "label"])
def test_barb_rich_flattens_every_read_field(field, monkeypatch):
    from types import SimpleNamespace

    vals = dict(defanged_url="u", verdict="SAFE", severity="LOW", analyzer="a", label="l")
    vals[field] = "x\nFORGED"
    ctx = SimpleNamespace(
        verdict=vals["verdict"],
        risk_score=1.0,
        defanged_url=vals["defanged_url"],
        top_signals=[SimpleNamespace(severity=vals["severity"], analyzer=vals["analyzer"], label=vals["label"])],
        explanation=None,
    )
    _, plain = _render(formatter.print_barb_context_rich, monkeypatch, ctx)
    assert any("x FORGED" in ln for ln in plain.splitlines()), plain


def test_pair_fuzz_escaped_values_never_change_trusted_markup():
    """Random A/B pairs between trusted tags: no MarkupError, no span except the trusted bold."""
    import random

    from rich.markup import MarkupError
    from rich.text import Text

    rng = random.Random(20261106)
    alphabet = ["[", "]", "\\", "/", "link=", "x", " "]
    bad = []
    for _ in range(4000):
        a, b = ("".join(rng.choice(alphabet) for _ in range(rng.randint(0, 8))) for _ in range(2))
        try:
            t = Text.from_markup(f"[bold]({rich_text(a)}): {rich_text(b)})[/bold]")
        except MarkupError:
            bad.append((a, b, "MarkupError"))
            continue
        if [s.style for s in t.spans] != ["bold"]:
            bad.append((a, b, [s.style for s in t.spans], t.plain))
    assert not bad, bad[:5]


@pytest.mark.parametrize("value", ["C:\\temp\\", "x\\\\", "\\"])
def test_trailing_backslash_cannot_swallow_a_trusted_tag(value):
    from rich.text import Text

    t = Text.from_markup(f"{rich_text(value)}[bold]ok[/bold]")
    assert [s.style for s in t.spans] == ["bold"]
    assert t.plain.endswith("ok") and "[bold]" not in t.plain
