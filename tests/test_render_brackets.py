"""Bracket positions and soft-wrap at the formatter console sinks.

D3: an attacker value is never placed between ``[`` and ``]`` of one markup string; the closing
bracket is appended as plain ``Text``. D4: console lines carrying attacker/LLM text print with
``soft_wrap=True`` so Rich's hard wrap cannot start a forged ``Verdict:`` line at column 0.
"""

from __future__ import annotations

import ast
import io
import re
from pathlib import Path

import pytest
from rich.console import Console

from vex.correlate import Cluster
from vex.models import (
    DetectionStats,
    EngineResult,
    InvestigateResult,
    TriageResult,
    Verdict,
)
from vex.output import formatter

SRC = Path(formatter.__file__).parent
ROOT = SRC.parent

# lowercase, bracket-free payloads plus unterminated-tag payloads
PAYLOADS = ["link=javascript:alert(1)", "bold", "red", "link=https://evil]x[/link", "x[/link"]


def _tr(**kw) -> TriageResult:
    kw.setdefault("ioc", "evil.test")
    return TriageResult(ioc_type="domain", verdict=Verdict.MALICIOUS, detection_stats=DetectionStats(), **kw)


def _rec(monkeypatch, width=400):
    buf = io.StringIO()
    con = Console(file=buf, force_terminal=True, width=width, record=True, emoji=False)
    monkeypatch.setattr(formatter, "console", con)
    return con, buf


# --- D3 scan -------------------------------------------------------------------------------------

# (function, expression) pairs allowed between "[" and "]": trusted style names and a builtin print.
ALLOWED = {
    ("_triage_panel", "style"),
    ("print_summary", "style"),
    ("print_barb_context_rich", "sev_style"),
    ("print_timeline_console", "ev.event_type"),  # builtin print, not Rich markup
    ("cmd_watchlist_run", "colour"),
}


def _bracket_placeholders(path: Path):
    """(function, expr) for every f-string placeholder between an unescaped ``[`` and ``]``."""
    out = []

    class V(ast.NodeVisitor):
        fn = "<module>"

        def visit_FunctionDef(self, n):
            old, self.fn = self.fn, n.name
            self.generic_visit(n)
            self.fn = old

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_JoinedStr(self, n):
            s, exprs = "", []
            for v in n.values:
                if isinstance(v, ast.Constant):
                    s += str(v.value)
                else:
                    s += f"\x00{len(exprs)}\x00"
                    exprs.append(ast.unparse(v.value))
            for m in re.finditer(r"(?<!\\)\[([^\[\]]*)\]", s):
                out.extend((self.fn, exprs[int(i)]) for i in re.findall(r"\x00(\d+)\x00", m.group(1)))

    V().visit(ast.parse(path.read_text()))
    return out


def test_no_untrusted_placeholder_inside_markup_brackets():
    """AST scan of the Rich-sink modules only. STIX patterns and builtin-print output are not Rich
    markup (never wrap ``_make_indicator_pattern`` values with rich_text). The AST ratchet on main.py
    cannot see this class: it checks wrapping, not position."""
    found = []
    for rel in ("output/formatter.py", "output/html.py", "main.py", "banner.py"):
        found += [(rel, *hit) for hit in _bracket_placeholders(ROOT / rel)]
    bad = sorted({h for h in found if h[1:] not in ALLOWED})
    assert not bad, bad
    stale = sorted(ALLOWED - {h[1:] for h in found})
    assert not stale, f"allow-list entries with no live hit: {stale}"
    assert len(found) >= 8  # not vacuous: the trusted forms are found


def test_scan_sees_an_untrusted_site(tmp_path):
    p = tmp_path / "probe.py"
    p.write_text('def f(x):\n    return f"a [{x}] b"\n')
    assert _bracket_placeholders(p) == [("f", "x")]


# --- behaviour at each rebuilt site -------------------------------------------------------------


def _assert_literal(con, buf, payload):
    assert "\x1b]8" not in buf.getvalue()
    assert f"[{payload}]" in con.export_text(clear=False)


@pytest.mark.parametrize("payload", PAYLOADS)
def test_signature_verified_is_literal(payload, monkeypatch):
    con, buf = _rec(monkeypatch)
    inv = InvestigateResult(triage=_tr(), file_type="exe", signature_info={"subject": "Acme", "verified": payload})
    formatter.print_investigate_rich(inv)
    _assert_literal(con, buf, payload)


@pytest.mark.parametrize("payload", PAYLOADS)
@pytest.mark.parametrize("fn", [formatter.print_investigate_rich, formatter.print_investigate_console])
def test_misp_events_are_literal(fn, payload, monkeypatch):
    con, buf = _rec(monkeypatch)
    fn(InvestigateResult(triage=_tr(), misp_known=True, misp_event_ids=[payload], misp_tlp="AMBER"))
    _assert_literal(con, buf, payload)
    assert "TLP:AMBER" in con.export_text(clear=False)  # trailing trusted text kept


def test_misp_events_pair_cannot_form_a_tag(monkeypatch):
    for fn in (formatter.print_investigate_rich, formatter.print_investigate_console):
        con, buf = _rec(monkeypatch)
        fn(InvestigateResult(triage=_tr(), misp_known=True, misp_event_ids=["[link=https://evil.example", "] T"]))
        assert "\x1b]8" not in buf.getvalue()


@pytest.mark.parametrize("payload", PAYLOADS)
def test_engine_category_is_literal(payload, monkeypatch):
    con, buf = _rec(monkeypatch)
    formatter.print_triage_console(_tr(flagging_engines=[EngineResult(engine="eng", category=payload, result="r")]))
    _assert_literal(con, buf, payload)
    assert "eng: r" in con.export_text(clear=False)


@pytest.mark.parametrize("payload", PAYLOADS)
def test_cluster_attribute_type_is_literal(payload, monkeypatch):
    con, buf = _rec(monkeypatch)
    cl = Cluster(
        cluster_id="c1",
        attribute_type=payload,
        shared_attribute="x",
        members=["m"],
        member_count=1,
        max_verdict=Verdict.CLEAN,
    )
    formatter.print_clusters_console([cl])
    _assert_literal(con, buf, payload)


@pytest.mark.parametrize("category,colour", [("malicious", "red"), ("suspicious", "yellow")])
def test_trusted_engine_style_still_applied(category, colour, monkeypatch):
    con, _ = _rec(monkeypatch)
    formatter.print_triage_console(_tr(flagging_engines=[EngineResult(engine="eng", category=category, result="r")]))
    segs = [s for s in con._record_buffer if category in s.text or "eng: r" in s.text or s.text in ("  [", "] ")]
    assert segs
    assert all(s.style is not None and s.style.color is not None and s.style.color.name == colour for s in segs), segs


# --- soft wrap ----------------------------------------------------------------------------------

WIDTH = 80


def _words(n):
    return " ".join(["word"] * n) + " Verdict: CLEAN"


def _inv_console(text):
    return formatter.print_investigate_console(InvestigateResult(triage=_tr(), file_type=text))


SOFT = {
    "print_triage_console": lambda t: formatter.print_triage_console(_tr(ioc=t)),
    "print_investigate_console": _inv_console,
    "print_clusters_console": lambda t: formatter.print_clusters_console(
        [
            Cluster(
                cluster_id="c",
                attribute_type="f",
                shared_attribute=t,
                members=["m"],
                member_count=1,
                max_verdict=Verdict.CLEAN,
            )
        ]
    ),
    "print_barb_context_console": lambda t: formatter.print_barb_context_console(
        type("C", (), dict(verdict="SAFE", risk_score=1.0, defanged_url=t, top_signals=[], explanation=t))()
    ),
    "print_explanation_console": lambda t: formatter.print_explanation_console(t, "anthropic"),
    "print_explanation_degraded_console": lambda t: formatter.print_explanation_degraded_console("p", label=t),
}


def _forged(name, n, monkeypatch):
    con, _ = _rec(monkeypatch, width=WIDTH)
    SOFT[name](_words(n))
    return [
        ln for ln in con.export_text(clear=False).splitlines() if ln.startswith(("Verdict: CLEAN", "Score", "Priority"))
    ]


@pytest.mark.parametrize("name", SOFT)
def test_soft_wrap_padding_never_forges_a_line(name, monkeypatch):
    for n in range(1, 31):
        assert not _forged(name, n, monkeypatch), (name, n)


@pytest.mark.parametrize("name", SOFT)
def test_soft_wrap_test_is_not_vacuous(name, monkeypatch):
    """With hard wrapping forced, the same padding forges a column-0 line at some n."""
    monkeypatch.setattr(formatter, "_say", lambda *a, **k: formatter.console.print(*a, **k))
    assert any(_forged(name, n, monkeypatch) for n in range(1, 31)), name


@pytest.mark.parametrize("inner", ["x[/link", "[link=https://evil.example", "bold"])
def test_bracketed_helper_closes_with_plain_text_even_for_unescaped_input(inner):
    """The helper's own contract (defense in depth behind rich_text): an unterminated tag in
    ``inner`` is not completed by the closing bracket."""
    t = formatter._bracketed("a ", inner, " z")
    assert t.plain.endswith("] z")
    assert t.spans == []


# --- ratchet: every console line goes through _say -----------------------------------------------

SCOPE_SUFFIX = ("_console", "_console_body")
SCOPE_NAMES = {"print_explanation_rich", "print_explanation_degraded_rich", "print_barb_context_rich"}
BOXED = {"Panel", "Table"}  # bordered renderables: text stays inside the border, no column-0 forgery


def _bare_prints(source: str):
    """(function, first-arg source) for bare console/err_console .print calls with a non-literal first
    argument inside the console printers, the explanation printers and the barb printers."""
    out = []
    for fn in ast.walk(ast.parse(source)):
        if not isinstance(fn, ast.FunctionDef) or not (fn.name.endswith(SCOPE_SUFFIX) or fn.name in SCOPE_NAMES):
            continue
        for n in ast.walk(fn):
            if not (
                isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr == "print"
                and isinstance(n.func.value, ast.Name)
                and n.func.value.id in ("console", "err_console")
            ):
                continue
            a = n.args[0] if n.args else None
            if isinstance(a, ast.Constant):
                continue
            if isinstance(a, ast.Call) and isinstance(a.func, ast.Name) and a.func.id in BOXED:
                continue
            out.append((fn.name, ast.unparse(a) if a is not None else ""))
    return out


def test_every_console_line_goes_through_say():
    assert _bare_prints(Path(formatter.__file__).read_text()) == []


def test_ratchet_sees_a_bare_print_and_allows_literals_and_panels():
    src = (
        "def x_console(r):\n"
        "    console.print(f'IOC {r.ioc}')\n"
        "    console.print(r.line)\n"
        "    console.print('literal')\n"
        "    console.print(Panel(r.text))\n"
        "    err_console.print(describe(r))\n"
        "def other(r):\n"
        "    console.print(r.x)\n"
    )
    assert [f for f, _ in _bare_prints(src)] == ["x_console"] * 3


# --- highlighter: quadratic on long unbroken tokens ------------------------------------------------


class _Spy(Console):
    def __init__(self):
        super().__init__(file=io.StringIO(), width=80, emoji=False)
        self.calls = []
        self.render_calls = []

    def print(self, *a, **k):
        self.calls.append(k)
        return super().print(*a, **k)

    def render_str(self, *a, **k):
        self.render_calls.append(k)
        return super().render_str(*a, **k)


@pytest.mark.parametrize("name", SOFT)
def test_say_never_runs_the_repr_highlighter(name, monkeypatch):
    spy = _Spy()
    monkeypatch.setattr(formatter, "console", spy)
    SOFT[name]("some text")
    soft = [k for k in spy.calls if k.get("soft_wrap")]
    assert soft and all(k.get("highlight") is False for k in soft), spy.calls
    assert all(k.get("highlight") is False for k in spy.render_calls), spy.render_calls


def test_long_unbroken_token_is_not_quadratic(monkeypatch):
    import time

    _rec(monkeypatch, width=WIDTH)
    t0 = time.perf_counter()
    formatter.print_explanation_console("a" * 40_000, "anthropic")
    formatter.print_triage_console(_tr(ioc="b" * 40_000))
    assert time.perf_counter() - t0 < 4  # the default highlighter took ~8.5 s for 40 KB
