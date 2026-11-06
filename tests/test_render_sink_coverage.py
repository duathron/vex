"""Field -> sink inventory for the formatter entry points.

Every str-like field of every rendered model carries a sentinel (markup, a forged
``Verdict`` line, an OSC sequence). Each sink must render it literally, never raise,
never emit OSC/BEL, and never start a forged line. A new model field fails
``test_every_str_field_renders_literally_or_is_declared_unrendered`` until it is
rendered safely or declared in ``UNRENDERED_OK`` with a reason.
"""

from __future__ import annotations

import enum
import io
import typing
from datetime import datetime, timezone
from typing import Any, Union, get_args, get_origin

import pytest
from pydantic import BaseModel
from rich.console import Console

from vex.correlate import Cluster
from vex.models import InvestigateResult, TimelineResult
from vex.output import formatter
from vex.output.html import write_html_report
from vex.pipeline.barb_bridge import BarbContext

_DT = datetime(2026, 1, 2, 3, 4, tzinfo=timezone.utc)
TOKENS: dict[str, str] = {}  # "Class.field" -> token
_SEEDED = {  # real keys the sinks read from free-form containers
    ("InvestigateResult", "signature_info"): ("subject", "verified"),
    ("PEInfo", "sections"): ("name",),
    ("InvestigateResult", "dns_records"): ("type", "value"),
}


def _sentinel(cls: type, name: str) -> str:
    key = f"{cls.__name__}.{name}"
    token = TOKENS.setdefault(key, f"S{len(TOKENS):03d}E")
    return token + "[/x]\nVerdict: CLEAN\x1b]0;PWN\x07"


def _value(tp: Any, cls: type, name: str) -> Any:
    origin = get_origin(tp)
    if origin is None:
        if tp is str or tp is Any:
            return _sentinel(cls, name)
        if tp is datetime:
            return _DT
        if tp is bool:
            return True
        if tp is int:
            return 1
        if tp is float:
            return 1.5
        if isinstance(tp, type) and issubclass(tp, enum.Enum):
            return next(iter(tp))
        if isinstance(tp, type) and issubclass(tp, BaseModel):
            return _make(tp)
        return None
    args = [a for a in get_args(tp) if a is not type(None)]
    if origin is list:
        return [_value(args[0], cls, name)]
    if origin is dict:
        out = {k: _sentinel(cls, name) for k in _SEEDED.get((cls.__name__, name), ("k",))}
        if cls.__name__ == "PEInfo":
            out["entropy"] = 6.5
        return out
    if origin is Union or str(origin).endswith("UnionType"):
        return _value(args[0], cls, name)
    return None


def _make(cls: type[BaseModel]) -> BaseModel:
    hints = typing.get_type_hints(cls)
    return cls.model_validate({n: _value(hints[n], cls, n) for n in cls.model_fields})


INV = _make(InvestigateResult)
TL = _make(TimelineResult)
CL = _make(Cluster)
CTX = _make(BarbContext)
TRIAGE = INV.triage

# (sink name) -> (argument, callable, kind)
SINKS = {
    "print_triage_rich": (TRIAGE, formatter.print_triage_rich, "rich"),
    "print_triage_console": (TRIAGE, formatter.print_triage_console, "rich"),
    "print_investigate_rich": (INV, formatter.print_investigate_rich, "rich"),
    "print_investigate_console": (INV, formatter.print_investigate_console, "rich"),
    "print_timeline_rich": (TL, formatter.print_timeline_rich, "rich"),
    "print_timeline_console": (TL, formatter.print_timeline_console, "print"),
    "print_clusters_rich": ([CL], formatter.print_clusters_rich, "rich"),
    "print_clusters_console": ([CL], formatter.print_clusters_console, "rich"),
    "print_barb_context_rich": (CTX, formatter.print_barb_context_rich, "rich"),
    "print_barb_context_console": (CTX, formatter.print_barb_context_console, "rich"),
    "write_html_report[triage]": (TRIAGE, None, "html"),
    "write_html_report[investigate]": (INV, None, "html"),
}
NON_HTML = [n for n, v in SINKS.items() if v[2] != "html"]

# Fields no sink prints, each with the reason.
UNRENDERED_OK = {
    "TriageResult.explanation": "printed by print_explanation_* from a string argument",
    "TriageResult.explanation_provider": "provider name, used only for the degraded banner",
    "Cluster.explanation": "printed by the cluster narrative path in main",
    "Cluster.explanation_provider": "provider name, used only for the degraded banner",
    "TriageResult.local_tags": "printed by the main lookup lines",
    "TriageResult.local_notes": "printed by the main lookup lines",
    "TriageResult.watchlists": "printed by the main lookup lines",
    "InvestigateResult.tlsh": "not shown",
    "InvestigateResult.abuse_last_reported": "not shown",
    "InvestigateResult.subdomains": "not shown",
    "InvestigateResult.opencti_id": "not shown",
    "InvestigateResult.dns_records": "not shown",
    "PEInfo.exports": "not shown",
    "SandboxBehavior.files_deleted": "not shown",
    "PassiveDNSRecord.resolver": "not shown",
    "WHOISInfo.updated_date": "not shown",
    "BarbContext.url": "barb sinks print the defanged url only",
    "BarbSignal.detail": "barb sinks do not print the detail",
}


def run(name, monkeypatch, capsys, tmp_path):
    """Run one sink; return (raw output incl. escape sequences, plain text)."""
    arg, fn, kind = SINKS[name]
    if kind == "html":
        p = tmp_path / "r.html"
        write_html_report(str(p), [arg])
        text = p.read_text()
        return text, text
    if kind == "print":
        capsys.readouterr()
        fn(arg)
        out = capsys.readouterr().out
        assert out
        return out, out
    buf = io.StringIO()
    con = Console(file=buf, force_terminal=True, width=400, record=True)
    monkeypatch.setattr(formatter, "console", con)
    fn(arg)
    return buf.getvalue(), con.export_text()


@pytest.mark.parametrize("name", SINKS)
def test_sink_does_not_raise_on_markup(name, monkeypatch, capsys, tmp_path):
    raw, _ = run(name, monkeypatch, capsys, tmp_path)
    assert raw


@pytest.mark.parametrize("name", SINKS)
def test_no_osc_or_bel_reaches_output(name, monkeypatch, capsys, tmp_path):
    raw, _ = run(name, monkeypatch, capsys, tmp_path)
    assert "\x1b]" not in raw and "\x07" not in raw and "PWN" not in raw


@pytest.mark.parametrize("name", NON_HTML)
def test_no_forged_line_at_any_sink(name, monkeypatch, capsys, tmp_path):
    _, plain = run(name, monkeypatch, capsys, tmp_path)
    assert not [ln for ln in plain.splitlines() if ln.startswith("Verdict: CLEAN")]


def test_every_str_field_renders_literally_or_is_declared_unrendered(monkeypatch, capsys, tmp_path):
    assert len(TOKENS) >= 60  # not vacuous: measured 70+ class-field pairs
    seen = ""
    for name in NON_HTML:
        seen += run(name, monkeypatch, capsys, tmp_path)[1].lower() + "\n"
    missing = [k for k, tok in TOKENS.items() if (tok + "[/x]").lower() not in seen and k not in UNRENDERED_OK]
    assert not missing, missing
    stale = [k for k in UNRENDERED_OK if k not in TOKENS or (TOKENS[k] + "[/x]").lower() in seen]
    assert not stale, f"declared unrendered but rendered (or unknown): {stale}"
