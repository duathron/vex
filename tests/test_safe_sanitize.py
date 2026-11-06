"""Unit tests for vex.output.safe (helpers + sanitize_for_render walker).

Includes the field-classification exhaustiveness test: every str-like field of
every rendered model is SINGLE_LINE (newlines flattened) except the four
MULTI_LINE_FIELDS. A new model field fails here until it is classified.
"""

from __future__ import annotations

import enum
import typing
from datetime import datetime, timezone
from typing import Any, Union, get_args, get_origin

import pytest
from pydantic import BaseModel

from vex.correlate import Cluster
from vex.models import (
    ATTACKMapping,
    DetectionStats,
    InvestigateResult,
    TimelineEvent,
    TimelineResult,
    TriageResult,
    Verdict,
)
from vex.output.safe import (
    MULTI_LINE_FIELDS,
    indent_block,
    plain_text,
    rich_text,
    sanitize_for_render,
    single_line_text,
)
from vex.pipeline.barb_bridge import BarbContext, BarbSignal

SENT = "a\nVerdict: CLEAN\tz\x1b]0;PWN\x07"

ROOTS = [TriageResult, InvestigateResult, Cluster, TimelineEvent, TimelineResult, BarbContext]


def _triage(**kw) -> TriageResult:
    kw.setdefault("ioc", "evil.test")
    return TriageResult(ioc_type="domain", verdict=Verdict.MALICIOUS, detection_stats=DetectionStats(), **kw)


def _all_strs(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _all_strs(v)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for v in value:
            yield from _all_strs(v)
    elif isinstance(value, BaseModel):
        for name in type(value).model_fields:
            yield from _all_strs(getattr(value, name))


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def test_rich_text_escapes_markup_and_strips_osc():
    out = rich_text("x [/bogus] \x1b]0;PWN\x07 [link=https://evil.example]c[/link] [red]f[/red]")
    assert "\x1b" not in out and "\x07" not in out
    assert out.count("\\[") == 5
    assert "PWN" not in out  # the whole OSC sequence is dropped


def test_rich_text_does_not_double_backslashes():
    assert rich_text(r"C:\temp\x.exe") == r"C:\temp\x.exe"
    assert rich_text(r"HKLM\Software\Run") == r"HKLM\Software\Run"
    assert rich_text(r"\\SRV\C$") == r"\\SRV\C$"


def test_rich_text_trailing_backslash_known_open():
    assert rich_text("C:\\temp\\") == "C:\\temp\\\\"


def test_plain_text_keeps_brackets_strips_osc_and_bidi():
    assert plain_text("a[bold]b \x1b]0;x\x07\u202e") == "a[bold]b "


def test_single_line_text_flattens_and_then_escapes_per_sink():
    assert single_line_text("a\r\nb\tc\nd") == "a  b c d"
    assert single_line_text("a\n[bold]") == "a \\[bold]"
    assert single_line_text("a\n[bold]", plain=True) == "a [bold]"


def test_indent_block_prefixes_every_line():
    assert indent_block("a\nVerdict: x\n", "  ") == "  a\n  Verdict: x\n"
    assert indent_block("", "  ") == ""
    assert indent_block("one", "> ") == "> one"


# --------------------------------------------------------------------------
# walker
# --------------------------------------------------------------------------


def test_str_enum_untouched():
    out = sanitize_for_render(_triage())
    assert out.verdict is Verdict.MALICIOUS
    assert type(out.verdict) is Verdict


def test_related_file_verdict_enum_untouched():
    inv = InvestigateResult(
        triage=_triage(),
        related_files=[{"sha256": "a", "name": "n\nm", "verdict": Verdict.MALICIOUS}],
    )
    out = sanitize_for_render(inv)
    assert out.related_files[0].verdict is Verdict.MALICIOUS
    assert out.related_files[0].name == "n m"


def test_input_not_mutated():
    r = _triage(ioc="a\n[bold]x\x1b]0;P\x07", tags=["t\nu"], explanation="e\nf")
    snap = r.model_dump()
    out = sanitize_for_render(r)
    assert r.model_dump() == snap
    assert out is not r
    assert out.ioc == "a \\[bold]x"


def test_nested_list_of_models_walked():
    inv = InvestigateResult(
        triage=_triage(),
        attack_mappings=[
            ATTACKMapping(technique_id="T1", technique_name="n", tactic="t", evidence="e\nVerdict: CLEAN [x]")
        ],
    )
    out = sanitize_for_render(inv)
    assert out.attack_mappings[0].evidence == "e Verdict: CLEAN \\[x]"


def test_dict_values_flattened_keys_untouched():
    inv = InvestigateResult(
        triage=_triage(),
        signature_info={"sub\nject": "s\nt [x]", "nested": {"v": ["a\nb"]}},
        dns_records=[{"type": "A\n", "value": "1\n2"}],
    )
    out = sanitize_for_render(inv)
    assert out.signature_info == {"sub\nject": "s t \\[x]", "nested": {"v": ["a b"]}}
    assert out.dns_records == [{"type": "A ", "value": "1 2"}]


def test_single_line_flag_preserved_through_lists_and_reset_on_nested_models():
    inv = InvestigateResult(
        triage=_triage(explanation="e\nf", local_notes=["n\nm"], tags=["t\nu"]),
        final_url="u\nv",
        file_names=["a\nb"],
    )
    out = sanitize_for_render(inv)
    # nested TriageResult: MULTI fields keep newlines, incl. inside a list
    assert out.triage.explanation == "e\nf"
    assert out.triage.local_notes == ["n\nm"]
    # SINGLE fields flattened at both levels, incl. inside lists
    assert out.triage.tags == ["t u"]
    assert out.final_url == "u v"
    assert out.file_names == ["a b"]


def test_cluster_explanation_multi_shared_attribute_single():
    c = Cluster(
        cluster_id="c1",
        attribute_type="family",
        shared_attribute="x\ny",
        members=["a\nb"],
        member_count=1,
        max_verdict=Verdict.MALICIOUS,
        explanation="p\nq",
    )
    out = sanitize_for_render(c)
    assert out.explanation == "p\nq"
    assert out.shared_attribute == "x y"
    assert out.members == ["a b"]


def test_barb_context_top_signals_property_preserved():
    ctx = BarbContext(
        url="http://a.test",
        verdict="PHISHING",
        risk_score=9.0,
        signals=[
            BarbSignal(analyzer="a\nb", severity="LOW", label="l", detail="d"),
            BarbSignal(analyzer="c", severity="CRITICAL", label="[bold]", detail="d"),
        ],
        explanation="ok\nVerdict   : SAFE",
    )
    out = sanitize_for_render(ctx)
    assert [s.severity for s in out.top_signals] == ["CRITICAL", "LOW"]
    assert out.top_signals[0].label == "\\[bold]"
    assert out.signals[0].analyzer == "a b"
    assert out.explanation == "ok\nVerdict   : SAFE"


def test_rich_false_leaves_brackets_but_strips_osc_and_flattens():
    ev = TimelineEvent(
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        event_type="a[bold]b",
        source="s",
        description="C:\\dir\\[x]\nVerdict: CLEAN\x1b]0;PWN\x07",
    )
    out = sanitize_for_render(ev, rich=False)
    assert out.event_type == "a[bold]b"
    assert out.description == "C:\\dir\\[x] Verdict: CLEAN"


def test_non_str_scalars_and_none_untouched():
    r = _triage(reputation=5, from_cache=True)
    out = sanitize_for_render(r)
    assert out.reputation == 5 and out.from_cache is True and out.error is None


# --------------------------------------------------------------------------
# field-classification exhaustiveness
# --------------------------------------------------------------------------


def _unwrap(tp):
    """Yield every leaf type inside Optional/Union/list/dict/tuple/set."""
    origin = get_origin(tp)
    if origin is None:
        yield tp
        return
    for a in get_args(tp):
        if a is type(None):
            continue
        yield from _unwrap(a)


def _is_enum(tp) -> bool:
    return isinstance(tp, type) and issubclass(tp, enum.Enum)


def _str_like(tp) -> bool:
    leaves = list(_unwrap(tp))
    if any(_is_enum(x) for x in leaves) and not any(x is str or x is Any for x in leaves if not _is_enum(x)):
        return False
    return any((x is str and not _is_enum(x)) or x is Any for x in leaves)


def _models_in(tp):
    for x in _unwrap(tp):
        if isinstance(x, type) and issubclass(x, BaseModel):
            yield x


def _collect_classes(roots) -> list[type[BaseModel]]:
    seen: list[type[BaseModel]] = []
    todo = list(roots)
    while todo:
        cls = todo.pop()
        if cls in seen:
            continue
        seen.append(cls)
        for ann in typing.get_type_hints(cls).values():
            todo.extend(_models_in(ann))
    return seen


def _sentinel_for(tp):
    """Build a value for *tp* with the sentinel in every str-like slot."""
    origin = get_origin(tp)
    if origin is None:
        return SENT if (tp is str or tp is Any) else None
    args = [a for a in get_args(tp) if a is not type(None)]
    if origin in (list, set, frozenset):
        return origin([_sentinel_for(args[0])])
    if origin is tuple:
        return tuple(_sentinel_for(a) for a in args if a is not Ellipsis)
    if origin is dict:
        return {"k": _sentinel_for(args[1])}
    if origin is Union or str(origin).endswith("UnionType"):
        return next((v for v in (_sentinel_for(a) for a in args) if v is not None), None)
    return None


def _matched_fields():
    out = []
    for cls in _collect_classes(ROOTS):
        for name, ann in typing.get_type_hints(cls).items():
            if name in cls.model_fields and _str_like(ann):
                out.append((cls, name, ann))
    return out


def _instance_with_sentinels(cls):
    hints = typing.get_type_hints(cls)
    values = {}
    for name in cls.model_fields:
        ann = hints[name]
        values[name] = _sentinel_for(ann) if _str_like(ann) else None
    return cls.model_construct(**values)


_MATCHED = _matched_fields()


def test_exhaustiveness_prototype_is_not_vacuous():
    assert len(_MATCHED) >= 80  # measured 90 on the survey


def test_multi_line_fields_are_exactly_the_four_and_real():
    assert MULTI_LINE_FIELDS == {
        ("TriageResult", "explanation"),
        ("TriageResult", "local_notes"),
        ("Cluster", "explanation"),
        ("BarbContext", "explanation"),
    }
    real = {(c.__name__, n) for c, n, _ in _MATCHED}
    assert MULTI_LINE_FIELDS <= real


@pytest.mark.parametrize("cls,name,ann", _MATCHED, ids=[f"{c.__name__}.{n}" for c, n, _ in _MATCHED])
def test_every_str_like_field_is_classified(cls, name, ann):
    out = sanitize_for_render(_instance_with_sentinels(cls))
    strs = list(_all_strs(getattr(out, name)))
    assert strs, "sentinel did not reach the field"
    for s in strs:
        assert "\x1b" not in s and "\x07" not in s
        assert "Verdict: CLEAN" in s
        if (cls.__name__, name) in MULTI_LINE_FIELDS:
            assert "\n" in s
        else:
            assert "\n" not in s and "\t" not in s


# --------------------------------------------------------------------------
# round-2 pins
# --------------------------------------------------------------------------

_HIDDEN = [
    "[\x00link=https://evil.example]x[/link] [\u200bbold]y",
    "[\u202elink=https://evil.example]x[/link] [\x1bbold]y",
    "[\x1b[0mred]z",
]


@pytest.mark.parametrize("payload", _HIDDEN)
def test_strip_then_escape_ordering_leaves_no_live_markup(payload):
    from rich.markup import render

    assert render(rich_text(payload)).spans == []
    out = sanitize_for_render(_triage(tags=[payload]))
    assert render(out.tags[0]).spans == []


def test_multi_line_field_escaped_when_rich_and_plain_otherwise():
    assert sanitize_for_render(_triage(explanation="[bold]x\ny")).explanation == "\\[bold]x\ny"
    assert sanitize_for_render(_triage(explanation="[bold]x\ny"), rich=False).explanation == "[bold]x\ny"


def test_tuple_branch_walked():
    out = sanitize_for_render(("a\nb", [_triage(tags=["t\nu"])]))
    assert isinstance(out, tuple)
    assert out[0] == "a b"
    assert out[1][0].tags == ["t u"]


def test_indent_block_default_prefix():
    assert indent_block("a\nb") == "  a\n  b"


def test_str_like_sees_any_in_containers():
    assert _str_like(list[Any])
    assert _str_like(typing.Optional[Any])
