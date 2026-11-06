"""Safe-render helpers for attacker-influenced text (API fields, IOCs, LLM output).

Rules (see the render-safety tests):

* ``rich_text`` for every Rich sink, ``plain_text`` for builtin ``print`` / non-Rich
  sinks only. Kit ``safe_render(escape_markup=True)`` is never used: it doubles
  backslashes (``C:\\temp`` -> ``C:\\\\temp``).
* ``safe_render`` is not idempotent: sanitise exactly once, at the outermost entry.
* ``sanitize_for_render`` walks a result model once and returns a copy; the input
  (used for JSON / STIX / cache) is never mutated.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel
from shipwright_kit.security.render import safe_render

# (model class name, field name). Every other str-like field is SINGLE_LINE.
# Multi-line is not a licence: sinks still indent every line of these.
MULTI_LINE_FIELDS: frozenset[tuple[str, str]] = frozenset(
    {
        ("TriageResult", "explanation"),
        ("TriageResult", "local_notes"),
        ("Cluster", "explanation"),
        ("BarbContext", "explanation"),
    }
)

_OPEN_BRACKET = re.compile(r"(\\*)\[")
_LINE_BREAKS = re.compile(r"[\r\n\t]")


def plain_text(x: Any) -> str:
    """Strip control/OSC/bidi characters; for builtin print and non-Rich sinks."""
    return safe_render(str(x), escape_markup=False)


def rich_text(x: Any) -> str:
    """``plain_text`` plus Rich markup escaping; for every Rich sink.

    Escapes EVERY ``[`` (``rich.markup.escape`` only escapes completed ``[tag]`` sequences, so an
    unterminated ``[link=...`` survives and a neighbouring list element or field supplies the ``]``).
    A backslash run before ``[`` is doubled first so the escape stays one level deep.
    """
    out = _OPEN_BRACKET.sub(lambda m: m.group(1) * 2 + "\\[", plain_text(x))
    if out.endswith("\\") and not out.endswith("\\\\"):  # a trailing backslash must not escape the next char
        out += "\\"
    return out


def single_line_text(x: Any, *, plain: bool = False) -> str:
    """Flatten CR/LF/TAB to a space, then apply the per-sink helper."""
    flat = _LINE_BREAKS.sub(" ", str(x))
    return plain_text(flat) if plain else rich_text(flat)


def indent_block(text: str, prefix: str = "  ") -> str:
    """Prefix every line so no line of multi-line text starts at column 0."""
    return "".join(prefix + line if line.strip("\r\n") else line for line in text.splitlines(keepends=True))


def _walk(value: Any, single_line: bool, rich: bool) -> Any:
    if type(value) is str:  # exact: str-Enums (Verdict) stay untouched
        if single_line:
            return single_line_text(value, plain=not rich)
        return rich_text(value) if rich else plain_text(value)
    if isinstance(value, BaseModel):
        cls = type(value).__name__
        update = {
            name: _walk(getattr(value, name), (cls, name) not in MULTI_LINE_FIELDS, rich)
            for name in type(value).model_fields
            if name in value.__dict__
        }
        return value.model_copy(update=update)
    if isinstance(value, list):
        return [_walk(v, single_line, rich) for v in value]
    if isinstance(value, tuple):
        return tuple(_walk(v, single_line, rich) for v in value)
    if isinstance(value, dict):
        return {k: _walk(v, single_line, rich) for k, v in value.items()}
    return value


def sanitize_for_render(obj: Any, *, rich: bool = True) -> Any:
    """Return a sanitised copy of *obj* (``rich=False`` for builtin-print sinks)."""
    return _walk(obj, True, rich)
