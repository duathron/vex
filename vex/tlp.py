"""Shared TLP parsing utilities.

Provides a single, canonical place for TLP level normalization and
most-restrictive-wins selection used by all enricher plugins.

Supported canonical levels (output): ``"red"`` | ``"amber"`` | ``"green"`` | ``"clear"``.
``"white"`` (TLP 1.0) is treated as an alias for ``"clear"`` (TLP 2.0).
``"amber+strict"`` collapses to ``"amber"`` for precedence purposes.
"""

from __future__ import annotations

import re
from typing import Iterable, Optional

# Regex accepts the prefix ``tlp:`` or ``tlp`` (colon optional), optional
# surrounding whitespace, and the known level names.
_TLP_RE = re.compile(r"(?i)^tlp:?\s*(red|amber\+strict|amber|green|clear|white)\s*$")

# Precedence order — lower index means more restrictive.
# amber+strict normalises to amber for precedence; the caller is responsible
# for the higher-level amber+strict STIX marking id if needed.
_TLP_PRECEDENCE = ["red", "amber", "green", "clear"]


def _tlp_rank(level: Optional[str]) -> int:
    """Return numeric rank for a canonical TLP level string.

    ``red`` is most restrictive (rank 0); ``clear`` is least (rank 3).
    ``None`` or unknown values return 99 (effectively "no TLP").

    Used by write-back writers to enforce the ceiling check:
    ``rank(source_tlp) < rank(ceiling)`` means source is stricter → skip.
    """
    if level is None:
        return 99
    try:
        return _TLP_PRECEDENCE.index(level)
    except ValueError:
        return 99


def normalize_tlp(raw: str) -> Optional[str]:
    """Return the canonical lowercase TLP level for *raw*, or ``None``.

    Accepted forms (case-insensitive, optional whitespace after colon):
    ``"tlp:red"``, ``"TLP:AMBER"``, ``"TLP:AMBER+STRICT"`` → ``"amber"``,
    ``"TLP:WHITE"`` → ``"clear"``, ``"TLP:CLEAR"``, ``"tlp:green"``, etc.

    Non-TLP strings return ``None``.
    """
    if not raw:
        return None
    m = _TLP_RE.match(raw.strip())
    if not m:
        return None
    level = m.group(1).lower()
    # Normalise aliases
    if level == "white":
        return "clear"
    if level == "amber+strict":
        return "amber"
    return level


def most_restrictive_tlp(values: Iterable[str]) -> Optional[str]:
    """Return the most restrictive TLP level found in *values*, or ``None``.

    Each element is passed through :func:`normalize_tlp`; elements that do
    not parse as TLP are silently skipped.  If no TLP level is found, returns
    ``None``.

    Restrictiveness order: ``red`` > ``amber`` > ``green`` > ``clear``.
    """
    best_rank: Optional[int] = None
    best_level: Optional[str] = None
    for v in values:
        level = normalize_tlp(v)
        if level is None:
            continue
        try:
            rank = _TLP_PRECEDENCE.index(level)
        except ValueError:
            continue
        if best_rank is None or rank < best_rank:
            best_rank = rank
            best_level = level
    return best_level
