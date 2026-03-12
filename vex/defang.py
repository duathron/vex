"""IOC defanging and refanging utilities.

Defanging replaces dangerous characters so IOCs can be safely shared
in reports, emails, and chat without accidental hyperlinks.

Supported transformations:
  http  ↔ hxxp       .   ↔ [.]
  https ↔ hxxps      :   ↔ [:]
  ://   ↔ [://]      @   ↔ [@]
  ftp   ↔ fxp
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Refang patterns  (defanged → live)
# ---------------------------------------------------------------------------

_REFANG_RULES: list[tuple[re.Pattern[str], str]] = [
    # Protocol
    (re.compile(r"\bhxxps\b", re.I), "https"),
    (re.compile(r"\bhxxp\b", re.I), "http"),
    (re.compile(r"\bfxp\b", re.I), "ftp"),
    # Bracket notations
    (re.compile(r"\[://\]"), "://"),
    (re.compile(r"\[\.\]"), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[@\]"), "@"),
    (re.compile(r"\[dot\]", re.I), "."),
    (re.compile(r"\[at\]", re.I), "@"),
]


# ---------------------------------------------------------------------------
# Defang patterns  (live → safe)
# ---------------------------------------------------------------------------

_DEFANG_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bhttps\b", re.I), "hxxps"),
    (re.compile(r"\bhttp\b", re.I), "hxxp"),
    (re.compile(r"\bftp\b", re.I), "fxp"),
    (re.compile(r"://"), "[://]"),
    (re.compile(r"\."), "[.]"),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def refang(ioc: str) -> str:
    """Convert a defanged IOC back to its live form.

    >>> refang("hxxps[://]evil[.]com")
    'https://evil.com'
    """
    result = ioc
    for pattern, replacement in _REFANG_RULES:
        result = pattern.sub(replacement, result)
    return result


def defang(ioc: str) -> str:
    """Defang a live IOC so it cannot be accidentally clicked.

    >>> defang("https://evil.com")
    'hxxps[://]evil[.]com'
    """
    result = ioc
    for pattern, replacement in _DEFANG_RULES:
        result = pattern.sub(replacement, result)
    return result


def is_defanged(ioc: str) -> bool:
    """Heuristic check whether an IOC string appears defanged."""
    lowered = ioc.lower()
    indicators = ("hxxp", "fxp", "[.]", "[://]", "[:]", "[@]", "[dot]", "[at]")
    return any(ind in lowered for ind in indicators)
