"""IOC defanging and refanging utilities.

Defanging replaces dangerous characters so IOCs can be safely shared
in reports, emails, and chat without accidental hyperlinks.

Supported transformations:
  http  ↔ hxxp         .   ↔ [.]
  https ↔ hxxps        :   ↔ [:]
  ://   ↔ [://]        @   ↔ [@]
  ftp   ↔ fxp          /   ↔ [/]
  (.)  → .    {.}  → .
  (dot) → .   {dot} → .   [dot] → .
  (at)  → @   {at}  → @   [at]  → @   (domain-lookahead guarded)
  fullwidth ．→.  ＠→@  ：→:  ／→/
  zero-width / BOM stripped before matching
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Zero-width / BOM characters stripped at the start of refang().
# ---------------------------------------------------------------------------

_ZERO_WIDTH_TABLE = {
    0x200B: None,  # ZERO WIDTH SPACE
    0x200C: None,  # ZERO WIDTH NON-JOINER
    0x200D: None,  # ZERO WIDTH JOINER
    0xFEFF: None,  # ZERO WIDTH NO-BREAK SPACE / BOM
    0x2060: None,  # WORD JOINER
}

# ---------------------------------------------------------------------------
# [at] / (at) / {at} — only refang when a domain-shaped token follows.
# Without the lookahead ``state[at]rest`` would be corrupted to
# ``state@rest``.  The lookahead requires word chars plus a literal ``.``
# or ``[dot]`` within 60 characters — the same guard sift uses.
# ---------------------------------------------------------------------------

_AT_DOMAIN_LOOKAHEAD = r"(?=[A-Za-z0-9._\-]{1,60}(?:\[dot\]|\.))"

# ---------------------------------------------------------------------------
# Refang patterns  (defanged → live)
# Order matters:
#   1. [://] must come BEFORE scheme keywords so ``hxxps[://]evil.com``
#      first becomes ``hxxps://evil.com``, then the scheme rule fires.
#   2. Bracket/paren/brace separators before word-form variants.
#   3. Fullwidth lookalikes last (rare, but unambiguous).
# ---------------------------------------------------------------------------

_REFANG_RULES: list[tuple[re.Pattern[str], str]] = [
    # Protocol — word-boundary match prevents ``hxxps`` inside longer tokens.
    (re.compile(r"\bhxxps\b", re.I), "https"),
    (re.compile(r"\bhxxp\b", re.I), "http"),
    (re.compile(r"\bfxp\b", re.I), "ftp"),
    # Bracketed scheme separator — keep BEFORE dot/colon rules.
    (re.compile(r"\[://\]"), "://"),
    # Dot separators — bracket, paren, brace forms.
    (re.compile(r"\[\.\]"), "."),
    (re.compile(r"\(\.\)"), "."),
    (re.compile(r"\{\.\}"), "."),
    # Colon separator.
    (re.compile(r"\[:\]"), ":"),
    # Slash separator.
    (re.compile(r"\[/\]"), "/"),
    # @ symbol form — always safe (no prose collision risk for ``[@]``).
    (re.compile(r"\[@\]"), "@"),
    # Word-form dot: [dot] / (dot) / {dot}
    (re.compile(r"\[dot\]", re.I), "."),
    (re.compile(r"\(dot\)", re.I), "."),
    (re.compile(r"\{dot\}", re.I), "."),
    # Word-form @ — guarded by domain lookahead to avoid corrupting prose
    # like ``state[at]rest`` or ``array{at}index``.
    (re.compile(r"\[at\]" + _AT_DOMAIN_LOOKAHEAD, re.I), "@"),
    (re.compile(r"\(at\)" + _AT_DOMAIN_LOOKAHEAD, re.I), "@"),
    (re.compile(r"\{at\}" + _AT_DOMAIN_LOOKAHEAD, re.I), "@"),
    # Fullwidth Unicode lookalikes.
    (re.compile("．"), "."),   # U+FF0E FULLWIDTH FULL STOP
    (re.compile("＠"), "@"),   # U+FF20 FULLWIDTH COMMERCIAL AT
    (re.compile("："), ":"),   # U+FF1A FULLWIDTH COLON
    (re.compile("／"), "/"),   # U+FF0F FULLWIDTH SOLIDUS
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

    Strips zero-width / BOM characters first, then applies all refang
    rules in order.  Idempotent: a live URL passed in is returned unchanged.

    IPv6 bracket notation (``[::1]``) is preserved because the ``[://]``
    rule matches only the exact three-character sequence ``://`` inside
    brackets, not the ``::`` used in compressed IPv6 addresses.

    >>> refang("hxxps[://]evil[.]com")
    'https://evil.com'
    """
    if not ioc:
        return ioc
    # Remove invisible characters that might break pattern matching.
    result = ioc.translate(_ZERO_WIDTH_TABLE)
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
    """Heuristic check whether an IOC string appears defanged.

    Detects all forms that ``refang()`` can reverse, including the paren/brace
    variants and fullwidth lookalikes added for portfolio parity.
    """
    lowered = ioc.lower()
    indicators = (
        "hxxp", "fxp",
        "[.]", "[://]", "[:]", "[@]", "[/]",
        "[dot]", "[at]",
        "(.)", "{.}",
        "(dot)", "{dot}",
        "(at)", "{at}",
        "．", "＠",
    )
    return any(ind in lowered for ind in indicators)
