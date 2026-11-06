"""AST ratchet over ``vex/main.py`` print sinks.

Every interpolated value (and every non-constant positional argument) that reaches a Rich sink in
``main.py`` must be wrapped in ``rich_text(`` / ``plain_text(`` or be explicitly allowed with a reason.
New sinks that print raw attacker text fail here until they are wrapped or reviewed.

Blind spots (covered elsewhere): a value placed between ``[`` and ``]`` of one markup string is the
bracket scan's job (``test_render_brackets.py``); strings assembled outside the accepted constructors
beyond the single-assignment rule are not seen.
"""

from __future__ import annotations

import ast
from pathlib import Path

import vex.main as main_module

MAIN_PY = Path(main_module.__file__)

SINK_CONSOLES = {"console", "err_console", "rec"}
WRAPPERS = {"rich_text", "plain_text"}
# A Name argument is accepted when every assignment to it in the function is one of these calls (or a
# trusted f-string / conditional).
# Table / Panel cells and titles are checked at their own sinks (add_row, title=).
ASSIGN_OK = WRAPPERS | {"Text", "Table", "Panel"}
TITLE_KEYWORDS = {"title", "caption", "subtitle"}

# Non-vacuity floor: the number of sink expressions the walk must find in main.py.
MIN_SINK_EXPRESSIONS = 180

Key = tuple[str, str]  # (enclosing function, ast.unparse(expr))


def _add(table: dict[Key, str], reason: str, funcs: str, *exprs: str) -> None:
    for fn in funcs.split():
        for expr in exprs:
            table[(fn, expr)] = reason


# Reviewed, trusted values. Every entry names the reason it needs no wrapper.
ALLOWED: dict[Key, str] = {}
_INT = "integer, count or numeric summary"
_CFG = "value from the operator's own config file or a fixed default"
_STATIC = "fixed text or markup owned by vex"
_add(ALLOWED, _INT, "cmd_triage cmd_investigate", "failed_count", "skipped_count", "removed", "pre_filter_count")
_add(ALLOWED, _INT, "cmd_triage cmd_investigate", "max_quota", "len(iocs) + removed")
_add(ALLOWED, _INT, "cmd_triage cmd_investigate", "estimate_eta(len(iocs), config)")
_add(
    ALLOWED,
    _INT,
    "cmd_triage cmd_investigate",
    "format_batch_summary(len(results), failed_count, from_api, from_cache_count)",
)
_add(ALLOWED, "alert level already validated as a Verdict name", "cmd_triage cmd_investigate", "alert.upper()")
_add(ALLOWED, _INT, "_quota_emit", "tracker.remaining_today()", "tracker.status_line()")
_add(
    ALLOWED,
    "provider class name",
    "_run_explain _run_correlation_explain",
    "provider.name",
)
_add(ALLOWED, _INT, "cmd_note", "nid", "delete_id", "n['id']", "n['created_at'][:10]")
_add(
    ALLOWED,
    _INT,
    "cmd_watchlist_run",
    *(f"run_result.{f}" for f in ("total", "worsened", "unchanged", "improved", "cache_misses", "errors")),
)
_add(ALLOWED, "verdict value string", "cmd_watchlist_run", "old_v", "new_v")
_add(ALLOWED, _STATIC, "cmd_doctor", "_bool_mark(s.configured)", "_bool_mark(s.reachable)", "s.name")
_add(ALLOWED, _STATIC, "cmd_manual", "_MANUAL_TOPICS[topic.lower()]")
_add(ALLOWED, _STATIC, "cmd_watchlist", "ctx.get_help()")
_add(ALLOWED, "local config or cache path", "cmd_config", "path")
_add(ALLOWED, "local config or cache path", "cmd_cache_clear", "db")
_add(ALLOWED, "provider class name", "_mark_explanation_degraded", "provider_name")
_add(ALLOWED, "fixed list of valid provider names", "cmd_config", "', '.join(valid)")
_add(
    ALLOWED,
    "addon registry entry or fixed status text",
    "cmd_addons _show_config",
    "a.name",
    "a.group",
    "a.description",
    "status",
)
_add(ALLOWED, "fixed install hint", "cmd_addons", "install")
_add(
    ALLOWED,
    "built from the escaped label (rich_text) plus the provider class name",
    "_run_correlation_explain",
    "_title(title)",
    "label",
)
_add(ALLOWED, _CFG, "_run_writeback", "config.enrichment.writeback_min_verdict", "config.enrichment.writeback_tlp")
_add(
    ALLOWED,
    _CFG,
    "_show_config",
    "mask(config.abuseipdb_api_key)",
    "mask(config.ai_api_key)",
    "mask(config.api.key)",
    "mask(config.misp_api_key)",
    "mask(config.opencti_token)",
    "mask(config.shodan_api_key)",
    "mask(os.getenv('VT_API_KEY'))",
    "config.ai.base_url or '[dim]not set[/dim]'",
    "config.ai.model or '[dim]default[/dim]'",
    "config.misp_url or '[dim]not set[/dim]'",
    "config.opencti_url or '[dim]not set[/dim]'",
    "config.ai.provider",
    "config.api.tier",
    "config.output.default_format",
    "config.rate_limit.requests_per_day",
    "config.rate_limit.requests_per_minute",
    "config.update_check.check_interval_hours",
)
_add(
    ALLOWED,
    _CFG,
    "_show_config",
    *(
        f"str(config.{f})"
        for f in (
            "ai.cache_ttl_hours",
            "ai.local_only",
            "ai.max_tokens",
            "ai.temperature",
            "cache.enabled",
            "cache.ttl_hours",
            "enrichment.abuseipdb_max_age_days",
            "enrichment.misp_verify_tls",
            "enrichment.opencti_verify_tls",
            "enrichment.whois_enabled",
            "output.quiet",
            "plugins.load_local",
            "thresholds.malicious_min_detections",
            "thresholds.min_engines_for_clean",
            "thresholds.suspicious_min_detections",
            "update_check.enabled",
        )
    ),
)

# Converted by the main.py sink change; must stay empty.
PENDING_A2A: dict[Key, str] = {}

# Sites converted by the watchlist/doctor/remote-exception change.
PENDING: dict[Key, str] = {}
_add(PENDING, "a2b-pending", "cmd_watchlist_run", "d['ioc']", "exc", "name")
_add(PENDING, "a2b-pending", "cmd_doctor", "s.detail", "_json.dumps([s.model_dump() for s in statuses], indent=2)")


def _call_name(node: ast.Call) -> str | None:
    f = node.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return None


def _is_sink(node: ast.Call) -> bool:
    f = node.func
    if isinstance(f, ast.Attribute):
        if f.attr == "print" and isinstance(f.value, ast.Name) and f.value.id in SINK_CONSOLES:
            return True
        return f.attr == "add_row"
    return False


def _assignments(func: ast.AST) -> dict[str, list[ast.expr]]:
    out: dict[str, list[ast.expr]] = {}
    for n in ast.walk(func):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name):
                    out.setdefault(t.id, []).append(n.value)
        elif isinstance(n, (ast.AnnAssign, ast.AugAssign)) and isinstance(n.target, ast.Name):
            if n.value is not None:
                out.setdefault(n.target.id, []).append(n.value)
    return out


def _wrapped(expr: ast.expr, assigns: dict[str, list[ast.expr]], depth: int = 0) -> bool:
    """True when *expr* is a trusted form (wrapper call, constant, count, enum value, version, type name)."""
    if isinstance(expr, ast.Constant):
        return True
    if isinstance(expr, ast.Call):
        name = _call_name(expr)
        if name in WRAPPERS:
            return True
        if name == "len" and isinstance(expr.func, ast.Name):
            return True
        if name in {"indent_block", "_title"} and expr.args:
            return _wrapped(expr.args[0], assigns, depth + 1)
        return name in {"Text", "Table", "Panel"}
    if isinstance(expr, ast.Attribute):
        if expr.attr == "value":  # enum .value
            return True
        if expr.attr == "__name__" and isinstance(expr.value, ast.Call) and _call_name(expr.value) == "type":
            return True
        return False
    if isinstance(expr, ast.Name):
        if expr.id == "__version__":
            return True
        found = assigns.get(expr.id, [])
        if depth >= 3 or not found:
            return False
        # Every assignment must itself be a trusted form (a wrapper or constructor call, or an f-string
        # whose placeholders are all trusted).
        return all(
            (isinstance(v, ast.Call) and _call_name(v) in ASSIGN_OK)
            or (isinstance(v, (ast.JoinedStr, ast.IfExp)) and _wrapped(v, assigns, depth + 1))
            for v in found
        )
    if isinstance(expr, ast.JoinedStr):
        return all(_wrapped(v, assigns, depth + 1) for v in expr.values)
    if isinstance(expr, ast.IfExp):
        return _wrapped(expr.body, assigns, depth + 1) and _wrapped(expr.orelse, assigns, depth + 1)
    if isinstance(expr, ast.FormattedValue):
        if expr.format_spec is not None:  # numeric format spec (":,", ":.1f") only formats numbers
            return True
        return _wrapped(expr.value, assigns, depth + 1)
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Mult):
        return _wrapped(expr.left, assigns, depth + 1) and _wrapped(expr.right, assigns, depth + 1)
    return False


def _fvalues(expr: ast.AST):
    """Every FormattedValue in the subtree (f-string placeholders, nested calls and keywords included)."""
    for n in ast.walk(expr):
        if isinstance(n, ast.FormattedValue):
            yield n


def _sink_exprs(call: ast.Call):
    """Expressions at a sink that need a trusted form: placeholders and non-constant positional args."""
    seen: set[int] = set()
    parts: list[ast.expr] = list(call.args) + [k.value for k in call.keywords]
    for p in parts:
        # Panel/Table built inline: its body argument and title/caption/subtitle are sinks too.
        for n in ast.walk(p):
            if isinstance(n, ast.Call) and _call_name(n) in {"Panel", "Table"}:
                for a in n.args:
                    yield from _positional(a, seen)
                for k in n.keywords:
                    if k.arg in TITLE_KEYWORDS:
                        yield from _positional(k.value, seen)
        yield from _positional(p, seen)


def _positional(p: ast.expr, seen: set[int]):
    if isinstance(p, ast.Call) and _call_name(p) in {"Panel", "Table"}:
        return
    if isinstance(p, ast.JoinedStr):
        for fv in _fvalues(p):
            if id(fv) not in seen:
                seen.add(id(fv))
                yield fv.value if fv.format_spec is None else None
        return
    if not isinstance(p, ast.Constant) and id(p) not in seen:
        seen.add(id(p))
        yield p


def scan(source: str) -> tuple[int, dict[Key, int]]:
    """Return (sink expression count, {(function, expr): occurrences} for untrusted ones)."""
    tree = ast.parse(source)
    total = 0
    bad: dict[Key, int] = {}
    funcs = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    # Innermost enclosing function for each call.
    owner: dict[int, ast.AST] = {}
    for fn in sorted(funcs, key=lambda f: (f.lineno, -(f.end_lineno or 0))):
        for n in ast.walk(fn):
            owner[id(n)] = fn
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not _is_sink(node):
            continue
        fn = owner.get(id(node))
        name = fn.name if fn is not None else "<module>"
        assigns = _assignments(fn) if fn is not None else {}
        for expr in _sink_exprs(node):
            if expr is None:
                continue
            total += 1
            if not _wrapped(expr, assigns):
                key = (name, ast.unparse(expr))
                bad[key] = bad.get(key, 0) + 1
    return total, bad


def test_ratchet_finds_the_sinks():
    total, _ = scan(MAIN_PY.read_text())
    assert total >= MIN_SINK_EXPRESSIONS, total


def test_every_untrusted_sink_expression_is_wrapped_or_listed():
    _, bad = scan(MAIN_PY.read_text())
    listed = set(ALLOWED) | set(PENDING_A2A) | set(PENDING)
    unlisted = sorted(set(bad) - listed)
    assert not unlisted, "unwrapped sink expressions (wrap in rich_text/plain_text or review):\n" + "\n".join(
        f"  {fn}: {expr}" for fn, expr in unlisted
    )


def test_lists_have_no_stale_entries():
    _, bad = scan(MAIN_PY.read_text())
    stale = sorted((set(ALLOWED) | set(PENDING_A2A) | set(PENDING)) - set(bad))
    assert not stale, f"entries that no longer match a sink expression: {stale}"


def test_no_a2a_pending_entries_remain():
    assert not PENDING_A2A


def test_a_planted_unwrapped_sink_is_caught():
    src = "def f(x):\n    console.print(f'IOC {x}')\n"
    _, bad = scan(src)
    assert ("f", "x") in bad
    ok = "def f(x):\n    console.print(f'IOC {rich_text(x)}')\n"
    assert scan(ok)[1] == {}
