from types import SimpleNamespace

from rich.console import Console

from vex.output import formatter


def _rec(monkeypatch):
    con = Console(record=True, force_terminal=True, width=200)
    monkeypatch.setattr(formatter, "console", con)  # module-level console (formatter.py:38)
    return con


def test_ai_explanation_markup_escaped(monkeypatch):
    con = _rec(monkeypatch)
    formatter.print_explanation_rich("[red]spoof[/] \x1b[31mx\x1b[0m", "anthropic")
    out = con.export_text()
    assert "[red]" in out  # LLM markup literal
    assert "\x1b[31m" not in out  # ANSI stripped


def test_ai_explanation_console_escaped(monkeypatch):
    con = _rec(monkeypatch)
    formatter.print_explanation_console("[red]spoof[/] \x1b[31mx\x1b[0m", "anthropic")
    out = con.export_text()
    assert "[red]" in out
    assert "\x1b[31m" not in out


def test_template_explanation_is_NOT_escaped(monkeypatch):
    # Field-scope positive control: template text is trusted; markup stays live.
    con = _rec(monkeypatch)
    formatter.print_explanation_rich("[bold]OK[/bold]", "template")
    out = con.export_text()
    assert "[bold]" not in out  # interpreted, not escaped
    assert "OK" in out


def test_barb_context_explanation_escaped_but_severity_preserved(monkeypatch):
    con = _rec(monkeypatch)
    ctx = SimpleNamespace(
        verdict="phishing",
        risk_score=15.0,
        defanged_url="hxxp://evil[.]example",
        top_signals=[SimpleNamespace(severity="CRITICAL", analyzer="vt", label="malicious")],
        explanation="[red]spoof[/] \x1b[31mx\x1b[0m",
    )
    formatter.print_barb_context_rich(ctx)
    out = con.export_text()
    assert "[red]spoof" in out  # explanation escaped to literal
    assert "\x1b[31m" not in out  # ANSI stripped
    # Trusted severity span at :549 stays LIVE. If the grid were wrongly escaped,
    # literal "[red]CRITICAL[/red]" would appear (distinct from "[red]spoof" — no
    # collision). Do NOT assert `"[CRITICAL]" not in out` (vacuous: bracket token
    # is the style name, so it never appears either way).
    assert "[red]CRITICAL[/red]" not in out
    assert "CRITICAL" in out


def test_barb_context_console_escapes_explanation(monkeypatch):
    # 4th sink: print_barb_context_console's Note line (formatter.py:581). Without
    # this the sink ships wrong-reason-green (no test drives it).
    con = _rec(monkeypatch)
    ctx = SimpleNamespace(
        verdict="phishing",
        risk_score=15.0,
        defanged_url="hxxp://evil[.]example",
        top_signals=[SimpleNamespace(severity="CRITICAL", analyzer="vt", label="malicious")],
        explanation="[red]spoof[/] \x1b[31mx\x1b[0m",
    )
    formatter.print_barb_context_console(ctx)
    out = con.export_text()
    assert "[red]spoof" in out  # explanation escaped to literal
    assert "\x1b[31m" not in out  # ANSI stripped
