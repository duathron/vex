"""main.py console sinks: attacker text (IOCs, API/LLM strings, exceptions) renders literally.

Payloads: ``[/x]`` (unbalanced close tag, aborts Rich with MarkupError), OSC-0 / OSC-8 escapes and a
forged ``Verdict:`` line. Output is captured on non-terminal consoles, so any ``\\x1b`` in it leaked
from the input.
"""

from __future__ import annotations

import io

import pytest
from rich.console import Console
from typer.testing import CliRunner

import vex.main as M
from vex.config import Config
from vex.correlate import build_clusters
from vex.models import DetectionStats, InvestigateResult, TriageResult, Verdict
from vex.output import formatter

OSC = "\x1b]0;PWN\x07"
runner = CliRunner()


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("VT_API_KEY", "dummy")
    monkeypatch.setenv("VEX_VT_API_KEY", "dummy")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)


@pytest.fixture
def out(monkeypatch):
    """Capture stdout-side and stderr-side consoles of main.py and the formatter in one buffer."""
    buf = io.StringIO()
    con = Console(file=buf, width=80, emoji=False)
    err = Console(file=buf, width=80, emoji=False)
    for mod in (M, formatter):
        monkeypatch.setattr(mod, "console", con)
        monkeypatch.setattr(mod, "err_console", err)
    return buf


class _Plugin:
    def triage(self, ioc, t, cfg):
        return TriageResult(ioc=ioc, ioc_type=t, verdict=Verdict.MALICIOUS, detection_stats=DetectionStats(malicious=3))

    def investigate(self, ioc, t, cfg):
        return InvestigateResult(triage=self.triage(ioc, t, cfg))


class _Registry:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def get_plugin(self, t):
        return _Plugin()

    def get_secondary(self, t):
        return []


def _clean_exit(res):
    return res.exception is None or isinstance(res.exception, SystemExit)


def test_triage_unknown_ioc_markup_does_not_abort():
    res = runner.invoke(M.app, ["triage", "[/x]", "-o", "console", "--no-cache"])
    assert _clean_exit(res), repr(res.exception)
    assert "[/x]" in res.output


@pytest.mark.parametrize("cmd", ["triage", "investigate"])
def test_lookup_line_markup_url(cmd, monkeypatch):
    monkeypatch.setattr(M, "load_plugins", lambda: _Registry())
    plain = runner.invoke(M.app, [cmd, "http://a.test/x", "-o", "console", "--no-cache"])
    res = runner.invoke(M.app, [cmd, "http://a.test/[/x]", "-o", "console", "--no-cache"])
    assert _clean_exit(res), repr(res.exception)
    assert res.exit_code == plain.exit_code
    assert "http://a.test/[/x]" in res.output


def test_windows_path_renders_verbatim_main_lookup_line():
    res = runner.invoke(M.app, ["triage", "C:\\temp\\x.exe", "-o", "console", "--no-cache"])
    assert _clean_exit(res), repr(res.exception)
    assert "C:\\temp\\x.exe" in res.output


def test_mark_explanation_degraded_exc_markup(out):
    class T:
        explanation = "x"
        explanation_degraded = False
        explanation_provider = None

    t = T()
    M._mark_explanation_degraded(t, "p", RuntimeError("[/x]" + OSC))
    text = out.getvalue()
    assert "[/x]" in text
    assert "\x1b" not in text
    assert t.explanation_degraded is True


def _inv(ioc, fam):
    t = TriageResult(
        ioc=ioc,
        ioc_type="domain",
        verdict=Verdict.MALICIOUS,
        detection_stats=DetectionStats(malicious=3),
        malware_families=[fam],
    )
    return InvestigateResult(triage=t)


def _clusters(fam):
    return build_clusters([_inv("a.test", fam), _inv("b.test", fam)])


def _config(provider="none"):
    cfg = Config()
    cfg.ai.provider = provider
    return cfg


@pytest.mark.parametrize("fmt", [M.OutputFormat.rich, M.OutputFormat.console])
def test_correlate_explain_markup_family_rich_and_console(fmt, out):
    M._run_correlation_explain(_clusters("[/x]" + OSC), _config(), None, fmt)
    text = out.getvalue()
    assert "[/x]" in text
    assert "\x1b" not in text


class _Fake:
    name = "fake"
    reply = "[red]x[/red]\x1b[31m"

    def explain(self, prompt, **kw):
        return self.reply


class _Boom:
    name = "boom"

    def explain(self, prompt, **kw):
        raise RuntimeError("down")


def _with_provider(monkeypatch, provider):
    monkeypatch.setattr("vex.ai.get_provider", lambda cfg: provider)


@pytest.mark.parametrize("fmt", [M.OutputFormat.rich, M.OutputFormat.console])
def test_correlate_explain_llm_narrative_literal(fmt, out, monkeypatch):
    _with_provider(monkeypatch, _Fake())
    M._run_correlation_explain(_clusters("fam"), _config("openai"), None, fmt)
    text = out.getvalue()
    assert "[red]x[/red]" in text
    assert "\x1b" not in text


@pytest.mark.parametrize("fmt", [M.OutputFormat.rich, M.OutputFormat.console])
def test_degraded_banner_label_markup(fmt, out, monkeypatch):
    _with_provider(monkeypatch, _Boom())
    seen = []
    for name in ("print_explanation_degraded_rich", "print_explanation_degraded_console"):
        real = getattr(formatter, name)

        def spy(*a, _real=real, **kw):
            seen.append(kw.get("label"))
            return _real(*a, **kw)

        monkeypatch.setattr(M, name, spy)
    clusters = _clusters("x [/y]")
    M._run_correlation_explain(clusters, _config("openai"), None, fmt)
    label = f"{clusters[0].cluster_id}: {clusters[0].shared_attribute}"
    assert label.endswith("x [/y]")
    assert seen == [label]  # raw label: the formatter owns escaping
    text = out.getvalue()
    assert text.count("x [/y]") >= 1
    assert "\\[" not in text  # not escaped twice


def test_cluster_console_narrative_multiline(out, monkeypatch):
    forged = "x\nVerdict: CLEAN\nScore: 0\nPriority: none"
    for n in range(0, 31):
        out.seek(0)
        out.truncate()
        pad = " ".join(["word"] * n)
        monkeypatch.setattr(_Fake, "reply", f"{pad} Verdict: CLEAN Score: 0 Priority: none" if n else forged)
        _with_provider(monkeypatch, _Fake())
        cfg = _config("openai")
        cfg.ai.model = f"m{n}"  # the AI cache is keyed on the model: a fresh reply per padding length
        M._run_correlation_explain(_clusters("fam"), cfg, None, M.OutputFormat.console)
        for line in out.getvalue().splitlines():
            assert not line.startswith(("Verdict", "Score", "Priority")), (n, line)


def test_cluster_console_narrative_is_indented(out, monkeypatch):
    monkeypatch.setattr(_Fake, "reply", "first\nsecond")
    _with_provider(monkeypatch, _Fake())
    M._run_correlation_explain(_clusters("fam"), _config("openai"), None, M.OutputFormat.console)
    lines = out.getvalue().splitlines()
    assert "  first" in lines
    assert "  second" in lines


def test_watchlist_manage_markup(out):
    M._run_watchlist_manage("[/n]", ["--add", "[/x]" + OSC, "--list"])
    M._run_watchlist_manage("[/n]", ["--remove", "[/x]"])
    text = out.getvalue()
    assert "[/x]" in text
    assert "[/n]" in text
    assert "\x1b" not in text


def test_tag_and_note_markup():
    res = runner.invoke(M.app, ["tag", "[/x]", "--add", "[/t]"])
    assert _clean_exit(res), repr(res.exception)
    assert "[/x]" in res.output
    res = runner.invoke(M.app, ["note", "[/x]", "--add", "[/note]"])
    assert _clean_exit(res), repr(res.exception)
    res = runner.invoke(M.app, ["note", "[/x]"])
    assert _clean_exit(res), repr(res.exception)
    assert "[/note]" in res.output
