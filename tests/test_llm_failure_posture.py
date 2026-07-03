"""CLI-level coverage for the F2 cut-1 unified LLM-provider-failure posture.

Reference: ``2026-07-03-f2-llm-failure-posture.md`` (MeetUp decision, signed
off). sift shipped the reference implementation (sift 1.3.3); barb copied
the spec (barb 1.7.3, ``tests/test_llm_failure_posture.py`` — the closest
structural analog to vex, since barb ALSO has no ``--provider`` CLI flag).
This is vex's copy.

vex's structure: `--explain` is opt-in on `triage`/`investigate`; the
provider comes from `config.ai.provider` (config file / env — no CLI flag).
vex's pre-F2 posture was already the best of the three siblings (loud yellow
stderr + provider_name="template" fallback) but had NO exit code and NO
machine marker — this file proves both now exist.

The new posture, proven end-to-end via the CLI:
  (a) no template_explain()/template_correlation() output is substituted for
      a failed REQUESTED LLM;
  (b) explanation is null and explanation_degraded/explanation_provider are
      set (additive machine markers, TriageResult / Cluster);
  (c) the run exits with the reserved degraded exit code (4), distinct from
      the verdict codes (0/1/2);
  (d) a loud "EXPLANATION UNAVAILABLE" notice goes to STDERR only — a
      ``-o json`` run's STDOUT stays ``json.loads``-parseable;
  (e) the triage/investigate VERDICT (vex's primary output) still completes;
  (f) a DELIBERATE ``ai.provider: none`` (template) run is never degraded;
  (g) no ``--on-llm-failure`` flag and no TTY prompt exist (deferred slice-2).

Isolation: vex has no ``--provider`` CLI flag, so these tests isolate
``Path.home()`` to a tmp dir (covers ``~/.vex/config.yaml``, cache.db, and
ai_cache.db in one patch) and set ``config.ai.provider`` via a hermetic
config file, then patch the VirusTotal plugin's ``.triage()``/``.investigate()``
to return a canned result (no network) and the provider's transport to fail
(no live LLM call). No live network, no real API keys.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from vex.main import app
from vex.models import DetectionStats, InvestigateResult, TriageResult, Verdict

runner = CliRunner()

_IP = "1.2.3.4"


def _canned_triage_result() -> TriageResult:
    return TriageResult(
        ioc=_IP,
        ioc_type="ip",
        verdict=Verdict.SUSPICIOUS,
        detection_stats=DetectionStats(malicious=3, undetected=60),
    )


def _canned_investigate_result() -> InvestigateResult:
    return InvestigateResult(triage=_canned_triage_result())


@pytest.fixture
def _hermetic_home(tmp_path, monkeypatch):
    """Isolate ~/.vex/{config.yaml,cache.db,ai_cache.db} so a real developer
    machine's state never leaks into these tests, and set a fake VT key
    (config.api_key raises ValueError before the CLI even reaches --explain
    if unset).

    IMPORTANT: vex.config._USER_CONFIG_PATH is a MODULE-LEVEL constant
    (`vex/config.py:13`, `Path.home() / ".vex" / "config.yaml"`) computed
    ONCE at import time — patching `Path.home` alone does NOT redirect it
    (vex.config is already imported transitively via `from vex.main import
    app` at this test module's top level, so the real Path.home() already
    ran). `cache_db_path` (a @property) and AICache.__init__ both call
    Path.home() at RUNTIME, so the Path.home patch still isolates those two.
    _USER_CONFIG_PATH needs its own explicit module-attribute patch — mirrors
    barb's own hermetic-config fixture (`monkeypatch.setattr(barb.config,
    "_APP_DIR", app_dir)` in tests/test_llm_failure_posture.py)."""
    import vex.config

    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr(vex.config, "_USER_CONFIG_PATH", tmp_path / ".vex" / "config.yaml")
    monkeypatch.delenv("VEX_AI_API_KEY", raising=False)
    monkeypatch.setenv("VT_API_KEY", "test-fake-vt-key-00000000")
    return tmp_path


def _write_config(home: Path, ai_provider: str, **ai_extra) -> None:
    vex_dir = home / ".vex"
    vex_dir.mkdir(parents=True, exist_ok=True)
    lines = [f"  provider: {ai_provider}"]
    for k, v in ai_extra.items():
        lines.append(f"  {k}: {v}")
    (vex_dir / "config.yaml").write_text("ai:\n" + "\n".join(lines) + "\n")


def _patch_vt_triage(result: TriageResult):
    return patch("vex.plugins.virustotal.VirusTotalPlugin.triage", return_value=result)


def _patch_vt_investigate(result: InvestigateResult):
    return patch("vex.plugins.virustotal.VirusTotalPlugin.investigate", return_value=result)


# ---------------------------------------------------------------------------
# (a)+(b)+(c)+(d)+(e) — ollama failure: no template, markers set, exit 4,
# stderr-only notice, JSON stays parseable, verdict still present.
# ---------------------------------------------------------------------------


class TestOllamaFailureJSON:
    def test_json_run_exit_4_markers_set_verdict_present(self, _hermetic_home, monkeypatch):
        _write_config(_hermetic_home, "ollama", base_url="http://localhost:11434")

        def fake_urlopen(req, timeout=None, **kwargs):
            raise __import__("urllib.error", fromlist=["URLError"]).URLError("connection refused")

        monkeypatch.setattr("shipwright_kit.llm.urllib.request.urlopen", fake_urlopen)

        with _patch_vt_triage(_canned_triage_result()):
            result = runner.invoke(app, ["triage", _IP, "-o", "json", "-q", "--no-cache", "--explain"])

        assert result.exit_code == 4
        data = json.loads(result.stdout)
        assert data["explanation"] is None
        assert data["explanation_degraded"] is True
        assert data["explanation_provider"] == "ollama"
        # (e) the PRIMARY output — verdict/detections — still completes
        assert data["verdict"] == "SUSPICIOUS"
        assert data["detection_stats"]["malicious"] == 3

    def test_loud_notice_on_stderr_not_stdout_for_json(self, _hermetic_home, monkeypatch):
        _write_config(_hermetic_home, "ollama")

        def fake_urlopen(req, timeout=None, **kwargs):
            raise __import__("urllib.error", fromlist=["URLError"]).URLError("connection refused")

        monkeypatch.setattr("shipwright_kit.llm.urllib.request.urlopen", fake_urlopen)

        with _patch_vt_triage(_canned_triage_result()):
            result = runner.invoke(app, ["triage", _IP, "-o", "json", "-q", "--no-cache", "--explain"])

        assert "EXPLANATION UNAVAILABLE" not in result.stdout
        assert "EXPLANATION UNAVAILABLE" in result.stderr
        assert "ollama" in result.stderr
        # stdout must still be exactly one parseable JSON document
        json.loads(result.stdout)


# ---------------------------------------------------------------------------
# (d) — the DEFAULT renderers (rich/console) scream the banner on stdout.
# ---------------------------------------------------------------------------


class TestLoudDefaultRenderers:
    def test_console_shows_loud_unavailable_banner(self, _hermetic_home, monkeypatch):
        _write_config(_hermetic_home, "ollama")

        def fake_urlopen(req, timeout=None, **kwargs):
            raise __import__("urllib.error", fromlist=["URLError"]).URLError("connection refused")

        monkeypatch.setattr("shipwright_kit.llm.urllib.request.urlopen", fake_urlopen)

        with _patch_vt_triage(_canned_triage_result()):
            result = runner.invoke(app, ["triage", _IP, "-o", "console", "-q", "--no-cache", "--explain"])

        assert "EXPLANATION UNAVAILABLE" in result.stdout
        assert result.exit_code == 4


# ---------------------------------------------------------------------------
# (g) [renumbered from barb's (g)] — anthropic/openai failure exits the
# controlled 4, degrades with a marker (no uncaught crash — vex never had
# barb's exit-1-collision bug, but the marker/exit-4 behavior is new).
# ---------------------------------------------------------------------------


class TestCloudProviderFailureDoesNotCrash:
    def test_anthropic_api_failure_exits_4(self, _hermetic_home):
        anthropic = pytest.importorskip("anthropic")  # skip when [ai] extra is absent (CI)

        _write_config(_hermetic_home, "anthropic", api_key="fake-key")

        def _boom(self, *a, **k):
            raise anthropic.APIError("boom", request=None, body=None)

        with (
            _patch_vt_triage(_canned_triage_result()),
            patch("vex.ai.anthropic.ClaudeProvider.explain", _boom),
        ):
            result = runner.invoke(app, ["triage", _IP, "-o", "json", "-q", "--no-cache", "--explain"])

        assert result.exit_code == 4
        data = json.loads(result.stdout)
        assert data["explanation"] is None
        assert data["explanation_degraded"] is True
        assert data["explanation_provider"] == "anthropic"

    def test_openai_api_failure_exits_4(self, _hermetic_home):
        openai = pytest.importorskip("openai")  # skip when [ai] extra is absent (CI)

        _write_config(_hermetic_home, "openai", api_key="fake-key")

        def _boom(self, *a, **k):
            raise openai.APIError("boom", request=None, body=None)

        with (
            _patch_vt_triage(_canned_triage_result()),
            patch("vex.ai.openai.OpenAIProvider.explain", _boom),
        ):
            result = runner.invoke(app, ["triage", _IP, "-o", "json", "-q", "--no-cache", "--explain"])

        assert result.exit_code == 4
        data = json.loads(result.stdout)
        assert data["explanation_degraded"] is True
        assert data["explanation_provider"] == "openai"

    def test_missing_api_key_is_degraded_not_silent_template(self, _hermetic_home):
        """A provider explicitly configured as anthropic with NO key used to
        echo a yellow warning and silently fall back to a template (no marker,
        no exit code). F2: an explicit-provider setup failure must fail loud
        + marked, same as a runtime failure."""
        _write_config(_hermetic_home, "anthropic")  # no api_key

        with _patch_vt_triage(_canned_triage_result()):
            result = runner.invoke(app, ["triage", _IP, "-o", "json", "-q", "--no-cache", "--explain"])

        assert result.exit_code == 4
        data = json.loads(result.stdout)
        assert data["explanation"] is None
        assert data["explanation_degraded"] is True
        assert data["explanation_provider"] == "anthropic"
        assert "EXPLANATION UNAVAILABLE" in result.stderr


# ---------------------------------------------------------------------------
# (f) — a deliberate `ai.provider: none` (template) run is NOT degraded.
# ---------------------------------------------------------------------------


class TestDeliberateTemplateIsNotDegraded:
    def test_template_provider_not_degraded(self, _hermetic_home, monkeypatch):
        """ai.provider=none (the default) is an explicit no-LLM choice: even
        though Ollama's transport is patched to fail, it is never invoked."""
        _write_config(_hermetic_home, "none")

        def fake_urlopen(req, timeout=None, **kwargs):
            raise AssertionError("ollama transport must never be called when ai.provider=none")

        monkeypatch.setattr("shipwright_kit.llm.urllib.request.urlopen", fake_urlopen)

        with _patch_vt_triage(_canned_triage_result()):
            result = runner.invoke(app, ["triage", _IP, "-o", "json", "-q", "--no-cache", "--explain"])

        # exit stands at the verdict code (this IOC is suspicious -> 1)
        assert result.exit_code in (0, 1, 2)
        data = json.loads(result.stdout)
        assert data["explanation"] is not None  # a template explanation IS produced
        assert data["explanation_degraded"] is False
        assert data["explanation_provider"] is None
        assert "EXPLANATION UNAVAILABLE" not in result.stderr

    def test_no_explain_flag_is_not_degraded(self, _hermetic_home):
        """The absolute baseline: no --explain at all -> no marker, verdict exit."""
        _write_config(_hermetic_home, "anthropic")  # provider set but unused

        with _patch_vt_triage(_canned_triage_result()):
            result = runner.invoke(app, ["triage", _IP, "-o", "json", "-q", "--no-cache"])

        assert result.exit_code in (0, 1, 2)
        data = json.loads(result.stdout)
        assert data["explanation_degraded"] is False
        assert data["explanation_provider"] is None


# ---------------------------------------------------------------------------
# investigate mirrors triage — one representative test proving the fix
# applies to both commands (the degraded marker lives at r.triage.* there).
# ---------------------------------------------------------------------------


class TestInvestigateMirrorsTriage:
    def test_investigate_ollama_failure_exits_4(self, _hermetic_home, monkeypatch):
        _write_config(_hermetic_home, "ollama")

        def fake_urlopen(req, timeout=None, **kwargs):
            raise __import__("urllib.error", fromlist=["URLError"]).URLError("connection refused")

        monkeypatch.setattr("shipwright_kit.llm.urllib.request.urlopen", fake_urlopen)

        with _patch_vt_investigate(_canned_investigate_result()):
            result = runner.invoke(app, ["investigate", _IP, "-o", "json", "-q", "--no-cache", "--explain"])

        assert result.exit_code == 4
        data = json.loads(result.stdout)
        assert data["triage"]["explanation_degraded"] is True
        assert data["triage"]["explanation_provider"] == "ollama"


# ---------------------------------------------------------------------------
# (g) — no --on-llm-failure flag / no TTY prompt (DEFERRED to slice-2).
# ---------------------------------------------------------------------------


class TestNoFlagNoPrompt:
    def test_no_on_llm_failure_flag_exists(self):
        result = runner.invoke(app, ["triage", "--help"])
        assert "--on-llm-failure" not in result.stdout
