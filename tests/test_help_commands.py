"""Every `--help` must exit 0 and print the usage line with plain, uppercase argument names.

typer 0.27 changed metavar printing: a required argument is brace-wrapped and
lower-cased (`vex tag [OPTIONS] {ioc}`) and an optional one is lower-cased
(`[ioc]`), where typer 0.26 printed `IOC` / `[IOC]`. These tests pin the
uppercase form on both versions, plus the no-`click`-import guard (click is not a
declared dependency; it is only transitive via typer).
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest
import typer.main
from typer.testing import CliRunner

from vex.main import app

runner = CliRunner()

VEX_PKG = Path(__file__).resolve().parent.parent / "vex"

_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_WIDE = {"COLUMNS": "200"}

# Command path -> exact tail of the usage line (after `[OPTIONS]`).
_EXPECTED_TAIL = {
    "triage": "[IOC]",
    "investigate": "[IOC]",
    "manual": "[TOPIC]",
    "tag": "IOC",
    "note": "IOC",
    "watchlist run": "NAME",
    "watchlist manage": "NAME",
    "watchlist": "COMMAND [ARGS]...",
    "cache-clear": "",
    "version": "",
    "addons": "",
    "doctor": "",
    "config": "",
}


def _command_paths() -> list[tuple[str, ...]]:
    """Every command and subcommand path, discovered from the live app."""
    paths: list[tuple[str, ...]] = []

    def walk(group, prefix: tuple[str, ...]) -> None:
        for name, cmd in sorted(group.commands.items()):
            paths.append((*prefix, name))
            if hasattr(cmd, "commands"):
                walk(cmd, (*prefix, name))

    walk(typer.main.get_command(app), ())
    return paths


def _usage_line(output: str) -> str:
    """The whole usage statement, joined across wrapped lines, ANSI-free."""
    lines = _ANSI.sub("", output).splitlines()
    for i, line in enumerate(lines):
        if line.strip().startswith("Usage:"):
            parts = [line.strip()]
            for cont in lines[i + 1 :]:
                if not cont.strip():
                    break
                parts.append(cont.strip())
            return " ".join(parts)
    raise AssertionError(f"no 'Usage:' line found in help output: {output!r}")


def _help(path: tuple[str, ...], env: dict[str, str] | None = None):
    return runner.invoke(app, [*path, "--help"], env=env if env is not None else _WIDE)


def test_command_discovery_is_not_empty() -> None:
    names = {" ".join(p) for p in _command_paths()}
    assert {"triage", "investigate", "tag", "note", "manual", "watchlist run"} <= names


def test_every_discovered_command_has_an_expected_tail() -> None:
    names = {" ".join(p) for p in _command_paths()}
    assert names == set(_EXPECTED_TAIL), names ^ set(_EXPECTED_TAIL)


def test_root_help() -> None:
    result = runner.invoke(app, ["--help"], env=_WIDE)
    assert result.exit_code == 0, result.output
    assert _usage_line(result.output).endswith("COMMAND [ARGS]...")


@pytest.mark.parametrize("path", _command_paths(), ids=lambda p: " ".join(p))
def test_command_help_exits_zero(path: tuple[str, ...]) -> None:
    result = _help(path)
    assert result.exception is None or isinstance(result.exception, SystemExit), repr(result.exception)
    assert result.exit_code == 0, result.output
    usage_lines = [ln for ln in _ANSI.sub("", result.output).splitlines() if ln.strip().startswith("Usage:")]
    assert len(usage_lines) == 1, result.output


@pytest.mark.parametrize("path", _command_paths(), ids=lambda p: " ".join(p))
def test_usage_line_has_no_placeholder_token(path: tuple[str, ...]) -> None:
    usage = _usage_line(_help(path).output)
    assert "{" not in usage and "}" not in usage, usage
    # No lowercase argument placeholder: every non-option word after the command is
    # uppercase (or punctuation), e.g. `IOC`, `[TOPIC]`, `COMMAND`, `[ARGS]...`.
    tail = usage.split("[OPTIONS]", 1)[1] if "[OPTIONS]" in usage else ""
    assert not re.search(r"[a-z]", tail), usage


@pytest.mark.parametrize("path", _command_paths(), ids=lambda p: " ".join(p))
def test_usage_line_ends_with_expected_tail(path: tuple[str, ...]) -> None:
    usage = _usage_line(_help(path).output)
    expected = _EXPECTED_TAIL[" ".join(path)]
    if expected:
        assert usage.endswith(f"[OPTIONS] {expected}"), usage
    else:
        assert usage.endswith("[OPTIONS]"), usage


@pytest.mark.parametrize(
    "env", [{"COLUMNS": "200", "FORCE_COLOR": "1"}, {"COLUMNS": "200", "NO_COLOR": "1"}, {"COLUMNS": "40"}]
)
@pytest.mark.parametrize("path", [("tag",), ("triage",), ("watchlist", "run")], ids=lambda p: " ".join(p))
def test_usage_line_survives_colour_and_narrow_width(path: tuple[str, ...], env: dict[str, str]) -> None:
    result = _help(path, env=env)
    assert result.exit_code == 0, result.output
    usage = _usage_line(result.output)
    assert "{" not in usage and "}" not in usage, usage
    assert usage.endswith(_EXPECTED_TAIL[" ".join(path)]), usage


def test_missing_argument_error_names_the_uppercase_argument() -> None:
    result = runner.invoke(app, ["tag"], env=_WIDE)
    assert result.exit_code == 2
    text = _ANSI.sub("", result.output)
    assert "Usage: vex tag [OPTIONS] IOC" in text
    assert "Missing argument 'IOC'" in text


def test_usage_line_joins_wrapped_continuation() -> None:
    wrapped = " Usage: vex watchlist run [OPTIONS]\n {NAME}\n\n Re-triage\n"
    assert _usage_line(wrapped) == "Usage: vex watchlist run [OPTIONS] {NAME}"


def test_usage_line_ignores_ansi() -> None:
    coloured = "\x1b[1;33mUsage:\x1b[0m vex tag [OPTIONS] IOC\n"
    assert _usage_line(coloured) == "Usage: vex tag [OPTIONS] IOC"


def test_usage_line_requires_a_real_usage_line() -> None:
    with pytest.raises(AssertionError):
        _usage_line("This text only mentions the word usage.\n")


def _is_click_name(name: str) -> bool:
    return name == "click" or name.startswith("click.")


def _is_vendored_click(name: str) -> bool:
    return name == "typer._click" or name.startswith("typer._click.")


def find_click_imports(source: str) -> list[int]:
    """Line numbers of static, dynamic or vendored click imports in `source`."""
    hits: list[int] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            if any(_is_click_name(a.name) or _is_vendored_click(a.name) for a in node.names):
                hits.append(node.lineno)
        elif isinstance(node, ast.ImportFrom):
            if node.level != 0:
                continue
            mod = node.module or ""
            if _is_click_name(mod) or _is_vendored_click(mod):
                hits.append(node.lineno)
            elif mod == "typer" and any(a.name == "_click" for a in node.names):
                hits.append(node.lineno)
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute):
                called = func.attr
            elif isinstance(func, ast.Name):
                called = func.id
            else:
                continue
            if called not in {"import_module", "__import__"} or not node.args:
                continue
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                if _is_click_name(first.value) or _is_vendored_click(first.value):
                    hits.append(node.lineno)
    return hits


@pytest.mark.parametrize(
    "source",
    [
        "import click",
        "import click.utils",
        "from click import echo",
        "from click.utils import echo",
        "import importlib\nimportlib.import_module('click')",
        "import importlib\nimportlib.import_module('click.utils')",
        "from importlib import import_module\nimport_module('click')",
        "__import__('click')",
        "__import__('click.core')",
        "from typer import _click",
        "from typer._click import echo",
        "import typer._click",
        "import importlib\nimportlib.import_module('typer._click')",
        "def f():\n    import click\n",
    ],
)
def test_detector_flags_bad_forms(source: str) -> None:
    assert find_click_imports(source) != []


@pytest.mark.parametrize(
    "source",
    [
        "import typer",
        "import typer\ntyper.echo('x')",
        "from typer import Exit",
        '"""Click here to continue."""',
        "x = 'click'",
        "import importlib\nimportlib.import_module('clicker')",
        "import importlib\nimportlib.import_module('json')",
        "__import__('os')",
        "from . import click_helpers",
    ],
)
def test_detector_ignores_benign_forms(source: str) -> None:
    assert find_click_imports(source) == []


def test_no_module_under_vex_imports_click() -> None:
    offenders: list[str] = []
    for path in sorted(VEX_PKG.rglob("*.py")):
        for lineno in find_click_imports(path.read_text(encoding="utf-8")):
            offenders.append(f"{path.relative_to(VEX_PKG.parent)}:{lineno}")
    assert offenders == [], f"undeclared dependency click imported at: {offenders}"
