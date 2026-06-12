"""Tests for S2: eager --version flag on the vex CLI app.

All tests are offline (no network, no filesystem).
"""

from __future__ import annotations

from typer.testing import CliRunner

from vex import __version__
from vex.main import app

runner = CliRunner()


class TestVersionFlag:
    def test_version_flag_exits_zero(self) -> None:
        """--version exits with code 0."""
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0

    def test_version_flag_prints_version_string(self) -> None:
        """--version prints the current __version__."""
        result = runner.invoke(app, ["--version"])
        assert __version__ in result.output

    def test_version_flag_prints_vex_prefix(self) -> None:
        """--version output contains 'vex' label."""
        result = runner.invoke(app, ["--version"])
        assert "vex" in result.output.lower()

    def test_version_subcommand_still_works(self) -> None:
        """The existing `vex version` subcommand still exits 0 (backward compat)."""
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0

    def test_version_subcommand_prints_version(self) -> None:
        """The existing `vex version` subcommand still prints the version string."""
        result = runner.invoke(app, ["version"])
        assert __version__ in result.output

    def test_version_flag_is_eager(self) -> None:
        """--version with other args still exits early (eager flag)."""
        result = runner.invoke(app, ["--version", "triage", "1.2.3.4"])
        assert result.exit_code == 0
        assert __version__ in result.output
