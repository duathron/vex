"""CLI banner display — ffuf-inspired ASCII art header."""

import sys
from pathlib import Path

from rich.console import Console

from . import __version__

try:
    _FIRST_RUN_FLAG: Path | None = Path.home() / ".vex" / ".first_run_complete"
except RuntimeError:
    _FIRST_RUN_FLAG = None  # no home dir (e.g. containers with no HOME env)

_BANNER = """\
[bold cyan]                        ██▀   ▄▄▄▄▄▄
     ▄▄▄▄▄    ▄▄▄▄▄▄▄▄▄     █████████▄
     █████▄██████████▀▄▄█▀▄██▄██████▄██▄
      ▀ ▄████████▄███████ ██████████████ █ ▄
   █▄  ███▀▀▀▀▀▀█▀▀██████ ██████▀███████ ▄██▄
      ██▀▄█████████▀███▀▀ ▀████████████  ▀███
   ██ ██ ████▀  █████▀▄████▄▀█████████▄   ▀
     ███ ███    █████ ███▀██▄▄▀▀▀▀▀▀ ▀██▄
     █▄█▄▀███▄▄▄███▀█▄▀█████▀█████   ▄ ▀██▄
     █████ ▀▀▀▀▀▀▀▄███▄▄▄▄▄▄██████ ▄███▄ ▀
   ▄███▄ ▀█████████████████▀▀▄███████████
 ▄███████ ▄▄▄▄▄▄ ▄▄▄ ▀███▀▄█ ███████▀███
▄████████▄ █████████▄▄▄  ▀ █ ████▄██ ▀▀
███████████ ▄▄▄▄▄▄  ▄██ ▄▄▄ █████▀▀▀ █▄
█████▀██████▄▀██████▄██ █▀▄██▀▀█▀    ▀▀
████▀ ▀█ ████████▄▄▄▄▄▄▄█████▄██ █▀
 ▀▀    ▀███████████████████████
         ▀█  ████▀  ▀▀▀▄██████
          ▀█████       ▀█████[/bold cyan]
[dim] v{version}[/dim] | [bold]by Christian Huhn[/bold] | [dim]VirusTotal IOC Enrichment[/dim]
[dim]________________________________________________[/dim]
"""


def print_banner(
    *,
    quiet: bool = False,
    update_check_enabled: bool = True,
    check_interval_hours: int = 24,
) -> None:
    """Print the vex ASCII-art banner to stderr.

    The banner is suppressed when:
    - *quiet* is True (via ``-q`` flag or ``output.quiet`` in config.yaml)
    - stdout is not a TTY (i.e. output is piped)
    """
    if quiet:
        return
    if not sys.stdout.isatty():
        return

    err = Console(stderr=True)
    err.print(_BANNER.format(version=__version__), highlight=False)

    # Version update notice (non-blocking, fail-silent)
    if update_check_enabled:
        try:
            from .version_check import check_for_update

            latest = check_for_update(check_interval_hours)
            if latest:
                err.print(f"  [bold yellow]Update available: {__version__} -> {latest}[/bold yellow]")
                err.print("  [dim]pip install --upgrade vex  |  https://github.com/duathron/vex/releases[/dim]")
        except Exception:
            pass

    # First-run addon hint (shown once, suppressed by -q and pipe)
    if _FIRST_RUN_FLAG is not None and not _FIRST_RUN_FLAG.exists():
        err.print("[dim]Tip: Run 'vex addons' to see available extras (AI explanations, pipeline).[/dim]")
        try:
            _FIRST_RUN_FLAG.parent.mkdir(parents=True, exist_ok=True)
            _FIRST_RUN_FLAG.touch()
        except Exception:
            pass
