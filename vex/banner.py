"""CLI banner display — ffuf-inspired ASCII art header."""

import sys

from rich.console import Console

from . import __version__

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


def print_banner(*, quiet: bool = False) -> None:
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
