"""
vex - VirusTotal IOC Enrichment Tool
Usage:
  vex triage <ioc> [options]
  vex investigate <ioc> [options]
"""

from __future__ import annotations

import sys
from enum import Enum
from pathlib import Path
from typing import Annotated, Optional

import typer

from . import __version__
from .banner import print_banner
from .cache import Cache
from .client import VTClient
from .config import load_config
from .defang import defang as defang_ioc, refang as refang_ioc
from .ioc_detector import IOCType, detect, is_hash
from .mitre.mapper import map_to_attack
from .models import InvestigateResult, TriageResult, Verdict
from .output.export import to_csv_triage, to_json, to_json_list
from .output.stix import to_stix_bundle
from .output.formatter import (
    console,
    err_console,
    print_investigate_console,
    print_investigate_rich,
    print_summary,
    print_timeline_console,
    print_timeline_rich,
    print_triage_console,
    print_triage_rich,
)
from .timeline import build_timeline

# Exit code mapping (highest severity wins)
_EXIT_CODES = {0: 0, 1: 0, 2: 1, 3: 2}  # severity → exit code

app = typer.Typer(
    name="vex",
    help="VirusTotal IOC Enrichment Tool - query VT API v3 for malware analysis.",
    add_completion=False,
    rich_markup_mode="rich",
    invoke_without_command=True,
)


# ---------------------------------------------------------------------------
# App callback — banner + global options
# ---------------------------------------------------------------------------

@app.callback()
def _app_callback(
    ctx: typer.Context,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Suppress the ASCII banner."),
    ] = False,
) -> None:
    """VirusTotal IOC Enrichment Tool — query VT API v3 for malware analysis."""
    cfg = load_config()
    print_banner(quiet=quiet or cfg.output.quiet)
    if ctx.invoked_subcommand is None:
        raise typer.Exit()


class OutputFormat(str, Enum):
    json = "json"
    rich = "rich"
    console = "console"


# ---------------------------------------------------------------------------
# Common options as reusable type aliases
# ---------------------------------------------------------------------------

_IOCArg = Annotated[
    Optional[str],
    typer.Argument(help="IOC to enrich (hash / IP / domain / URL). Reads from stdin if omitted."),
]
_FileOpt = Annotated[
    Optional[Path],
    typer.Option("--file", "-f", help="File with one IOC per line.", exists=True, readable=True),
]
_OutputOpt = Annotated[
    OutputFormat,
    typer.Option("--output", "-o", help="Output format: json | rich | console"),
]
_ConfigOpt = Annotated[
    Optional[Path],
    typer.Option("--config", "-c", help="Path to config.yaml", exists=True, readable=True),
]
_NoCacheOpt = Annotated[
    bool,
    typer.Option("--no-cache", help="Bypass cache and force fresh API lookup."),
]
_CsvOpt = Annotated[
    bool,
    typer.Option("--csv", help="Output as CSV (triage only, overrides --output)."),
]
_DefangOpt = Annotated[
    bool,
    typer.Option("--defang", help="Defang IOCs in output (e.g. evil.com → evil[.]com)."),
]
_AlertOpt = Annotated[
    Optional[str],
    typer.Option("--alert", help="Only show results with at least this verdict (CLEAN/UNKNOWN/SUSPICIOUS/MALICIOUS)."),
]
_SummaryOpt = Annotated[
    bool,
    typer.Option("--summary", help="Print a one-line verdict summary to stderr."),
]
_StixOpt = Annotated[
    bool,
    typer.Option("--stix", help="Export results as STIX 2.1 JSON bundle."),
]
_TimelineOpt = Annotated[
    bool,
    typer.Option("--timeline", help="Show chronological event timeline (investigate only)."),
]


# ---------------------------------------------------------------------------
# IOC collection helpers
# ---------------------------------------------------------------------------

_MAX_IOC_LEN = 2048  # max IOC string length (URLs can be long)
_MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


def _collect_iocs(ioc: Optional[str], file: Optional[Path]) -> list[str]:
    iocs: list[str] = []
    if file:
        if file.stat().st_size > _MAX_FILE_SIZE:
            err_console.print("[red]Error:[/red] IOC file too large (max 10 MB).")
            raise typer.Exit(code=1)
        iocs.extend(
            line.strip()[:_MAX_IOC_LEN]
            for line in file.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        )
    if ioc:
        iocs.append(ioc.strip()[:_MAX_IOC_LEN])
    if not iocs and not sys.stdin.isatty():
        iocs.extend(line.strip()[:_MAX_IOC_LEN] for line in sys.stdin if line.strip())
    if not iocs:
        err_console.print("[red]Error:[/red] Provide an IOC as argument, via --file, or via stdin.")
        raise typer.Exit(code=1)
    return iocs


def _resolve_enricher(ioc_type: IOCType):
    """Return the correct enricher module for an IOC type."""
    from .enrichers import hash as hash_enricher, ip as ip_enricher, domain as domain_enricher, url as url_enricher
    if is_hash(ioc_type):
        return hash_enricher
    if ioc_type in (IOCType.IPV4, IOCType.IPV6):
        return ip_enricher
    if ioc_type == IOCType.DOMAIN:
        return domain_enricher
    if ioc_type == IOCType.URL:
        return url_enricher
    return None


def _maybe_defang(result: TriageResult, do_defang: bool) -> TriageResult:
    """Replace the IOC string in the result with its defanged form."""
    if do_defang and result.ioc:
        result.ioc = defang_ioc(result.ioc)
    return result


def _maybe_defang_inv(result: InvestigateResult, do_defang: bool) -> InvestigateResult:
    """Replace the IOC string in the investigate result with its defanged form."""
    if do_defang and result.triage.ioc:
        result.triage.ioc = defang_ioc(result.triage.ioc)
    return result


def _max_severity(results: list[TriageResult]) -> int:
    """Return the highest severity across all results."""
    if not results:
        return 0
    return max(r.verdict.severity for r in results)


def _filter_by_alert(results: list[TriageResult], alert: Optional[str]) -> list[TriageResult]:
    """Keep only results whose verdict meets or exceeds the *alert* threshold."""
    if not alert:
        return results
    try:
        threshold = Verdict(alert.upper()).severity
    except ValueError:
        err_console.print(f"[yellow]Warning:[/yellow] Invalid --alert value '{alert}'. Use CLEAN/UNKNOWN/SUSPICIOUS/MALICIOUS.")
        return results
    return [r for r in results if r.verdict.severity >= threshold]


def _filter_inv_by_alert(results: list[InvestigateResult], alert: Optional[str]) -> list[InvestigateResult]:
    """Keep only investigate results whose triage verdict meets the threshold."""
    if not alert:
        return results
    try:
        threshold = Verdict(alert.upper()).severity
    except ValueError:
        err_console.print(f"[yellow]Warning:[/yellow] Invalid --alert value '{alert}'. Use CLEAN/UNKNOWN/SUSPICIOUS/MALICIOUS.")
        return results
    return [r for r in results if r.triage.verdict.severity >= threshold]


def _output_triage(result: TriageResult, fmt: OutputFormat) -> None:
    if fmt == OutputFormat.rich:
        print_triage_rich(result)
    elif fmt == OutputFormat.console:
        print_triage_console(result)
    else:
        print(to_json(result))


def _output_investigate(result: InvestigateResult, fmt: OutputFormat) -> None:
    if fmt == OutputFormat.rich:
        print_investigate_rich(result)
    elif fmt == OutputFormat.console:
        print_investigate_console(result)
    else:
        print(to_json(result))


# ---------------------------------------------------------------------------
# Subcommand: triage
# ---------------------------------------------------------------------------

@app.command(name="triage", help="[bold cyan]Fast SOC triage[/bold cyan] - detection ratio, verdict, families. Minimal API calls.")
def cmd_triage(
    ioc: _IOCArg = None,
    file: _FileOpt = None,
    output: _OutputOpt = OutputFormat.json,
    config_path: _ConfigOpt = None,
    no_cache: _NoCacheOpt = False,
    csv: _CsvOpt = False,
    do_defang: _DefangOpt = False,
    alert: _AlertOpt = None,
    summary: _SummaryOpt = False,
    stix: _StixOpt = False,
) -> None:
    config = load_config(config_path)
    iocs = _collect_iocs(ioc, file)

    try:
        config.api_key  # validate key exists before proceeding
    except ValueError as e:
        err_console.print(f"[red]{e}[/red]")
        raise typer.Exit(code=1)

    results: list[TriageResult] = []

    with Cache(config.cache_db_path, config.cache.ttl_hours, config.cache.enabled and not no_cache) as cache:
        with VTClient(config) as client:
            for raw_ioc in iocs:
                ioc_type, normalised_ioc = detect(raw_ioc)

                if ioc_type == IOCType.UNKNOWN:
                    err_console.print(f"[yellow]Warning:[/yellow] Cannot detect IOC type for '{raw_ioc}' - skipping.")
                    continue

                cache_key = f"triage:{ioc_type.value}:{normalised_ioc}"
                cached = cache.get(cache_key)

                if cached:
                    result = TriageResult.model_validate(cached)
                    result.from_cache = True
                else:
                    enricher = _resolve_enricher(ioc_type)
                    if output in (OutputFormat.rich, OutputFormat.console):
                        err_console.print(f"[dim]→ Looking up {ioc_type.value}: {normalised_ioc}[/dim]")
                    try:
                        result = enricher.triage(normalised_ioc, ioc_type.value, client, config)
                        cache.set(cache_key, result.model_dump(mode="json"))
                    except Exception as e:
                        err_console.print(f"[red]Error enriching {normalised_ioc}:[/red] {type(e).__name__}")
                        continue

                results.append(result)

    # Apply defanging if requested
    if do_defang:
        results = [_maybe_defang(r, True) for r in results]

    # Compute exit code from the highest severity BEFORE filtering
    exit_code = _EXIT_CODES.get(_max_severity(results), 0)

    # Filter by alert threshold
    results = _filter_by_alert(results, alert)

    # Summary to stderr
    if summary:
        print_summary(results)

    # Output results
    if stix:
        print(to_stix_bundle(results))
    elif csv:
        print(to_csv_triage(results))
    elif output == OutputFormat.json:
        print(to_json_list(results) if len(results) > 1 else to_json(results[0]) if results else "[]")
    else:
        for r in results:
            _output_triage(r, output)

    raise typer.Exit(code=exit_code)


# ---------------------------------------------------------------------------
# Subcommand: investigate
# ---------------------------------------------------------------------------

@app.command(name="investigate", help="[bold magenta]Deep DFIR investigation[/bold magenta] - PE info, sandbox, passive DNS, relationships.")
def cmd_investigate(
    ioc: _IOCArg = None,
    file: _FileOpt = None,
    output: _OutputOpt = OutputFormat.json,
    config_path: _ConfigOpt = None,
    no_cache: _NoCacheOpt = False,
    do_defang: _DefangOpt = False,
    alert: _AlertOpt = None,
    summary: _SummaryOpt = False,
    stix: _StixOpt = False,
    timeline: _TimelineOpt = False,
) -> None:
    config = load_config(config_path)
    iocs = _collect_iocs(ioc, file)

    try:
        config.api_key  # validate key exists before proceeding
    except ValueError as e:
        err_console.print(f"[red]{e}[/red]")
        raise typer.Exit(code=1)

    results: list[InvestigateResult] = []

    with Cache(config.cache_db_path, config.cache.ttl_hours, config.cache.enabled and not no_cache) as cache:
        with VTClient(config) as client:
            for raw_ioc in iocs:
                ioc_type, normalised_ioc = detect(raw_ioc)

                if ioc_type == IOCType.UNKNOWN:
                    err_console.print(f"[yellow]Warning:[/yellow] Cannot detect IOC type for '{raw_ioc}' - skipping.")
                    continue

                cache_key = f"investigate:{ioc_type.value}:{normalised_ioc}"
                cached = cache.get(cache_key)

                if cached:
                    result = InvestigateResult.model_validate(cached)
                    result.triage.from_cache = True
                else:
                    enricher = _resolve_enricher(ioc_type)
                    if output in (OutputFormat.rich, OutputFormat.console):
                        err_console.print(f"[dim]→ Investigating {ioc_type.value}: {normalised_ioc}[/dim]")
                    try:
                        result = enricher.investigate(normalised_ioc, ioc_type.value, client, config)
                        # MITRE ATT&CK mapping
                        result.attack_mappings = map_to_attack(result)
                        cache.set(cache_key, result.model_dump(mode="json"))
                    except Exception as e:
                        err_console.print(f"[red]Error investigating {normalised_ioc}:[/red] {type(e).__name__}")
                        continue

                results.append(result)

    # Apply defanging if requested
    if do_defang:
        results = [_maybe_defang_inv(r, True) for r in results]

    # Compute exit code from highest severity BEFORE filtering
    exit_code = _EXIT_CODES.get(
        max((r.triage.verdict.severity for r in results), default=0), 0
    )

    # Filter by alert threshold
    results = _filter_inv_by_alert(results, alert)

    # Summary to stderr
    if summary:
        print_summary([r.triage for r in results])

    # Output results
    if stix:
        print(to_stix_bundle(results))
    elif output == OutputFormat.json:
        print(to_json_list(results) if len(results) > 1 else to_json(results[0]) if results else "[]")
    else:
        for r in results:
            _output_investigate(r, output)

    # Timeline (appended after main output)
    if timeline:
        for r in results:
            tl = build_timeline(r)
            if output == OutputFormat.rich:
                print_timeline_rich(tl)
            else:
                print_timeline_console(tl)

    raise typer.Exit(code=exit_code)


# ---------------------------------------------------------------------------
# Utility commands
# ---------------------------------------------------------------------------

@app.command(name="cache-clear", help="Clear all cached results.")
def cmd_cache_clear(config_path: _ConfigOpt = None) -> None:
    config = load_config(config_path)
    db = config.cache_db_path
    if db.exists():
        db.unlink()
        console.print(f"[green]Cache cleared:[/green] {db}")
    else:
        console.print("[dim]No cache file found.[/dim]")


@app.command(name="version", help="Show version.")
def cmd_version() -> None:
    console.print(f"vex [bold]{__version__}[/bold]")


# ---------------------------------------------------------------------------
# Knowledge base commands
# ---------------------------------------------------------------------------

@app.command(name="tag", help="[bold green]Manage IOC tags[/bold green] in the local knowledge base.")
def cmd_tag(
    ioc: Annotated[str, typer.Argument(help="IOC to tag.")],
    add: Annotated[Optional[list[str]], typer.Option("--add", "-a", help="Tag(s) to add.")] = None,
    remove: Annotated[Optional[list[str]], typer.Option("--remove", "-r", help="Tag(s) to remove.")] = None,
) -> None:
    from .knowledge.db import KnowledgeDB
    with KnowledgeDB() as db:
        if add:
            for t in add:
                db.add_tag(ioc, t)
                console.print(f"[green]+[/green] Tagged [bold]{ioc}[/bold] with [cyan]{t}[/cyan]")
        if remove:
            for t in remove:
                db.remove_tag(ioc, t)
                console.print(f"[red]-[/red] Removed tag [cyan]{t}[/cyan] from [bold]{ioc}[/bold]")
        tags = db.get_tags(ioc)
        if tags:
            console.print(f"[dim]Tags for {ioc}:[/dim] {', '.join(tags)}")
        elif not add and not remove:
            console.print(f"[dim]No tags for {ioc}[/dim]")


@app.command(name="note", help="[bold green]Manage IOC notes[/bold green] in the local knowledge base.")
def cmd_note(
    ioc: Annotated[str, typer.Argument(help="IOC to annotate.")],
    add: Annotated[Optional[str], typer.Option("--add", "-a", help="Note text to add.")] = None,
    delete_id: Annotated[Optional[int], typer.Option("--delete", "-d", help="Note ID to delete.")] = None,
) -> None:
    from .knowledge.db import KnowledgeDB
    with KnowledgeDB() as db:
        if add:
            nid = db.add_note(ioc, add)
            console.print(f"[green]+[/green] Note #{nid} added to [bold]{ioc}[/bold]")
        if delete_id is not None:
            db.delete_note(delete_id)
            console.print(f"[red]-[/red] Deleted note #{delete_id}")
        notes = db.get_notes(ioc)
        if notes:
            console.print(f"[dim]Notes for {ioc}:[/dim]")
            for n in notes:
                console.print(f"  [dim]#{n['id']}[/dim] {n['note']}  [dim]({n['created_at'][:10]})[/dim]")
        elif not add and delete_id is None:
            console.print(f"[dim]No notes for {ioc}[/dim]")


@app.command(name="watchlist", help="[bold green]Manage watchlists[/bold green] in the local knowledge base.")
def cmd_watchlist(
    name: Annotated[str, typer.Argument(help="Watchlist name.")],
    add: Annotated[Optional[list[str]], typer.Option("--add", "-a", help="IOC(s) to add.")] = None,
    remove: Annotated[Optional[list[str]], typer.Option("--remove", "-r", help="IOC(s) to remove.")] = None,
    show: Annotated[bool, typer.Option("--list", "-l", help="List all IOCs in this watchlist.")] = False,
) -> None:
    from .knowledge.db import KnowledgeDB
    with KnowledgeDB() as db:
        if add:
            for ioc in add:
                db.add_to_watchlist(name, ioc)
                console.print(f"[green]+[/green] Added [bold]{ioc}[/bold] to watchlist [cyan]{name}[/cyan]")
        if remove:
            for ioc in remove:
                db.remove_from_watchlist(name, ioc)
                console.print(f"[red]-[/red] Removed [bold]{ioc}[/bold] from watchlist [cyan]{name}[/cyan]")
        if show or (not add and not remove):
            iocs = db.get_watchlist(name)
            if iocs:
                console.print(f"[dim]Watchlist '{name}' ({len(iocs)} IOCs):[/dim]")
                for i in iocs:
                    console.print(f"  {i}")
            else:
                console.print(f"[dim]Watchlist '{name}' is empty.[/dim]")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
