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
from .config import load_config, save_config
from .defang import defang as defang_ioc, refang as refang_ioc
from .ioc_detector import IOCType, detect, is_hash
from .mitre.mapper import map_to_attack
from .models import InvestigateResult, TriageResult, Verdict
from .output.export import to_csv_triage, to_json, to_json_list
from .output.stix import to_stix_bundle
from .output.formatter import (
    console,
    err_console,
    print_explanation_console,
    print_explanation_rich,
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
    help="VirusTotal IOC Enrichment Tool - query VT API v3 for malware analysis with optional AI-powered explanations.",
    add_completion=False,
    rich_markup_mode="rich",
    invoke_without_command=True,
    epilog="[dim]Quick start:  vex config --set-api-key YOUR_VT_KEY  |  vex triage <ioc>  |  vex triage <ioc> --explain[/dim]",
)


# ---------------------------------------------------------------------------
# App callback — banner + global options
# ---------------------------------------------------------------------------

@app.callback()
def _app_callback(
    ctx: typer.Context,
) -> None:
    """VirusTotal IOC Enrichment Tool — query VT API v3 for malware analysis."""
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
_ApiKeyOpt = Annotated[
    Optional[str],
    typer.Option("--api-key", "-k", help="VirusTotal API key (overrides VT_API_KEY env var and config.yaml)."),
]
_QuietOpt = Annotated[
    bool,
    typer.Option("--quiet", "-q", help="Suppress the ASCII banner."),
]
_ExplainOpt = Annotated[
    bool,
    typer.Option("--explain", "-e", help="Add AI-powered threat explanation. Providers: anthropic, openai, ollama. Falls back to template if unconfigured. See 'vex manual ai' for setup."),
]
_ExplainModelOpt = Annotated[
    Optional[str],
    typer.Option("--explain-model", help="Override AI model (e.g. claude-sonnet-4-20250514, gpt-4o, llama3). Requires provider in ~/.vex/config.yaml."),
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


def _run_explain(
    results: list,
    config,
    model_override: Optional[str],
    output_fmt: OutputFormat,
) -> None:
    """Generate and display AI explanations for results."""
    from .ai import get_provider
    from .ai.cache import AICache
    from .ai.prompt import build_explain_prompt
    from .ai.template import template_explain

    if model_override:
        config.ai.model = model_override

    # Get provider (None = use template fallback)
    provider = None
    try:
        provider = get_provider(config)
    except (ValueError, ImportError) as e:
        err_console.print(f"[yellow]AI:[/yellow] {e}")
        err_console.print("[dim]Falling back to template-based explanation.[/dim]")

    for result in results:
        prompt = build_explain_prompt(result)

        if provider:
            model_name = config.ai.model or "default"
            with AICache(config.ai.cache_ttl_hours) as cache:
                cached = cache.get(provider.name, model_name, prompt)
                if cached:
                    explanation = cached
                    err_console.print(f"[dim]AI explanation from cache ({provider.name})[/dim]")
                else:
                    try:
                        err_console.print(f"[dim]→ Generating AI explanation ({provider.name})...[/dim]")
                        explanation = provider.explain(
                            prompt,
                            max_tokens=config.ai.max_tokens,
                            temperature=config.ai.temperature,
                        )
                        cache.set(provider.name, model_name, prompt, explanation)
                    except Exception as e:
                        err_console.print(f"[yellow]AI error ({provider.name}):[/yellow] {e}")
                        err_console.print("[dim]Falling back to template-based explanation.[/dim]")
                        explanation = template_explain(result)
                        provider = None  # mark as fallback for display
            provider_name = provider.name if provider else "template"
        else:
            explanation = template_explain(result)
            provider_name = "template"

        # Output explanation
        if output_fmt == OutputFormat.rich:
            print_explanation_rich(explanation, provider_name)
        elif output_fmt == OutputFormat.console:
            print_explanation_console(explanation, provider_name)
        # JSON: explanation is added to the result dict (handled separately)


# ---------------------------------------------------------------------------
# Subcommand: triage
# ---------------------------------------------------------------------------

@app.command(name="triage", help="[bold cyan]Fast SOC triage[/bold cyan] - detection ratio, verdict, families. Minimal API calls.")
def cmd_triage(
    ioc: _IOCArg = None,
    file: _FileOpt = None,
    output: _OutputOpt = OutputFormat.console,
    config_path: _ConfigOpt = None,
    no_cache: _NoCacheOpt = False,
    csv: _CsvOpt = False,
    do_defang: _DefangOpt = False,
    alert: _AlertOpt = None,
    summary: _SummaryOpt = False,
    stix: _StixOpt = False,
    api_key: _ApiKeyOpt = None,
    quiet: _QuietOpt = False,
    explain: _ExplainOpt = False,
    explain_model: _ExplainModelOpt = None,
) -> None:
    config = load_config(config_path)
    if api_key:
        config.api.key = api_key
    print_banner(
        quiet=quiet or config.output.quiet,
        update_check_enabled=config.update_check.enabled,
        check_interval_hours=config.update_check.check_interval_hours,
    )
    iocs = _collect_iocs(ioc, file)

    try:
        config.api_key  # validate key exists before proceeding
    except ValueError as e:
        err_console.print(f"[red]{e}[/red]")
        raise typer.Exit(code=1)

    results: list[TriageResult] = []
    failed_count = 0

    if len(iocs) > 1:
        from .batch import batch_triage
        show_progress = output in (OutputFormat.rich, OutputFormat.console)
        results, failed_count = batch_triage(iocs, config, no_cache=no_cache, show_progress=show_progress)
    else:
        with Cache(config.cache_db_path, config.cache.ttl_hours, config.cache.enabled and not no_cache) as cache:
            with VTClient(config) as client:
                for raw_ioc in iocs:
                    ioc_type, normalised_ioc = detect(raw_ioc)

                    if ioc_type == IOCType.UNKNOWN:
                        err_console.print(f"[yellow]Warning:[/yellow] Cannot detect IOC type for '{raw_ioc}' - skipping.")
                        failed_count += 1
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
                            failed_count += 1
                            continue

                    results.append(result)

    if failed_count:
        err_console.print(f"[yellow]{len(results)} processed, {failed_count} failed (see errors above)[/yellow]")

    # Apply defanging if requested
    if do_defang:
        results = [_maybe_defang(r, True) for r in results]

    # Compute exit code from the highest severity BEFORE filtering
    exit_code = _EXIT_CODES.get(_max_severity(results), 0)

    # Filter by alert threshold
    pre_filter_count = len(results)
    results = _filter_by_alert(results, alert)
    if alert and not results and pre_filter_count > 0:
        err_console.print(f"[dim]No IOCs matched alert threshold {alert.upper()} ({pre_filter_count} below threshold)[/dim]")

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

    # AI explanation (opt-in)
    if explain and results:
        _run_explain(results, config, explain_model, output)

    raise typer.Exit(code=exit_code)


# ---------------------------------------------------------------------------
# Subcommand: investigate
# ---------------------------------------------------------------------------

@app.command(name="investigate", help="[bold magenta]Deep DFIR investigation[/bold magenta] - PE info, sandbox, passive DNS, relationships.")
def cmd_investigate(
    ioc: _IOCArg = None,
    file: _FileOpt = None,
    output: _OutputOpt = OutputFormat.console,
    config_path: _ConfigOpt = None,
    no_cache: _NoCacheOpt = False,
    do_defang: _DefangOpt = False,
    alert: _AlertOpt = None,
    summary: _SummaryOpt = False,
    stix: _StixOpt = False,
    timeline: _TimelineOpt = False,
    api_key: _ApiKeyOpt = None,
    quiet: _QuietOpt = False,
    explain: _ExplainOpt = False,
    explain_model: _ExplainModelOpt = None,
) -> None:
    config = load_config(config_path)
    if api_key:
        config.api.key = api_key
    print_banner(
        quiet=quiet or config.output.quiet,
        update_check_enabled=config.update_check.enabled,
        check_interval_hours=config.update_check.check_interval_hours,
    )
    iocs = _collect_iocs(ioc, file)

    try:
        config.api_key  # validate key exists before proceeding
    except ValueError as e:
        err_console.print(f"[red]{e}[/red]")
        raise typer.Exit(code=1)

    results: list[InvestigateResult] = []
    failed_count = 0

    if len(iocs) > 1:
        from .batch import batch_investigate
        show_progress = output in (OutputFormat.rich, OutputFormat.console)
        results, failed_count = batch_investigate(iocs, config, no_cache=no_cache, show_progress=show_progress)
    else:
        with Cache(config.cache_db_path, config.cache.ttl_hours, config.cache.enabled and not no_cache) as cache:
            with VTClient(config) as client:
                for raw_ioc in iocs:
                    ioc_type, normalised_ioc = detect(raw_ioc)

                    if ioc_type == IOCType.UNKNOWN:
                        err_console.print(f"[yellow]Warning:[/yellow] Cannot detect IOC type for '{raw_ioc}' - skipping.")
                        failed_count += 1
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
                            failed_count += 1
                            continue

                    results.append(result)

    if failed_count:
        err_console.print(f"[yellow]{len(results)} processed, {failed_count} failed (see errors above)[/yellow]")

    # Apply defanging if requested
    if do_defang:
        results = [_maybe_defang_inv(r, True) for r in results]

    # Compute exit code from highest severity BEFORE filtering
    exit_code = _EXIT_CODES.get(
        max((r.triage.verdict.severity for r in results), default=0), 0
    )

    # Filter by alert threshold
    pre_filter_count = len(results)
    results = _filter_inv_by_alert(results, alert)
    if alert and not results and pre_filter_count > 0:
        err_console.print(f"[dim]No IOCs matched alert threshold {alert.upper()} ({pre_filter_count} below threshold)[/dim]")

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

    # AI explanation (opt-in)
    if explain and results:
        _run_explain(results, config, explain_model, output)

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
    from .plugins.loader import load_plugins
    console.print(f"vex [bold]{__version__}[/bold]")
    registry = load_plugins()
    names = [p.name for p in registry.plugins]
    if names:
        console.print(f"[dim]Plugins: {', '.join(names)}[/dim]")
    try:
        from .version_check import check_for_update
        latest = check_for_update(check_interval_hours=24)
        if latest:
            console.print(f"  [yellow]Latest: {latest}[/yellow] [dim](update available)[/dim]")
    except Exception:
        pass


@app.command(name="config", help="[bold blue]Manage configuration[/bold blue] - save API key, AI provider, show settings.")
def cmd_config(
    set_api_key: Annotated[
        Optional[str],
        typer.Option("--set-api-key", help="Save VirusTotal API key to ~/.vex/config.yaml"),
    ] = None,
    set_ai_provider: Annotated[
        Optional[str],
        typer.Option("--set-ai-provider", help="Set AI provider (anthropic | openai | ollama | none)."),
    ] = None,
    set_ai_key: Annotated[
        Optional[str],
        typer.Option("--set-ai-key", help="Save AI provider API key to ~/.vex/config.yaml."),
    ] = None,
    show: Annotated[
        bool,
        typer.Option("--show", help="Display active configuration with masked secrets."),
    ] = False,
) -> None:
    config = load_config()
    changed = False

    if set_api_key:
        config.api.key = set_api_key
        changed = True
        path = save_config(config)
        console.print(f"[green]✓[/green] VT API key saved to [bold]{path}[/bold]")

    if set_ai_provider:
        valid = ("anthropic", "openai", "ollama", "none")
        if set_ai_provider.lower() not in valid:
            console.print(f"[red]Error:[/red] Invalid provider '{set_ai_provider}'. Use: {', '.join(valid)}")
            raise typer.Exit(code=1)
        config.ai.provider = set_ai_provider.lower()
        changed = True
        path = save_config(config)
        console.print(f"[green]✓[/green] AI provider set to [bold]{set_ai_provider.lower()}[/bold] in {path}")
        if set_ai_provider.lower() in ("anthropic", "openai") and not config.ai_api_key:
            console.print("[yellow]Note:[/yellow] Set the AI API key with [bold]--set-ai-key[/bold] or [bold]VEX_AI_API_KEY[/bold] env var.")
        if set_ai_provider.lower() in ("anthropic", "openai"):
            console.print(r"[dim]Install AI packages: pip install vex-ioc\[ai][/dim]")

    if set_ai_key:
        config.ai.api_key = set_ai_key
        changed = True
        path = save_config(config)
        console.print(f"[green]✓[/green] AI API key saved to [bold]{path}[/bold]")

    if show:
        _show_config(config)
    elif not changed:
        console.print("[cyan]vex config[/cyan] — Manage configuration")
        console.print("  [bold]--set-api-key KEY[/bold]      Save VirusTotal API key permanently")
        console.print("  [bold]--set-ai-provider NAME[/bold] Set AI provider (anthropic | openai | ollama | none)")
        console.print("  [bold]--set-ai-key KEY[/bold]       Save AI provider API key")
        console.print("  [bold]--show[/bold]                 Display active configuration")
        console.print()
        console.print("[dim]AI setup: run 'vex manual ai' for a step-by-step guide.[/dim]")


def _show_config(config) -> None:
    """Display active config with masked secrets."""
    import os
    from rich.table import Table
    from rich import box

    def mask(val: Optional[str]) -> str:
        if not val:
            return "[dim]not set[/dim]"
        if len(val) <= 8:
            return "****"
        return f"{'*' * (len(val) - 4)}{val[-4:]}"

    t = Table(title="vex configuration", box=box.ROUNDED)
    t.add_column("Key", style="cyan")
    t.add_column("Value")

    # API
    t.add_row("api.key (config)", mask(config.api.key))
    t.add_row("api.key (env VT_API_KEY)", mask(os.getenv("VT_API_KEY")))
    t.add_row("api.tier", config.api.tier)
    t.add_row("api.rate_limit", f"{config.rate_limit.requests_per_minute} req/min, {config.rate_limit.requests_per_day} req/day")

    # Thresholds
    t.add_row("thresholds.malicious_min", str(config.thresholds.malicious_min_detections))
    t.add_row("thresholds.suspicious_min", str(config.thresholds.suspicious_min_detections))
    t.add_row("thresholds.min_engines_clean", str(config.thresholds.min_engines_for_clean))

    # Cache
    t.add_row("cache.enabled", str(config.cache.enabled))
    t.add_row("cache.ttl_hours", str(config.cache.ttl_hours))

    # Output
    t.add_row("output.default_format", config.output.default_format)
    t.add_row("output.quiet", str(config.output.quiet))

    # Plugins
    t.add_row("plugins.load_local", str(config.plugins.load_local))

    # Update check
    t.add_row("update_check.enabled", str(config.update_check.enabled))
    t.add_row("update_check.interval", f"{config.update_check.check_interval_hours}h")

    # AI
    t.add_row("ai.provider", config.ai.provider)
    t.add_row("ai.model", config.ai.model or "[dim]default[/dim]")
    t.add_row("ai.api_key", mask(config.ai_api_key))
    t.add_row("ai.base_url", config.ai.base_url or "[dim]not set[/dim]")
    t.add_row("ai.max_tokens", str(config.ai.max_tokens))
    t.add_row("ai.temperature", str(config.ai.temperature))
    t.add_row("ai.local_only", str(config.ai.local_only))
    t.add_row("ai.cache_ttl_hours", str(config.ai.cache_ttl_hours))

    console.print(t)

    # AI setup hint
    if config.ai.provider == "none":
        console.print()
        console.print("[dim]Hint: AI explanations not configured. Run 'vex manual ai' for setup instructions.[/dim]")


# ---------------------------------------------------------------------------
# Manual / help subcommand
# ---------------------------------------------------------------------------

_MANUAL_TOPICS: dict[str, str] = {
    "ai": r"""\
[bold cyan]AI-POWERED EXPLANATIONS[/bold cyan]

vex can generate natural-language threat explanations using LLM providers.
The [bold]--explain[/bold] flag is strictly opt-in — it is never active by default.

[bold]SUPPORTED PROVIDERS:[/bold]
  [cyan]anthropic[/cyan]   Claude models (cloud, requires API key)
  [cyan]openai[/cyan]      GPT models (cloud, requires API key)
  [cyan]ollama[/cyan]      Local models (no API key, privacy-friendly)
  [cyan]none[/cyan]        Disabled (default) — uses template-based fallback

[bold]INSTALLATION:[/bold]
  Cloud providers:   [green]pip install vex-ioc\[ai][/green]
  Local (Ollama):    [green]pip install vex-ioc[/green]        (uses built-in httpx)
  All providers:     [green]pip install vex-ioc\[ai-all][/green]

[bold]QUICK SETUP:[/bold]
  [green]vex config --set-ai-provider anthropic[/green]
  [green]vex config --set-ai-key sk-ant-...[/green]
  [green]vex triage 44d88612fea8a8f36de82e1278abb02f --explain[/green]

[bold]CONFIGURATION (~/.vex/config.yaml):[/bold]
  ai:
    provider: anthropic           # or: openai, ollama, none
    model: claude-sonnet-4-20250514   # optional, uses provider default
    api_key: sk-...               # or set VEX_AI_API_KEY env var
    base_url: http://localhost:11434  # for Ollama only
    local_only: false             # true = block cloud providers
    max_tokens: 500
    temperature: 0.3
    cache_ttl_hours: 72

[bold]ENVIRONMENT VARIABLES:[/bold]
  [cyan]VEX_AI_API_KEY[/cyan]     AI provider API key (overrides config.yaml)
  [cyan]VEX_AI_PROVIDER[/cyan]    AI provider name (overrides config.yaml)

[bold]USAGE EXAMPLES:[/bold]
  [green]vex triage <hash> --explain[/green]
  [green]vex triage <hash> --explain --explain-model gpt-4o[/green]
  [green]vex investigate <domain> -o rich --explain[/green]

[bold]OLLAMA (LOCAL MODELS):[/bold]
  1. Install Ollama: https://ollama.com
  2. Pull a model:   [green]ollama pull llama3[/green]
  3. Configure vex:  [green]vex config --set-ai-provider ollama[/green]
  4. Run:            [green]vex triage <ioc> --explain[/green]

[bold]PRIVACY:[/bold]
  With --explain, vex sends IOC enrichment data (detection stats, verdict,
  malware families, sandbox behaviors) to the configured LLM provider.
  • Set [cyan]ai.local_only: true[/cyan] to enforce local-only processing (Ollama).
  • Without --explain, no data leaves your machine (except VT API queries).
  • IOCs are defanged in prompts for safety.

[bold]TEMPLATE FALLBACK:[/bold]
  If no AI provider is configured, --explain produces a deterministic
  template-based explanation from enrichment data. No external calls.
  This ensures --explain always produces useful output.
""",

    "config": """\
[bold cyan]CONFIGURATION REFERENCE[/bold cyan]

vex reads configuration from multiple sources (priority order):

  1. [bold]CLI flags[/bold] (--api-key, --explain-model)    [highest priority]
  2. [bold]Environment variables[/bold] (VT_API_KEY, VEX_AI_API_KEY)
  3. [bold]~/.vex/config.yaml[/bold] (user config)
  4. [bold]Default values[/bold] from Pydantic models        [lowest priority]

[bold]QUICK SETUP:[/bold]
  [green]vex config --set-api-key YOUR_VT_KEY[/green]       Save VirusTotal API key
  [green]vex config --set-ai-provider anthropic[/green]     Set AI provider
  [green]vex config --set-ai-key sk-ant-...[/green]         Save AI API key
  [green]vex config --show[/green]                          Show active configuration

[bold]CONFIG FILE LOCATION:[/bold]
  ~/.vex/config.yaml  (permissions: 0o600, directory: 0o700)

[bold]CONFIG SECTIONS:[/bold]
  api:           VT API key, tier (free/premium), rate limits
  thresholds:    malicious/suspicious detection thresholds
  cache:         SQLite cache TTL (default 24h)
  output:        Default format (json/rich/console), quiet mode
  plugins:       Plugin loading settings
  update_check:  PyPI version check interval
  ai:            AI provider, model, API key, privacy settings

[bold]ENVIRONMENT VARIABLES:[/bold]
  VT_API_KEY         VirusTotal API key
  VEX_AI_API_KEY     AI provider API key
  VEX_AI_PROVIDER    AI provider name
""",

    "examples": """\
[bold cyan]USAGE EXAMPLES[/bold cyan]

[bold]Basic triage:[/bold]
  [green]vex triage 44d88612fea8a8f36de82e1278abb02f[/green]
  [green]vex triage 8.8.8.8 -o rich[/green]
  [green]vex triage evil.com --explain[/green]

[bold]Deep investigation:[/bold]
  [green]vex investigate evil.com -o rich --timeline --explain[/green]
  [green]vex investigate <hash> --stix > bundle.json[/green]

[bold]Batch processing:[/bold]
  [green]vex triage -f iocs.txt -o rich[/green]
  [green]vex triage -f iocs.txt --csv > results.csv[/green]
  [green]vex triage -f iocs.txt --alert SUSPICIOUS --summary[/green]
  [green]cat iocs.txt | vex triage -o json[/green]

[bold]Defanged IOC support:[/bold]
  [green]vex triage "hxxps[://]evil[.]com"[/green]
  [green]vex investigate "8[.]8[.]8[.]8" --defang[/green]

[bold]Knowledge base:[/bold]
  [green]vex tag 8.8.8.8 --add dns --add google[/green]
  [green]vex note evil.com --add "Seen in phishing Q4"[/green]
  [green]vex watchlist priority --add 8.8.8.8 --list[/green]

[bold]Configuration:[/bold]
  [green]vex config --set-api-key YOUR_KEY[/green]
  [green]vex config --set-ai-provider ollama[/green]
  [green]vex config --show[/green]

[bold]Automation (exit codes):[/bold]
  [green]vex triage <ioc> && echo "clean" || echo "alert"[/green]
  Exit 0 = clean/unknown, 1 = suspicious, 2 = malicious, 3 = error
""",
}


@app.command(name="manual", help="[bold blue]Show usage guide[/bold blue] — setup, AI, config, examples.")
def cmd_manual(
    topic: Annotated[
        Optional[str],
        typer.Argument(help="Topic: ai, config, examples. Omit for overview."),
    ] = None,
) -> None:
    """Display comprehensive usage guides."""
    if topic and topic.lower() in _MANUAL_TOPICS:
        console.print(_MANUAL_TOPICS[topic.lower()])
        return

    if topic:
        console.print(f"[red]Unknown topic:[/red] '{topic}'")
        console.print()

    # Overview
    console.print("[bold cyan]VEX MANUAL[/bold cyan]")
    console.print()
    console.print(f"  vex {__version__} — VirusTotal IOC Enrichment Tool")
    console.print("  https://github.com/duathron/vex")
    console.print("  https://pypi.org/project/vex-ioc/")
    console.print()
    console.print("[bold]Available topics:[/bold]")
    console.print("  [green]vex manual ai[/green]         AI-powered explanations setup guide")
    console.print("  [green]vex manual config[/green]     Configuration reference")
    console.print("  [green]vex manual examples[/green]   Usage examples")
    console.print()
    console.print("[bold]Quick start:[/bold]")
    console.print("  [green]vex config --set-api-key YOUR_VT_KEY[/green]")
    console.print("  [green]vex triage <ioc>[/green]")
    console.print("  [green]vex investigate <domain> -o rich --explain[/green]")
    console.print()
    console.print("[dim]Part of the security portfolio: vex (IOC enrichment) + barb (phishing URL analysis)[/dim]")


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
