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
from .config import load_config, save_config
from .defang import defang as defang_ioc
from .ioc_detector import IOCType, detect
from .mitre.mapper import map_to_attack
from .models import InvestigateResult, TriageResult, Verdict
from .output.export import to_csv_triage, to_json, to_json_list, to_json_list_with_clusters, to_ndjson
from .output.formatter import (
    console,
    err_console,
    print_barb_context_console,
    print_barb_context_rich,
    print_clusters_console,
    print_clusters_rich,
    print_explanation_console,
    print_explanation_degraded_console,
    print_explanation_degraded_rich,
    print_explanation_rich,
    print_investigate_console,
    print_investigate_rich,
    print_summary,
    print_timeline_console,
    print_timeline_rich,
    print_triage_console,
    print_triage_rich,
)
from .output.html import write_html_report
from .output.stix import to_stix_bundle
from .plugins.loader import load_plugins
from .quota_tracker import QuotaTracker
from .timeline import build_timeline

# Exit code mapping (highest severity wins)
_EXIT_CODES = {0: 0, 1: 0, 2: 1, 3: 2}  # severity → exit code
# F2 cut-1 (2026-07-03 MeetUp — 2026-07-03-f2-llm-failure-posture.md): reserved
# exit code for a degraded explanation (a REQUESTED LLM provider failed).
# Distinct from the verdict codes (0/1/2) and any future CLI-usage code (3
# is unused/reserved, matching sift/barb's identical taxonomy note).
_EXIT_EXPLANATION_DEGRADED = 4


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"vex {__version__}")
        raise typer.Exit(0)


# ---------------------------------------------------------------------------
# Quota-tracker helpers (V3) — fail-open throughout
# ---------------------------------------------------------------------------


def _build_quota_tracker(config) -> Optional[QuotaTracker]:
    """Create a QuotaTracker from config.  Returns None on any error (fail-open)."""
    try:
        daily_limit = config.rate_limit.requests_per_day
        return QuotaTracker(daily_limit=daily_limit)
    except Exception:
        return None


def _quota_record(tracker: Optional[QuotaTracker]) -> None:
    """Increment the tracker for one fresh lookup.  Fail-open."""
    if tracker is None:
        return
    try:
        tracker.record_fresh_lookup()
    except Exception:
        pass


def _quota_emit(tracker: Optional[QuotaTracker]) -> None:
    """Print quota status + optional warning to stderr.  Fail-open."""
    if tracker is None:
        return
    try:
        from .output.formatter import err_console

        err_console.print(f"[dim]{tracker.status_line()}[/dim]")
        if tracker.is_near_exhaustion():
            err_console.print(
                "[yellow]WARNING:[/yellow] VT quota is nearly exhausted — "
                f"{tracker.remaining_today()} lookups remaining today."
            )
    except Exception:
        pass


app = typer.Typer(
    name="vex",
    help="VirusTotal IOC Enrichment Tool - query VT API v3 for malware analysis with optional AI-powered explanations.",
    add_completion=False,
    rich_markup_mode="rich",
    invoke_without_command=True,
    epilog="[dim]Quick start:  vex config --set-api-key YOUR_VT_KEY  |  vex triage <ioc>  |  vex triage <ioc> --explain[/dim]",  # noqa: E501
)


# ---------------------------------------------------------------------------
# App callback — banner + global options
# ---------------------------------------------------------------------------


@app.callback()
def _app_callback(
    ctx: typer.Context,
    version: Annotated[
        Optional[bool],
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version and exit."),
    ] = None,
) -> None:
    """VirusTotal IOC Enrichment Tool — query VT API v3 for malware analysis."""
    if ctx.invoked_subcommand is None:
        raise typer.Exit()


class OutputFormat(str, Enum):
    json = "json"
    rich = "rich"
    console = "console"
    ndjson = "ndjson"


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
    typer.Option("--output", "-o", help="Output format: json | rich | console | ndjson"),
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
    typer.Option(
        "--explain",
        "-e",
        help="Add AI-powered threat explanation. Providers: anthropic, openai, ollama. Falls back to template if unconfigured. See 'vex manual ai' for setup.",  # noqa: E501
    ),
]
_ExplainModelOpt = Annotated[
    Optional[str],
    typer.Option(
        "--explain-model",
        help="Override AI model (e.g. claude-sonnet-4-20250514, gpt-4o, llama3). Requires provider in ~/.vex/config.yaml.",  # noqa: E501
    ),
]
_FromBarbOpt = Annotated[
    bool,
    typer.Option(
        "--from-barb",
        help=(
            "Read barb JSON from stdin and use URLs as IOCs. "
            "Displays barb pre-scan verdict alongside VT enrichment. "
            "Usage: barb analyze <url> -o json | vex triage --from-barb. "
            "See 'vex manual pipeline'."
        ),
    ),
]
_FromSiftOpt = Annotated[
    bool,
    typer.Option(
        "--from-sift",
        help=(
            "Read sift JSON (TriageReport) from stdin and enrich the IOCs it found. "
            "Usage: sift triage alerts.json -o json | vex triage --from-sift. "
            "See 'vex manual pipeline'."
        ),
    ),
]
_NavigatorOpt = Annotated[
    bool,
    typer.Option(
        "--navigator",
        help=(
            "Export ATT&CK Navigator layer JSON to stdout (investigate only). "
            "Redirect to file: vex investigate <ioc> --navigator > layer.json"
        ),
    ),
]
_CorrelateOpt = Annotated[
    bool,
    typer.Option(
        "--correlate",
        help=(
            "Cluster batch IOCs by shared infrastructure (ASN, malware family, "
            "contacted IPs/domains, passive DNS). Batch only; no-op for single IOC."
        ),
    ),
]
_HtmlOpt = Annotated[
    Optional[str],
    typer.Option(
        "--html",
        help=(
            "Write a self-contained HTML report to this path. "
            "IOC strings are defanged in the report. "
            "Works alongside normal console/rich output."
        ),
    ),
]
_NoDedupOpt = Annotated[
    bool,
    typer.Option("--no-dedup", help="Disable IOC deduplication (default: dedup enabled)."),
]
_MaxQuotaOpt = Annotated[
    Optional[int],
    typer.Option(
        "--max-quota",
        help="Cap the number of fresh API lookups this run. Cached IOCs are always served and do not count against the quota.",  # noqa: E501
    ),
]
_SightOpt = Annotated[
    bool,
    typer.Option(
        "--sight",
        help=(
            "Write sightings/observables back to MISP + OpenCTI for IOCs at/above "
            "the write verdict floor (requires enrichment.writeback_enabled in config)."
        ),
    ),
]
_DryRunSightOpt = Annotated[
    bool,
    typer.Option(
        "--dry-run-sight",
        help="Show write payloads without sending (no network). Use with --sight for a preview.",
    ),
]


# ---------------------------------------------------------------------------
# IOC collection helpers
# ---------------------------------------------------------------------------

_MAX_IOC_LEN = 2048  # max IOC string length (URLs can be long)
_MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


def dedup_iocs(iocs: list[str]) -> tuple[list[str], int]:
    """Remove duplicate IOC strings, preserving first-seen order.

    Dedup key is the exact stripped string (no network or type detection).
    Returns (unique_list, num_removed).
    """
    seen: set[str] = set()
    unique: list[str] = []
    for ioc in iocs:
        if ioc not in seen:
            seen.add(ioc)
            unique.append(ioc)
    removed = len(iocs) - len(unique)
    return unique, removed


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
        err_console.print(
            f"[yellow]Warning:[/yellow] Invalid --alert value '{alert}'. Use CLEAN/UNKNOWN/SUSPICIOUS/MALICIOUS."
        )
        return results
    return [r for r in results if r.verdict.severity >= threshold]


def _filter_inv_by_alert(results: list[InvestigateResult], alert: Optional[str]) -> list[InvestigateResult]:
    """Keep only investigate results whose triage verdict meets the threshold."""
    if not alert:
        return results
    try:
        threshold = Verdict(alert.upper()).severity
    except ValueError:
        err_console.print(
            f"[yellow]Warning:[/yellow] Invalid --alert value '{alert}'. Use CLEAN/UNKNOWN/SUSPICIOUS/MALICIOUS."
        )
        return results
    return [r for r in results if r.triage.verdict.severity >= threshold]


def _output_triage(result: TriageResult, fmt: OutputFormat, barb_map: Optional[dict] = None) -> None:
    if fmt == OutputFormat.rich:
        print_triage_rich(result)
        if barb_map and result.ioc in barb_map:
            print_barb_context_rich(barb_map[result.ioc])
    elif fmt == OutputFormat.console:
        print_triage_console(result)
        if barb_map and result.ioc in barb_map:
            print_barb_context_console(barb_map[result.ioc])
    elif fmt == OutputFormat.ndjson:
        sys.stdout.write(to_ndjson(result) + "\n")
        sys.stdout.flush()
    else:
        print(to_json(result))


def _output_investigate(result: InvestigateResult, fmt: OutputFormat, barb_map: Optional[dict] = None) -> None:
    if fmt == OutputFormat.rich:
        print_investigate_rich(result)
        if barb_map and result.triage.ioc in barb_map:
            print_barb_context_rich(barb_map[result.triage.ioc])
    elif fmt == OutputFormat.console:
        print_investigate_console(result)
        if barb_map and result.triage.ioc in barb_map:
            print_barb_context_console(barb_map[result.triage.ioc])
    elif fmt == OutputFormat.ndjson:
        sys.stdout.write(to_ndjson(result) + "\n")
        sys.stdout.flush()
    else:
        print(to_json(result))


def _run_explain(
    results: list,
    config,
    model_override: Optional[str],
    output_fmt: OutputFormat,
) -> None:
    """Generate and display AI explanations for results.

    F2 cut-1 (2026-07-03 MeetUp — 2026-07-03-f2-llm-failure-posture.md): a
    REQUESTED LLM provider (config.ai.provider != "none") that fails must
    NEVER silently substitute template_explain() — the analyst would read a
    rule-based template believing it was an LLM explanation. Mutates each
    result's explanation/explanation_degraded/explanation_provider fields in
    place (mirrors barb's _explain(result, config) -> None). The caller
    (cmd_triage/cmd_investigate) inspects `any(r.explanation_degraded ...)`
    afterward to decide the exit code (Task 7).
    """
    from .ai import get_provider
    from .ai.cache import AICache
    from .ai.prompt import build_explain_prompt, get_system_prompt
    from .ai.template import template_explain

    if model_override:
        config.ai.model = model_override

    # A real LLM was requested iff config.ai.provider != "none" (get_provider
    # returns None only for the deliberate "none" choice). ValueError/
    # ImportError from get_provider() itself (bad key, unknown provider,
    # missing SDK, local_only violation) is ALSO a requested-provider
    # failure under F2 — it must degrade loud+marked+exit-4, not silently
    # fall back to a template as before.
    llm_requested = config.ai.provider.lower().strip() != "none"
    provider = None
    provider_setup_error: Optional[Exception] = None
    if llm_requested:
        try:
            provider = get_provider(config)
        except (ValueError, ImportError) as e:
            provider_setup_error = e

    for result in results:
        target = result.triage if isinstance(result, InvestigateResult) else result
        prompt = build_explain_prompt(result)

        if provider_setup_error is not None:
            _mark_explanation_degraded(target, config.ai.provider, provider_setup_error)
            explanation = None
            provider_name = "template"  # unused for JSON; kept for rich/console below
        elif provider:
            model_name = config.ai.model or "default"
            with AICache(config.ai.cache_ttl_hours) as cache:
                cached = cache.get(provider.name, model_name, prompt)
                if cached:
                    explanation = cached
                    err_console.print(f"[dim]AI explanation from cache ({provider.name})[/dim]")
                    target.explanation = explanation
                else:
                    try:
                        err_console.print(f"[dim]→ Generating AI explanation ({provider.name})...[/dim]")
                        explanation = provider.explain(
                            prompt,
                            system=get_system_prompt("explain"),
                            max_tokens=config.ai.max_tokens,
                            temperature=config.ai.temperature,
                        )
                        cache.set(provider.name, model_name, prompt, explanation)
                        target.explanation = explanation
                    except Exception as e:
                        _mark_explanation_degraded(target, provider.name, e)
                        explanation = None
            provider_name = provider.name if target.explanation_provider is None else "template"
        else:
            explanation = template_explain(result)
            target.explanation = explanation
            provider_name = "template"

        # Output explanation
        if output_fmt == OutputFormat.rich:
            if target.explanation_degraded:
                print_explanation_degraded_rich(target.explanation_provider or config.ai.provider)
            else:
                print_explanation_rich(explanation, provider_name)
        elif output_fmt == OutputFormat.console:
            if target.explanation_degraded:
                print_explanation_degraded_console(target.explanation_provider or config.ai.provider)
            else:
                print_explanation_console(explanation, provider_name)
        # JSON: explanation/explanation_degraded/explanation_provider are
        # already set on `target` above — model_dump() picks them up.


def _mark_explanation_degraded(target, provider_name: str, exc: Exception) -> None:
    """Set the F2 degraded marker + print the loud stderr-only notice.

    Shared by _run_explain and _run_correlation_explain. Never touches
    stdout (F2 BLOCK condition: a -o json run's stdout must stay
    json.loads-parseable).
    """
    err_console.print(f"⚠ EXPLANATION UNAVAILABLE — provider '{provider_name}' failed: {exc}")
    target.explanation = None
    target.explanation_degraded = True
    target.explanation_provider = provider_name


def _run_correlation_explain(
    clusters: list,
    config,
    model_override: Optional[str],
    output_fmt: OutputFormat,
) -> None:
    """Generate and display AI narratives for correlation clusters.

    Mirrors _run_explain but operates on Cluster objects.  Called only when
    both --correlate and --explain are active on a batch run.

    F2 cut-1 (2026-07-03 MeetUp — 2026-07-03-f2-llm-failure-posture.md): same
    degrade-loud-and-marked posture as _run_explain — a REQUESTED LLM
    provider that fails must never silently substitute template_correlation().
    """
    from .ai import get_provider
    from .ai.cache import AICache
    from .ai.prompt import build_correlation_prompt, get_system_prompt
    from .ai.template import template_correlation

    if model_override:
        config.ai.model = model_override

    llm_requested = config.ai.provider.lower().strip() != "none"
    provider = None
    provider_setup_error: Optional[Exception] = None
    if llm_requested:
        try:
            provider = get_provider(config)
        except (ValueError, ImportError) as e:
            provider_setup_error = e

    for cluster in clusters:
        prompt = build_correlation_prompt(cluster)

        if provider_setup_error is not None:
            _mark_explanation_degraded(cluster, config.ai.provider, provider_setup_error)
            narrative = None
        elif provider:
            model_name = config.ai.model or "default"
            with AICache(config.ai.cache_ttl_hours) as cache:
                cached = cache.get(provider.name, model_name, prompt)
                if cached:
                    narrative = cached
                    err_console.print(f"[dim]AI cluster narrative from cache ({provider.name})[/dim]")
                    cluster.explanation = narrative
                else:
                    try:
                        err_console.print(f"[dim]→ Generating AI cluster narrative ({provider.name})...[/dim]")
                        narrative = provider.explain(
                            prompt,
                            system=get_system_prompt("correlation"),
                            max_tokens=config.ai.max_tokens,
                            temperature=config.ai.temperature,
                        )
                        cache.set(provider.name, model_name, prompt, narrative)
                        cluster.explanation = narrative
                    except Exception as e:
                        _mark_explanation_degraded(cluster, provider.name, e)
                        narrative = None
            provider_name = provider.name if cluster.explanation_provider is None else "template"
        else:
            narrative = template_correlation(cluster)
            cluster.explanation = narrative
            provider_name = "template"

        # Render as "AI Analysis" panel per cluster, reusing print_explanation_*
        cluster_label = f"{cluster.cluster_id}: {cluster.shared_attribute}"
        if output_fmt == OutputFormat.rich:
            if cluster.explanation_degraded:
                print_explanation_degraded_rich(cluster.explanation_provider or config.ai.provider, label=cluster_label)
            else:
                if provider_name == "template":
                    title = f"[bold]Template Analysis[/bold] [dim]— {cluster_label}[/dim]"
                else:
                    title = f"[bold]AI Analysis[/bold] [dim]({provider_name}) — {cluster_label}[/dim]"
                from rich.panel import Panel

                console.print(
                    Panel(
                        narrative,
                        title=title,
                        border_style="cyan",
                        padding=(1, 2),
                    )
                )
        elif output_fmt == OutputFormat.console:
            if cluster.explanation_degraded:
                print_explanation_degraded_console(
                    cluster.explanation_provider or config.ai.provider, label=cluster_label
                )
            else:
                label = (
                    f"Template Analysis — {cluster_label}"
                    if provider_name == "template"
                    else f"AI Analysis ({provider_name}) — {cluster_label}"
                )
                console.print(f"\n{'─' * 60}")
                console.print(f"{label}:")
                console.print(f"{'─' * 60}")
                console.print(narrative)
                console.print(f"{'─' * 60}")
        # JSON: cluster.explanation/explanation_degraded/explanation_provider
        # are already set above; export handles serialisation (_cluster_to_dict).


# ---------------------------------------------------------------------------
# Subcommand: triage
# ---------------------------------------------------------------------------


@app.command(
    name="triage",
    help="[bold cyan]Fast SOC triage[/bold cyan] - detection ratio, verdict, families. Minimal API calls.",
)
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
    from_barb: _FromBarbOpt = False,
    from_sift: _FromSiftOpt = False,
    correlate: _CorrelateOpt = False,
    html: _HtmlOpt = None,
    no_dedup: _NoDedupOpt = False,
    max_quota: _MaxQuotaOpt = None,
) -> None:
    config = load_config(config_path)
    if api_key:
        config.api.key = api_key
    print_banner(
        quiet=quiet or config.output.quiet,
        update_check_enabled=config.update_check.enabled,
        check_interval_hours=config.update_check.check_interval_hours,
    )

    # --from-barb / --from-sift are mutually exclusive
    if from_barb and from_sift:
        err_console.print("[red]Error:[/red] --from-barb and --from-sift are mutually exclusive.")
        raise typer.Exit(code=1)

    # --from-barb: read barb JSON from stdin, extract URLs as IOCs
    barb_map: dict = {}
    if from_barb:
        from .pipeline.barb_bridge import parse_barb_json

        try:
            raw_barb = sys.stdin.read()
            barb_entries = parse_barb_json(raw_barb)
            if not barb_entries:
                err_console.print("[red]Error:[/red] No valid barb entries found in stdin.")
                raise typer.Exit(code=1)
            iocs = [entry.url for entry in barb_entries]
            barb_map = {entry.url: entry for entry in barb_entries}
            err_console.print(f"[dim]→ barb pipeline: {len(iocs)} URL(s) loaded[/dim]")
        except ValueError as e:
            err_console.print(f"[red]Error parsing barb JSON:[/red] {e}")
            raise typer.Exit(code=1)
    elif from_sift:
        from .pipeline.sift_bridge import extract_iocs_from_sift

        try:
            raw_sift = sys.stdin.read()
            iocs = extract_iocs_from_sift(raw_sift)
            if not iocs:
                err_console.print("[dim]No IOCs found in sift output.[/dim]")
                raise typer.Exit(code=0)
            err_console.print(f"[dim]Loaded {len(iocs)} IOCs from sift output[/dim]")
        except ValueError as e:
            err_console.print(f"[red]Error parsing sift JSON:[/red] {e}")
            raise typer.Exit(code=1)
    else:
        iocs = _collect_iocs(ioc, file)

    # Dedup IOCs (default on; use --no-dedup to disable)
    if not no_dedup:
        iocs, removed = dedup_iocs(iocs)
        if removed:
            err_console.print(
                f"[dim]Deduplicated: {len(iocs) + removed} IOCs → {len(iocs)} unique ({removed} removed)[/dim]"
            )

    try:
        config.api_key  # validate key exists before proceeding
    except ValueError as e:
        err_console.print(f"[red]{e}[/red]")
        raise typer.Exit(code=1)

    results: list[TriageResult] = []
    failed_count = 0

    if len(iocs) > 1:
        from .batch import batch_triage
        from .scheduling import count_cache_hits, estimate_eta, format_batch_summary, partition_by_cache

        # Part A: ETA line before starting the batch
        err_console.print(f"[dim]{estimate_eta(len(iocs), config)}[/dim]")

        # Part C: --max-quota partition (pre-check pass, no network). Only run when a
        # budget is set; otherwise skip the extra cache reads on the default path
        # (cache/fresh counts for Part B come from the results, not the pre-check).
        if max_quota is not None:
            with Cache(
                config.cache_db_path, config.cache.ttl_hours, config.cache.enabled and not no_cache
            ) as pre_cache:
                cached_iocs, quota_iocs, skipped_iocs = partition_by_cache(
                    iocs, pre_cache, "triage", no_cache, max_quota
                )
            batch_iocs = cached_iocs + quota_iocs
            skipped_count = len(skipped_iocs)
        else:
            batch_iocs = iocs
            skipped_count = 0
        if skipped_count:
            err_console.print(
                f"[yellow]--max-quota {max_quota} reached: {skipped_count} IOCs skipped (not enriched). "
                f"Re-run to continue.[/yellow]"
            )

        show_progress = output in (OutputFormat.rich, OutputFormat.console)
        results, failed_count = batch_triage(
            batch_iocs,
            config,
            no_cache=no_cache,
            show_progress=show_progress,
            quota_tracker=_build_quota_tracker(config),
        )

        # Part B: cache/fresh counters in the post-batch summary
        from_api, from_cache_count = count_cache_hits(results)
        err_console.print(f"[dim]{format_batch_summary(len(results), failed_count, from_api, from_cache_count)}[/dim]")
    else:
        _qt = _build_quota_tracker(config)
        with Cache(config.cache_db_path, config.cache.ttl_hours, config.cache.enabled and not no_cache) as cache:
            with load_plugins() as registry:
                for raw_ioc in iocs:
                    ioc_type, normalised_ioc = detect(raw_ioc)

                    if ioc_type == IOCType.UNKNOWN:
                        err_console.print(
                            f"[yellow]Warning:[/yellow] Cannot detect IOC type for '{raw_ioc}' - skipping."
                        )
                        failed_count += 1
                        continue

                    cache_key = f"triage:{ioc_type.value}:{normalised_ioc}"
                    cached = cache.get(cache_key)

                    if cached:
                        result = TriageResult.model_validate(cached)
                        result.from_cache = True
                    else:
                        plugin = registry.get_plugin(ioc_type.value)
                        if plugin is None:
                            err_console.print(
                                f"[yellow]Warning:[/yellow] No plugin for IOC type '{ioc_type.value}' - skipping."
                            )
                            failed_count += 1
                            continue
                        if output in (OutputFormat.rich, OutputFormat.console):
                            err_console.print(f"[dim]→ Looking up {ioc_type.value}: {normalised_ioc}[/dim]")
                        try:
                            result = plugin.triage(normalised_ioc, ioc_type.value, config)
                            cache.set(cache_key, result.model_dump(mode="json"))
                            _quota_record(_qt)
                        except Exception as e:
                            err_console.print(f"[red]Error enriching {normalised_ioc}:[/red] {type(e).__name__}")
                            failed_count += 1
                            continue

                    results.append(result)
        _quota_emit(_qt)

    if failed_count and len(iocs) <= 1:
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
        err_console.print(
            f"[dim]No IOCs matched alert threshold {alert.upper()} ({pre_filter_count} below threshold)[/dim]"
        )

    # Summary to stderr
    if summary:
        print_summary(results)

    # Correlation (batch only)
    if correlate and len(iocs) <= 1:
        err_console.print("[dim]--correlate is a no-op for a single IOC.[/dim]")

    # Build clusters once (batch correlate only) so both output and explain can use them
    triage_clusters: list = []
    if correlate and len(results) > 1:
        from .correlate import build_clusters

        triage_clusters = build_clusters(results)

    # Output results
    if stix:
        print(to_stix_bundle(results, config=config))
    elif csv:
        print(to_csv_triage(results))
    elif output == OutputFormat.ndjson:
        # NDJSON: one JSON object per line, flushed immediately
        for r in results:
            sys.stdout.write(to_ndjson(r) + "\n")
            sys.stdout.flush()
        # Emit cluster objects as additional NDJSON lines with _type discriminator
        if triage_clusters:
            import json as _json

            from .output.export import _cluster_to_dict

            for cl in triage_clusters:
                d = _cluster_to_dict(cl)
                d["_type"] = "cluster"
                sys.stdout.write(_json.dumps(d, default=str, ensure_ascii=False) + "\n")
                sys.stdout.flush()
    elif output == OutputFormat.json:
        if correlate and len(results) > 1:
            if explain:
                # Generate narratives first so explanation is included in JSON
                _run_correlation_explain(triage_clusters, config, explain_model, output)
            print(to_json_list_with_clusters(results, triage_clusters))
        elif from_barb and barb_map:
            # Generate explanations first so they're included in JSON (F2 cut-1,
            # 2026-07-03: matches the --correlate branch above — explain must run
            # before the JSON print, not after, or the marker/explanation never
            # reaches the output).
            if explain and results:
                _run_explain(results, config, explain_model, output)
            # Inject barb_context into JSON output
            import json as _json

            out = []
            for r in results:
                d = r.model_dump(mode="json")
                bc = barb_map.get(r.ioc)
                if bc:
                    d["barb_context"] = bc.model_dump(mode="json")
                out.append(d)
            print(_json.dumps(out if len(out) > 1 else out[0] if out else [], indent=2, ensure_ascii=False))
        else:
            # Generate explanations first so they're included in JSON (F2 cut-1,
            # 2026-07-03) — was previously generated AFTER this print and
            # silently discarded (a pre-existing gap found while implementing
            # F2: --explain -o json never surfaced the explanation at all for
            # a non-correlate run).
            if explain and results:
                _run_explain(results, config, explain_model, output)
            print(to_json_list(results) if len(results) > 1 else to_json(results[0]) if results else "[]")
    else:
        for r in results:
            _output_triage(r, output, barb_map=barb_map)
        if triage_clusters:
            if output == OutputFormat.rich:
                print_clusters_rich(triage_clusters)
            else:
                print_clusters_console(triage_clusters)

    # AI explanation (opt-in). F2 cut-1 (2026-07-03): the OutputFormat.json
    # case is now handled entirely inside the `elif output == OutputFormat.json:`
    # block above (Step 1) — skip here to avoid calling _run_explain twice
    # (which would double the LLM API cost and double-append cache writes).
    if explain and results and output != OutputFormat.json:
        if triage_clusters and output != OutputFormat.ndjson:
            # Narratives per cluster (--correlate + --explain, non-JSON/ndjson path)
            _run_correlation_explain(triage_clusters, config, explain_model, output)
        else:
            # Per-result explain (--explain without --correlate)
            if not (correlate and len(results) > 1):
                _run_explain(results, config, explain_model, output)

    # HTML report (opt-in, additive)
    if html:
        write_html_report(html, results, mode="triage")
        console.print(f"[green]HTML report written to {html}[/green]")

    # F2 cut-1 (2026-07-03 MeetUp — 2026-07-03-f2-llm-failure-posture.md):
    # a degraded explanation (a REQUESTED LLM provider failed) exits with the
    # reserved code 4, taking PRIORITY over the severity-based exit code
    # computed above (_EXIT_CODES) — a degraded run always needs operator
    # attention regardless of the underlying verdict severity, mirroring
    # sift's TriageReport.exit_code property and barb's pre-verdict-exit
    # check in cmd analyze(). The verdict/triage output itself (vex's primary
    # output) is unaffected — it already printed/rendered above.
    if any(r.explanation_degraded for r in results) or any(c.explanation_degraded for c in triage_clusters):
        raise typer.Exit(code=_EXIT_EXPLANATION_DEGRADED)

    raise typer.Exit(code=exit_code)


# ---------------------------------------------------------------------------
# Subcommand: investigate
# ---------------------------------------------------------------------------


@app.command(
    name="investigate",
    help="[bold magenta]Deep DFIR investigation[/bold magenta] - PE info, sandbox, passive DNS, relationships.",
)
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
    from_barb: _FromBarbOpt = False,
    from_sift: _FromSiftOpt = False,
    navigator: _NavigatorOpt = False,
    correlate: _CorrelateOpt = False,
    html: _HtmlOpt = None,
    no_dedup: _NoDedupOpt = False,
    max_quota: _MaxQuotaOpt = None,
    sight: _SightOpt = False,
    dry_run_sight: _DryRunSightOpt = False,
) -> None:
    config = load_config(config_path)
    if api_key:
        config.api.key = api_key
    print_banner(
        quiet=quiet or config.output.quiet,
        update_check_enabled=config.update_check.enabled,
        check_interval_hours=config.update_check.check_interval_hours,
    )

    # --from-barb / --from-sift are mutually exclusive
    if from_barb and from_sift:
        err_console.print("[red]Error:[/red] --from-barb and --from-sift are mutually exclusive.")
        raise typer.Exit(code=1)

    # --from-barb: read barb JSON from stdin, extract URLs as IOCs
    barb_map: dict = {}
    if from_barb:
        from .pipeline.barb_bridge import parse_barb_json

        try:
            raw_barb = sys.stdin.read()
            barb_entries = parse_barb_json(raw_barb)
            if not barb_entries:
                err_console.print("[red]Error:[/red] No valid barb entries found in stdin.")
                raise typer.Exit(code=1)
            iocs = [entry.url for entry in barb_entries]
            barb_map = {entry.url: entry for entry in barb_entries}
            err_console.print(f"[dim]→ barb pipeline: {len(iocs)} URL(s) loaded[/dim]")
        except ValueError as e:
            err_console.print(f"[red]Error parsing barb JSON:[/red] {e}")
            raise typer.Exit(code=1)
    elif from_sift:
        from .pipeline.sift_bridge import extract_iocs_from_sift

        try:
            raw_sift = sys.stdin.read()
            iocs = extract_iocs_from_sift(raw_sift)
            if not iocs:
                err_console.print("[dim]No IOCs found in sift output.[/dim]")
                raise typer.Exit(code=0)
            err_console.print(f"[dim]Loaded {len(iocs)} IOCs from sift output[/dim]")
        except ValueError as e:
            err_console.print(f"[red]Error parsing sift JSON:[/red] {e}")
            raise typer.Exit(code=1)
    else:
        iocs = _collect_iocs(ioc, file)

    # Dedup IOCs (default on; use --no-dedup to disable)
    if not no_dedup:
        iocs, removed = dedup_iocs(iocs)
        if removed:
            err_console.print(
                f"[dim]Deduplicated: {len(iocs) + removed} IOCs → {len(iocs)} unique ({removed} removed)[/dim]"
            )

    try:
        config.api_key  # validate key exists before proceeding
    except ValueError as e:
        err_console.print(f"[red]{e}[/red]")
        raise typer.Exit(code=1)

    results: list[InvestigateResult] = []
    failed_count = 0

    if len(iocs) > 1:
        from .batch import batch_investigate
        from .scheduling import count_cache_hits, estimate_eta, format_batch_summary, partition_by_cache

        # Part A: ETA line before starting the batch
        err_console.print(f"[dim]{estimate_eta(len(iocs), config)}[/dim]")

        # Part C: --max-quota partition (pre-check pass, no network). Only run when a
        # budget is set; otherwise skip the extra cache reads on the default path
        # (cache/fresh counts for Part B come from the results, not the pre-check).
        if max_quota is not None:
            with Cache(
                config.cache_db_path, config.cache.ttl_hours, config.cache.enabled and not no_cache
            ) as pre_cache:
                cached_iocs, quota_iocs, skipped_iocs = partition_by_cache(
                    iocs, pre_cache, "investigate", no_cache, max_quota
                )
            batch_iocs = cached_iocs + quota_iocs
            skipped_count = len(skipped_iocs)
        else:
            batch_iocs = iocs
            skipped_count = 0
        if skipped_count:
            err_console.print(
                f"[yellow]--max-quota {max_quota} reached: {skipped_count} IOCs skipped (not enriched). "
                f"Re-run to continue.[/yellow]"
            )

        show_progress = output in (OutputFormat.rich, OutputFormat.console)
        results, failed_count = batch_investigate(batch_iocs, config, no_cache=no_cache, show_progress=show_progress)

        # Part B: cache/fresh counters in the post-batch summary
        from_api, from_cache_count = count_cache_hits(results)
        err_console.print(f"[dim]{format_batch_summary(len(results), failed_count, from_api, from_cache_count)}[/dim]")
    else:
        with Cache(config.cache_db_path, config.cache.ttl_hours, config.cache.enabled and not no_cache) as cache:
            with load_plugins() as registry:
                for raw_ioc in iocs:
                    ioc_type, normalised_ioc = detect(raw_ioc)

                    if ioc_type == IOCType.UNKNOWN:
                        err_console.print(
                            f"[yellow]Warning:[/yellow] Cannot detect IOC type for '{raw_ioc}' - skipping."
                        )
                        failed_count += 1
                        continue

                    cache_key = f"investigate:{ioc_type.value}:{normalised_ioc}"
                    cached = cache.get(cache_key)

                    if cached:
                        result = InvestigateResult.model_validate(cached)
                        result.triage.from_cache = True
                    else:
                        plugin = registry.get_plugin(ioc_type.value)
                        if plugin is None:
                            err_console.print(
                                f"[yellow]Warning:[/yellow] No plugin for IOC type '{ioc_type.value}' - skipping."
                            )
                            failed_count += 1
                            continue
                        if output in (OutputFormat.rich, OutputFormat.console):
                            err_console.print(f"[dim]→ Investigating {ioc_type.value}: {normalised_ioc}[/dim]")
                        try:
                            result = plugin.investigate(normalised_ioc, ioc_type.value, config)
                            # MITRE ATT&CK mapping
                            result.attack_mappings = map_to_attack(result)
                            # Secondary enrichers — run in parallel, fail-open per enricher
                            from .batch import run_secondary_enrichers  # noqa: PLC0415

                            run_secondary_enrichers(
                                result,
                                normalised_ioc,
                                ioc_type.value,
                                config,
                                registry.get_secondary(ioc_type.value),
                            )
                            cache.set(cache_key, result.model_dump(mode="json"))
                        except Exception as e:
                            err_console.print(f"[red]Error investigating {normalised_ioc}:[/red] {type(e).__name__}")
                            failed_count += 1
                            continue

                    results.append(result)

    if failed_count and len(iocs) <= 1:
        err_console.print(f"[yellow]{len(results)} processed, {failed_count} failed (see errors above)[/yellow]")

    # Apply defanging if requested
    if do_defang:
        results = [_maybe_defang_inv(r, True) for r in results]

    # Compute exit code from highest severity BEFORE filtering
    exit_code = _EXIT_CODES.get(max((r.triage.verdict.severity for r in results), default=0), 0)

    # Write-back (opt-in: --sight or --dry-run-sight + enrichment.writeback_enabled)
    _run_writeback(results, config, sight=sight, dry_run_sight=dry_run_sight)

    # Filter by alert threshold
    pre_filter_count = len(results)
    results = _filter_inv_by_alert(results, alert)
    if alert and not results and pre_filter_count > 0:
        err_console.print(
            f"[dim]No IOCs matched alert threshold {alert.upper()} ({pre_filter_count} below threshold)[/dim]"
        )

    # Summary to stderr
    if summary:
        print_summary([r.triage for r in results])

    # Correlation (batch only)
    if correlate and len(iocs) <= 1:
        err_console.print("[dim]--correlate is a no-op for a single IOC.[/dim]")

    # ATT&CK Navigator export (exclusive — skips all other output)
    if navigator:
        from .output.navigator import to_navigator_layer

        sys.stdout.write(to_navigator_layer(results, ioc=iocs[0] if iocs else None))
        sys.stdout.write("\n")
        raise typer.Exit(code=exit_code)

    # Build clusters once (batch correlate only) so both output and explain can use them
    inv_clusters: list = []
    if correlate and len(results) > 1:
        from .correlate import build_clusters

        inv_clusters = build_clusters(results)

    # Output results
    if stix:
        print(to_stix_bundle(results, config=config))
    elif output == OutputFormat.ndjson:
        # NDJSON: one JSON object per line, flushed immediately
        for r in results:
            sys.stdout.write(to_ndjson(r) + "\n")
            sys.stdout.flush()
        # Emit cluster objects as additional NDJSON lines with _type discriminator
        if inv_clusters:
            import json as _json

            from .output.export import _cluster_to_dict

            for cl in inv_clusters:
                d = _cluster_to_dict(cl)
                d["_type"] = "cluster"
                sys.stdout.write(_json.dumps(d, default=str, ensure_ascii=False) + "\n")
                sys.stdout.flush()
    elif output == OutputFormat.json:
        if correlate and len(results) > 1:
            if explain:
                # Generate narratives first so explanation is included in JSON
                _run_correlation_explain(inv_clusters, config, explain_model, output)
            print(to_json_list_with_clusters(results, inv_clusters))
        else:
            # Generate explanations first so they're included in JSON (F2 cut-1,
            # 2026-07-03) — see cmd_triage's identical fix for the full rationale.
            if explain and results:
                _run_explain(results, config, explain_model, output)
            print(to_json_list(results) if len(results) > 1 else to_json(results[0]) if results else "[]")
    else:
        for r in results:
            _output_investigate(r, output, barb_map=barb_map)
        if inv_clusters:
            if output == OutputFormat.rich:
                print_clusters_rich(inv_clusters)
            else:
                print_clusters_console(inv_clusters)

    # Timeline (appended after main output)
    if timeline:
        for r in results:
            tl = build_timeline(r)
            if output == OutputFormat.rich:
                print_timeline_rich(tl)
            else:
                print_timeline_console(tl)

    # AI explanation (opt-in). F2 cut-1 (2026-07-03): see cmd_triage's
    # identical guard — the OutputFormat.json case is handled above.
    if explain and results and output != OutputFormat.json:
        if inv_clusters and output != OutputFormat.ndjson:
            # Narratives per cluster (--correlate + --explain, non-JSON/ndjson path)
            _run_correlation_explain(inv_clusters, config, explain_model, output)
        else:
            # Per-result explain (--explain without --correlate)
            if not (correlate and len(results) > 1):
                _run_explain(results, config, explain_model, output)

    # HTML report (opt-in, additive)
    if html:
        write_html_report(html, results, mode="investigate")
        console.print(f"[green]HTML report written to {html}[/green]")

    # F2 cut-1 (2026-07-03 MeetUp): see cmd_triage's identical check.
    if any(r.triage.explanation_degraded for r in results) or any(c.explanation_degraded for c in inv_clusters):
        raise typer.Exit(code=_EXIT_EXPLANATION_DEGRADED)

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


@app.command(
    name="addons", help="[bold green]Show available addons[/bold green] — AI providers, extras, installation status."
)
def cmd_addons() -> None:
    """Display all optional vex addons and their installation status."""
    from rich import box
    from rich.table import Table

    from .addons import get_addon_status

    addons = get_addon_status()
    t = Table(title="vex addons", box=box.ROUNDED)
    t.add_column("Package", style="cyan", no_wrap=True)
    t.add_column("Group", style="dim", no_wrap=True)
    t.add_column("Status", no_wrap=True)
    t.add_column("Description")
    t.add_column("Install", style="dim")

    for a in addons:
        if a.installed:
            ver = f" [dim]{a.version}[/dim]" if a.version else ""
            status = f"[green]✓ installed[/green]{ver}"
            install = "[dim]—[/dim]"
        else:
            status = "[dim]not installed[/dim]"
            install = a.install_cmd

        t.add_row(a.name, a.group, status, a.description, install)

    console.print(t)
    console.print()
    console.print("[dim]AI explanations (--explain): requires anthropic or openai addon.[/dim]")
    console.print("[dim]WHOIS enrichment: included in base install.[/dim]")
    console.print("[dim]barb pipeline (--from-barb): requires 'pip install barb-phish'.[/dim]")


@app.command(
    name="doctor",
    help=(
        "[bold green]Diagnose enricher/service config + connectivity[/bold green] — "
        "surfaces silently-failing enrichers. Config-only by default; "
        "use --probe to test live connectivity."
    ),
)
def cmd_doctor(
    config_path: _ConfigOpt = None,
    probe: Annotated[
        bool,
        typer.Option(
            "--probe",
            help="Test live connectivity (network). Default off: config-only, no network.",
        ),
    ] = False,
    output: Annotated[
        str,
        typer.Option("--output", "-o", help="Output format: rich (default) | json"),
    ] = "rich",
) -> None:
    """Report whether each external service is configured and (optionally) reachable."""
    import json as _json

    from rich import box
    from rich.table import Table

    from .doctor import run_doctor

    config = load_config(config_path)
    statuses = run_doctor(config, probe=probe)

    if output.lower() == "json":
        console.print(_json.dumps([s.model_dump() for s in statuses], indent=2))
        return

    def _bool_mark(value: Optional[bool]) -> str:
        if value is None:
            return "[dim]—[/dim]"
        return "[green]✓[/green]" if value else "[red]✗[/red]"

    t = Table(
        title="vex doctor" + (" (--probe)" if probe else " (config-only)"),
        box=box.ROUNDED,
    )
    t.add_column("Service", style="cyan", no_wrap=True)
    t.add_column("Configured", justify="center", no_wrap=True)
    t.add_column("Reachable", justify="center", no_wrap=True)
    t.add_column("Detail")

    for s in statuses:
        t.add_row(
            s.name,
            _bool_mark(s.configured),
            _bool_mark(s.reachable),
            s.detail,
        )

    console.print(t)
    console.print()
    if not probe:
        console.print("[dim]Config-only check (no network). Run 'vex doctor --probe' to test live connectivity.[/dim]")


@app.command(
    name="config", help="[bold blue]Manage configuration[/bold blue] - save API key, AI provider, show settings."
)
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
            console.print(
                "[yellow]Note:[/yellow] Set the AI API key with [bold]--set-ai-key[/bold] or [bold]VEX_AI_API_KEY[/bold] env var."  # noqa: E501
            )
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

    from rich import box
    from rich.table import Table

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
    t.add_row(
        "api.rate_limit",
        f"{config.rate_limit.requests_per_minute} req/min, {config.rate_limit.requests_per_day} req/day",
    )

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

    # Enrichment
    t.add_row("enrichment.whois_enabled", str(config.enrichment.whois_enabled))
    t.add_row("enrichment.abuseipdb_api_key", mask(config.abuseipdb_api_key))
    t.add_row("enrichment.abuseipdb_max_age_days", str(config.enrichment.abuseipdb_max_age_days))
    t.add_row("enrichment.shodan_api_key", mask(config.shodan_api_key))
    t.add_row("enrichment.misp_url", config.misp_url or "[dim]not set[/dim]")
    t.add_row("enrichment.misp_api_key", mask(config.misp_api_key))
    t.add_row("enrichment.misp_verify_tls", str(config.enrichment.misp_verify_tls))
    t.add_row("enrichment.opencti_url", config.opencti_url or "[dim]not set[/dim]")
    t.add_row("enrichment.opencti_token", mask(config.opencti_token))
    t.add_row("enrichment.opencti_verify_tls", str(config.enrichment.opencti_verify_tls))

    console.print(t)

    # Addon status
    from .addons import get_addon_status

    addons = get_addon_status()
    addon_t = Table(title="Addons", box=box.ROUNDED)
    addon_t.add_column("Package", style="cyan")
    addon_t.add_column("Group", style="dim")
    addon_t.add_column("Status")
    addon_t.add_column("Description")
    for a in addons:
        if a.installed:
            status = "[green]✓ installed[/green]" + (f" [dim]{a.version}[/dim]" if a.version else "")
        else:
            status = f"[dim]not installed[/dim]  [dim]{a.install_cmd}[/dim]"
        addon_t.add_row(a.name, a.group, status, a.description)
    console.print(addon_t)

    # Hints
    if config.ai.provider == "none":
        console.print()
        console.print("[dim]Hint: AI explanations not configured. Run 'vex manual ai' for setup instructions.[/dim]")


# ---------------------------------------------------------------------------
# Write-back helper
# ---------------------------------------------------------------------------


def _run_writeback(
    results: list[InvestigateResult],
    config,
    *,
    sight: bool,
    dry_run_sight: bool,
) -> None:
    """Write sightings/observables back to MISP + OpenCTI.

    Called from cmd_investigate after results are built and exit_code computed.

    Triple opt-in:
      1. enrichment.writeback_enabled must be True in config.
      2. --sight flag must be passed.
      3. Optionally --dry-run-sight for a preview without network.

    The verdict floor (enrichment.writeback_min_verdict) controls which IOCs
    qualify. The TLP ceiling (enrichment.writeback_tlp) blocks data that would
    upgrade the classification of what is already known on each platform.
    """
    from .tlp import _tlp_rank  # noqa: PLC0415

    if not sight and not dry_run_sight:
        return

    if sight and not config.enrichment.writeback_enabled:
        err_console.print(
            "[yellow]Warning:[/yellow] --sight given but enrichment.writeback_enabled is false "
            "— enable it in config to write."
        )
        return

    # Parse verdict floor
    try:
        floor_severity = Verdict[config.enrichment.writeback_min_verdict].severity
    except KeyError:
        err_console.print(
            f"[yellow]Warning:[/yellow] Invalid writeback_min_verdict "
            f"'{config.enrichment.writeback_min_verdict}', defaulting to SUSPICIOUS."
        )
        floor_severity = Verdict.SUSPICIOUS.severity

    for result in results:
        if result.triage.verdict.severity < floor_severity:
            continue

        ioc = result.triage.ioc
        ioc_type = result.triage.ioc_type

        # Build source_tlp from the most-restrictive TLP known for this IOC
        # misp_tlp and opencti_tlp are stored uppercase (e.g. "AMBER"); _tlp_rank expects lowercase
        raw_tlps = [t.lower() for t in [result.misp_tlp, result.opencti_tlp] if t]
        source_tlp: str | None = min(raw_tlps, key=_tlp_rank) if raw_tlps else None

        if dry_run_sight:
            err_console.print(
                f"[dim][dry-run-sight] would write: ioc={ioc} type={ioc_type} "
                f"source_tlp={source_tlp or 'none'} "
                f"ceiling={config.enrichment.writeback_tlp}[/dim]"
            )
            # Fields stay None — not attempted
            continue

        # MISP sighting
        from .plugins.misp import MISPEnricher  # noqa: PLC0415

        misp_ok = MISPEnricher().add_sighting(ioc, config, source_tlp=source_tlp)
        result.writeback_misp = misp_ok
        status = "ok" if misp_ok else "failed/skipped"
        err_console.print(f"[dim]sighting → MISP {status}: {ioc}[/dim]")

        # OpenCTI observable
        from .plugins.opencti import OpenCTIEnricher  # noqa: PLC0415

        opencti_ok = OpenCTIEnricher().add_observable(ioc, ioc_type, config, source_tlp=source_tlp)
        result.writeback_opencti = opencti_ok
        status = "ok" if opencti_ok else "failed/skipped"
        err_console.print(f"[dim]observable → OpenCTI {status}: {ioc}[/dim]")


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
  If no AI provider is configured (ai.provider: none, the default),
  --explain produces a deterministic template-based explanation from
  enrichment data. No external calls.

[bold]LLM FAILURE POSTURE:[/bold]
  If a provider IS configured (anthropic/openai/ollama) and it fails,
  vex does NOT silently fall back to a template. The verdict/enrichment
  output still completes; the explanation is left unavailable
  (JSON: "explanation": null, "explanation_degraded": true,
  "explanation_provider": "<name>"), a loud warning is printed to
  stderr, and vex exits with code 4 (distinct from the verdict codes
  0/1/2). This is deliberate: an explicitly configured provider that
  fails should never be silently masked by a template the analyst
  might mistake for a real LLM explanation.
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
  [green]vex investigate evil.com --navigator > layer.json[/green]

[bold]Batch processing:[/bold]
  [green]vex triage -f iocs.txt -o rich[/green]
  [green]vex triage -f iocs.txt --csv > results.csv[/green]
  [green]vex triage -f iocs.txt --alert SUSPICIOUS --summary[/green]
  [green]cat iocs.txt | vex triage -o json[/green]

[bold]barb pipeline:[/bold]
  [green]barb analyze https://evil.com -o json | vex triage --from-barb -o rich[/green]
  [green]barb analyze https://evil.com -o json | vex investigate --from-barb -o rich[/green]

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
    "pipeline": r"""\
[bold cyan]vex PIPELINE — barb → vex → sift[/bold cyan]

vex is the enrichment hub. Upstream, [bold]barb[/bold] (heuristic phishing URL
analyzer) feeds URLs in; downstream, [bold]sift[/bold] (alert triage summarizer)
consumes vex output AND feeds the IOCs it found back for enrichment — the
[bold]sift ↔ vex loop[/bold]. Each direction has a bridge flag ([cyan]--from-barb[/cyan] /
[cyan]--from-sift[/cyan], mutually exclusive). Both read JSON from stdin.

[bold]WHAT IS barb?[/bold]
  barb is a CLI tool for offline heuristic phishing URL analysis.
  It runs 8 analyzers (entropy, homoglyphs, brand squatting, etc.)
  and produces a verdict (SAFE/LOW_RISK/SUSPICIOUS/HIGH_RISK/PHISHING)
  with a risk score — without making any HTTP requests to the target URL.
  Install: [green]pip install barb-phish[/green]   |   GitHub: https://github.com/duathron/barb

[bold]HOW THE PIPELINE WORKS:[/bold]
  1. barb analyzes the URL heuristically (offline, instant)
  2. barb outputs JSON with verdict, risk_score, and signal breakdown
  3. vex reads the barb JSON, extracts URLs as IOCs
  4. vex queries VirusTotal for live enrichment
  5. vex displays both barb pre-scan context AND VT results side-by-side

[bold]USAGE:[/bold]
  [green]barb analyze https://evil.com -o json | vex triage --from-barb[/green]
  [green]barb analyze https://evil.com -o json | vex triage --from-barb -o rich[/green]
  [green]barb analyze https://evil.com -o json | vex investigate --from-barb -o rich[/green]
  [green]barb analyze https://evil.com -o json | vex triage --from-barb -o json[/green]

  Batch (multiple URLs from a file via barb):
  [green]barb analyze -f urls.txt -o json | vex triage --from-barb --alert SUSPICIOUS[/green]

[bold]OUTPUT:[/bold]
  Rich/console: barb pre-scan panel shown alongside VT enrichment result.
  JSON: result includes a [cyan]"barb_context"[/cyan] field with verdict, risk_score, signals.

[bold]BARB VERDICT LEVELS:[/bold]
  [green]SAFE[/green]          No heuristic indicators
  [cyan]LOW_RISK[/cyan]      Minor indicators, likely benign
  [yellow]SUSPICIOUS[/yellow]    Moderate risk signals
  [dark_orange]HIGH_RISK[/dark_orange]     Strong phishing indicators
  [red]PHISHING[/red]      Confirmed phishing pattern

[bold cyan]sift → vex  (--from-sift)[/bold cyan]
[bold]WHAT IS sift?[/bold]
  sift is a SOC alert-triage summarizer: it ingests SIEM alerts, clusters
  and prioritizes them, and extracts the IOCs they contain.
  Install: [green]pip install sift-triage[/green]   |   GitHub: https://github.com/duathron/sift

[bold]HOW IT WORKS:[/bold]
  1. sift triages alerts and emits a JSON TriageReport (clusters + IOCs)
  2. [cyan]--from-sift[/cyan] reads that report from stdin and pulls every IOC it found
     (cluster IOCs, alert IOCs, source/dest IPs) — deduplicated
  3. vex enriches each IOC; pipe the result (e.g. NDJSON) back into your
     workflow — closing the sift <-> vex loop

[bold]USAGE:[/bold]
  [green]sift triage alerts.json -o json | vex triage --from-sift[/green]
  [green]sift triage alerts.json -o json | vex triage --from-sift -o ndjson[/green]   # stream enriched IOCs onward
  [green]sift triage alerts.json -o json | vex investigate --from-sift -o rich[/green]

[bold]WHY USE BOTH TOOLS?[/bold]
  barb is instant and offline — no API calls, no rate limits.
  Use it to pre-screen large batches before spending VT API quota.
  vex then provides ground truth with live VT detection data.
  sift turns a flood of alerts into prioritized clusters, and --from-sift
  enriches the IOCs inside them in one pass.
""",
    "addons": r"""\
[bold cyan]ADDONS & EXTRAS[/bold cyan]

vex ships with a small core (VirusTotal enrichment, WHOIS, MITRE ATT&CK,
STIX 2.1, barb pipeline). Optional extras enable additional capabilities.

[bold]RUN 'vex addons' TO SEE CURRENT STATUS[/bold]

[bold]OPTIONAL EXTRAS:[/bold]

  [cyan]AI explanations[/cyan]  (extras group: ai)
    Adds --explain flag: generate threat narratives via Claude, GPT, or Ollama.
    Install cloud providers:  [green]pip install vex-ioc\[ai][/green]
    Local (Ollama):           no extras needed (uses built-in httpx)
    Setup:                    [green]vex config --set-ai-provider anthropic[/green]
    Docs:                     [green]vex manual ai[/green]

[bold]INCLUDED IN BASE INSTALL (no extras needed):[/bold]

  [cyan]WHOIS enrichment[/cyan]  (python-whois, core dep since v1.2.0)
    Direct WHOIS lookups for domain IOCs (supplements VT premium WHOIS).
    Works automatically in 'vex investigate' for domain IOCs.
    Toggle: [green]enrichment.whois_enabled: true/false[/green] in ~/.vex/config.yaml

  [cyan]barb pipeline[/cyan]  (requires barb-phish)
    Pipe barb heuristic output into vex for combined analysis.
    Install barb:  [green]pip install barb-phish[/green]
    Usage:         [green]barb analyze <url> -o json | vex triage --from-barb[/green]
    Docs:          [green]vex manual pipeline[/green]

[bold]INSTALL ON KALI/DEBIAN (system Python):[/bold]
  Use [bold]pipx[/bold] to avoid system package conflicts:
    [green]sudo apt install pipx && pipx ensurepath[/green]
    [green]pipx install vex-ioc[/green]
    [green]pipx install "vex-ioc\[ai]"[/green]

[bold]CHECKING ADDON STATUS:[/bold]
  [green]vex addons[/green]          List all addons and installation status
  [green]vex config --show[/green]   Full config + addon status overview
""",
    "writeback": """\
[bold cyan]TI WRITE-BACK — MISP sightings + OpenCTI observables[/bold cyan]

vex can write sightings back to MISP and create observables in OpenCTI for
IOCs that meet a configurable verdict floor. This is strictly opt-in — three
separate gates must all be open before any write occurs.

[bold]TRIPLE OPT-IN GATES:[/bold]
  1. [cyan]enrichment.writeback_enabled: true[/cyan] in config (default false)
  2. [bold]--sight[/bold] flag passed to [bold]vex investigate[/bold]
  3. Alternatively: [bold]--dry-run-sight[/bold] for a preview (no network)

[bold]VERDICT FLOOR:[/bold]
  Only IOCs at or above [cyan]enrichment.writeback_min_verdict[/cyan] are written.
  Default: [bold]SUSPICIOUS[/bold]. Valid values: CLEAN, UNKNOWN, SUSPICIOUS, MALICIOUS.
  IOCs below the floor are silently skipped.

[bold]TLP MARKING-CHECK (cross-platform leak protection):[/bold]
  Before each write, vex compares the source IOC's most-restrictive known TLP
  (from MISP and OpenCTI enrichment) against [cyan]enrichment.writeback_tlp[/cyan] (the ceiling).
  If the source TLP is MORE restrictive than the ceiling the write is SKIPPED.

  Example: IOC was enriched with TLP:RED from MISP.
    writeback_tlp = "green" → rank(red)=0 < rank(green)=2 → SKIP.
    writeback_tlp = "red"   → rank(red)=0 < rank(red)=0 is False → ALLOW.

  This prevents accidentally pushing RED-marked data from one platform to another.

[bold]FAIL-OPEN:[/bold]
  A write failure (network error, HTTP non-200, GraphQL error) never crashes the
  run or blocks other output. It logs at DEBUG and sets the field to False.

[bold]OPENCTI MUTATION NOTE (OPERATOR MUST VERIFY):[/bold]
  The mutation used is:
    mutation AddObservable($type: String!, $value: String!) {
      stixCyberObservableAdd(type: $type, observableData: { value: $value }) { id }
    }
  For network observables (IPv4, domain, URL) this works on OpenCTI >= 5.x.
  For file hashes (StixFile), some versions require {hashes: {MD5: ...}}.
  Verify against your instance before relying on hash write-back.

[bold]CONFIGURATION (~/.vex/config.yaml):[/bold]
  enrichment:
    writeback_enabled: true        # master switch
    writeback_tlp: "green"         # TLP ceiling for writes
    writeback_min_verdict: "SUSPICIOUS"  # floor (CLEAN/UNKNOWN/SUSPICIOUS/MALICIOUS)
    # MISP and OpenCTI credentials also required (see 'vex manual config')

[bold]USAGE:[/bold]
  [green]vex investigate 1.2.3.4 --dry-run-sight[/green]    # preview, no network
  [green]vex investigate 1.2.3.4 --sight[/green]            # write if enabled
  [green]vex investigate -f iocs.txt --sight[/green]        # batch write-back

[bold]RESULT FIELDS:[/bold]
  writeback_misp:    null (not attempted) | true (written) | false (failed/skipped)
  writeback_opencti: null (not attempted) | true (written) | false (failed/skipped)
""",
}


@app.command(
    name="manual", help="[bold blue]Show usage guide[/bold blue] — setup, AI, config, addons, pipeline, examples."
)
def cmd_manual(
    topic: Annotated[
        Optional[str],
        typer.Argument(help="Topic: ai, config, examples, pipeline, addons. Omit for overview."),
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
    console.print("  [green]vex manual pipeline[/green]   barb → vex pipeline integration")
    console.print("  [green]vex manual addons[/green]     Optional extras and installation")
    console.print("  [green]vex manual writeback[/green]  TI write-back (MISP sightings + OpenCTI observables)")
    console.print()
    console.print("[bold]Quick start:[/bold]")
    console.print("  [green]vex config --set-api-key YOUR_VT_KEY[/green]")
    console.print("  [green]vex triage <ioc>[/green]")
    console.print("  [green]vex investigate <domain> -o rich --explain[/green]")
    console.print()
    console.print("[dim]Part of the security portfolio: vex (IOC enrichment) + barb (phishing URL analysis)[/dim]")
    console.print("[dim]Pipeline: barb analyze <url> -o json | vex triage --from-barb -o rich[/dim]")


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


# ---------------------------------------------------------------------------
# Watchlist sub-app  (V2: adds `vex watchlist run <name>`)
# ---------------------------------------------------------------------------

from .knowledge.db import KnowledgeDB  # noqa: E402
from .watchlist_runner import WatchlistRunResult, retriage_watchlist  # noqa: E402


class _WatchlistGroup(typer.core.TyperGroup):
    """Custom TyperGroup that routes unknown positional args to the callback.

    Typer/Click normally treats the first positional arg after group options as
    a required subcommand name.  This subclass intercepts ``parse_args`` and,
    when the first positional is NOT a registered subcommand, clears the
    ``_protected_args`` slot so Click takes the ``invoke_without_command`` path
    and lets the callback handle all remaining args via ``ctx.args``.
    """

    def parse_args(self, ctx: typer.Context, args: list[str]) -> list[str]:  # type: ignore[override]
        # Scan for the first non-option token to see if it's a known command.
        i = 0
        while i < len(args):
            token = args[i]
            if token == "--":
                break
            if token.startswith("-"):
                i += 1  # skip option flag; value (if any) is the next token
                continue
            # First positional found.
            if token not in self.commands:
                # Not a known subcommand — run parent parser then route to callback.
                result = super().parse_args(ctx, args)
                if ctx._protected_args:  # type: ignore[attr-defined]
                    ctx.args = ctx._protected_args + list(ctx.args)  # type: ignore[attr-defined]
                    ctx._protected_args = []  # type: ignore[attr-defined]
                return result
            break  # noqa: SIM105 — unreachable i += 1 removed intentionally
        return super().parse_args(ctx, args)


def _run_watchlist_manage(name: str, args: list[str]) -> None:
    """Shared manage logic used by both the flat callback and `manage` alias."""
    add_iocs: list[str] = []
    remove_iocs: list[str] = []
    show = False

    i = 0
    while i < len(args):
        tok = args[i]
        if tok in ("--add", "-a"):
            i += 1
            if i < len(args):
                add_iocs.append(args[i])
        elif tok in ("--remove", "-r"):
            i += 1
            if i < len(args):
                remove_iocs.append(args[i])
        elif tok in ("--list", "-l"):
            show = True
        i += 1

    with KnowledgeDB() as db:
        if add_iocs:
            for ioc in add_iocs:
                db.add_to_watchlist(name, ioc)
                console.print(f"[green]+[/green] Added [bold]{ioc}[/bold] to watchlist [cyan]{name}[/cyan]")
        if remove_iocs:
            for ioc in remove_iocs:
                db.remove_from_watchlist(name, ioc)
                console.print(f"[red]-[/red] Removed [bold]{ioc}[/bold] from watchlist [cyan]{name}[/cyan]")
        if show or (not add_iocs and not remove_iocs):
            iocs = db.get_watchlist(name)
            if iocs:
                console.print(f"[dim]Watchlist '{name}' ({len(iocs)} IOCs):[/dim]")
                for i in iocs:
                    console.print(f"  {i}")
            else:
                console.print(f"[dim]Watchlist '{name}' is empty.[/dim]")


watchlist_app = typer.Typer(
    name="watchlist",
    help="[bold green]Manage watchlists[/bold green] in the local knowledge base.",
    invoke_without_command=True,
    no_args_is_help=False,
    cls=_WatchlistGroup,
)
app.add_typer(watchlist_app, name="watchlist")


@watchlist_app.callback()
def cmd_watchlist(
    ctx: typer.Context,
) -> None:
    """Manage watchlists in the local knowledge base.

    Usage (manage):   vex watchlist <name> [--add IOC] [--remove IOC] [--list]
    Usage (re-triage): vex watchlist run <name>
    """
    # Sub-commands (e.g. 'run') are handled by their own command below.
    if ctx.invoked_subcommand is not None:
        return
    # ctx.args holds all unparsed tokens (name + options) because
    # _WatchlistGroup moved them out of _protected_args.
    args = list(ctx.args)
    if not args:
        console.print(ctx.get_help())
        raise typer.Exit()
    # First positional token is the watchlist name; the rest are options.
    name = args[0]
    remaining = args[1:]
    _run_watchlist_manage(name, remaining)


@watchlist_app.command(
    name="manage",
    help="[bold]Manage[/bold] IOCs in a watchlist (add / remove / list).",
    hidden=True,
)
def cmd_watchlist_manage(
    name: Annotated[str, typer.Argument(help="Watchlist name.")],
    add: Annotated[Optional[list[str]], typer.Option("--add", "-a", help="IOC(s) to add.")] = None,
    remove: Annotated[Optional[list[str]], typer.Option("--remove", "-r", help="IOC(s) to remove.")] = None,
    show: Annotated[bool, typer.Option("--list", "-l", help="List all IOCs in this watchlist.")] = False,
) -> None:
    """Add, remove, or list IOCs in a named watchlist (hidden alias — prefer flat shape).

    The canonical shape is ``vex watchlist <name> [--add IOC] [--remove IOC] [--list]``.
    """
    # Build a synthetic args list and delegate to the shared helper.
    synthetic: list[str] = []
    if add:
        for ioc in add:
            synthetic += ["--add", ioc]
    if remove:
        for ioc in remove:
            synthetic += ["--remove", ioc]
    if show:
        synthetic.append("--list")
    _run_watchlist_manage(name, synthetic)


@watchlist_app.command(name="run", help="Re-triage every IOC in a watchlist and report verdict changes.")
def cmd_watchlist_run(
    name: Annotated[str, typer.Argument(help="Watchlist name to re-triage.")],
    output: Annotated[
        str,
        typer.Option("--output", "-o", help="Output format: rich (default) | console | json"),
    ] = "rich",
    config_path: _ConfigOpt = None,
    no_cache: _NoCacheOpt = False,
    quiet: _QuietOpt = False,
) -> None:
    """Re-triage all IOCs in a named watchlist and report verdict diffs.

    Compares each fresh verdict against the cached prior verdict and reports
    worsening changes (e.g. CLEAN → MALICIOUS).  Exits non-zero if any IOC
    worsened.  Quota-thrifty: only the watchlist-sized set is re-looked-up.
    """
    import json as _json

    from rich import box
    from rich.table import Table

    config = load_config(config_path)
    print_banner(
        quiet=quiet or config.output.quiet,
        update_check_enabled=config.update_check.enabled,
        check_interval_hours=config.update_check.check_interval_hours,
    )

    qt = _build_quota_tracker(config)
    try:
        with KnowledgeDB() as db:
            with Cache(config.cache_db_path, config.cache.ttl_hours, config.cache.enabled and not no_cache) as cache:
                run_result: WatchlistRunResult = retriage_watchlist(name, db, cache, config, quota_tracker=qt)
    except Exception as exc:
        err_console.print(f"[red]Error running watchlist re-triage:[/red] {exc}")
        raise typer.Exit(code=1)
    _quota_emit(qt)

    # Build serialisable diffs list
    diffs_out = [
        {
            "ioc": d["ioc"],
            "old_verdict": d["old_verdict"].value if hasattr(d["old_verdict"], "value") else str(d["old_verdict"]),
            "new_verdict": d["new_verdict"].value if hasattr(d["new_verdict"], "value") else str(d["new_verdict"]),
        }
        for d in run_result.diffs
    ]

    summary = {
        "watchlist": name,
        "total": run_result.total,
        "worsened": run_result.worsened,
        "unchanged": run_result.unchanged,
        "improved": run_result.improved,
        "cache_misses": run_result.cache_misses,
        "errors": run_result.errors,
        "diffs": diffs_out,
    }

    if output.lower() == "json":
        print(_json.dumps(summary, indent=2))
    else:
        # Rich / console table
        if run_result.total == 0:
            console.print(f"[dim]Watchlist '[cyan]{name}[/cyan]' is empty or unknown — nothing to re-triage.[/dim]")
        elif run_result.diffs:
            t = Table(
                title=f"Watchlist '{name}' — verdict changes",
                box=box.ROUNDED,
            )
            t.add_column("IOC", style="cyan", no_wrap=True)
            t.add_column("Prior verdict", style="dim", no_wrap=True)
            t.add_column("New verdict", no_wrap=True)
            for d in run_result.diffs:
                new_v = d["new_verdict"].value if hasattr(d["new_verdict"], "value") else str(d["new_verdict"])
                old_v = d["old_verdict"].value if hasattr(d["old_verdict"], "value") else str(d["old_verdict"])
                colour = "red" if new_v == "MALICIOUS" else "yellow"
                t.add_row(d["ioc"], old_v, f"[{colour}]{new_v}[/{colour}]")
            console.print(t)
        else:
            console.print(f"[green]✓[/green] Watchlist '[cyan]{name}[/cyan]': no verdict changes detected.")

        # Summary line
        console.print(
            f"[dim]Checked {run_result.total} IOC(s) — "
            f"{run_result.worsened} worsened, {run_result.unchanged} unchanged, "
            f"{run_result.improved} improved, {run_result.cache_misses} new, "
            f"{run_result.errors} error(s)[/dim]"
        )

    exit_code = 1 if run_result.has_worsening else 0
    raise typer.Exit(code=exit_code)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
