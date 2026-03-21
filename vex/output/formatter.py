"""Rich terminal and plain console output formatters."""

from __future__ import annotations

from typing import Union

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from ..models import (
    ATTACKMapping,
    InvestigateResult,
    SandboxBehavior,
    TimelineResult,
    TriageResult,
    Verdict,
)

_VERDICT_STYLE = {
    Verdict.MALICIOUS: "bold red",
    Verdict.SUSPICIOUS: "bold yellow",
    Verdict.UNKNOWN: "bold magenta",
    Verdict.CLEAN: "bold green",
}

_VERDICT_ICON = {
    Verdict.MALICIOUS: "[red]✗ MALICIOUS[/red]",
    Verdict.SUSPICIOUS: "[yellow]⚠ SUSPICIOUS[/yellow]",
    Verdict.UNKNOWN: "[magenta]? UNKNOWN[/magenta]",
    Verdict.CLEAN: "[green]✓ CLEAN[/green]",
}

console = Console()
err_console = Console(stderr=True)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _verdict_badge(verdict: Verdict) -> Text:
    style = _VERDICT_STYLE.get(verdict, "bold white")
    return Text(f" {verdict.value} ", style=f"on {style.split()[-1]} bold white")


def _triage_panel(r: TriageResult) -> Panel:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", no_wrap=True)
    grid.add_column()

    grid.add_row("IOC", r.ioc)
    grid.add_row("Type", r.ioc_type.upper())
    grid.add_row("Verdict", _verdict_badge(r.verdict))
    grid.add_row(
        "Detections",
        f"[bold]{r.detection_stats.malicious}[/bold] malicious / "
        f"{r.detection_stats.suspicious} suspicious / "
        f"{r.detection_stats.total} total engines",
    )

    if r.malware_families:
        grid.add_row("Families", _truncated(r.malware_families, 5))
    if r.categories:
        grid.add_row("Categories", _truncated(r.categories, 5))
    if r.tags:
        grid.add_row("Tags", _truncated(r.tags, 8))
    if r.reputation is not None:
        grid.add_row("Reputation", str(r.reputation))
    if r.first_seen:
        grid.add_row("First Seen", r.first_seen.strftime("%Y-%m-%d %H:%M UTC"))
    if r.last_seen:
        grid.add_row("Last Seen", r.last_seen.strftime("%Y-%m-%d %H:%M UTC"))
    if r.last_analysis_date:
        grid.add_row("Last Analysis", r.last_analysis_date.strftime("%Y-%m-%d %H:%M UTC"))
    if r.from_cache:
        grid.add_row("Source", "[dim]cache[/dim]")
    if r.error:
        grid.add_row("[red]Error[/red]", f"[red]{r.error}[/red]")

    if r.flagging_engines:
        eng_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        eng_table.add_column("Engine", style="dim")
        eng_table.add_column("Result")
        for e in r.flagging_engines[:8]:
            style = "red" if e.category == "malicious" else "yellow"
            eng_table.add_row(e.engine, f"[{style}]{e.result or e.category}[/{style}]")
        grid.add_row("Top Engines", eng_table)

    title = _VERDICT_ICON.get(r.verdict, r.verdict.value)
    border_style = _VERDICT_STYLE.get(r.verdict, "white").split()[-1]
    return Panel(grid, title=f"[bold]{r.ioc}[/bold]  {title}", border_style=border_style)


# ---------------------------------------------------------------------------
# Rich output
# ---------------------------------------------------------------------------

def print_triage_rich(result: TriageResult) -> None:
    console.print(_triage_panel(result))


def print_investigate_rich(result: InvestigateResult) -> None:
    console.print(_triage_panel(result.triage))

    # --- File-specific ---
    if result.file_type or result.file_size or result.pe_info:
        file_grid = Table.grid(padding=(0, 2))
        file_grid.add_column(style="bold cyan", no_wrap=True)
        file_grid.add_column()

        if result.file_type:
            file_grid.add_row("File Type", result.file_type)
        if result.file_size:
            file_grid.add_row("File Size", f"{result.file_size:,} bytes")
        if result.magic:
            file_grid.add_row("Magic", result.magic)
        if result.file_names:
            file_grid.add_row("Names Seen", ", ".join(result.file_names[:5]))
        if result.ssdeep:
            file_grid.add_row("SSDeep", (result.ssdeep[:60] + "…") if len(result.ssdeep) > 60 else result.ssdeep)
        if result.yara_hits:
            file_grid.add_row("YARA Hits", ", ".join(result.yara_hits[:5]))
        if result.signature_info:
            sig = result.signature_info
            file_grid.add_row("Signature", f"{sig.get('subject', '')} [{sig.get('verified', 'unverified')}]")

        if result.pe_info:
            pe = result.pe_info
            if pe.compilation_timestamp:
                file_grid.add_row("Compiled", pe.compilation_timestamp.strftime("%Y-%m-%d %H:%M UTC"))
            if pe.target_machine:
                file_grid.add_row("PE Target", pe.target_machine)
            if pe.sections:
                section_info = ", ".join(
                    f"{s.get('name', '?')}(entropy={s['entropy']:.2f})" if isinstance(s.get('entropy'), (int, float)) else s.get('name', '?')
                    for s in pe.sections[:5]
                )
                file_grid.add_row("PE Sections", section_info)
            if pe.imports:
                file_grid.add_row("Imports (sample)", ", ".join(pe.imports[:5]))

        console.print(Panel(file_grid, title="[bold]File Details[/bold]", border_style="blue"))

    # --- Sandbox behavior ---
    for sb in result.sandbox_behaviors[:2]:
        _print_sandbox_rich(sb)

    # --- MITRE ATT&CK Mappings ---
    if result.attack_mappings:
        atk_table = Table(
            title="MITRE ATT&CK Mappings",
            box=box.SIMPLE_HEAVY,
            show_lines=False,
        )
        atk_table.add_column("Technique", style="bold red", no_wrap=True)
        atk_table.add_column("Name", style="yellow")
        atk_table.add_column("Tactic", style="cyan")
        atk_table.add_column("Evidence", style="dim", max_width=40)
        for m in result.attack_mappings[:20]:
            atk_table.add_row(
                m.technique_id,
                m.technique_name,
                m.tactic,
                (m.evidence[:40] + "…") if m.evidence and len(m.evidence) > 40 else (m.evidence or ""),
            )
        console.print(atk_table)

    # --- Contacted IPs/Domains ---
    if result.contacted_ips or result.contacted_domains:
        net_grid = Table.grid(padding=(0, 2))
        net_grid.add_column(style="bold cyan", no_wrap=True)
        net_grid.add_column()
        if result.contacted_ips:
            net_grid.add_row("Contacted IPs", ", ".join(result.contacted_ips[:10]))
        if result.contacted_domains:
            net_grid.add_row("Contacted Domains", ", ".join(result.contacted_domains[:10]))
        console.print(Panel(net_grid, title="[bold]Network Activity[/bold]", border_style="yellow"))

    # --- Network IOC specific ---
    if result.asn or result.country:
        net_grid = Table.grid(padding=(0, 2))
        net_grid.add_column(style="bold cyan", no_wrap=True)
        net_grid.add_column()
        if result.asn:
            net_grid.add_row("ASN", f"AS{result.asn} {result.asn_owner or ''}")
        if result.country:
            net_grid.add_row("Country", f"{result.country} ({result.continent or ''})")
        if result.network:
            net_grid.add_row("Network", result.network)
        console.print(Panel(net_grid, title="[bold]Network Info[/bold]", border_style="blue"))

    if result.passive_dns:
        pdns_table = Table(title="Passive DNS", box=box.SIMPLE_HEAVY, show_lines=False)
        pdns_table.add_column("Hostname", style="cyan")
        pdns_table.add_column("IP Address", style="green")
        pdns_table.add_column("Last Resolved")
        for rec in result.passive_dns[:15]:
            pdns_table.add_row(
                rec.hostname or "",
                rec.ip_address or "",
                rec.last_resolved.strftime("%Y-%m-%d") if rec.last_resolved else "",
            )
        console.print(pdns_table)

    if result.whois:
        w = result.whois
        whois_grid = Table.grid(padding=(0, 2))
        whois_grid.add_column(style="bold cyan", no_wrap=True)
        whois_grid.add_column()
        if w.registrar:
            whois_grid.add_row("Registrar", w.registrar)
        if w.creation_date:
            whois_grid.add_row("Created", w.creation_date)
        if w.expiration_date:
            whois_grid.add_row("Expires", w.expiration_date)
        if w.registrant_org:
            whois_grid.add_row("Org", w.registrant_org)
        if w.registrant_country:
            whois_grid.add_row("Country", w.registrant_country)
        if w.name_servers:
            whois_grid.add_row("Name Servers", ", ".join(w.name_servers[:4]))
        console.print(Panel(whois_grid, title="[bold]WHOIS[/bold]", border_style="blue"))

    # --- Related files ---
    for label, files in [
        ("Communicating Files", result.communicating_files),
        ("Downloaded Files", result.downloaded_files),
        ("Dropped Files", result.dropped_files),
        ("Related Files", result.related_files),
    ]:
        if files:
            t = Table(title=label, box=box.SIMPLE_HEAVY)
            t.add_column("SHA256", style="dim", width=20, no_wrap=True)
            t.add_column("Name")
            t.add_column("Ratio", style="red")
            for f in files[:10]:
                t.add_row(f.sha256[:16] + "…", f.name or "", f.detection_ratio or "")
            console.print(t)

    # --- URL specific ---
    if result.final_url or result.title:
        url_grid = Table.grid(padding=(0, 2))
        url_grid.add_column(style="bold cyan", no_wrap=True)
        url_grid.add_column()
        if result.final_url:
            url_grid.add_row("Final URL", result.final_url)
        if result.title:
            url_grid.add_row("Page Title", result.title)
        console.print(Panel(url_grid, title="[bold]URL Details[/bold]", border_style="blue"))


def _print_sandbox_rich(sb: SandboxBehavior) -> None:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", no_wrap=True)
    grid.add_column()

    if sb.verdict:
        grid.add_row("Verdict", f"[red]{sb.verdict}[/red]" if "malicious" in sb.verdict.lower() else sb.verdict)
    if sb.processes_created:
        grid.add_row("Processes", ", ".join(sb.processes_created[:5]))
    if sb.network_connections:
        grid.add_row("Network", ", ".join(sb.network_connections[:5]))
    if sb.dns_lookups:
        grid.add_row("DNS", ", ".join(sb.dns_lookups[:5]))
    if sb.files_written:
        grid.add_row("Files Written", ", ".join(sb.files_written[:5]))
    if sb.registry_keys_set:
        grid.add_row("Registry", ", ".join(sb.registry_keys_set[:5]))
    if sb.mutexes:
        grid.add_row("Mutexes", ", ".join(sb.mutexes[:5]))

    console.print(Panel(grid, title=f"[bold]Sandbox: {sb.sandbox_name or 'Unknown'}[/bold]", border_style="magenta"))


# ---------------------------------------------------------------------------
# Plain console output (no rich dependency at runtime for piping)
# ---------------------------------------------------------------------------

def _truncated(items: list[str], limit: int) -> str:
    """Join items with truncation indicator if list exceeds limit."""
    shown = items[:limit]
    remaining = len(items) - limit
    text = ", ".join(shown)
    if remaining > 0:
        text += f" (+{remaining} more)"
    return text


def print_triage_console(result: TriageResult) -> None:
    verdict_markup = _VERDICT_ICON.get(result.verdict, result.verdict.value)
    console.print(f"\n{'='*60}")
    console.print(f"IOC     : {result.ioc}")
    console.print(f"Type    : {result.ioc_type.upper()}")
    console.print(f"Verdict : {verdict_markup}")
    console.print(f"Engines : {result.detection_stats.ratio_str}")
    if result.malware_families:
        console.print(f"Families: {_truncated(result.malware_families, 5)}")
    if result.categories:
        console.print(f"Categs  : {_truncated(result.categories, 5)}")
    if result.tags:
        console.print(f"Tags    : {_truncated(result.tags, 8)}")
    if result.reputation is not None:
        console.print(f"Repute  : {result.reputation}")
    if result.first_seen:
        console.print(f"First   : {result.first_seen.strftime('%Y-%m-%d %H:%M UTC')}")
    if result.last_seen:
        console.print(f"Last    : {result.last_seen.strftime('%Y-%m-%d %H:%M UTC')}")
    if result.last_analysis_date:
        console.print(f"Analysis: {result.last_analysis_date.strftime('%Y-%m-%d %H:%M UTC')}")
    if result.flagging_engines:
        console.print("Engines flagging:")
        for e in result.flagging_engines[:8]:
            style = "red" if e.category == "malicious" else "yellow"
            console.print(f"  [{style}][{e.category}] {e.engine}: {e.result or '-'}[/{style}]")
    if result.from_cache:
        console.print("[dim](from cache)[/dim]")
    if result.error:
        console.print(f"[red]ERROR   : {result.error}[/red]")
    console.print(f"{'='*60}")


def print_summary(results: list[TriageResult]) -> None:
    """Print a one-line summary to stderr (for --summary flag)."""
    if not results:
        err_console.print("[dim]No results.[/dim]")
        return
    counts = {v: 0 for v in Verdict}
    for r in results:
        counts[r.verdict] += 1
    parts = []
    for v in (Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.UNKNOWN, Verdict.CLEAN):
        if counts[v]:
            style = _VERDICT_STYLE.get(v, "white")
            parts.append(f"[{style}]{counts[v]} {v.value}[/{style}]")
    err_console.print(f"[bold]Summary:[/bold] {len(results)} IOC(s) — {' / '.join(parts)}")


def print_timeline_rich(timeline: TimelineResult) -> None:
    """Print a chronological timeline in rich format."""
    if not timeline.events:
        console.print("[dim]No timeline events found.[/dim]")
        return

    tl_table = Table(
        title=f"Timeline: {timeline.ioc}",
        box=box.SIMPLE_HEAVY,
        show_lines=False,
    )
    tl_table.add_column("Timestamp", style="cyan", no_wrap=True)
    tl_table.add_column("Type", style="bold yellow", width=16)
    tl_table.add_column("Source", style="dim", width=16)
    tl_table.add_column("Description")

    for ev in timeline.events:
        tl_table.add_row(
            ev.timestamp.strftime("%Y-%m-%d %H:%M"),
            ev.event_type,
            ev.source,
            ev.description,
        )

    console.print(tl_table)
    if timeline.earliest and timeline.latest:
        span = timeline.latest - timeline.earliest
        console.print(f"[dim]  Span: {span.days} days from first to last event[/dim]")


def print_timeline_console(timeline: TimelineResult) -> None:
    """Print a chronological timeline in plain text."""
    if not timeline.events:
        print("No timeline events found.")
        return

    print(f"\n{'='*60}")
    print(f"Timeline: {timeline.ioc}")
    print(f"{'='*60}")
    for ev in timeline.events:
        print(f"  {ev.timestamp.strftime('%Y-%m-%d %H:%M')}  [{ev.event_type}]  {ev.description}")
    if timeline.earliest and timeline.latest:
        span = timeline.latest - timeline.earliest
        print(f"  Span: {span.days} days")
    print(f"{'='*60}")


# ---------------------------------------------------------------------------
# AI explanation output
# ---------------------------------------------------------------------------

def print_explanation_rich(explanation: str, provider: str = "template") -> None:
    """Print AI or template explanation as a Rich panel with blue border."""
    if provider == "template":
        title = "[bold]Template Explanation[/bold]"
    else:
        title = f"[bold]AI Explanation[/bold] [dim]({provider})[/dim]"
    console.print(Panel(
        explanation,
        title=title,
        border_style="blue",
        padding=(1, 2),
    ))


def print_explanation_console(explanation: str, provider: str = "template") -> None:
    """Print AI or template explanation in plain text."""
    label = "Template Explanation" if provider == "template" else f"AI Explanation ({provider})"
    console.print(f"\n{'─' * 60}")
    console.print(f"{label}:")
    console.print(f"{'─' * 60}")
    console.print(explanation)
    console.print(f"{'─' * 60}")


# ---------------------------------------------------------------------------
# barb pre-scan context output
# ---------------------------------------------------------------------------

_BARB_VERDICT_STYLE: dict[str, str] = {
    "SAFE": "bold green",
    "LOW_RISK": "bold cyan",
    "SUSPICIOUS": "bold yellow",
    "HIGH_RISK": "bold dark_orange",
    "PHISHING": "bold red",
}

_BARB_VERDICT_ICON: dict[str, str] = {
    "SAFE": "[green]✓ SAFE[/green]",
    "LOW_RISK": "[cyan]~ LOW RISK[/cyan]",
    "SUSPICIOUS": "[yellow]⚠ SUSPICIOUS[/yellow]",
    "HIGH_RISK": "[dark_orange]⚠ HIGH RISK[/dark_orange]",
    "PHISHING": "[red]✗ PHISHING[/red]",
}


def print_barb_context_rich(ctx) -> None:  # ctx: BarbContext (lazy import to avoid circular)
    """Print barb pre-scan verdict as a Rich panel with orange border."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", no_wrap=True)
    grid.add_column()

    verdict_upper = ctx.verdict.upper()
    verdict_icon = _BARB_VERDICT_ICON.get(verdict_upper, f"[white]{ctx.verdict}[/white]")
    grid.add_row("Verdict", verdict_icon)
    grid.add_row("Risk Score", f"{ctx.risk_score:.1f} / 100")

    if ctx.defanged_url:
        grid.add_row("URL", ctx.defanged_url)

    top = ctx.top_signals
    if top:
        sig_table = Table(box=box.SIMPLE, show_header=True, padding=(0, 1))
        sig_table.add_column("Analyzer", style="dim", no_wrap=True)
        sig_table.add_column("Severity", no_wrap=True)
        sig_table.add_column("Signal")
        _sev_style = {"CRITICAL": "red", "HIGH": "dark_orange", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim"}
        for s in top:
            sev_style = _sev_style.get(s.severity.upper(), "white")
            sig_table.add_row(
                s.analyzer,
                f"[{sev_style}]{s.severity}[/{sev_style}]",
                s.label,
            )
        grid.add_row("Signals", sig_table)

    if ctx.explanation:
        grid.add_row("Explanation", ctx.explanation[:200] + ("…" if len(ctx.explanation) > 200 else ""))

    border_style = "dark_orange"
    console.print(Panel(
        grid,
        title="[bold]barb pre-scan[/bold]",
        border_style=border_style,
        subtitle="[dim]offline heuristic analysis[/dim]",
    ))


def print_barb_context_console(ctx) -> None:  # ctx: BarbContext
    """Print barb pre-scan context in plain text."""
    verdict_upper = ctx.verdict.upper()
    verdict_icon = _BARB_VERDICT_ICON.get(verdict_upper, ctx.verdict)
    console.print(f"\n{'─' * 60}")
    console.print(f"barb pre-scan")
    console.print(f"{'─' * 60}")
    console.print(f"Verdict   : {verdict_icon}  (risk score: {ctx.risk_score:.1f}/100)")
    if ctx.defanged_url:
        console.print(f"URL       : {ctx.defanged_url}")
    for s in ctx.top_signals:
        console.print(f"  [{s.severity}] {s.analyzer}: {s.label}")
    if ctx.explanation:
        console.print(f"Note      : {ctx.explanation[:200]}")
    console.print(f"{'─' * 60}")


# ---------------------------------------------------------------------------
# Plain console output (no rich dependency at runtime for piping)
# ---------------------------------------------------------------------------

def print_investigate_console(result: InvestigateResult) -> None:
    print_triage_console(result.triage)

    if result.file_type:
        console.print(f"File Type : {result.file_type}")
    if result.file_size:
        console.print(f"File Size : {result.file_size:,} bytes")
    if result.magic:
        console.print(f"Magic     : {result.magic}")
    if result.file_names:
        console.print(f"Names     : {_truncated(result.file_names, 5)}")
    if result.yara_hits:
        console.print(f"YARA      : {_truncated(result.yara_hits, 5)}")
    if result.pe_info and result.pe_info.compilation_timestamp:
        console.print(f"Compiled  : {result.pe_info.compilation_timestamp.strftime('%Y-%m-%d %H:%M UTC')}")

    for sb in result.sandbox_behaviors[:2]:
        console.print(f"\n-- Sandbox: {sb.sandbox_name or 'Unknown'} --")
        if sb.processes_created:
            console.print(f"  Processes : {_truncated(sb.processes_created, 5)}")
        if sb.network_connections:
            console.print(f"  Network   : {_truncated(sb.network_connections, 5)}")
        if sb.dns_lookups:
            console.print(f"  DNS       : {_truncated(sb.dns_lookups, 5)}")

    if result.contacted_ips:
        console.print(f"Contacted IPs     : {_truncated(result.contacted_ips, 10)}")
    if result.contacted_domains:
        console.print(f"Contacted Domains : {_truncated(result.contacted_domains, 10)}")

    if result.asn:
        console.print(f"ASN     : AS{result.asn} {result.asn_owner or ''}")
    if result.country:
        console.print(f"Country : {result.country}")

    if result.passive_dns:
        console.print("\nPassive DNS:")
        for r in result.passive_dns[:10]:
            resolved = r.last_resolved.strftime("%Y-%m-%d") if r.last_resolved else ""
            console.print(f"  [cyan]{r.hostname or r.ip_address}[/cyan] -> [green]{r.ip_address or r.hostname}[/green]  [dim]\\[{resolved}][/dim]")

    if result.whois:
        w = result.whois
        console.print(f"\nWHOIS: registrar={w.registrar}, created={w.creation_date}, expires={w.expiration_date}")
