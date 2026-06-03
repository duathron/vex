"""HTML report export for vex enrichment results.

Produces a self-contained HTML file (embedded CSS) by recording Rich output
via Console(record=True), then calling console.export_html().

IOC strings are defanged before rendering so the report contains no live,
clickable malware indicators.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Union

from rich.console import Console

from ..defang import defang, is_defanged
from ..models import InvestigateResult, TriageResult
from .formatter import (
    _triage_panel,
)


def _defang_triage(result: TriageResult) -> TriageResult:
    """Return a copy of *result* with the IOC field defanged."""
    data = result.model_copy(deep=True)
    if data.ioc and not is_defanged(data.ioc):
        data.ioc = defang(data.ioc)
    return data


def _defang_investigate(result: InvestigateResult) -> InvestigateResult:
    """Return a copy of *result* with the triage IOC field defanged."""
    data = result.model_copy(deep=True)
    if data.triage.ioc and not is_defanged(data.triage.ioc):
        data.triage.ioc = defang(data.triage.ioc)
    return data


def _make_recording_console() -> Console:
    """Create a wide recording console suitable for HTML export."""
    return Console(record=True, width=120)


def _render_triage_to_console(
    result: TriageResult,
    rec: Console,
) -> None:
    """Render a single TriageResult onto *rec* (a recording Console)."""
    rec.print(_triage_panel(result))


def _render_investigate_to_console(
    result: InvestigateResult,
    rec: Console,
) -> None:
    """Render a single InvestigateResult onto *rec* by replaying formatter logic.

    We import and call the same internal helpers used by print_investigate_rich
    to avoid duplicating rendering logic.  The only difference is that we target
    our recording console rather than the module-level one.
    """
    from rich import box
    from rich.panel import Panel
    from rich.table import Table

    r = result

    # --- Triage panel (shared) ---
    rec.print(_triage_panel(r.triage))

    # --- File-specific ---
    if r.file_type or r.file_size or r.pe_info:
        file_grid = Table.grid(padding=(0, 2))
        file_grid.add_column(style="bold cyan", no_wrap=True)
        file_grid.add_column()

        if r.file_type:
            file_grid.add_row("File Type", r.file_type)
        if r.file_size:
            file_grid.add_row("File Size", f"{r.file_size:,} bytes")
        if r.magic:
            file_grid.add_row("Magic", r.magic)
        if r.file_names:
            file_grid.add_row("Names Seen", ", ".join(r.file_names[:5]))
        if r.ssdeep:
            file_grid.add_row("SSDeep", (r.ssdeep[:60] + "…") if len(r.ssdeep) > 60 else r.ssdeep)
        if r.yara_hits:
            file_grid.add_row("YARA Hits", ", ".join(r.yara_hits[:5]))
        if r.signature_info:
            sig = r.signature_info
            file_grid.add_row("Signature", f"{sig.get('subject', '')} [{sig.get('verified', 'unverified')}]")

        if r.pe_info:
            pe = r.pe_info
            if pe.compilation_timestamp:
                file_grid.add_row("Compiled", pe.compilation_timestamp.strftime("%Y-%m-%d %H:%M UTC"))
            if pe.target_machine:
                file_grid.add_row("PE Target", pe.target_machine)
            if pe.sections:
                section_info = ", ".join(
                    f"{s.get('name', '?')}(entropy={s['entropy']:.2f})"
                    if isinstance(s.get("entropy"), (int, float))
                    else s.get("name", "?")
                    for s in pe.sections[:5]
                )
                file_grid.add_row("PE Sections", section_info)
            if pe.imports:
                file_grid.add_row("Imports (sample)", ", ".join(pe.imports[:5]))

        rec.print(Panel(file_grid, title="[bold]File Details[/bold]", border_style="blue"))

    # --- Sandbox behavior ---
    for sb in r.sandbox_behaviors[:2]:
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="bold cyan", no_wrap=True)
        grid.add_column()
        if sb.verdict:
            grid.add_row(
                "Verdict",
                f"[red]{sb.verdict}[/red]" if "malicious" in sb.verdict.lower() else sb.verdict,
            )
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
        rec.print(Panel(grid, title=f"[bold]Sandbox: {sb.sandbox_name or 'Unknown'}[/bold]", border_style="magenta"))

    # --- MITRE ATT&CK ---
    if r.attack_mappings:
        atk_table = Table(
            title="MITRE ATT&CK Mappings",
            box=box.SIMPLE_HEAVY,
            show_lines=False,
        )
        atk_table.add_column("Technique", style="bold red", no_wrap=True)
        atk_table.add_column("Name", style="yellow")
        atk_table.add_column("Tactic", style="cyan")
        atk_table.add_column("Evidence", style="dim", max_width=40)
        for m in r.attack_mappings[:20]:
            atk_table.add_row(
                m.technique_id,
                m.technique_name,
                m.tactic,
                (m.evidence[:40] + "…") if m.evidence and len(m.evidence) > 40 else (m.evidence or ""),
            )
        rec.print(atk_table)

    # --- Contacted IPs/Domains ---
    if r.contacted_ips or r.contacted_domains:
        net_grid = Table.grid(padding=(0, 2))
        net_grid.add_column(style="bold cyan", no_wrap=True)
        net_grid.add_column()
        if r.contacted_ips:
            net_grid.add_row("Contacted IPs", ", ".join(r.contacted_ips[:10]))
        if r.contacted_domains:
            net_grid.add_row("Contacted Domains", ", ".join(r.contacted_domains[:10]))
        rec.print(Panel(net_grid, title="[bold]Network Activity[/bold]", border_style="yellow"))

    # --- Network IOC specific ---
    if r.asn or r.country or r.abuse_confidence is not None:
        net_grid = Table.grid(padding=(0, 2))
        net_grid.add_column(style="bold cyan", no_wrap=True)
        net_grid.add_column()
        if r.asn:
            net_grid.add_row("ASN", f"AS{r.asn} {r.asn_owner or ''}")
        if r.country:
            net_grid.add_row("Country", f"{r.country} ({r.continent or ''})")
        if r.network:
            net_grid.add_row("Network", r.network)
        if r.abuse_confidence is not None:
            reports = r.abuse_total_reports or 0
            net_grid.add_row("AbuseIPDB", f"{r.abuse_confidence}/100 ({reports} reports)")
        rec.print(Panel(net_grid, title="[bold]Network Info[/bold]", border_style="blue"))

    if r.passive_dns:
        pdns_table = Table(title="Passive DNS", box=box.SIMPLE_HEAVY, show_lines=False)
        pdns_table.add_column("Hostname", style="cyan")
        pdns_table.add_column("IP Address", style="green")
        pdns_table.add_column("Last Resolved")
        for rec_dns in r.passive_dns[:15]:
            pdns_table.add_row(
                rec_dns.hostname or "",
                rec_dns.ip_address or "",
                rec_dns.last_resolved.strftime("%Y-%m-%d") if rec_dns.last_resolved else "",
            )
        rec.print(pdns_table)

    if r.whois:
        w = r.whois
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
        rec.print(Panel(whois_grid, title="[bold]WHOIS[/bold]", border_style="blue"))

    # --- Related files ---
    for label, files in [
        ("Communicating Files", r.communicating_files),
        ("Downloaded Files", r.downloaded_files),
        ("Dropped Files", r.dropped_files),
        ("Related Files", r.related_files),
    ]:
        if files:
            t = Table(title=label, box=box.SIMPLE_HEAVY)
            t.add_column("SHA256", style="dim", width=20, no_wrap=True)
            t.add_column("Name")
            t.add_column("Ratio", style="red")
            for f in files[:10]:
                t.add_row(f.sha256[:16] + "…", f.name or "", f.detection_ratio or "")
            rec.print(t)

    # --- URL specific ---
    if r.final_url or r.title:
        url_grid = Table.grid(padding=(0, 2))
        url_grid.add_column(style="bold cyan", no_wrap=True)
        url_grid.add_column()
        if r.final_url:
            url_grid.add_row("Final URL", r.final_url)
        if r.title:
            url_grid.add_row("Page Title", r.title)
        rec.print(Panel(url_grid, title="[bold]URL Details[/bold]", border_style="blue"))


def _html_wrapper(body_html: str, title: str) -> str:
    """Wrap Rich-exported HTML in a minimal outer page with a header."""
    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        f"<title>{title}</title>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        "<style>\n"
        "body { background: #1a1a1a; color: #e0e0e0; font-family: monospace; margin: 0; padding: 1rem; }\n"
        "header { margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 1px solid #444; }\n"
        "header h1 { margin: 0; font-size: 1.2rem; color: #aef; }\n"
        "header p { margin: 0.25rem 0 0; font-size: 0.8rem; color: #888; }\n"
        ".vex-body { overflow-x: auto; }\n"
        "</style>\n"
        "</head>\n"
        "<body>\n"
        "<header>\n"
        f"<h1>vex IOC Enrichment Report</h1>\n"
        f"<p>Generated: {ts} &mdash; IOC strings are defanged for safe sharing.</p>\n"
        "</header>\n"
        '<div class="vex-body">\n'
        f"{body_html}\n"
        "</div>\n"
        "</body>\n"
        "</html>\n"
    )


def write_html_report(
    path: str,
    results: list[Union[TriageResult, InvestigateResult]],
    mode: str = "triage",
) -> None:
    """Render *results* to a self-contained HTML file at *path*.

    Parameters
    ----------
    path:
        Filesystem path for the output file.
    results:
        List of TriageResult or InvestigateResult objects.  May be a
        single-element list for one-IOC reports.
    mode:
        ``"triage"`` or ``"investigate"`` — controls which formatter is used.
        Auto-detected per result when the list is mixed.
    """
    if not results:
        open(path, "w").close()
        return

    rec = _make_recording_console()

    for result in results:
        if isinstance(result, InvestigateResult):
            safe = _defang_investigate(result)
            _render_investigate_to_console(safe, rec)
        else:
            safe = _defang_triage(result)
            _render_triage_to_console(safe, rec)

    # export_html() returns a full <html>…</html> document from Rich.
    # We strip that and use our own wrapper to keep the dark theme consistent.
    rich_html = rec.export_html(inline_styles=True)

    # Extract just the <body> content from Rich's output
    body_start = rich_html.find("<body>")
    body_end = rich_html.find("</body>")
    if body_start != -1 and body_end != -1:
        body_content = rich_html[body_start + len("<body>") : body_end].strip()
    else:
        # Fallback: use the full Rich HTML
        body_content = rich_html

    # Build IOC list for the page title — defang so the title is safe too
    ioc_labels = []
    for r in results:
        if isinstance(r, InvestigateResult):
            raw = r.triage.ioc
        else:
            raw = r.ioc
        ioc_labels.append(raw if is_defanged(raw) else defang(raw))
    title = "vex report: " + ", ".join(ioc_labels[:3])
    if len(ioc_labels) > 3:
        title += f" (+{len(ioc_labels) - 3} more)"

    html = _html_wrapper(body_content, title)

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
