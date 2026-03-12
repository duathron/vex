"""Timeline enrichment — chronological event reconstruction.

Extracts all dated events from an ``InvestigateResult`` and arranges
them into a sortable timeline useful for incident reconstruction.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from .models import InvestigateResult, TimelineEvent, TimelineResult


def _ensure_utc(dt: datetime) -> datetime:
    """Ensure a datetime is timezone-aware (assume UTC if naive)."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def build_timeline(result: InvestigateResult) -> TimelineResult:
    """Build a chronological timeline from an investigate result."""
    events: list[TimelineEvent] = []
    triage = result.triage

    # --- Triage timestamps ---
    if triage.first_seen:
        events.append(TimelineEvent(
            timestamp=triage.first_seen,
            event_type="first_seen",
            source="VirusTotal",
            description=f"First seen on VirusTotal ({triage.ioc_type})",
        ))

    if triage.last_seen:
        events.append(TimelineEvent(
            timestamp=triage.last_seen,
            event_type="last_seen",
            source="VirusTotal",
            description=f"Last seen on VirusTotal",
        ))

    if triage.last_analysis_date:
        events.append(TimelineEvent(
            timestamp=triage.last_analysis_date,
            event_type="analysis",
            source="VirusTotal",
            description=f"Last analysis: {triage.detection_stats.ratio_str} detections → {triage.verdict.value}",
        ))

    # --- File-specific ---
    if result.pe_info and result.pe_info.compilation_timestamp:
        events.append(TimelineEvent(
            timestamp=result.pe_info.compilation_timestamp,
            event_type="compiled",
            source="PE Header",
            description=f"PE compiled (target: {result.pe_info.target_machine or 'unknown'})",
        ))

    if result.signature_info:
        sig_date = result.signature_info.get("signing date")
        if sig_date:
            try:
                ts = datetime.fromisoformat(sig_date) if isinstance(sig_date, str) else None
                if ts:
                    events.append(TimelineEvent(
                        timestamp=ts,
                        event_type="signed",
                        source="Signature",
                        description=f"Digitally signed by {result.signature_info.get('subject', 'unknown')}",
                    ))
            except (ValueError, TypeError):
                pass

    # --- Domain WHOIS ---
    if result.whois:
        whois = result.whois
        for field, label in [
            ("creation_date", "Domain registered"),
            ("updated_date", "WHOIS updated"),
            ("expiration_date", "Domain expires"),
        ]:
            val = getattr(whois, field, None)
            if val:
                try:
                    ts = datetime.fromisoformat(val) if isinstance(val, str) else None
                    if ts:
                        events.append(TimelineEvent(
                            timestamp=ts,
                            event_type="whois",
                            source="WHOIS",
                            description=f"{label} (registrar: {whois.registrar or 'unknown'})",
                        ))
                except (ValueError, TypeError):
                    pass

    # --- Passive DNS ---
    for rec in result.passive_dns[:20]:
        if rec.last_resolved:
            events.append(TimelineEvent(
                timestamp=rec.last_resolved,
                event_type="dns_resolution",
                source="Passive DNS",
                description=f"{rec.hostname or '?'} → {rec.ip_address or '?'}",
            ))

    # --- Sandbox behaviors ---
    for sb in result.sandbox_behaviors:
        if sb.dns_lookups:
            desc = f"Sandbox '{sb.sandbox_name or 'unknown'}': DNS lookups to {', '.join(sb.dns_lookups[:3])}"
            # Sandbox entries don't have timestamps, so we use last_analysis_date
            if triage.last_analysis_date:
                events.append(TimelineEvent(
                    timestamp=triage.last_analysis_date,
                    event_type="sandbox",
                    source=f"Sandbox: {sb.sandbox_name or 'unknown'}",
                    description=desc,
                ))

    # Normalize all timestamps to UTC-aware, then sort
    for ev in events:
        ev.timestamp = _ensure_utc(ev.timestamp)
    events.sort(key=lambda e: e.timestamp)

    return TimelineResult(
        ioc=triage.ioc,
        events=events,
        earliest=events[0].timestamp if events else None,
        latest=events[-1].timestamp if events else None,
    )
