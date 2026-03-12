"""Pydantic v2 models for normalized IOC enrichment results."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class Verdict(str, Enum):
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    UNKNOWN = "UNKNOWN"
    CLEAN = "CLEAN"

    @property
    def severity(self) -> int:
        """Numeric severity: CLEAN=0, UNKNOWN=1, SUSPICIOUS=2, MALICIOUS=3."""
        return _SEVERITY[self]


_SEVERITY = {
    Verdict.CLEAN: 0,
    Verdict.UNKNOWN: 1,
    Verdict.SUSPICIOUS: 2,
    Verdict.MALICIOUS: 3,
}


class DetectionStats(BaseModel):
    malicious: int = 0
    suspicious: int = 0
    undetected: int = 0
    harmless: int = 0
    timeout: int = 0
    type_unsupported: int = 0
    confirmed_timeout: int = 0
    failure: int = 0

    @property
    def total(self) -> int:
        return (
            self.malicious
            + self.suspicious
            + self.undetected
            + self.harmless
            + self.timeout
            + self.type_unsupported
            + self.confirmed_timeout
            + self.failure
        )

    @property
    def ratio_str(self) -> str:
        return f"{self.malicious}/{self.total}"


class EngineResult(BaseModel):
    engine: str
    category: str
    result: Optional[str] = None


# --- Triage result (minimal, all IOC types) ---

class TriageResult(BaseModel):
    ioc: str
    ioc_type: str
    verdict: Verdict
    detection_stats: DetectionStats
    malware_families: list[str] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    last_analysis_date: Optional[datetime] = None
    # Top engines that flagged as malicious
    flagging_engines: list[EngineResult] = Field(default_factory=list)
    reputation: Optional[int] = None
    # Source metadata
    from_cache: bool = False
    error: Optional[str] = None
    # Local knowledge base
    local_tags: list[str] = Field(default_factory=list)
    local_notes: list[str] = Field(default_factory=list)
    watchlists: list[str] = Field(default_factory=list)


# --- Investigate results (extended, per IOC type) ---

class PEInfo(BaseModel):
    compilation_timestamp: Optional[datetime] = None
    entry_point: Optional[int] = None
    target_machine: Optional[str] = None
    sections: list[dict[str, Any]] = Field(default_factory=list)
    imports: list[str] = Field(default_factory=list)
    exports: list[str] = Field(default_factory=list)


class SandboxBehavior(BaseModel):
    sandbox_name: Optional[str] = None
    processes_created: list[str] = Field(default_factory=list)
    files_written: list[str] = Field(default_factory=list)
    files_deleted: list[str] = Field(default_factory=list)
    registry_keys_set: list[str] = Field(default_factory=list)
    network_connections: list[str] = Field(default_factory=list)
    dns_lookups: list[str] = Field(default_factory=list)
    mutexes: list[str] = Field(default_factory=list)
    verdict: Optional[str] = None


class PassiveDNSRecord(BaseModel):
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    resolver: Optional[str] = None
    last_resolved: Optional[datetime] = None


class WHOISInfo(BaseModel):
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    updated_date: Optional[str] = None
    name_servers: list[str] = Field(default_factory=list)
    registrant_org: Optional[str] = None
    registrant_country: Optional[str] = None


class RelatedFile(BaseModel):
    sha256: str
    name: Optional[str] = None
    detection_ratio: Optional[str] = None
    verdict: Optional[Verdict] = None


class ATTACKMapping(BaseModel):
    """A single MITRE ATT&CK technique mapping."""
    technique_id: str
    technique_name: str
    tactic: str
    evidence: Optional[str] = None


class InvestigateResult(BaseModel):
    """Extended result for investigate mode - includes triage data + deep dive."""
    triage: TriageResult
    attack_mappings: list[ATTACKMapping] = Field(default_factory=list)

    # File-specific
    file_type: Optional[str] = None
    file_size: Optional[int] = None
    file_names: list[str] = Field(default_factory=list)
    magic: Optional[str] = None
    ssdeep: Optional[str] = None
    tlsh: Optional[str] = None
    pe_info: Optional[PEInfo] = None
    sandbox_behaviors: list[SandboxBehavior] = Field(default_factory=list)
    contacted_ips: list[str] = Field(default_factory=list)
    contacted_domains: list[str] = Field(default_factory=list)
    dropped_files: list[RelatedFile] = Field(default_factory=list)
    yara_hits: list[str] = Field(default_factory=list)
    signature_info: Optional[dict[str, Any]] = None

    # Network-specific (IP/Domain)
    asn: Optional[int] = None
    asn_owner: Optional[str] = None
    country: Optional[str] = None
    continent: Optional[str] = None
    network: Optional[str] = None
    passive_dns: list[PassiveDNSRecord] = Field(default_factory=list)
    communicating_files: list[RelatedFile] = Field(default_factory=list)
    downloaded_files: list[RelatedFile] = Field(default_factory=list)

    # Domain-specific
    whois: Optional[WHOISInfo] = None
    dns_records: list[dict[str, Any]] = Field(default_factory=list)
    subdomains: list[str] = Field(default_factory=list)

    # URL-specific
    final_url: Optional[str] = None
    title: Optional[str] = None
    related_files: list[RelatedFile] = Field(default_factory=list)


# --- Timeline models ---

class TimelineEvent(BaseModel):
    """A single dated event in the IOC's lifecycle."""
    timestamp: datetime
    event_type: str
    source: str
    description: str


class TimelineResult(BaseModel):
    """Chronological timeline reconstructed from investigate data."""
    ioc: str
    events: list[TimelineEvent] = Field(default_factory=list)
    earliest: Optional[datetime] = None
    latest: Optional[datetime] = None
