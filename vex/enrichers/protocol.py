"""Protocol (interface) for enricher plugins.

Any enrichment source (VirusTotal, OTX, AbuseIPDB, etc.) must implement
this protocol so vex can discover and use it transparently.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..config import Config
from ..models import InvestigateResult, TriageResult


@runtime_checkable
class EnricherProtocol(Protocol):
    """Interface that every enricher plugin must satisfy."""

    @property
    def name(self) -> str:
        """Human-readable plugin name (e.g. 'VirusTotal')."""
        ...

    @property
    def supported_ioc_types(self) -> list[str]:
        """IOC type strings this plugin handles (e.g. ['md5', 'sha256', 'ipv4'])."""
        ...

    def triage(self, ioc: str, ioc_type: str, config: Config) -> TriageResult:
        """Perform a fast triage lookup."""
        ...

    def investigate(self, ioc: str, ioc_type: str, config: Config) -> InvestigateResult:
        """Perform a deep investigation lookup."""
        ...
