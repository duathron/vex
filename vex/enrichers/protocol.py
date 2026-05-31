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


@runtime_checkable
class SecondaryEnricherProtocol(Protocol):
    """Interface for secondary enricher plugins that augment an existing InvestigateResult.

    Secondary enrichers run after the primary enricher on investigate calls only.
    They mutate ``result`` in place and must never raise — implement fail-open internally.
    """

    @property
    def name(self) -> str:
        """Human-readable plugin name (e.g. 'AbuseIPDB')."""
        ...

    @property
    def supported_ioc_types(self) -> list[str]:
        """IOC type strings this secondary handles (e.g. ['ipv4', 'ipv6'])."""
        ...

    def enrich(
        self,
        result: InvestigateResult,
        ioc: str,
        ioc_type: str,
        config: Config,
    ) -> None:
        """Augment *result* in place with additional enrichment data.

        Must never raise. Any error should be handled internally (fail-open).
        """
        ...
