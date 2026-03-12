"""Built-in VirusTotal enricher plugin.

Wraps the existing enricher modules into the plugin protocol so
VirusTotal works seamlessly with the plugin architecture.
"""

from __future__ import annotations

from ..client import VTClient
from ..config import Config
from ..enrichers import domain as domain_enricher
from ..enrichers import hash as hash_enricher
from ..enrichers import ip as ip_enricher
from ..enrichers import url as url_enricher
from ..enrichers.protocol import EnricherProtocol
from ..ioc_detector import IOCType, is_hash
from ..models import InvestigateResult, TriageResult


class VirusTotalPlugin:
    """Default enricher plugin — wraps the built-in VT modules."""

    @property
    def name(self) -> str:
        return "VirusTotal"

    @property
    def supported_ioc_types(self) -> list[str]:
        return ["md5", "sha1", "sha256", "ipv4", "ipv6", "domain", "url"]

    def _resolve_module(self, ioc_type: str):
        ioc_enum = IOCType(ioc_type)
        if is_hash(ioc_enum):
            return hash_enricher
        if ioc_enum in (IOCType.IPV4, IOCType.IPV6):
            return ip_enricher
        if ioc_enum == IOCType.DOMAIN:
            return domain_enricher
        if ioc_enum == IOCType.URL:
            return url_enricher
        return None

    def triage(self, ioc: str, ioc_type: str, config: Config) -> TriageResult:
        module = self._resolve_module(ioc_type)
        if module is None:
            raise ValueError(f"Unsupported IOC type: {ioc_type}")
        with VTClient(config) as client:
            return module.triage(ioc, ioc_type, client, config)

    def investigate(self, ioc: str, ioc_type: str, config: Config) -> InvestigateResult:
        module = self._resolve_module(ioc_type)
        if module is None:
            raise ValueError(f"Unsupported IOC type: {ioc_type}")
        with VTClient(config) as client:
            return module.investigate(ioc, ioc_type, client, config)


# Verify protocol compliance at import time
assert isinstance(VirusTotalPlugin(), EnricherProtocol)
