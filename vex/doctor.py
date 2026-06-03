"""Service configuration and connectivity diagnostics for vex.

Surfaces whether each enricher / external service is configured and, when
``probe=True``, whether it is actually reachable. This fixes the "silent
fail-open" problem where enrichers quietly no-op when misconfigured or
unreachable.

Config-only by default (no network). Probing is opt-in and fully defensive:
every network call has a short timeout and is wrapped in try/except, so an
unreachable service is *reported*, never raised. Secrets are never logged or
included in any detail string.
"""

from __future__ import annotations

from typing import Optional

import httpx
from pydantic import BaseModel

from .config import Config

# VirusTotal base used for the optional lightweight probe.
VT_BASE = "https://www.virustotal.com/api/v3"

# Short timeout for all probe network calls (seconds).
PROBE_TIMEOUT_S = 5.0


class ServiceStatus(BaseModel):
    """Status of a single external service / enricher."""

    name: str
    configured: bool
    reachable: Optional[bool] = None  # None when not probed
    detail: str = ""


def _status_code_class(code: int) -> str:
    """Human-readable class for an HTTP status code."""
    return f"HTTP {code} ({code // 100}xx)"


def _check_virustotal(config: Config, probe: bool) -> ServiceStatus:
    """VirusTotal — configured if a VT key resolves (api_key raises if missing)."""
    try:
        config.api_key  # noqa: B018 — accessing the property raises when unset
        configured = True
    except Exception:
        configured = False

    if not configured:
        return ServiceStatus(
            name="VirusTotal",
            configured=False,
            reachable=None,
            detail="no API key (set VT_API_KEY or run 'vex config --set-api-key')",
        )

    if not probe:
        return ServiceStatus(
            name="VirusTotal",
            configured=True,
            reachable=None,
            detail="API key present (not probed — config-only)",
        )

    # Lightweight, safe probe: hit the API base. We do not call a real
    # endpoint that would burn quota; we only report the status code class.
    try:
        resp = httpx.get(VT_BASE, timeout=PROBE_TIMEOUT_S)
        # Any HTTP response (even 401/404) means the host is reachable.
        return ServiceStatus(
            name="VirusTotal",
            configured=True,
            reachable=True,
            detail=f"reachable — {_status_code_class(resp.status_code)}",
        )
    except Exception as exc:  # noqa: BLE001 — surface, never crash
        return ServiceStatus(
            name="VirusTotal",
            configured=True,
            reachable=False,
            detail=f"unreachable: {exc}",
        )


def _check_ai(config: Config, probe: bool) -> ServiceStatus:
    """AI provider — configured if ai.provider != 'none'."""
    provider = (config.ai.provider or "none").lower().strip()
    local_only = config.ai.local_only

    if provider == "none":
        return ServiceStatus(
            name="AI provider",
            configured=False,
            reachable=None,
            detail="provider=none (AI explanations disabled)",
        )

    base_detail = f"provider={provider}, local_only={local_only}"

    if not probe:
        return ServiceStatus(
            name="AI provider",
            configured=True,
            reachable=None,
            detail=base_detail,
        )

    if provider == "ollama":
        try:
            from .ai.ollama import OllamaProvider

            available = OllamaProvider(model=config.ai.model, base_url=config.ai.base_url).is_available()
            return ServiceStatus(
                name="AI provider",
                configured=True,
                reachable=bool(available),
                detail=(f"{base_detail} — Ollama reachable" if available else f"{base_detail} — Ollama not reachable"),
            )
        except Exception as exc:  # noqa: BLE001
            return ServiceStatus(
                name="AI provider",
                configured=True,
                reachable=False,
                detail=f"{base_detail} — Ollama probe error: {exc}",
            )

    # Cloud providers (anthropic / openai): do not probe — it would bill.
    return ServiceStatus(
        name="AI provider",
        configured=True,
        reachable=None,
        detail=f"{base_detail} — configured (not probed — would bill)",
    )


def _check_abuseipdb(config: Config, probe: bool) -> ServiceStatus:
    """AbuseIPDB — configured if its key is set. Never probed (burns quota)."""
    configured = bool(config.abuseipdb_api_key)
    if not configured:
        return ServiceStatus(
            name="AbuseIPDB",
            configured=False,
            reachable=None,
            detail="no API key (set VEX_ABUSEIPDB_API_KEY)",
        )
    detail = "key present, not probed (preserves quota)" if probe else "key present (not probed — config-only)"
    return ServiceStatus(name="AbuseIPDB", configured=True, reachable=None, detail=detail)


def _check_shodan(config: Config, probe: bool) -> ServiceStatus:
    """Shodan — configured if its key is set. Never probed (burns quota)."""
    configured = bool(config.shodan_api_key)
    if not configured:
        return ServiceStatus(
            name="Shodan",
            configured=False,
            reachable=None,
            detail="no API key (set VEX_SHODAN_API_KEY)",
        )
    detail = "key present, not probed (preserves quota)" if probe else "key present (not probed — config-only)"
    return ServiceStatus(name="Shodan", configured=True, reachable=None, detail=detail)


def _check_misp(config: Config, probe: bool) -> ServiceStatus:
    """MISP — configured if both url + api_key. Probe getVersion endpoint.

    Catches all exceptions and reports reachable=False + the error string.
    The MISP API key is never logged or included in the detail.
    """
    url = config.misp_url
    api_key = config.misp_api_key
    configured = bool(url and api_key)

    if not configured:
        missing = []
        if not url:
            missing.append("misp_url")
        if not api_key:
            missing.append("misp_api_key")
        return ServiceStatus(
            name="MISP",
            configured=False,
            reachable=None,
            detail=f"not configured (missing: {', '.join(missing)})",
        )

    if not probe:
        return ServiceStatus(
            name="MISP",
            configured=True,
            reachable=None,
            detail=f"configured ({url}) — not probed (config-only)",
        )

    endpoint = f"{url.rstrip('/')}/servers/getVersion"
    try:
        resp = httpx.get(
            endpoint,
            headers={
                "Authorization": api_key,
                "Accept": "application/json",
            },
            verify=config.enrichment.misp_verify_tls,
            timeout=PROBE_TIMEOUT_S,
        )
        if resp.status_code == 200:
            version = ""
            try:
                version = str(resp.json().get("version", "")).strip()
            except Exception:  # noqa: BLE001
                version = ""
            detail = f"reachable — version {version}" if version else "reachable (200)"
            return ServiceStatus(name="MISP", configured=True, reachable=True, detail=detail)
        return ServiceStatus(
            name="MISP",
            configured=True,
            reachable=False,
            detail=f"not reachable — {_status_code_class(resp.status_code)}",
        )
    except Exception as exc:  # noqa: BLE001 — surface the silent failure
        return ServiceStatus(
            name="MISP",
            configured=True,
            reachable=False,
            detail=f"error: {exc}",
        )


def _check_opencti(config: Config, probe: bool) -> ServiceStatus:
    """OpenCTI — configured if both url + token. Probe the GraphQL about query.

    Catches all exceptions and reports reachable=False + the error string.
    The OpenCTI token is never logged or included in the detail.
    """
    url = config.opencti_url
    token = config.opencti_token
    configured = bool(url and token)

    if not configured:
        missing = []
        if not url:
            missing.append("opencti_url")
        if not token:
            missing.append("opencti_token")
        return ServiceStatus(
            name="OpenCTI",
            configured=False,
            reachable=None,
            detail=f"not configured (missing: {', '.join(missing)})",
        )

    if not probe:
        return ServiceStatus(
            name="OpenCTI",
            configured=True,
            reachable=None,
            detail=f"configured ({url}) — not probed (config-only)",
        )

    endpoint = f"{url.rstrip('/')}/graphql"
    try:
        resp = httpx.post(
            endpoint,
            json={"query": "{ about { version } }"},
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            verify=config.enrichment.opencti_verify_tls,
            timeout=PROBE_TIMEOUT_S,
        )
        if resp.status_code == 200:
            version = ""
            try:
                version = str(resp.json().get("data", {}).get("about", {}).get("version", "")).strip()
            except Exception:  # noqa: BLE001
                version = ""
            if version:
                return ServiceStatus(
                    name="OpenCTI",
                    configured=True,
                    reachable=True,
                    detail=f"reachable — version {version}",
                )
            return ServiceStatus(
                name="OpenCTI",
                configured=True,
                reachable=False,
                detail="HTTP 200 but no version in response",
            )
        return ServiceStatus(
            name="OpenCTI",
            configured=True,
            reachable=False,
            detail=f"not reachable — {_status_code_class(resp.status_code)}",
        )
    except Exception as exc:  # noqa: BLE001 — surface the silent failure
        return ServiceStatus(
            name="OpenCTI",
            configured=True,
            reachable=False,
            detail=f"error: {exc}",
        )


def run_doctor(config: Config, *, probe: bool = False) -> list[ServiceStatus]:
    """Return a configuration/connectivity status for each external service.

    Config-only by default. When *probe* is True, performs defensive live
    checks where it is safe to do so (no quota-burning, no billing). Never
    raises on an unreachable service and never includes secrets in details.
    """
    return [
        _check_virustotal(config, probe),
        _check_ai(config, probe),
        _check_abuseipdb(config, probe),
        _check_shodan(config, probe),
        _check_misp(config, probe),
        _check_opencti(config, probe),
    ]
