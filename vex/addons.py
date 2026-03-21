"""Addon detection and status reporting for vex.

Provides introspection over vex's optional dependency groups so users
can discover what extras are available and which are installed.

Used by:
- ``vex addons`` subcommand (human-readable table)
- ``vex config --show`` addon status section
- ``vex/banner.py`` first-run hint
"""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass
from typing import Optional


@dataclass
class AddonInfo:
    """Status of a single optional addon package."""

    name: str           # package import name (e.g. "anthropic")
    group: str          # extras group (e.g. "ai")
    description: str    # human-readable description
    install_cmd: str    # pip install command for this addon
    installed: bool     # whether the package is importable
    version: Optional[str] = None  # installed version string, or None


# Registry of all known optional addons.
# Tuple: (import_name, extras_group, description, install_command)
_ADDON_REGISTRY: list[tuple[str, str, str, str]] = [
    (
        "anthropic",
        "ai",
        "AI explanations via Claude (Anthropic)",
        "pip install vex-ioc[ai]",
    ),
    (
        "openai",
        "ai",
        "AI explanations via GPT (OpenAI)",
        "pip install vex-ioc[ai]",
    ),
    (
        "whois",
        "core",
        "Direct WHOIS enrichment for domains",
        "included in base install",
    ),
]


def get_addon_status() -> list[AddonInfo]:
    """Return the installation status of all known vex addons.

    Uses ``importlib.util.find_spec()`` for fast, side-effect-free detection.
    Fetches installed version via ``importlib.metadata`` if available.

    Returns:
        List of AddonInfo objects, one per registered addon.
    """
    results: list[AddonInfo] = []
    for import_name, group, description, install_cmd in _ADDON_REGISTRY:
        spec = importlib.util.find_spec(import_name)
        installed = spec is not None
        version: Optional[str] = None
        if installed:
            try:
                import importlib.metadata as meta
                version = meta.version(import_name)
            except Exception:
                pass
        results.append(AddonInfo(
            name=import_name,
            group=group,
            description=description,
            install_cmd=install_cmd,
            installed=installed,
            version=version,
        ))
    return results


def any_ai_addon_installed() -> bool:
    """Return True if at least one AI provider package is installed."""
    return any(
        a.installed for a in get_addon_status() if a.group == "ai"
    )
