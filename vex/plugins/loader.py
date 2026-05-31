"""Plugin loader — discover and instantiate plugins.

Loads the built-in VirusTotal plugin, then scans ``entry_points``
for third-party enricher plugins registered under the ``vex.plugins``
group.

Secondary enrichers (implementing SecondaryEnricherProtocol) are loaded
from the built-in AbuseIPDB plugin and from third-party entry points
registered under the ``vex.secondary_plugins`` group.
"""

from __future__ import annotations

import importlib.metadata
import logging

from .abuseipdb import AbuseIPDBPlugin
from .registry import PluginRegistry
from .virustotal import VirusTotalPlugin

logger = logging.getLogger("vex.plugins")


def load_plugins() -> PluginRegistry:
    """Create a registry populated with all available plugins."""
    registry = PluginRegistry()

    # Built-in primary: VirusTotal (always available)
    registry.register(VirusTotalPlugin())

    # Third-party primary plugins via entry_points
    try:
        eps = importlib.metadata.entry_points(group="vex.plugins")
    except TypeError:
        # Python < 3.12 compat: entry_points() may not support group kwarg
        eps = importlib.metadata.entry_points().get("vex.plugins", [])

    for ep in eps:
        try:
            plugin_cls = ep.load()
            plugin = plugin_cls()
            registry.register(plugin)
            logger.info("Loaded plugin '%s' from entry point '%s'", plugin.name, ep.name)
        except Exception as e:
            logger.warning("Failed to load plugin '%s': %s", ep.name, e)

    # Built-in secondary: AbuseIPDB (always present, no-op without key)
    registry.register_secondary(AbuseIPDBPlugin())

    # Third-party secondary plugins via entry_points
    try:
        sec_eps = importlib.metadata.entry_points(group="vex.secondary_plugins")
    except TypeError:
        sec_eps = importlib.metadata.entry_points().get("vex.secondary_plugins", [])

    for ep in sec_eps:
        try:
            enricher_cls = ep.load()
            enricher = enricher_cls()
            registry.register_secondary(enricher)
            logger.info(
                "Loaded secondary enricher '%s' from entry point '%s'",
                enricher.name,
                ep.name,
            )
        except Exception as e:
            logger.warning("Failed to load secondary enricher '%s': %s", ep.name, e)

    return registry
