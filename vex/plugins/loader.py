"""Plugin loader — discover and instantiate plugins.

Loads the built-in VirusTotal plugin, then scans ``entry_points``
for third-party enricher plugins registered under the ``vex.plugins``
group.
"""

from __future__ import annotations

import importlib.metadata
import logging

from .registry import PluginRegistry
from .virustotal import VirusTotalPlugin

logger = logging.getLogger("vex.plugins")


def load_plugins() -> PluginRegistry:
    """Create a registry populated with all available plugins."""
    registry = PluginRegistry()

    # Built-in: VirusTotal (always available)
    registry.register(VirusTotalPlugin())

    # Third-party plugins via entry_points
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

    return registry
