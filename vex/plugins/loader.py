"""Plugin loader — discover and instantiate plugins.

Currently loads the built-in VirusTotal plugin. In the future this
will scan ``~/.vex/plugins/`` and ``entry_points`` for third-party
enricher plugins.
"""

from __future__ import annotations

from .registry import PluginRegistry
from .virustotal import VirusTotalPlugin


def load_plugins() -> PluginRegistry:
    """Create a registry populated with all available plugins."""
    registry = PluginRegistry()

    # Built-in: VirusTotal (always available)
    registry.register(VirusTotalPlugin())

    # Future: scan entry_points, ~/.vex/plugins/, config.yaml plugins list
    # for ep in importlib.metadata.entry_points(group="vex.plugins"):
    #     plugin_cls = ep.load()
    #     registry.register(plugin_cls())

    return registry
