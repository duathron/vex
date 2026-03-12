"""Plugin registry — discover, register, and look up enricher plugins."""

from __future__ import annotations

from typing import Optional

from ..enrichers.protocol import EnricherProtocol


class PluginRegistry:
    """Central registry for enricher plugins.

    Usage::

        registry = PluginRegistry()
        registry.register(my_plugin)
        plugin = registry.get_plugin("ipv4")
    """

    def __init__(self) -> None:
        self._plugins: list[EnricherProtocol] = []

    def register(self, plugin: EnricherProtocol) -> None:
        """Register an enricher plugin instance."""
        if not isinstance(plugin, EnricherProtocol):
            raise TypeError(
                f"Plugin must implement EnricherProtocol, got {type(plugin).__name__}"
            )
        self._plugins.append(plugin)

    def get_plugin(self, ioc_type: str) -> Optional[EnricherProtocol]:
        """Return the first plugin that supports the given IOC type."""
        for plugin in self._plugins:
            if ioc_type in plugin.supported_ioc_types:
                return plugin
        return None

    def get_all_plugins(self, ioc_type: str) -> list[EnricherProtocol]:
        """Return ALL plugins that support the given IOC type."""
        return [p for p in self._plugins if ioc_type in p.supported_ioc_types]

    @property
    def plugins(self) -> list[EnricherProtocol]:
        return list(self._plugins)

    def __len__(self) -> int:
        return len(self._plugins)
