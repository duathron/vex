"""Plugin registry — discover, register, and look up enricher plugins."""

from __future__ import annotations

from typing import Optional

from ..enrichers.protocol import EnricherProtocol, SecondaryEnricherProtocol


class PluginRegistry:
    """Central registry for enricher plugins.

    Usage::

        registry = PluginRegistry()
        registry.register(my_plugin)
        plugin = registry.get_plugin("ipv4")

    As a context manager::

        with load_plugins() as registry:
            plugin = registry.get_plugin("ipv4")
            ...
        # plugin clients are closed automatically on exit
    """

    def __init__(self) -> None:
        self._plugins: list[EnricherProtocol] = []
        self._secondary_plugins: list[SecondaryEnricherProtocol] = []

    def register(self, plugin: EnricherProtocol) -> None:
        """Register an enricher plugin instance."""
        if not isinstance(plugin, EnricherProtocol):
            raise TypeError(
                f"Plugin must implement EnricherProtocol, got {type(plugin).__name__}"
            )
        self._plugins.append(plugin)

    def register_secondary(self, enricher: SecondaryEnricherProtocol) -> None:
        """Register a secondary enricher plugin instance."""
        if not isinstance(enricher, SecondaryEnricherProtocol):
            raise TypeError(
                f"Secondary enricher must implement SecondaryEnricherProtocol, got {type(enricher).__name__}"
            )
        self._secondary_plugins.append(enricher)

    def get_plugin(self, ioc_type: str) -> Optional[EnricherProtocol]:
        """Return the first plugin that supports the given IOC type."""
        for plugin in self._plugins:
            if ioc_type in plugin.supported_ioc_types:
                return plugin
        return None

    def get_all_plugins(self, ioc_type: str) -> list[EnricherProtocol]:
        """Return ALL plugins that support the given IOC type."""
        return [p for p in self._plugins if ioc_type in p.supported_ioc_types]

    def get_secondary(self, ioc_type: str) -> list[SecondaryEnricherProtocol]:
        """Return all secondary enrichers that support the given IOC type."""
        return [s for s in self._secondary_plugins if ioc_type in s.supported_ioc_types]

    @property
    def plugins(self) -> list[EnricherProtocol]:
        return list(self._plugins)

    @property
    def secondary_plugins(self) -> list[SecondaryEnricherProtocol]:
        return list(self._secondary_plugins)

    def __len__(self) -> int:
        return len(self._plugins)

    def close(self) -> None:
        """Close any plugin that exposes a ``close()`` method (e.g. VirusTotalPlugin)."""
        for plugin in self._plugins:
            if hasattr(plugin, "close"):
                plugin.close()
        for enricher in self._secondary_plugins:
            if hasattr(enricher, "close"):
                enricher.close()

    def __enter__(self) -> "PluginRegistry":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
