"""Tests for Phase 1 plugin-registry dispatch plumbing.

All tests are offline — no real VirusTotal calls are made.
VTClient and enricher module functions are monkeypatched throughout.
"""

from __future__ import annotations

import threading
from unittest.mock import MagicMock, patch

from vex.enrichers.protocol import EnricherProtocol
from vex.plugins.loader import load_plugins
from vex.plugins.registry import PluginRegistry
from vex.plugins.virustotal import VirusTotalPlugin

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _make_triage_result():
    """Build a minimal TriageResult-like MagicMock."""
    from vex.models import TriageResult

    result = MagicMock(spec=TriageResult)
    result.model_dump.return_value = {}
    return result


def _make_investigate_result():
    from vex.models import InvestigateResult

    result = MagicMock(spec=InvestigateResult)
    result.model_dump.return_value = {}
    return result


def _dummy_config():
    """Return a Config instance with a fake API key."""
    from vex.config import Config

    cfg = Config()
    cfg.api.key = "test-fake-key-00000000"
    return cfg


# ---------------------------------------------------------------------------
# Task 1 — VirusTotalPlugin: lazy, reused, thread-safe client
# ---------------------------------------------------------------------------


class TestVirusTotalPluginClientReuse:
    """The same VTClient must be returned on every call within one plugin instance."""

    def test_client_created_once_across_two_triage_calls(self, monkeypatch):
        """VTClient constructor must run exactly once even across two triage calls."""
        config = _dummy_config()
        fake_result = _make_triage_result()

        # Patch VTClient to count instantiations
        mock_client_instance = MagicMock()
        mock_client_instance.__enter__ = MagicMock(return_value=mock_client_instance)
        mock_client_instance.__exit__ = MagicMock(return_value=False)

        constructor_calls = []

        def fake_vtclient(cfg):
            constructor_calls.append(cfg)
            return mock_client_instance

        # Patch the enricher module used for ipv4
        with patch("vex.plugins.virustotal.VTClient", side_effect=fake_vtclient):
            with patch("vex.plugins.virustotal.ip_enricher") as mock_ip:
                mock_ip.triage.return_value = fake_result

                plugin = VirusTotalPlugin()
                plugin.triage("8.8.8.8", "ipv4", config)
                plugin.triage("1.1.1.1", "ipv4", config)

        # Constructor must have been called exactly once
        assert len(constructor_calls) == 1

    def test_close_resets_client_so_next_call_creates_new_one(self, monkeypatch):
        """After close(), the next triage call must create a fresh VTClient."""
        config = _dummy_config()
        fake_result = _make_triage_result()

        mock_client_instance = MagicMock()
        mock_client_instance.__enter__ = MagicMock(return_value=mock_client_instance)
        mock_client_instance.__exit__ = MagicMock(return_value=False)

        constructor_calls = []

        def fake_vtclient(cfg):
            constructor_calls.append(cfg)
            return mock_client_instance

        with patch("vex.plugins.virustotal.VTClient", side_effect=fake_vtclient):
            with patch("vex.plugins.virustotal.ip_enricher") as mock_ip:
                mock_ip.triage.return_value = fake_result

                plugin = VirusTotalPlugin()
                plugin.triage("8.8.8.8", "ipv4", config)  # creates client #1
                plugin.close()  # resets to None
                plugin.triage("1.1.1.1", "ipv4", config)  # creates client #2

        assert len(constructor_calls) == 2

    def test_lazy_init_is_thread_safe(self, monkeypatch):
        """Concurrent calls must not create more than one VTClient."""
        config = _dummy_config()
        fake_result = _make_triage_result()

        # Simulate a slow constructor to expose races
        import time

        constructor_calls = []
        lock = threading.Lock()

        mock_client_instance = MagicMock()
        mock_client_instance.__enter__ = MagicMock(return_value=mock_client_instance)
        mock_client_instance.__exit__ = MagicMock(return_value=False)

        def slow_vtclient(cfg):
            time.sleep(0.01)
            with lock:
                constructor_calls.append(cfg)
            return mock_client_instance

        errors: list[Exception] = []

        with patch("vex.plugins.virustotal.VTClient", side_effect=slow_vtclient):
            with patch("vex.plugins.virustotal.ip_enricher") as mock_ip:
                mock_ip.triage.return_value = fake_result

                plugin = VirusTotalPlugin()

                def worker():
                    try:
                        plugin.triage("8.8.8.8", "ipv4", config)
                    except Exception as exc:
                        errors.append(exc)

                threads = [threading.Thread(target=worker) for _ in range(8)]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()

        assert not errors, f"Thread errors: {errors}"
        assert len(constructor_calls) == 1, f"Expected 1 VTClient construction, got {len(constructor_calls)}"


# ---------------------------------------------------------------------------
# Task 1 — VirusTotalPlugin: investigate delegates correctly
# ---------------------------------------------------------------------------


class TestVirusTotalPluginInvestigate:
    def test_investigate_reuses_same_client_as_triage(self, monkeypatch):
        """triage and investigate on the same plugin share one VTClient."""
        config = _dummy_config()
        t_result = _make_triage_result()
        i_result = _make_investigate_result()

        mock_client_instance = MagicMock()
        mock_client_instance.__enter__ = MagicMock(return_value=mock_client_instance)
        mock_client_instance.__exit__ = MagicMock(return_value=False)

        constructor_calls = []

        def fake_vtclient(cfg):
            constructor_calls.append(cfg)
            return mock_client_instance

        with patch("vex.plugins.virustotal.VTClient", side_effect=fake_vtclient):
            with patch("vex.plugins.virustotal.ip_enricher") as mock_ip:
                mock_ip.triage.return_value = t_result
                mock_ip.investigate.return_value = i_result

                plugin = VirusTotalPlugin()
                plugin.triage("8.8.8.8", "ipv4", config)
                plugin.investigate("8.8.8.8", "ipv4", config)

        assert len(constructor_calls) == 1


# ---------------------------------------------------------------------------
# Task 1 — VirusTotalPlugin: protocol compliance
# ---------------------------------------------------------------------------


class TestVirusTotalPluginProtocol:
    def test_isinstance_enricher_protocol(self):
        assert isinstance(VirusTotalPlugin(), EnricherProtocol)

    def test_supported_ioc_types(self):
        plugin = VirusTotalPlugin()
        for ioc_type in ("md5", "sha1", "sha256", "ipv4", "ipv6", "domain", "url"):
            assert ioc_type in plugin.supported_ioc_types

    def test_name(self):
        assert VirusTotalPlugin().name == "VirusTotal"


# ---------------------------------------------------------------------------
# Task 2 — PluginRegistry: close() and context-manager
# ---------------------------------------------------------------------------


class TestPluginRegistryLifecycle:
    def test_close_calls_close_on_plugins_that_have_it(self):
        """PluginRegistry.close() must call close() on any plugin that has it."""
        registry = PluginRegistry()

        plugin_with_close = MagicMock(spec=EnricherProtocol)
        plugin_with_close.name = "WithClose"
        plugin_with_close.supported_ioc_types = ["ipv4"]
        plugin_with_close.close = MagicMock()

        # Register it directly, bypassing the isinstance check by using the real mock
        registry._plugins.append(plugin_with_close)

        registry.close()
        plugin_with_close.close.assert_called_once()

    def test_close_ignores_plugins_without_close(self):
        """PluginRegistry.close() must not raise when a plugin has no close()."""
        registry = PluginRegistry()

        plain_plugin = MagicMock(spec=EnricherProtocol)
        plain_plugin.name = "Plain"
        plain_plugin.supported_ioc_types = ["ipv4"]
        # No .close attribute — spec=EnricherProtocol excludes it
        registry._plugins.append(plain_plugin)

        registry.close()  # must not raise

    def test_context_manager_calls_close(self):
        """__exit__ must trigger close()."""
        registry = PluginRegistry()

        closed = []
        plugin = MagicMock(spec=EnricherProtocol)
        plugin.name = "P"
        plugin.supported_ioc_types = ["ipv4"]
        plugin.close = MagicMock(side_effect=lambda: closed.append(True))
        registry._plugins.append(plugin)

        with registry:
            assert not closed  # not closed yet

        assert closed  # closed on exit

    def test_load_plugins_context_manager_closes_vt_plugin(self):
        """with load_plugins() as r: should close the VirusTotalPlugin on exit."""
        close_calls = []

        with patch(
            "vex.plugins.virustotal.VirusTotalPlugin.close", side_effect=lambda: close_calls.append(True)
        ) as mock_close:
            with load_plugins() as registry:
                assert len(registry.plugins) >= 1

        # close() must have been called (once per VT plugin instance)
        assert mock_close.called


# ---------------------------------------------------------------------------
# Task 2 — PluginRegistry: get_plugin
# ---------------------------------------------------------------------------


class TestPluginRegistryGetPlugin:
    def _make_plugin(self, types: list[str]) -> MagicMock:
        p = MagicMock(spec=EnricherProtocol)
        p.name = "Fake"
        p.supported_ioc_types = types
        return p

    def test_get_plugin_returns_vt_for_supported_type(self):
        registry = PluginRegistry()
        plugin = self._make_plugin(["ipv4", "domain"])
        registry._plugins.append(plugin)
        assert registry.get_plugin("ipv4") is plugin

    def test_get_plugin_returns_none_for_unsupported_type(self):
        registry = PluginRegistry()
        plugin = self._make_plugin(["ipv4"])
        registry._plugins.append(plugin)
        assert registry.get_plugin("foobar") is None

    def test_load_plugins_returns_vt_plugin_for_ipv4(self):
        with load_plugins() as registry:
            plugin = registry.get_plugin("ipv4")
            assert plugin is not None
            assert plugin.name == "VirusTotal"

    def test_load_plugins_returns_none_for_unknown_type(self):
        with load_plugins() as registry:
            plugin = registry.get_plugin("__nonexistent_type__")
            assert plugin is None
