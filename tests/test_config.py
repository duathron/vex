"""Tests for vex.config — deterministic, no network.

Uses tmp_path and monkeypatch to avoid reading the user's real config.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from vex.config import (
    AIConfig,
    ApiConfig,
    CacheConfig,
    Config,
    EnrichmentConfig,
    OutputConfig,
    PluginConfig,
    RateLimits,
    RateLimitTier,
    ThresholdConfig,
    UpdateCheckConfig,
    load_config,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_yaml(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        yaml.safe_dump(data, f)


# ---------------------------------------------------------------------------
# Default config (no file, no env)
# ---------------------------------------------------------------------------


class TestDefaults:
    def test_load_config_no_file_returns_defaults(self, tmp_path: Path, monkeypatch) -> None:
        # Point both config path variables at non-existent files.
        monkeypatch.setattr("vex.config._USER_CONFIG_PATH", tmp_path / "missing.yaml")
        monkeypatch.setattr("vex.config._DEFAULT_CONFIG_PATH", tmp_path / "missing_default.yaml")
        cfg = load_config()
        assert isinstance(cfg, Config)

    def test_default_api_tier_is_free(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr("vex.config._USER_CONFIG_PATH", tmp_path / "missing.yaml")
        monkeypatch.setattr("vex.config._DEFAULT_CONFIG_PATH", tmp_path / "missing_default.yaml")
        cfg = load_config()
        assert cfg.api.tier == "free"

    def test_default_cache_enabled(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr("vex.config._USER_CONFIG_PATH", tmp_path / "missing.yaml")
        monkeypatch.setattr("vex.config._DEFAULT_CONFIG_PATH", tmp_path / "missing_default.yaml")
        cfg = load_config()
        assert cfg.cache.enabled is True

    def test_default_cache_ttl_is_24(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr("vex.config._USER_CONFIG_PATH", tmp_path / "missing.yaml")
        monkeypatch.setattr("vex.config._DEFAULT_CONFIG_PATH", tmp_path / "missing_default.yaml")
        cfg = load_config()
        assert cfg.cache.ttl_hours == 24

    def test_default_output_format_is_json(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr("vex.config._USER_CONFIG_PATH", tmp_path / "missing.yaml")
        monkeypatch.setattr("vex.config._DEFAULT_CONFIG_PATH", tmp_path / "missing_default.yaml")
        cfg = load_config()
        assert cfg.output.default_format == "json"

    def test_default_thresholds(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr("vex.config._USER_CONFIG_PATH", tmp_path / "missing.yaml")
        monkeypatch.setattr("vex.config._DEFAULT_CONFIG_PATH", tmp_path / "missing_default.yaml")
        cfg = load_config()
        assert cfg.thresholds.malicious_min_detections == 3
        assert cfg.thresholds.suspicious_min_detections == 1
        assert cfg.thresholds.min_engines_for_clean == 10

    def test_default_free_rate_limits(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr("vex.config._USER_CONFIG_PATH", tmp_path / "missing.yaml")
        monkeypatch.setattr("vex.config._DEFAULT_CONFIG_PATH", tmp_path / "missing_default.yaml")
        cfg = load_config()
        assert cfg.api.rate_limit.free.requests_per_minute == 4
        assert cfg.api.rate_limit.free.requests_per_day == 500


# ---------------------------------------------------------------------------
# File-based config loading
# ---------------------------------------------------------------------------


class TestFileLoading:
    def test_explicit_path_loaded(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "custom.yaml"
        _write_yaml(cfg_file, {"api": {"tier": "premium"}})
        cfg = load_config(config_path=cfg_file)
        assert cfg.api.tier == "premium"

    def test_explicit_path_overrides_user_config(self, tmp_path: Path, monkeypatch) -> None:
        user_cfg = tmp_path / "user.yaml"
        _write_yaml(user_cfg, {"api": {"tier": "free"}})
        monkeypatch.setattr("vex.config._USER_CONFIG_PATH", user_cfg)

        explicit_cfg = tmp_path / "explicit.yaml"
        _write_yaml(explicit_cfg, {"api": {"tier": "premium"}})

        cfg = load_config(config_path=explicit_cfg)
        assert cfg.api.tier == "premium"

    def test_user_config_loaded_when_exists(self, tmp_path: Path, monkeypatch) -> None:
        user_cfg = tmp_path / "user.yaml"
        _write_yaml(user_cfg, {"api": {"tier": "premium"}})
        monkeypatch.setattr("vex.config._USER_CONFIG_PATH", user_cfg)
        monkeypatch.setattr("vex.config._DEFAULT_CONFIG_PATH", tmp_path / "missing_default.yaml")
        cfg = load_config()
        assert cfg.api.tier == "premium"

    def test_default_config_loaded_as_fallback(self, tmp_path: Path, monkeypatch) -> None:
        default_cfg = tmp_path / "default.yaml"
        _write_yaml(default_cfg, {"output": {"default_format": "rich"}})
        monkeypatch.setattr("vex.config._USER_CONFIG_PATH", tmp_path / "missing_user.yaml")
        monkeypatch.setattr("vex.config._DEFAULT_CONFIG_PATH", default_cfg)
        cfg = load_config()
        assert cfg.output.default_format == "rich"

    def test_user_config_takes_priority_over_default(self, tmp_path: Path, monkeypatch) -> None:
        user_cfg = tmp_path / "user.yaml"
        _write_yaml(user_cfg, {"output": {"default_format": "rich"}})
        default_cfg = tmp_path / "default.yaml"
        _write_yaml(default_cfg, {"output": {"default_format": "json"}})

        monkeypatch.setattr("vex.config._USER_CONFIG_PATH", user_cfg)
        monkeypatch.setattr("vex.config._DEFAULT_CONFIG_PATH", default_cfg)
        cfg = load_config()
        assert cfg.output.default_format == "rich"

    def test_empty_yaml_file_returns_defaults(self, tmp_path: Path) -> None:
        empty_cfg = tmp_path / "empty.yaml"
        empty_cfg.write_text("")
        cfg = load_config(config_path=empty_cfg)
        assert isinstance(cfg, Config)
        assert cfg.api.tier == "free"

    def test_partial_yaml_merges_defaults(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "partial.yaml"
        _write_yaml(cfg_file, {"cache": {"ttl_hours": 48}})
        cfg = load_config(config_path=cfg_file)
        assert cfg.cache.ttl_hours == 48
        assert cfg.cache.enabled is True  # default preserved

    def test_nested_threshold_config(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "thresh.yaml"
        _write_yaml(cfg_file, {"thresholds": {"malicious_min_detections": 5}})
        cfg = load_config(config_path=cfg_file)
        assert cfg.thresholds.malicious_min_detections == 5


# ---------------------------------------------------------------------------
# Environment variable priority
# ---------------------------------------------------------------------------


class TestEnvVarPriority:
    def test_vt_api_key_from_env(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setenv("VT_API_KEY", "env-test-key-123")
        monkeypatch.setattr("vex.config._USER_CONFIG_PATH", tmp_path / "missing.yaml")
        monkeypatch.setattr("vex.config._DEFAULT_CONFIG_PATH", tmp_path / "missing.yaml")
        cfg = load_config()
        assert cfg.api_key == "env-test-key-123"

    def test_vt_api_key_env_overrides_file(self, tmp_path: Path, monkeypatch) -> None:
        cfg_file = tmp_path / "cfg.yaml"
        _write_yaml(cfg_file, {"api": {"key": "file-key"}})
        monkeypatch.setenv("VT_API_KEY", "env-key")
        cfg = load_config(config_path=cfg_file)
        # Env var takes priority in the api_key property
        assert cfg.api_key == "env-key"

    def test_api_key_from_file_when_no_env(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.delenv("VT_API_KEY", raising=False)
        cfg_file = tmp_path / "cfg.yaml"
        _write_yaml(cfg_file, {"api": {"key": "file-key-xyz"}})
        cfg = load_config(config_path=cfg_file)
        assert cfg.api_key == "file-key-xyz"

    def test_missing_api_key_raises(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.delenv("VT_API_KEY", raising=False)
        monkeypatch.setattr("vex.config._USER_CONFIG_PATH", tmp_path / "missing.yaml")
        monkeypatch.setattr("vex.config._DEFAULT_CONFIG_PATH", tmp_path / "missing.yaml")
        cfg = load_config()
        with pytest.raises(ValueError, match="No VirusTotal API key"):
            _ = cfg.api_key

    def test_vex_ai_api_key_from_env(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setenv("VEX_AI_API_KEY", "ai-key-from-env")
        monkeypatch.setattr("vex.config._USER_CONFIG_PATH", tmp_path / "missing.yaml")
        monkeypatch.setattr("vex.config._DEFAULT_CONFIG_PATH", tmp_path / "missing.yaml")
        cfg = load_config()
        assert cfg.ai_api_key == "ai-key-from-env"

    def test_vex_ai_api_key_absent_returns_none(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.delenv("VEX_AI_API_KEY", raising=False)
        monkeypatch.setattr("vex.config._USER_CONFIG_PATH", tmp_path / "missing.yaml")
        monkeypatch.setattr("vex.config._DEFAULT_CONFIG_PATH", tmp_path / "missing.yaml")
        cfg = load_config()
        assert cfg.ai_api_key is None


# ---------------------------------------------------------------------------
# Config model properties
# ---------------------------------------------------------------------------


class TestConfigProperties:
    def test_is_premium_false_for_free_tier(self) -> None:
        cfg = Config(api=ApiConfig(tier="free"))
        assert cfg.is_premium is False

    def test_is_premium_true_for_premium_tier(self) -> None:
        cfg = Config(api=ApiConfig(tier="premium"))
        assert cfg.is_premium is True

    def test_is_premium_case_insensitive(self) -> None:
        cfg = Config(api=ApiConfig(tier="PREMIUM"))
        assert cfg.is_premium is True

    def test_rate_limit_returns_free_for_free_tier(self) -> None:
        cfg = Config(api=ApiConfig(tier="free"))
        assert cfg.rate_limit.requests_per_minute == 4

    def test_rate_limit_returns_premium_for_premium_tier(self) -> None:
        cfg = Config(api=ApiConfig(tier="premium"))
        assert cfg.rate_limit.requests_per_minute == 1000

    def test_cache_db_path_custom_string(self, tmp_path: Path) -> None:
        custom = str(tmp_path / "my_cache.db")
        cfg = Config(cache=CacheConfig(db_path=custom))
        assert cfg.cache_db_path == Path(custom)


# ---------------------------------------------------------------------------
# Sub-model defaults (unit tests, no file I/O)
# ---------------------------------------------------------------------------


class TestSubModelDefaults:
    def test_ai_config_defaults(self) -> None:
        ai = AIConfig()
        assert ai.provider == "none"
        assert ai.max_tokens == 500
        assert ai.temperature == 0.3
        assert ai.local_only is False
        assert ai.cache_ttl_hours == 72

    def test_threshold_config_defaults(self) -> None:
        t = ThresholdConfig()
        assert t.malicious_min_detections == 3
        assert t.suspicious_min_detections == 1
        assert t.min_engines_for_clean == 10

    def test_output_config_defaults(self) -> None:
        o = OutputConfig()
        assert o.default_format == "json"
        assert o.quiet is False

    def test_plugin_config_defaults(self) -> None:
        p = PluginConfig()
        assert p.load_local is False

    def test_update_check_config_defaults(self) -> None:
        u = UpdateCheckConfig()
        assert u.enabled is True
        assert u.check_interval_hours == 24

    def test_enrichment_config_defaults(self) -> None:
        e = EnrichmentConfig()
        assert e.whois_enabled is True

    def test_rate_limit_tier_model(self) -> None:
        t = RateLimitTier(requests_per_minute=10, requests_per_day=1000)
        assert t.requests_per_minute == 10
        assert t.requests_per_day == 1000

    def test_rate_limits_free_defaults(self) -> None:
        rl = RateLimits()
        assert rl.free.requests_per_minute == 4
        assert rl.free.requests_per_day == 500

    def test_rate_limits_premium_defaults(self) -> None:
        rl = RateLimits()
        assert rl.premium.requests_per_minute == 1000
        assert rl.premium.requests_per_day == 50000
