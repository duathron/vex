"""Configuration loader: config.yaml + environment variables."""

import os
import stat
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel
from dotenv import load_dotenv

_USER_CONFIG_PATH = Path.home() / ".vex" / "config.yaml"
_DEFAULT_CONFIG_PATH = Path(__file__).parent.parent / "config.yaml"


class RateLimitTier(BaseModel):
    requests_per_minute: int
    requests_per_day: int


class RateLimits(BaseModel):
    free: RateLimitTier = RateLimitTier(requests_per_minute=4, requests_per_day=500)
    premium: RateLimitTier = RateLimitTier(requests_per_minute=1000, requests_per_day=50000)


class ApiConfig(BaseModel):
    key: Optional[str] = None
    tier: str = "free"
    rate_limit: RateLimits = RateLimits()


class ThresholdConfig(BaseModel):
    malicious_min_detections: int = 3
    suspicious_min_detections: int = 1
    min_engines_for_clean: int = 10


class CacheConfig(BaseModel):
    enabled: bool = True
    ttl_hours: int = 24
    db_path: Optional[str] = None


class OutputConfig(BaseModel):
    default_format: str = "json"
    quiet: bool = False


def _ensure_dir(path: Path) -> None:
    """Create directory with restrictive permissions (owner-only)."""
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(stat.S_IRWXU)  # 0o700


class Config(BaseModel):
    api: ApiConfig = ApiConfig()
    thresholds: ThresholdConfig = ThresholdConfig()
    cache: CacheConfig = CacheConfig()
    output: OutputConfig = OutputConfig()

    @property
    def api_key(self) -> str:
        key = os.getenv("VT_API_KEY") or self.api.key
        if not key:
            raise ValueError(
                "No VirusTotal API key found.\n"
                "  Option 1: Use --api-key flag (vex triage IOC --api-key YOUR_KEY)\n"
                "  Option 2: Set environment variable VT_API_KEY\n"
                "  Option 3: Run 'vex config set-api-key YOUR_KEY' to save permanently"
            )
        return key

    @property
    def is_premium(self) -> bool:
        return self.api.tier.lower() == "premium"

    @property
    def rate_limit(self) -> RateLimitTier:
        return self.api.rate_limit.premium if self.is_premium else self.api.rate_limit.free

    @property
    def cache_db_path(self) -> Path:
        if self.cache.db_path:
            return Path(self.cache.db_path)
        default = Path.home() / ".vex" / "cache.db"
        _ensure_dir(default.parent)
        return default


def load_config(config_path: Optional[Path] = None) -> Config:
    load_dotenv()
    # Priority: explicit path > user config > default config
    if config_path:
        path = config_path
    elif _USER_CONFIG_PATH.exists():
        path = _USER_CONFIG_PATH
    elif _DEFAULT_CONFIG_PATH.exists():
        path = _DEFAULT_CONFIG_PATH
    else:
        return Config()

    with open(path) as f:
        data = yaml.safe_load(f) or {}
    return Config.model_validate(data)


def save_config(config: Config) -> Path:
    """Save config to user's ~/.vex/config.yaml."""
    _ensure_dir(_USER_CONFIG_PATH.parent)
    data = config.model_dump(exclude_defaults=False)
    with open(_USER_CONFIG_PATH, "w") as f:
        yaml.safe_dump(data, f, default_flow_style=False)
    _USER_CONFIG_PATH.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0o600
    return _USER_CONFIG_PATH
