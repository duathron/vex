"""Configuration loader: config.yaml + environment variables."""

import os
import stat
from pathlib import Path
from typing import Optional

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel

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


class PluginConfig(BaseModel):
    load_local: bool = False  # opt-in ~/.vex/plugins/ scanning


class AIConfig(BaseModel):
    provider: str = "none"  # none | anthropic | openai | ollama
    model: Optional[str] = None  # default per provider
    api_key: Optional[str] = None  # overridden by VEX_AI_API_KEY env
    base_url: Optional[str] = None  # for Ollama: http://localhost:11434
    max_tokens: int = 500
    temperature: float = 0.3
    local_only: bool = False  # when True, reject cloud providers
    cache_ttl_hours: int = 72


class UpdateCheckConfig(BaseModel):
    enabled: bool = True
    check_interval_hours: int = 24


class EnrichmentConfig(BaseModel):
    whois_enabled: bool = True  # Direct WHOIS lookup (requires: pip install vex-ioc[whois])
    abuseipdb_api_key: Optional[str] = None
    abuseipdb_max_age_days: int = 90
    shodan_api_key: Optional[str] = None
    misp_url: Optional[str] = None
    misp_api_key: Optional[str] = None
    misp_verify_tls: bool = True
    opencti_url: Optional[str] = None
    opencti_token: Optional[str] = None
    opencti_verify_tls: bool = True
    stix_tlp_version: str = "1.0"  # "1.0" or "2.0" — controls TLP marking-definition ids in STIX export


def _ensure_dir(path: Path) -> None:
    """Create directory with restrictive permissions (owner-only)."""
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(stat.S_IRWXU)  # 0o700


class Config(BaseModel):
    api: ApiConfig = ApiConfig()
    thresholds: ThresholdConfig = ThresholdConfig()
    cache: CacheConfig = CacheConfig()
    output: OutputConfig = OutputConfig()
    plugins: PluginConfig = PluginConfig()
    update_check: UpdateCheckConfig = UpdateCheckConfig()
    ai: AIConfig = AIConfig()
    enrichment: EnrichmentConfig = EnrichmentConfig()

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
    def ai_api_key(self) -> Optional[str]:
        """AI provider API key: VEX_AI_API_KEY env > config ai.api_key."""
        return os.getenv("VEX_AI_API_KEY") or self.ai.api_key

    @property
    def abuseipdb_api_key(self) -> Optional[str]:
        """AbuseIPDB API key: VEX_ABUSEIPDB_API_KEY env > config enrichment.abuseipdb_api_key."""
        return os.getenv("VEX_ABUSEIPDB_API_KEY") or self.enrichment.abuseipdb_api_key

    @property
    def shodan_api_key(self) -> Optional[str]:
        """Shodan API key: VEX_SHODAN_API_KEY env > config enrichment.shodan_api_key."""
        return os.getenv("VEX_SHODAN_API_KEY") or self.enrichment.shodan_api_key

    @property
    def misp_url(self) -> Optional[str]:
        """MISP base URL: MISP_URL env > config enrichment.misp_url."""
        return os.getenv("MISP_URL") or self.enrichment.misp_url

    @property
    def misp_api_key(self) -> Optional[str]:
        """MISP API key: MISP_API_KEY env > config enrichment.misp_api_key."""
        return os.getenv("MISP_API_KEY") or self.enrichment.misp_api_key

    @property
    def opencti_url(self) -> Optional[str]:
        """OpenCTI base URL: OPENCTI_URL env > config enrichment.opencti_url."""
        return os.getenv("OPENCTI_URL") or self.enrichment.opencti_url

    @property
    def opencti_token(self) -> Optional[str]:
        """OpenCTI API token: OPENCTI_TOKEN env > config enrichment.opencti_token."""
        return os.getenv("OPENCTI_TOKEN") or self.enrichment.opencti_token

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
