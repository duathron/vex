"""VirusTotal API v3 client with rate limiting and retry logic."""

import base64
import threading
import time
from typing import Any, Optional

import httpx

from .config import Config

VT_BASE = "https://www.virustotal.com/api/v3"


class RateLimiter:
    """Thread-safe token bucket rate limiter."""

    def __init__(self, requests_per_minute: int):
        self._interval = 60.0 / requests_per_minute
        self._last_call: float = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_call
            if elapsed < self._interval:
                time.sleep(self._interval - elapsed)
            self._last_call = time.monotonic()


class VTClient:
    def __init__(self, config: Config):
        self._config = config
        self._limiter = RateLimiter(config.rate_limit.requests_per_minute)
        self._client = httpx.Client(
            base_url=VT_BASE,
            headers={"x-apikey": config.api_key, "Accept": "application/json"},
            timeout=30.0,
            verify=True,
        )

    def _get(self, path: str, params: Optional[dict] = None) -> dict[str, Any]:
        self._limiter.wait()
        resp = self._client.get(path, params=params)
        if resp.status_code == 404:
            return {}
        if resp.status_code == 429:
            time.sleep(60)
            self._limiter.wait()
            resp = self._client.get(path, params=params)
            if resp.status_code == 429:
                raise RuntimeError("VirusTotal rate limit exceeded after retry. Wait and try again.")
        resp.raise_for_status()
        return resp.json()

    def _post(self, path: str, data: dict) -> dict[str, Any]:
        self._limiter.wait()
        resp = self._client.post(path, data=data)
        resp.raise_for_status()
        return resp.json()

    # --- Core lookups ---

    def get_file(self, hash_value: str) -> dict[str, Any]:
        return self._get(f"/files/{hash_value}")

    def get_ip(self, ip: str) -> dict[str, Any]:
        return self._get(f"/ip_addresses/{ip}")

    def get_domain(self, domain: str) -> dict[str, Any]:
        return self._get(f"/domains/{domain}")

    def get_url(self, url: str) -> dict[str, Any]:
        url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
        result = self._get(f"/urls/{url_id}")
        if not result:
            # Not cached yet - submit for analysis
            post_result = self._post("/urls", {"url": url})
            analysis_id = post_result.get("data", {}).get("id", "")
            if analysis_id:
                time.sleep(15)  # Wait for analysis
                result = self._get(f"/analyses/{analysis_id}")
        return result

    # --- Relationship lookups (investigate mode) ---

    def get_file_behaviors(self, hash_value: str, limit: int = 1) -> dict[str, Any]:
        """Sandbox behavior reports (premium tier)."""
        return self._get(f"/files/{hash_value}/behaviours", params={"limit": limit})

    def get_file_contacted_ips(self, hash_value: str, limit: int = 10) -> dict[str, Any]:
        return self._get(f"/files/{hash_value}/contacted_ips", params={"limit": limit})

    def get_file_contacted_domains(self, hash_value: str, limit: int = 10) -> dict[str, Any]:
        return self._get(f"/files/{hash_value}/contacted_domains", params={"limit": limit})

    def get_file_dropped_files(self, hash_value: str, limit: int = 10) -> dict[str, Any]:
        return self._get(f"/files/{hash_value}/dropped_files", params={"limit": limit})

    def get_ip_resolutions(self, ip: str, limit: int = 10) -> dict[str, Any]:
        """Passive DNS: which domains resolved to this IP."""
        return self._get(f"/ip_addresses/{ip}/resolutions", params={"limit": limit})

    def get_ip_communicating_files(self, ip: str, limit: int = 10) -> dict[str, Any]:
        return self._get(f"/ip_addresses/{ip}/communicating_files", params={"limit": limit})

    def get_ip_downloaded_files(self, ip: str, limit: int = 10) -> dict[str, Any]:
        return self._get(f"/ip_addresses/{ip}/downloaded_files", params={"limit": limit})

    def get_domain_resolutions(self, domain: str, limit: int = 10) -> dict[str, Any]:
        """Passive DNS: which IPs this domain resolved to."""
        return self._get(f"/domains/{domain}/resolutions", params={"limit": limit})

    def get_domain_communicating_files(self, domain: str, limit: int = 10) -> dict[str, Any]:
        return self._get(f"/domains/{domain}/communicating_files", params={"limit": limit})

    def get_domain_whois(self, domain: str) -> dict[str, Any]:
        return self._get(f"/domains/{domain}/historical_whois")

    def get_url_related_files(self, url: str, limit: int = 10) -> dict[str, Any]:
        url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
        return self._get(f"/urls/{url_id}/downloaded_files", params={"limit": limit})

    def close(self) -> None:
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
