"""Async VirusTotal API v3 client for parallel batch processing."""

from __future__ import annotations

import asyncio
import base64
from typing import Any, Optional

import httpx

from .config import Config

VT_BASE = "https://www.virustotal.com/api/v3"


class AsyncRateLimiter:
    """Async-compatible rate limiter using asyncio.Semaphore + sleep."""

    def __init__(self, requests_per_minute: int):
        self._interval = 60.0 / requests_per_minute
        self._semaphore = asyncio.Semaphore(1)
        self._last_call: float = 0.0

    async def acquire(self) -> None:
        async with self._semaphore:
            loop = asyncio.get_running_loop()
            now = loop.time()
            elapsed = now - self._last_call
            if elapsed < self._interval:
                await asyncio.sleep(self._interval - elapsed)
            self._last_call = loop.time()


class AsyncVTClient:
    """Async VirusTotal API client for parallel batch lookups."""

    def __init__(self, config: Config):
        self._config = config
        self._limiter = AsyncRateLimiter(config.rate_limit.requests_per_minute)
        self._client = httpx.AsyncClient(
            base_url=VT_BASE,
            headers={"x-apikey": config.api_key, "Accept": "application/json"},
            timeout=30.0,
            verify=True,
        )

    async def _get(self, path: str, params: Optional[dict] = None) -> dict[str, Any]:
        await self._limiter.acquire()
        resp = await self._client.get(path, params=params)
        if resp.status_code == 404:
            return {}
        if resp.status_code == 429:
            await asyncio.sleep(60)
            await self._limiter.acquire()
            resp = await self._client.get(path, params=params)
        resp.raise_for_status()
        return resp.json()

    async def get_file(self, file_hash: str) -> dict[str, Any]:
        return await self._get(f"/files/{file_hash}")

    async def get_ip(self, ip: str) -> dict[str, Any]:
        return await self._get(f"/ip_addresses/{ip}")

    async def get_domain(self, domain: str) -> dict[str, Any]:
        return await self._get(f"/domains/{domain}")

    async def get_url(self, url: str) -> dict[str, Any]:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        return await self._get(f"/urls/{url_id}")

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()
