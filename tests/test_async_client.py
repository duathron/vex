"""Tests for vex.async_client — deterministic, no network.

Uses httpx.MockTransport (built into httpx) to intercept all HTTP calls.
Coroutines are driven with asyncio.run() inside plain sync test functions;
no pytest-asyncio or other async plugin is required.

asyncio.sleep is monkeypatched in vex.async_client's module namespace so
that rate-limiter spacing and 429-retry sleeps are instant.
"""

from __future__ import annotations

import asyncio
import base64
from typing import Any, Callable

import httpx
import pytest

import vex.async_client as ac_module
from vex.async_client import AsyncRateLimiter, AsyncVTClient
from vex.config import ApiConfig, Config

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_VT_BASE = "https://www.virustotal.com/api/v3"
_TEST_KEY = "test-api-key-1234"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(requests_per_minute: int = 4) -> Config:
    """Build a minimal Config with a hard-coded API key and given RPM."""
    from vex.config import RateLimits, RateLimitTier

    rate_limits = RateLimits(
        free=RateLimitTier(requests_per_minute=requests_per_minute, requests_per_day=500),
        premium=RateLimitTier(requests_per_minute=1000, requests_per_day=50000),
    )
    return Config(api=ApiConfig(key=_TEST_KEY, tier="free", rate_limit=rate_limits))


def _make_client(
    handler: Callable[[httpx.Request], httpx.Response],
    requests_per_minute: int = 4,
) -> AsyncVTClient:
    """Construct AsyncVTClient and swap its internal httpx.AsyncClient for a mock one."""
    cfg = _make_config(requests_per_minute=requests_per_minute)
    client = AsyncVTClient(cfg)
    client._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url=_VT_BASE,
        headers={"x-apikey": _TEST_KEY, "Accept": "application/json"},
    )
    return client


def _seq_handler(
    responses: list[httpx.Response],
) -> Callable[[httpx.Request], httpx.Response]:
    """Return a handler that yields responses in order."""
    it = iter(responses)

    def handler(request: httpx.Request) -> httpx.Response:
        return next(it)

    return handler


class _SleepRecorder:
    """Async no-op replacement for asyncio.sleep that records all calls."""

    def __init__(self) -> None:
        self.calls: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


def _patch_sleep(monkeypatch: Any) -> _SleepRecorder:
    """Monkeypatch asyncio.sleep in the async_client module; return recorder."""
    recorder = _SleepRecorder()
    monkeypatch.setattr(ac_module.asyncio, "sleep", recorder)
    return recorder


# ---------------------------------------------------------------------------
# AsyncRateLimiter
# ---------------------------------------------------------------------------


class TestAsyncRateLimiter:
    def test_interval_calculation(self) -> None:
        rl = AsyncRateLimiter(requests_per_minute=4)
        assert rl._interval == 15.0

    def test_interval_calculation_premium(self) -> None:
        rl = AsyncRateLimiter(requests_per_minute=1000)
        assert rl._interval == pytest.approx(0.06)

    def test_first_acquire_does_not_sleep(self, monkeypatch: Any) -> None:
        """First call starts from last_call=0 so elapsed is huge — no sleep."""
        recorder = _patch_sleep(monkeypatch)

        async def run():
            rl = AsyncRateLimiter(requests_per_minute=4)
            await rl.acquire()

        asyncio.run(run())
        assert recorder.calls == []

    def test_second_acquire_sleeps_with_positive_delay(self, monkeypatch: Any) -> None:
        """Back-to-back acquires: second call must sleep for a positive interval."""
        recorder = _patch_sleep(monkeypatch)

        async def run():
            rl = AsyncRateLimiter(requests_per_minute=4)
            await rl.acquire()
            # Reset last_call to 'now' so the second acquire sees elapsed ≈ 0
            loop = asyncio.get_running_loop()
            rl._last_call = loop.time()
            await rl.acquire()

        asyncio.run(run())
        assert len(recorder.calls) == 1
        assert recorder.calls[0] > 0

    def test_spacing_sleep_less_than_interval(self, monkeypatch: Any) -> None:
        """The spacing sleep must be ≤ interval (can't overshoot)."""
        recorder = _patch_sleep(monkeypatch)

        async def run():
            rl = AsyncRateLimiter(requests_per_minute=4)
            await rl.acquire()
            loop = asyncio.get_running_loop()
            rl._last_call = loop.time()
            await rl.acquire()

        asyncio.run(run())
        assert recorder.calls[0] <= 15.0


# ---------------------------------------------------------------------------
# AsyncVTClient — 200 OK paths
# ---------------------------------------------------------------------------


class TestAsyncVTClientOKPaths:
    def test_get_file_correct_path_and_returns_json(self, monkeypatch: Any) -> None:
        recorded: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            recorded.append(str(request.url))
            return httpx.Response(200, json={"data": {"id": "abc123"}})

        _patch_sleep(monkeypatch)
        client = _make_client(handler)

        async def run():
            result = await client.get_file("abc123")
            await client.close()
            return result

        result = asyncio.run(run())
        assert result == {"data": {"id": "abc123"}}
        assert "/files/abc123" in recorded[0]

    def test_get_ip_correct_path_and_returns_json(self, monkeypatch: Any) -> None:
        recorded: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            recorded.append(str(request.url))
            return httpx.Response(200, json={"data": {"id": "1.2.3.4"}})

        _patch_sleep(monkeypatch)
        client = _make_client(handler)

        async def run():
            result = await client.get_ip("1.2.3.4")
            await client.close()
            return result

        result = asyncio.run(run())
        assert result == {"data": {"id": "1.2.3.4"}}
        assert "/ip_addresses/1.2.3.4" in recorded[0]

    def test_get_domain_correct_path_and_returns_json(self, monkeypatch: Any) -> None:
        recorded: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            recorded.append(str(request.url))
            return httpx.Response(200, json={"data": {"id": "evil.com"}})

        _patch_sleep(monkeypatch)
        client = _make_client(handler)

        async def run():
            result = await client.get_domain("evil.com")
            await client.close()
            return result

        result = asyncio.run(run())
        assert result == {"data": {"id": "evil.com"}}
        assert "/domains/evil.com" in recorded[0]

    def test_get_url_correct_path_and_url_id_encoding(self, monkeypatch: Any) -> None:
        """get_url must build a VT url-id: unpadded base64-urlsafe of the URL."""
        test_url = "https://example.com/malware"
        expected_url_id = base64.urlsafe_b64encode(test_url.encode()).decode().rstrip("=")
        recorded: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            recorded.append(str(request.url))
            return httpx.Response(200, json={"data": {"id": expected_url_id}})

        _patch_sleep(monkeypatch)
        client = _make_client(handler)

        async def run():
            result = await client.get_url(test_url)
            await client.close()
            return result

        result = asyncio.run(run())
        assert result == {"data": {"id": expected_url_id}}
        assert f"/urls/{expected_url_id}" in recorded[0]
        # Confirm no padding characters
        assert "=" not in expected_url_id

    def test_get_url_no_padding_in_url_id(self, monkeypatch: Any) -> None:
        """URL-id must never contain '=' padding characters."""
        # Use a URL whose base64 would require padding
        test_url = "http://x.co"
        raw_b64 = base64.urlsafe_b64encode(test_url.encode()).decode()
        assert "=" in raw_b64, "precondition: raw b64 has padding"

        recorded: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            recorded.append(str(request.url))
            return httpx.Response(200, json={"data": {}})

        _patch_sleep(monkeypatch)
        client = _make_client(handler)

        async def run():
            await client.get_url(test_url)
            await client.close()

        asyncio.run(run())
        path = recorded[0]
        assert "=" not in path


# ---------------------------------------------------------------------------
# AsyncVTClient — 404 → empty dict
# ---------------------------------------------------------------------------


class TestAsyncVTClient404:
    def test_get_file_404_returns_empty_dict(self, monkeypatch: Any) -> None:
        _patch_sleep(monkeypatch)
        client = _make_client(lambda _req: httpx.Response(404))

        async def run():
            result = await client.get_file("deadbeef")
            await client.close()
            return result

        assert asyncio.run(run()) == {}

    def test_get_ip_404_returns_empty_dict(self, monkeypatch: Any) -> None:
        _patch_sleep(monkeypatch)
        client = _make_client(lambda _req: httpx.Response(404))

        async def run():
            result = await client.get_ip("10.0.0.1")
            await client.close()
            return result

        assert asyncio.run(run()) == {}

    def test_get_domain_404_returns_empty_dict(self, monkeypatch: Any) -> None:
        _patch_sleep(monkeypatch)
        client = _make_client(lambda _req: httpx.Response(404))

        async def run():
            result = await client.get_domain("notfound.invalid")
            await client.close()
            return result

        assert asyncio.run(run()) == {}

    def test_get_url_404_returns_empty_dict(self, monkeypatch: Any) -> None:
        _patch_sleep(monkeypatch)
        client = _make_client(lambda _req: httpx.Response(404))

        async def run():
            result = await client.get_url("https://gone.example.com/")
            await client.close()
            return result

        assert asyncio.run(run()) == {}


# ---------------------------------------------------------------------------
# AsyncVTClient — 429 retry
# ---------------------------------------------------------------------------


class TestAsyncVTClient429Retry:
    def test_429_retries_once_and_returns_second_response(self, monkeypatch: Any) -> None:
        """On HTTP 429, _get must sleep and retry once; the second response is returned."""
        recorder = _patch_sleep(monkeypatch)
        payload = {"data": {"id": "retry-result"}}
        handler = _seq_handler(
            [
                httpx.Response(429),
                httpx.Response(200, json=payload),
            ]
        )
        client = _make_client(handler)

        async def run():
            result = await client.get_file("abc123")
            await client.close()
            return result

        result = asyncio.run(run())
        assert result == payload
        # The 60-second retry sleep must have been called
        assert 60 in recorder.calls

    def test_429_sleep_is_called_with_60s(self, monkeypatch: Any) -> None:
        recorder = _patch_sleep(monkeypatch)
        handler = _seq_handler(
            [
                httpx.Response(429),
                httpx.Response(200, json={}),
            ]
        )
        client = _make_client(handler)

        async def run():
            await client.get_ip("1.2.3.4")
            await client.close()

        asyncio.run(run())
        assert recorder.calls[0] == 60


# ---------------------------------------------------------------------------
# AsyncVTClient — non-2xx raises
# ---------------------------------------------------------------------------


class TestAsyncVTClientErrorRaises:
    def test_500_raises_http_status_error(self, monkeypatch: Any) -> None:
        _patch_sleep(monkeypatch)
        client = _make_client(lambda _req: httpx.Response(500))

        async def run():
            await client.get_file("abc123")
            await client.close()

        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            asyncio.run(run())
        assert exc_info.value.response.status_code == 500

    def test_403_raises_http_status_error(self, monkeypatch: Any) -> None:
        _patch_sleep(monkeypatch)
        client = _make_client(lambda _req: httpx.Response(403))

        async def run():
            await client.get_ip("1.1.1.1")
            await client.close()

        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            asyncio.run(run())
        assert exc_info.value.response.status_code == 403

    def test_401_raises_http_status_error(self, monkeypatch: Any) -> None:
        _patch_sleep(monkeypatch)
        client = _make_client(lambda _req: httpx.Response(401))

        async def run():
            await client.get_domain("evil.com")
            await client.close()

        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            asyncio.run(run())
        assert exc_info.value.response.status_code == 401


# ---------------------------------------------------------------------------
# AsyncVTClient — lifecycle (close and context manager)
# ---------------------------------------------------------------------------


class TestAsyncVTClientLifecycle:
    def test_close_does_not_raise(self, monkeypatch: Any) -> None:
        _patch_sleep(monkeypatch)
        client = _make_client(lambda _req: httpx.Response(200, json={}))

        async def run():
            await client.close()

        asyncio.run(run())  # must not raise

    def test_async_context_manager_enters_and_exits(self, monkeypatch: Any) -> None:
        _patch_sleep(monkeypatch)

        async def run():
            cfg = _make_config()
            async with AsyncVTClient(cfg) as client:
                # Replace transport after entering — __aenter__ just returns self
                client._client = httpx.AsyncClient(
                    transport=httpx.MockTransport(lambda _req: httpx.Response(200, json={"data": "ok"})),
                    base_url=_VT_BASE,
                )
                result = await client.get_file("abc123")
            return result

        result = asyncio.run(run())
        assert result == {"data": "ok"}

    def test_async_context_manager_closes_on_exit(self, monkeypatch: Any) -> None:
        """After __aexit__ the underlying httpx client should be closed."""
        _patch_sleep(monkeypatch)
        closed: list[bool] = []

        async def run():
            cfg = _make_config()
            async with AsyncVTClient(cfg) as client:
                client._client = httpx.AsyncClient(
                    transport=httpx.MockTransport(lambda _req: httpx.Response(200, json={})),
                    base_url=_VT_BASE,
                )
            closed.append(client._client.is_closed)

        asyncio.run(run())
        assert closed == [True]
