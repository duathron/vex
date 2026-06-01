"""Tests for vex.client: RateLimiter and VTClient.

All tests are offline — no real VirusTotal calls are made.
httpx.MockTransport is used to inject canned HTTP responses.
time.sleep and time.monotonic are monkeypatched where needed.
"""

from __future__ import annotations

import base64
from typing import Any
from unittest.mock import patch

import httpx
import pytest

from vex.client import RateLimiter, VTClient, VT_BASE
from vex.config import Config


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config(api_key: str = "test-key-00000000") -> Config:
    cfg = Config()
    cfg.api.key = api_key
    return cfg


def _json_response(data: dict[str, Any], status_code: int = 200) -> httpx.Response:
    return httpx.Response(status_code, json=data)


def _status_response(status_code: int) -> httpx.Response:
    return httpx.Response(status_code, content=b"")


class _SequenceTransport(httpx.BaseTransport):
    """Serve a list of responses in order."""

    def __init__(self, responses: list[httpx.Response]) -> None:
        self._responses = list(responses)
        self._idx = 0

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        resp = self._responses[self._idx]
        self._idx = min(self._idx + 1, len(self._responses) - 1)
        # Attach request so raise_for_status() works correctly
        resp.request = request
        return resp


def _single_transport(resp: httpx.Response) -> _SequenceTransport:
    return _SequenceTransport([resp])


def _make_client(config: Config, transport: httpx.MockTransport) -> VTClient:
    """Build a VTClient with a mock transport and no-op rate limiter."""
    client = VTClient.__new__(VTClient)
    client._config = config
    client._limiter = RateLimiter(999999)  # effectively unlimited; no real sleep
    client._client = httpx.Client(
        base_url=VT_BASE,
        headers={"x-apikey": config.api.key or "test", "Accept": "application/json"},
        transport=transport,
    )
    return client


# ---------------------------------------------------------------------------
# RateLimiter tests
# ---------------------------------------------------------------------------

class TestRateLimiter:
    def test_interval_calculation(self) -> None:
        rl = RateLimiter(4)
        assert abs(rl._interval - 15.0) < 1e-9

    def test_interval_60rpm(self) -> None:
        rl = RateLimiter(60)
        assert abs(rl._interval - 1.0) < 1e-9

    def test_first_call_does_not_sleep(self) -> None:
        rl = RateLimiter(4)
        # _last_call starts at 0; first call: elapsed >= _interval is false iff
        # monotonic() < _interval, which for 15s and a tiny test, elapsed ≫ 15s.
        # The first call should NOT sleep because elapsed = now - 0 >> interval.
        slept = []
        with patch("vex.client.time.sleep", side_effect=lambda d: slept.append(d)):
            with patch("vex.client.time.monotonic", return_value=100.0):
                rl.wait()
        assert slept == []

    def test_back_to_back_calls_enforce_sleep(self) -> None:
        """Second call within the interval window must trigger sleep."""
        rl = RateLimiter(4)  # interval = 15 s
        slept = []

        # Simulate: last call at t=100; now at t=104 (only 4 s elapsed, need 15)
        rl._last_call = 100.0
        with patch("vex.client.time.sleep", side_effect=lambda d: slept.append(d)):
            with patch("vex.client.time.monotonic", return_value=104.0):
                rl.wait()

        assert len(slept) == 1
        assert abs(slept[0] - 11.0) < 1e-6  # 15 - 4 = 11 s

    def test_sufficient_elapsed_no_sleep(self) -> None:
        """When enough time has passed, no sleep is issued."""
        rl = RateLimiter(4)  # interval = 15 s
        rl._last_call = 100.0
        slept = []
        with patch("vex.client.time.sleep", side_effect=lambda d: slept.append(d)):
            with patch("vex.client.time.monotonic", return_value=120.0):
                rl.wait()
        assert slept == []

    def test_last_call_updated_after_wait(self) -> None:
        rl = RateLimiter(60)
        with patch("vex.client.time.monotonic", return_value=42.0):
            rl.wait()
        assert rl._last_call == 42.0


# ---------------------------------------------------------------------------
# VTClient._get — HTTP status handling
# ---------------------------------------------------------------------------

class TestVTClientGet:
    def test_200_returns_parsed_json(self) -> None:
        cfg = _make_config()
        payload = {"data": {"id": "abc", "type": "file"}}
        transport = _single_transport(_json_response(payload))
        client = _make_client(cfg, transport)
        result = client._get("/files/abc")
        assert result == payload

    def test_404_returns_empty_dict(self) -> None:
        cfg = _make_config()
        transport = _single_transport(_status_response(404))
        client = _make_client(cfg, transport)
        result = client._get("/files/notfound")
        assert result == {}

    def test_403_premium_optional_returns_empty_dict(self) -> None:
        cfg = _make_config()
        transport = _single_transport(_status_response(403))
        client = _make_client(cfg, transport)
        result = client._get("/files/hash/behaviours", premium_optional=True)
        assert result == {}

    def test_403_non_premium_raises(self) -> None:
        cfg = _make_config()
        transport = _single_transport(_status_response(403))
        client = _make_client(cfg, transport)
        with pytest.raises(httpx.HTTPStatusError):
            client._get("/files/hash/behaviours", premium_optional=False)

    def test_500_raises(self) -> None:
        cfg = _make_config()
        transport = _single_transport(_status_response(500))
        client = _make_client(cfg, transport)
        with pytest.raises(httpx.HTTPStatusError):
            client._get("/files/abc")

    def test_429_sleeps_then_retries_successfully(self) -> None:
        """On 429: sleep 60 s, retry, succeed on second attempt."""
        cfg = _make_config()
        payload = {"data": {"id": "abc"}}
        transport = _SequenceTransport([
            _status_response(429),
            _json_response(payload),
        ])
        client = _make_client(cfg, transport)
        slept = []
        with patch("vex.client.time.sleep", side_effect=lambda d: slept.append(d)):
            result = client._get("/files/abc")
        assert result == payload
        assert 60 in slept

    def test_429_twice_raises_runtime_error(self) -> None:
        """Two consecutive 429 responses must raise RuntimeError."""
        cfg = _make_config()
        transport = _SequenceTransport([
            _status_response(429),
            _status_response(429),
        ])
        client = _make_client(cfg, transport)
        with patch("vex.client.time.sleep"):
            with pytest.raises(RuntimeError, match="rate limit exceeded"):
                client._get("/files/abc")


# ---------------------------------------------------------------------------
# VTClient — URL path construction
# ---------------------------------------------------------------------------

class TestVTClientPaths:
    def _last_request_path(self, transport: _SequenceTransport, idx: int = 0) -> str:
        """Peek at the last handled request's URL path."""
        # We'll use a capturing transport instead
        raise NotImplementedError  # not used; see below

    def _capturing_client(self, cfg: Config) -> tuple[VTClient, list[httpx.Request]]:
        """Return client + list that accumulates every request."""
        captured: list[httpx.Request] = []
        payload = {"data": {}}

        class CapturingTransport(httpx.BaseTransport):
            def handle_request(self, request: httpx.Request) -> httpx.Response:
                captured.append(request)
                resp = httpx.Response(200, json=payload)
                resp.request = request
                return resp

        client = VTClient.__new__(VTClient)
        client._config = cfg
        client._limiter = RateLimiter(999999)
        client._client = httpx.Client(
            base_url=VT_BASE,
            headers={"x-apikey": "test"},
            transport=CapturingTransport(),
        )
        return client, captured

    def test_get_file_uses_files_path(self) -> None:
        cfg = _make_config()
        client, captured = self._capturing_client(cfg)
        client.get_file("abc123")
        assert captured[0].url.path == "/api/v3/files/abc123"

    def test_get_ip_uses_ip_addresses_path(self) -> None:
        cfg = _make_config()
        client, captured = self._capturing_client(cfg)
        client.get_ip("1.2.3.4")
        assert captured[0].url.path == "/api/v3/ip_addresses/1.2.3.4"

    def test_get_domain_uses_domains_path(self) -> None:
        cfg = _make_config()
        client, captured = self._capturing_client(cfg)
        client.get_domain("evil.com")
        assert captured[0].url.path == "/api/v3/domains/evil.com"

    def test_get_url_encodes_url_id(self) -> None:
        """get_url() must base64url-encode the URL (no padding) and hit /urls/{id}."""
        cfg = _make_config()
        client, captured = self._capturing_client(cfg)
        raw_url = "http://evil.com/malware"
        expected_id = base64.urlsafe_b64encode(raw_url.encode()).rstrip(b"=").decode()
        client.get_url(raw_url)
        # First request is the GET on /urls/{id}
        assert captured[0].url.path == f"/api/v3/urls/{expected_id}"

    def test_get_file_behaviors_uses_behaviours_path(self) -> None:
        cfg = _make_config()
        client, captured = self._capturing_client(cfg)
        client.get_file_behaviors("deadbeef")
        assert "/behaviours" in captured[0].url.path

    def test_get_ip_resolutions_path(self) -> None:
        cfg = _make_config()
        client, captured = self._capturing_client(cfg)
        client.get_ip_resolutions("1.2.3.4")
        assert "/resolutions" in captured[0].url.path

    def test_get_domain_resolutions_path(self) -> None:
        cfg = _make_config()
        client, captured = self._capturing_client(cfg)
        client.get_domain_resolutions("evil.com")
        assert "/resolutions" in captured[0].url.path


# ---------------------------------------------------------------------------
# VTClient — get_url submit-and-poll path (cache miss)
# ---------------------------------------------------------------------------

class TestVTClientGetUrlSubmit:
    def test_get_url_submits_when_not_cached(self) -> None:
        """If GET /urls/{id} returns {}, POST + sleep + GET /analyses/{id}."""
        cfg = _make_config()
        analysis_payload = {"data": {"id": "anal-001", "type": "analysis", "attributes": {}}}
        result_payload = {"data": {"type": "analysis", "attributes": {"stats": {}, "results": {}}}}

        requests_seen: list[httpx.Request] = []

        class MultiTransport(httpx.BaseTransport):
            def handle_request(self, request: httpx.Request) -> httpx.Response:
                requests_seen.append(request)
                if request.method == "GET" and "/urls/" in request.url.path and "/analyses/" not in request.url.path:
                    resp = httpx.Response(404, content=b"")
                elif request.method == "POST":
                    resp = httpx.Response(200, json=analysis_payload)
                else:
                    resp = httpx.Response(200, json=result_payload)
                resp.request = request
                return resp

        client = VTClient.__new__(VTClient)
        client._config = cfg
        client._limiter = RateLimiter(999999)
        client._client = httpx.Client(
            base_url=VT_BASE,
            headers={"x-apikey": "test"},
            transport=MultiTransport(),
        )

        slept = []
        with patch("vex.client.time.sleep", side_effect=lambda d: slept.append(d)):
            res = client.get_url("http://evil.com/page")

        methods = [r.method for r in requests_seen]
        assert "POST" in methods
        # sleep(15) for analysis wait
        assert 15 in slept
        assert res == result_payload


# ---------------------------------------------------------------------------
# VTClient — context manager / close
# ---------------------------------------------------------------------------

class TestVTClientLifecycle:
    def test_context_manager_closes_http_client(self) -> None:
        cfg = _make_config()
        transport = _single_transport(_json_response({}))
        client = _make_client(cfg, transport)
        closed = []
        client._client.close = lambda: closed.append(True)
        with client:
            pass
        assert closed

    def test_close_explicitly(self) -> None:
        cfg = _make_config()
        transport = _single_transport(_json_response({}))
        client = _make_client(cfg, transport)
        closed = []
        client._client.close = lambda: closed.append(True)
        client.close()
        assert closed
