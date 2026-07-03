"""Shared fake-urlopen helper for mocking shipwright_kit.llm.ollama_generate's
urllib transport in vex's ollama provider tests (W3 retrofit, 2026-07-03).

ollama_generate does:
    req = urllib.request.Request(url, data=..., headers=..., method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8")
    outer = json.loads(body)
    return outer["response"]

So a fake urlopen must (a) accept the same call shape (positional req,
keyword timeout), (b) return a context-manager with a .read() -> bytes,
and (c) let the test inspect the captured Request (url/data/timeout).
"""

from __future__ import annotations

import json
from typing import Any


class _FakeHTTPResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "_FakeHTTPResponse":
        return self

    def __exit__(self, *exc: Any) -> bool:
        return False


def make_fake_urlopen(response_json: dict, *, raise_error: Exception | None = None):
    """Return (captured: dict, fake_urlopen: callable).

    captured["request"] holds the urllib.request.Request the code under test
    built (inspect .full_url / .data / .headers); captured["timeout"] holds
    the timeout kwarg it was called with. If raise_error is given, the fake
    raises it instead of returning a response (for transport/HTTP-error
    tests).
    """
    captured: dict = {}

    def fake_urlopen(req, timeout=None, **kwargs):
        captured["request"] = req
        captured["timeout"] = timeout
        if raise_error is not None:
            raise raise_error
        return _FakeHTTPResponse(json.dumps(response_json).encode("utf-8"))

    return captured, fake_urlopen
