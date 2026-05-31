"""Tests for vex.cache.Cache.

Includes a regression test for v1.2.1: concurrent SQLite access from
ThreadPoolExecutor workers must be serialized by the internal lock and
must not raise ``InterfaceError: bad parameter or other API misuse``.
"""

from __future__ import annotations

import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from vex.cache import Cache


@pytest.fixture()
def cache(tmp_path: Path) -> Cache:
    c = Cache(tmp_path / "cache.db", ttl_hours=24, enabled=True)
    yield c
    c.close()


def test_set_then_get_roundtrip(cache: Cache) -> None:
    cache.set("k", {"verdict": "malicious", "score": 9})
    assert cache.get("k") == {"verdict": "malicious", "score": 9}


def test_get_missing_returns_none(cache: Cache) -> None:
    assert cache.get("absent") is None


def test_disabled_cache_is_noop(tmp_path: Path) -> None:
    c = Cache(tmp_path / "off.db", enabled=False)
    c.set("k", {"a": 1})
    assert c.get("k") is None
    c.close()


def test_ttl_expiry_evicts_entry(tmp_path: Path) -> None:
    c = Cache(tmp_path / "ttl.db", ttl_hours=0, enabled=True)  # ttl == 0 -> immediately stale
    c.set("k", {"a": 1})
    time.sleep(0.01)
    assert c.get("k") is None  # expired and deleted
    c.close()


def test_invalidate_removes_key(cache: Cache) -> None:
    cache.set("k", {"a": 1})
    cache.invalidate("k")
    assert cache.get("k") is None


def test_purge_expired_counts_rows(tmp_path: Path) -> None:
    c = Cache(tmp_path / "purge.db", ttl_hours=0, enabled=True)
    c.set("a", {"x": 1})
    c.set("b", {"x": 2})
    time.sleep(0.01)
    assert c.purge_expired() == 2
    c.close()


def test_concurrent_access_no_interface_error(tmp_path: Path) -> None:
    """Regression for v1.2.1.

    ThreadPoolExecutor workers sharing one Cache (check_same_thread=False
    connection) must not raise sqlite3.InterfaceError. The threading.Lock
    serializes access.
    """
    c = Cache(tmp_path / "concurrent.db", ttl_hours=24, enabled=True)

    def worker(i: int) -> dict | None:
        key = f"ioc-{i % 16}"
        c.set(key, {"i": i})
        return c.get(key)

    errors: list[Exception] = []

    def guarded(i: int):
        try:
            return worker(i)
        except sqlite3.InterfaceError as exc:  # the exact v1.2.1 failure
            errors.append(exc)
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(guarded, range(400)))

    c.close()
    assert errors == [], f"concurrent SQLite access raised: {errors[:3]}"
