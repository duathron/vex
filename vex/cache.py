"""SQLite-based result cache with TTL support."""

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Optional


class Cache:
    def __init__(self, db_path: Path, ttl_hours: int = 24, enabled: bool = True):
        self._enabled = enabled
        self._ttl = ttl_hours * 3600
        self._conn = None
        if not enabled:
            return
        self._conn = sqlite3.connect(str(db_path))
        self._conn.execute("PRAGMA busy_timeout = 5000")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS results (
                key      TEXT PRIMARY KEY,
                data     TEXT NOT NULL,
                stored   REAL NOT NULL
            )
            """
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_stored ON results(stored)"
        )
        self._conn.commit()

    def get(self, key: str) -> Optional[dict[str, Any]]:
        if not self._enabled:
            return None
        row = self._conn.execute(
            "SELECT data, stored FROM results WHERE key = ?", (key,)
        ).fetchone()
        if row is None:
            return None
        data, stored = row
        if time.time() - stored > self._ttl:
            self._conn.execute("DELETE FROM results WHERE key = ?", (key,))
            self._conn.commit()
            return None
        return json.loads(data)

    def set(self, key: str, value: dict[str, Any]) -> None:
        if not self._enabled:
            return
        self._conn.execute(
            "INSERT OR REPLACE INTO results (key, data, stored) VALUES (?, ?, ?)",
            (key, json.dumps(value), time.time()),
        )
        self._conn.commit()

    def invalidate(self, key: str) -> None:
        if not self._enabled:
            return
        self._conn.execute("DELETE FROM results WHERE key = ?", (key,))
        self._conn.commit()

    def purge_expired(self) -> int:
        if not self._enabled:
            return 0
        cutoff = time.time() - self._ttl
        cur = self._conn.execute(
            "DELETE FROM results WHERE stored < ?", (cutoff,)
        )
        self._conn.commit()
        return cur.rowcount

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
