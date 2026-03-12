"""SQLite-backed local IOC knowledge base.

Stores tags, notes, and watchlist membership for IOCs.
Database location: ``~/.vex/knowledge.db``
"""

from __future__ import annotations

import sqlite3
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


class KnowledgeDB:
    """Local IOC knowledge base backed by SQLite."""

    def __init__(self, db_path: Optional[Path] = None):
        self._path = db_path or (Path.home() / ".vex" / "knowledge.db")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.parent.chmod(stat.S_IRWXU)  # 0o700
        self._conn = sqlite3.connect(str(self._path))
        self._conn.execute("PRAGMA busy_timeout = 5000")
        self._conn.row_factory = sqlite3.Row
        self._init_tables()

    def _init_tables(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS ioc_tags (
                ioc TEXT NOT NULL,
                tag TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (ioc, tag)
            );
            CREATE TABLE IF NOT EXISTS ioc_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc TEXT NOT NULL,
                note TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS watchlists (
                name TEXT NOT NULL,
                ioc TEXT NOT NULL,
                added_at TEXT NOT NULL,
                PRIMARY KEY (name, ioc)
            );
            CREATE INDEX IF NOT EXISTS idx_tags_ioc ON ioc_tags(ioc);
            CREATE INDEX IF NOT EXISTS idx_notes_ioc ON ioc_notes(ioc);
            CREATE INDEX IF NOT EXISTS idx_watch_name ON watchlists(name);
        """)

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    # --- Tags ---

    def add_tag(self, ioc: str, tag: str) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO ioc_tags (ioc, tag, created_at) VALUES (?, ?, ?)",
            (ioc, tag.lower(), self._now()),
        )
        self._conn.commit()

    def remove_tag(self, ioc: str, tag: str) -> None:
        self._conn.execute("DELETE FROM ioc_tags WHERE ioc = ? AND tag = ?", (ioc, tag.lower()))
        self._conn.commit()

    def get_tags(self, ioc: str) -> list[str]:
        rows = self._conn.execute("SELECT tag FROM ioc_tags WHERE ioc = ? ORDER BY tag", (ioc,)).fetchall()
        return [r["tag"] for r in rows]

    # --- Notes ---

    def add_note(self, ioc: str, note: str) -> int:
        cur = self._conn.execute(
            "INSERT INTO ioc_notes (ioc, note, created_at) VALUES (?, ?, ?)",
            (ioc, note, self._now()),
        )
        self._conn.commit()
        return cur.lastrowid

    def get_notes(self, ioc: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT id, note, created_at FROM ioc_notes WHERE ioc = ? ORDER BY created_at DESC",
            (ioc,),
        ).fetchall()
        return [dict(r) for r in rows]

    def delete_note(self, note_id: int) -> None:
        self._conn.execute("DELETE FROM ioc_notes WHERE id = ?", (note_id,))
        self._conn.commit()

    # --- Watchlists ---

    def add_to_watchlist(self, name: str, ioc: str) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO watchlists (name, ioc, added_at) VALUES (?, ?, ?)",
            (name.lower(), ioc, self._now()),
        )
        self._conn.commit()

    def remove_from_watchlist(self, name: str, ioc: str) -> None:
        self._conn.execute("DELETE FROM watchlists WHERE name = ? AND ioc = ?", (name.lower(), ioc))
        self._conn.commit()

    def get_watchlist(self, name: str) -> list[str]:
        rows = self._conn.execute(
            "SELECT ioc FROM watchlists WHERE name = ? ORDER BY added_at DESC",
            (name.lower(),),
        ).fetchall()
        return [r["ioc"] for r in rows]

    def list_watchlists(self) -> list[str]:
        rows = self._conn.execute("SELECT DISTINCT name FROM watchlists ORDER BY name").fetchall()
        return [r["name"] for r in rows]

    def is_watched(self, ioc: str) -> list[str]:
        """Return watchlist names that contain this IOC."""
        rows = self._conn.execute("SELECT name FROM watchlists WHERE ioc = ?", (ioc,)).fetchall()
        return [r["name"] for r in rows]

    # --- Lifecycle ---

    def close(self) -> None:
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
