"""AI response cache — caches LLM explanations to avoid redundant API calls.

Keys are SHA-256 hashes of (provider, model, prompt). Default TTL: 72 hours.
Stored in ~/.vex/ai_cache.db (separate from the main result cache).
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Optional

from ..cache import Cache
from ..config import _ensure_dir


class AICache:
    """Caches AI explanations keyed by hash of (provider, model, prompt)."""

    def __init__(self, ttl_hours: int = 72):
        db_path = Path.home() / ".vex" / "ai_cache.db"
        _ensure_dir(db_path.parent)
        self._cache = Cache(db_path, ttl_hours=ttl_hours, enabled=True)

    def get(self, provider: str, model: str, prompt: str) -> Optional[str]:
        """Return cached explanation or None."""
        key = self._make_key(provider, model, prompt)
        cached = self._cache.get(key)
        return cached.get("explanation") if cached else None

    def set(
        self, provider: str, model: str, prompt: str, explanation: str
    ) -> None:
        """Cache an explanation."""
        key = self._make_key(provider, model, prompt)
        self._cache.set(key, {"explanation": explanation})

    @staticmethod
    def _make_key(provider: str, model: str, prompt: str) -> str:
        content = f"{provider}:{model}:{prompt}"
        return f"ai:{hashlib.sha256(content.encode()).hexdigest()}"

    def close(self) -> None:
        self._cache.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
