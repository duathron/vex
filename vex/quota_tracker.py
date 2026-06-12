"""Persistent daily VT API quota counter (V3).

Tracks actual fresh-lookup consumption against ``config.requests_per_day``.
Keyed by UTC date — resets automatically on a new day.
Fail-open: any read/write error is swallowed so quota tracking never blocks triage.

Storage: a small JSON file under the vex app dir (``~/.vex/quota.json`` by default).
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("vex.quota_tracker")

_DEFAULT_STATE_PATH = Path.home() / ".vex" / "quota.json"
_DEFAULT_DAILY_LIMIT = 500  # matches the free-tier default in config
_DEFAULT_WARN_THRESHOLD = 0.10  # warn when ≤ 10 % remaining


class QuotaTracker:
    """Persistent daily counter for VirusTotal API requests.

    Parameters
    ----------
    state_path:
        Where to store the JSON state file.  Defaults to ``~/.vex/quota.json``.
    daily_limit:
        Maximum requests per day (used for remaining / warning calculations).
    warn_threshold:
        Fraction of daily_limit remaining at which ``is_near_exhaustion()`` fires.
        Default 0.10 → warn when ≤ 10 % of quota is left.
    """

    def __init__(
        self,
        state_path: Optional[Path] = None,
        daily_limit: int = _DEFAULT_DAILY_LIMIT,
        warn_threshold: float = _DEFAULT_WARN_THRESHOLD,
    ) -> None:
        self._path = state_path or _DEFAULT_STATE_PATH
        self._daily_limit = daily_limit
        self._warn_threshold = warn_threshold
        self._count: int = 0
        self._load()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _today(self) -> str:
        return datetime.now(timezone.utc).date().isoformat()

    def _load(self) -> None:
        """Load state from disk; start fresh on any error or date mismatch."""
        try:
            raw = self._path.read_text(encoding="utf-8")
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError("invalid state shape")
            stored_date = data.get("date")
            stored_count = data.get("count")
            if stored_date == self._today() and isinstance(stored_count, int):
                self._count = stored_count
            # else: different day or missing keys → reset (count stays 0)
        except (FileNotFoundError, IsADirectoryError):
            pass  # first run or path is a directory — fail-open
        except Exception:
            logger.debug("quota_tracker: could not load state, starting fresh", exc_info=True)

    def _save(self) -> None:
        """Persist count to disk; swallow all errors (fail-open)."""
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            state = {"date": self._today(), "count": self._count}
            self._path.write_text(json.dumps(state), encoding="utf-8")
        except Exception:
            logger.debug("quota_tracker: could not save state", exc_info=True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record_fresh_lookup(self) -> None:
        """Increment the daily counter by 1.  Fail-open — never raises."""
        try:
            self._count += 1
            self._save()
        except Exception:
            logger.debug("quota_tracker: record_fresh_lookup failed", exc_info=True)

    def used_today(self) -> int:
        """Return the number of fresh lookups performed today (0-based day)."""
        try:
            return self._count
        except Exception:
            return 0

    def remaining_today(self) -> int:
        """Remaining quota for today (never negative)."""
        return max(0, self._daily_limit - self.used_today())

    def is_near_exhaustion(self) -> bool:
        """Return True when remaining quota is ≤ warn_threshold of daily_limit."""
        return self.remaining_today() <= (self._warn_threshold * self._daily_limit)

    def status_line(self) -> str:
        """One-line human-readable quota status for stderr output."""
        used = self.used_today()
        limit = self._daily_limit
        remaining = self.remaining_today()
        return f"VT quota: {used}/{limit} used today, {remaining} remaining"
