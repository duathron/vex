"""Check for newer vex releases on GitHub."""

from __future__ import annotations

import json
import stat
import time
from pathlib import Path
from typing import Optional

import httpx

from . import __version__

_STATE_PATH = Path.home() / ".vex" / "version_check.json"
_GITHUB_API = "https://api.github.com/repos/duathron/vex/releases/latest"
_CHECK_TIMEOUT = 3.0


def _parse_version(v: str) -> tuple[int, ...]:
    """Parse 'v1.2.3' or '1.2.3' into (1, 2, 3) for comparison."""
    v = v.lstrip("v").strip()
    try:
        return tuple(int(x) for x in v.split("."))
    except (ValueError, AttributeError):
        return (0,)


def _load_state() -> dict:
    """Load cached version check state from disk."""
    try:
        if _STATE_PATH.exists():
            return json.loads(_STATE_PATH.read_text())
    except (OSError, ValueError, KeyError):
        pass
    return {}


def _save_state(state: dict) -> None:
    """Save version check state to disk with restricted permissions."""
    try:
        _STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _STATE_PATH.parent.chmod(stat.S_IRWXU)
        _STATE_PATH.write_text(json.dumps(state))
        _STATE_PATH.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0o600
    except OSError:
        pass


def _fetch_latest_version() -> Optional[str]:
    """Query GitHub releases API for the latest stable version."""
    try:
        resp = httpx.get(
            _GITHUB_API,
            timeout=_CHECK_TIMEOUT,
            headers={"Accept": "application/vnd.github.v3+json"},
            follow_redirects=True,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        if data.get("prerelease") or data.get("draft"):
            return None
        tag = data.get("tag_name", "")
        return tag if tag else None
    except (httpx.HTTPError, ValueError, KeyError):
        return None


def check_for_update(check_interval_hours: int = 24) -> Optional[str]:
    """Return the latest version string if an update is available.

    Returns None if current version is up to date, check was performed
    recently, or a network error occurred.
    """
    state = _load_state()

    last_check = state.get("last_check", 0)
    cached_version = state.get("latest_version")
    interval = check_interval_hours * 3600
    elapsed = time.time() - last_check

    if 0 < elapsed < interval and cached_version:
        latest = cached_version
    else:
        latest = _fetch_latest_version()
        if latest:
            _save_state({
                "last_check": time.time(),
                "latest_version": latest,
            })
        else:
            return None

    current = _parse_version(__version__)
    remote = _parse_version(latest)

    if remote > current:
        return latest.lstrip("v")

    return None
