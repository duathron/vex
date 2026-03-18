"""Direct WHOIS enrichment via python-whois (optional dependency).

For free-tier users who don't have access to VirusTotal's premium WHOIS
endpoint, this module provides direct WHOIS lookups using the python-whois
library.

Falls back gracefully when python-whois is not installed::

    # Install optional dep
    pip install vex-ioc[whois]

Integration point in domain.py::

    if result.whois is None and config.enrichment.whois_enabled:
        result.whois = enrich_whois(ioc)
"""

from __future__ import annotations

import logging
from typing import Optional

from ..models import WHOISInfo

logger = logging.getLogger("vex.enrichers.whois")


def is_available() -> bool:
    """Return True if python-whois is installed."""
    try:
        import whois  # noqa: F401
        return True
    except ImportError:
        return False


def enrich_whois(domain: str) -> Optional[WHOISInfo]:
    """Query WHOIS for *domain*. Returns WHOISInfo or None.

    Handles all python-whois quirks:
    - Values may be single items or lists; we always take the first.
    - Dates may be datetime objects or strings; we coerce to str.
    - Exceptions are caught and logged as warnings (never raises).

    Args:
        domain: Bare domain name (e.g. "evil.com"). No protocol prefix.

    Returns:
        Populated WHOISInfo or None if lookup failed / lib unavailable.
    """
    if not is_available():
        logger.debug("python-whois not installed — skipping direct WHOIS lookup")
        return None

    try:
        import whois  # type: ignore[import]

        w = whois.whois(domain)
        if not w:
            return None

        def _first(val) -> Optional[str]:
            """Coerce single value or list to a single string, or None."""
            if val is None:
                return None
            if isinstance(val, list):
                return str(val[0]) if val else None
            return str(val)

        ns_raw = w.name_servers or []
        if isinstance(ns_raw, str):
            ns_raw = [ns_raw]
        name_servers = [str(n).lower() for n in ns_raw if n]

        return WHOISInfo(
            registrar=_first(w.registrar),
            creation_date=_first(w.creation_date),
            expiration_date=_first(w.expiration_date),
            updated_date=_first(w.updated_date),
            name_servers=name_servers,
            registrant_org=_first(getattr(w, "org", None)),
            registrant_country=_first(getattr(w, "country", None)),
        )

    except Exception as e:
        logger.warning("WHOIS lookup failed for %s: %s", domain, e)
        return None
