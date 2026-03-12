"""High-level API for the local knowledge base.

Provides convenience functions that combine DB operations with
enrichment result annotation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from ..models import TriageResult
from .db import KnowledgeDB


def annotate_result(result: TriageResult, db: KnowledgeDB) -> TriageResult:
    """Enrich a triage result with local tags, notes, and watchlist info."""
    result.local_tags = db.get_tags(result.ioc)
    notes = db.get_notes(result.ioc)
    result.local_notes = [n["note"] for n in notes]
    result.watchlists = db.is_watched(result.ioc)
    return result


def get_knowledge_db(db_path: Optional[Path] = None) -> KnowledgeDB:
    """Get a KnowledgeDB instance (convenience factory)."""
    return KnowledgeDB(db_path)
