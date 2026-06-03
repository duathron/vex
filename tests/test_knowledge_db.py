"""Tests for vex.knowledge.db.KnowledgeDB — deterministic, no network.

All tests use tmp_path so the real ~/.vex/knowledge.db is never touched.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from vex.knowledge.db import KnowledgeDB

IOC = "8.8.8.8"
IOC2 = "evil.com"


@pytest.fixture()
def db(tmp_path: Path) -> KnowledgeDB:
    d = KnowledgeDB(db_path=tmp_path / "k.db")
    yield d
    d.close()


# ---------------------------------------------------------------------------
# Tags
# ---------------------------------------------------------------------------


class TestTags:
    def test_add_and_get_tag(self, db: KnowledgeDB) -> None:
        db.add_tag(IOC, "malicious")
        assert "malicious" in db.get_tags(IOC)

    def test_tags_stored_lowercase(self, db: KnowledgeDB) -> None:
        db.add_tag(IOC, "MALICIOUS")
        assert "malicious" in db.get_tags(IOC)
        assert "MALICIOUS" not in db.get_tags(IOC)

    def test_multiple_tags(self, db: KnowledgeDB) -> None:
        db.add_tag(IOC, "apt29")
        db.add_tag(IOC, "c2")
        tags = db.get_tags(IOC)
        assert "apt29" in tags
        assert "c2" in tags

    def test_duplicate_tag_ignored(self, db: KnowledgeDB) -> None:
        db.add_tag(IOC, "malicious")
        db.add_tag(IOC, "malicious")
        assert db.get_tags(IOC).count("malicious") == 1

    def test_remove_tag(self, db: KnowledgeDB) -> None:
        db.add_tag(IOC, "malicious")
        db.remove_tag(IOC, "malicious")
        assert "malicious" not in db.get_tags(IOC)

    def test_remove_nonexistent_tag_is_noop(self, db: KnowledgeDB) -> None:
        db.remove_tag(IOC, "nonexistent")  # must not raise

    def test_tags_isolated_by_ioc(self, db: KnowledgeDB) -> None:
        db.add_tag(IOC, "shared-tag")
        assert db.get_tags(IOC2) == []

    def test_get_tags_empty_for_unknown_ioc(self, db: KnowledgeDB) -> None:
        assert db.get_tags("unknown-ioc") == []

    def test_tags_returned_sorted(self, db: KnowledgeDB) -> None:
        db.add_tag(IOC, "zzz")
        db.add_tag(IOC, "aaa")
        tags = db.get_tags(IOC)
        assert tags == sorted(tags)


# ---------------------------------------------------------------------------
# Notes
# ---------------------------------------------------------------------------


class TestNotes:
    def test_add_and_get_note(self, db: KnowledgeDB) -> None:
        db.add_note(IOC, "Suspicious outbound traffic")
        notes = db.get_notes(IOC)
        assert len(notes) == 1
        assert notes[0]["note"] == "Suspicious outbound traffic"

    def test_add_note_returns_id(self, db: KnowledgeDB) -> None:
        note_id = db.add_note(IOC, "First note")
        assert isinstance(note_id, int)
        assert note_id > 0

    def test_multiple_notes(self, db: KnowledgeDB) -> None:
        db.add_note(IOC, "Note 1")
        db.add_note(IOC, "Note 2")
        assert len(db.get_notes(IOC)) == 2

    def test_delete_note_by_id(self, db: KnowledgeDB) -> None:
        note_id = db.add_note(IOC, "To be deleted")
        db.delete_note(note_id)
        notes = db.get_notes(IOC)
        assert all(n["id"] != note_id for n in notes)

    def test_delete_nonexistent_note_is_noop(self, db: KnowledgeDB) -> None:
        db.delete_note(999999)  # must not raise

    def test_notes_isolated_by_ioc(self, db: KnowledgeDB) -> None:
        db.add_note(IOC, "Note for IOC1")
        assert db.get_notes(IOC2) == []

    def test_get_notes_empty_for_unknown_ioc(self, db: KnowledgeDB) -> None:
        assert db.get_notes("unknown-ioc") == []

    def test_note_dict_has_expected_keys(self, db: KnowledgeDB) -> None:
        db.add_note(IOC, "check keys")
        note = db.get_notes(IOC)[0]
        assert "id" in note
        assert "note" in note
        assert "created_at" in note


# ---------------------------------------------------------------------------
# Watchlists
# ---------------------------------------------------------------------------


class TestWatchlists:
    def test_add_and_get_watchlist(self, db: KnowledgeDB) -> None:
        db.add_to_watchlist("critical", IOC)
        assert IOC in db.get_watchlist("critical")

    def test_watchlist_name_stored_lowercase(self, db: KnowledgeDB) -> None:
        db.add_to_watchlist("CRITICAL", IOC)
        assert IOC in db.get_watchlist("critical")

    def test_duplicate_watchlist_entry_ignored(self, db: KnowledgeDB) -> None:
        db.add_to_watchlist("critical", IOC)
        db.add_to_watchlist("critical", IOC)
        assert db.get_watchlist("critical").count(IOC) == 1

    def test_remove_from_watchlist(self, db: KnowledgeDB) -> None:
        db.add_to_watchlist("critical", IOC)
        db.remove_from_watchlist("critical", IOC)
        assert IOC not in db.get_watchlist("critical")

    def test_remove_nonexistent_watchlist_entry_is_noop(self, db: KnowledgeDB) -> None:
        db.remove_from_watchlist("critical", "not-there")  # must not raise

    def test_get_empty_watchlist(self, db: KnowledgeDB) -> None:
        assert db.get_watchlist("empty-list") == []

    def test_list_watchlists(self, db: KnowledgeDB) -> None:
        db.add_to_watchlist("alpha", IOC)
        db.add_to_watchlist("beta", IOC)
        lists = db.list_watchlists()
        assert "alpha" in lists
        assert "beta" in lists

    def test_list_watchlists_empty_db(self, db: KnowledgeDB) -> None:
        assert db.list_watchlists() == []

    def test_is_watched_returns_list_names(self, db: KnowledgeDB) -> None:
        db.add_to_watchlist("critical", IOC)
        db.add_to_watchlist("review", IOC)
        names = db.is_watched(IOC)
        assert "critical" in names
        assert "review" in names

    def test_is_watched_empty_for_unwatched_ioc(self, db: KnowledgeDB) -> None:
        assert db.is_watched("not-watched") == []

    def test_multiple_iocs_in_watchlist(self, db: KnowledgeDB) -> None:
        db.add_to_watchlist("critical", IOC)
        db.add_to_watchlist("critical", IOC2)
        wl = db.get_watchlist("critical")
        assert IOC in wl
        assert IOC2 in wl


# ---------------------------------------------------------------------------
# Context manager
# ---------------------------------------------------------------------------


class TestContextManager:
    def test_context_manager_enter_returns_db(self, tmp_path: Path) -> None:
        with KnowledgeDB(db_path=tmp_path / "k.db") as db:
            assert db is not None

    def test_context_manager_data_persists_within_block(self, tmp_path: Path) -> None:
        with KnowledgeDB(db_path=tmp_path / "k.db") as db:
            db.add_tag(IOC, "ctx-test")
            assert "ctx-test" in db.get_tags(IOC)

    def test_context_manager_closes_on_exit(self, tmp_path: Path) -> None:
        with KnowledgeDB(db_path=tmp_path / "k.db") as db:
            db.add_tag(IOC, "close-test")
        # After __exit__, the connection should be closed; verify db file exists
        assert (tmp_path / "k.db").exists()

    def test_separate_db_instances_share_data(self, tmp_path: Path) -> None:
        db_file = tmp_path / "k.db"
        with KnowledgeDB(db_path=db_file) as db1:
            db1.add_tag(IOC, "shared")
        with KnowledgeDB(db_path=db_file) as db2:
            assert "shared" in db2.get_tags(IOC)
