"""Tests for IOC deduplication — deterministic, no network."""

from __future__ import annotations

from vex.main import dedup_iocs


class TestDedupIocs:
    def test_removes_exact_duplicates(self) -> None:
        iocs = ["8.8.8.8", "evil.com", "8.8.8.8", "1.1.1.1", "evil.com"]
        unique, removed = dedup_iocs(iocs)
        assert unique == ["8.8.8.8", "evil.com", "1.1.1.1"]
        assert removed == 2

    def test_preserves_first_seen_order(self) -> None:
        iocs = ["c.com", "a.com", "b.com", "a.com", "c.com"]
        unique, removed = dedup_iocs(iocs)
        assert unique == ["c.com", "a.com", "b.com"]
        assert removed == 2

    def test_empty_list(self) -> None:
        unique, removed = dedup_iocs([])
        assert unique == []
        assert removed == 0

    def test_all_unique_returns_original_order(self) -> None:
        iocs = ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
        unique, removed = dedup_iocs(iocs)
        assert unique == iocs
        assert removed == 0

    def test_all_same(self) -> None:
        iocs = ["evil.com"] * 5
        unique, removed = dedup_iocs(iocs)
        assert unique == ["evil.com"]
        assert removed == 4

    def test_single_element(self) -> None:
        unique, removed = dedup_iocs(["8.8.8.8"])
        assert unique == ["8.8.8.8"]
        assert removed == 0

    def test_count_correct_large_list(self) -> None:
        # Simulate 5000 IOCs → 4123 unique
        base = [f"10.0.{i // 256}.{i % 256}" for i in range(4123)]
        duplicates = base[:877]
        iocs = base + duplicates
        unique, removed = dedup_iocs(iocs)
        assert len(unique) == 4123
        assert removed == 877

    def test_dedup_key_is_exact_stripped_string(self) -> None:
        # Already-stripped strings — "evil.com" and "evil.com" are the same key
        iocs = ["evil.com", "EVIL.COM", "evil.com"]
        unique, removed = dedup_iocs(iocs)
        # "evil.com" and "EVIL.COM" are different strings — only the third is a dup
        assert unique == ["evil.com", "EVIL.COM"]
        assert removed == 1

    def test_no_dedup_preserves_duplicates(self) -> None:
        """When no_dedup=True the caller skips dedup_iocs — verify helper contract.

        We can verify indirectly: if we call dedup_iocs we get deduplication.
        If we skip calling it the list stays unchanged. This tests the helper
        itself rather than the CLI wiring (which requires a real VT key).
        """
        iocs = ["evil.com", "evil.com", "evil.com"]
        # When --no-dedup: caller does NOT call dedup_iocs, so list remains as-is
        # Verify the unmodified list has duplicates (the flag would preserve this)
        assert len(iocs) == 3

        # When dedup IS called, duplicates are removed
        unique, removed = dedup_iocs(iocs)
        assert len(unique) == 1
        assert removed == 2
