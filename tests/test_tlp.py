"""Tests for the shared TLP parsing utilities in vex.tlp."""

from __future__ import annotations

import pytest

from vex.tlp import most_restrictive_tlp, normalize_tlp


# ---------------------------------------------------------------------------
# normalize_tlp — single-string parsing
# ---------------------------------------------------------------------------

class TestNormalizeTlp:
    # Basic levels — exact lowercase
    def test_red_lowercase(self) -> None:
        assert normalize_tlp("tlp:red") == "red"

    def test_amber_lowercase(self) -> None:
        assert normalize_tlp("tlp:amber") == "amber"

    def test_green_lowercase(self) -> None:
        assert normalize_tlp("tlp:green") == "green"

    def test_clear_lowercase(self) -> None:
        assert normalize_tlp("tlp:clear") == "clear"

    # Case-insensitive
    def test_uppercase_tlp_prefix(self) -> None:
        assert normalize_tlp("TLP:RED") == "red"

    def test_mixed_case_prefix(self) -> None:
        assert normalize_tlp("Tlp:Amber") == "amber"

    def test_uppercase_level_only(self) -> None:
        assert normalize_tlp("TLP:GREEN") == "green"

    def test_all_uppercase(self) -> None:
        assert normalize_tlp("TLP:CLEAR") == "clear"

    # TLP 1.0 WHITE → clear alias
    def test_white_maps_to_clear(self) -> None:
        assert normalize_tlp("tlp:white") == "clear"

    def test_white_uppercase_maps_to_clear(self) -> None:
        assert normalize_tlp("TLP:WHITE") == "clear"

    def test_White_mixed_maps_to_clear(self) -> None:
        assert normalize_tlp("TLP:White") == "clear"

    # amber+strict → amber
    def test_amber_plus_strict_lowercase(self) -> None:
        assert normalize_tlp("tlp:amber+strict") == "amber"

    def test_amber_plus_strict_uppercase(self) -> None:
        assert normalize_tlp("TLP:AMBER+STRICT") == "amber"

    def test_amber_plus_strict_mixed(self) -> None:
        assert normalize_tlp("TLP:Amber+Strict") == "amber"

    # Non-TLP strings → None
    def test_non_tlp_string_returns_none(self) -> None:
        assert normalize_tlp("malware:emotet") is None

    def test_empty_string_returns_none(self) -> None:
        assert normalize_tlp("") is None

    def test_plain_red_returns_none(self) -> None:
        """Without the 'tlp:' prefix the string is not a TLP tag."""
        assert normalize_tlp("red") is None

    def test_random_garbage_returns_none(self) -> None:
        assert normalize_tlp("not-a-tlp-tag") is None

    def test_misp_galaxy_tag_returns_none(self) -> None:
        assert normalize_tlp("misp-galaxy:threat-actor=Wizard Spider") is None

    def test_tlp_colon_unknown_level_returns_none(self) -> None:
        assert normalize_tlp("tlp:purple") is None

    # Whitespace tolerance
    def test_leading_trailing_whitespace_stripped(self) -> None:
        assert normalize_tlp("  tlp:amber  ") == "amber"

    # Parametrized canonical round-trip
    @pytest.mark.parametrize("raw,expected", [
        ("tlp:red", "red"),
        ("TLP:RED", "red"),
        ("tlp:amber", "amber"),
        ("TLP:AMBER", "amber"),
        ("tlp:green", "green"),
        ("TLP:GREEN", "green"),
        ("tlp:clear", "clear"),
        ("TLP:CLEAR", "clear"),
        ("tlp:white", "clear"),
        ("TLP:WHITE", "clear"),
        ("tlp:amber+strict", "amber"),
        ("TLP:AMBER+STRICT", "amber"),
    ])
    def test_parametrized(self, raw: str, expected: str) -> None:
        assert normalize_tlp(raw) == expected


# ---------------------------------------------------------------------------
# most_restrictive_tlp — precedence + edge cases
# ---------------------------------------------------------------------------

class TestMostRestrictiveTlp:
    def test_red_beats_amber(self) -> None:
        assert most_restrictive_tlp(["tlp:amber", "tlp:red"]) == "red"

    def test_amber_beats_green(self) -> None:
        assert most_restrictive_tlp(["tlp:green", "tlp:amber"]) == "amber"

    def test_green_beats_clear(self) -> None:
        assert most_restrictive_tlp(["tlp:clear", "tlp:green"]) == "green"

    def test_red_beats_all(self) -> None:
        values = ["tlp:white", "tlp:clear", "tlp:green", "tlp:amber", "tlp:red"]
        assert most_restrictive_tlp(values) == "red"

    def test_single_level_returned(self) -> None:
        assert most_restrictive_tlp(["tlp:green"]) == "green"

    def test_white_treated_as_clear(self) -> None:
        """white and clear are equivalent; green beats both."""
        assert most_restrictive_tlp(["tlp:white", "tlp:green"]) == "green"

    def test_only_clear_white(self) -> None:
        """Both white and clear normalise to clear."""
        result = most_restrictive_tlp(["tlp:white", "tlp:clear"])
        assert result == "clear"

    def test_non_tlp_tags_ignored(self) -> None:
        result = most_restrictive_tlp(["malware:emotet", "tlp:amber", "actor:apt28"])
        assert result == "amber"

    def test_empty_iterable_returns_none(self) -> None:
        assert most_restrictive_tlp([]) is None

    def test_all_non_tlp_returns_none(self) -> None:
        assert most_restrictive_tlp(["malware:emotet", "actor:wizard-spider"]) is None

    def test_amber_plus_strict_normalises_before_comparison(self) -> None:
        """amber+strict collapses to amber; green stays green → amber wins."""
        assert most_restrictive_tlp(["tlp:amber+strict", "tlp:green"]) == "amber"

    def test_case_insensitive_mixed(self) -> None:
        assert most_restrictive_tlp(["TLP:AMBER", "TLP:RED"]) == "red"

    def test_generator_input_accepted(self) -> None:
        """Accepts any Iterable, not just lists."""
        gen = (v for v in ["tlp:green", "tlp:amber"])
        assert most_restrictive_tlp(gen) == "amber"

    def test_duplicates_no_problem(self) -> None:
        assert most_restrictive_tlp(["tlp:amber", "tlp:amber", "tlp:amber"]) == "amber"
