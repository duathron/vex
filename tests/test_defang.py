"""Tests for vex.defang — deterministic, no network."""

from __future__ import annotations

import pytest

from vex.defang import defang, is_defanged, refang


# ---------------------------------------------------------------------------
# refang
# ---------------------------------------------------------------------------

class TestRefang:
    def test_hxxps_protocol(self) -> None:
        assert refang("hxxps://evil.com") == "https://evil.com"

    def test_hxxp_protocol(self) -> None:
        assert refang("hxxp://evil.com") == "http://evil.com"

    def test_fxp_protocol(self) -> None:
        assert refang("fxp://files.example.com") == "ftp://files.example.com"

    def test_bracket_dot(self) -> None:
        assert refang("evil[.]com") == "evil.com"

    def test_bracket_colon_slash(self) -> None:
        assert refang("hxxps[://]evil.com") == "https://evil.com"

    def test_bracket_at(self) -> None:
        assert refang("user[@]evil.com") == "user@evil.com"

    def test_bracket_colon(self) -> None:
        assert refang("evil.com[:]8080") == "evil.com:8080"

    def test_dot_word(self) -> None:
        assert refang("evil[dot]com") == "evil.com"

    def test_at_word(self) -> None:
        assert refang("user[at]evil.com") == "user@evil.com"

    def test_combined_full_url(self) -> None:
        assert refang("hxxps[://]evil[.]com/path") == "https://evil.com/path"

    def test_case_insensitive_hxxp(self) -> None:
        assert refang("HXXP://evil.com") == "http://evil.com"

    def test_no_change_already_live(self) -> None:
        assert refang("https://evil.com") == "https://evil.com"

    def test_ipv4_bracket_dot(self) -> None:
        assert refang("192[.]168[.]1[.]1") == "192.168.1.1"


# ---------------------------------------------------------------------------
# defang
# ---------------------------------------------------------------------------

class TestDefang:
    def test_https_url(self) -> None:
        assert defang("https://evil.com") == "hxxps[://]evil[.]com"

    def test_http_url(self) -> None:
        assert defang("http://evil.com") == "hxxp[://]evil[.]com"

    def test_ftp_url(self) -> None:
        assert defang("ftp://files.example.com") == "fxp[://]files[.]example[.]com"

    def test_dots_in_domain(self) -> None:
        result = defang("evil.sub.example.com")
        assert "[.]" in result
        assert "." not in result.replace("[.]", "")

    def test_no_change_already_defanged(self) -> None:
        # Running defang on an already-defanged string shouldn't break it;
        # dots become [.] once, [.] has no dots to defang further.
        defanged = "hxxps[://]evil[.]com"
        assert "[.]" in defang(defanged)


# ---------------------------------------------------------------------------
# Round-trip: defang then refang
# ---------------------------------------------------------------------------

class TestRoundTrip:
    @pytest.mark.parametrize("live", [
        "https://evil.com",
        "http://malware.example.com/payload",
        "ftp://files.corp.internal",
        "https://evil.com/path?q=1&r=2",
    ])
    def test_defang_refang_roundtrip(self, live: str) -> None:
        assert refang(defang(live)) == live

    def test_refang_docstring_example(self) -> None:
        assert refang("hxxps[://]evil[.]com") == "https://evil.com"

    def test_defang_docstring_example(self) -> None:
        assert defang("https://evil.com") == "hxxps[://]evil[.]com"


# ---------------------------------------------------------------------------
# is_defanged
# ---------------------------------------------------------------------------

class TestIsDefanged:
    @pytest.mark.parametrize("ioc", [
        "hxxp://evil.com",
        "hxxps://evil.com",
        "fxp://evil.com",
        "evil[.]com",
        "hxxps[://]evil.com",
        "evil.com[:]8080",
        "user[@]evil.com",
        "evil[dot]com",
        "user[at]evil.com",
    ])
    def test_defanged_strings_detected(self, ioc: str) -> None:
        assert is_defanged(ioc) is True

    @pytest.mark.parametrize("ioc", [
        "https://evil.com",
        "http://evil.com",
        "8.8.8.8",
        "evil.com",
        "user@evil.com",
    ])
    def test_live_strings_not_defanged(self, ioc: str) -> None:
        assert is_defanged(ioc) is False

    def test_case_insensitive_hxxp(self) -> None:
        assert is_defanged("HXXP://evil.com") is True

    def test_case_insensitive_dot_bracket(self) -> None:
        # is_defanged lowercases the input before checking indicators,
        # so both [DOT] and [dot] are detected.
        assert is_defanged("evil[DOT]com") is True
        assert is_defanged("evil[dot]com") is True
