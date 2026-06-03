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
    @pytest.mark.parametrize(
        "live",
        [
            "https://evil.com",
            "http://malware.example.com/payload",
            "ftp://files.corp.internal",
            "https://evil.com/path?q=1&r=2",
        ],
    )
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
    @pytest.mark.parametrize(
        "ioc",
        [
            "hxxp://evil.com",
            "hxxps://evil.com",
            "fxp://evil.com",
            "evil[.]com",
            "hxxps[://]evil.com",
            "evil.com[:]8080",
            "user[@]evil.com",
            "evil[dot]com",
            "user[at]evil.com",
        ],
    )
    def test_defanged_strings_detected(self, ioc: str) -> None:
        assert is_defanged(ioc) is True

    @pytest.mark.parametrize(
        "ioc",
        [
            "https://evil.com",
            "http://evil.com",
            "8.8.8.8",
            "evil.com",
            "user@evil.com",
        ],
    )
    def test_live_strings_not_defanged(self, ioc: str) -> None:
        assert is_defanged(ioc) is False

    def test_case_insensitive_hxxp(self) -> None:
        assert is_defanged("HXXP://evil.com") is True

    def test_case_insensitive_dot_bracket(self) -> None:
        # is_defanged lowercases the input before checking indicators,
        # so both [DOT] and [dot] are detected.
        assert is_defanged("evil[DOT]com") is True
        assert is_defanged("evil[dot]com") is True


# ---------------------------------------------------------------------------
# Portfolio parity — new forms added for vex/sift/barb alignment
# ---------------------------------------------------------------------------


class TestRefangParity:
    """New defang forms: paren/brace dots, word-forms, fullwidth, zero-width."""

    # --- (.) and {.} dot variants ---
    def test_paren_dot(self) -> None:
        assert refang("evil(.)com") == "evil.com"

    def test_brace_dot(self) -> None:
        assert refang("evil{.}com") == "evil.com"

    # --- (dot) and {dot} word forms ---
    def test_paren_dot_word(self) -> None:
        assert refang("evil(dot)com") == "evil.com"

    def test_brace_dot_word(self) -> None:
        assert refang("evil{dot}com") == "evil.com"

    def test_paren_dot_word_case_insensitive(self) -> None:
        assert refang("evil(DOT)com") == "evil.com"

    def test_brace_dot_word_case_insensitive(self) -> None:
        assert refang("evil{DOT}com") == "evil.com"

    # --- [/] slash variant ---
    def test_bracket_slash(self) -> None:
        assert refang("hxxps://evil.com[/]path") == "https://evil.com/path"

    # --- (at) and {at} with domain-lookahead ---
    def test_paren_at_with_domain(self) -> None:
        assert refang("evil(at)mail(.)com") == "evil@mail.com"

    def test_brace_at_with_domain(self) -> None:
        assert refang("evil{at}mail[.]com") == "evil@mail.com"

    def test_paren_at_case_insensitive(self) -> None:
        assert refang("user(AT)example[.]com") == "user@example.com"

    def test_paren_at_no_domain_preserved(self) -> None:
        # ``state(at)rest`` has no domain-shape after it — must NOT be refanged.
        assert refang("state(at)rest") == "state(at)rest"

    def test_brace_at_no_domain_preserved(self) -> None:
        assert refang("array{at}index") == "array{at}index"

    # --- Fullwidth Unicode lookalikes ---
    def test_fullwidth_dot(self) -> None:
        assert refang("evil．com") == "evil.com"

    def test_fullwidth_at(self) -> None:
        assert refang("user＠evil．com") == "user@evil.com"

    def test_fullwidth_colon(self) -> None:
        assert refang("evil.com：8080") == "evil.com:8080"

    def test_fullwidth_slash(self) -> None:
        assert refang("https://evil.com／path") == "https://evil.com/path"

    # --- Zero-width character stripping ---
    def test_zero_width_space_stripped(self) -> None:
        # Insert U+200B between characters — must be stripped before matching.
        assert refang("e​vil[.]com") == "evil.com"

    def test_zero_width_joiner_stripped(self) -> None:
        assert refang("evil[.‍]com") == "evil.com"

    def test_bom_stripped(self) -> None:
        assert refang("﻿e​vil[.]com") == "evil.com"

    # --- Idempotency ---
    def test_idempotent_live_url(self) -> None:
        assert refang("https://google.com") == "https://google.com"

    def test_idempotent_double_refang(self) -> None:
        defanged = "hxxps[://]evil[.]com"
        assert refang(refang(defanged)) == refang(defanged)

    def test_idempotent_paren_dot(self) -> None:
        assert refang(refang("evil(.)com")) == refang("evil(.)com")

    def test_idempotent_fullwidth(self) -> None:
        assert refang(refang("evil．com")) == refang("evil．com")

    # --- IPv6 preservation ---
    def test_ipv6_url_unchanged(self) -> None:
        # [::1] must not be altered — ``[://]`` only matches literal ``[://]``
        assert refang("http://[::1]/x") == "http://[::1]/x"

    def test_ipv6_full_address_unchanged(self) -> None:
        assert refang("http://[2001:db8::1]:8080/path") == "http://[2001:db8::1]:8080/path"

    # --- Pre-existing forms still work ---
    def test_pre_existing_bracket_dot(self) -> None:
        assert refang("hxxps[://]evil[.]com") == "https://evil.com"

    def test_pre_existing_bracket_at_word(self) -> None:
        assert refang("evil[at]mail[.]com") == "evil@mail.com"

    def test_pre_existing_bracket_at_symbol(self) -> None:
        assert refang("user[@]evil.com") == "user@evil.com"


class TestIsDefangedParity:
    """New indicators added to is_defanged for parity."""

    @pytest.mark.parametrize(
        "ioc",
        [
            "evil(.)com",
            "evil{.}com",
            "evil(dot)com",
            "evil{dot}com",
            "evil．com",
            "user＠evil.com",
        ],
    )
    def test_new_forms_detected(self, ioc: str) -> None:
        assert is_defanged(ioc) is True

    @pytest.mark.parametrize(
        "ioc",
        [
            "https://evil.com",
            "evil.com",
            "user@evil.com",
            "8.8.8.8",
        ],
    )
    def test_live_forms_still_not_defanged(self, ioc: str) -> None:
        assert is_defanged(ioc) is False
