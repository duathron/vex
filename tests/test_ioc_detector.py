"""Tests for vex.ioc_detector.detect — deterministic, no network."""

from __future__ import annotations

import pytest

from vex.ioc_detector import IOCType, detect, is_hash, is_network


@pytest.mark.parametrize(
    "raw, expected_type, expected_value",
    [
        ("d41d8cd98f00b204e9800998ecf8427e", IOCType.MD5, "d41d8cd98f00b204e9800998ecf8427e"),
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", IOCType.SHA1, "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        ("e" * 64, IOCType.SHA256, "e" * 64),
        ("8.8.8.8", IOCType.IPV4, "8.8.8.8"),
        ("2001:db8::1", IOCType.IPV6, "2001:db8::1"),
        ("evil.com", IOCType.DOMAIN, "evil.com"),
        ("https://evil.com/path", IOCType.URL, "https://evil.com/path"),
        ("not a valid ioc!!", IOCType.UNKNOWN, "not a valid ioc!!"),
    ],
)
def test_detect_types(raw: str, expected_type: IOCType, expected_value: str) -> None:
    t, value = detect(raw)
    assert t == expected_type
    assert value == expected_value


def test_detect_strips_whitespace() -> None:
    t, value = detect("  8.8.8.8  ")
    assert t == IOCType.IPV4
    assert value == "8.8.8.8"


def test_detect_refangs_defanged_input() -> None:
    t, value = detect("hxxps://evil[.]com")
    assert t == IOCType.URL
    assert value == "https://evil.com"


def test_detect_ipv6_zone_id_stripped() -> None:
    t, value = detect("fe80::1%eth0")
    assert t == IOCType.IPV6
    assert value == "fe80::1"


def test_detect_ipv6_canonical_compression() -> None:
    t, value = detect("2001:0db8:0000:0000:0000:0000:0000:0001")
    assert t == IOCType.IPV6
    assert value == "2001:db8::1"


def test_is_hash_and_is_network_classifiers() -> None:
    assert is_hash(IOCType.SHA256)
    assert not is_hash(IOCType.IPV4)
    assert is_network(IOCType.DOMAIN)
    assert not is_network(IOCType.MD5)
