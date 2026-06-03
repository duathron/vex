"""Regression tests: malformed/edge-case VT field types.

Each test feeds a malformed VT-style payload into the affected parser and
asserts no exception is raised and a sensible value is returned (None / 0 / []).
Behaviour on valid data is covered by the existing test suite; these tests
specifically target the crash-inducing edge cases found in the audit.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from vex.config import Config
from vex.enrichers import domain as domain_enricher
from vex.enrichers import ip as ip_enricher
from vex.enrichers.base import _ts, parse_stats, safe_int, safe_timestamp
from vex.enrichers.hash import _parse_pe_info

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(malicious_min: int = 3, suspicious_min: int = 1, min_engines: int = 10) -> Config:
    cfg = Config()
    cfg.api.key = "fake-key-00000000"
    cfg.api.tier = "free"
    cfg.thresholds.malicious_min_detections = malicious_min
    cfg.thresholds.suspicious_min_detections = suspicious_min
    cfg.thresholds.min_engines_for_clean = min_engines
    cfg.enrichment.whois_enabled = False
    return cfg


def _fake_client(**methods) -> MagicMock:
    client = MagicMock()
    for name, retval in methods.items():
        getattr(client, name).return_value = retval
    return client


def _ip_attrs(extra: dict | None = None) -> dict:
    """Minimal VT IP attributes dict, enough to pass through investigate()."""
    base = {
        "last_analysis_stats": {"malicious": 0, "suspicious": 0, "undetected": 50},
        "last_analysis_results": {},
        "tags": [],
        "categories": {},
    }
    if extra:
        base.update(extra)
    return base


def _domain_attrs(extra: dict | None = None) -> dict:
    base = {
        "last_analysis_stats": {"malicious": 0, "suspicious": 0, "undetected": 50},
        "last_analysis_results": {},
        "tags": [],
        "categories": {},
    }
    if extra:
        base.update(extra)
    return base


# ---------------------------------------------------------------------------
# Finding 1 & hash ts_raw (Findings 1 & 3): safe_timestamp / _ts with bad input
# ---------------------------------------------------------------------------


class TestSafeTimestamp:
    def test_dict_returns_none(self):
        assert safe_timestamp({"nested": "junk"}) is None

    def test_none_returns_none(self):
        assert safe_timestamp(None) is None

    def test_string_returns_none(self):
        assert safe_timestamp("2023-01-01") is None

    def test_bool_true_returns_none(self):
        # bool is a subclass of int — must be excluded
        assert safe_timestamp(True) is None

    def test_bool_false_returns_none(self):
        assert safe_timestamp(False) is None

    def test_list_returns_none(self):
        assert safe_timestamp([1234567890]) is None

    def test_valid_int_returns_datetime(self):
        from datetime import datetime, timezone

        result = safe_timestamp(1609459200)  # 2021-01-01T00:00:00Z
        assert result is not None
        assert result == datetime(2021, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    def test_valid_float_returns_datetime(self):
        result = safe_timestamp(1609459200.5)
        assert result is not None

    def test_overflow_returns_none(self):
        assert safe_timestamp(10**20) is None


class TestTsWrapper:
    """_ts() must not raise on non-numeric input (Finding 1)."""

    def test_dict_value_returns_none(self):
        # Before fix: datetime.fromtimestamp({"key": "val"}) → TypeError (uncaught)
        assert _ts({"key": "val"}) is None

    def test_string_value_returns_none(self):
        assert _ts("not-a-timestamp") is None

    def test_none_returns_none(self):
        assert _ts(None) is None

    def test_valid_unix_returns_datetime(self):
        result = _ts(1609459200)
        assert result is not None


# ---------------------------------------------------------------------------
# Finding 2: parse_stats() with null/string values
# ---------------------------------------------------------------------------


class TestParseStats:
    def test_null_values_default_to_zero(self):
        # Before fix: DetectionStats(malicious=None) → Pydantic ValidationError
        stats = parse_stats({"malicious": None, "suspicious": None, "undetected": None})
        assert stats.malicious == 0
        assert stats.suspicious == 0
        assert stats.undetected == 0

    def test_string_values_coerced(self):
        stats = parse_stats({"malicious": "5", "suspicious": "2", "undetected": "10"})
        assert stats.malicious == 5
        assert stats.suspicious == 2

    def test_non_coercible_string_defaults_to_zero(self):
        stats = parse_stats({"malicious": "N/A", "suspicious": "unknown"})
        assert stats.malicious == 0
        assert stats.suspicious == 0

    def test_empty_dict_all_zeros(self):
        stats = parse_stats({})
        assert stats.malicious == 0
        assert stats.total == 0

    def test_valid_ints_unchanged(self):
        stats = parse_stats({"malicious": 3, "suspicious": 1, "undetected": 50})
        assert stats.malicious == 3
        assert stats.suspicious == 1
        assert stats.undetected == 50


# ---------------------------------------------------------------------------
# Finding 3: hash.py ts_raw (pe timestamp as dict / non-numeric)
# ---------------------------------------------------------------------------


class TestHashPeTimestamp:
    def test_pe_timestamp_as_dict_no_crash(self):
        # Before fix: datetime.fromtimestamp({"ts": 0}) → TypeError not caught
        attrs = {"pe_info": {"timestamp": {"value": 1609459200}, "machine_type": 332}}
        result = _parse_pe_info(attrs)
        assert result is not None
        assert result.compilation_timestamp is None  # bad type → None

    def test_pe_timestamp_as_string_no_crash(self):
        attrs = {"pe_info": {"timestamp": "2021-01-01T00:00:00", "machine_type": 332}}
        result = _parse_pe_info(attrs)
        assert result is not None
        assert result.compilation_timestamp is None

    def test_pe_timestamp_as_none_no_crash(self):
        attrs = {"pe_info": {"timestamp": None, "machine_type": 332}}
        result = _parse_pe_info(attrs)
        assert result is not None
        assert result.compilation_timestamp is None

    def test_pe_timestamp_valid_int_preserved(self):
        attrs = {"pe_info": {"timestamp": 1609459200, "machine_type": 332}}
        result = _parse_pe_info(attrs)
        assert result is not None
        assert result.compilation_timestamp is not None


# ---------------------------------------------------------------------------
# Finding 4: domain.py WHOIS dates — str() coerced missing/null into "" or "None"
# (old: str(get("creation_date","")) → "" for a missing key, "None" for explicit null)
# ---------------------------------------------------------------------------


class TestDomainWhoisDates:
    """Missing or non-string WHOIS dates must pass through as None, not "" or "None"."""

    def _run_investigate(self, whois_attrs: dict) -> object:
        attrs = _domain_attrs()
        whois_entry = {"attributes": whois_attrs}
        client = _fake_client(
            get_domain={"data": {"attributes": attrs}},
            get_domain_resolutions={"data": []},
            get_domain_communicating_files={"data": []},
            get_domain_whois={"data": [whois_entry]},
        )
        cfg = _make_config()
        cfg.api.tier = "premium"
        return domain_enricher.investigate("example.com", "domain", client, cfg)

    def test_missing_creation_date_is_none_not_string(self):
        result = self._run_investigate({"registrar": "ICANN"})  # no dates
        assert result.whois is not None
        # Before fix: str(get("creation_date", "")) → "" (empty string) for a missing key
        assert result.whois.creation_date is None

    def test_missing_expiration_date_is_none(self):
        result = self._run_investigate({"registrar": "ICANN"})
        assert result.whois.expiration_date is None

    def test_missing_updated_date_is_none(self):
        result = self._run_investigate({"registrar": "ICANN"})
        assert result.whois.updated_date is None

    def test_valid_string_date_preserved(self):
        result = self._run_investigate(
            {
                "registrar": "ICANN",
                "creation_date": "2000-01-01",
                "expiration_date": "2030-01-01",
                "updated_date": "2023-06-01",
            }
        )
        assert result.whois.creation_date == "2000-01-01"
        assert result.whois.expiration_date == "2030-01-01"
        assert result.whois.updated_date == "2023-06-01"

    def test_non_string_creation_date_becomes_none(self):
        # VT might return an int unix ts for the date field
        result = self._run_investigate({"creation_date": 1609459200})
        assert result.whois.creation_date is None


# ---------------------------------------------------------------------------
# Finding 5: ip.py asn as non-numeric string
# ---------------------------------------------------------------------------


class TestIPAsnCoercion:
    def _run_investigate(self, extra_attrs: dict) -> object:
        attrs = _ip_attrs(extra_attrs)
        client = _fake_client(
            get_ip={"data": {"attributes": attrs}},
            get_ip_resolutions={"data": []},
            get_ip_communicating_files={"data": []},
            get_ip_downloaded_files={"data": []},
        )
        return ip_enricher.investigate("8.8.8.8", "ip", client, _make_config())

    def test_asn_as_string_with_prefix_returns_none(self):
        # "AS15169" cannot be coerced to int → None (no ValidationError)
        result = self._run_investigate({"asn": "AS15169"})
        assert result.asn is None

    def test_asn_as_numeric_string_coerced(self):
        result = self._run_investigate({"asn": "15169"})
        assert result.asn == 15169

    def test_asn_as_none_returns_none(self):
        result = self._run_investigate({"asn": None})
        assert result.asn is None

    def test_asn_as_valid_int_preserved(self):
        result = self._run_investigate({"asn": 15169})
        assert result.asn == 15169


# ---------------------------------------------------------------------------
# Finding 6: hash.py exports_list as non-list
# ---------------------------------------------------------------------------


class TestExportsList:
    def test_exports_list_as_dict_returns_empty(self):
        # Before fix: dict[:20] → TypeError
        attrs = {"pe_info": {"exports_list": {"func_a": 1, "func_b": 2}}}
        result = _parse_pe_info(attrs)
        assert result is not None
        assert result.exports == []

    def test_exports_list_as_none_returns_empty(self):
        attrs = {"pe_info": {"exports_list": None}}
        result = _parse_pe_info(attrs)
        assert result is not None
        assert result.exports == []

    def test_exports_list_as_string_returns_empty(self):
        attrs = {"pe_info": {"exports_list": "ExportedFunc"}}
        result = _parse_pe_info(attrs)
        assert result is not None
        assert result.exports == []

    def test_exports_list_missing_returns_empty(self):
        # An empty pe_info dict is falsy → _parse_pe_info returns None (existing behaviour).
        # Test with a non-empty pe_info that simply lacks exports_list.
        attrs = {"pe_info": {"machine_type": 332}}
        result = _parse_pe_info(attrs)
        assert result is not None
        assert result.exports == []

    def test_exports_list_valid_list_preserved(self):
        exports = ["func_a", "func_b", "func_c"]
        attrs = {"pe_info": {"exports_list": exports}}
        result = _parse_pe_info(attrs)
        assert result is not None
        assert result.exports == exports

    def test_exports_list_truncated_to_20(self):
        exports = [f"func_{i}" for i in range(30)]
        attrs = {"pe_info": {"exports_list": exports}}
        result = _parse_pe_info(attrs)
        assert result is not None
        assert result.exports == exports[:20]


# ---------------------------------------------------------------------------
# safe_int: direct unit tests
# ---------------------------------------------------------------------------


class TestSafeInt:
    def test_int_returned_as_is(self):
        assert safe_int(42) == 42

    def test_zero_returned(self):
        assert safe_int(0) == 0

    def test_numeric_string_coerced(self):
        assert safe_int("15169") == 15169

    def test_string_with_whitespace_coerced(self):
        assert safe_int("  42  ") == 42

    def test_non_numeric_string_returns_none(self):
        assert safe_int("AS15169") is None

    def test_none_returns_none(self):
        assert safe_int(None) is None

    def test_dict_returns_none(self):
        assert safe_int({"value": 1}) is None

    def test_list_returns_none(self):
        assert safe_int([1]) is None

    def test_bool_true_returns_none(self):
        # bool is a subclass of int — must be excluded
        assert safe_int(True) is None

    def test_bool_false_returns_none(self):
        assert safe_int(False) is None

    def test_float_returns_none(self):
        # float is not int/bool; str("3.9") can't be int()-ed directly → None
        assert safe_int(3.9) is None
