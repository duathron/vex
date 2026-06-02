"""Regression: VT returns pe_info.machine_type as an int (e.g. 332 = 0x14C i386),
but PEInfo.target_machine is a str field. _parse_pe_info must coerce it instead
of raising a Pydantic ValidationError (broke `vex investigate <sha1>` on PE files)."""

from __future__ import annotations

from vex.enrichers.hash import _parse_pe_info


def test_int_machine_type_coerced_to_str() -> None:
    pe = _parse_pe_info({"pe_info": {"machine_type": 332, "entry_point": 4096}})
    assert pe is not None
    assert pe.target_machine == "332"  # coerced, no ValidationError


def test_str_machine_type_preserved() -> None:
    pe = _parse_pe_info({"pe_info": {"machine_type": "AMD64"}})
    assert pe.target_machine == "AMD64"


def test_missing_machine_type_is_none() -> None:
    pe = _parse_pe_info({"pe_info": {"entry_point": 4096}})
    assert pe.target_machine is None


def test_no_pe_info_returns_none() -> None:
    assert _parse_pe_info({}) is None
