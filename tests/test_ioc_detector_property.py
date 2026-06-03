"""Property-based + regression tests for the IOC detection parse boundary.

Hypothesis generates arbitrary inputs — the class of bug mock-based tests miss.
detect() must never crash, must honour its (IOCType, str) contract, and must
never misclassify a filename (e.g. *.dll) as a domain.
"""
from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from vex.ioc_detector import (
    _FILE_EXTENSIONS,
    IOCType,
    detect,
)


@given(st.text())
def test_detect_never_crashes_and_honours_contract(value):
    ioc_type, normalised = detect(value)
    assert isinstance(ioc_type, IOCType)
    assert isinstance(normalised, str)


@given(
    st.text(
        alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd")),
        min_size=1,
        max_size=20,
    ),
    st.sampled_from(sorted(_FILE_EXTENSIONS)),
)
def test_filenames_never_classified_as_domain(stem, ext):
    ioc_type, _ = detect(f"{stem}.{ext}")
    assert ioc_type is not IOCType.DOMAIN


def test_dll_regression_and_real_domains():
    assert detect("wcdbcrk.dll")[0] is IOCType.UNKNOWN
    assert detect("report.dll")[0] is IOCType.UNKNOWN
    assert detect("example.com")[0] is IOCType.DOMAIN
    assert detect("evil.app")[0] is IOCType.DOMAIN
