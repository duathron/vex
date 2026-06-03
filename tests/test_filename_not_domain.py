"""Regression: executable/script filenames (e.g. wcdbcrk.dll, payload.exe) matched
the domain regex and were classified DOMAIN -> bogus VT domain lookup -> HTTP 400.
Their extensions are not real TLDs, so they must detect as UNKNOWN. Real TLDs that
look extension-ish (.zip, .app, .dev, .mov) must still be DOMAIN."""

from __future__ import annotations

import pytest

from vex.ioc_detector import IOCType, detect


@pytest.mark.parametrize(
    "name",
    [
        "wcdbcrk.dll",
        "payload.exe",
        "evil.sys",
        "dropper.scr",
        "run.bat",
        "stage.ps1",
        "macro.vbs",
        "installer.msi",
        "shortcut.lnk",
        "x.cpl",
    ],
)
def test_executable_filenames_are_not_domains(name: str) -> None:
    assert detect(name)[0] == IOCType.UNKNOWN


@pytest.mark.parametrize(
    "domain",
    ["evil.com", "sub.example.co.uk", "files.zip", "my.app", "a.dev", "trailer.mov", "host.io", "x.sh"],
)
def test_real_tlds_still_detect_as_domain(domain: str) -> None:
    # .zip/.app/.dev/.mov/.sh are real TLDs — must NOT be excluded as file extensions
    assert detect(domain)[0] == IOCType.DOMAIN
