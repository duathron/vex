"""Tests for vex.output.html — self-contained HTML report export.

No network calls. All results are built in-memory.
"""

from __future__ import annotations

import os

from vex.models import (
    DetectionStats,
    InvestigateResult,
    TriageResult,
    Verdict,
)
from vex.output.html import write_html_report

# ---------------------------------------------------------------------------
# Fixtures: minimal in-memory results
# ---------------------------------------------------------------------------


def _make_triage(ioc: str = "evil.com", verdict: Verdict = Verdict.MALICIOUS) -> TriageResult:
    return TriageResult(
        ioc=ioc,
        ioc_type="domain",
        verdict=verdict,
        detection_stats=DetectionStats(malicious=30, suspicious=2, undetected=20),
        malware_families=["TestFamily"],
        tags=["c2"],
    )


def _make_triage_url(ioc: str = "https://evil.example.com/payload") -> TriageResult:
    return TriageResult(
        ioc=ioc,
        ioc_type="url",
        verdict=Verdict.MALICIOUS,
        detection_stats=DetectionStats(malicious=15, suspicious=0, undetected=55),
    )


def _make_investigate(ioc: str = "evil.com") -> InvestigateResult:
    triage = _make_triage(ioc=ioc)
    return InvestigateResult(
        triage=triage,
        file_type="PE32",
        file_size=102400,
        contacted_ips=["1.2.3.4"],
        contacted_domains=["c2.evil.com"],
    )


# ---------------------------------------------------------------------------
# Basic existence and structure tests
# ---------------------------------------------------------------------------


class TestWriteHtmlReport:
    def test_creates_file(self, tmp_path) -> None:
        path = str(tmp_path / "report.html")
        write_html_report(path, [_make_triage()])
        assert os.path.exists(path)

    def test_file_is_nonempty(self, tmp_path) -> None:
        path = str(tmp_path / "report.html")
        write_html_report(path, [_make_triage()])
        assert os.path.getsize(path) > 0

    def test_contains_html_tag(self, tmp_path) -> None:
        path = str(tmp_path / "report.html")
        write_html_report(path, [_make_triage()])
        content = open(path, encoding="utf-8").read()
        assert "<html" in content.lower()

    def test_empty_results_creates_file(self, tmp_path) -> None:
        path = str(tmp_path / "empty.html")
        write_html_report(path, [])
        assert os.path.exists(path)


# ---------------------------------------------------------------------------
# Defanging: domain IOC
# ---------------------------------------------------------------------------


class TestDefangingDomain:
    def test_domain_defanged_in_html(self, tmp_path) -> None:
        """The IOC 'evil.com' should appear defanged as 'evil[.]com' in the HTML."""
        path = str(tmp_path / "report.html")
        write_html_report(path, [_make_triage(ioc="evil.com")])
        content = open(path, encoding="utf-8").read()
        # Defanged form must be present
        assert "evil[.]com" in content

    def test_domain_live_form_not_in_html(self, tmp_path) -> None:
        """The live dot-separated domain should NOT appear as a raw hyperlink target."""
        path = str(tmp_path / "report.html")
        write_html_report(path, [_make_triage(ioc="evil.com")])
        content = open(path, encoding="utf-8").read()
        # The raw (non-defanged) clickable domain must not appear as an href
        assert 'href="http://evil.com"' not in content
        assert 'href="https://evil.com"' not in content


# ---------------------------------------------------------------------------
# Defanging: URL IOC
# ---------------------------------------------------------------------------


class TestDefangingURL:
    def test_url_defanged_in_html(self, tmp_path) -> None:
        """A URL IOC should be defanged — http(s) becomes hxxp(s)."""
        ioc = "https://evil.example.com/payload"
        path = str(tmp_path / "report.html")
        write_html_report(path, [_make_triage_url(ioc=ioc)])
        content = open(path, encoding="utf-8").read()
        # The defanged protocol must appear
        assert "hxxps" in content

    def test_url_live_http_not_as_ioc_in_html(self, tmp_path) -> None:
        """The live https:// form of the IOC must not appear verbatim in body text."""
        ioc = "https://evil.example.com/payload"
        path = str(tmp_path / "report.html")
        write_html_report(path, [_make_triage_url(ioc=ioc)])
        content = open(path, encoding="utf-8").read()
        # The defanged IOC string must not contain the live https:// form as IOC text
        # (Rich meta links in CSS/head are OK, but the IOC value row must be defanged)
        # We check the body doesn't contain the live IOC as plain text
        assert "https://evil.example.com/payload" not in content


# ---------------------------------------------------------------------------
# Batch list
# ---------------------------------------------------------------------------


class TestBatchList:
    def test_batch_two_triage(self, tmp_path) -> None:
        results = [
            _make_triage(ioc="evil.com"),
            _make_triage(ioc="bad.net", verdict=Verdict.SUSPICIOUS),
        ]
        path = str(tmp_path / "batch.html")
        write_html_report(path, results)
        content = open(path, encoding="utf-8").read()
        assert "<html" in content.lower()
        # Both IOCs should appear defanged
        assert "evil[.]com" in content
        assert "bad[.]net" in content

    def test_batch_investigate(self, tmp_path) -> None:
        results = [
            _make_investigate(ioc="evil.com"),
            _make_investigate(ioc="bad.net"),
        ]
        path = str(tmp_path / "batch_inv.html")
        write_html_report(path, results, mode="investigate")
        content = open(path, encoding="utf-8").read()
        assert "<html" in content.lower()
        assert "evil[.]com" in content
        assert "bad[.]net" in content


# ---------------------------------------------------------------------------
# Single InvestigateResult
# ---------------------------------------------------------------------------


class TestInvestigateResult:
    def test_investigate_creates_file(self, tmp_path) -> None:
        path = str(tmp_path / "investigate.html")
        write_html_report(path, [_make_investigate()], mode="investigate")
        assert os.path.exists(path)
        assert os.path.getsize(path) > 0

    def test_investigate_contains_html(self, tmp_path) -> None:
        path = str(tmp_path / "investigate.html")
        write_html_report(path, [_make_investigate()], mode="investigate")
        content = open(path, encoding="utf-8").read()
        assert "<html" in content.lower()

    def test_investigate_ioc_defanged(self, tmp_path) -> None:
        path = str(tmp_path / "investigate.html")
        write_html_report(path, [_make_investigate(ioc="evil.com")], mode="investigate")
        content = open(path, encoding="utf-8").read()
        assert "evil[.]com" in content

    def test_investigate_already_defanged_ioc(self, tmp_path) -> None:
        """If IOC is already defanged, it must not be double-defanged."""
        already_defanged = "evil[.]com"
        triage = TriageResult(
            ioc=already_defanged,
            ioc_type="domain",
            verdict=Verdict.CLEAN,
            detection_stats=DetectionStats(),
        )
        result = InvestigateResult(triage=triage)
        path = str(tmp_path / "already.html")
        write_html_report(path, [result], mode="investigate")
        content = open(path, encoding="utf-8").read()
        # Should still appear (not mangled)
        assert "evil[.]com" in content
        # Should not be double-defanged like evil[[.]com or evil[.]com[.]
        assert "evil[[.]" not in content


# ---------------------------------------------------------------------------
# Mixed list (TriageResult and InvestigateResult together)
# ---------------------------------------------------------------------------


class TestMixedList:
    def test_mixed_triage_and_investigate(self, tmp_path) -> None:
        results = [
            _make_triage(ioc="evil.com"),
            _make_investigate(ioc="bad.net"),
        ]
        path = str(tmp_path / "mixed.html")
        write_html_report(path, results)
        content = open(path, encoding="utf-8").read()
        assert "<html" in content.lower()
        assert "evil[.]com" in content
        assert "bad[.]net" in content
