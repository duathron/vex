"""Tests for vex.output.html — self-contained HTML report export.

No network calls. All results are built in-memory.
"""

from __future__ import annotations

import os
import re

import pytest

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


# ---------------------------------------------------------------------------
# Render safety: title escape, link neutralisation (no network)
# ---------------------------------------------------------------------------


def _read(tmp_path, results):
    p = tmp_path / "r.html"
    write_html_report(str(p), results)
    return p.read_text(encoding="utf-8")


def test_html_title_escaped(tmp_path):
    import re

    html = _read(tmp_path, [_make_triage(ioc="http://a.test/</title><script>alert(1)</script>")])
    m = re.search(r"<title>(.*?)</title>", html, re.S)
    assert m is not None
    assert "&lt;/title&gt;" in m.group(1)
    assert "<script>" not in m.group(1)


def test_html_no_javascript_href(tmp_path):
    tri = _make_triage()
    tri.tags = ["[link=javascript:alert(1)]click[/link]"]
    html = _read(tmp_path, [tri])
    assert 'href="javascript:' not in html


def test_html_unsafe_href_neutralised_even_if_sanitizer_bypassed(tmp_path, monkeypatch):
    import vex.output.html as vh

    monkeypatch.setattr(vh, "sanitize_for_render", lambda x: x)
    tri = _make_triage()
    tri.tags = ["[link=javascript:alert(1)]click[/link]"]
    html = _read(tmp_path, [tri])
    assert 'href="javascript:' not in html


def test_html_https_href_kept(tmp_path, monkeypatch):
    import vex.output.html as vh

    monkeypatch.setattr(vh, "sanitize_for_render", lambda x: x)
    tri = _make_triage()
    tri.tags = ["[link=https://ok.example/x]click[/link]"]
    html = _read(tmp_path, [tri])
    assert 'href="https://ok.example/x"' in html


def test_html_markup_in_api_fields_renders_literally_triage(tmp_path):
    tri = _make_triage()
    tri.tags = ["x [/bogus] y [bold]z"]
    html = _read(tmp_path, [tri])
    assert "x [/bogus] y [bold]z" in html


def test_html_markup_in_api_fields_renders_literally_investigate(tmp_path):
    inv = InvestigateResult(
        triage=_make_triage(), file_type="exe", file_names=["a [/bogus] [bold]b"], magic="m \x1b]0;PWN\x07"
    )
    html = _read(tmp_path, [inv])
    assert "a [/bogus] [bold]b" in html
    assert "PWN" not in html


_ATTR_PAYLOADS = [
    '[link=https://a.test/"onmouseover="alert(1)]c[/link]',
    '[link=https://a/"style="x]c[/link]',
    "[link=data:text/html;base64,AAAA]c[/link]",
    "[link=JAVASCRIPT:alert(1)]c[/link]",
    "[link=//evil.example/x]c[/link]",
    "[link= https://evil.example/x]c[/link]",
]


@pytest.mark.parametrize("payload", _ATTR_PAYLOADS)
def test_html_link_attribute_allowlist_with_sanitizer_bypassed(tmp_path, monkeypatch, payload):
    import re

    import vex.output.html as vh

    monkeypatch.setattr(vh, "sanitize_for_render", lambda x: x)
    monkeypatch.setattr(vh, "_strip_unsafe_links", lambda rec: None)  # exercise the second layer alone
    tri = _make_triage()
    tri.tags = [payload]
    html = _read(tmp_path, [tri])
    tags = re.findall(r"<a\b[^>]*>", html, re.I)
    assert tags
    for t in tags:
        assert re.fullmatch(r'<a href="(?:https?://[^\s"\'<>]*|#)">', t), t


def test_html_signature_bracket_template_cannot_forge_markup(tmp_path):
    for verified in ("link=https://evil.example/login]Signed OK[/link", "bold green]VERIFIED[/bold green"):
        inv = InvestigateResult(
            triage=_make_triage(),
            file_type="exe",
            signature_info={"subject": "Microsoft", "verified": verified},
        )
        html = _read(tmp_path, [inv])
        assert "<a href" not in html
        assert "VERIFIED" in html or "Signed OK" in html
        assert "font-weight: bold" not in html.split("Signature", 1)[1].split("</pre>")[0]


def test_html_sanitizer_runs_on_defanged_result(tmp_path, monkeypatch):
    import vex.output.html as vh

    seen = []
    real = vh.sanitize_for_render

    def spy(x):
        seen.append(x.triage.ioc if hasattr(x, "triage") else x.ioc)
        return real(x)

    monkeypatch.setattr(vh, "sanitize_for_render", spy)
    _read(tmp_path, [_make_triage(ioc="http://evil.com/x"), _make_investigate(ioc="http://evil.org/y")])
    assert len(seen) == 2
    assert all("hxxp" in s for s in seen), seen


def test_html_title_strips_control_and_bidi(tmp_path):
    html = _read(tmp_path, [_make_triage(ioc="evil.com\u202e\x1b]0;x\x07")])
    title = html.split("<title>", 1)[1].split("</title>", 1)[0]
    assert "\u202e" not in title and "\x1b" not in title and "\x07" not in title


_SPLIT = '[link=https://a"><img/src=x/onerror=alert(1)><a/href="https://b]x[/link]'


def _parse_dom(html):
    from html.parser import HTMLParser

    class P(HTMLParser):
        def __init__(self):
            super().__init__()
            self.tags = []

        def handle_starttag(self, tag, attrs):
            self.tags.append((tag, attrs))

    p = P()
    p.feed(html)
    return p.tags


def _assert_links_clean(html):
    tags = _parse_dom(html)
    assert not [t for t, _ in tags if t == "img"]
    for tag, attrs in tags:
        if tag == "a":
            assert [k for k, _ in attrs] == ["href"], attrs
            assert re.fullmatch(r"https?://[^\s\"'<>]*|#", attrs[0][1] or ""), attrs


@pytest.mark.parametrize("where", ["tags", "subject"])
def test_html_tag_splitting_link_value_cannot_inject_elements(tmp_path, monkeypatch, where):
    import vex.output.html as vh

    monkeypatch.setattr(vh, "sanitize_for_render", lambda x: x)
    if where == "tags":
        tri = _make_triage()
        tri.tags = [_SPLIT]
        results = [tri]
    else:
        results = [
            InvestigateResult(
                triage=_make_triage(), file_type="exe", signature_info={"subject": _SPLIT, "verified": "ok"}
            )
        ]
    _assert_links_clean(_read(tmp_path, results))


def test_html_legit_link_with_query_stays_clickable(tmp_path, monkeypatch):
    import vex.output.html as vh

    monkeypatch.setattr(vh, "sanitize_for_render", lambda x: x)
    tri = _make_triage()
    tri.tags = ["[link=https://ok.example/x?a=1&b=2]go[/link]"]
    html = _read(tmp_path, [tri])
    assert [a for t, a in _parse_dom(html) if t == "a"] == [[("href", "https://ok.example/x?a=1&b=2")]]
