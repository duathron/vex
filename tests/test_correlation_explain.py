"""Tests for AI correlation narratives (v1.3.0 P1 — MeetUp VEX-2026-008).

All tests are offline — no real LLM or network calls.
A FAKE provider stub is used for provider-present paths.

Patch paths for locally-imported symbols inside _run_correlation_explain:
  - get_provider  → "vex.ai.get_provider"
  - AICache       → "vex.ai.cache.AICache"
"""

from __future__ import annotations

from typing import Optional
from unittest.mock import MagicMock, patch

from vex.ai.prompt import build_correlation_prompt
from vex.ai.template import template_correlation
from vex.correlate import Cluster, build_clusters
from vex.models import DetectionStats, TriageResult, Verdict
from vex.output.export import _cluster_to_dict

# ---------------------------------------------------------------------------
# FAKE provider stub — no network, no deps
# ---------------------------------------------------------------------------


class FakeProvider:
    """Minimal stub implementing the LLMProviderProtocol."""

    name = "fake"
    call_count: int = 0

    def explain(
        self,
        prompt: str,
        *,
        system: Optional[str] = None,
        max_tokens: int = 512,
        temperature: float = 0.2,
    ) -> str:
        FakeProvider.call_count += 1
        return f"[FAKE] Cluster narrative for prompt of {len(prompt)} chars."

    @classmethod
    def reset(cls) -> None:
        cls.call_count = 0


class ErrorProvider:
    """Provider that always raises on .explain()."""

    name = "error_provider"

    def explain(self, prompt, *, system=None, max_tokens=512, temperature=0.2):
        raise RuntimeError("Simulated LLM API failure")


class CountingProvider:
    """Provider that counts calls."""

    name = "counting"
    call_count: int = 0

    def explain(self, prompt, *, system=None, max_tokens=512, temperature=0.2):
        CountingProvider.call_count += 1
        return "Live narrative"

    @classmethod
    def reset(cls) -> None:
        cls.call_count = 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_STATS = DetectionStats(malicious=3, undetected=60)


def _make_cluster(
    cluster_id: str = "C1",
    attribute_type: str = "asn",
    shared_attribute: str = "ASN 12345 (EVILNET)",
    members: list[str] | None = None,
    max_verdict: Verdict = Verdict.MALICIOUS,
    explanation: Optional[str] = None,
) -> Cluster:
    members = members or ["1.2.3.4", "5.6.7.8"]
    return Cluster(
        cluster_id=cluster_id,
        attribute_type=attribute_type,
        shared_attribute=shared_attribute,
        members=members,
        member_count=len(members),
        max_verdict=max_verdict,
        explanation=explanation,
    )


def _triage(ioc: str, families: list[str] | None = None) -> TriageResult:
    return TriageResult(
        ioc=ioc,
        ioc_type="domain",
        verdict=Verdict.MALICIOUS,
        detection_stats=_STATS,
        malware_families=families or [],
    )


def _make_aicache_mock(cached_value: Optional[str] = None) -> MagicMock:
    """Return a context-manager mock for AICache with optional cached hit."""
    mock_cache_instance = MagicMock()
    mock_cache_instance.__enter__ = MagicMock(return_value=mock_cache_instance)
    mock_cache_instance.__exit__ = MagicMock(return_value=False)
    mock_cache_instance.get.return_value = cached_value
    return mock_cache_instance


def _default_config():
    from vex.config import Config

    config = Config()
    config.ai.provider = "fake"
    config.ai.model = "test-model"
    config.ai.cache_ttl_hours = 72
    return config


# ---------------------------------------------------------------------------
# 1. Cluster model: explanation field
# ---------------------------------------------------------------------------


def test_cluster_explanation_defaults_to_none() -> None:
    cl = _make_cluster()
    assert cl.explanation is None


def test_cluster_explanation_can_be_set() -> None:
    cl = _make_cluster(explanation="Some narrative.")
    assert cl.explanation == "Some narrative."


# ---------------------------------------------------------------------------
# 2. export._cluster_to_dict: explanation serialisation
# ---------------------------------------------------------------------------


def test_cluster_to_dict_no_explanation_key_absent() -> None:
    cl = _make_cluster()
    d = _cluster_to_dict(cl)
    assert "explanation" not in d
    assert d["cluster_id"] == "C1"
    assert d["max_verdict"] == Verdict.MALICIOUS.value


def test_cluster_to_dict_with_explanation_included() -> None:
    cl = _make_cluster(explanation="A narrative.")
    d = _cluster_to_dict(cl)
    assert d["explanation"] == "A narrative."
    assert d["cluster_id"] == "C1"


# ---------------------------------------------------------------------------
# 3. build_correlation_prompt — structure and defanging
# ---------------------------------------------------------------------------


def test_build_correlation_prompt_contains_cluster_fields() -> None:
    cl = _make_cluster(
        cluster_id="C1",
        attribute_type="asn",
        shared_attribute="ASN 13335 (CLOUDFLARENET)",
        members=["1.1.1.1", "1.0.0.1"],
        max_verdict=Verdict.SUSPICIOUS,
    )
    prompt = build_correlation_prompt(cl)
    assert "C1" in prompt
    assert "asn" in prompt
    assert "ASN 13335" in prompt
    assert Verdict.SUSPICIOUS.value.lower() in prompt.lower()
    assert "2" in prompt  # member count


def test_build_correlation_prompt_defangs_http_iocs() -> None:
    """IOCs with http:// must appear defanged in the prompt — no bare http://."""
    cl = _make_cluster(
        members=["http://evil.com/payload", "http://bad.org/malware"],
    )
    prompt = build_correlation_prompt(cl)
    assert "http://" not in prompt
    assert "hxxp" in prompt


def test_build_correlation_prompt_defangs_domain_dots() -> None:
    """Bare domain dots must be replaced with [.] in the prompt."""
    cl = _make_cluster(
        members=["evil.com", "bad.org"],
        attribute_type="family",
        shared_attribute="family:emotet",
    )
    prompt = build_correlation_prompt(cl)
    assert "evil[.]com" in prompt
    assert "bad[.]org" in prompt
    assert "evil.com" not in prompt
    assert "bad.org" not in prompt


def test_build_correlation_prompt_returns_str() -> None:
    cl = _make_cluster()
    assert isinstance(build_correlation_prompt(cl), str)


# ---------------------------------------------------------------------------
# 4. template_correlation — deterministic fallback
# ---------------------------------------------------------------------------


def test_template_correlation_returns_str() -> None:
    cl = _make_cluster()
    result = template_correlation(cl)
    assert isinstance(result, str)
    assert len(result) > 20


def test_template_correlation_mentions_attribute() -> None:
    cl = _make_cluster(shared_attribute="ASN 12345 (EVILNET)", attribute_type="asn")
    result = template_correlation(cl)
    assert "ASN 12345 (EVILNET)" in result


def test_template_correlation_mentions_member_count() -> None:
    cl = _make_cluster(members=["a.com", "b.com", "c.com"])
    result = template_correlation(cl)
    assert "3" in result


def test_template_correlation_family_attribute() -> None:
    cl = _make_cluster(attribute_type="family", shared_attribute="family:emotet")
    result = template_correlation(cl)
    assert "family" in result.lower() or "malware" in result.lower()


def test_template_correlation_ip_attribute() -> None:
    cl = _make_cluster(attribute_type="ip", shared_attribute="ip:192.168.1.1")
    result = template_correlation(cl)
    lower = result.lower()
    assert "c2" in lower or "ip" in lower


def test_template_correlation_unknown_attribute_type_fallback() -> None:
    cl = _make_cluster(attribute_type="custom_unknown", shared_attribute="something")
    result = template_correlation(cl)
    assert isinstance(result, str)
    assert len(result) > 10


# ---------------------------------------------------------------------------
# 5. Provider present → each cluster gets a narrative
# ---------------------------------------------------------------------------


def test_provider_present_fills_explanation() -> None:
    """When a provider is available and cache misses, each cluster.explanation is set."""
    from vex.main import OutputFormat, _run_correlation_explain

    FakeProvider.reset()
    config = _default_config()
    clusters = [
        _make_cluster("C1"),
        _make_cluster("C2", attribute_type="family", shared_attribute="family:qakbot"),
    ]
    mock_cache = _make_aicache_mock(cached_value=None)  # no cache hit

    with (
        patch("vex.ai.get_provider", return_value=FakeProvider()),
        patch("vex.ai.cache.AICache", return_value=mock_cache),
    ):
        _run_correlation_explain(clusters, config, None, OutputFormat.console)

    for cl in clusters:
        assert cl.explanation is not None
        assert len(cl.explanation) > 0


# ---------------------------------------------------------------------------
# 6. No provider → template fallback fills explanation
# ---------------------------------------------------------------------------


def test_no_provider_uses_template_fallback() -> None:
    """When provider returns None (ai.provider='none'), template fills explanation.

    UNCHANGED by F2 cut-1: ai.provider="none" is a DELIBERATE non-LLM choice,
    never degraded, regardless of the F2 posture change to the error-path
    sibling test above."""
    from vex.config import Config
    from vex.main import OutputFormat, _run_correlation_explain

    config = Config()
    config.ai.provider = "none"
    clusters = [_make_cluster("C1")]

    with patch("vex.ai.get_provider", return_value=None):
        _run_correlation_explain(clusters, config, None, OutputFormat.console)

    cl = clusters[0]
    assert cl.explanation is not None
    assert len(cl.explanation) > 10
    assert cl.explanation_degraded is False
    assert cl.explanation_provider is None


# ---------------------------------------------------------------------------
# 7. Provider error → degraded marker, NOT template fallback (F2 cut-1)
#
# FLIPPED for F2 cut-1 (2026-07-03 MeetUp — 2026-07-03-f2-llm-failure-posture.md).
#   OLD posture (pinned here before the flip): when provider.explain() raised,
#     _run_correlation_explain SILENTLY substituted template_correlation()'s
#     output as cluster.explanation — the analyst received a rule-based
#     template believing it was an LLM narrative.
#   NEW posture (asserted below): cluster.explanation stays None,
#     cluster.explanation_degraded is set True, cluster.explanation_provider
#     records which provider failed, and the loud stderr notice is printed.
#     _run_correlation_explain still does not raise (the caller,
#     cmd_triage/cmd_investigate, decides the exit code — see Task 7).
#   WHY: BLOCK condition (2026-07-03 F2 MeetUp) — "any output where a
#     template reaches the analyst without a machine degraded/provider
#     marker" must be flipped with documented before/after.
# ---------------------------------------------------------------------------


def test_provider_error_sets_degraded_marker_not_template(capsys) -> None:
    """If provider.explain raises, the cluster is marked degraded — no
    template substitution, no crash."""
    from vex.main import OutputFormat, _run_correlation_explain

    config = _default_config()
    clusters = [_make_cluster("C1")]
    mock_cache = _make_aicache_mock(cached_value=None)
    expected_template = template_correlation(clusters[0])

    with (
        patch("vex.ai.get_provider", return_value=ErrorProvider()),
        patch("vex.ai.cache.AICache", return_value=mock_cache),
    ):
        # Must not raise — the error is caught and marked, not propagated.
        _run_correlation_explain(clusters, config, None, OutputFormat.console)

    cl = clusters[0]
    assert cl.explanation is None
    assert cl.explanation != expected_template  # no silent template substitution
    assert cl.explanation_degraded is True
    assert cl.explanation_provider == "error_provider"

    captured = capsys.readouterr()
    assert "EXPLANATION UNAVAILABLE" in captured.out or "EXPLANATION UNAVAILABLE" in captured.err


# ---------------------------------------------------------------------------
# 8. Cache hit: AICache hit avoids .explain call
# ---------------------------------------------------------------------------


def test_cache_hit_avoids_explain_call() -> None:
    """When AICache returns a hit, provider.explain is never called."""
    from vex.main import OutputFormat, _run_correlation_explain

    CountingProvider.reset()
    cached_narrative = "Cached narrative from a previous run."
    config = _default_config()
    clusters = [_make_cluster("C1"), _make_cluster("C2")]
    mock_cache = _make_aicache_mock(cached_value=cached_narrative)

    with (
        patch("vex.ai.get_provider", return_value=CountingProvider()),
        patch("vex.ai.cache.AICache", return_value=mock_cache),
    ):
        _run_correlation_explain(clusters, config, None, OutputFormat.console)

    assert CountingProvider.call_count == 0
    for cl in clusters:
        assert cl.explanation == cached_narrative


# ---------------------------------------------------------------------------
# 9. build_clusters: explanation is None after clustering (no auto-generate)
# ---------------------------------------------------------------------------


def test_build_clusters_explanation_starts_as_none() -> None:
    r1 = _triage("a.com", families=["emotet"])
    r2 = _triage("b.com", families=["emotet"])
    clusters = build_clusters([r1, r2])
    assert len(clusters) == 1
    assert clusters[0].explanation is None


# ---------------------------------------------------------------------------
# 10. correlate-only: no narrative generated (unchanged deterministic path)
# ---------------------------------------------------------------------------


def test_correlate_alone_leaves_explanation_none() -> None:
    """build_clusters never auto-populates explanations."""
    r1 = _triage("x.com", families=["cobalt"])
    r2 = _triage("y.com", families=["cobalt"])
    clusters = build_clusters([r1, r2])
    for cl in clusters:
        assert cl.explanation is None
