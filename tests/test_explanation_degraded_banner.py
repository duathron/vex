"""Tests for the F2 cut-1 loud degraded-explanation banner (rich/console).

2026-07-03 MeetUp — 2026-07-03-f2-llm-failure-posture.md, point 3: "Loud in
the DEFAULT renderers... must SCREAM a banner above a degraded [output]."
Mirrors barb's output/formatter.py Panel treatment (border_style="red").
"""

from __future__ import annotations

from vex.output.formatter import print_explanation_degraded_console, print_explanation_degraded_rich


def test_print_explanation_degraded_rich_mentions_provider(capsys) -> None:
    print_explanation_degraded_rich("anthropic")
    captured = capsys.readouterr()
    assert "EXPLANATION UNAVAILABLE" in captured.out
    assert "anthropic" in captured.out


def test_print_explanation_degraded_console_mentions_provider(capsys) -> None:
    print_explanation_degraded_console("ollama")
    captured = capsys.readouterr()
    assert "EXPLANATION UNAVAILABLE" in captured.out
    assert "ollama" in captured.out


def test_print_explanation_degraded_rich_includes_cluster_label_when_given(capsys) -> None:
    print_explanation_degraded_rich("openai", label="C1: ASN 1234")
    captured = capsys.readouterr()
    assert "C1: ASN 1234" in captured.out
