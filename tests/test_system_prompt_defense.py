"""Both AI system prompts carry an instructional-defense block against
prompt injection (defense-in-depth with the field-level redaction)."""

from __future__ import annotations

import pytest

from vex.ai.prompt import get_system_prompt


@pytest.mark.parametrize("mode", ["explain", "correlation"])
def test_system_prompt_has_untrusted_input_defense(mode: str) -> None:
    p = get_system_prompt(mode).lower()
    assert "untrusted" in p
    assert "data" in p
    # instructs the model to never follow embedded instructions
    assert "never follow" in p
    assert "instruction" in p


def test_explain_and_correlation_defense_both_present() -> None:
    assert "untrusted" in get_system_prompt("explain").lower()
    assert "untrusted" in get_system_prompt("correlation").lower()
