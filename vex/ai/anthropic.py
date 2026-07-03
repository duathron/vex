"""Anthropic Claude provider for vex AI explanations."""

from __future__ import annotations

from typing import Optional

from shipwright_kit.llm import anthropic_complete


class ClaudeProvider:
    """LLM provider using the Anthropic Claude API."""

    DEFAULT_MODEL = "claude-sonnet-4-6"

    def __init__(self, api_key: str, model: Optional[str] = None):
        try:
            import anthropic
        except ImportError:
            raise ImportError("anthropic package not installed. Run: pip install vex-ioc[ai]")
        self._anthropic = anthropic
        self._client = anthropic.Anthropic(api_key=api_key)
        self._model = model or self.DEFAULT_MODEL

    @property
    def name(self) -> str:
        return "anthropic"

    def explain(
        self,
        prompt: str,
        *,
        system: Optional[str] = None,
        max_tokens: int = 500,
        temperature: float = 0.3,
    ) -> str:
        """Send prompt to Claude and return explanation.

        Delegates request construction + extraction to
        ``shipwright_kit.llm.anthropic_complete`` (W3 retrofit, 2026-07-03).
        ``extract="first_text_block"`` matches vex's pre-retrofit defensive
        extraction (scan for the first content block exposing ``.text``,
        return ``""`` if none is found). ``system`` is coerced to ``""``
        when ``None`` — the shared transport always sends a ``system`` key
        (no omission support); vex's own call sites never pass ``system=None``
        in practice (see tests/test_ai_providers.py for the characterization).

        Raises:
            RuntimeError: Wraps any :class:`anthropic.APIError` with a
                user-friendly message. Any other exception type propagates
                unchanged (preserved from pre-retrofit behavior).
        """
        try:
            return anthropic_complete(
                client=self._client,
                model=self._model,
                max_tokens=max_tokens,
                system=system if system is not None else "",
                user=prompt,
                temperature=temperature,
                extract="first_text_block",
            )
        except self._anthropic.APIError as exc:
            raise RuntimeError(f"Anthropic API error while generating explanation: {exc}") from exc

    def is_available(self) -> bool:
        """Check if anthropic SDK is installed."""
        try:
            import anthropic  # noqa: F401

            return True
        except ImportError:
            return False
