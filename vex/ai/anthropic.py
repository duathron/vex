"""Anthropic Claude provider for vex AI explanations."""

from __future__ import annotations

from typing import Optional


class ClaudeProvider:
    """LLM provider using the Anthropic Claude API."""

    DEFAULT_MODEL = "claude-sonnet-4-6"

    def __init__(self, api_key: str, model: Optional[str] = None):
        try:
            import anthropic
        except ImportError:
            raise ImportError(
                "anthropic package not installed. "
                "Run: pip install vex-ioc[ai]"
            )
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

        Args:
            prompt: User-turn content (data block).
            system: Optional system prompt. When set, forwarded to the
                ``system`` parameter of the Messages API. Omitted when None.
            max_tokens: Maximum tokens to generate.
            temperature: Sampling temperature.

        Raises:
            RuntimeError: Wraps any :class:`anthropic.APIError` with a
                user-friendly message.
        """
        kwargs: dict = {
            "model": self._model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system is not None:
            kwargs["system"] = system

        try:
            message = self._client.messages.create(**kwargs)
        except self._anthropic.APIError as exc:
            raise RuntimeError(
                f"Anthropic API error while generating explanation: {exc}"
            ) from exc

        # Defensive extraction: iterate content blocks, take first with .text
        response_text = ""
        for block in message.content:
            if hasattr(block, "text"):
                response_text = block.text
                break

        return response_text

    def is_available(self) -> bool:
        """Check if anthropic SDK is installed."""
        try:
            import anthropic  # noqa: F401
            return True
        except ImportError:
            return False
