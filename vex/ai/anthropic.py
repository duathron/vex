"""Anthropic Claude provider for vex AI explanations."""

from __future__ import annotations

from typing import Optional


class ClaudeProvider:
    """LLM provider using the Anthropic Claude API."""

    DEFAULT_MODEL = "claude-sonnet-4-20250514"

    def __init__(self, api_key: str, model: Optional[str] = None):
        try:
            import anthropic
        except ImportError:
            raise ImportError(
                "anthropic package not installed. "
                "Run: pip install vex-ioc[ai]"
            )
        self._client = anthropic.Anthropic(api_key=api_key)
        self._model = model or self.DEFAULT_MODEL

    @property
    def name(self) -> str:
        return "anthropic"

    def explain(
        self,
        prompt: str,
        *,
        max_tokens: int = 500,
        temperature: float = 0.3,
    ) -> str:
        """Send prompt to Claude and return explanation."""
        resp = self._client.messages.create(
            model=self._model,
            max_tokens=max_tokens,
            temperature=temperature,
            messages=[{"role": "user", "content": prompt}],
        )
        return resp.content[0].text

    def is_available(self) -> bool:
        """Check if anthropic SDK is installed."""
        try:
            import anthropic  # noqa: F401
            return True
        except ImportError:
            return False
