"""OpenAI provider for vex AI explanations."""

from __future__ import annotations

from typing import Optional


class OpenAIProvider:
    """LLM provider using the OpenAI API."""

    DEFAULT_MODEL = "gpt-4o"

    def __init__(self, api_key: str, model: Optional[str] = None):
        try:
            import openai
        except ImportError:
            raise ImportError(
                "openai package not installed. "
                "Run: pip install vex-ioc[ai]"
            )
        self._client = openai.OpenAI(api_key=api_key)
        self._model = model or self.DEFAULT_MODEL

    @property
    def name(self) -> str:
        return "openai"

    def explain(
        self,
        prompt: str,
        *,
        max_tokens: int = 500,
        temperature: float = 0.3,
    ) -> str:
        """Send prompt to OpenAI and return explanation."""
        resp = self._client.chat.completions.create(
            model=self._model,
            max_tokens=max_tokens,
            temperature=temperature,
            messages=[{"role": "user", "content": prompt}],
        )
        return resp.choices[0].message.content

    def is_available(self) -> bool:
        """Check if openai SDK is installed."""
        try:
            import openai  # noqa: F401
            return True
        except ImportError:
            return False
