"""OpenAI provider for vex AI explanations."""

from __future__ import annotations

from typing import Optional

from shipwright_kit.llm import openai_complete


class OpenAIProvider:
    """LLM provider using the OpenAI API."""

    DEFAULT_MODEL = "gpt-4o"

    def __init__(self, api_key: str, model: Optional[str] = None):
        try:
            import openai
        except ImportError:
            raise ImportError("openai package not installed. Run: pip install vex-ioc[ai]")
        self._client = openai.OpenAI(api_key=api_key)
        self._model = model or self.DEFAULT_MODEL

    @property
    def name(self) -> str:
        return "openai"

    def explain(
        self,
        prompt: str,
        *,
        system: Optional[str] = None,
        max_tokens: int = 500,
        temperature: float = 0.3,
    ) -> str:
        """Send prompt to OpenAI and return explanation.

        Delegates request construction + extraction to
        ``shipwright_kit.llm.openai_complete`` (W3 retrofit, 2026-07-03).
        The shared transport always sends BOTH a system-role and a user-role
        message (no omission support) — ``system`` is coerced to ``""`` when
        ``None``. No try/except here (preserved from pre-retrofit behavior:
        vex never wrapped OpenAI exceptions) — any exception, including an
        ``IndexError`` from an empty ``choices`` list, propagates unchanged.
        """
        return openai_complete(
            client=self._client,
            model=self._model,
            max_tokens=max_tokens,
            system=system if system is not None else "",
            user=prompt,
            temperature=temperature,
        )

    def is_available(self) -> bool:
        """Check if openai SDK is installed."""
        try:
            import openai  # noqa: F401

            return True
        except ImportError:
            return False
