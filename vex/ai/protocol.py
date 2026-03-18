"""Protocol (interface) for LLM providers.

Any AI provider (Anthropic, OpenAI, Ollama, etc.) must implement this
protocol so vex can use it transparently via --explain.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class LLMProviderProtocol(Protocol):
    """Interface that every LLM provider must satisfy."""

    @property
    def name(self) -> str:
        """Provider name (e.g. 'anthropic', 'openai', 'ollama')."""
        ...

    def explain(
        self,
        prompt: str,
        *,
        max_tokens: int = 500,
        temperature: float = 0.3,
    ) -> str:
        """Send prompt, return explanation text."""
        ...

    def is_available(self) -> bool:
        """Check if the provider's SDK is installed and configured."""
        ...
