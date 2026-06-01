"""Protocol (interface) for LLM providers.

Any AI provider (Anthropic, OpenAI, Ollama, etc.) must implement this
protocol so vex can use it transparently via --explain.
"""

from __future__ import annotations

from typing import Optional, Protocol, runtime_checkable


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
        system: Optional[str] = None,
        max_tokens: int = 500,
        temperature: float = 0.3,
    ) -> str:
        """Send prompt, return explanation text.

        Args:
            prompt: The user-turn content (data block).
            system: Optional system prompt. When ``None``, providers that
                support a system role omit it, preserving backward compatibility.
            max_tokens: Maximum tokens to generate.
            temperature: Sampling temperature.
        """
        ...

    def is_available(self) -> bool:
        """Check if the provider's SDK is installed and configured."""
        ...
