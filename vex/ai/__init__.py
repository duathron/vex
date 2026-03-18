"""AI-powered IOC explanations for vex.

Factory function to get the configured LLM provider.
Providers: anthropic (Claude), openai (GPT), ollama (local).
"""

from __future__ import annotations

import logging
from typing import Optional

from ..config import Config
from .protocol import LLMProviderProtocol

logger = logging.getLogger("vex.ai")


def get_provider(config: Config) -> Optional[LLMProviderProtocol]:
    """Return the configured LLM provider, or None if ai.provider is 'none'.

    Raises ValueError for invalid configuration (missing key, local_only
    violation, unknown provider).
    """
    ai = config.ai
    provider_name = ai.provider.lower().strip()

    if provider_name == "none":
        return None

    # Enforce local_only
    if ai.local_only and provider_name in ("anthropic", "openai"):
        raise ValueError(
            f"ai.local_only=true blocks cloud provider '{provider_name}'. "
            "Use 'ollama' or set ai.local_only=false in config."
        )

    if provider_name == "anthropic":
        key = config.ai_api_key
        if not key:
            raise ValueError(
                "Anthropic API key required for --explain.\n"
                "  Set VEX_AI_API_KEY env var, or\n"
                "  Set ai.api_key in ~/.vex/config.yaml"
            )
        from .anthropic import ClaudeProvider
        return ClaudeProvider(api_key=key, model=ai.model)

    if provider_name == "openai":
        key = config.ai_api_key
        if not key:
            raise ValueError(
                "OpenAI API key required for --explain.\n"
                "  Set VEX_AI_API_KEY env var, or\n"
                "  Set ai.api_key in ~/.vex/config.yaml"
            )
        from .openai import OpenAIProvider
        return OpenAIProvider(api_key=key, model=ai.model)

    if provider_name == "ollama":
        from .ollama import OllamaProvider
        return OllamaProvider(model=ai.model, base_url=ai.base_url)

    raise ValueError(
        f"Unknown AI provider: '{provider_name}'. "
        "Use: anthropic, openai, ollama, or none."
    )
