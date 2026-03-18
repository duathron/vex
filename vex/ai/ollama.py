"""Ollama local LLM provider for vex AI explanations.

Uses httpx (already a core dependency) to call the Ollama REST API.
No additional packages required — works out of the box for air-gapped
and privacy-sensitive environments.
"""

from __future__ import annotations

from typing import Optional

import httpx


class OllamaProvider:
    """LLM provider using a local Ollama instance."""

    DEFAULT_MODEL = "llama3"
    DEFAULT_BASE_URL = "http://localhost:11434"

    def __init__(
        self,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
    ):
        self._model = model or self.DEFAULT_MODEL
        self._base_url = (base_url or self.DEFAULT_BASE_URL).rstrip("/")

    @property
    def name(self) -> str:
        return "ollama"

    def explain(
        self,
        prompt: str,
        *,
        max_tokens: int = 500,
        temperature: float = 0.3,
    ) -> str:
        """Send prompt to local Ollama and return explanation."""
        resp = httpx.post(
            f"{self._base_url}/api/generate",
            json={
                "model": self._model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "num_predict": max_tokens,
                    "temperature": temperature,
                },
            },
            timeout=120.0,
        )
        resp.raise_for_status()
        return resp.json()["response"]

    def is_available(self) -> bool:
        """Check if Ollama is running and reachable."""
        try:
            r = httpx.get(f"{self._base_url}/api/tags", timeout=3.0)
            return r.status_code == 200
        except Exception:
            return False
