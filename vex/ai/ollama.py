"""Ollama local LLM provider for vex AI explanations.

The /api/generate call is migrated onto the shared shipwright_kit.llm
transport (W3 retrofit, 2026-07-03), which uses stdlib urllib instead of
httpx — a deliberate transport change (same wire request: POST
/api/generate with the same JSON body) shared with sift/barb. vex keeps
httpx for its health-check (/api/tags below) and for its other 9
non-AI files (VirusTotal client, enrichers) — only the generate call moves.
"""

from __future__ import annotations

from typing import Optional

import httpx
from shipwright_kit.llm import ollama_generate


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
        system: Optional[str] = None,
        max_tokens: int = 500,
        temperature: float = 0.3,
    ) -> str:
        """Send prompt to local Ollama and return explanation.

        Delegates the /api/generate call to
        ``shipwright_kit.llm.ollama_generate`` (urllib transport,
        ``system_mode="field"`` — system as its own top-level payload key,
        matching vex's pre-retrofit shape). ``options`` carries vex's
        existing num_predict/temperature mapping, preserved unconditionally
        (unchanged from pre-retrofit). ``system`` is coerced to ``""`` when
        ``None`` (the shared transport has no omission support — see
        tests/test_ai_providers.py for the characterization). No try/except
        here (preserved from pre-retrofit behavior: vex never wrapped
        Ollama transport/parse errors) — any exception (urllib.error.URLError,
        urllib.error.HTTPError, json.JSONDecodeError, KeyError) propagates
        unchanged.
        """
        return ollama_generate(
            base_url=self._base_url,
            model=self._model,
            system=system if system is not None else "",
            user=prompt,
            timeout=120.0,
            system_mode="field",
            options={"num_predict": max_tokens, "temperature": temperature},
        )

    def is_available(self) -> bool:
        """Check if Ollama is running and reachable.

        Unchanged by the W3 retrofit — the health-check stays on httpx
        (only the /api/generate call migrated to the shared urllib transport).
        """
        try:
            r = httpx.get(f"{self._base_url}/api/tags", timeout=3.0)
            return r.status_code == 200
        except Exception:
            return False
