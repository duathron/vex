"""Characterization tests pinning vex's CURRENT AI provider behavior.

Written ahead of a planned retrofit of vex's anthropic/openai/ollama
providers onto the shared ``shipwright_kit.llm`` library (which already
serves sibling projects sift/barb). These tests exist to PIN existing
behavior (including quirks) — they intentionally do not judge whether the
behavior is "correct". Do not "fix" anything here if a test looks odd;
that is the point.

This file EXTENDS tests/test_ai_providers.py rather than duplicating it.
Already covered there (not repeated here): system prompt forwarding,
Anthropic defensive extraction (skip non-text block / all-non-text ->
""), Anthropic APIError -> RuntimeError wrapping, OpenAI system message
prepend/omit, OpenAI empty-choices -> "", Ollama system field
forwarded/omitted, Ollama missing-'response'-key -> "".

New coverage added here:
  - temperature: default 0.3 unconditionally present in the request/
    payload for all three providers, and custom overrides forwarded.
  - max_tokens forwarding (all three) and model-name forwarding
    (openai, ollama; anthropic model already pinned via DEFAULT_MODEL
    in test_ai_providers.py, so here we pin that it reaches the actual
    request kwargs too).
  - Ollama full request payload shape (model/prompt/stream/options{...})
    and the exact httpx transport call (module-level httpx.post, json=,
    timeout=120.0, URL built from base_url, no persistent client).
  - Client construction: anthropic.Anthropic(...) / openai.OpenAI(...)
    built once in __init__ and reused (same instance) across repeated
    .explain() calls.
  - Response extraction edge cases not yet pinned: Anthropic with a
    genuinely empty content list, Anthropic first-block-wins when
    multiple blocks all have .text, OpenAI message.content is None
    (falls through the ``or ""`` — not the except branch).
  - Error posture divergences: OpenAI has NO try/except around the SDK
    call at all (any exception propagates unwrapped, unlike Anthropic's
    APIError -> RuntimeError wrap). Anthropic only wraps its own
    ``anthropic.APIError`` subclass — any other exception type from
    messages.create propagates unwrapped. Ollama does not catch
    httpx transport errors (httpx.post raising) nor HTTP-status errors
    (raise_for_status() raising) — both propagate unwrapped. Ollama's
    JSON-parse guard is a bare ``except Exception`` that also swallows
    a raising .json() call, not just a missing key.
"""

from __future__ import annotations

import importlib
import sys
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Shared helpers (mirrors tests/test_ai_providers.py conventions)
# ---------------------------------------------------------------------------


def _make_fake_anthropic_module() -> MagicMock:
    """Build a minimal fake anthropic module with Anthropic client and APIError.

    Real `anthropic` package is NOT installed in this environment (it lives
    behind the optional `ai` extra). vex's own tests work around this by
    injecting a fake module into sys.modules before importing vex.ai.anthropic,
    so ClaudeProvider.__init__'s `import anthropic` succeeds against the fake.
    We follow the same convention here.
    """
    fake_anthropic = MagicMock()

    class FakeAPIError(Exception):
        pass

    fake_anthropic.APIError = FakeAPIError
    return fake_anthropic


def _make_claude_provider(fake_anthropic: MagicMock, model: str | None = None):
    with patch.dict("sys.modules", {"anthropic": fake_anthropic}):
        sys.modules.pop("vex.ai.anthropic", None)
        provider_mod = importlib.import_module("vex.ai.anthropic")
        return provider_mod.ClaudeProvider(api_key="test-key", model=model)


def _make_openai_provider(fake_openai: MagicMock, model: str | None = None):
    with patch.dict("sys.modules", {"openai": fake_openai}):
        sys.modules.pop("vex.ai.openai", None)
        provider_mod = importlib.import_module("vex.ai.openai")
        return provider_mod.OpenAIProvider(api_key="test-key", model=model)


def _fake_anthropic_text_message(text: str) -> MagicMock:
    text_block = MagicMock()
    text_block.text = text
    fake_message = MagicMock()
    fake_message.content = [text_block]
    return fake_message


def _fake_openai_response(content) -> MagicMock:
    choice = MagicMock()
    choice.message.content = content
    return MagicMock(choices=[choice])


# ===========================================================================
# 1. Temperature — unconditional presence + default value + override
# ===========================================================================


def test_anthropic_temperature_default_present_in_kwargs() -> None:
    """Anthropic always sends temperature=0.3 by default (protocol.py:27 default,
    anthropic.py:32/50 mirrors it and unconditionally puts it in kwargs)."""
    fake_anthropic = _make_fake_anthropic_module()
    fake_anthropic.Anthropic.return_value.messages.create.return_value = _fake_anthropic_text_message("x")

    provider = _make_claude_provider(fake_anthropic)
    provider.explain("data block")

    call_kwargs = fake_anthropic.Anthropic.return_value.messages.create.call_args[1]
    assert call_kwargs["temperature"] == 0.3


def test_anthropic_temperature_override_forwarded() -> None:
    fake_anthropic = _make_fake_anthropic_module()
    fake_anthropic.Anthropic.return_value.messages.create.return_value = _fake_anthropic_text_message("x")

    provider = _make_claude_provider(fake_anthropic)
    provider.explain("data block", temperature=0.9)

    call_kwargs = fake_anthropic.Anthropic.return_value.messages.create.call_args[1]
    assert call_kwargs["temperature"] == 0.9


def test_openai_temperature_default_present_in_kwargs() -> None:
    """OpenAI always sends temperature=0.3 by default (openai.py:31/46)."""
    fake_openai = MagicMock()
    fake_openai.OpenAI.return_value.chat.completions.create.return_value = _fake_openai_response("resp")

    provider = _make_openai_provider(fake_openai)
    provider.explain("user prompt")

    call_kwargs = fake_openai.OpenAI.return_value.chat.completions.create.call_args[1]
    assert call_kwargs["temperature"] == 0.3


def test_openai_temperature_override_forwarded() -> None:
    fake_openai = MagicMock()
    fake_openai.OpenAI.return_value.chat.completions.create.return_value = _fake_openai_response("resp")

    provider = _make_openai_provider(fake_openai)
    provider.explain("user prompt", temperature=0.0)

    call_kwargs = fake_openai.OpenAI.return_value.chat.completions.create.call_args[1]
    assert call_kwargs["temperature"] == 0.0


def test_ollama_temperature_default_present_in_options() -> None:
    """Ollama always sends options.temperature=0.3 by default (unchanged by the retrofit)."""
    import json as _json

    from _ollama_transport import make_fake_urlopen

    captured, fake_urlopen = make_fake_urlopen({"response": "ok"})

    with patch("shipwright_kit.llm.urllib.request.urlopen", fake_urlopen):
        from vex.ai.ollama import OllamaProvider

        provider = OllamaProvider()
        provider.explain("user prompt")

    payload = _json.loads(captured["request"].data.decode())
    assert payload["options"]["temperature"] == 0.3


def test_ollama_temperature_override_forwarded_in_options() -> None:
    import json as _json

    from _ollama_transport import make_fake_urlopen

    captured, fake_urlopen = make_fake_urlopen({"response": "ok"})

    with patch("shipwright_kit.llm.urllib.request.urlopen", fake_urlopen):
        from vex.ai.ollama import OllamaProvider

        provider = OllamaProvider()
        provider.explain("user prompt", temperature=0.7)

    payload = _json.loads(captured["request"].data.decode())
    assert payload["options"]["temperature"] == 0.7


# ===========================================================================
# 2. max_tokens + model-name forwarding
# ===========================================================================


def test_anthropic_max_tokens_and_model_forwarded() -> None:
    fake_anthropic = _make_fake_anthropic_module()
    fake_anthropic.Anthropic.return_value.messages.create.return_value = _fake_anthropic_text_message("x")

    provider = _make_claude_provider(fake_anthropic, model="claude-custom")
    provider.explain("data block", max_tokens=42)

    call_kwargs = fake_anthropic.Anthropic.return_value.messages.create.call_args[1]
    assert call_kwargs["max_tokens"] == 42
    assert call_kwargs["model"] == "claude-custom"


def test_openai_max_tokens_and_model_forwarded() -> None:
    fake_openai = MagicMock()
    fake_openai.OpenAI.return_value.chat.completions.create.return_value = _fake_openai_response("resp")

    provider = _make_openai_provider(fake_openai, model="gpt-custom")
    provider.explain("user prompt", max_tokens=77)

    call_kwargs = fake_openai.OpenAI.return_value.chat.completions.create.call_args[1]
    assert call_kwargs["max_tokens"] == 77
    assert call_kwargs["model"] == "gpt-custom"


def test_ollama_max_tokens_maps_to_num_predict_and_model_forwarded() -> None:
    """Ollama has no top-level max_tokens key — max_tokens is mapped to
    options.num_predict, and model is a top-level key (unchanged by the retrofit)."""
    import json as _json

    from _ollama_transport import make_fake_urlopen

    captured, fake_urlopen = make_fake_urlopen({"response": "ok"})

    with patch("shipwright_kit.llm.urllib.request.urlopen", fake_urlopen):
        from vex.ai.ollama import OllamaProvider

        provider = OllamaProvider(model="llama3-custom")
        provider.explain("user prompt", max_tokens=99)

    payload = _json.loads(captured["request"].data.decode())
    assert payload["options"]["num_predict"] == 99
    assert "max_tokens" not in payload
    assert payload["model"] == "llama3-custom"


def test_ollama_default_model_is_llama3() -> None:
    from vex.ai.ollama import OllamaProvider

    assert OllamaProvider.DEFAULT_MODEL == "llama3"


def test_openai_default_model_is_gpt_4o() -> None:
    from vex.ai.openai import OpenAIProvider

    assert OpenAIProvider.DEFAULT_MODEL == "gpt-4o"


# ===========================================================================
# 3. Ollama — full request payload shape + exact urllib transport call
#
# FLIPPED for the W3 retrofit (2026-07-03) onto shipwright_kit.llm. Ollama's
# /api/generate call migrated from module-level httpx.post to
# shipwright_kit.llm.ollama_generate's urllib.request transport (a
# deliberate, documented transport change — same wire request, different
# client library). The "no system when omitted" assertion also flips (see
# the forced-divergence note in tests/test_ai_providers.py); "raise_for_status
# is called" has no urllib equivalent (urlopen raises HTTPError automatically
# on a non-2xx status — no manual call to assert) and is retired in favor of
# test_ollama_http_error_status_propagates below.
# ===========================================================================


def test_ollama_full_payload_shape_no_system() -> None:
    """Pin the exact top-level payload keys when system is omitted.

    FLIPPED: "system" is now ALWAYS present (as "") — see forced-divergence
    note in tests/test_ai_providers.py. All other keys/values unchanged."""
    import json as _json

    from _ollama_transport import make_fake_urlopen

    captured, fake_urlopen = make_fake_urlopen({"response": "ok"})

    with patch("shipwright_kit.llm.urllib.request.urlopen", fake_urlopen):
        from vex.ai.ollama import OllamaProvider

        provider = OllamaProvider(model="llama3")
        provider.explain("hello prompt", max_tokens=500, temperature=0.3)

    payload = _json.loads(captured["request"].data.decode())
    assert set(payload.keys()) == {"model", "system", "prompt", "stream", "options"}
    assert payload["model"] == "llama3"
    assert payload["system"] == ""
    assert payload["prompt"] == "hello prompt"
    assert payload["stream"] is False
    assert set(payload["options"].keys()) == {"num_predict", "temperature"}
    assert payload["options"]["num_predict"] == 500
    assert payload["options"]["temperature"] == 0.3
    assert "message" not in payload
    assert "messages" not in payload


def test_ollama_full_payload_shape_with_system() -> None:
    """When system is provided it is a top-level key, not nested in options (unchanged)."""
    import json as _json

    from _ollama_transport import make_fake_urlopen

    captured, fake_urlopen = make_fake_urlopen({"response": "ok"})

    with patch("shipwright_kit.llm.urllib.request.urlopen", fake_urlopen):
        from vex.ai.ollama import OllamaProvider

        provider = OllamaProvider()
        provider.explain("hello prompt", system="sys prompt")

    payload = _json.loads(captured["request"].data.decode())
    assert set(payload.keys()) == {"model", "prompt", "stream", "options", "system"}
    assert payload["system"] == "sys prompt"
    assert "system" not in payload["options"]


def test_ollama_transport_is_urllib_urlopen_with_url_and_timeout() -> None:
    """Pin the exact transport call: shipwright_kit.llm's urllib.request.urlopen
    (no httpx.post any more), URL built from base_url + '/api/generate', and
    the same fixed 120.0s timeout vex has always used."""
    from _ollama_transport import make_fake_urlopen

    captured, fake_urlopen = make_fake_urlopen({"response": "ok"})

    with patch("shipwright_kit.llm.urllib.request.urlopen", side_effect=fake_urlopen) as mock_urlopen:
        from vex.ai.ollama import OllamaProvider

        provider = OllamaProvider(base_url="http://myhost:12345/")
        provider.explain("hello")

    assert mock_urlopen.call_count == 1
    assert captured["request"].full_url == "http://myhost:12345/api/generate"
    assert captured["timeout"] == 120.0


def test_ollama_default_base_url() -> None:
    from vex.ai.ollama import OllamaProvider

    assert OllamaProvider.DEFAULT_BASE_URL == "http://localhost:11434"

    from _ollama_transport import make_fake_urlopen

    captured, fake_urlopen = make_fake_urlopen({"response": "ok"})

    with patch("shipwright_kit.llm.urllib.request.urlopen", fake_urlopen):
        provider = OllamaProvider()
        provider.explain("hi")

    assert captured["request"].full_url == "http://localhost:11434/api/generate"


def test_ollama_http_error_status_propagates() -> None:
    """A non-2xx HTTP status raises urllib.error.HTTPError automatically inside
    urlopen (urllib's built-in equivalent of httpx's raise_for_status()) —
    replaces the retired test_ollama_raise_for_status_is_called (no manual
    raise_for_status call exists in the urllib transport to assert on)."""
    import urllib.error

    from _ollama_transport import make_fake_urlopen

    http_error = urllib.error.HTTPError("http://localhost:11434/api/generate", 500, "Internal Server Error", {}, None)
    _captured, fake_urlopen = make_fake_urlopen({}, raise_error=http_error)

    with patch("shipwright_kit.llm.urllib.request.urlopen", fake_urlopen):
        from vex.ai.ollama import OllamaProvider

        provider = OllamaProvider()
        with pytest.raises(urllib.error.HTTPError):
            provider.explain("hi")


# ===========================================================================
# 4. Client construction — built once in __init__, same instance reused
# ===========================================================================


def test_anthropic_client_built_once_and_reused_across_calls() -> None:
    """anthropic.Anthropic(...) is constructed exactly once (in __init__);
    repeated .explain() calls reuse the same self._client instance. This is
    what makes a client-injection retrofit pattern (client=self._client)
    feasible."""
    fake_anthropic = _make_fake_anthropic_module()
    fake_anthropic.Anthropic.return_value.messages.create.return_value = _fake_anthropic_text_message("x")

    provider = _make_claude_provider(fake_anthropic)
    provider.explain("first")
    provider.explain("second")

    assert fake_anthropic.Anthropic.call_count == 1
    fake_anthropic.Anthropic.assert_called_once_with(api_key="test-key")
    assert fake_anthropic.Anthropic.return_value.messages.create.call_count == 2
    # The provider stores the constructed client instance directly.
    assert provider._client is fake_anthropic.Anthropic.return_value


def test_openai_client_built_once_and_reused_across_calls() -> None:
    fake_openai = MagicMock()
    fake_openai.OpenAI.return_value.chat.completions.create.return_value = _fake_openai_response("resp")

    provider = _make_openai_provider(fake_openai)
    provider.explain("first")
    provider.explain("second")

    assert fake_openai.OpenAI.call_count == 1
    fake_openai.OpenAI.assert_called_once_with(api_key="test-key")
    assert fake_openai.OpenAI.return_value.chat.completions.create.call_count == 2
    assert provider._client is fake_openai.OpenAI.return_value


def test_ollama_provider_has_no_persistent_client_attribute() -> None:
    """OllamaProvider holds no SDK/HTTP client instance at all — each call to
    .explain() goes through the module-level httpx.post function directly.
    There is no self._client to inject into a shared function; a retrofit
    would need to pass base_url/timeout instead of a client object."""
    from vex.ai.ollama import OllamaProvider

    provider = OllamaProvider()
    assert not hasattr(provider, "_client")


# ===========================================================================
# 5. Response extraction — additional edge cases
# ===========================================================================


def test_anthropic_extraction_empty_content_list_returns_empty_string() -> None:
    """message.content == [] (not just all-non-text blocks) -> ''."""
    fake_anthropic = _make_fake_anthropic_module()
    fake_message = MagicMock()
    fake_message.content = []
    fake_anthropic.Anthropic.return_value.messages.create.return_value = fake_message

    provider = _make_claude_provider(fake_anthropic)
    result = provider.explain("data block")
    assert result == ""


def test_anthropic_extraction_first_of_multiple_text_blocks_wins() -> None:
    """When multiple blocks all have .text, the loop breaks on the FIRST
    one found — later blocks' text is discarded, not concatenated."""
    fake_anthropic = _make_fake_anthropic_module()
    block1 = MagicMock()
    block1.text = "first block text"
    block2 = MagicMock()
    block2.text = "second block text"
    fake_message = MagicMock()
    fake_message.content = [block1, block2]
    fake_anthropic.Anthropic.return_value.messages.create.return_value = fake_message

    provider = _make_claude_provider(fake_anthropic)
    result = provider.explain("data block")
    assert result == "first block text"


def test_openai_extraction_none_content_falls_back_to_empty_string() -> None:
    """message.content is a valid (non-missing) attribute but is None ->
    the `or ""` on openai.py:52 converts it to "", NOT the except branch
    (choices[0] and .message both resolve fine here)."""
    fake_openai = MagicMock()
    fake_openai.OpenAI.return_value.chat.completions.create.return_value = _fake_openai_response(None)

    provider = _make_openai_provider(fake_openai)
    result = provider.explain("data block")
    assert result == ""


def test_ollama_extraction_happy_path_uses_response_key() -> None:
    from _ollama_transport import make_fake_urlopen

    _captured, fake_urlopen = make_fake_urlopen({"response": "the actual answer", "done": True, "model": "llama3"})

    with patch("shipwright_kit.llm.urllib.request.urlopen", fake_urlopen):
        from vex.ai.ollama import OllamaProvider

        provider = OllamaProvider()
        result = provider.explain("hi")

    assert result == "the actual answer"


# FLIPPED for the W3 retrofit (2026-07-03) onto shipwright_kit.llm.
#   OLD posture (pinned here before the flip): a raising .json() call (e.g.
#     malformed body) -> vex's old bare `except Exception: return ""`
#     swallowed it, returning "".
#   NEW posture (asserted below): shipwright_kit.llm.ollama_generate does
#     `json.loads(body)` with no try/except -> a malformed body now raises
#     json.JSONDecodeError, uncaught, propagating to the caller.
#   WHY: same exception-transparency reasoning as the KeyError flip in
#     tests/test_ai_providers.py — net-positive for F2 (no more silent ""
#     masquerading as a successful call).
def test_ollama_json_decode_failure_propagates() -> None:
    """A malformed response body raises json.JSONDecodeError, not swallowed to ""."""
    import json as _json

    from _ollama_transport import _FakeHTTPResponse

    def fake_urlopen(req, timeout=None, **kwargs):
        return _FakeHTTPResponse(b"not valid json")

    with patch("shipwright_kit.llm.urllib.request.urlopen", fake_urlopen):
        from vex.ai.ollama import OllamaProvider

        provider = OllamaProvider()
        with pytest.raises(_json.JSONDecodeError):
            provider.explain("hi")


# ===========================================================================
# 6. Error posture — per-provider divergences
# ===========================================================================


def test_anthropic_non_api_error_propagates_unwrapped() -> None:
    """Only anthropic.APIError is caught+wrapped (anthropic.py:58). Any other
    exception type raised by messages.create() propagates unchanged — it is
    NOT wrapped into RuntimeError."""
    fake_anthropic = _make_fake_anthropic_module()
    fake_anthropic.Anthropic.return_value.messages.create.side_effect = ValueError("not an APIError")

    provider = _make_claude_provider(fake_anthropic)

    with pytest.raises(ValueError, match="not an APIError"):
        provider.explain("data block")


def test_openai_error_propagates_unwrapped_no_try_except() -> None:
    """openai.py has NO try/except around chat.completions.create() at all —
    diverges from anthropic.py's APIError->RuntimeError wrap. Any exception
    (including a fake openai-SDK-shaped error) propagates as-is."""
    fake_openai = MagicMock()
    fake_openai.OpenAI.return_value.chat.completions.create.side_effect = RuntimeError("rate limited")

    provider = _make_openai_provider(fake_openai)

    with pytest.raises(RuntimeError, match="rate limited"):
        provider.explain("data block")


# FLIPPED for the W3 retrofit (2026-07-03): the transport is now urllib, not
# httpx, so the exception TYPE changes from httpx.HTTPStatusError to
# urllib.error.HTTPError. The POSTURE is unchanged (still propagates
# unwrapped — vex deliberately does not add RuntimeError wrapping here,
# unlike barb's OllamaExplainer; see the plan's forced-divergence notes).
def test_ollama_http_status_error_propagates_unwrapped() -> None:
    """A non-2xx HTTP status (urllib.error.HTTPError) is not caught by
    ollama.py — it propagates directly to the caller."""
    import urllib.error

    from _ollama_transport import make_fake_urlopen

    http_error = urllib.error.HTTPError("http://localhost:11434/api/generate", 500, "Internal Server Error", {}, None)
    _captured, fake_urlopen = make_fake_urlopen({}, raise_error=http_error)

    with patch("shipwright_kit.llm.urllib.request.urlopen", fake_urlopen):
        from vex.ai.ollama import OllamaProvider

        provider = OllamaProvider()
        with pytest.raises(urllib.error.HTTPError):
            provider.explain("hi")


def test_ollama_transport_error_propagates_unwrapped() -> None:
    """urlopen() itself raising a transport-level error (e.g. connection
    refused because no local Ollama is running) is not caught either —
    propagates directly as urllib.error.URLError."""
    import urllib.error

    from _ollama_transport import make_fake_urlopen

    _captured, fake_urlopen = make_fake_urlopen({}, raise_error=urllib.error.URLError("connection refused"))

    with patch("shipwright_kit.llm.urllib.request.urlopen", fake_urlopen):
        from vex.ai.ollama import OllamaProvider

        provider = OllamaProvider()
        with pytest.raises(urllib.error.URLError):
            provider.explain("hi")
