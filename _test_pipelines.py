"""
Local test harness for new LLM pipelines. Runs without real API keys —
mocks LLM responses to exercise parsers, validators, decision logic.

Usage:
  GITHUB_TOKEN=dummy TELEGRAM_BOT_TOKEN=dummy TELEGRAM_CHAT_ID=0 python _test_pipelines.py
"""

from __future__ import annotations

import asyncio
import json
import sys
import re
from unittest.mock import patch, AsyncMock

# Force test envs
import os
os.environ.setdefault("GITHUB_TOKEN",        "dummy_pat")
os.environ.setdefault("TELEGRAM_BOT_TOKEN",  "dummy_bot")
os.environ.setdefault("TELEGRAM_CHAT_ID",    "0")

import db
db.init_db()


# ── Test 1: GLM client - parser + dead-key rotation ──────────────────────
def test_glm_extract_text():
    from glm_client import extract_text
    # Standard OpenAI-shaped response
    assert extract_text({"choices": [{"message": {"content": "hello"}}]}) == "hello"
    # Missing fields → None
    assert extract_text({}) is None
    assert extract_text({"choices": []}) is None
    assert extract_text(None) is None
    print("[OK] glm_client.extract_text handles all shapes")


# ── Test 2: LLM client - call_creative falls back to GLM when DeepSeek None
async def test_llm_fallback_chain():
    from unittest.mock import patch, AsyncMock
    import llm_client

    # Scenario A: DeepSeek returns text → use it
    with patch("llm_client.call_deepseek", new=AsyncMock(
            return_value={"choices": [{"message": {"content": "DS_RESPONSE"}}]})), \
         patch("llm_client.call_glm",      new=AsyncMock(return_value=None)):
        text, source = await llm_client.call_creative([{"role": "user", "content": "hi"}])
        assert text == "DS_RESPONSE", f"got {text!r}"
        assert source == "deepseek", f"got {source!r}"
    print("[OK] call_creative uses DeepSeek when available")

    # Scenario B: DeepSeek returns None → GLM responds
    with patch("llm_client.call_deepseek", new=AsyncMock(return_value=None)), \
         patch("llm_client.call_glm",      new=AsyncMock(
            return_value={"choices": [{"message": {"content": "GLM_RESPONSE"}}]})):
        text, source = await llm_client.call_creative([{"role": "user", "content": "hi"}])
        assert text == "GLM_RESPONSE", f"got {text!r}"
        assert source == "glm", f"got {source!r}"
    print("[OK] call_creative falls back to GLM when DeepSeek empty")

    # Scenario C: both return None → ('none')
    with patch("llm_client.call_deepseek", new=AsyncMock(return_value=None)), \
         patch("llm_client.call_glm",      new=AsyncMock(return_value=None)):
        text, source = await llm_client.call_creative([{"role": "user", "content": "hi"}])
        assert text is None
        assert source == "none"
    print("[OK] call_creative returns ('none') when both fail")


# ── Test 3: Repo prioritizer - decision matrix ───────────────────────────
def test_repo_prioritizer_decisions():
    from repo_prioritizer import _decide

    # Confident template/tutorial → SKIP
    assert _decide("template",  90) is False
    assert _decide("tutorial",  85) is False
    assert _decide("example",   85) is False
    # Low confidence → WALK (be conservative, don't lose finds)
    assert _decide("template",  50) is True
    assert _decide("tutorial",  40) is True
    # Production always walked regardless of confidence
    assert _decide("production", 90) is True
    assert _decide("production", 30) is True
    # Example needs higher threshold (some are real)
    assert _decide("example",   75) is True   # under 80 → walk
    assert _decide("example",   85) is False  # over 80 → skip
    print("[OK] repo_prioritizer._decide matrix correct")


def test_repo_prioritizer_parser():
    from repo_prioritizer import _parse_classification

    # Clean JSON
    assert _parse_classification('{"class":"template","confidence":85}') == ("template", 85)
    # With code fence
    assert _parse_classification('```json\n{"class":"production","confidence":70}\n```') == ("production", 70)
    # JSON inside prose
    assert _parse_classification('Here it is: {"class":"tutorial","confidence":60} that\'s all') == ("tutorial", 60)
    # Bad class → None
    assert _parse_classification('{"class":"bogus","confidence":90}') is None
    # Bad JSON → None
    assert _parse_classification('not json') is None
    # Confidence clamping
    assert _parse_classification('{"class":"template","confidence":150}') == ("template", 100)
    assert _parse_classification('{"class":"template","confidence":-5}')  == ("template", 0)
    print("[OK] repo_prioritizer._parse_classification handles all shapes")


# ── Test 4: Pre-validator - heuristic + parser ───────────────────────────
def test_prevalidator_heuristics():
    from pre_validator import _heuristic_pre_filter

    # Obvious placeholders → True (skip validation)
    assert _heuristic_pre_filter("sk-XXXXXXXXXXXXXX", ".env") is True
    assert _heuristic_pre_filter("AIzaSy<your-key-here>", "config.py") is True
    assert _heuristic_pre_filter("${OPENAI_API_KEY}", ".env.example") is True
    assert _heuristic_pre_filter("sk-your-openai-key", "test.py") is True
    assert _heuristic_pre_filter("sk-replace-me-with-key", "config") is True
    # Real-looking keys → False (proceed to LLM). These contain incidentally
    # adjacent letters like 'AbCdEf' which used to be false-flagged before
    # we removed the alphabet-sequential heuristic.
    assert _heuristic_pre_filter("sk-proj-AbCdEfGhIjKlMnOpQrStUvWx", ".env") is False
    assert _heuristic_pre_filter("AIzaSyDvD2-3xKpj7K9zX_bQrT0vN", "settings.py") is False
    assert _heuristic_pre_filter("sk-1234567890abcdef", "any") is False  # let LLM decide
    # Template filename → True even if key looks real
    assert _heuristic_pre_filter("sk-realLookingKey1234", ".env.example") is True
    assert _heuristic_pre_filter("sk-realLookingKey1234", ".env.template") is True
    print("[OK] pre_validator heuristic catches obvious placeholders")


def test_prevalidator_parser():
    from pre_validator import _parse_classification

    # Clean JSON
    assert _parse_classification('{"is_real":true,"reason":"prod env"}') is True
    assert _parse_classification('{"is_real":false,"reason":"placeholder"}') is False
    # With fence
    assert _parse_classification('```json\n{"is_real":true,"reason":"x"}\n```') is True
    # Bool as string (some LLMs do this)
    assert _parse_classification('{"is_real":"true","reason":"x"}') is True
    assert _parse_classification('{"is_real":"yes","reason":"x"}') is True
    assert _parse_classification('{"is_real":"false","reason":"x"}') is False
    # Bad → None
    assert _parse_classification('not json') is None
    assert _parse_classification('') is None
    print("[OK] pre_validator parser handles JSON variants")


# ── Test 5: Active learner - parser + query validation ───────────────────
def test_active_learner_validation():
    from active_learner import _parse_response, _validate_queries

    # Clean LLM output
    sample = json.dumps({
        "queries": [
            {"q": '"OPENAI_API_KEY" filename:.env', "provider": "openai",     "file_type": "env",    "theme": "core"},
            {"q": '"DEEPSEEK_API_KEY" language:python', "provider": "deepseek", "file_type": "code",   "theme": "lang"},
            {"q": "no operators no quotes",                "provider": "openai",   "file_type": "env"},  # invalid
            {"q": "x" * 300,                                "provider": "openai",   "file_type": "env"},  # too long
            {"q": '"TEST" filename:.env',                   "provider": "serper",   "file_type": "env"},  # deprioritized
            {"q": '"NEW_KEY" filename:.env',                "provider": "unknown",  "file_type": "env"},  # unknown -> multi
        ]
    })
    parsed = _parse_response(sample)
    assert len(parsed) == 6
    valid = _validate_queries(parsed)
    assert len(valid) == 4, f"expected 4, got {len(valid)}: {valid}"
    # serper -> remapped to multi
    serper_q = next(q for q in valid if "TEST" in q["query_str"])
    assert serper_q["provider"] == "multi"
    # unknown -> multi
    unk_q = next(q for q in valid if "NEW_KEY" in q["query_str"])
    assert unk_q["provider"] == "multi"
    # All have theme prefix
    assert all(q["theme"].startswith("active_learner:") for q in valid)
    print("[OK] active_learner parser + validator OK")


# ── Test 6: Author profiler - parser ─────────────────────────────────────
def test_author_profiler_parser():
    from author_profiler import _parse_response

    sample = json.dumps({
        "recidivism_score": 75,
        "watch_priority": "high",
        "next_check_hours": 2,
        "reason": "active production developer"
    })
    parsed = _parse_response(sample)
    assert parsed["recidivism_score"] == 75
    assert parsed["watch_priority"] == "high"
    assert parsed["next_check_hours"] == 2

    # Out-of-range clamping
    parsed = _parse_response(json.dumps({
        "recidivism_score": 150, "watch_priority": "high",
        "next_check_hours": 1000
    }))
    assert parsed["recidivism_score"] == 100  # clamped
    assert parsed["next_check_hours"] == 168  # clamped to 1 week max

    # Invalid JSON -> None
    assert _parse_response("not json") is None
    assert _parse_response(None) is None
    print("[OK] author_profiler parser handles edge cases")


# ── Test 7: Extractor synthesizer - regex validation ─────────────────────
def test_extractor_synth_validation():
    from extractor_synthesizer import _validate_pattern

    # Valid pattern with capture group
    assert _validate_pattern({"regex": r"(sk-[a-zA-Z0-9]{20,})", "provider": "openai"}) is not None
    # No capture group → invalid
    assert _validate_pattern({"regex": r"sk-[a-zA-Z0-9]+", "provider": "openai"}) is None
    # Bad regex
    assert _validate_pattern({"regex": r"sk-[unbalanced", "provider": "openai"}) is None
    # Empty
    assert _validate_pattern({"regex": "", "provider": "openai"}) is None
    # Too long
    assert _validate_pattern({"regex": "(" + "a" * 600 + ")", "provider": "openai"}) is None
    # Unknown provider → remapped to 'generic'
    res = _validate_pattern({"regex": r"(test-[a-z]+)", "provider": "fakeprovider"})
    assert res is not None
    _, prov = res
    assert prov == "generic"
    print("[OK] extractor_synthesizer validates regexes correctly")


# ── Test 8: GLM client request payload structure ─────────────────────────
def test_glm_payload():
    """Verify call_glm constructs request payload correctly without making
    real HTTP calls."""
    from unittest.mock import patch, AsyncMock, MagicMock
    import glm_client

    captured_payload = {}

    async def fake_post(url, headers=None, json=None, **kw):
        captured_payload.update(json or {})
        # Return successful 200 — keeps key valid across re-runs of the test
        m = MagicMock()
        m.status_code = 200
        m.json = lambda: {"choices": [{"message": {"content": "ok"}}]}
        return m

    # Use unique key per test run to avoid stale dead-marks from previous runs
    import time as _time
    test_key = f"test-glm-key-{int(_time.time())}-xxxxxxxxxxxx"
    db.save_key("glm", test_key, "test/repo",
                "test.py", "https://x", 0, "", "test", True)

    async def run():
        with patch("httpx.AsyncClient") as MockClient:
            mock_client_instance = MagicMock()
            mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
            mock_client_instance.__aexit__  = AsyncMock(return_value=None)
            mock_client_instance.post = AsyncMock(side_effect=fake_post)
            MockClient.return_value = mock_client_instance

            await glm_client.call_glm(
                messages=[{"role": "user", "content": "test"}],
                model="glm-5.1",
                response_format={"type": "json_object"},
                thinking=True,
            )
        return captured_payload

    payload = asyncio.run(run())
    assert payload.get("model") == "glm-5.1"
    assert payload.get("thinking") == {"type": "enabled"}
    assert payload.get("response_format") == {"type": "json_object"}
    assert payload.get("messages") == [{"role": "user", "content": "test"}]
    print("[OK] glm_client constructs correct payload (model, thinking, response_format)")


# ── Run all ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("LLM PIPELINE TEST SUITE")
    print("=" * 60)
    test_glm_extract_text()
    asyncio.run(test_llm_fallback_chain())
    test_repo_prioritizer_decisions()
    test_repo_prioritizer_parser()
    test_prevalidator_heuristics()
    test_prevalidator_parser()
    test_active_learner_validation()
    test_author_profiler_parser()
    test_extractor_synth_validation()
    test_glm_payload()
    print("=" * 60)
    print("ALL TESTS PASSED")
    print("=" * 60)
