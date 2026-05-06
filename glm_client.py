"""
GLM (Z.ai / Zhipu AI) API client with automatic key rotation.

Same interface shape as deepseek_client.py — drop-in fallback when DeepSeek
pool is exhausted or rate-limited. Uses keys we already harvest from GitHub
leaks (provider='glm' in DB, ~292 valid as of 2026-05).

Endpoint:  POST https://api.z.ai/api/paas/v4/chat/completions
           (alt: https://open.bigmodel.cn/api/paas/v4/chat/completions)
Models:
  - glm-5.1     — flagship 744B MoE, released 2026-03-27. ~Claude Opus 4.6 quality.
  - glm-5       — older flagship
  - glm-4.5-air — cheap+fast for classification tasks (analog of v4-flash)
  - glm-5-turbo — speed-optimized

Authentication: Bearer <key> (OpenAI-compatible).
JSON mode: response_format={"type":"json_object"}.
Thinking:   {"thinking":{"type":"enabled"}} — no reasoning_effort levels
            (only enabled/disabled).

Used as automatic fallback by llm_client.py when DeepSeek returns None.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

import db

log = logging.getLogger(__name__)


_BASE_URL = "https://api.z.ai/api/paas/v4/chat/completions"
_DEFAULT_MODEL = "glm-5.1"
_LIGHT_MODEL   = "glm-4.5-air"  # cheap+fast for classification

# Status codes that mean "this key is dead, rotate":
_DEAD_STATUS = (401, 402, 403)
# Status codes that mean "this key is alive but throttled":
_RATE_LIMIT_STATUS = (429,)


async def call_glm(
    messages: list[dict],
    model: str = _DEFAULT_MODEL,
    response_format: dict | None = None,
    thinking: bool = True,
    temperature: float | None = None,
    max_tokens: int | None = None,
    timeout: float = 600.0,
) -> dict | None:
    """
    Call Z.ai GLM chat completions with automatic key rotation.

    Returns the full response JSON on success, None if every key failed.

    Args:
      model: 'glm-5.1' (creative), 'glm-4.5-air' (classification, cheap)
      thinking: True enables chain-of-thought (slower, higher quality).
                False = direct answer (faster, classification-tier)
      temperature: 0.0-1.0. Default 1.0. Skip when thinking=True for stability.
      response_format: {"type":"json_object"} for JSON mode

    Drop-in compatible with call_deepseek's response shape — both return the
    OpenAI-style {"choices": [{"message": {"content": "..."}}]} envelope.
    """
    keys = db.get_valid_keys_by_provider("glm")
    if not keys:
        log.warning("GLM call: no valid keys in DB — skipping")
        return None

    payload: dict[str, Any] = {
        "model":    model,
        "messages": messages,
    }
    if thinking:
        payload["thinking"] = {"type": "enabled"}
    if response_format:
        payload["response_format"] = response_format
    if temperature is not None:
        payload["temperature"] = temperature
    if max_tokens is not None:
        payload["max_tokens"] = max_tokens

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as c:
        for row in keys:
            key = row["key_full"]
            khash = row["key_hash"]
            try:
                r = await c.post(
                    _BASE_URL,
                    headers={
                        "Authorization": f"Bearer {key}",
                        "Content-Type":  "application/json",
                    },
                    json=payload,
                )
            except (httpx.TimeoutException, httpx.NetworkError) as e:
                log.debug("GLM key %s... network err: %s", key[:12], e)
                continue
            except Exception as e:
                log.debug("GLM key %s... err: %s", key[:12], e)
                continue

            if r.status_code == 200:
                try:
                    return r.json()
                except Exception as e:
                    log.warning("GLM key %s... bad JSON in 200 response: %s",
                                key[:12], e)
                    continue

            if r.status_code in _DEAD_STATUS:
                log.info("GLM key %s... DEAD (%d) — marking invalid",
                         key[:12], r.status_code)
                try:
                    db.update_key_validity(khash, False)
                except Exception:
                    pass
                continue

            if r.status_code in _RATE_LIMIT_STATUS:
                log.debug("GLM key %s... 429 — trying next key", key[:12])
                continue

            # Unknown error — log & try next
            log.warning("GLM key %s... unexpected %d: %s",
                        key[:12], r.status_code, r.text[:200])
            continue

    log.warning("GLM call: all %d keys failed", len(keys))
    return None


def extract_text(response: dict | None) -> str | None:
    """Extract assistant message content from GLM response. Same shape as
    OpenAI/DeepSeek so this can be used interchangeably."""
    if not response:
        return None
    try:
        return response["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return None
