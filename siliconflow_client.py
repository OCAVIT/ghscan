"""
SiliconFlow API client with automatic key rotation.

SiliconFlow (siliconflow.cn) is an OpenAI-compatible aggregator that
serves Kimi K2.6 (and many other models) under a unified billing pool.
Used as a SECOND source of Kimi K2.6 alongside the official Moonshot
endpoints — when Moonshot keys are exhausted or rate-limited.

Endpoint:  POST https://api.siliconflow.cn/v1/chat/completions
Model ID:  moonshotai/kimi-k2.6   (provider/model HuggingFace-style)

Authentication: Bearer <key> (OpenAI-compatible).
JSON mode: response_format={"type":"json_object"}.

Validator already exists in validators.py (validate_siliconflow checks
balance via /v1/user/info). Pattern extraction in patterns.py finds
SILICONFLOW_API_KEY / SILICONCLOUD_API_KEY etc. in scanned repos.

Used as fallback by llm_client.py after GLM and Kimi (when the kimi
pool is exhausted but we still want Kimi-quality output via SF). Also
exposed via /api/keys?provider=siliconflow for hermes-bounty
rotation_proxy.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

import db

log = logging.getLogger(__name__)


_BASE_URL = "https://api.siliconflow.cn/v1/chat/completions"
_DEFAULT_MODEL = "moonshotai/kimi-k2.6"

_DEAD_STATUS = (401, 403)
_RATE_LIMIT_STATUS = (429,)
_DEAD_BODY_MARKERS = (
    "balance not enough",
    "insufficient balance",
    "exceeded_current_quota",
    "invalid_api_key",
    "account_deactivated",
)


async def call_siliconflow(
    messages: list[dict],
    model: str = _DEFAULT_MODEL,
    response_format: dict | None = None,
    temperature: float | None = None,
    max_tokens: int | None = None,
    timeout: float = 600.0,
) -> dict | None:
    """
    Call SiliconFlow chat completions with automatic key rotation.

    Returns the full response JSON on success, None if every key failed.

    Args:
      model: 'moonshotai/kimi-k2.6' (DEFAULT). SF also serves Qwen,
             DeepSeek, GLM and others under their HF-style provider/model
             slugs — pass any supported slug here.
      temperature: 0.0-1.0
      response_format: {"type":"json_object"} for JSON mode

    Drop-in compatible with call_deepseek/call_glm/call_kimi response
    shape (OpenAI-style choices[0].message.content).
    """
    keys = db.get_valid_keys_by_provider("siliconflow")
    if not keys:
        log.warning("SiliconFlow call: no valid keys in DB — skipping")
        return None

    payload: dict[str, Any] = {
        "model":    model,
        "messages": messages,
    }
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
                log.debug("SF key %s... network err: %s", key[:12], e)
                continue
            except Exception as e:
                log.debug("SF key %s... err: %s", key[:12], e)
                continue

            body_lower = (r.text or "").lower()
            hidden_dead = any(m in body_lower for m in _DEAD_BODY_MARKERS)

            if r.status_code == 200 and not hidden_dead:
                try:
                    return r.json()
                except Exception as e:
                    log.warning("SF key %s... bad JSON in 200: %s",
                                key[:12], e)
                    continue

            if r.status_code in _DEAD_STATUS or hidden_dead:
                log.info("SF key %s... DEAD (%d) — marking invalid",
                         key[:12], r.status_code)
                try:
                    db.update_key_validity(khash, False)
                except Exception:
                    pass
                continue

            if r.status_code in _RATE_LIMIT_STATUS:
                log.debug("SF key %s... 429 — trying next key", key[:12])
                continue

            log.warning("SF key %s... unexpected %d: %s",
                        key[:12], r.status_code, r.text[:200])
            continue

    log.warning("SiliconFlow call: all %d keys failed", len(keys))
    return None


def extract_text(response: dict | None) -> str | None:
    """Extract assistant message content from SiliconFlow response."""
    if not response:
        return None
    try:
        return response["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return None
