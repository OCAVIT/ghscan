"""
Moonshot/Kimi API client with automatic key rotation.

Same interface shape as glm_client.py and deepseek_client.py — drop-in
fallback when both DeepSeek and GLM pools are exhausted. Uses keys we
already harvest from GitHub leaks (provider='kimi' in DB).

Endpoints:
  Primary:  POST https://api.moonshot.cn/v1/chat/completions
  Fallback: POST https://api.moonshot.ai/v1/chat/completions
            (same key works on both — Moonshot serves China + intl with
             a single key namespace; .cn is faster from CN egress, .ai
             is the international gateway. Some keys are scoped to one
             only — try both before declaring dead.)

Models:
  - kimi-k2.6  — flagship long-context, OpenAI-compatible (DEFAULT)
  - kimi-latest

Authentication: Bearer <key> (OpenAI-compatible).
JSON mode: response_format={"type":"json_object"}.

Used as fallback by llm_client.py after GLM. Slot also exposed via
the rotation HTTP API at /api/keys?provider=kimi for hermes-bounty.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

import db

log = logging.getLogger(__name__)


_BASE_URLS = (
    "https://api.moonshot.cn/v1/chat/completions",
    "https://api.moonshot.ai/v1/chat/completions",
)
_DEFAULT_MODEL = "kimi-k2.6"

_DEAD_STATUS = (401, 403)
_RATE_LIMIT_STATUS = (429,)
# Body fragments that look like dead keys even on 200/400 (Moonshot
# sometimes returns 200 with an error envelope — paranoid match).
_DEAD_BODY_MARKERS = (
    "exceeded_current_quota",
    "insufficient_quota",
    "invalid_api_key",
    "account_deactivated",
)


async def call_kimi(
    messages: list[dict],
    model: str = _DEFAULT_MODEL,
    response_format: dict | None = None,
    temperature: float | None = None,
    max_tokens: int | None = None,
    timeout: float = 600.0,
) -> dict | None:
    """
    Call Moonshot/Kimi chat completions with automatic key rotation.

    Returns the full response JSON on success, None if every key failed
    on every endpoint.

    Args:
      model: 'kimi-k2.6' (flagship) or 'kimi-latest'
      temperature: 0.0-1.0. Skip for default Moonshot tuning.
      response_format: {"type":"json_object"} for JSON mode

    Drop-in compatible with call_deepseek/call_glm response shape.
    """
    keys = db.get_valid_keys_by_provider("kimi")
    if not keys:
        log.warning("Kimi call: no valid keys in DB — skipping")
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

            killed = False
            for url in _BASE_URLS:
                try:
                    r = await c.post(
                        url,
                        headers={
                            "Authorization": f"Bearer {key}",
                            "Content-Type":  "application/json",
                        },
                        json=payload,
                    )
                except (httpx.TimeoutException, httpx.NetworkError) as e:
                    log.debug("Kimi key %s... network err on %s: %s",
                              key[:12], url, e)
                    continue
                except Exception as e:
                    log.debug("Kimi key %s... err on %s: %s", key[:12], url, e)
                    continue

                # Hidden quota error in 200/400 body
                body_lower = (r.text or "").lower()
                hidden_dead = any(m in body_lower for m in _DEAD_BODY_MARKERS)

                if r.status_code == 200 and not hidden_dead:
                    try:
                        return r.json()
                    except Exception as e:
                        log.warning("Kimi key %s... bad JSON in 200: %s",
                                    key[:12], e)
                        continue

                if r.status_code in _DEAD_STATUS or hidden_dead:
                    # Try next URL before declaring dead — some keys are
                    # scoped to .cn or .ai only.
                    log.debug("Kimi key %s... DEAD (%d) on %s — try next URL",
                              key[:12], r.status_code, url)
                    if url == _BASE_URLS[-1]:
                        log.info("Kimi key %s... DEAD on all endpoints — "
                                 "marking invalid", key[:12])
                        try:
                            db.update_key_validity(khash, False)
                        except Exception:
                            pass
                        killed = True
                    continue

                if r.status_code in _RATE_LIMIT_STATUS:
                    log.debug("Kimi key %s... 429 on %s — trying next key",
                              key[:12], url)
                    break  # don't retry same key on different URL for 429

                # Unknown error — log & try next URL
                log.warning("Kimi key %s... unexpected %d on %s: %s",
                            key[:12], r.status_code, url, r.text[:200])
                continue

            if killed:
                continue

    log.warning("Kimi call: all %d keys failed", len(keys))
    return None


def extract_text(response: dict | None) -> str | None:
    """Extract assistant message content from Kimi response."""
    if not response:
        return None
    try:
        return response["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return None
