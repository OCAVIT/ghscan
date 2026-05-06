"""
Unified LLM client — single entry point for all DeepSeek-driven pipelines.
Automatically falls back from DeepSeek → GLM-5.1 when DeepSeek pool exhausts.

Two task tiers:
  - call_creative()  — quality-first. Uses DeepSeek v4-pro reasoning_effort=max
                       (or GLM-5.1 with thinking=true). For: themer, archetype
                       miner, active learning, custom extractor synthesis.
  - call_fast()      — speed-first. Uses DeepSeek v4-flash (or GLM-4.5-air)
                       without thinking. For: repo classifier, pre-validator,
                       author profiler. Cheap + sub-5s response.

Pool rotation handled inside deepseek_client / glm_client. Failures cascade:
  DeepSeek (44 keys) → GLM (292 keys) → None (caller skips gracefully)

DOES NOT use AIMLAPI fallback — user excluded that tier.
"""

from __future__ import annotations

import logging
from typing import Any

from deepseek_client import call_deepseek, extract_text as ds_extract
from glm_client      import call_glm,      extract_text as glm_extract

log = logging.getLogger(__name__)


async def call_creative(
    messages: list[dict],
    response_format: dict | None = None,
    timeout: float = 900.0,
) -> tuple[str | None, str]:
    """
    Quality-first LLM call (creative generation, structural reasoning).
    Returns (text_or_None, source) where source ∈ {"deepseek","glm","none"}.

    DeepSeek v4-pro reasoning_effort=max → GLM-5.1 thinking=enabled fallback.
    """
    # 1) Try DeepSeek v4-pro with max thinking
    resp = await call_deepseek(
        messages=messages,
        model="deepseek-v4-pro",
        response_format=response_format,
        reasoning_effort="max",
        timeout=timeout,
    )
    if resp is not None:
        text = ds_extract(resp)
        if text:
            return text, "deepseek"
        log.debug("creative: deepseek returned response but no text")

    # 2) Fallback GLM-5.1 with thinking
    log.info("creative: DeepSeek pool exhausted/empty, falling back to GLM-5.1")
    resp = await call_glm(
        messages=messages,
        model="glm-5.1",
        response_format=response_format,
        thinking=True,
        timeout=timeout,
    )
    if resp is not None:
        text = glm_extract(resp)
        if text:
            return text, "glm"

    log.warning("creative: both DeepSeek and GLM failed, returning None")
    return None, "none"


async def call_fast(
    messages: list[dict],
    response_format: dict | None = None,
    temperature: float | None = 0.3,
    max_tokens: int | None = 512,
    timeout: float = 30.0,
) -> tuple[str | None, str]:
    """
    Speed-first LLM call (classification, extraction, binary judgments).
    Returns (text_or_None, source).

    DeepSeek v4-flash (no thinking) → GLM-4.5-air fallback.
    Tuned for sub-5-second response on small inputs (<2KB).
    """
    # 1) DeepSeek v4-flash (no reasoning_effort = lightning)
    resp = await call_deepseek(
        messages=messages,
        model="deepseek-v4-flash",
        response_format=response_format,
        reasoning_effort=None,  # None → not sent (flash works without it)
        timeout=timeout,
    )
    if resp is not None:
        text = ds_extract(resp)
        if text:
            return text, "deepseek"

    # 2) GLM-4.5-air fallback
    resp = await call_glm(
        messages=messages,
        model="glm-4.5-air",
        response_format=response_format,
        thinking=False,
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=timeout,
    )
    if resp is not None:
        text = glm_extract(resp)
        if text:
            return text, "glm"

    return None, "none"


async def llm_pool_stats() -> dict:
    """Snapshot of available LLM compute capacity. Used by /admin/llm_pool_stats
    and Telegram low-pool alerts."""
    import db
    return {
        "deepseek_valid": len(db.get_valid_keys_by_provider("deepseek")),
        "glm_valid":      len(db.get_valid_keys_by_provider("glm")),
    }
