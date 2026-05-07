"""
Unified LLM client — single entry point for all DeepSeek-driven pipelines.
Automatically cascades through DeepSeek → GLM → Kimi → SiliconFlow as
each pool exhausts.

Two task tiers:
  - call_creative()  — quality-first. DS v4-pro (reasoning=max) → GLM-5.1
                       (thinking) → Kimi K2.6 → SiliconFlow Kimi K2.6.
  - call_fast()      — speed-first. DS v4-flash → GLM-4.5-air → Kimi K2.6
                       → SiliconFlow Kimi K2.6.

Pool rotation handled inside each *_client.py. Failures cascade:
  DeepSeek (44 keys) → GLM (292) → Kimi (~Moonshot pool) →
  SiliconFlow (Kimi served via SF) → None (caller skips gracefully)

DOES NOT use AIMLAPI fallback — user excluded that tier.
"""

from __future__ import annotations

import logging
from typing import Any

from deepseek_client    import call_deepseek,    extract_text as ds_extract
from glm_client         import call_glm,         extract_text as glm_extract
from kimi_client        import call_kimi,        extract_text as kimi_extract
from siliconflow_client import call_siliconflow, extract_text as sf_extract

log = logging.getLogger(__name__)


async def call_creative(
    messages: list[dict],
    response_format: dict | None = None,
    timeout: float = 900.0,
) -> tuple[str | None, str]:
    """
    Quality-first LLM call (creative generation, structural reasoning).
    Returns (text_or_None, source) where
    source ∈ {"deepseek","glm","kimi","siliconflow","none"}.

    Cascade: DeepSeek v4-pro (reasoning=max) → GLM-5.1 (thinking) →
             Kimi K2.6 (Moonshot) → SiliconFlow Kimi K2.6.
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

    # 3) Fallback Kimi K2.6 (Moonshot official)
    log.info("creative: GLM exhausted, falling back to Kimi K2.6 (Moonshot)")
    resp = await call_kimi(
        messages=messages,
        model="kimi-k2.6",
        response_format=response_format,
        timeout=timeout,
    )
    if resp is not None:
        text = kimi_extract(resp)
        if text:
            return text, "kimi"

    # 4) Fallback SiliconFlow (Kimi K2.6 via aggregator)
    log.info("creative: Kimi exhausted, falling back to SiliconFlow Kimi K2.6")
    resp = await call_siliconflow(
        messages=messages,
        model="moonshotai/kimi-k2.6",
        response_format=response_format,
        timeout=timeout,
    )
    if resp is not None:
        text = sf_extract(resp)
        if text:
            return text, "siliconflow"

    log.warning("creative: DeepSeek+GLM+Kimi+SiliconFlow all failed, "
                "returning None")
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
    Returns (text_or_None, source) where
    source ∈ {"deepseek","glm","kimi","siliconflow","none"}.

    Cascade: DeepSeek v4-flash (no thinking) → GLM-4.5-air → Kimi K2.6 →
             SiliconFlow Kimi K2.6. Tuned for sub-5-second response on
             small inputs (<2KB) when the first tier is healthy.
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

    # 3) Kimi K2.6 (Moonshot)
    resp = await call_kimi(
        messages=messages,
        model="kimi-k2.6",
        response_format=response_format,
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=timeout,
    )
    if resp is not None:
        text = kimi_extract(resp)
        if text:
            return text, "kimi"

    # 4) SiliconFlow (Kimi K2.6 via aggregator)
    resp = await call_siliconflow(
        messages=messages,
        model="moonshotai/kimi-k2.6",
        response_format=response_format,
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=timeout,
    )
    if resp is not None:
        text = sf_extract(resp)
        if text:
            return text, "siliconflow"

    return None, "none"


async def llm_pool_stats() -> dict:
    """Snapshot of available LLM compute capacity. Used by /admin/llm_pool_stats
    and Telegram low-pool alerts."""
    import db
    return {
        "deepseek_valid":     len(db.get_valid_keys_by_provider("deepseek")),
        "glm_valid":          len(db.get_valid_keys_by_provider("glm")),
        "kimi_valid":         len(db.get_valid_keys_by_provider("kimi")),
        "siliconflow_valid":  len(db.get_valid_keys_by_provider("siliconflow")),
    }
