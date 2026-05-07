"""
Kaggle query mutation engine — generates query variants WITHOUT LLM calls.

Two strategies:

1. Yield-mutation
   Takes existing top-yielding queries (kernels_returned > 0 in
   kaggle_dynamic_queries) and produces deterministic variants via:
     - Year suffix:      "rag langchain" → "rag langchain 2025 / 2026"
     - Framework suffix: "openai chatbot" → "openai chatbot langchain / crewai"
     - Language suffix:  "deepseek api" → "deepseek api python / jupyter"
     - Verb swap:        "tutorial" ↔ "notebook" ↔ "example" ↔ "demo"
     - CN model names:   insert known CN model aliases for CN-provider queries

2. Cartesian
   Builds queries from cross-product of:
     PROVIDERS_SHORT × TUTORIAL_STYLES × YEAR_TAGS
   Generates ~400 candidates per run — programmatic, zero cost,
   surfaces provider+style combos the themer never thought of.

Both strategies insert into kaggle_dynamic_queries with theme
"mutator:..." / "cartesian:...", subject to the same 15-day hash-dedup
as the themer. Runs every 15 min on master (via _kaggle_mutator_loop in
main.py). Mirrors pick up via /admin/kaggle_dynamic_queries_export sync.
"""

from __future__ import annotations

import logging
import random
from itertools import product

import db
from db import _query_hash  # canonical hash (whitespace-norm, NO lowercase) — must match db.kaggle_register_queries

log = logging.getLogger(__name__)

# ── Year / framework / language suffixes ─────────────────────────────────────

_YEAR_TAGS = ["2025", "2026"]
_FRAMEWORKS = [
    "langchain", "llamaindex", "crewai", "autogen", "smolagents",
    "haystack", "dspy", "litellm",
]
_LANG_TAGS = ["python", "jupyter notebook", "google colab"]
_VERB_MAP = {
    "tutorial": ["notebook", "example", "demo", "guide"],
    "notebook": ["tutorial", "example", "demo"],
    "example":  ["tutorial", "notebook", "demo"],
    "demo":     ["tutorial", "notebook", "example"],
    "guide":    ["tutorial", "notebook"],
}
# CN model aliases to append when query is CN-provider flavoured
_CN_ALIASES = {
    "glm": ["glm-4", "glm-4-plus", "chatglm"],
    "zhipuai": ["glm-4", "bigmodel"],
    "ark": ["doubao", "seedance", "doubao-pro"],
    "kling": ["kling-v2", "kuaishou"],
    "siliconflow": ["siliconcloud", "qwen", "qwq"],
    "moonshot": ["kimi", "kimi-k2", "moonshot-v1"],
    "deepseek": ["deepseek-v4", "deepseek-v4-pro", "deepseek-r2"],
}

_QUERY_LEN_CAP = 120


def _make_variants(query_str: str) -> list[tuple[str, str]]:
    """Return (variant_query, theme_tag) pairs for a single source query."""
    variants: list[tuple[str, str]] = []
    q = query_str.strip().lower()

    # ── Year suffix ──────────────────────────────────────────────────────────
    for yr in _YEAR_TAGS:
        if yr not in q:
            v = f"{query_str} {yr}"
            if len(v) <= _QUERY_LEN_CAP:
                variants.append((v, f"mutator:year_{yr}"))

    # ── Framework suffix (only when query doesn't already mention one) ───────
    already_fw = any(f in q for f in _FRAMEWORKS)
    if not already_fw:
        # Pick 2 random frameworks to avoid quadratic explosion
        for fw in random.sample(_FRAMEWORKS, min(2, len(_FRAMEWORKS))):
            v = f"{query_str} {fw}"
            if len(v) <= _QUERY_LEN_CAP:
                variants.append((v, f"mutator:fw_{fw}"))

    # ── Language suffix (only when query doesn't already mention one) ────────
    if not any(lang in q for lang in ["python", "jupyter", "colab"]):
        v = f"{query_str} python"
        if len(v) <= _QUERY_LEN_CAP:
            variants.append((v, f"mutator:lang_python"))

    # ── Verb swap ────────────────────────────────────────────────────────────
    for src, targets in _VERB_MAP.items():
        if f" {src}" in q or q.startswith(src):
            for tgt in targets[:2]:  # cap at 2 swaps per verb
                v = query_str.replace(src, tgt, 1)
                if len(v) <= _QUERY_LEN_CAP and v != query_str:
                    variants.append((v, f"mutator:verb_{src}_{tgt}"))
            break  # only first matching verb per query

    # ── CN model alias injection ─────────────────────────────────────────────
    for cn_kw, aliases in _CN_ALIASES.items():
        if cn_kw in q:
            for alias in aliases[:2]:
                if alias not in q:
                    v = f"{query_str} {alias}"
                    if len(v) <= _QUERY_LEN_CAP:
                        variants.append((v, f"mutator:cn_{alias}"))
            break

    return variants


async def generate_mutated_batch(max_source: int = 30) -> int:
    """Mutate top-yielding queries. Returns count of new rows inserted."""
    try:
        with db._conn() as c:
            rows = c.execute(
                """SELECT query_str FROM kaggle_dynamic_queries
                   WHERE kernels_returned > 0
                   ORDER BY valid_keys_found DESC, kernels_returned DESC
                   LIMIT ?""",
                (max_source,),
            ).fetchall()
        sources = [r["query_str"] for r in rows]
    except Exception as e:
        log.warning("kaggle_mutator: failed to load top-yielders: %s", e)
        return 0

    if not sources:
        log.debug("kaggle_mutator: no top-yielders yet, skipping mutation")
        return 0

    forbidden = db.kaggle_get_recent_query_hashes(days=15)
    candidates: list[dict] = []
    seen: set[str] = set()

    for src in sources:
        for variant, theme in _make_variants(src):
            h = _query_hash(variant)
            if h in forbidden or h in seen:
                continue
            seen.add(h)
            candidates.append({"query_str": variant, "theme": theme})

    if not candidates:
        log.debug("kaggle_mutator: all variants already in 15-day window")
        return 0

    inserted = db.kaggle_register_queries(candidates)
    log.info("kaggle_mutator: inserted %d/%d mutation variants", inserted, len(candidates))
    return inserted


# ── Cartesian generator ───────────────────────────────────────────────────────

# Short provider name list — most Kaggle-relevant (free-text search terms)
_PROVIDERS_SHORT = [
    "openai", "anthropic claude", "gemini", "deepseek", "groq",
    "elevenlabs", "stability", "huggingface", "openrouter",
    "replicate", "together ai", "fireworks ai",
    "zhipuai glm", "moonshot kimi", "ark doubao", "siliconflow",
    "kling video", "luma dream machine", "wavespeed",
    "higgsfield", "fal flux", "grok xai",
]

_TUTORIAL_STYLES = [
    "tutorial", "notebook", "api integration", "rag pipeline",
    "chatbot", "llm agent", "fine-tuning", "langchain",
    "llamaindex", "crewai", "multimodal",
]

_YEAR_COMBOS = ["2025", "2026", ""]  # "" = no year


async def generate_cartesian_batch() -> int:
    """Cross-product providers × styles × years → insert new queries."""
    forbidden = db.kaggle_get_recent_query_hashes(days=15)
    candidates: list[dict] = []
    seen: set[str] = set()

    combos = list(product(_PROVIDERS_SHORT, _TUTORIAL_STYLES, _YEAR_COMBOS))
    random.shuffle(combos)  # randomise order so partial batches have variety

    for provider, style, year in combos:
        q = f"{provider} {style} {year}".strip()
        if len(q) > _QUERY_LEN_CAP:
            continue
        h = _query_hash(q)
        if h in forbidden or h in seen:
            continue
        seen.add(h)
        tag = f"cartesian:{provider.split()[0]}_{style.replace(' ','_')}"
        candidates.append({"query_str": q, "theme": tag})

    if not candidates:
        log.debug("kaggle_mutator: cartesian — all combos in 15-day window")
        return 0

    inserted = db.kaggle_register_queries(candidates)
    log.info("kaggle_mutator: cartesian inserted %d/%d combos", inserted, len(candidates))
    return inserted
