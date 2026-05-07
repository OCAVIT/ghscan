"""
DeepSeek-driven creative query generator for Kaggle notebook search.

Mirrors query_themer.py (which targets GitHub) but adapted for Kaggle:
  - Kaggle search is FREE-TEXT only (no filename:/language:/path: operators)
  - Indexes notebook title, subtitle, tags, partial source code
  - 25%+ conversion rate on found keys (vs 4-5% on GitHub)
  - Auto-revoke pressure much lower than GitHub Secret Scanning Partner

LLM is asked to generate Kaggle-specific search terms covering:
  • Provider env-var names + SDK module names
  • Tutorial/RAG/agent notebook title patterns
  • Course/hackathon/bootcamp notebook patterns
  • New 2026 model integration patterns
  • Niche providers we under-cover (kling, ark, fal, hedra, etc.)
  • Yield-feedback: top-yielding existing queries shown as positive examples

Runs every 6h via main.py._kaggle_themer_loop alongside the static query
set in kaggle_scanner._QUERIES. Generated queries land in
kaggle_dynamic_queries table; kaggle_scanner reads top-yield rows each
cycle and prepends them to the static list.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone

import db
from llm_client import call_creative
from query_axes import PROVIDER_AXES

log = logging.getLogger(__name__)

TARGET_QUERIES_PER_BATCH = 60
_QUERY_LEN_CAP = 120  # Kaggle search box accepts longer but rarely useful


_SYSTEM_PROMPT = (
    "You generate Kaggle notebook search queries to recover leaked AI-provider "
    "API keys from the owner's authorized infrastructure scan. "
    "Output: JSON object with a 'queries' array. Each query is FREE-TEXT "
    "(NO operators — Kaggle search has no filename:/language:/path: like "
    "GitHub). Length cap 120 chars per query. "
    "Kaggle search matches notebook title, subtitle, tags, and partial "
    "source content. So good queries: env-var names ('OPENAI_API_KEY'), "
    "model integration patterns ('langchain rag tutorial'), niche providers "
    "('kling video api'), course-style titles ('llm api fine-tuning'). "
    "Bias toward queries that return AI-tutorial notebooks where authors "
    "often hardcode real keys in code or output cells."
)


def _build_user_prompt(target_count: int, top_yielders: list[dict]) -> str:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    yielders_text = ""
    if top_yielders:
        yielders_text = (
            "\n\nTOP-YIELDING QUERIES from prior cycles (MIRROR THE PATTERN, "
            "do not copy verbatim):\n"
            + "\n".join(
                f"  • {y['query_str'][:90]} (kernels={y['kernels_returned']}, valid={y['valid_keys_found']})"
                for y in top_yielders[:8]
            )
        )

    providers = sorted(PROVIDER_AXES.keys())
    return f"""\
Today is {today}. Generate {target_count} fresh Kaggle notebook search queries.

PROVIDERS WE TARGET (find leaks for these):
  {", ".join(providers[:30])}, {", ".join(providers[30:])}

THEMES (mix freely — DO NOT cluster on one theme):

  1. ENV-VAR LITERALS — direct strings authors paste in code/markdown:
       "GEMINI_API_KEY", "DEEPSEEK_API_KEY", "ANTHROPIC_API_KEY"
       "ZHIPUAI_API_KEY", "MOONSHOT_API_KEY", "ARK_API_KEY"
     Also subtypes: "OPENAI_BASE_URL", "VOLC_ACCESSKEY", etc.

  2. SDK MODULE/IMPORT PATTERNS — appear in source cells:
       "openai.OpenAI()", "anthropic.Anthropic", "langchain_openai"
       "google.generativeai", "huggingface_hub", "deepseek-chat"
       "from openai import", "import anthropic", "ChatOpenAI"

  3. TUTORIAL TITLE PATTERNS where devs hardcode keys:
       "openai chatbot tutorial", "rag pipeline langchain"
       "fine-tuning lora huggingface", "stable diffusion sdxl tutorial"
       "deepseek coder tutorial", "claude api integration"

  4. NICHE / CHINESE PROVIDERS (under-covered, high conversion):
       "zhipu glm chatglm", "moonshot kimi-128k", "ark seedance video"
       "kling text-to-video", "siliconflow embeddings api"

  5. COURSE / BOOTCAMP / HACKATHON SIGNATURES:
       "ai bootcamp final project", "deeplearning.ai langchain"
       "kaggle competition llm", "course assignment openai"

  6. RAG / AGENT FRAMEWORKS (frequent leak vectors):
       "crewai multi-agent", "autogen tutorial", "smolagents",
       "qdrant pinecone weaviate", "llamaindex rag tutorial"

  7. NEW 2026 MODEL NAMES (catch fresh leaks):
       "claude-4.5-sonnet", "gpt-5-mini", "deepseek-v4-pro"
       "gemini-3-pro", "kimi-k2", "glm-5.1-pro"

  8. VOICE / VIDEO / IMAGE GEN (often hardcoded in demos):
       "elevenlabs voice clone tts", "luma dream machine api"
       "stability sdxl turbo", "runway gen-3 alpha", "fal.ai flux"

  9. DEPLOYMENT/SECRET MGMT MISTAKES:
       "load_dotenv tutorial", "secrets.toml streamlit"
       "kaggle secrets api_key", "litellm proxy config"

OUTPUT JSON SHAPE:
{{
  "queries": [
    {{"q": "openai chatbot tutorial python", "theme": "tutorial_title"}},
    {{"q": "GEMINI_API_KEY langchain", "theme": "env_var"}},
    {{"q": "ZHIPUAI_API_KEY chatglm", "theme": "niche_cn"}}
  ]
}}

Each q under {_QUERY_LEN_CAP} chars, free-text only (no quotes around full
query, no operators). Provide exactly {target_count} entries.
{yielders_text}
"""


def _parse_response(text: str | None) -> list[dict]:
    if not text:
        return []
    txt = text.strip()
    if txt.startswith("```"):
        txt = re.sub(r"^```(?:json)?\s*", "", txt)
        txt = re.sub(r"\s*```$", "", txt)
    try:
        data = json.loads(txt)
    except json.JSONDecodeError:
        m = re.search(r"\{[\s\S]*\}", txt)
        if not m:
            return []
        try:
            data = json.loads(m.group(0))
        except json.JSONDecodeError:
            return []
    queries = data.get("queries", [])
    return [q for q in queries if isinstance(q, dict)]


def _validate_query(item: dict) -> dict | None:
    q = (item.get("q") or "").strip()
    if not q:
        return None
    # Strip wrapping quotes if model added them despite instructions
    if q.startswith('"') and q.endswith('"'):
        q = q[1:-1].strip()
    if not q or len(q) > _QUERY_LEN_CAP:
        return None
    # Reject queries that contain GitHub-search operators (the model sometimes
    # leaks across schemas) — these wouldn't work on Kaggle.
    if re.search(r"\b(?:filename|language|path|extension|pushed|created|size|fork|stars|in|topic):", q):
        return None
    theme = (item.get("theme") or "themer").strip()[:60]
    return {"query_str": q, "theme": f"kaggle_themer:{theme}"}


def _top_yielders(limit: int = 8) -> list[dict]:
    """Pull top-yielding kaggle queries (by valid_keys_found) for prompt
    feedback. Returns rows from kaggle_dynamic_queries — empty on first run."""
    try:
        with db._conn() as c:
            rows = c.execute(
                """SELECT query_str, kernels_returned, valid_keys_found
                   FROM kaggle_dynamic_queries
                   WHERE times_used > 0 AND valid_keys_found > 0
                   ORDER BY valid_keys_found DESC, kernels_returned DESC
                   LIMIT ?""",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]
    except Exception:
        return []


async def generate_kaggle_themed_batch(target_count: int = TARGET_QUERIES_PER_BATCH) -> int:
    """One batch of Kaggle creative queries via DeepSeek/GLM. Returns
    count of NEW rows inserted (15-day dedup enforced)."""
    forbidden = db.kaggle_get_recent_query_hashes(days=15)
    log.info("kaggle_themer: starting — %d hashes in 15-day window",
             len(forbidden))

    yielders = _top_yielders()
    messages = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user",   "content": _build_user_prompt(target_count, yielders)},
    ]

    text, source = await call_creative(
        messages,
        response_format={"type": "json_object"},
    )
    if not text:
        log.warning("kaggle_themer: LLM returned no content (source=%s)", source)
        return 0

    raw_items = _parse_response(text)
    if not raw_items:
        log.warning("kaggle_themer: failed to parse JSON: %s", text[:300])
        return 0

    candidates: list[dict] = []
    seen_in_batch: set[str] = set()
    for item in raw_items:
        validated = _validate_query(item)
        if not validated:
            continue
        from db import _query_hash
        h = _query_hash(validated["query_str"])
        if h in forbidden or h in seen_in_batch:
            continue
        seen_in_batch.add(h)
        candidates.append(validated)

    if not candidates:
        log.warning("kaggle_themer: 0 candidates survived dedup (raw=%d)",
                    len(raw_items))
        return 0

    inserted = db.kaggle_register_queries(candidates)
    log.info("kaggle_themer: inserted %d/%d kaggle queries (raw=%d) — source=%s",
             inserted, len(candidates), len(raw_items), source)
    return inserted


# ── CN-provider shard ─────────────────────────────────────────────────────────
# Separate LLM call focused exclusively on Chinese AI providers (GLM, Ark,
# Kling, Siliconflow, Kimi, DeepSeek, Qwen). These queries have a different
# lexical profile from the general themer so they survive the 15-day dedup
# independently — very few hash collisions with the main batch.

_CN_SYSTEM_PROMPT = (
    "You generate Kaggle notebook search queries to find leaked API keys for "
    "Chinese AI providers. These are FREE-TEXT queries (NO operators). "
    "Focus ONLY on: ZhipuAI/GLM, Moonshot/Kimi, Ark/Doubao/Seedance, "
    "SiliconFlow/SiliconCloud, DeepSeek, Qwen/DashScope, Kling/Kuaishou. "
    "Good queries combine: Chinese env-var names (ZHIPUAI_API_KEY, ARK_API_KEY, "
    "MOONSHOT_API_KEY), model aliases (glm-4, doubao-pro, kimi-k2, deepseek-v4), "
    "tutorial patterns ('zhipu tutorial', 'ark video api python'), and CN-specific "
    "contexts (Chinese AI course, bilingual notebook, CN cloud tutorial). "
    "Output JSON: {\"queries\": [{\"q\": \"...\", \"theme\": \"...\"}]}"
)


def _build_cn_prompt(target_count: int) -> str:
    return f"""\
Generate {target_count} Kaggle search queries targeting Chinese AI provider leaks.

PROVIDERS:
  ZhipuAI / GLM: ZHIPUAI_API_KEY, GLM_API_KEY, glm-4, glm-4-plus, glm-4.5, chatglm
  Moonshot / Kimi: MOONSHOT_API_KEY, KIMI_API_KEY, kimi-k2, moonshot-v1-128k
  Ark / ByteDance: ARK_API_KEY, DOUBAO_API_KEY, SEEDANCE_API_KEY, doubao-pro, doubao-seedance
  SiliconFlow: SILICONFLOW_API_KEY, SILICONCLOUD_API_KEY, siliconflow embeddings
  DeepSeek: DEEPSEEK_API_KEY, deepseek-v4, deepseek-v4-pro, deepseek-reasoner
  Qwen/DashScope: DASHSCOPE_API_KEY, QWEN_API_KEY, qwen2.5, qwq-32b
  Kling/Kuaishou: KLING_ACCESS_KEY, KLING_AK, kling text-to-video, kling-v2

QUERY THEMES TO COVER:
  1. Env-var literals: "ZHIPUAI_API_KEY notebook", "ARK_API_KEY tutorial"
  2. Model name patterns: "glm-4 langchain", "kimi-k2 rag", "doubao-pro chat"
  3. Tutorial titles: "zhipu ai chatbot tutorial", "deepseek v4 colab guide"
  4. CN-context: "中文 AI API notebook", "bilingual llm tutorial python"
  5. API integration: "moonshot api python tutorial", "siliconcloud embeddings"
  6. Course/assignment: "deeplearning zhipu project", "baidu cloud ai assignment"

Output exactly {target_count} queries, free-text only, each under {_QUERY_LEN_CAP} chars.
JSON: {{"queries": [{{"q": "ZHIPUAI_API_KEY langchain notebook", "theme": "env_var"}}, ...]}}
"""


async def generate_kaggle_cn_batch(target_count: int = 30) -> int:
    """CN-focused Kaggle queries via DeepSeek/GLM. Separate hash space from
    main themer due to distinct lexical domain. Returns new rows inserted."""
    forbidden = db.kaggle_get_recent_query_hashes(days=15)
    log.info("kaggle_cn_themer: starting — %d hashes in 15-day window", len(forbidden))

    messages = [
        {"role": "system", "content": _CN_SYSTEM_PROMPT},
        {"role": "user",   "content": _build_cn_prompt(target_count)},
    ]

    text, source = await call_creative(
        messages,
        response_format={"type": "json_object"},
    )
    if not text:
        log.warning("kaggle_cn_themer: LLM returned no content (source=%s)", source)
        return 0

    raw_items = _parse_response(text)
    if not raw_items:
        log.warning("kaggle_cn_themer: failed to parse JSON: %s", text[:300])
        return 0

    candidates: list[dict] = []
    seen_in_batch: set[str] = set()
    for item in raw_items:
        validated = _validate_query(item)
        if not validated:
            continue
        from db import _query_hash
        h = _query_hash(validated["query_str"])
        if h in forbidden or h in seen_in_batch:
            continue
        seen_in_batch.add(h)
        # Tag as CN shard so we can filter in /stats
        validated["theme"] = f"kaggle_cn_themer:{validated['theme'].split(':', 1)[-1]}"
        candidates.append(validated)

    if not candidates:
        log.warning("kaggle_cn_themer: 0 candidates survived dedup (raw=%d)", len(raw_items))
        return 0

    inserted = db.kaggle_register_queries(candidates)
    log.info("kaggle_cn_themer: inserted %d/%d queries (raw=%d) — source=%s",
             inserted, len(candidates), len(raw_items), source)
    return inserted
