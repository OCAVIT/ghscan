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
    "often hardcode real keys in code or output cells. "
    "PRIORITY PROVIDERS (generate MORE queries for these): OpenAI, Anthropic "
    "Claude, video-generation APIs (Kling, Pika, Runway, Seedance, Luma, "
    "Pixverse, Hedra, Wavespeed), audio (ElevenLabs), image-gen (Stability, "
    "fal.ai). DE-PRIORITIZE HuggingFace Hub tokens — they are already "
    "over-represented; generate AT MOST 2 HuggingFace queries per batch."
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
    feedback. Returns rows from kaggle_dynamic_queries — empty on first run.

    On master DB this only has data when mirror_yield_sync is running
    (MIRROR_URLS env set + master_api_token shared). Otherwise it falls
    back to an empty list and the prompt skips the positive-examples block."""
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


def _top_dead(limit: int = 15) -> list[dict]:
    """Pull confirmed-dead queries (>=3 uses, 0 kernels) so DS gets explicit
    negative examples in the prompt. Same caveat as _top_yielders: needs
    mirror_yield_sync to be populating master's DB."""
    try:
        return db.kaggle_get_dead_queries(min_uses=3, max_kernels=0, limit=limit)
    except Exception:
        return []


def _dead_queries_block(dead: list[dict]) -> str:
    """Format dead queries as a negative-examples section for the user
    prompt. Tells DS the patterns to avoid; without examples returns ""
    so the prompt template doesn't show an empty section."""
    if not dead:
        return ""
    bullets = "\n".join(
        f'  • "{q["query_str"][:90]}" (tried {q["times_used"]}× → 0 kernels)'
        for q in dead[:15]
    )
    return (
        "\n\nDEAD QUERIES — DO NOT GENERATE ANYTHING STRUCTURALLY SIMILAR. "
        "These queries were tried multiple times by scanner and returned ZERO "
        "kernels from Kaggle (either too narrow, no longer indexed, or the "
        "literal string never appears in notebook content):\n"
        + bullets
        + "\n\nLearn the PATTERN of what fails (e.g. very long compound queries, "
        "obscure variable names that don't show up in tutorials, model aliases "
        "that aren't actually used in code). Diversify away from these shapes."
    )


async def generate_kaggle_themed_batch(target_count: int = TARGET_QUERIES_PER_BATCH) -> int:
    """One batch of Kaggle creative queries via DeepSeek/GLM. Returns
    count of NEW rows inserted (15-day dedup enforced)."""
    forbidden = db.kaggle_get_recent_query_hashes(days=15)
    log.info("kaggle_themer: starting — %d hashes in 15-day window",
             len(forbidden))

    yielders = _top_yielders()
    dead = _top_dead()
    user_prompt = _build_user_prompt(target_count, yielders) + _dead_queries_block(dead)
    messages = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user",   "content": user_prompt},
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

    dead = _top_dead()
    messages = [
        {"role": "system", "content": _CN_SYSTEM_PROMPT},
        {"role": "user",   "content": _build_cn_prompt(target_count) + _dead_queries_block(dead)},
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


# ── Premium shard — OpenAI / Anthropic / Video-gen / Audio ───────────────────
# Focused exclusively on high-value commercial providers that are under-covered
# by the general themer. Separate LLM call so the 15-day dedup is independent
# from the main and CN shards — distinct lexical space, minimal hash collision.

_PREMIUM_SYSTEM_PROMPT = (
    "You generate Kaggle notebook search queries to find leaked API keys for "
    "high-value commercial AI providers. FREE-TEXT only (no operators). "
    "Focus EXCLUSIVELY on: OpenAI (gpt-4o, o3, o4-mini), Anthropic Claude "
    "(claude-3.5-sonnet, claude-4), video-generation (Kling, Pika, Runway ML, "
    "Seedance/ByteDance, Luma Dream Machine, Pixverse, Hedra, Higgsfield, "
    "Wavespeed), audio (ElevenLabs, PlayHT, Cartesia), image-gen (Stability AI, "
    "fal.ai FLUX, Ideogram, Recraft). "
    "Good queries: env-var literals (OPENAI_API_KEY, ANTHROPIC_API_KEY, "
    "ELEVENLABS_API_KEY, KLING_ACCESS_KEY), model name patterns (gpt-4o tutorial, "
    "claude chatbot langchain, runway gen-3 api), tutorial titles (openai "
    "assistants api notebook, anthropic claude agent python). "
    "Output JSON: {\"queries\": [{\"q\": \"...\", \"theme\": \"...\"}]}"
)


def _build_premium_prompt(target_count: int) -> str:
    return f"""\
Generate {target_count} Kaggle search queries targeting COMMERCIAL AI provider leaks.

PRIORITY PROVIDERS (cover all of them):
  OpenAI: OPENAI_API_KEY, gpt-4o, o3, o4-mini, openai assistants, openai realtime
  Anthropic: ANTHROPIC_API_KEY, claude-3.5-sonnet, claude-4, claude haiku tutorial
  ElevenLabs: ELEVENLABS_API_KEY, elevenlabs voice clone, tts api notebook
  Kling/Kuaishou: KLING_ACCESS_KEY, KLING_API_KEY, kling-v2, kling text-to-video
  Pika Labs: PIKA_API_KEY, pika video generation api python
  Runway ML: RUNWAYML_API_SECRET, runway gen-3 alpha, runway api tutorial
  Seedance/ByteDance: SEEDANCE_API_KEY, ARK_API_KEY, seedance video api
  Luma AI: LUMAAI_API_KEY, luma dream machine api, luma video generation
  Pixverse: PIXVERSE_API_KEY, pixverse text-to-video
  Hedra: HEDRA_API_KEY, hedra character video api
  Stability AI: STABILITY_API_KEY, stable diffusion xl api, stability sdxl
  fal.ai: FAL_KEY, fal flux api, fal ai image generation
  Cartesia / PlayHT / Suno: CARTESIA_API_KEY, PLAY_HT_API_KEY, SUNO_API_KEY

QUERY THEMES:
  1. Env-var literals: "OPENAI_API_KEY tutorial", "ANTHROPIC_API_KEY langchain"
  2. Model patterns: "gpt-4o chatbot python", "claude-3.5-sonnet rag notebook"
  3. Tutorial titles: "openai assistants api guide", "runway ml api integration"
  4. Video gen demos: "text to video api python notebook", "kling video generation tutorial"
  5. Audio demos: "elevenlabs tts python", "voice synthesis api notebook"
  6. Image gen demos: "stable diffusion sdxl api", "flux image generation fal"
  7. Multi-modal: "gpt-4o vision tutorial", "claude multimodal notebook"
  8. Agent frameworks + commercial key: "crewai openai", "autogen anthropic claude"

Output exactly {target_count} queries, free-text only, each under {_QUERY_LEN_CAP} chars.
JSON: {{"queries": [{{"q": "OPENAI_API_KEY langchain tutorial", "theme": "env_var"}}, ...]}}
"""


async def generate_kaggle_premium_batch(target_count: int = 30) -> int:
    """Premium shard: OpenAI/Anthropic/video-gen/audio Kaggle queries.
    Runs every 45min on master, 20min boot offset. Returns new rows inserted."""
    forbidden = db.kaggle_get_recent_query_hashes(days=15)
    log.info("kaggle_premium_themer: starting — %d hashes in 15-day window", len(forbidden))

    dead = _top_dead()
    messages = [
        {"role": "system", "content": _PREMIUM_SYSTEM_PROMPT},
        {"role": "user",   "content": _build_premium_prompt(target_count) + _dead_queries_block(dead)},
    ]

    text, source = await call_creative(
        messages,
        response_format={"type": "json_object"},
    )
    if not text:
        log.warning("kaggle_premium_themer: LLM returned no content (source=%s)", source)
        return 0

    raw_items = _parse_response(text)
    if not raw_items:
        log.warning("kaggle_premium_themer: failed to parse JSON: %s", text[:300])
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
        validated["theme"] = f"kaggle_premium:{validated['theme'].split(':', 1)[-1]}"
        candidates.append(validated)

    if not candidates:
        log.warning("kaggle_premium_themer: 0 candidates survived dedup (raw=%d)", len(raw_items))
        return 0

    inserted = db.kaggle_register_queries(candidates)
    log.info("kaggle_premium_themer: inserted %d/%d queries (raw=%d) — source=%s",
             inserted, len(candidates), len(raw_items), source)
    return inserted
