"""
Active learning yield refinement — generates tactical follow-up queries
based on the LATEST cycle's observations, not stale 8h-old aggregates.

Why: themer runs every 8h. By then trends have shifted (new model name went
viral, Chinese aggregator launched, hackathon weekend started). Active learner
fires every 30 min, reads last cycle's stats + last 100 finds, generates 5-10
SHARP tactical queries — fast adaptation to emerging patterns.

Quality model required: this is creative generation, not classification.
Uses call_creative() = deepseek-v4-pro reasoning_effort=max with GLM-5.1 fallback.

Cost: 1 LLM call / 30 min = 48/day × $0.005-0.015 = $0.25-0.75/day
On our pool of 44 deepseek + 292 glm valid keys: $0/day.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone, timedelta

import db
from llm_client import call_creative
from query_axes import PROVIDER_AXES, DEPRIORITIZED_PROVIDERS

log = logging.getLogger(__name__)


_QUERY_LEN_CAP = 240
_TARGET_QUERIES_PER_RUN = 10


_SYSTEM_PROMPT = (
    "You generate REACTIVE GitHub Code Search queries for AI-key recovery, "
    "based on the LATEST 30-min cycle observations. Goal: catch trending leak "
    "patterns before they auto-revoke (24h SS Partner window).\n\n"
    "Output JSON only:\n"
    '{"queries":[{"q":"...","provider":"openai|...|multi","file_type":"env|config|notebook|code","theme":"reactive,..."}]}\n\n'
    "Each query: <240 chars, GitHub search syntax, MUST quote env-var names."
)


def _build_user_prompt(cycle_stats: dict, recent_finds: list[dict]) -> str:
    today = datetime.now(timezone.utc).date().isoformat()
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).date().isoformat()

    parts = [
        f"Today: {today}",
        f"Last cycle stats: {json.dumps(cycle_stats, ensure_ascii=False)[:1500]}",
        "",
        "RECENT FINDS (last 100, latest first):",
    ]
    for f in recent_finds[:50]:
        parts.append(
            f"  [{f['provider']}/{f.get('file_type','?')}] {f.get('repo','')[:60]} "
            f"{f.get('file_path','')[:60]} valid={f.get('is_valid',0)}"
        )

    parts.extend([
        "",
        "TASK:",
        f"Generate {_TARGET_QUERIES_PER_RUN} TACTICAL queries that:",
        f"1. Target patterns visible in recent finds — same providers/file_types "
        f"   that just produced valid keys. Hit them harder (different angles).",
        "2. Include 3-5 PRE-REVOKE RACE queries with `pushed:>"
        + yesterday + "` for SS Partner providers (openai/anthropic/google/"
        "perplexity/huggingface).",
        "3. NO queries for: serper, firecrawl (deprioritized tools).",
        "4. AVOID duplicating queries that just ran (those in cycle_stats).",
        "",
        "Bias: high-precision (<1000 results), recent push, niche file types "
        "from recent finds, model names mentioned in recent finds.",
    ])

    return "\n".join(parts)


_VALID_FILE_TYPES = {"env", "config", "notebook", "docker", "ci", "code", "sa_json"}
_VALID_PROVIDERS = set(PROVIDER_AXES.keys()) | {"multi", "google", "gemini"}


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


def _validate_queries(raw: list[dict]) -> list[dict]:
    """Validate + sanitize queries from LLM output. Returns list ready for
    db.register_dynamic_queries."""
    out: list[dict] = []
    seen_qs: set[str] = set()
    for qd in raw:
        q = (qd.get("q") or "").strip()
        if not q or len(q) > _QUERY_LEN_CAP:
            continue
        if q in seen_qs:
            continue
        if not re.search(
            r"\b(?:filename|language|path|extension|pushed|created|size|fork|stars|in|topic):", q,
        ) and '"' not in q:
            continue
        provider = (qd.get("provider") or "multi").strip().lower().split(",")[0]
        if provider in ("gemini", "veo"):
            provider = "google"
        if provider in DEPRIORITIZED_PROVIDERS:
            provider = "multi"
        if provider not in _VALID_PROVIDERS:
            provider = "multi"
        file_type = (qd.get("file_type") or "code").strip().lower()
        if file_type not in _VALID_FILE_TYPES:
            file_type = "code"
        seen_qs.add(q)
        out.append({
            "query_str": q,
            "provider":  provider,
            "file_type": file_type,
            "theme":     "active_learner:" + (qd.get("theme") or "reactive")[:50],
        })
    return out


async def run_active_learning() -> dict:
    """Single active-learning pass. Returns summary {generated, inserted,
    source}. Called by background loop in main.py every 30 min."""
    # Pull last 100 finds with timestamps to feed LLM
    recent: list[dict] = []
    try:
        with db._conn() as c:
            rows = c.execute(
                """SELECT provider, repo, file_path, file_type, is_valid, discovered_at
                   FROM found_keys
                   ORDER BY discovered_at DESC
                   LIMIT 100"""
            ).fetchall()
            recent = [dict(r) for r in rows]
    except Exception as e:
        log.error("active_learner: recent-finds fetch failed: %s", e)
        return {"error": str(e)[:100]}

    # Last cycle stats — query yields, blacklist count, etc
    cycle_stats: dict = {
        "recent_find_count": len(recent),
    }
    try:
        # Top providers in last 100 finds
        prov_count: dict[str, int] = {}
        valid_count: dict[str, int] = {}
        for r in recent:
            p = r["provider"]
            prov_count[p] = prov_count.get(p, 0) + 1
            if r["is_valid"]:
                valid_count[p] = valid_count.get(p, 0) + 1
        cycle_stats["top_providers"] = sorted(
            prov_count.items(), key=lambda x: -x[1])[:10]
        cycle_stats["top_valid"] = sorted(
            valid_count.items(), key=lambda x: -x[1])[:10]
    except Exception:
        pass

    user_msg = _build_user_prompt(cycle_stats, recent)

    log.info("active_learner: calling LLM (recent=%d finds, top_provs=%s)",
             len(recent), cycle_stats.get("top_providers", [])[:3])

    text, source = await call_creative(
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user",   "content": user_msg},
        ],
        response_format={"type": "json_object"},
        timeout=600,
    )

    if not text:
        log.warning("active_learner: both DeepSeek and GLM unavailable — skipping")
        return {"generated": 0, "inserted": 0, "source": source}

    raw = _parse_response(text)
    queries = _validate_queries(raw)

    inserted = 0
    if queries:
        try:
            inserted = db.register_dynamic_queries(queries)
        except Exception as e:
            log.error("active_learner: register failed: %s", e)

    log.info("active_learner: source=%s generated=%d valid=%d inserted=%d",
             source, len(raw), len(queries), inserted)
    return {
        "generated": len(raw),
        "validated": len(queries),
        "inserted":  inserted,
        "source":    source,
    }
