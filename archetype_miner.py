"""
Archetype miner — pattern-mine high-yield repos to generate queries
targeting structurally-similar repos.

Premise: leaks cluster. If one Vercel-deployed AI-startup template leaked
80 valid keys, similar templates probably do too. The signal is in:
README + framework signatures + topics + file structure + naming convention
of the repo.

Pipeline (every 24h):
  1. Pull top-10 repos with most validated keys in last 30 days
  2. Fetch evidence: README, package.json/requirements.txt/pyproject.toml,
     top-level file list, GitHub topics
  3. Pull a few "dead" repos that match scanner patterns but yielded 0
     keys — train DeepSeek to AVOID those archetypes
  4. Single DeepSeek call (effort=max, 1M context fits comfortably):
       "Identify 3-5 archetypes from these jackpot repos. For each, give
        6-10 GH search queries that would find structurally-similar repos."
  5. Insert queries into dynamic_queries with theme='archetype:NAME'
  6. Yield tracker observes per-archetype performance via the theme tag

No vector DB / no embedding API. DeepSeek's 1M context window holds all
evidence directly — vector retrieval would only matter at >100K repos.
Currently 5-15 high-yield repos per cycle = ~200KB evidence = ~50K tokens
of input.

Cost ~$0.10 per cycle × 30 days = ~$3/month.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
from typing import Any

import httpx

import db
from config import GITHUB_TOKENS
from deepseek_client import call_deepseek, extract_text
from query_axes import PROVIDER_AXES

log = logging.getLogger(__name__)


# How many top yielders to send DeepSeek per cycle. Empirically 8-12 is
# the sweet spot — fewer than 5 lacks pattern signal, more than 15 dilutes
# the prompt and DeepSeek starts repeating itself.
_TOP_YIELDERS = 12

# How many "dead pattern" examples to feed as anti-archetypes
_DEAD_EXAMPLES = 6

# Per-archetype query target — DeepSeek tends to overshoot this. We accept
# whatever it returns and validate length/syntax before insert.
_TARGET_QUERIES_PER_ARCHETYPE = 8

# GH evidence files to fetch per repo (in priority order — first that exists wins)
_EVIDENCE_FILES = (
    "README.md", "README.rst", "README.txt", "README",
    "package.json", "requirements.txt", "pyproject.toml",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "next.config.js", "vercel.json", "wrangler.toml", "fly.toml",
    "supabase/config.toml",
)
_EVIDENCE_BUDGET_PER_REPO = 4   # max files fetched per repo
_EVIDENCE_BUDGET_BYTES_PER_FILE = 8192   # truncate per-file content


# ── GH evidence fetcher ────────────────────────────────────────────────────

async def _fetch_evidence(client: httpx.AsyncClient, repo: str,
                          token: str) -> dict:
    """Fetch README + key config + topics + tree-snippet for one repo.
    Returns {readme, configs: [{path, content}], topics, tree_sample}."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept":        "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent":    "ghscan-archetype/1.0",
    }
    out: dict = {"repo": repo, "readme": "", "configs": [],
                  "topics": [], "tree_sample": []}

    # Topics
    try:
        r = await client.get(
            f"https://api.github.com/repos/{repo}/topics",
            headers={**headers, "Accept": "application/vnd.github.mercy-preview+json"},
            timeout=10,
        )
        if r.status_code == 200:
            out["topics"] = r.json().get("names", [])
    except Exception:
        pass

    # Top-level tree (just file/dir names, helps identify framework)
    try:
        r = await client.get(
            f"https://api.github.com/repos/{repo}/contents/",
            headers=headers, timeout=10,
        )
        if r.status_code == 200:
            for entry in r.json()[:30]:
                out["tree_sample"].append(entry.get("name", ""))
    except Exception:
        pass

    # README — try multiple variants, take first
    try:
        r = await client.get(
            f"https://api.github.com/repos/{repo}/readme",
            headers=headers, timeout=10,
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("encoding") == "base64":
                try:
                    out["readme"] = base64.b64decode(data.get("content", "")
                                                     ).decode("utf-8", "replace")[:_EVIDENCE_BUDGET_BYTES_PER_FILE]
                except Exception:
                    pass
    except Exception:
        pass

    # Config files (cap at _EVIDENCE_BUDGET_PER_REPO total fetches)
    fetched = 0
    for fname in _EVIDENCE_FILES:
        if fetched >= _EVIDENCE_BUDGET_PER_REPO:
            break
        if fname.startswith("README"):
            continue   # already got readme above
        try:
            r = await client.get(
                f"https://api.github.com/repos/{repo}/contents/{fname}",
                headers=headers, timeout=10,
            )
            if r.status_code != 200:
                continue
            data = r.json()
            if isinstance(data, list):   # directory listing — skip
                continue
            if data.get("encoding") == "base64":
                try:
                    content = base64.b64decode(data.get("content", "")
                                               ).decode("utf-8", "replace")[:_EVIDENCE_BUDGET_BYTES_PER_FILE]
                    out["configs"].append({"path": fname, "content": content})
                    fetched += 1
                except Exception:
                    pass
        except Exception:
            pass

    return out


# ── Prompt construction ────────────────────────────────────────────────────

_SYSTEM_PROMPT = (
    "You analyze leaked AI-credential repositories to find structural "
    "patterns (archetypes), then produce GitHub Code Search queries that "
    "would surface MORE repos of the same archetype.\n\n"
    "An archetype is identified by combination of: framework SDK imports "
    "(e.g. langchain, llamaindex, vercel/ai), domain language (chatbot / "
    "agentic / RAG / saas-template / hackathon-starter), file structure, "
    "topic tags, and naming convention. Two repos are 'same archetype' if "
    "their READMEs would substitute for each other.\n\n"
    "Output queries that use GH search syntax (filename:, language:, path:, "
    "size:, pushed:>YYYY-MM-DD, extension:, quoted-strings) and would "
    "TARGET this archetype precisely. Each query under 240 chars. "
    "Avoid revoked-by-secret-scanning patterns (raw sk-ant-, raw AIzaSy "
    "without filename anchor)."
)


def _build_user_prompt(yielders: list[dict], dead: list[dict],
                       today_iso: str) -> str:
    parts = [
        f"Today: {today_iso}",
        "",
        f"=== JACKPOT REPOS (total {len(yielders)}) ===",
        "These repos leaked LIVE AI-provider keys. Pattern-match them.",
    ]
    for i, y in enumerate(yielders, 1):
        parts.append(f"\n--- #{i}  {y['repo']}  ({y['valid_keys']} valid keys, providers: {y['providers']}) ---")
        ev = y.get("evidence") or {}
        if ev.get("topics"):
            parts.append(f"topics: {ev['topics'][:15]}")
        if ev.get("tree_sample"):
            parts.append(f"top-level: {ev['tree_sample'][:25]}")
        if ev.get("readme"):
            parts.append("README excerpt:")
            parts.append(ev["readme"][:3500])
        for cfg in (ev.get("configs") or [])[:3]:
            parts.append(f"\n[config] {cfg['path']}:")
            parts.append(cfg["content"][:1500])

    if dead:
        parts.append(f"\n\n=== ANTI-ARCHETYPES ({len(dead)} dead repos) ===")
        parts.append("These repos LOOK like AI projects but yielded 0 valid keys. "
                     "DON'T target their archetypes.")
        for i, d in enumerate(dead, 1):
            parts.append(f"\n--- DEAD #{i}  {d['repo']} ---")
            ev = d.get("evidence") or {}
            if ev.get("topics"):
                parts.append(f"topics: {ev['topics'][:10]}")
            if ev.get("readme"):
                parts.append(ev["readme"][:1500])

    parts.extend([
        "",
        "=== TASK ===",
        "1. Identify 3-5 distinct ARCHETYPES from the JACKPOT repos.",
        "   Each archetype has: a short slug-name (e.g. 'n8n-ai-workflows'),",
        f"   1-line description, and {_TARGET_QUERIES_PER_ARCHETYPE} GH search queries.",
        "2. Queries must surface MORE repos of that archetype but NOT match",
        "   the anti-archetypes.",
        "3. Use diverse anchors: distinctive imports, framework strings, "
        "topic combos, distinctive file paths/names, niche env-var names.",
        "",
        "Return ONLY this JSON shape (no prose, no fences):",
        "{",
        '  "archetypes": [',
        "    {",
        '      "name": "slug-name",',
        '      "description": "one-line",',
        '      "signatures": ["distinctive token", ...],',
        '      "queries": [',
        '        {"q": "...", "provider": "openai|...|multi", "file_type": "env|config|notebook|code"}',
        "      ]",
        "    }",
        "  ]",
        "}",
    ])
    return "\n".join(parts)


# ── Output validation ──────────────────────────────────────────────────────

_VALID_FILE_TYPES = {"env", "config", "notebook", "docker", "ci", "code", "sa_json"}
_VALID_PROVIDERS = set(PROVIDER_AXES.keys()) | {"multi", "google", "gemini"}
_QUERY_LEN_CAP = 240


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
    archs = data.get("archetypes", [])
    if not isinstance(archs, list):
        return []
    return [a for a in archs if isinstance(a, dict)]


def _flatten_archetypes_to_queries(archetypes: list[dict]) -> list[dict]:
    """Flatten {archetypes: [{name, queries: [...]}]} into a flat list of
    candidates ready for db.register_dynamic_queries."""
    out: list[dict] = []
    for arch in archetypes:
        name = (arch.get("name") or "").strip()[:60] or "unnamed"
        for qd in (arch.get("queries") or []):
            if not isinstance(qd, dict):
                continue
            q = (qd.get("q") or "").strip()
            if not q or len(q) > _QUERY_LEN_CAP:
                continue
            if not re.search(
                r"\b(?:filename|language|path|extension|pushed|created|size|fork|stars|in|topic):", q,
            ) and '"' not in q:
                continue
            provider = (qd.get("provider") or "multi").strip().lower().split(",")[0]
            if provider in ("gemini", "veo"):
                provider = "google"
            if provider not in _VALID_PROVIDERS:
                provider = "multi"
            file_type = (qd.get("file_type") or "code").strip().lower()
            if file_type not in _VALID_FILE_TYPES:
                file_type = "code"
            out.append({
                "query_str": q,
                "provider":  provider,
                "file_type": file_type,
                "theme":     f"archetype:{name}",
            })
    return out


# ── Main entry point ──────────────────────────────────────────────────────

async def run_archetype_cycle() -> dict:
    """One full archetype-mining cycle. Returns counters."""
    if not GITHUB_TOKENS:
        log.warning("archetype_miner: no GITHUB_TOKENS — skipping")
        return {"error": "no_github_tokens"}

    yielders = db.get_top_yielding_repos(days=30, min_valid_keys=3,
                                          limit=_TOP_YIELDERS)
    if len(yielders) < 3:
        log.info("archetype_miner: only %d high-yield repos in last 30d "
                 "(need >=3) — skipping cycle", len(yielders))
        return {"error": "not_enough_yielders", "count": len(yielders)}

    # Fetch GH evidence for each
    gh_token = GITHUB_TOKENS[0]
    async with httpx.AsyncClient(follow_redirects=True) as c:
        sem = asyncio.Semaphore(5)

        async def _bound_fetch(repo: str) -> dict:
            async with sem:
                return await _fetch_evidence(c, repo, gh_token)

        evidence_list = await asyncio.gather(
            *(_bound_fetch(y["repo"]) for y in yielders),
            return_exceptions=True,
        )
        for y, ev in zip(yielders, evidence_list):
            if isinstance(ev, Exception):
                y["evidence"] = {}
            else:
                y["evidence"] = ev

    # Pull dead-pattern examples — from blacklisted dynamic_queries
    dead_query_rows: list[dict] = []
    for prov in list(PROVIDER_AXES.keys())[:10]:
        for r in db.get_dead_queries(prov, limit=2):
            dead_query_rows.append({"repo": "(dead-pattern)", "evidence": {
                "readme": f"Query: {r['query_str']} (used {r['times_used']}x, 0 yield)",
                "topics": [], "tree_sample": [],
            }})
        if len(dead_query_rows) >= _DEAD_EXAMPLES:
            break

    from datetime import datetime as _dt, timezone as _tz
    today = _dt.now(_tz.utc).date().isoformat()

    messages = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user",
         "content": _build_user_prompt(yielders, dead_query_rows[:_DEAD_EXAMPLES], today)},
    ]

    log.info("archetype_miner: calling DeepSeek with %d yielders + %d dead-examples",
             len(yielders), len(dead_query_rows))

    response = await call_deepseek(
        messages,
        response_format={"type": "json_object"},
        reasoning_effort="max",
    )
    text = extract_text(response)
    if not text:
        return {"error": "deepseek_empty"}

    archetypes = _parse_response(text)
    if not archetypes:
        log.warning("archetype_miner: failed to parse DeepSeek output: %s", text[:300])
        return {"error": "parse_failed", "raw": text[:200]}

    candidates = _flatten_archetypes_to_queries(archetypes)
    if not candidates:
        return {"error": "no_valid_queries", "archetype_count": len(archetypes)}

    # Dedup against 15-day window
    forbidden = db.get_recent_query_hashes(days=15)
    from db import _query_hash
    fresh = []
    for c in candidates:
        h = _query_hash(c["query_str"])
        if h not in forbidden:
            fresh.append(c)

    inserted = db.register_dynamic_queries(fresh)
    archetype_summary = [
        {"name": a.get("name", "?")[:40],
         "queries_proposed": len(a.get("queries") or [])}
        for a in archetypes
    ]
    log.info("archetype_miner done: %d archetypes, %d candidates, %d inserted",
             len(archetypes), len(candidates), inserted)
    return {
        "archetype_count":  len(archetypes),
        "queries_proposed": len(candidates),
        "queries_inserted": inserted,
        "archetypes":       archetype_summary,
        "yielders_used":    [y["repo"] for y in yielders],
        "usage":            (response.get("usage") if response else {}) or {},
    }
