"""
Core scanner — parallel worker architecture.

With N GitHub PATs we run N concurrent query-workers simultaneously:
  - Each worker owns an exclusive slice of QUERIES (round-robin partition)
  - Each worker uses its own token → full 30 req/min per worker
  - Total throughput: 30 × N req/min (linear scaling with token count)
  - Item processing is bounded by shared asyncio.Semaphore (CONCURRENT_ITEMS)
  - httpx connection pool sized for high parallelism (500 connections)

Example with 6 tokens + 110 queries:
  - 6 workers × ~18 queries × 5 pages = ~90 search reqs per worker
  - 90 / 30 req/min = 3 minutes per full cycle (all workers in parallel)
  vs ~18 minutes sequential with 1 token

BUG FIX (vs v1): query strings no longer include "q=" prefix or "&sort=..."
suffix — those were URL-encoded into the q param causing malformed requests.
"""

import asyncio
import base64
import logging
from datetime import datetime, timezone

import httpx

import db
from config import (
    GITHUB_TOKENS, YOUNG_REPO_DAYS, BIG_SERVICE_STARS,
    CONCURRENT_ITEMS, MAX_PAGES,
)
from patterns import QUERIES, EXTRACTORS, is_skippable_path
from infra_patterns import INFRA_QUERIES, INFRA_EXTRACTORS, INFRA_PROVIDERS, assess_risk, extract_destination
from validators import validate
from notifier import notify_found, notify_cycle_done, notify_infra_found

# Merge AI-key queries + infra queries into one pool; workers partition both
ALL_QUERIES = QUERIES + INFRA_QUERIES
ALL_EXTRACTORS = {**EXTRACTORS, **INFRA_EXTRACTORS}

log = logging.getLogger(__name__)

_BASE = "https://api.github.com"

# httpx pool — 500 connections for high parallelism across 24 vCPU
_LIMITS = httpx.Limits(
    max_connections=500,
    max_keepalive_connections=150,
    keepalive_expiry=30,
)

# Realistic browser User-Agent — python-httpx/x.y is an obvious bot signal.
# GitHub doesn't block on UA alone, but it's a free OpSec improvement.
_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


# ── GitHub auth helpers ────────────────────────────────────────────────────

def _gh_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": _USER_AGENT,
    }


# ── GitHub API primitives ──────────────────────────────────────────────────

async def _gh_get(client: httpx.AsyncClient, url: str,
                  params: dict | None = None, headers: dict | None = None) -> dict | list | None:
    for attempt in range(4):
        try:
            r = await client.get(url, headers=headers, params=params, timeout=20)

            if r.status_code == 403:
                # Primary rate-limit: X-RateLimit-Reset tells us exactly when to retry.
                # Don't sleep a flat 10 minutes — read the header (usually 60-90s).
                reset = int(r.headers.get("X-RateLimit-Reset", 0))
                now   = int(datetime.now(timezone.utc).timestamp())
                wait  = max(reset - now, 5)
                wait  = min(wait, 90)  # cap at 90s — never need more
                log.warning("rate-limited (403) on %s, sleeping %ds (reset=%s)",
                            url.split("/")[-1], wait, reset)
                await asyncio.sleep(wait)
                continue

            if r.status_code == 429:
                # Secondary rate-limit (undocumented concurrency limit).
                # Exponential backoff: 10s, 20s, 40s — then give up.
                wait = 10 * (2 ** attempt)
                log.warning("secondary rate-limit (429), backoff %ds", wait)
                await asyncio.sleep(wait)
                continue

            if r.status_code in (422, 404):
                return None

            r.raise_for_status()
            return r.json()

        except httpx.TimeoutException:
            wait = 5 * (2 ** attempt)  # exponential: 5, 10, 20, 40s
            await asyncio.sleep(wait)
        except Exception as e:
            log.debug("gh_get err: %s", e)
            await asyncio.sleep(3)
    return None


async def _check_search_quota(client: httpx.AsyncClient, token_headers: dict) -> int:
    """
    Returns remaining search requests for this token via /rate_limit.
    This endpoint is NOT counted against the quota (GitHub documented behaviour).
    Returns -1 on failure (treat as quota available).
    """
    try:
        r = await client.get(
            f"{_BASE}/rate_limit",
            headers=token_headers,
            timeout=10,
        )
        if r.status_code == 200:
            data = r.json()
            remaining = data["resources"]["search"]["remaining"]
            reset_at  = data["resources"]["search"]["reset"]
            log.debug("search quota: %d remaining (reset %s)", remaining, reset_at)
            return remaining
    except Exception:
        pass
    return -1


async def search_code(client: httpx.AsyncClient, query: str,
                      page: int, token_headers: dict) -> list[dict]:
    data = await _gh_get(
        client, f"{_BASE}/search/code",
        params={"q": query, "sort": "indexed", "order": "desc",
                "per_page": 100, "page": page},
        headers=token_headers,
    )
    return (data or {}).get("items", [])


async def get_repo_meta(client: httpx.AsyncClient, full_name: str,
                        token_headers: dict) -> dict | None:
    return await _gh_get(client, f"{_BASE}/repos/{full_name}", headers=token_headers)


async def get_file_content(client: httpx.AsyncClient, url: str,
                           token_headers: dict) -> str | None:
    data = await _gh_get(client, url, headers=token_headers)
    if not data:
        return None
    enc = data.get("encoding", "")
    raw = data.get("content", "")
    if enc == "base64":
        try:
            return base64.b64decode(raw).decode("utf-8", errors="replace")
        except Exception:
            return None
    return raw or None


# ── Repo age / stars filter ────────────────────────────────────────────────

def _passes_filter(stars: int, created_at: str) -> bool:
    try:
        dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        age_ok = (datetime.now(timezone.utc) - dt).days <= YOUNG_REPO_DAYS
    except Exception:
        age_ok = False
    return age_ok or stars >= BIG_SERVICE_STARS


# ── Item processing (semaphore-bounded) ────────────────────────────────────

async def process_item(client: httpx.AsyncClient, item: dict,
                       provider: str, file_type: str,
                       sem: asyncio.Semaphore, token_headers: dict):
    async with sem:
        await _process_inner(client, item, provider, file_type, token_headers)


async def _process_inner(client: httpx.AsyncClient, item: dict,
                         provider: str, file_type: str, token_headers: dict):
    repo_info   = item.get("repository", {})
    full_name   = repo_info.get("full_name", "")
    file_path   = item.get("path", "")
    sha         = item.get("sha", "")
    file_url    = item.get("html_url", "")
    content_url = item.get("url", "")

    if not full_name or not sha:
        return

    # Atomic claim — if another worker already took this SHA, skip immediately.
    # try_claim_file() does INSERT OR IGNORE and returns True only for the first caller.
    # This replaces the old two-step is_file_scanned + mark_file_scanned which
    # had a TOCTOU race under parallel workers.
    if is_skippable_path(file_path):
        db.try_claim_file(sha)  # mark it even for trash paths so we don't revisit
        return
    if not db.try_claim_file(sha):
        return  # another worker claimed it first — skip

    # Repo meta — age/stars gate
    if db.should_scan_repo(full_name):
        meta = await get_repo_meta(client, full_name, token_headers)
        if not meta:
            return
        stars      = meta.get("stargazers_count", 0)
        created_at = meta.get("created_at", "")
        db.mark_repo_scanned(full_name, stars, created_at)
        if not _passes_filter(stars, created_at):
            return  # SHA already claimed above — no need to mark again
    else:
        cached = db.get_repo_cached(full_name)
        if cached:
            stars, created_at = cached
            if not _passes_filter(stars, created_at):
                return
        else:
            stars, created_at = 0, ""

    content = await get_file_content(client, content_url, token_headers)
    if not content:
        return

    extractor = ALL_EXTRACTORS.get(provider)
    if not extractor:
        return
    creds = extractor(content)
    if not creds:
        return

    if provider in INFRA_PROVIDERS:
        # ── Infrastructure credential branch ──────────────────────────────
        risk_level, risk_reasons = assess_risk(content, file_path, stars, created_at)
        for cred in creds:
            if db.infra_exists(cred):
                continue
            destination = extract_destination(cred) if "://" in cred else ""
            saved = db.save_infra(
                provider, cred, full_name, file_path, file_url,
                stars, created_at, file_type, destination,
                risk_level, risk_reasons,
            )
            if saved:
                await notify_infra_found(
                    provider, cred, full_name, file_path, file_url,
                    stars, created_at, file_type,
                    destination, risk_level, risk_reasons,
                )
                log.info("[infra/%s] risk=%s dest=%s repo=%s",
                         provider, risk_level, destination or "—", full_name)
    else:
        # ── AI provider key branch ────────────────────────────────────────
        for key in creds:
            if db.key_exists(key):
                continue
            is_valid = await validate(provider, key)
            saved = db.save_key(
                provider, key, full_name, file_path, file_url,
                stars, created_at, file_type, is_valid,
            )
            if saved:
                await notify_found(
                    provider, key, full_name, file_path, file_url,
                    stars, created_at, file_type, is_valid,
                )
                log.info("[%s] %s from %s",
                         "VALID" if is_valid else "found", provider, full_name)


# ── Per-token worker ────────────────────────────────────────────────────────

async def _run_chunk(client: httpx.AsyncClient,
                     queries: list[tuple], token: str,
                     sem: asyncio.Semaphore, worker_id: int):
    """
    Processes an exclusive slice of QUERIES using a single token.
    Maintains 2s inter-query sleep → stays within 30 req/min per token.
    """
    hdrs = _gh_headers(token)
    log.info("[w%d token=%s...] handling %d queries", worker_id, token[:8], len(queries))

    queries_done = 0

    for query_str, provider, file_type in queries:
        # Check search quota every 10 queries via /rate_limit (free endpoint).
        # If < 5 requests left, sleep until reset to avoid wasting 403 round-trips.
        if queries_done % 10 == 0:
            remaining = await _check_search_quota(client, hdrs)
            if remaining == 0:
                log.warning("[w%d] search quota exhausted, sleeping 65s", worker_id)
                await asyncio.sleep(65)
            elif 0 < remaining < 5:
                log.warning("[w%d] search quota low (%d), sleeping 30s", worker_id, remaining)
                await asyncio.sleep(30)

        for page in range(1, MAX_PAGES + 1):
            try:
                items = await search_code(client, query_str, page, hdrs)
            except Exception as e:
                log.error("[w%d] search err: %s", worker_id, e)
                break

            if not items:
                break

            tasks = [
                asyncio.create_task(
                    process_item(client, item, provider, file_type, sem, hdrs)
                )
                for item in items
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for exc in results:
                if isinstance(exc, Exception):
                    log.debug("[w%d] item err: %s", worker_id, exc)

            if len(items) < 100:
                break

            await asyncio.sleep(2)  # between pages — secondary rate-limit buffer

        queries_done += 1
        await asyncio.sleep(2)  # between queries — keeps token at ≤30 req/min


# ── Main cycle ─────────────────────────────────────────────────────────────

async def run_cycle():
    n = len(GITHUB_TOKENS)
    chunks: list[list] = [[] for _ in range(n)]
    for i, q in enumerate(ALL_QUERIES):
        chunks[i % n].append(q)

    log.info(
        "=== scan cycle start | %d tokens | %d queries (%d AI + %d infra) → %s chunks | "
        "%d concurrent items | max %d pages ===",
        n, len(ALL_QUERIES), len(QUERIES), len(INFRA_QUERIES),
        [len(c) for c in chunks], CONCURRENT_ITEMS, MAX_PAGES,
    )

    sem = asyncio.Semaphore(CONCURRENT_ITEMS)

    async with httpx.AsyncClient(follow_redirects=True, limits=_LIMITS) as client:
        workers = [
            asyncio.create_task(_run_chunk(client, chunks[i], GITHUB_TOKENS[i], sem, i))
            for i in range(n)
        ]
        results = await asyncio.gather(*workers, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                log.error("worker crashed: %s", r)

    stats = db.get_stats()
    log.info("=== cycle done: %s ===", stats)
    await notify_cycle_done(stats)
