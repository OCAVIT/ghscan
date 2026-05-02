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
import hashlib
import logging
import random
from datetime import datetime, timezone

import httpx

import db
from config import (
    GITHUB_TOKENS, YOUNG_REPO_DAYS, BIG_SERVICE_STARS,
    CONCURRENT_ITEMS, MAX_PAGES,
)
from patterns import QUERIES, EXTRACTORS, is_skippable_path
from infra_patterns import INFRA_EXTRACTORS, assess_risk, extract_destination
from validators import validate, INFRA_VALIDATORS
from notifier import notify_found, notify_cycle_done, notify_infra_found, notify_dead_token

# Intersecting track: AI queries are the search vector; infra extractors run
# on the same files. This guarantees infra creds come only from AI-related repos.
ALL_QUERIES = QUERIES

log = logging.getLogger(__name__)

# ── Token health tracking ──────────────────────────────────────────────────────
# Updated by _check_quota; read by /health endpoint and dead-token alert.
# Key: sha256(token)[:12] — avoids collision when multiple PATs share the same 8-char prefix
# (e.g. two tokens from the same GH account: ghp_AbCdEfGh... vs ghp_AbCdEfGi...).
# Fields: alive, remaining (search), reset_at (search), limit (search),
#         core_remaining, core_reset, core_limit,
#         core_blocked_until — unix timestamp; if now < this, every request on
#                              this token is short-circuited to a sleep instead
#                              of spamming GitHub with guaranteed-403 retries.
_TOKEN_STATUS: dict[str, dict] = {}
_DEAD_ALERTED: set[str] = set()      # tokens already alerted this session (avoid spam)

# Strong-reference set for background infra-validation tasks.
# asyncio may GC a task if no reference is held; keeping tasks here prevents that.
_BG_TASKS: set[asyncio.Task] = set()


def _tkey(token: str) -> str:
    """Collision-safe token key: sha256[:12] instead of raw prefix slice."""
    return hashlib.sha256(token.encode()).hexdigest()[:12]

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
# Caps: PRIMARY rate-limit reset can be up to ~60 min away (core REST 5000/hr).
# SECONDARY (concurrent abuse) Retry-After is usually 60-300 s.
_PRIMARY_WAIT_CAP   = 1800  # 30 min — honor X-RateLimit-Reset up to this
_SECONDARY_WAIT_CAP = 300


def _token_from_headers(headers: dict | None) -> str:
    if not headers:
        return ""
    auth = headers.get("Authorization", "") or ""
    return auth.removeprefix("Bearer ").strip()


async def _await_token_unblock(token: str) -> None:
    """If this token is in a primary-rate-limit window, sleep until reset
    BEFORE sending the request. Avoids spamming GitHub with guaranteed-403s
    from 50+ concurrent tasks, all of which would otherwise sleep
    independently and burst again together at wakeup."""
    if not token:
        return
    tk = _tkey(token)
    blocked = _TOKEN_STATUS.get(tk, {}).get("core_blocked_until", 0)
    if not blocked:
        return
    now = int(datetime.now(timezone.utc).timestamp())
    if now >= blocked:
        # Window expired — clear flag (race-safe: setdefault then overwrite)
        _TOKEN_STATUS.setdefault(tk, {})["core_blocked_until"] = 0
        return
    # Sleep until reset + jitter(0-30s) so 50 simultaneous wakers don't burst
    wait = (blocked - now) + 5 + random.uniform(0, 30)
    wait = min(wait, _PRIMARY_WAIT_CAP)
    log.debug("token %s pre-blocked, sleeping %.0fs until reset", tk, wait)
    await asyncio.sleep(wait)
    _TOKEN_STATUS.setdefault(tk, {})["core_blocked_until"] = 0


async def _gh_get(client: httpx.AsyncClient, url: str,
                  params: dict | None = None, headers: dict | None = None) -> dict | list | None:
    token = _token_from_headers(headers)
    await _await_token_unblock(token)

    for attempt in range(4):
        try:
            r = await client.get(url, headers=headers, params=params, timeout=20)

            if r.status_code == 403:
                # Distinguish primary (quota) vs secondary (concurrent abuse) rate-limit:
                #   primary   → X-RateLimit-Remaining=0 + X-RateLimit-Reset=<unix>
                #   secondary → Retry-After=<seconds> (concurrent / abuse detection)
                retry_after = r.headers.get("Retry-After")
                reset       = int(r.headers.get("X-RateLimit-Reset", "0") or 0)
                remaining   = int(r.headers.get("X-RateLimit-Remaining", "-1") or -1)

                if retry_after:
                    wait = min(int(retry_after), _SECONDARY_WAIT_CAP)
                    log.warning("secondary 403 on %s, Retry-After=%ds",
                                url.rsplit("/", 1)[-1][:40], wait)
                elif remaining == 0 and reset > 0:
                    now  = int(datetime.now(timezone.utc).timestamp())
                    wait = max(reset - now, 5) + 5  # safety margin
                    wait = min(wait, _PRIMARY_WAIT_CAP)
                    if token:
                        # Mark token globally blocked so all 50+ concurrent tasks
                        # see this and sleep ONCE in _await_token_unblock instead
                        # of each one independently sleeping 90s and re-bursting.
                        _TOKEN_STATUS.setdefault(_tkey(token), {})["core_blocked_until"] = reset
                    log.warning(
                        "primary 403 on %s, sleeping %ds until reset (token-wide block set)",
                        url.rsplit("/", 1)[-1][:40], wait,
                    )
                    # Add jitter so the wakeup doesn't burst
                    wait += random.uniform(0, 30)
                else:
                    # 403 with no rate-limit headers — likely auth / SSO issue
                    wait = 30
                    log.warning("403 (no rate-limit headers) on %s, sleeping %ds",
                                url.rsplit("/", 1)[-1][:40], wait)
                await asyncio.sleep(wait)
                continue

            if r.status_code == 429:
                # Honor server-provided Retry-After if present; otherwise exp backoff
                retry_after = r.headers.get("Retry-After")
                if retry_after:
                    wait = min(int(retry_after), _SECONDARY_WAIT_CAP)
                else:
                    wait = 10 * (2 ** attempt)
                log.warning("429 on %s, sleeping %ds", url.rsplit("/", 1)[-1][:40], wait)
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


async def _check_quota(client: httpx.AsyncClient, token_headers: dict,
                       token: str = "") -> tuple[int, int]:
    """
    Returns (search_remaining, core_remaining) for this token via /rate_limit.
    /rate_limit is NOT counted against the quota (GitHub documented behaviour).

    Sentinels:
      ( -2, -2)  → dead token (401)
      ( -1, -1)  → check failed (treat as quota available)

    Updates _TOKEN_STATUS for /health endpoint and for the pre-block check
    in _await_token_unblock (preserves any existing core_blocked_until).
    """
    raw  = token or token_headers.get("Authorization", "").removeprefix("Bearer ").strip()
    tk   = _tkey(raw)
    try:
        r = await client.get(f"{_BASE}/rate_limit", headers=token_headers, timeout=10)
        if r.status_code == 401:
            _TOKEN_STATUS[tk] = {
                "alive": False, "remaining": 0, "reset_at": 0, "limit": 0,
                "core_remaining": 0, "core_reset": 0, "core_limit": 0,
                "core_blocked_until": 0,
            }
            return -2, -2
        if r.status_code == 200:
            data = r.json()
            s    = data["resources"]["search"]
            c    = data["resources"]["core"]
            prev_block = _TOKEN_STATUS.get(tk, {}).get("core_blocked_until", 0)
            _TOKEN_STATUS[tk] = {
                "alive": True,
                "remaining":      s["remaining"],
                "reset_at":       s["reset"],
                "limit":          s.get("limit", 30),
                "core_remaining": c["remaining"],
                "core_reset":     c["reset"],
                "core_limit":     c.get("limit", 5000),
                "core_blocked_until": prev_block,
            }
            log.debug("quota [%s]: search=%d core=%d", tk, s["remaining"], c["remaining"])
            return s["remaining"], c["remaining"]
    except Exception:
        pass
    return -1, -1


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


async def _validate_infra_bg(infra_prov: str, cred: str, cred_hash: str):
    """Background infra validation — updates DB without blocking the scan."""
    fn = INFRA_VALIDATORS.get(infra_prov)
    if fn is None:
        return
    try:
        result = await fn(cred)
        db.update_infra_validation(cred_hash, 1 if result else 0,
                                   "ok" if result else "unreachable")
        if result:
            log.info("[infra/%s] VALIDATED %s...", infra_prov, cred[:30])
    except Exception as e:
        log.debug("infra validate bg err (%s): %s", infra_prov, e)


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

    # claim first: atomic INSERT OR IGNORE — skippable paths also get claimed
    # so we never revisit them (avoids re-fetch on next cycle)
    if not db.try_claim_file(sha):
        return
    if is_skippable_path(file_path):
        return

    if db.should_scan_repo(full_name):
        meta = await get_repo_meta(client, full_name, token_headers)
        if not meta:
            return
        stars      = meta.get("stargazers_count", 0)
        created_at = meta.get("created_at", "")
        db.mark_repo_scanned(full_name, stars, created_at)
        if not _passes_filter(stars, created_at):
            return
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

    # Fast-path: skip heavy regex if no trigger strings present anywhere in content.
    # Saves CPU on large files that are clearly irrelevant (e.g. pure binary-as-text).
    # Keep in sync with gitee_scanner._AI_TRIGGER when adding new providers.
    _AI_TRIGGER    = (
        "sk-", "AIzaSy", "eyJ",           # OpenAI / Google / JWT
        "hf_",                             # HuggingFace
        "pplx-",                           # Perplexity
        "xai-",                            # xAI / Grok
        "r8_",                             # Replicate
        "ZHIPUAI", "zhipuai",             # GLM
        "moonshot", "MOONSHOT",            # Kimi
        "klingai", "KLINGAI", "KLING_",   # Kling
        "DEEPSEEK", "deepseek",           # DeepSeek
        "ARK_API", "ark_api",             # Volcengine ARK
        "DOUBAO", "doubao",               # Doubao
        "VOLCSTACK", "VOLCENGINE_API",    # Volcengine alt names
        "VOLC_ACCESSKEY",                 # Volcengine alt names
    )
    _INFRA_TRIGGER = ("://", "BEGIN PRIVATE KEY", "BEGIN RSA", "BEGIN OPENSSH",
                      "AKIA", "AIPA", "AIDA", "AROA", "ASIA")
    has_ai_trigger    = any(t in content for t in _AI_TRIGGER)
    has_infra_trigger = any(t in content for t in _INFRA_TRIGGER)
    if not has_ai_trigger and not has_infra_trigger:
        return

    # ── AI key extractors — run ALL providers on every file ────────────────
    # (not just the query's "provider": a .env might have OpenAI + DeepSeek + ARK)
    if has_ai_trigger:
        for ai_prov, ai_fn in EXTRACTORS.items():
            for key in ai_fn(content):
                if db.key_exists(key):
                    continue
                is_valid = await validate(ai_prov, key)
                saved = db.save_key(
                    ai_prov, key, full_name, file_path, file_url,
                    stars, created_at, file_type, is_valid,
                )
                if saved:
                    await notify_found(
                        ai_prov, key, full_name, file_path, file_url,
                        stars, created_at, file_type, is_valid,
                    )
                    log.info("[%s] %s from %s",
                             "VALID" if is_valid else "found", ai_prov, full_name)

    # ── Infra extractors — intersecting track ──────────────────────────────
    # Only files found via AI queries are scanned → infra creds come from AI repos.
    # Risk assessment is computed once and reused across all infra providers.
    if has_infra_trigger:
        import hashlib as _hl
        risk_cache: tuple | None = None
        for infra_prov, infra_fn in INFRA_EXTRACTORS.items():
            creds = infra_fn(content)
            if not creds:
                continue
            if risk_cache is None:
                risk_cache = assess_risk(content, file_path, stars, created_at)
            risk_level, risk_reasons = risk_cache
            for cred in creds:
                if db.infra_exists(cred):
                    continue
                destination = extract_destination(cred) if "://" in cred else ""
                saved = db.save_infra(
                    infra_prov, cred, full_name, file_path, file_url,
                    stars, created_at, file_type, destination,
                    risk_level, risk_reasons,
                )
                if saved:
                    real_hash = _hl.sha256(cred.encode()).hexdigest()
                    t = asyncio.create_task(
                        _validate_infra_bg(infra_prov, cred, real_hash),
                        name=f"infra_val_{infra_prov}",
                    )
                    _BG_TASKS.add(t)
                    t.add_done_callback(_BG_TASKS.discard)
                    await notify_infra_found(
                        infra_prov, cred, full_name, file_path, file_url,
                        stars, created_at, file_type,
                        destination, risk_level, risk_reasons,
                    )
                    log.info("[infra/%s] risk=%s dest=%s repo=%s",
                             infra_prov, risk_level, destination or "—", full_name)


# ── Per-token worker ────────────────────────────────────────────────────────

async def _run_chunk(client: httpx.AsyncClient,
                     queries: list[tuple], token: str,
                     sem: asyncio.Semaphore, worker_id: int):
    """
    Processes an exclusive slice of QUERIES using a single token.
    Maintains 2s inter-query sleep → stays within 30 req/min per token.
    """
    hdrs = _gh_headers(token)
    tk   = _tkey(token)

    # Initial health check — skip entire worker if token is dead
    search_q, core_q = await _check_quota(client, hdrs, token)
    if search_q == -2:
        if tk not in _DEAD_ALERTED:
            _DEAD_ALERTED.add(tk)
            await notify_dead_token(token[:8])
        log.error("[w%d token=%s...] DEAD (401) — worker skipped", worker_id, token[:8])
        return

    log.info("[w%d token=%s...] handling %d queries, search=%s core=%s",
             worker_id, token[:8], len(queries),
             search_q if search_q >= 0 else "unknown",
             core_q   if core_q   >= 0 else "unknown")

    queries_done = 0

    for query_str, provider, file_type in queries:
        if queries_done % 10 == 0 and queries_done > 0:
            search_q, core_q = await _check_quota(client, hdrs, token)
            if search_q == -2:
                if tk not in _DEAD_ALERTED:
                    _DEAD_ALERTED.add(tk)
                    await notify_dead_token(token[:8])
                log.error("[w%d] token died mid-cycle, stopping worker", worker_id)
                return
            if search_q == 0:
                log.warning("[w%d] search quota exhausted, sleeping 65s", worker_id)
                await asyncio.sleep(65)
            elif 0 < search_q < 5:
                log.warning("[w%d] search quota low (%d), sleeping 30s", worker_id, search_q)
                await asyncio.sleep(30)
            # Core quota throttle — each search result triggers ~1.5 core REST
            # calls (repo meta + file content). With 5000/hr per token, hitting
            # <200 means the next batch of items will blow through the quota.
            if 0 <= core_q < 200:
                core_reset = _TOKEN_STATUS.get(tk, {}).get("core_reset", 0)
                now        = int(datetime.now(timezone.utc).timestamp())
                wait       = max(min(core_reset - now, _PRIMARY_WAIT_CAP), 60) if core_reset else 120
                log.warning("[w%d] core quota low (%d remaining), sleeping %ds until reset",
                            worker_id, core_q, wait)
                await asyncio.sleep(wait + random.uniform(0, 30))

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
        "=== scan cycle start | %d tokens | %d AI queries → %s chunks | "
        "%d concurrent items | max %d pages | cross-extract: %d infra providers ===",
        n, len(ALL_QUERIES), [len(c) for c in chunks],
        CONCURRENT_ITEMS, MAX_PAGES, len(INFRA_EXTRACTORS),
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
