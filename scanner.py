"""
Core GitHub search + key extraction + validation loop.
"""

import asyncio
import base64
import logging
from datetime import datetime, timezone, timedelta

import httpx

import db
from config import GITHUB_TOKEN, YOUNG_REPO_DAYS, BIG_SERVICE_STARS
from patterns import QUERIES, extract_openai, extract_ark, is_skippable_path, is_server_path
from validators import validate
from notifier import notify_found, notify_cycle_done

log = logging.getLogger(__name__)

_HEADERS = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}
_BASE = "https://api.github.com"

EXTRACTORS = {
    "openai": extract_openai,
    "ark":    extract_ark,
}


# ── GitHub helpers ─────────────────────────────────────────────────────────

async def _gh_get(client: httpx.AsyncClient, url: str, params: dict | None = None) -> dict | list | None:
    for attempt in range(3):
        try:
            r = await client.get(url, headers=_HEADERS, params=params, timeout=20)
            if r.status_code == 403:
                reset = int(r.headers.get("X-RateLimit-Reset", 0))
                wait = max(reset - int(datetime.now(timezone.utc).timestamp()), 5)
                wait = min(wait, 90)
                log.warning("rate-limited, sleeping %ds", wait)
                await asyncio.sleep(wait)
                continue
            if r.status_code == 422:
                return None  # query not processable
            if r.status_code == 404:
                return None
            r.raise_for_status()
            return r.json()
        except httpx.TimeoutException:
            await asyncio.sleep(5 * (attempt + 1))
        except Exception as e:
            log.debug("gh_get err: %s", e)
            await asyncio.sleep(3)
    return None


async def search_code(client: httpx.AsyncClient, query: str, page: int = 1) -> list[dict]:
    data = await _gh_get(client, f"{_BASE}/search/code",
                         params={"q": query, "per_page": 100, "page": page})
    if not data:
        return []
    return data.get("items", [])


async def get_repo_meta(client: httpx.AsyncClient, full_name: str) -> dict | None:
    return await _gh_get(client, f"{_BASE}/repos/{full_name}")


async def get_file_content(client: httpx.AsyncClient, url: str) -> str | None:
    data = await _gh_get(client, url)
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


# ── Repo filter ────────────────────────────────────────────────────────────

def _is_young(created_at: str) -> bool:
    try:
        dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days <= YOUNG_REPO_DAYS
    except Exception:
        return False


def _is_big(stars: int) -> bool:
    return stars >= BIG_SERVICE_STARS


def _passes_filter(stars: int, created_at: str) -> bool:
    """Keep: young repo OR big-service repo."""
    return _is_young(created_at) or _is_big(stars)


# ── Item processing ────────────────────────────────────────────────────────

async def process_item(client: httpx.AsyncClient, item: dict, provider: str, file_type: str):
    repo_info = item.get("repository", {})
    full_name  = repo_info.get("full_name", "")
    file_path  = item.get("path", "")
    sha        = item.get("sha", "")
    file_url   = item.get("html_url", "")
    content_url = item.get("url", "")

    if not full_name or not sha:
        return

    # Skip already-processed files
    if db.is_file_scanned(sha):
        return

    # Skip trash paths
    if is_skippable_path(file_path):
        db.mark_file_scanned(sha)
        return

    # Fetch repo metadata — needed for age/stars filter
    need_meta = db.should_scan_repo(full_name)
    if need_meta:
        meta = await get_repo_meta(client, full_name)
        if not meta:
            return
        stars      = meta.get("stargazers_count", 0)
        created_at = meta.get("created_at", "")
        db.mark_repo_scanned(full_name, stars, created_at)

        if not _passes_filter(stars, created_at):
            db.mark_file_scanned(sha)
            return
    else:
        # Repo already known — pull cached meta from DB
        import sqlite3
        with sqlite3.connect(db.DB_PATH) as c:
            row = c.execute("SELECT stars, created_at FROM scanned_repos WHERE full_name=?",
                            (full_name,)).fetchone()
        if row:
            stars, created_at = row
        else:
            stars, created_at = 0, ""
        if not _passes_filter(stars, created_at):
            db.mark_file_scanned(sha)
            return

    # Fetch file content
    content = await get_file_content(client, content_url)
    db.mark_file_scanned(sha)
    if not content:
        return

    # Extract keys
    extractor = EXTRACTORS.get(provider)
    if not extractor:
        return
    keys = extractor(content)
    if not keys:
        return

    for key in keys:
        if db.key_exists(key):
            continue

        # Live validation — only notify if confirmed active
        is_valid = await validate(provider, key)

        saved = db.save_key(
            provider, key, full_name, file_path, file_url,
            stars, created_at, file_type, is_valid
        )
        if saved:
            await notify_found(
                provider, key, full_name, file_path, file_url,
                stars, created_at, file_type, is_valid
            )
            status = "VALID" if is_valid else "unverified"
            log.info("[%s] %s key from %s (%s)", status, provider, full_name, file_type)

        # Small delay between validations to avoid hammering provider
        await asyncio.sleep(1)


# ── Scan cycle ─────────────────────────────────────────────────────────────

async def run_cycle():
    log.info("=== scan cycle starting ===")
    async with httpx.AsyncClient(follow_redirects=True) as client:
        for query_str, provider, file_type in QUERIES:
            log.info("query [%s/%s]: %s", provider, file_type, query_str[:60])
            # GitHub code search returns max 1000 results (10 pages)
            # We only go 3 pages deep — freshest results have highest hit rate
            for page in range(1, 4):
                items = await search_code(client, query_str, page)
                if not items:
                    break

                for item in items:
                    try:
                        await process_item(client, item, provider, file_type)
                    except Exception as e:
                        log.error("process_item err: %s", e)
                    await asyncio.sleep(0.3)  # polite pacing

                if len(items) < 100:
                    break  # no more pages
                # Rate-limit pause between pages
                await asyncio.sleep(3)

            # Pause between queries (code search: ~30 req/min with PAT)
            await asyncio.sleep(2)

    stats = db.get_stats()
    log.info("cycle done — %s", stats)
    await notify_cycle_done(stats)
