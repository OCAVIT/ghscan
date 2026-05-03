"""
Author tracking — periodic walker for serial leakers.

Picks watched_authors (is_watched=1, last_walked_at stale) and walks their
public GitHub repos, running the standard tree-walk on each new repo. New
keys committed by these high-signal users are captured within hours of
push (vs days/weeks for full Code Search cycle).

Schedule: every 24h via author_walk_loop().
Manual trigger: walk_one_author() called from /admin/walk_author endpoint.

Cost per author:
  ~1 list_repos call + (up to MAX_REPOS_PER_AUTHOR) tree-walks.
  Each tree-walk: 1 tree-list + ~30 blob fetches (capped at 100 files).
  → 30 repos × ~30 blobs ≈ ~900 GH calls per active author per 24h.

Bounds (configurable via env):
  AUTHOR_WALK_BATCH       max authors per cycle             (default 30)
  AUTHOR_WALK_MAX_REPOS   max repos per author              (default 30)
  AUTHOR_WALK_INTERVAL    seconds between cycles            (default 86400)
  AUTHOR_WALK_MAX_AGE_H   hours before re-walking same one  (default 24)
"""

import asyncio
import logging
import os
import sqlite3

import httpx

import db
import scanner
from config import DB_PATH, GITHUB_TOKENS

log = logging.getLogger(__name__)

# Tunables
_BATCH        = int(os.environ.get("AUTHOR_WALK_BATCH",     "30"))
_MAX_REPOS    = int(os.environ.get("AUTHOR_WALK_MAX_REPOS", "30"))
_INTERVAL     = int(os.environ.get("AUTHOR_WALK_INTERVAL",  "86400"))
_MAX_AGE_H    = int(os.environ.get("AUTHOR_WALK_MAX_AGE_H", "24"))


def _release_treewalk_claim(full_name: str):
    """Drop the placeholder row inserted by try_claim_repo_tree, so the
    actual walk_repo_tree() call can re-claim and proceed. Used when the
    outer caller pre-claimed to test "should we walk this repo".
    """
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "DELETE FROM tree_walked_repos WHERE repo_full_name=?",
                (full_name,),
            )
    except Exception as e:
        log.debug("release claim err %s: %s", full_name, e)


async def walk_one_author(
    client: httpx.AsyncClient,
    login: str,
    platform: str = "github",
    max_repos: int = _MAX_REPOS,
    token: str | None = None,
) -> dict:
    """List a user's public repos and tree-walk those not yet walked.

    Returns {walked: int, skipped: int, errors: int}. Best-effort —
    individual repo failures are logged and counted, never raised.
    """
    if platform != "github":
        return {"walked": 0, "skipped": 0, "errors": 0,
                "error": f"platform {platform} not supported"}

    tok = token or (GITHUB_TOKENS[0] if GITHUB_TOKENS else None)
    if not tok:
        return {"walked": 0, "skipped": 0, "errors": 0,
                "error": "no GITHUB_TOKEN configured"}
    headers = {"Authorization": f"Bearer {tok}",
               "Accept": "application/vnd.github+json"}

    repos = await scanner._gh_get(
        client,
        f"https://api.github.com/users/{login}/repos",
        params={"per_page": max_repos, "type": "public", "sort": "pushed"},
        headers=headers,
    )
    if not repos:
        return {"walked": 0, "skipped": 0, "errors": 0,
                "error": f"could not list repos for {login}"}

    walked = skipped = errors = 0
    for repo in repos:
        full_name = repo.get("full_name", "")
        if not full_name:
            continue
        # Skip if already walked. Otherwise we briefly hold the placeholder
        # claim then release it so walk_repo_tree's own claim succeeds.
        if not db.try_claim_repo_tree(full_name):
            skipped += 1
            continue
        _release_treewalk_claim(full_name)

        stars   = repo.get("stargazers_count", 0)
        created = repo.get("created_at", "")
        try:
            await scanner.walk_repo_tree(client, full_name, stars, created, headers)
            walked += 1
        except Exception as e:
            log.debug("treewalk err %s/%s: %s", login, full_name, e)
            errors += 1

    db.mark_author_walked(login, platform)
    return {"walked": walked, "skipped": skipped, "errors": errors}


async def run_author_cycle() -> dict:
    """Walk one batch of authors due for re-scan. Called by the loop."""
    authors = db.get_authors_to_walk(limit=_BATCH, max_age_hours=_MAX_AGE_H)
    if not authors:
        return {"authors_processed": 0, "total_walked": 0, "total_skipped": 0}

    total_walked = total_skipped = total_errors = 0
    async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
        for a in authors:
            res = await walk_one_author(
                client, a["login"], a["platform"],
                max_repos=_MAX_REPOS,
            )
            total_walked  += res.get("walked", 0)
            total_skipped += res.get("skipped", 0)
            total_errors  += res.get("errors", 0)

    log.info("author_walk: %d authors → walked=%d skipped=%d errors=%d",
             len(authors), total_walked, total_skipped, total_errors)
    return {
        "authors_processed": len(authors),
        "total_walked":      total_walked,
        "total_skipped":     total_skipped,
        "total_errors":      total_errors,
    }


async def author_walk_loop():
    """Background loop — runs run_author_cycle() every _INTERVAL seconds.

    Sleeps first so a freshly-deployed instance doesn't hammer GitHub
    immediately on startup; gives the main scan loop time to build up
    enough leak data for the watchlist to make sense.
    """
    log.info(
        "author_walk_loop: batch=%d max_repos=%d interval=%ds max_age=%dh",
        _BATCH, _MAX_REPOS, _INTERVAL, _MAX_AGE_H,
    )
    # Initial wait — let the first scan cycle finish so watched_authors
    # has data to act on. Half the interval avoids both startup spike and
    # full-day delay before any walking happens.
    await asyncio.sleep(_INTERVAL // 2)
    while True:
        try:
            await run_author_cycle()
        except Exception as e:
            log.error("author_walk_loop crashed: %s", e)
        await asyncio.sleep(_INTERVAL)
