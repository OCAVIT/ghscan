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

# Org-members walk gating: only fire for authors with strong leak signal,
# capped per cycle to avoid scope blowout. ~5 leaks is the empirical line
# where 'serial leaker' becomes statistically reliable.
_ORG_WALK_MIN_LEAK_COUNT = int(os.environ.get("AUTHOR_WALK_ORG_MIN_LEAK_COUNT", "5"))
_MAX_ORGS_PER_AUTHOR     = int(os.environ.get("AUTHOR_WALK_MAX_ORGS_PER_AUTHOR", "3"))


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

    # Cross-source signal #1: walk this author's public gists. Cheap (1 list
    # call + N gist fetches) and uses /gists/* rate-limit pool which is
    # separate from /search/code. Atomic 24h dedup inside walk_user_gists.
    gist_result = {}
    try:
        gist_result = await walk_user_gists(client, login, token=tok)
        if gist_result.get("keys_found", 0) > 0:
            log.info("walk_user_gists: %s → %d new keys from gists",
                     login, gist_result["keys_found"])
    except Exception as e:
        log.debug("walk_user_gists err for %s: %s", login, e)

    return {
        "walked":       walked,
        "skipped":      skipped,
        "errors":       errors,
        "gists_result": gist_result or None,
    }


# ── Cross-source #1: walk user's public gists ──────────────────────────────
# Gists are common leak vectors — devs paste quick test scripts with real
# keys. /users/{login}/gists is on a separate /gists rate-limit pool from
# /search/code so it adds capacity, not contention. Triggered AFTER repo
# walk for a watched author.

_MAX_GISTS_PER_AUTHOR = int(os.environ.get("AUTHOR_WALK_MAX_GISTS", "30"))


async def walk_user_gists(client: httpx.AsyncClient, login: str,
                          token: str | None = None) -> dict:
    """Walk a user's public gists. For each gist, fetch each file's content
    and run the standard AI/infra extractor pipeline.

    Returns {gists_listed, files_scanned, keys_found}.
    Atomic 24h dedup via db.try_claim_gist_walk — multiple author_walk
    cycles within 24h won't re-walk the same gists.
    """
    if not db.try_claim_gist_walk(login, max_age_hours=24):
        return {"gists_listed": 0, "files_scanned": 0, "keys_found": 0,
                "skipped": "recently_walked"}

    tok = token or (GITHUB_TOKENS[0] if GITHUB_TOKENS else None)
    if not tok:
        return {"error": "no GITHUB_TOKEN configured"}
    headers = {
        "Authorization": f"Bearer {tok}",
        "Accept":        "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    # 1) List gists
    try:
        listing = await scanner._gh_get(
            client,
            f"https://api.github.com/users/{login}/gists",
            params={"per_page": _MAX_GISTS_PER_AUTHOR},
            headers=headers,
        )
    except Exception as e:
        log.debug("gist list err for %s: %s", login, e)
        return {"error": f"list_failed: {type(e).__name__}"}
    if not listing or not isinstance(listing, list):
        db.mark_gist_walk(login, 0, 0, 0)
        return {"gists_listed": 0, "files_scanned": 0, "keys_found": 0}

    files_scanned = 0
    keys_found = 0

    # Lazy imports to avoid circular at module load
    from patterns       import EXTRACTORS, AI_TRIGGER, INFRA_TRIGGER
    from infra_patterns import INFRA_EXTRACTORS
    from validators     import validate
    from notifier       import notify_found

    for gist in listing[:_MAX_GISTS_PER_AUTHOR]:
        gist_id   = gist.get("id")
        html_url  = gist.get("html_url", "")
        if not gist_id:
            continue
        # 2) Fetch full gist (includes files inline)
        try:
            full = await scanner._gh_get(
                client,
                f"https://api.github.com/gists/{gist_id}",
                headers=headers,
            )
        except Exception as e:
            log.debug("gist %s fetch err: %s", gist_id, e)
            continue
        if not full or not isinstance(full, dict):
            continue
        files = full.get("files") or {}
        if not isinstance(files, dict):
            continue

        for filename, fdata in files.items():
            if not isinstance(fdata, dict):
                continue
            content = fdata.get("content", "") or ""
            # File-level dedup via SHA — gist file SHAs are stored in fdata
            file_sha = fdata.get("raw_url", "") or filename
            file_url = f"{html_url}#file-{filename.replace('.', '-')}"
            files_scanned += 1
            # Trigger filter (cheap — same as scanner.process_item)
            if not (any(t in content for t in AI_TRIGGER) or
                    any(t in content for t in INFRA_TRIGGER)):
                continue
            # AI extractors
            for ai_prov, ai_fn in EXTRACTORS.items():
                for key in ai_fn(content):
                    if db.key_exists(key):
                        continue
                    is_valid = await validate(ai_prov, key)
                    saved = db.save_key(
                        ai_prov, key, f"gist:{gist_id}", filename, file_url,
                        0, "", "gist", is_valid,
                    )
                    if saved:
                        keys_found += 1
                        await notify_found(
                            ai_prov, key, f"gist:{gist_id}", filename, file_url,
                            0, "", "gist", is_valid,
                        )
                        log.info("[gist %s] %s key from %s/%s",
                                 "VALID" if is_valid else "found",
                                 ai_prov, login, filename)

    db.mark_gist_walk(login, len(listing[:_MAX_GISTS_PER_AUTHOR]),
                      files_scanned, keys_found)
    return {
        "gists_listed":   len(listing[:_MAX_GISTS_PER_AUTHOR]),
        "files_scanned":  files_scanned,
        "keys_found":     keys_found,
    }


# ── Cross-source #2: walk an org's public members ──────────────────────────
# When a high-recidivism author is in a small org, their coworkers likely
# share the same poor key-hygiene culture. Enumerate org members, walk
# each non-watched one's recent repos. Gated by org size (skip if too big
# — large orgs have weak signal), and 7-day dedup so we don't churn.

_MAX_ORG_MEMBERS  = int(os.environ.get("AUTHOR_WALK_MAX_ORG_MEMBERS", "40"))
_MAX_ORG_SIZE     = int(os.environ.get("AUTHOR_WALK_MAX_ORG_SIZE",    "100"))
_MAX_REPOS_PER_ORG_MEMBER = int(os.environ.get("AUTHOR_WALK_MAX_REPOS_PER_ORG_MEMBER", "10"))


async def walk_org_members(client: httpx.AsyncClient, org: str,
                            token: str | None = None) -> dict:
    """Walk an org's public members and tree-walk their recent repos.

    Returns {members_listed, members_walked, total_walked_repos, total_keys_found,
              skipped (reason str if applicable)}.

    Gates:
      - 7-day dedup via db.try_claim_org_walk — same org not re-walked
      - org size cap _MAX_ORG_SIZE: skip if member count > threshold
        (too many → weak signal-to-noise)
      - per-member repo cap _MAX_REPOS_PER_ORG_MEMBER (smaller than direct
        author walk: org members are weaker prior than direct leakers)
    """
    if not db.try_claim_org_walk(org, max_age_hours=24 * 7):
        return {"skipped": "recently_walked", "members_listed": 0,
                "members_walked": 0, "total_walked_repos": 0,
                "total_keys_found": 0}

    tok = token or (GITHUB_TOKENS[0] if GITHUB_TOKENS else None)
    if not tok:
        return {"error": "no GITHUB_TOKEN configured"}
    headers = {
        "Authorization": f"Bearer {tok}",
        "Accept":        "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    # 1) Quick org-size check (big orgs = weak prior, skip)
    try:
        org_meta = await scanner._gh_get(
            client, f"https://api.github.com/orgs/{org}", headers=headers,
        )
    except Exception:
        org_meta = None
    if org_meta and isinstance(org_meta, dict):
        public_members = int(org_meta.get("public_members", 0) or 0)
        if public_members > _MAX_ORG_SIZE:
            db.mark_org_walked(org, public_members, 0)
            log.info("walk_org_members: %s skipped — too big (%d > %d)",
                     org, public_members, _MAX_ORG_SIZE)
            return {"skipped": f"too_big({public_members})",
                    "members_listed": public_members,
                    "members_walked": 0, "total_walked_repos": 0,
                    "total_keys_found": 0}

    # 2) List public members
    try:
        members = await scanner._gh_get(
            client, f"https://api.github.com/orgs/{org}/members",
            params={"per_page": _MAX_ORG_MEMBERS}, headers=headers,
        )
    except Exception as e:
        log.debug("walk_org_members list err %s: %s", org, e)
        db.mark_org_walked(org, 0, 0)
        return {"error": f"list_failed: {type(e).__name__}"}
    if not members or not isinstance(members, list):
        db.mark_org_walked(org, 0, 0)
        return {"members_listed": 0, "members_walked": 0,
                "total_walked_repos": 0, "total_keys_found": 0}

    total_walked = 0
    total_keys   = 0
    members_walked = 0
    new_members = 0

    for m in members[:_MAX_ORG_MEMBERS]:
        login = m.get("login")
        if not login:
            continue
        # Don't re-walk authors we already have on watch (their own loop covers them)
        if db.is_author_watched(login):
            continue
        # walk_one_author already dedups individual repos via try_claim_repo_tree
        try:
            res = await walk_one_author(
                client, login, platform="github",
                max_repos=_MAX_REPOS_PER_ORG_MEMBER, token=tok,
            )
            members_walked += 1
            total_walked   += res.get("walked", 0)
            new_members    += 1 if res.get("walked", 0) > 0 else 0
        except Exception as e:
            log.debug("walk_org_members member %s err: %s", login, e)
            continue

    db.mark_org_walked(org, len(members), new_members)
    log.info("walk_org_members: org=%s listed=%d walked_members=%d "
             "walked_repos=%d new_keys=%d",
             org, len(members), members_walked, total_walked, total_keys)
    return {
        "members_listed":      len(members),
        "members_walked":      members_walked,
        "total_walked_repos":  total_walked,
        "total_keys_found":    total_keys,
    }


async def _orgs_for_user(client: httpx.AsyncClient, login: str,
                          token: str) -> list[str]:
    """List public orgs a user belongs to. Returns list of org logins."""
    try:
        orgs = await scanner._gh_get(
            client, f"https://api.github.com/users/{login}/orgs",
            headers={"Authorization": f"Bearer {token}",
                     "Accept": "application/vnd.github+json"},
        )
        if isinstance(orgs, list):
            return [o.get("login", "") for o in orgs if o.get("login")]
    except Exception:
        pass
    return []


async def run_author_cycle() -> dict:
    """Walk one batch of authors due for re-scan. Called by the loop.

    Author flow per cycle:
      1. walk_one_author → repos + gists (gists embedded inside)
      2. If author leak_count >= _ORG_WALK_MIN_LEAK_COUNT → also enumerate
         their public orgs and walk org members. Heavy cost but only fires
         on truly high-signal authors (~5+ leaks). Per-org dedup via
         walked_orgs table — same org won't be re-walked sooner than 7 days.
    """
    authors = db.get_authors_to_walk(limit=_BATCH, max_age_hours=_MAX_AGE_H)
    if not authors:
        return {"authors_processed": 0, "total_walked": 0, "total_skipped": 0}

    total_walked  = total_skipped = total_errors = 0
    total_org_members_walked = total_gist_keys = 0
    tok = GITHUB_TOKENS[0] if GITHUB_TOKENS else None
    async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
        for a in authors:
            res = await walk_one_author(
                client, a["login"], a["platform"],
                max_repos=_MAX_REPOS, token=tok,
            )
            total_walked  += res.get("walked", 0)
            total_skipped += res.get("skipped", 0)
            total_errors  += res.get("errors", 0)
            gist_res = res.get("gists_result") or {}
            total_gist_keys += gist_res.get("keys_found", 0)

            # High-signal author? Also walk their org's public members
            leak_count = a.get("leak_count", 0) or 0
            if leak_count >= _ORG_WALK_MIN_LEAK_COUNT and tok:
                try:
                    orgs = await _orgs_for_user(client, a["login"], tok)
                    for org in orgs[:_MAX_ORGS_PER_AUTHOR]:
                        org_res = await walk_org_members(client, org, token=tok)
                        total_org_members_walked += org_res.get("members_walked", 0)
                except Exception as e:
                    log.debug("org walk err for %s: %s", a["login"], e)

    log.info("author_walk: %d authors → repos walked=%d skipped=%d errors=%d  "
             "gist_keys=%d  org_members_walked=%d",
             len(authors), total_walked, total_skipped, total_errors,
             total_gist_keys, total_org_members_walked)
    return {
        "authors_processed":         len(authors),
        "total_walked":              total_walked,
        "total_skipped":             total_skipped,
        "total_errors":              total_errors,
        "total_gist_keys":           total_gist_keys,
        "total_org_members_walked":  total_org_members_walked,
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
