"""
GitHub Issues / PR / Discussions scanner.

Different surface from code search: devs paste env-files in issue
descriptions ("why does my code error?"), in PR descriptions, in
discussion threads. /search/issues uses a separate rate-limit pool
from /search/code (same 30 req/min/token, but counted separately —
effectively doubles our scan budget).

Pipeline:
  1. Pull dynamic_queries (last 15d, AI-key oriented) — reuse the same
     query pool as code-search since the goal is similar
  2. For each query: GET /search/issues?q=<query>+is:public
  3. For each hit: fetch issue body via GET /repos/{owner}/{repo}/issues/{n}
  4. Run AI_TRIGGER fast-path + EXTRACTORS on body + comments
  5. Save_key with file_type='issue' / 'pr' / 'discussion'

Key differences from scanner.py:
  - GH issue body up to ~64KB; comments lazy-fetched only if body had a trigger
  - SHA-dedup uses issue node_id instead of file SHA
  - file_url = html_url of the issue (clickable in Telegram)
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

import httpx

import db
from config import GITHUB_TOKENS, CONCURRENT_ITEMS, MAX_PAGES
from patterns import EXTRACTORS, AI_TRIGGER, INFRA_TRIGGER, is_skippable_path
from infra_patterns import INFRA_EXTRACTORS, assess_risk, extract_destination
from validators import validate, INFRA_VALIDATORS
from notifier import notify_found, notify_infra_found
from deobfuscate import expand as _deobf_expand

log = logging.getLogger(__name__)

_BASE = "https://api.github.com"
_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

ISSUES_SCAN_INTERVAL = 3600   # 1h between cycles
ISSUES_MAX_PAGES = 3           # cap per query — issues yield is lower than code
ISSUES_PER_PAGE  = 100


def _hdrs(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": _USER_AGENT,
    }


async def _gh_get(client: httpx.AsyncClient, url: str,
                  params: dict | None = None,
                  headers: dict | None = None) -> dict | list | None:
    """Minimal request wrapper with 403/429 backoff. Mirrors scanner._gh_get
    but simpler — issues yield rate is low so we can be less aggressive."""
    for attempt in range(3):
        try:
            r = await client.get(url, params=params, headers=headers, timeout=20)
            if r.status_code == 200:
                return r.json()
            if r.status_code in (403, 429):
                wait = 30 * (attempt + 1)
                log.warning("issues 403/429 on %s — sleep %ds",
                            url.rsplit("/", 1)[-1][:40], wait)
                await asyncio.sleep(wait)
                continue
            return None
        except Exception as e:
            log.debug("issues gh_get err %s: %s", url[:80], e)
            await asyncio.sleep(5)
    return None


def _query_for_issues(query_str: str) -> str:
    """Adapt code-search query to issue-search syntax.

    Differences:
      - issue search has no `language:`, `path:`, `extension:`, `filename:`
      - it has `is:issue`, `is:pr`, `repo:`, `org:`, `user:`, `in:title|body|comments`
    Strategy: strip operators that don't apply, keep quoted literals + add is:public.
    """
    # Strip code-search-only operators
    parts = []
    for tok in query_str.split():
        if any(tok.startswith(p) for p in
                ("language:", "path:", "extension:", "filename:", "size:",
                 "fork:", "in:readme")):
            continue
        parts.append(tok)
    parts.append("is:public")
    parts.append("in:body")
    return " ".join(parts)


async def _process_issue(client: httpx.AsyncClient, item: dict,
                          provider_hint: str, hdrs: dict, sem: asyncio.Semaphore):
    """Fetch issue body + comments, run extractors, save_key."""
    async with sem:
        node_id = item.get("node_id") or str(item.get("id", ""))
        if not node_id:
            return
        if not db.try_claim_file(node_id):
            return    # already scanned

        body = item.get("body") or ""
        if not body:
            return

        body = _deobf_expand(body)
        has_ai    = any(t in body for t in AI_TRIGGER)
        has_infra = any(t in body for t in INFRA_TRIGGER)
        if not (has_ai or has_infra):
            return

        repo_url = item.get("repository_url", "")
        # /repos/owner/repo
        if "/repos/" in repo_url:
            full_name = repo_url.split("/repos/", 1)[1]
        else:
            return
        html_url = item.get("html_url", "")
        kind = "pr" if item.get("pull_request") else "issue"

        # Run AI extractors
        if has_ai:
            for ai_prov, ai_fn in EXTRACTORS.items():
                for key in ai_fn(body):
                    if db.key_exists(key):
                        continue
                    is_valid = await validate(ai_prov, key)
                    saved = db.save_key(
                        ai_prov, key, full_name,
                        f"#{item.get('number','?')}", html_url,
                        0, "", kind, is_valid,
                    )
                    if saved:
                        await notify_found(
                            ai_prov, key, full_name,
                            f"#{item.get('number','?')}", html_url,
                            0, "", kind, is_valid,
                        )
                        log.info("[issues %s] %s from %s#%s",
                                 "VALID" if is_valid else "found",
                                 ai_prov, full_name, item.get("number"))

        # Infra extractors
        if has_infra:
            risk_cache = None
            for infra_prov, infra_fn in INFRA_EXTRACTORS.items():
                creds = infra_fn(body)
                if not creds:
                    continue
                if risk_cache is None:
                    risk_cache = assess_risk(body, f"#{item.get('number')}", 0, "")
                risk_level, risk_reasons = risk_cache
                for cred in creds:
                    if db.infra_exists(cred):
                        continue
                    destination = extract_destination(cred) if "://" in cred else ""
                    saved = db.save_infra(
                        infra_prov, cred, full_name,
                        f"#{item.get('number','?')}", html_url,
                        0, "", kind, destination,
                        risk_level, risk_reasons,
                    )
                    if saved:
                        await notify_infra_found(
                            infra_prov, cred, full_name,
                            f"#{item.get('number','?')}", html_url,
                            0, "", kind, destination, risk_level, risk_reasons,
                        )

        # If body had something, also pull comments — devs often paste
        # follow-up env content in replies
        if has_ai or has_infra:
            try:
                comments_url = item.get("comments_url")
                if comments_url:
                    cdata = await _gh_get(client, comments_url, headers=hdrs)
                    if isinstance(cdata, list):
                        for cmt in cdata[:30]:
                            ctext = (cmt.get("body") or "")
                            if not ctext:
                                continue
                            ctext = _deobf_expand(ctext)
                            for ai_prov, ai_fn in EXTRACTORS.items():
                                for key in ai_fn(ctext):
                                    if db.key_exists(key):
                                        continue
                                    is_valid = await validate(ai_prov, key)
                                    saved = db.save_key(
                                        ai_prov, key, full_name,
                                        f"#{item.get('number','?')}/comment", html_url,
                                        0, "", f"{kind}_comment", is_valid,
                                    )
                                    if saved:
                                        await notify_found(
                                            ai_prov, key, full_name,
                                            f"#{item.get('number','?')}/comment", html_url,
                                            0, "", f"{kind}_comment", is_valid,
                                        )
            except Exception as e:
                log.debug("issue comments err: %s", e)


async def _run_chunk(client: httpx.AsyncClient, queries: list[tuple],
                      token: str, sem: asyncio.Semaphore, worker_id: int):
    hdrs = _hdrs(token)
    for query_tuple in queries:
        if len(query_tuple) == 4:
            query_str, provider, _ftype, _qhash = query_tuple
        else:
            query_str, provider, _ftype = query_tuple
            _qhash = None

        adapted = _query_for_issues(query_str)
        # Issue search rejects > 256 chars. Truncate gracefully.
        if len(adapted) > 256:
            continue

        for page in range(1, ISSUES_MAX_PAGES + 1):
            try:
                data = await _gh_get(
                    client, f"{_BASE}/search/issues",
                    params={"q": adapted, "sort": "updated", "order": "desc",
                             "per_page": ISSUES_PER_PAGE, "page": page},
                    headers=hdrs,
                )
            except Exception as e:
                log.debug("[issues w%d] search err: %s", worker_id, e)
                break
            items = (data or {}).get("items", [])
            if not items:
                break
            tasks = [
                asyncio.create_task(_process_issue(client, it, provider, hdrs, sem))
                for it in items
            ]
            await asyncio.gather(*tasks, return_exceptions=True)
            if len(items) < ISSUES_PER_PAGE:
                break
            await asyncio.sleep(3)
        await asyncio.sleep(3)


async def run_issues_cycle():
    """One full issues scan cycle. Uses same query pool as code search."""
    if not GITHUB_TOKENS:
        return
    # Pick a SUBSET of dynamic queries — just yielding ones (skip dead patterns)
    rows = db.get_active_dynamic_queries(max_age_days=15)
    # Take top 100 by yield potential (newcomers + valid_yielders)
    pool: list[tuple] = []
    for r in rows[:200]:
        pool.append((r["query_str"], r["provider"], r["file_type"], r["query_hash"]))
    if len(pool) < 5:
        log.info("issues_cycle: only %d queries available — skipping", len(pool))
        return

    n = len(GITHUB_TOKENS)
    chunks: list[list] = [[] for _ in range(n)]
    for i, q in enumerate(pool):
        chunks[i % n].append(q)
    log.info("=== issues cycle | %d tokens | %d queries -> %s ===",
             n, len(pool), [len(c) for c in chunks])
    sem = asyncio.Semaphore(min(CONCURRENT_ITEMS, 15))
    async with httpx.AsyncClient(follow_redirects=True) as client:
        workers = [
            asyncio.create_task(_run_chunk(client, chunks[i], GITHUB_TOKENS[i],
                                            sem, i))
            for i in range(n)
        ]
        await asyncio.gather(*workers, return_exceptions=True)
    log.info("issues cycle done")


async def issues_loop():
    while True:
        try:
            await run_issues_cycle()
        except Exception as e:
            log.error("issues_loop crashed: %s", e)
        await asyncio.sleep(ISSUES_SCAN_INTERVAL)
