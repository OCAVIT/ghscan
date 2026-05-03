"""
Postman public-workspace scanner — finds leaked AI API keys in collections.

Why Postman:
  - Devs testing OpenAI/Anthropic/etc. integrations hardcode keys in collections
  - 16% of forks of the official OpenAI Postman collection had live credentials
    (Truffle Security research, 2024-2025)
  - Postman doesn't warn when a workspace is set Public
  - Keys live in:
      • Collection variables (auto_variable, request bodies)
      • Request headers (Authorization: Bearer sk-...)
      • Pre-request / test scripts
      • Environment variables

Architecture:
  - List public workspaces accessible to API key
  - For each workspace, list collections + environments
  - Fetch full JSON of each (contains all hardcoded values)
  - Run AI_TRIGGER + extractors on JSON text
  - Dedup via try_claim_file(sha256("postman:{collection_uid}"))

Auth:
  - X-Api-Key: PMAK-... header
  - Free tier: ~60 req/min per API key (1000 reqs/month free baseline)
"""

import asyncio
import hashlib
import json
import logging

import httpx

import db
from config import POSTMAN_TOKENS, POSTMAN_SCAN_INTERVAL
from patterns import EXTRACTORS, AI_TRIGGER
from validators import validate
from notifier import notify_found, notify_dead_token

log = logging.getLogger(__name__)

_BASE = "https://api.postman.com"

_REQUEST_SLEEP   = 1.2   # seconds between requests per token (free tier rate-limit cushion)
_CONCURRENT      = 4     # parallel collection fetches per worker
_MAX_WORKSPACES  = 200   # cap per cycle to stay within free-tier monthly budget

_LIMITS = httpx.Limits(
    max_connections=20,
    max_keepalive_connections=8,
    keepalive_expiry=30,
)

_TOKEN_STATUS: dict[str, dict] = {}
_DEAD_ALERTED: set[str] = set()


def _headers(token: str) -> dict:
    return {
        "X-Api-Key": token,
        "Accept":    "application/json",
        "User-Agent": "ghscan-postman/1.0",
    }


def _claim_key(uid: str) -> str:
    return hashlib.sha256(f"postman:{uid}".encode()).hexdigest()[:40]


def _token_id(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()[:12]


async def _check_token(client: httpx.AsyncClient, token: str) -> bool:
    """Verify token via /me endpoint."""
    try:
        r = await client.get(f"{_BASE}/me", headers=_headers(token), timeout=12)
        if r.status_code == 200:
            _TOKEN_STATUS[_token_id(token)] = {"alive": True}
            return True
        if r.status_code in (401, 403):
            _TOKEN_STATUS[_token_id(token)] = {"alive": False}
            return False
        _TOKEN_STATUS[_token_id(token)] = {"alive": True}
        return True
    except Exception as e:
        log.debug("postman check_token exception: %s", e)
        return True


async def _list_public_workspaces(client: httpx.AsyncClient,
                                  token: str) -> list[dict]:
    """List public workspaces accessible to the API key."""
    try:
        r = await client.get(
            f"{_BASE}/workspaces",
            headers=_headers(token),
            params={"type": "public"},
            timeout=20,
        )
        if r.status_code in (401, 403):
            _TOKEN_STATUS[_token_id(token)] = {"alive": False}
            return []
        if r.status_code != 200:
            log.debug("postman list_workspaces status=%d body=%s",
                      r.status_code, r.text[:200])
            return []
        data = r.json()
        return data.get("workspaces", []) if isinstance(data, dict) else []
    except Exception as e:
        log.debug("postman list_workspaces err: %s", e)
        return []


async def _get_workspace_detail(client: httpx.AsyncClient,
                                token: str, ws_id: str) -> dict | None:
    """Fetch full workspace metadata including collections + environments lists."""
    try:
        r = await client.get(
            f"{_BASE}/workspaces/{ws_id}",
            headers=_headers(token),
            timeout=15,
        )
        if r.status_code != 200:
            return None
        data = r.json()
        return data.get("workspace") if isinstance(data, dict) else None
    except Exception as e:
        log.debug("postman ws_detail err [%s]: %s", ws_id, e)
        return None


async def _get_collection(client: httpx.AsyncClient,
                          token: str, uid: str) -> str | None:
    """Fetch full collection JSON as text (for grep + extractor pass)."""
    try:
        r = await client.get(
            f"{_BASE}/collections/{uid}",
            headers=_headers(token),
            timeout=20,
        )
        if r.status_code != 200:
            return None
        return r.text
    except Exception as e:
        log.debug("postman collection err [%s]: %s", uid, e)
        return None


async def _get_environment(client: httpx.AsyncClient,
                           token: str, uid: str) -> str | None:
    """Fetch full environment JSON (env vars often contain hardcoded keys)."""
    try:
        r = await client.get(
            f"{_BASE}/environments/{uid}",
            headers=_headers(token),
            timeout=15,
        )
        if r.status_code != 200:
            return None
        return r.text
    except Exception as e:
        log.debug("postman env err [%s]: %s", uid, e)
        return None


async def _scan_content(uid: str, kind: str, content: str,
                        ws_name: str, item_name: str):
    """Run AI extractors on Postman JSON content."""
    if not any(t in content for t in AI_TRIGGER):
        return

    repo_label = f"postman:{ws_name}"
    item_path  = f"{kind}/{item_name}"
    file_url   = f"https://www.postman.com/{kind}/{uid}"

    for prov, fn in EXTRACTORS.items():
        for key in fn(content):
            if db.key_exists(key):
                continue
            is_valid = await validate(prov, key)
            saved = db.save_key(
                prov, key, repo_label, item_path, file_url,
                0, "", "postman", is_valid,
            )
            if saved:
                await notify_found(
                    prov, key, repo_label, item_path, file_url,
                    0, "", "postman", is_valid,
                )
                log.info("[postman %s] %s from %s/%s",
                         "VALID" if is_valid else "found", prov, ws_name, item_name)


async def _scan_workspace(client: httpx.AsyncClient, token: str,
                          workspace: dict, sem: asyncio.Semaphore):
    """Fetch + scan all collections and environments in a workspace."""
    ws_id   = workspace.get("id", "")
    ws_name = workspace.get("name", ws_id)
    if not ws_id:
        return

    detail = await _get_workspace_detail(client, token, ws_id)
    await asyncio.sleep(_REQUEST_SLEEP)
    if not detail:
        return

    collections  = detail.get("collections",  []) or []
    environments = detail.get("environments", []) or []

    async def fetch_collection(c: dict):
        uid = c.get("uid") or c.get("id")
        if not uid:
            return
        if not db.try_claim_file(_claim_key(f"col:{uid}")):
            return
        async with sem:
            content = await _get_collection(client, token, uid)
        await asyncio.sleep(_REQUEST_SLEEP)
        if content:
            await _scan_content(uid, "collection", content,
                                ws_name, c.get("name", uid))

    async def fetch_env(e: dict):
        uid = e.get("uid") or e.get("id")
        if not uid:
            return
        if not db.try_claim_file(_claim_key(f"env:{uid}")):
            return
        async with sem:
            content = await _get_environment(client, token, uid)
        await asyncio.sleep(_REQUEST_SLEEP)
        if content:
            await _scan_content(uid, "environment", content,
                                ws_name, e.get("name", uid))

    tasks = ([asyncio.create_task(fetch_collection(c)) for c in collections] +
             [asyncio.create_task(fetch_env(e))        for e in environments])
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


async def _run_worker(client: httpx.AsyncClient, token: str, worker_id: int):
    tid = _token_id(token)
    alive = await _check_token(client, token)
    if not alive:
        if tid not in _DEAD_ALERTED:
            _DEAD_ALERTED.add(tid)
            await notify_dead_token(f"postman:{tid}")
        log.error("[postman w%d token=%s...] DEAD — skipped", worker_id, token[:12])
        return

    log.info("[postman w%d token=%s...] fetching public workspaces",
             worker_id, token[:12])

    workspaces = await _list_public_workspaces(client, token)
    workspaces = workspaces[:_MAX_WORKSPACES]  # rate-limit cushion
    log.info("[postman w%d] %d public workspaces to scan",
             worker_id, len(workspaces))

    sem = asyncio.Semaphore(_CONCURRENT)

    for ws in workspaces:
        try:
            await _scan_workspace(client, token, ws, sem)
        except Exception as e:
            log.debug("[postman w%d] ws scan err %s: %s",
                      worker_id, ws.get("id"), e)


async def run_postman_cycle():
    if not POSTMAN_TOKENS:
        return

    log.info("=== postman cycle start | %d tokens ===", len(POSTMAN_TOKENS))

    async with httpx.AsyncClient(follow_redirects=True, limits=_LIMITS) as client:
        workers = [
            asyncio.create_task(
                _run_worker(client, tok, i),
                name=f"postman_w{i}",
            )
            for i, tok in enumerate(POSTMAN_TOKENS)
        ]
        results = await asyncio.gather(*workers, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                log.error("postman worker crashed: %s", r)

    log.info("=== postman cycle done ===")


async def postman_loop():
    if not POSTMAN_TOKENS:
        log.info("postman: no POSTMAN_TOKENS configured — skipping")
        return

    log.info("postman scanner started | %d tokens | interval=%ds",
             len(POSTMAN_TOKENS), POSTMAN_SCAN_INTERVAL)

    while True:
        try:
            await run_postman_cycle()
        except Exception as e:
            log.error("postman cycle crashed: %s", e)
        log.info("postman sleeping %ds until next cycle", POSTMAN_SCAN_INTERVAL)
        await asyncio.sleep(POSTMAN_SCAN_INTERVAL)
