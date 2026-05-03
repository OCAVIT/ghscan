"""
GitHub Gists scanner — polls /gists/public for leaked secrets.

Why Gists in addition to Code Search:
  - Gists are NOT indexed by /search/code at all — completely separate surface
  - Devs paste .env / config snippets to share for debugging → keys end up there
  - Uses core quota (NOT search quota) — same pool as Events API, 5000/hr per token
  - ETag caching: 304 responses free, just like Events API

Architecture:
  - One worker per GitHub token
  - Each worker polls /gists/public?since=<last_seen_time> to get new gists only
  - For every gist, fetches raw file content of interesting filenames
  - Dedup via try_claim_file(sha256("gist:{gist_id}:{file_sha}"))
  - ETag per worker to cache the list response itself (304 = nothing new)

Rate budget (9 tokens, 60s poll):
  - 9 req/min for gist list = 540 req/hour out of 45,000 available (1.2%)
  - File fetches: ~2-10% of gists touch watched filenames → ~10-50 req/hour
"""

import asyncio
import base64
import hashlib
import logging
from datetime import datetime, timezone, timedelta

import httpx

import db
from config import GITHUB_TOKENS
from patterns import EXTRACTORS, is_skippable_path, AI_TRIGGER, INFRA_TRIGGER
from infra_patterns import INFRA_EXTRACTORS, assess_risk, extract_destination
from validators import validate
from notifier import notify_found, notify_infra_found

log = logging.getLogger(__name__)

_BASE = "https://api.github.com"
_DEFAULT_POLL_INTERVAL = 60   # seconds; overridden by X-Poll-Interval header

_LIMITS = httpx.Limits(
    max_connections=30,
    max_keepalive_connections=10,
    keepalive_expiry=30,
)

# Filenames worth fetching from gists — same set as events_scanner + some extras
# that devs commonly paste as one-off gists.
_WATCH_NAMES: frozenset[str] = frozenset({
    ".env", ".env.local", ".env.example", ".env.production",
    ".env.development", ".env.staging", ".env.backup",
    ".env.dev", ".env.test", ".env.qa",
    "config.py", "settings.py", "api_config.py",
    "config.yaml", "config.yml", "config.json", "config.toml",
    "config.ts", "config.js",
    "docker-compose.yml", "docker-compose.yaml",
    "application.yml", "application.yaml", "application.properties",
    "appsettings.json",
    "llm_config.yaml", "model_config.json",
    "secrets.py", "secrets.js", "secrets.yaml", "secrets.json",
    "credentials.json", "credentials.py",
    "keys.py", "keys.js", "keys.yaml",
    "values.yaml", "values-dev.yaml", "values-prod.yaml",
    "terraform.tfvars", "variables.tfvars",
    "Makefile",
    # Gist-specific: devs often name pastes descriptively
    "env.txt", "env.sh", "environment.txt",
    "test.py", "test.js", "example.py", "example.js", "demo.py",
})

_AI_TRIGGER = AI_TRIGGER
_INFRA_TRIGGER = INFRA_TRIGGER


def _headers(token: str) -> dict:
    return {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "ghscan-gists/1.0",
    }


def _claim_key(gist_id: str, file_sha: str) -> str:
    return hashlib.sha256(
        f"gist:{gist_id}:{file_sha}".encode()
    ).hexdigest()[:40]


def _is_watched(filename: str) -> bool:
    leaf = filename.rsplit("/", 1)[-1]
    return leaf in _WATCH_NAMES


async def _scan_content(gist_id: str, filename: str, content: str, file_url: str):
    """Run AI + infra extractors on gist content and persist findings."""
    has_ai    = any(t in content for t in _AI_TRIGGER)
    has_infra = any(t in content for t in _INFRA_TRIGGER)
    if not has_ai and not has_infra:
        return

    full_name = f"gist:{gist_id}"   # pseudo repo name for DB storage

    if has_ai:
        for prov, fn in EXTRACTORS.items():
            for key in fn(content):
                if db.key_exists(key):
                    continue
                is_valid = await validate(prov, key)
                saved = db.save_key(
                    prov, key, full_name, filename, file_url,
                    0, "", "gists", is_valid,
                )
                if saved:
                    await notify_found(
                        prov, key, full_name, filename, file_url,
                        0, "", "gists", is_valid,
                    )
                    log.info("[gists %s] %s from gist/%s/%s",
                             "VALID" if is_valid else "found", prov, gist_id, filename)

    if has_infra:
        risk_cache = None
        for iprov, ifn in INFRA_EXTRACTORS.items():
            creds = ifn(content)
            if not creds:
                continue
            if risk_cache is None:
                risk_cache = assess_risk(content, filename, 0, "")
            risk_level, risk_reasons = risk_cache
            for cred in creds:
                if db.infra_exists(cred):
                    continue
                destination = extract_destination(cred) if "://" in cred else ""
                db.save_infra(
                    iprov, cred, full_name, filename, file_url,
                    0, "", "gists", destination, risk_level, risk_reasons,
                )
                await notify_infra_found(
                    iprov, cred, full_name, filename, file_url,
                    0, "", "gists", destination, risk_level, risk_reasons,
                )


async def _fetch_raw(client: httpx.AsyncClient, raw_url: str, token: str) -> str | None:
    """Fetch raw gist file content directly via raw_url."""
    try:
        r = await client.get(
            raw_url,
            headers=_headers(token),
            timeout=10,
        )
        if r.status_code != 200:
            return None
        return r.text
    except Exception as e:
        log.debug("gist fetch raw err [%s]: %s", raw_url, e)
        return None


async def _process_gist(client: httpx.AsyncClient, gist: dict, token: str):
    """Scan relevant files from a single gist entry."""
    gist_id  = gist.get("id", "")
    html_url = gist.get("html_url", "")
    files    = gist.get("files") or {}

    for filename, finfo in files.items():
        if not _is_watched(filename) or is_skippable_path(filename):
            continue

        file_sha = (finfo.get("filename", "") + str(finfo.get("size", ""))).encode()
        ck = _claim_key(gist_id, hashlib.sha256(file_sha).hexdigest()[:20])
        if not db.try_claim_file(ck):
            continue

        raw_url = finfo.get("raw_url", "")
        if not raw_url:
            continue

        content = await _fetch_raw(client, raw_url, token)
        if not content:
            continue

        file_url = f"{html_url}#file-{filename.replace('.', '-').replace('/', '-')}"
        await _scan_content(gist_id, filename, content, file_url)


async def _poll_gists(
    client: httpx.AsyncClient,
    token: str,
    since: str,
    etag: str,
) -> tuple[list[dict], str, str, int]:
    """Poll /gists/public?since=<since> with ETag caching.

    Returns (gists, new_since, new_etag, poll_interval_seconds).
    Empty list on 304 or error.
    """
    hdrs = dict(_headers(token))
    if etag:
        hdrs["If-None-Match"] = etag

    params: dict = {"per_page": 100}
    if since:
        params["since"] = since

    try:
        r = await client.get(
            f"{_BASE}/gists/public",
            headers=hdrs,
            params=params,
            timeout=15,
        )
        poll_interval = int(r.headers.get("X-Poll-Interval", _DEFAULT_POLL_INTERVAL))

        if r.status_code == 304:
            return [], since, etag, poll_interval

        if r.status_code in (401, 403):
            log.warning("[gists] token %s... dead/forbidden", token[:8])
            return [], since, etag, poll_interval

        if r.status_code != 200:
            log.debug("[gists] poll status=%d", r.status_code)
            return [], since, etag, poll_interval

        new_etag = r.headers.get("ETag", etag)
        gists = r.json()
        if not isinstance(gists, list) or not gists:
            return [], since, new_etag, poll_interval

        # Next poll: use the updated_at of the most recent gist as since=
        new_since = gists[0].get("updated_at", since) if gists else since
        return gists, new_since, new_etag, poll_interval

    except Exception as e:
        log.debug("[gists] poll exception: %s", e)
        return [], since, etag, _DEFAULT_POLL_INTERVAL


async def _gist_worker(token: str, worker_id: int):
    """Poll /gists/public indefinitely, process interesting gists."""
    log.info("[gists w%d token=%s...] started", worker_id, token[:8])

    # Start from last 5 minutes to catch anything we may have missed on startup
    since = (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    etag          = ""
    poll_interval = _DEFAULT_POLL_INTERVAL

    async with httpx.AsyncClient(follow_redirects=True, limits=_LIMITS) as client:
        while True:
            try:
                gists, since, etag, poll_interval = await _poll_gists(
                    client, token, since, etag
                )
                if gists:
                    log.debug("[gists w%d] %d new gists", worker_id, len(gists))
                for gist in gists:
                    try:
                        await _process_gist(client, gist, token)
                    except Exception as e:
                        log.debug("[gists w%d] process err: %s", worker_id, e)
            except Exception as e:
                log.error("[gists w%d] loop err: %s", worker_id, e)

            await asyncio.sleep(poll_interval)


async def gists_loop():
    """Start one worker per token."""
    if not GITHUB_TOKENS:
        return

    workers = [
        asyncio.create_task(
            _gist_worker(GITHUB_TOKENS[i], i),
            name=f"gists_w{i}",
        )
        for i in range(len(GITHUB_TOKENS))
    ]

    log.info("gists scanner started | %d workers | ~%ds poll",
             len(workers), _DEFAULT_POLL_INTERVAL)

    results = await asyncio.gather(*workers, return_exceptions=True)
    for r in results:
        if isinstance(r, Exception):
            log.error("gist worker crashed: %s", r)


# ── Local smoke test ──────────────────────────────────────────────────────────
# Run: python gist_scanner.py
# Polls once, prints gists with relevant filenames. No DB writes.
if __name__ == "__main__":
    import os, sys

    logging.basicConfig(level=logging.DEBUG,
                        format="%(asctime)s %(levelname)s: %(message)s")

    token = os.environ.get("GITHUB_TOKEN") or (
        GITHUB_TOKENS[0] if GITHUB_TOKENS else ""
    )
    if not token:
        print("Set GITHUB_TOKEN env var"); sys.exit(1)

    async def _smoke():
        since = (datetime.now(timezone.utc) - timedelta(minutes=30)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        async with httpx.AsyncClient(follow_redirects=True) as c:
            gists, new_since, etag, pi = await _poll_gists(c, token, since, "")
            print(f"ETag: {etag}  X-Poll-Interval: {pi}s  Gists: {len(gists)}")

            hits = 0
            for g in gists:
                files = g.get("files") or {}
                relevant = [fn for fn in files if _is_watched(fn)]
                if relevant:
                    hits += 1
                    print(f"  HIT: gist/{g['id']} files={relevant}")

            print(f"\nTotal hits (watched files in public gists): {hits}")

    asyncio.run(_smoke())
