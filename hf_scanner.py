"""
HuggingFace Spaces scanner — finds leaked AI API keys in public Spaces apps.

Why HuggingFace Spaces:
  - Gradio/Streamlit demos routinely hardcode API keys for quick prototyping
  - No GitHub Secret Scanning → keys stay valid
  - ~400k+ public Spaces, ~5k+ created/updated per day
  - High density of Cerebras, Together, Groq, OpenRouter, OpenAI keys
  - Most developers don't realize their Space source is public

Architecture:
  - Lists Spaces sorted by recently modified (catches fresh leaks) + trending
  - For each Space, fetches key files (app.py, .env, config.py, utils.py…)
  - Dedup via try_claim_file(sha256("hf:{space_id}:{filepath}"))
  - Single HF_TOKEN (read scope), rate limit ~1000 req/min

Rate limits (HuggingFace):
  - /api/spaces list: generous, no strict limit documented
  - File fetch: ~300-500 req/min with token
"""

import asyncio
import hashlib
import logging

import httpx

import db
from config import HF_TOKEN, HF_SCAN_INTERVAL
from patterns import EXTRACTORS, is_skippable_path, AI_TRIGGER, INFRA_TRIGGER
from infra_patterns import INFRA_EXTRACTORS, assess_risk, extract_destination
from validators import validate
from notifier import notify_found, notify_infra_found

log = logging.getLogger(__name__)

_BASE          = "https://huggingface.co"
_API_BASE      = "https://huggingface.co/api"
_SPACES_LIMIT  = 500    # spaces per list request
_FILE_TIMEOUT  = 10     # seconds per file fetch
_CONCURRENT    = 8      # parallel file fetches
_FILE_SIZE_MAX = 512_000  # skip files > 512KB (minified JS, model weights, etc.)

_LIMITS = httpx.Limits(
    max_connections=60,
    max_keepalive_connections=20,
    keepalive_expiry=30,
)

# Files to try in every Space (ordered by likelihood of containing keys)
_TARGET_FILES: list[str] = [
    "app.py",
    ".env",
    ".env.example",
    "main.py",
    "config.py",
    "settings.py",
    "utils.py",
    "helpers.py",
    "src/app.py",
    "src/main.py",
    "src/config.py",
    "api.py",
    "backend.py",
    "server.py",
    "app.ipynb",
    "notebook.ipynb",
    "demo.py",
    "inference.py",
    "model.py",
    "llm.py",
    "chatbot.py",
    "gradio_app.py",
]

# HF Spaces extra heuristics: catch generic os.environ[...] / os.getenv(...) refs
# to a key. Narrower than bare "os.environ" (which is in 90% of Python files).
_HF_EXTRA_TRIGGERS = ("os.environ[", "os.getenv(")
_AI_TRIGGER = AI_TRIGGER + _HF_EXTRA_TRIGGERS
_INFRA_TRIGGER = INFRA_TRIGGER


def _headers() -> dict:
    return {
        "Authorization": f"Bearer {HF_TOKEN}",
        "User-Agent": "Mozilla/5.0 (compatible; ghscan/1.0)",
    }


def _claim_key(space_id: str, filepath: str) -> str:
    return hashlib.sha256(f"hf:{space_id}:{filepath}".encode()).hexdigest()[:40]


async def _check_token(client: httpx.AsyncClient) -> bool:
    try:
        r = await client.get(
            f"{_API_BASE}/whoami-v2", headers=_headers(), timeout=10
        )
        return r.status_code == 200
    except Exception:
        return True  # network hiccup — assume alive, will surface on first list call


async def _list_spaces(client: httpx.AsyncClient,
                       sort: str = "modified") -> list[dict]:
    """Fetch a page of public Spaces sorted by `sort`."""
    try:
        r = await client.get(
            f"{_API_BASE}/spaces",
            headers=_headers(),
            params={
                "limit":     _SPACES_LIMIT,
                "sort":      sort,
                "direction": -1,
                "full":      "false",
            },
            timeout=20,
        )
        if r.status_code in (401, 403):
            log.warning("[hf] token unauthorized (check HF_TOKEN scope)")
            return []
        if r.status_code != 200:
            log.debug("[hf] list status=%d sort=%s", r.status_code, sort)
            return []
        data = r.json()
        return data if isinstance(data, list) else []
    except Exception as e:
        log.debug("[hf] list err: %s", e)
        return []


async def _fetch_file(client: httpx.AsyncClient,
                      space_id: str, filepath: str) -> str | None:
    """Fetch raw file content from a HuggingFace Space."""
    owner, repo = (space_id.split("/", 1) + [""])[:2]
    if not owner or not repo:
        return None

    # HF raw file URL: /spaces/{owner}/{repo}/resolve/main/{filepath}
    url = f"{_BASE}/spaces/{owner}/{repo}/resolve/main/{filepath}"
    try:
        r = await client.get(
            url, headers=_headers(), timeout=_FILE_TIMEOUT, follow_redirects=True
        )
        if r.status_code == 404:
            return None
        if r.status_code in (401, 403):
            return None
        if r.status_code != 200:
            log.debug("[hf] file status=%d %s/%s", r.status_code, space_id, filepath)
            return None
        if len(r.content) > _FILE_SIZE_MAX:
            return None
        return r.text
    except Exception as e:
        log.debug("[hf] fetch err %s/%s: %s", space_id, filepath, e)
        return None


async def _scan_content(space_id: str, filepath: str, content: str):
    """Run extractors on Space file content."""
    has_ai    = any(t in content for t in _AI_TRIGGER)
    has_infra = any(t in content for t in _INFRA_TRIGGER)
    if not has_ai and not has_infra:
        return

    file_url   = f"{_BASE}/spaces/{space_id}/blob/main/{filepath}"
    repo_label = space_id

    if has_ai:
        for prov, fn in EXTRACTORS.items():
            for key in fn(content):
                if db.key_exists(key):
                    continue
                is_valid = await validate(prov, key)
                saved = db.save_key(
                    prov, key, repo_label, filepath, file_url,
                    0, "", "hf_spaces", is_valid,
                )
                if saved:
                    await notify_found(
                        prov, key, repo_label, filepath, file_url,
                        0, "", "hf_spaces", is_valid,
                    )
                    log.info("[hf %s] %s from %s/%s",
                             "VALID" if is_valid else "found", prov, space_id, filepath)

    if has_infra:
        risk_cache = None
        for iprov, ifn in INFRA_EXTRACTORS.items():
            creds = ifn(content)
            if not creds:
                continue
            if risk_cache is None:
                risk_cache = assess_risk(content, filepath, 0, "")
            risk_level, risk_reasons = risk_cache
            for cred in creds:
                if db.infra_exists(cred):
                    continue
                destination = extract_destination(cred) if "://" in cred else ""
                db.save_infra(
                    iprov, cred, repo_label, filepath, file_url,
                    0, "", "hf_spaces", destination, risk_level, risk_reasons,
                )
                await notify_infra_found(
                    iprov, cred, repo_label, filepath, file_url,
                    0, "", "hf_spaces", destination, risk_level, risk_reasons,
                )


_INTERESTING_EXT = (
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".env", ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg",
    ".ipynb", ".md", ".sh",
)


async def _list_space_tree(client: httpx.AsyncClient, space_id: str) -> list[str]:
    """Get the full file list of a Space via /api/spaces/{id}/tree/main?recursive=true.
    Returns paths only — much more efficient than probing 21 fixed filenames since
    most Spaces have unique directory layouts."""
    paths: list[str] = []
    url = f"{_API_BASE}/spaces/{space_id}/tree/main"
    next_url = url + "?recursive=true&expand=false"
    for _ in range(5):  # cap pagination
        try:
            r = await client.get(next_url, headers=_headers(), timeout=15)
            if r.status_code != 200:
                return paths
            data = r.json()
            entries = data if isinstance(data, list) else data.get("siblings", [])
            for e in entries:
                if not isinstance(e, dict):
                    continue
                if e.get("type") != "file":
                    continue
                p = e.get("path", "")
                if not p or len(p) > 200:
                    continue
                # Filter to interesting extensions/names
                if p.endswith(_INTERESTING_EXT) or p.split("/")[-1] in {
                    ".env", "Dockerfile", "Procfile", "Makefile",
                    "requirements.txt", "package.json"
                }:
                    paths.append(p)
            # Pagination: HF uses Link headers occasionally
            link = r.headers.get("Link", "")
            if 'rel="next"' in link:
                import re as _re
                m = _re.search(r'<([^>]+)>;\s*rel="next"', link)
                if m:
                    next_url = m.group(1)
                    continue
            break
        except Exception as e:
            log.debug("[hf] tree err %s: %s", space_id, e)
            break
    return paths


async def _scan_space(client: httpx.AsyncClient,
                      space: dict, sem: asyncio.Semaphore):
    """Fetch and scan all interesting files in a Space (via tree listing)."""
    space_id = space.get("id", "")
    if not space_id or "/" not in space_id:
        return

    paths = await _list_space_tree(client, space_id)
    if not paths:
        # Fallback to fixed list when tree API fails
        paths = _TARGET_FILES

    # Cap paths to scan (very large Spaces could have hundreds of files)
    paths = paths[:60]

    async def fetch_one(filepath: str):
        if is_skippable_path(filepath):
            return
        ck = _claim_key(space_id, filepath)
        if not db.try_claim_file(ck):
            return
        async with sem:
            content = await _fetch_file(client, space_id, filepath)
        if content:
            await _scan_content(space_id, filepath, content)

    tasks = [asyncio.create_task(fetch_one(f)) for f in paths]
    await asyncio.gather(*tasks, return_exceptions=True)


async def run_hf_cycle():
    if not HF_TOKEN:
        return

    log.info("=== hf_spaces cycle start ===")

    sem = asyncio.Semaphore(_CONCURRENT)

    async with httpx.AsyncClient(follow_redirects=False, limits=_LIMITS) as client:
        if not await _check_token(client):
            log.error("[hf] token dead (401 on /api/whoami-v2) — skipping cycle")
            return

        # Two passes: recently modified (fresh leaks) + trending (popular repos)
        all_spaces: list[dict] = []
        seen_ids: set[str] = set()

        for sort in ("modified", "trendingScore"):
            batch = await _list_spaces(client, sort=sort)
            for s in batch:
                sid = s.get("id", "")
                if sid and sid not in seen_ids:
                    seen_ids.add(sid)
                    all_spaces.append(s)

        log.info("[hf] %d unique spaces to scan", len(all_spaces))

        for space in all_spaces:
            try:
                await _scan_space(client, space, sem)
            except Exception as e:
                log.debug("[hf] space scan err %s: %s", space.get("id"), e)

    log.info("=== hf_spaces cycle done ===")


async def hf_loop():
    if not HF_TOKEN:
        log.info("hf_spaces: no HF_TOKEN configured — skipping")
        return

    log.info("hf_spaces scanner started | interval=%ds | %d files/space",
             HF_SCAN_INTERVAL, len(_TARGET_FILES))

    while True:
        try:
            await run_hf_cycle()
        except Exception as e:
            log.error("hf_spaces cycle crashed: %s", e)
        log.info("hf_spaces sleeping %ds until next cycle", HF_SCAN_INTERVAL)
        await asyncio.sleep(HF_SCAN_INTERVAL)
