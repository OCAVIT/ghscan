"""
Kaggle notebooks scanner — finds leaked AI API keys in public Jupyter notebooks.

Why Kaggle:
  - Data scientists routinely hardcode API keys in notebooks shared publicly
  - No GitHub Secret Scanning partnership → keys stay valid much longer
  - Cerebras, Together, Groq, HuggingFace, OpenRouter keys at high density
  - ~10M public notebooks, growing fast with AI competition wave

Architecture:
  - REST search API (Bearer KGAT_ token) to find relevant notebooks by keyword
  - kaggle Python package for downloading .ipynb source (handles gRPC auth)
  - Parses all cell sources + outputs from .ipynb JSON
  - Dedup via try_claim_file(sha256("kaggle:{owner}/{slug}"))
  - One worker per KGAT_ token, queries distributed round-robin

Rate limits (Kaggle):
  - Search: no documented limit, ~60 req/min observed safe
  - Pull: ~1 per second per account is safe
"""

import asyncio
import hashlib
import json
import base64
import logging
import os
import tempfile

import httpx

import db
from config import KAGGLE_TOKENS, KAGGLE_SCAN_INTERVAL
from patterns import EXTRACTORS, AI_TRIGGER
from deobfuscate import expand as _deobf_expand
from validators import validate
from notifier import notify_found

log = logging.getLogger(__name__)

_BASE         = "https://www.kaggle.com/api/v1"

# Legacy Basic auth (KAGGLE_USERNAME + KAGGLE_KEY from kaggle.json) takes
# precedence — Kaggle's REST API endpoints (/api/v1/*) require Basic auth,
# the new "KGAT_*" tokens are for the SDK only and return 404 against /api/v1.
#
# Multi-account: KAGGLE_USERNAME and KAGGLE_KEY can each be a comma-separated
# list of equal length — pairwise zip into multiple Basic-auth strings. Each
# worker picks its own credentials round-robin → distributes search rate across
# accounts and lets us scan more queries per cycle without hitting per-account
# rate limits.
_kg_users = [u.strip() for u in os.environ.get("KAGGLE_USERNAME", "").split(",") if u.strip()]
_kg_keys  = [k.strip() for k in os.environ.get("KAGGLE_KEY",      "").split(",") if k.strip()]
_BASIC_AUTHS: list[str] = []
if _kg_users and _kg_keys and len(_kg_users) == len(_kg_keys):
    for u, k in zip(_kg_users, _kg_keys):
        _BASIC_AUTHS.append("Basic " + base64.b64encode(f"{u}:{k}".encode()).decode())
_PULL_SLEEP   = 1.5   # seconds between pulls per token
_SEARCH_SLEEP = 2.0   # seconds between search queries
_MAX_PAGES    = 3     # search pages per query (20 results/page = 60 notebooks)
_LANGUAGES    = ["python", "r"]  # R community uses openai/ellmer R packages

_LIMITS = httpx.Limits(
    max_connections=40,
    max_keepalive_connections=10,
    keepalive_expiry=30,
)

# Search queries — match notebook titles/descriptions that suggest AI key presence.
# Kaggle search indexes title, subtitle, tags, and (partially) source code.
_QUERIES: list[str] = [
    # Env var names — most likely to be in code comments / markdown cells too
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "TOGETHER_API_KEY",
    "GROQ_API_KEY",
    "CEREBRAS_API_KEY",
    "REPLICATE_API_TOKEN",
    "HF_TOKEN huggingface",
    "FIREWORKS_API_KEY",
    "OPENROUTER_API_KEY",
    "MISTRAL_API_KEY",
    "COHERE_API_KEY",
    "PERPLEXITY_API_KEY",
    "FAL_KEY",
    "DEEPSEEK_API_KEY",
    # Common integration patterns
    "langchain openai api key",
    "openai api key tutorial",
    "huggingface inference api token",
    "replicate api python",
    "fireworks ai python",
    "openrouter api",
    # Notebook title patterns where devs often hardcode
    "llm api keys notebook",
    "ai provider api",
    "inference api notebook",
]

# AI trigger strings for fast pre-scan (avoids running full regex on irrelevant cells)
_AI_TRIGGER = AI_TRIGGER


def _headers(token: str) -> dict:
    """Build Authorization header. Prefers KAGGLE_USERNAME+KAGGLE_KEY Basic
    auth (the only scheme accepted by /api/v1 endpoints); falls back to
    Bearer KGAT for backwards compat (will likely 404 but won't crash).

    `token` is repurposed: when Basic auths are configured, it's interpreted
    as the index hint to pick a Basic-auth string (round-robin per worker).
    Otherwise it's the literal Bearer token.
    """
    if _BASIC_AUTHS:
        # Worker token is "basic:<idx>:<username>" — parse idx for stable
        # per-worker assignment (each worker uses its own account end-to-end).
        idx = 0
        if token and token.startswith("basic:"):
            try:
                idx = int(token.split(":", 2)[1]) % len(_BASIC_AUTHS)
            except Exception:
                idx = 0
        return {"Authorization": _BASIC_AUTHS[idx], "Content-Type": "application/json"}
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def _claim_key(ref: str) -> str:
    """Dedup key for a Kaggle notebook (owner/slug)."""
    return hashlib.sha256(f"kaggle:{ref}".encode()).hexdigest()[:40]


def _extract_notebook_text(ipynb_content: str) -> str:
    """Extract all source + output text from a .ipynb file."""
    try:
        nb = json.loads(ipynb_content)
    except Exception:
        return ipynb_content

    parts: list[str] = []
    for cell in nb.get("cells", []):
        src = cell.get("source", [])
        if isinstance(src, list):
            parts.append("".join(src))
        elif isinstance(src, str):
            parts.append(src)

        # Also scan outputs — devs sometimes print keys accidentally
        for out in cell.get("outputs", []):
            text = out.get("text", [])
            if isinstance(text, list):
                parts.append("".join(text))
            elif isinstance(text, str):
                parts.append(text)
            data = out.get("data", {})
            for val in data.values():
                if isinstance(val, list):
                    parts.append("".join(str(v) for v in val))
                elif isinstance(val, str):
                    parts.append(val)

    return "\n".join(parts)


async def _search_kernels(client: httpx.AsyncClient,
                          token: str, query: str, page: int,
                          language: str = "python") -> list[dict]:
    """Search Kaggle kernels by keyword. Returns list of kernel refs."""
    try:
        r = await client.get(
            f"{_BASE}/kernels/list",
            headers=_headers(token),
            params={
                "search":    query,
                "page":      page,
                "pageSize":  20,
                "sortBy":    "hotness",
                "language":  language,
            },
            timeout=20,
        )
        if r.status_code in (401, 403):
            log.warning("[kaggle] token %s... dead/forbidden", token[:12])
            return []
        if r.status_code != 200:
            log.debug("[kaggle] search status=%d query=%r", r.status_code, query[:40])
            return []
        data = r.json()
        if not isinstance(data, list):
            return []
        return data
    except Exception as e:
        log.debug("[kaggle] search err query=%r: %s", query[:40], e)
        return []


def _pull_kernel_sync(token: str, ref: str, tmpdir: str) -> str | None:
    """
    Synchronous kaggle package kernel pull. Runs in asyncio.to_thread().
    Uses KAGGLE_API_TOKEN env var which the package reads via get_access_token_from_env().
    """
    old_token = os.environ.get("KAGGLE_API_TOKEN", "")
    try:
        os.environ["KAGGLE_API_TOKEN"] = token
        from kaggle.api.kaggle_api_extended import KaggleApi
        api = KaggleApi()
        api.authenticate()
        api.kernels_pull(ref, path=tmpdir, quiet=True)

        files = os.listdir(tmpdir)
        if not files:
            return None
        fpath = os.path.join(tmpdir, files[0])
        with open(fpath, encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception as e:
        log.debug("[kaggle] pull err ref=%s: %s", ref, e)
        return None
    finally:
        if old_token:
            os.environ["KAGGLE_API_TOKEN"] = old_token
        else:
            os.environ.pop("KAGGLE_API_TOKEN", None)


async def _fetch_kernel_source(token: str, ref: str) -> str | None:
    """Download kernel source in a thread to avoid blocking the event loop."""
    with tempfile.TemporaryDirectory() as tmpdir:
        return await asyncio.to_thread(_pull_kernel_sync, token, ref, tmpdir)


async def _scan_notebook(ref: str, content: str):
    """Run extractors on notebook content and persist findings."""
    text = _extract_notebook_text(content)
    text = _deobf_expand(text)
    if not any(t in text for t in _AI_TRIGGER):
        return

    owner, slug = (ref.split("/", 1) + [""])[:2]
    file_url = f"https://www.kaggle.com/{ref}"
    repo_label = ref  # use ref as repo identifier in DB

    for prov, fn in EXTRACTORS.items():
        for key in fn(text):
            if db.key_exists(key):
                continue
            is_valid = await validate(prov, key)
            saved = db.save_key(
                prov, key, repo_label, "notebook.ipynb", file_url,
                0, "", "kaggle", is_valid,
            )
            if saved:
                await notify_found(
                    prov, key, repo_label, "notebook.ipynb", file_url,
                    0, "", "kaggle", is_valid,
                )
                log.info("[kaggle %s] %s from %s",
                         "VALID" if is_valid else "found", prov, ref)


async def _run_worker(token: str, queries: list[str], worker_id: int):
    """Search + pull worker for one Kaggle token."""
    log.info("[kaggle w%d token=%s...] %d queries", worker_id, token[:12], len(queries))

    async with httpx.AsyncClient(follow_redirects=True, limits=_LIMITS) as client:
        scanned: set[str] = set()

        for query in queries:
            for lang in _LANGUAGES:
                for page in range(1, _MAX_PAGES + 1):
                    kernels = await _search_kernels(client, token, query, page, lang)
                    if not kernels:
                        break

                    for k in kernels:
                        ref = k.get("ref", "")
                        if not ref or ref in scanned:
                            continue

                        ck = _claim_key(ref)
                        if not db.try_claim_file(ck):
                            continue

                        scanned.add(ref)
                        content = await _fetch_kernel_source(token, ref)
                        if content:
                            await _scan_notebook(ref, content)

                        await asyncio.sleep(_PULL_SLEEP)

                    if len(kernels) < 20:
                        break
                    await asyncio.sleep(_SEARCH_SLEEP)

            await asyncio.sleep(_SEARCH_SLEEP)

    log.info("[kaggle w%d] cycle done, %d unique notebooks processed",
             worker_id, len(scanned))


def _worker_tokens() -> list[str]:
    """Pick the per-worker auth identity list. Prefers Basic-auth pairs
    (KAGGLE_USERNAME/KAGGLE_KEY) since /api/v1 only accepts Basic; falls
    back to KGAT KAGGLE_TOKENS otherwise. Each entry maps to one worker
    that uses that account's auth via _headers()."""
    if _BASIC_AUTHS:
        # Use a stable, distinct synthetic token per Basic-auth pair.
        # _headers() hashes this to select the right auth string.
        return [f"basic:{i}:{_kg_users[i]}" for i in range(len(_BASIC_AUTHS))]
    return list(KAGGLE_TOKENS)


async def run_kaggle_cycle():
    workers_auth = _worker_tokens()
    if not workers_auth:
        return

    n = len(workers_auth)
    chunks: list[list[str]] = [[] for _ in range(n)]
    for i, q in enumerate(_QUERIES):
        chunks[i % n].append(q)

    auth_kind = "basic" if _BASIC_AUTHS else "kgat"
    log.info("=== kaggle cycle start | %d %s accounts | %d queries ===",
             n, auth_kind, len(_QUERIES))

    workers = [
        asyncio.create_task(
            _run_worker(workers_auth[i], chunks[i], i),
            name=f"kaggle_w{i}",
        )
        for i in range(n)
        if chunks[i]
    ]
    results = await asyncio.gather(*workers, return_exceptions=True)
    for r in results:
        if isinstance(r, Exception):
            log.error("kaggle worker crashed: %s", r)

    log.info("=== kaggle cycle done ===")


async def kaggle_loop():
    if not KAGGLE_TOKENS and not _BASIC_AUTHS:
        log.info("kaggle: no KAGGLE_TOKENS or KAGGLE_USERNAME/KEY configured — skipping")
        return

    n_accounts = len(_BASIC_AUTHS) if _BASIC_AUTHS else len(KAGGLE_TOKENS)
    auth_kind  = "basic" if _BASIC_AUTHS else "kgat"
    log.info("kaggle scanner started | %d %s accounts | %d queries | interval=%ds",
             n_accounts, auth_kind, len(_QUERIES), KAGGLE_SCAN_INTERVAL)

    while True:
        try:
            await run_kaggle_cycle()
        except Exception as e:
            log.error("kaggle cycle crashed: %s", e)
        log.info("kaggle sleeping %ds until next cycle", KAGGLE_SCAN_INTERVAL)
        await asyncio.sleep(KAGGLE_SCAN_INTERVAL)
