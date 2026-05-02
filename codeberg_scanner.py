"""
Codeberg (Forgejo) scanner — finds leaked AI API keys in public repos.

Why Codeberg:
  - Privacy-focused devs, open-source AI projects — no GitHub Secret Scanning
  - Keys stay valid indefinitely (Codeberg has zero auto-revocation)
  - Forgejo API is Gitea-compatible: same code as gitee_scanner, different base URL
  - 300 req/min per token (10× more generous than GitHub search)

Architecture mirrors gitee_scanner.py:
  - Repo keyword search via /api/v1/repos/search
  - For each repo, fetches _TARGET_PATHS (same list as Gitee scanner)
  - Root listing pre-check to skip empty/docs-only repos
  - Dedup via try_claim_file(sha256("codeberg:{full_name}:{path}"))
"""

import asyncio
import base64
import hashlib
import logging
import math

import httpx

import db
from config import CODEBERG_TOKENS, CODEBERG_SCAN_INTERVAL
from patterns import EXTRACTORS, is_skippable_path
from infra_patterns import INFRA_EXTRACTORS, assess_risk, extract_destination
from validators import validate
from notifier import notify_found, notify_infra_found, notify_dead_token

log = logging.getLogger(__name__)

_BASE = "https://codeberg.org/api/v1"

_CONCURRENT_ITEMS = 8
_PAGE_SLEEP       = 1.5
_REPO_SLEEP       = 0.5
_MAX_REPO_PAGES   = 10
_SEARCH_PAGES     = 5    # 50 results/page × 5 pages = 250 repos per query

_LIMITS = httpx.Limits(
    max_connections=80,
    max_keepalive_connections=20,
    keepalive_expiry=30,
)

_TOKEN_STATUS: dict[str, dict] = {}
_DEAD_ALERTED: set[str] = set()

# Same target paths as gitee_scanner — config/env files likely to contain keys
_TARGET_PATHS: list[str] = [
    ".env",
    ".env.local",
    ".env.example",
    ".env.production",
    ".env.development",
    ".env.staging",
    ".env.backup",
    "config.py",
    "settings.py",
    "api_config.py",
    "config/config.py",
    "app/config.py",
    "src/config.py",
    "core/config.py",
    "config/settings.py",
    "config.yaml",
    "config.yml",
    "config.json",
    "config.toml",
    "config.ts",
    "config.js",
    "docker-compose.yml",
    "docker-compose.yaml",
    ".github/workflows/main.yml",
    ".github/workflows/ci.yml",
    ".github/workflows/deploy.yml",
    "Makefile",
    "application.yml",
    "application.yaml",
    "application.properties",
    "application-dev.yml",
    "application-prod.yml",
    "bootstrap.yml",
    "appsettings.json",
    "appsettings.Development.json",
    "llm_config.yaml",
    "model_config.json",
    "deploy/.env",
    # Python notebook files — common on Codeberg AI projects
    "notebook.ipynb",
    "demo.ipynb",
    "main.ipynb",
    "train.ipynb",
]

# Keyword search queries for Codeberg repo search
# Codeberg searches repo name, description, and topics
_SEARCH_QUERIES: list[str] = [
    # Universal provider env var names
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "TOGETHER_API_KEY",
    "GROQ_API_KEY",
    "CEREBRAS_API_KEY",
    "REPLICATE_API_TOKEN",
    "HUGGINGFACE_TOKEN",
    "FIREWORKS_API_KEY",
    "OPENROUTER_API_KEY",
    "MISTRAL_API_KEY",
    "COHERE_API_KEY",
    "PERPLEXITY_API_KEY",
    "FAL_KEY",
    "DEEPSEEK_API_KEY",
    # AI provider / framework topics
    "langchain",
    "llm-api",
    "openai-api",
    "groq-api",
    "huggingface",
    "llama-cpp",
    "ollama",
    "llm-wrapper",
    "ai-assistant",
    "chatbot-api",
    "text-generation",
    "inference-api",
    "mistral",
    "cerebras",
    "together-ai",
    # German/European open-source AI community (Codeberg has strong DE community)
    "ki-api",  # German: KI = AI
    "sprachmodell",  # German: language model
    "llm-projekt",
]

_AI_TRIGGER = (
    "sk-", "AIzaSy", "eyJ",
    "hf_", "pplx-", "xai-", "r8_",
    "gsk_", "fw_", "sk-or-v1", "csk-",
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "TOGETHER_API_KEY",
    "GROQ_API_KEY", "CEREBRAS_API_KEY",
    "DEEPSEEK", "deepseek",
    "ARK_API", "DOUBAO",
    "ZHIPUAI", "zhipuai", "moonshot", "MOONSHOT",
    "klingai", "KLINGAI", "KLING_",
    "VOLCSTACK", "VOLCENGINE_API", "VOLC_ACCESSKEY",
    "MISTRAL", "COHERE",
)
_INFRA_TRIGGER = (
    "://", "BEGIN PRIVATE KEY", "BEGIN RSA", "BEGIN OPENSSH",
    "AKIA", "AIPA", "AIDA", "AROA", "ASIA",
)


def _headers(token: str) -> dict:
    return {
        "Authorization": f"token {token}",
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        ),
    }


def _claim_key(full_name: str, path: str) -> str:
    return hashlib.sha256(f"codeberg:{full_name}:{path}".encode()).hexdigest()[:40]


async def _check_token(client: httpx.AsyncClient, token: str) -> bool:
    for attempt in range(2):
        try:
            r = await client.get(
                f"{_BASE}/user", headers=_headers(token), timeout=12
            )
            if r.status_code == 200:
                _TOKEN_STATUS[hashlib.sha256(token.encode()).hexdigest()[:12]] = {"alive": True}
                return True
            if r.status_code in (401, 403):
                _TOKEN_STATUS[hashlib.sha256(token.encode()).hexdigest()[:12]] = {"alive": False}
                return False
            _TOKEN_STATUS[hashlib.sha256(token.encode()).hexdigest()[:12]] = {"alive": True}
            return True
        except Exception as e:
            if attempt == 0:
                await asyncio.sleep(3)
                continue
            log.debug("codeberg check_token exception (treating as alive): %s", e)
            _TOKEN_STATUS[hashlib.sha256(token.encode()).hexdigest()[:12]] = {"alive": True}
            return True
    return True


async def _search_repos(client: httpx.AsyncClient,
                        query: str, token: str) -> list[dict]:
    """Search public repos by keyword."""
    all_repos: list[dict] = []

    for page in range(1, _SEARCH_PAGES + 1):
        try:
            r = await client.get(
                f"{_BASE}/repos/search",
                headers=_headers(token),
                params={
                    "q":        query,
                    "limit":    50,
                    "page":     page,
                    "sort":     "updated",
                    "order":    "desc",
                    "is_private": False,
                },
                timeout=20,
            )
            if r.status_code in (401, 403):
                _TOKEN_STATUS[hashlib.sha256(token.encode()).hexdigest()[:12]] = {"alive": False}
                break
            if r.status_code != 200:
                break
            data = r.json()
            batch = data.get("data", []) if isinstance(data, dict) else (
                data if isinstance(data, list) else []
            )
            if not batch:
                break
            all_repos.extend(batch)
            if len(batch) < 50:
                break
            await asyncio.sleep(_PAGE_SLEEP)
        except Exception as e:
            log.debug("codeberg search err [%s]: %s", query[:40], e)
            break

    return all_repos


async def _get_file(client: httpx.AsyncClient,
                    full_name: str, path: str, token: str) -> str | None:
    """Fetch a single file from a Codeberg repo."""
    ck = _claim_key(full_name, path)
    if not db.try_claim_file(ck):
        return None

    try:
        r = await client.get(
            f"{_BASE}/repos/{full_name}/contents/{path}",
            headers=_headers(token),
            timeout=15,
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
        log.debug("codeberg get_file err [%s/%s]: %s", full_name, path, e)
        return None


_INTERESTING_ROOT_FILES = frozenset({
    ".env", ".env.local", ".env.example", ".env.production",
    ".env.development", ".env.staging",
    "config.py", "settings.py", "api_config.py",
    "config.yaml", "config.yml", "config.json", "config.toml",
    "config.ts", "config.js",
    "docker-compose.yml", "docker-compose.yaml",
    "Makefile", "application.yml", "application.yaml",
    "application.properties", "appsettings.json",
    "llm_config.yaml", "model_config.json",
    "notebook.ipynb", "demo.ipynb", "main.ipynb",
})
_INTERESTING_ROOT_DIRS = frozenset({
    "config", "src", "app", "core", "deploy",
    ".github", "conf", "settings", "notebooks",
})


async def _has_interesting_root(client: httpx.AsyncClient,
                                full_name: str, token: str) -> bool:
    """Pre-check repo root to skip pure-docs/empty repos."""
    try:
        r = await client.get(
            f"{_BASE}/repos/{full_name}/contents/",
            headers=_headers(token),
            timeout=10,
        )
        if r.status_code != 200:
            return True
        entries = r.json()
        if not isinstance(entries, list):
            return True
        for entry in entries:
            name = entry.get("name", "")
            kind = entry.get("type", "")
            if kind == "file" and name in _INTERESTING_ROOT_FILES:
                return True
            if kind == "dir" and name in _INTERESTING_ROOT_DIRS:
                return True
        return False
    except Exception:
        return True


async def _scan_file(full_name: str, path: str, content: str, stars: int, file_url: str):
    """Run extractors on file content."""
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
                    stars, "", "codeberg", is_valid,
                )
                if saved:
                    await notify_found(
                        prov, key, full_name, path, file_url,
                        stars, "", "codeberg", is_valid,
                    )
                    log.info("[codeberg %s] %s from %s/%s",
                             "VALID" if is_valid else "found", prov, full_name, path)

    if has_infra:
        risk_cache = None
        for iprov, ifn in INFRA_EXTRACTORS.items():
            creds = ifn(content)
            if not creds:
                continue
            if risk_cache is None:
                risk_cache = assess_risk(content, path, stars, "")
            risk_level, risk_reasons = risk_cache
            for cred in creds:
                if db.infra_exists(cred):
                    continue
                destination = extract_destination(cred) if "://" in cred else ""
                db.save_infra(
                    iprov, cred, full_name, path, file_url,
                    stars, "", "codeberg", destination, risk_level, risk_reasons,
                )
                await notify_infra_found(
                    iprov, cred, full_name, path, file_url,
                    stars, "", "codeberg", destination, risk_level, risk_reasons,
                )


async def _scan_repo(client: httpx.AsyncClient, repo: dict,
                     sem: asyncio.Semaphore, token: str):
    """Fetch and scan all target file paths in a repo."""
    full_name = repo.get("full_name", "")
    if not full_name:
        return

    async with sem:
        interesting = await _has_interesting_root(client, full_name, token)
    if not interesting:
        log.debug("codeberg skip (no interesting root): %s", full_name)
        return

    stars    = repo.get("stars_count", 0) or 0
    base_url = f"https://codeberg.org/{full_name}/raw/branch/main"

    async def fetch_one(path: str):
        if is_skippable_path(path):
            return
        async with sem:
            content = await _get_file(client, full_name, path, token)
        if content:
            file_url = f"https://codeberg.org/{full_name}/src/branch/main/{path}"
            await _scan_file(full_name, path, content, stars, file_url)

    tasks = [asyncio.create_task(fetch_one(p)) for p in _TARGET_PATHS]
    await asyncio.gather(*tasks, return_exceptions=True)


async def _run_worker(token: str, queries: list[str],
                      worker_id: int, sem: asyncio.Semaphore,
                      client: httpx.AsyncClient):
    alive = await _check_token(client, token)
    if not alive:
        tk = token[:12]
        if tk not in _DEAD_ALERTED:
            _DEAD_ALERTED.add(tk)
            await notify_dead_token(f"codeberg:{tk}")
        log.error("[codeberg w%d token=%s...] DEAD — skipped", worker_id, token[:12])
        return

    log.info("[codeberg w%d token=%s...] %d search queries",
             worker_id, token[:12], len(queries))

    scanned: set[str] = set()

    for query in queries:
        repos = await _search_repos(client, query, token)
        new_repos = [r for r in repos if r.get("full_name") not in scanned]
        if not new_repos:
            log.debug("[codeberg w%d] query '%s' → all already scanned", worker_id, query[:40])
            continue

        log.info("[codeberg w%d] query '%s' → %d new repos",
                 worker_id, query[:40], len(new_repos))

        for repo in new_repos:
            fn = repo.get("full_name", "")
            if fn:
                scanned.add(fn)
            await _scan_repo(client, repo, sem, token)
            await asyncio.sleep(_REPO_SLEEP)

        await asyncio.sleep(_PAGE_SLEEP)


async def run_codeberg_cycle():
    if not CODEBERG_TOKENS:
        return

    n = len(CODEBERG_TOKENS)
    query_chunks: list[list[str]] = [[] for _ in range(n)]
    for i, q in enumerate(_SEARCH_QUERIES):
        query_chunks[i % n].append(q)

    log.info("=== codeberg cycle start | %d tokens | %d queries ===",
             n, len(_SEARCH_QUERIES))

    sem = asyncio.Semaphore(_CONCURRENT_ITEMS)

    async with httpx.AsyncClient(follow_redirects=True, limits=_LIMITS) as client:
        workers = [
            asyncio.create_task(
                _run_worker(CODEBERG_TOKENS[i], query_chunks[i], i, sem, client),
                name=f"codeberg_w{i}",
            )
            for i in range(n)
            if query_chunks[i]
        ]
        results = await asyncio.gather(*workers, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                log.error("codeberg worker crashed: %s", r)

    log.info("=== codeberg cycle done ===")


async def codeberg_loop():
    if not CODEBERG_TOKENS:
        log.info("codeberg: no CODEBERG_TOKENS configured — skipping")
        return

    log.info("codeberg scanner started | %d tokens | %d queries | interval=%ds",
             len(CODEBERG_TOKENS), len(_SEARCH_QUERIES), CODEBERG_SCAN_INTERVAL)

    while True:
        try:
            await run_codeberg_cycle()
        except Exception as e:
            log.error("codeberg cycle crashed: %s", e)
        log.info("codeberg sleeping %ds until next cycle", CODEBERG_SCAN_INTERVAL)
        await asyncio.sleep(CODEBERG_SCAN_INTERVAL)
