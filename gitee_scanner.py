"""
Gitee (gitee.com) scanner — org/user enumeration + repo keyword search + targeted file fetch.

Gitee has NO public code search API (unlike GitHub /search/code).
This scanner works by:
  1. Enumerating repos of known Chinese AI orgs + users
  2. Keyword search via /api/v5/search/repositories (no auth required, finds
     community repos outside org namespaces — students, startups, forks)
  3. Fetching known config/env paths in each repo
  4. Running the same extractors/validators as the GitHub scanner

Covered orgs: DeepSeek, Baidu PaddlePaddle, Zhipu AI (THUDM), Moonshot,
ByteDance/Volcengine, Huawei MindSpore, Alibaba ModelScope, + community forks.

Why Gitee despite API limitations:
  - Chinese AI developer repos absent from GitHub code search
  - Keys stay valid much longer (slower rotation in Chinese AI startups)
  - GLM, Kimi, KLING, DeepSeek, ARK keys at high density
  - Zero competition from other security scanners
"""

import asyncio
import base64
import hashlib
import logging

import httpx

import db
from config import GITEE_TOKENS, GITEE_SCAN_INTERVAL, evomi_proxy_url
from patterns import EXTRACTORS, is_skippable_path
from infra_patterns import INFRA_EXTRACTORS, assess_risk, extract_destination
from validators import validate
from notifier import notify_found, notify_infra_found, notify_dead_token

log = logging.getLogger(__name__)

_BASE = "https://gitee.com/api/v5"

_CONCURRENT_ITEMS = 6    # parallel file fetches per worker
_PAGE_SLEEP       = 2    # seconds between repo-listing pages
_REPO_SLEEP       = 1    # seconds between repos in same org
_MAX_REPO_PAGES   = 10   # max pages per org (100 repos/page = 1000 repos)
_SEARCH_PAGES     = 3    # max pages per search query (100/page = 300 repos)

_LIMITS = httpx.Limits(
    max_connections=80,
    max_keepalive_connections=20,
    keepalive_expiry=30,
)

_TOKEN_STATUS: dict[str, dict] = {}
_DEAD_ALERTED: set[str] = set()

# Common config/env file paths to check in every repo
_TARGET_PATHS = [
    ".env",
    ".env.local",
    ".env.example",
    ".env.production",
    ".env.development",
    ".env.staging",
    "config.py",
    "settings.py",
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
    # Spring Boot / Java (common in Chinese enterprise AI projects)
    "application.yml",
    "application.yaml",
    "application.properties",
    "application-dev.yml",
    "application-prod.yml",
    "bootstrap.yml",
    "src/main/resources/application.yml",
    "src/main/resources/application.properties",
    # .NET
    "appsettings.json",
    "appsettings.Development.json",
]

# Keyword queries for /api/v5/search/repositories — catches community repos
# outside known org namespaces (students, startups, independent developers).
# No auth required for this endpoint.
_SEARCH_QUERIES = [
    "seedance",
    "doubao",
    "volcengine",
    "ark_api_key",
    "VOLC_ACCESSKEY",
    "VOLCSTACK",
    "kling",
    "klingai",
    "hailuo",
    "doubao-seedance",
    "moonshot-api",
    "zhipuai",
    "chatglm",
    "deepseek-api",
    "minimax-api",
]

# Seed list of Chinese AI orgs/users with high key density.
GITEE_TARGET_ORGS: list[tuple[str, str]] = [
    # (type, name)  type = "org" | "user"
    ("org",  "deepseek-ai"),
    ("org",  "paddlepaddle"),
    ("org",  "THUDM"),             # Zhipu AI / ChatGLM — Tsinghua
    ("org",  "openvino-project"),
    ("org",  "mindspore-ai"),
    ("org",  "huaweicloud"),
    ("org",  "volcengine"),        # ByteDance Volcengine (correct Gitee name)
    ("org",  "bytedance"),         # ByteDance main org
    ("org",  "modelscope-ai"),     # Alibaba ModelScope
    ("org",  "openmmlab"),         # OpenMMLab
    ("org",  "baidu"),
    ("org",  "baidu-security"),
    ("org",  "tencent"),
    ("org",  "alibaba"),
    ("org",  "xfyun"),             # iFlytek / Spark LLM
    ("org",  "moonshot-ai"),       # Kimi
    ("org",  "klingai"),           # Kling / Kuaishou
    ("org",  "baichuan-inc"),      # Baichuan LLM
    ("org",  "01-ai"),             # Yi / 01.AI
    ("org",  "InternLM"),          # Shanghai AI Lab
    ("org",  "MiniMax-AI"),        # MiniMax
    ("org",  "coze-dev"),          # ByteDance Coze
]

# Additional users known to work on Chinese AI projects
GITEE_TARGET_USERS: list[str] = []


def _headers(token: str) -> dict:
    return {
        "Authorization": f"token {token}",
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        ),
    }


def _claim_key(full_name: str, path: str) -> str:
    return hashlib.sha256(f"gitee:{full_name}:{path}".encode()).hexdigest()[:40]


async def _check_token(client: httpx.AsyncClient, token: str) -> bool:
    try:
        r = await client.get(f"{_BASE}/user", headers=_headers(token), timeout=10)
        alive = r.status_code == 200
        _TOKEN_STATUS[token[:8]] = {"alive": alive}
        return alive
    except Exception:
        _TOKEN_STATUS[token[:8]] = {"alive": False}
        return False


async def _list_repos(client: httpx.AsyncClient,
                      kind: str, name: str, token: str) -> list[dict]:
    """List all public repos for an org or user."""
    url = (f"{_BASE}/orgs/{name}/repos" if kind == "org"
           else f"{_BASE}/users/{name}/repos")
    all_repos = []
    for page in range(1, _MAX_REPO_PAGES + 1):
        try:
            r = await client.get(
                url,
                headers=_headers(token),
                params={"type": "public", "per_page": 100, "page": page},
                timeout=20,
            )
            if r.status_code == 404:
                break  # org/user doesn't exist
            if r.status_code in (401, 403):
                _TOKEN_STATUS[token[:8]] = {"alive": False}
                break
            if r.status_code != 200:
                break
            batch = r.json()
            if not isinstance(batch, list) or not batch:
                break
            all_repos.extend(batch)
            if len(batch) < 100:
                break
            await asyncio.sleep(_PAGE_SLEEP)
        except Exception as e:
            log.debug("gitee list_repos err [%s/%s]: %s", kind, name, e)
            break
    return all_repos


async def _search_repos(client: httpx.AsyncClient,
                        query: str, token: str) -> list[dict]:
    """Search public repos by keyword via /search/repositories.

    No auth required but token prevents anonymous rate-limiting.
    Returns repos sorted by most recently updated (best for fresh key finds).
    """
    all_repos = []
    for page in range(1, _SEARCH_PAGES + 1):
        try:
            r = await client.get(
                f"{_BASE}/search/repositories",
                headers=_headers(token),
                params={
                    "q":        query,
                    "per_page": 100,
                    "page":     page,
                    "order":    "desc",
                    "sort":     "updated",
                },
                timeout=20,
            )
            if r.status_code in (401, 403):
                _TOKEN_STATUS[token[:8]] = {"alive": False}
                break
            if r.status_code != 200:
                break
            data = r.json()
            # API returns {"total_count": N, "items": [...]} or bare list
            if isinstance(data, dict):
                batch = data.get("items", [])
            elif isinstance(data, list):
                batch = data
            else:
                break
            if not batch:
                break
            all_repos.extend(batch)
            if len(batch) < 100:
                break
            await asyncio.sleep(_PAGE_SLEEP)
        except Exception as e:
            log.debug("gitee search_repos err [%s]: %s", query, e)
            break
    return all_repos


async def _get_file(client: httpx.AsyncClient,
                    full_name: str, path: str, token: str) -> str | None:
    """Fetch a single file from a Gitee repo."""
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
        log.debug("gitee get_file err [%s/%s]: %s", full_name, path, e)
        return None


async def _scan_file(full_name: str, path: str, content: str,
                     stars: int, file_url: str):
    """Run extractors on content and persist/notify findings."""
    _AI_TRIGGER    = ("sk-", "AIzaSy", "eyJ", "hf_", "pplx-", "xai-", "r8_",
                      "ZHIPUAI", "moonshot", "klingai", "KLING_",
                      "DEEPSEEK", "ARK_API", "DOUBAO",
                      "VOLCSTACK", "VOLCENGINE_API", "VOLC_ACCESSKEY")
    _INFRA_TRIGGER = ("://", "BEGIN PRIVATE KEY", "BEGIN RSA", "BEGIN OPENSSH",
                      "AKIA", "AIPA", "AIDA", "AROA", "ASIA")

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
                    stars, "", "gitee", is_valid,
                )
                if saved:
                    await notify_found(
                        prov, key, full_name, path, file_url,
                        stars, "", "gitee", is_valid,
                    )
                    log.info("[gitee %s] %s from %s/%s",
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
                    stars, "", "gitee", destination, risk_level, risk_reasons,
                )
                await notify_infra_found(
                    iprov, cred, full_name, path, file_url,
                    stars, "", "gitee", destination, risk_level, risk_reasons,
                )


async def _scan_repo(client: httpx.AsyncClient, repo: dict,
                     sem: asyncio.Semaphore, token: str):
    """Fetch and scan all target file paths in a repo."""
    full_name = repo.get("full_name", "")
    if not full_name:
        return
    stars    = repo.get("stargazers_count", 0) or 0
    base_url = f"https://gitee.com/{full_name}/blob/master"

    async def fetch_one(path: str):
        if is_skippable_path(path):
            return
        async with sem:
            content = await _get_file(client, full_name, path, token)
        if content:
            file_url = f"{base_url}/{path}"
            await _scan_file(full_name, path, content, stars, file_url)

    tasks = [asyncio.create_task(fetch_one(p)) for p in _TARGET_PATHS]
    await asyncio.gather(*tasks, return_exceptions=True)


async def _run_worker(client: httpx.AsyncClient,
                      targets: list[tuple[str, str]],
                      search_queries: list[str],
                      token: str, sem: asyncio.Semaphore, worker_id: int):
    alive = await _check_token(client, token)
    if not alive:
        tk = token[:8]
        if tk not in _DEAD_ALERTED:
            _DEAD_ALERTED.add(tk)
            await notify_dead_token(f"gitee:{tk}")
        log.error("[gitee w%d token=%s...] DEAD — skipped", worker_id, token[:8])
        return

    log.info("[gitee w%d token=%s...] %d org/user targets + %d search queries",
             worker_id, token[:8], len(targets), len(search_queries))

    # Track repos scanned this cycle to avoid rescanning via search
    scanned: set[str] = set()

    # Phase 1: org / user enumeration
    for kind, name in targets:
        repos = await _list_repos(client, kind, name, token)
        if not repos:
            log.debug("[gitee w%d] no repos for %s/%s", worker_id, kind, name)
            continue
        log.info("[gitee w%d] %s/%s → %d repos", worker_id, kind, name, len(repos))
        for repo in repos:
            fn = repo.get("full_name", "")
            if fn:
                scanned.add(fn)
            await _scan_repo(client, repo, sem, token)
            await asyncio.sleep(_REPO_SLEEP)

    # Phase 2: keyword search — finds community repos outside org namespaces
    for query in search_queries:
        repos = await _search_repos(client, query, token)
        new_repos = [r for r in repos if r.get("full_name") not in scanned]
        if not new_repos:
            log.debug("[gitee w%d] search '%s' → all already scanned", worker_id, query)
            continue
        log.info("[gitee w%d] search '%s' → %d new repos", worker_id, query, len(new_repos))
        for repo in new_repos:
            fn = repo.get("full_name", "")
            if fn:
                scanned.add(fn)
            await _scan_repo(client, repo, sem, token)
            await asyncio.sleep(_REPO_SLEEP)
        await asyncio.sleep(_PAGE_SLEEP)


async def run_gitee_cycle():
    if not GITEE_TOKENS:
        return

    all_targets: list[tuple[str, str]] = [
        *GITEE_TARGET_ORGS,
        *[("user", u) for u in GITEE_TARGET_USERS],
    ]
    n = len(GITEE_TOKENS)

    # Distribute org/user targets across tokens
    chunks: list[list] = [[] for _ in range(n)]
    for i, t in enumerate(all_targets):
        chunks[i % n].append(t)

    # Distribute search queries across tokens
    query_chunks: list[list] = [[] for _ in range(n)]
    for i, q in enumerate(_SEARCH_QUERIES):
        query_chunks[i % n].append(q)

    log.info(
        "=== gitee cycle start | %d tokens | %d org targets | %d search queries | %d paths each ===",
        n, len(all_targets), len(_SEARCH_QUERIES), len(_TARGET_PATHS),
    )

    sem = asyncio.Semaphore(_CONCURRENT_ITEMS)

    # Route only gitee.com traffic through Evomi CN residential proxy.
    # Validator calls (moonshot, openai, glm…) go direct — saves proxy bandwidth.
    proxy = evomi_proxy_url()
    mounts = (
        {
            "https://gitee.com": httpx.AsyncHTTPTransport(proxy=proxy),
            "http://gitee.com":  httpx.AsyncHTTPTransport(proxy=proxy),
        }
        if proxy else {}
    )
    if proxy:
        log.info("gitee: routing via Evomi CN proxy (gitee.com only)")

    async with httpx.AsyncClient(follow_redirects=True, limits=_LIMITS,
                                 mounts=mounts) as client:
        workers = [
            asyncio.create_task(
                _run_worker(client, chunks[i], query_chunks[i],
                            GITEE_TOKENS[i], sem, i)
            )
            for i in range(n)
        ]
        results = await asyncio.gather(*workers, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                log.error("gitee worker crashed: %s", r)

    log.info("=== gitee cycle done ===")


async def gitee_loop():
    if not GITEE_TOKENS:
        log.info("gitee: no GITEE_TOKENS configured — skipping")
        return

    log.info("gitee scanner started | %d tokens | %d orgs+users | %d search queries | interval=%ds",
             len(GITEE_TOKENS),
             len(GITEE_TARGET_ORGS) + len(GITEE_TARGET_USERS),
             len(_SEARCH_QUERIES),
             GITEE_SCAN_INTERVAL)

    while True:
        try:
            await run_gitee_cycle()
        except Exception as e:
            log.error("gitee cycle crashed: %s", e)
        log.info("gitee sleeping %ds until next cycle", GITEE_SCAN_INTERVAL)
        await asyncio.sleep(GITEE_SCAN_INTERVAL)
