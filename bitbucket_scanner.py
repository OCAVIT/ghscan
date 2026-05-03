"""
Bitbucket Cloud scanner — finds leaked AI API keys in public repos.

Why Bitbucket:
  - Atlassian ecosystem → enterprise integrations (Jira, Slack, AWS) often
    have hardcoded API keys in repo configs
  - No GitHub Secret Scanning equivalent → keys stay valid much longer
  - Public repos sortable by recently-updated → fresh leaks surface fast
  - Free tier: 1000 API req/h per account, very lenient

Architecture (mirrors codeberg_scanner):
  - List recently-updated public repos via /repositories?sort=-updated_on
  - For each repo, fetch _TARGET_PATHS (same as gitee/codeberg)
  - Root listing pre-check to skip empty/docs-only repos
  - Dedup via try_claim_file(sha256("bitbucket:{full_name}:{path}"))

Auth:
  - Atlassian API tokens (NOT legacy app passwords)
  - Basic auth: base64(email:api_token)
  - Token format in BITBUCKET_TOKENS env var: "email1:token1,email2:token2"
"""

import asyncio
import hashlib
import logging

import httpx

import db
from config import BITBUCKET_TOKENS, BITBUCKET_SCAN_INTERVAL
from patterns import EXTRACTORS, is_skippable_path, AI_TRIGGER, INFRA_TRIGGER
from infra_patterns import INFRA_EXTRACTORS, assess_risk, extract_destination
from validators import validate
from notifier import notify_found, notify_infra_found, notify_dead_token

log = logging.getLogger(__name__)

_BASE = "https://api.bitbucket.org/2.0"

_CONCURRENT_ITEMS = 6
_REPO_SLEEP       = 0.4
_LIST_PAGES       = 15   # 100 repos/page × 15 = 1500 freshest public repos per cycle

_LIMITS = httpx.Limits(
    max_connections=60,
    max_keepalive_connections=15,
    keepalive_expiry=30,
)

_TOKEN_STATUS: dict[str, dict] = {}
_DEAD_ALERTED: set[str] = set()

# Same target paths as gitee/codeberg — config/env files likely to contain keys
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
    "bitbucket-pipelines.yml",  # Bitbucket-specific CI config
    "Makefile",
    "application.yml",
    "application.yaml",
    "application.properties",
    "application-dev.yml",
    "application-prod.yml",
    "bootstrap.yml",
    "appsettings.json",
    "appsettings.Development.json",
    "src/main/resources/application.yml",
    "src/main/resources/application.properties",
    "llm_config.yaml",
    "model_config.json",
    "deploy/.env",
    # Atlassian-stack specific (Bitbucket users often have Jira/Confluence creds too)
    "jira.config",
    "atlassian.config",
]


def _parse_token(entry: str) -> tuple[str, str] | None:
    """Split 'email:apitoken' into (email, token). Returns None if malformed."""
    if ":" not in entry:
        return None
    email, _, token = entry.partition(":")
    return (email.strip(), token.strip()) if email and token else None


def _claim_key(full_name: str, path: str) -> str:
    return hashlib.sha256(f"bitbucket:{full_name}:{path}".encode()).hexdigest()[:40]


def _token_id(email: str) -> str:
    """Stable short ID for token in logs/dedup — derived from email, not token."""
    return hashlib.sha256(email.encode()).hexdigest()[:12]


async def _check_token(client: httpx.AsyncClient, auth: tuple[str, str]) -> bool:
    """Verify token by hitting /user. Returns False only on hard auth failure."""
    for attempt in range(2):
        try:
            r = await client.get(f"{_BASE}/user", auth=auth, timeout=12)
            if r.status_code == 200:
                _TOKEN_STATUS[_token_id(auth[0])] = {"alive": True}
                return True
            if r.status_code in (401, 403):
                _TOKEN_STATUS[_token_id(auth[0])] = {"alive": False}
                return False
            _TOKEN_STATUS[_token_id(auth[0])] = {"alive": True}
            return True
        except Exception as e:
            if attempt == 0:
                await asyncio.sleep(3)
                continue
            log.debug("bitbucket check_token exception (treating as alive): %s", e)
            _TOKEN_STATUS[_token_id(auth[0])] = {"alive": True}
            return True
    return True


async def _list_public_repos(client: httpx.AsyncClient,
                             auth: tuple[str, str]) -> list[dict]:
    """List recently-updated public repos (1500 per cycle by default)."""
    all_repos: list[dict] = []
    next_url = (f"{_BASE}/repositories?pagelen=100&sort=-updated_on"
                "&fields=values.full_name,values.mainbranch.name,values.size,"
                "values.is_private,values.scm,next")

    for _ in range(_LIST_PAGES):
        try:
            r = await client.get(next_url, auth=auth, timeout=20)
            if r.status_code in (401, 403):
                _TOKEN_STATUS[_token_id(auth[0])] = {"alive": False}
                break
            if r.status_code != 200:
                log.debug("bitbucket list status=%d", r.status_code)
                break
            data = r.json()
            for repo in data.get("values", []):
                if repo.get("is_private", True):
                    continue
                if repo.get("scm", "git") != "git":  # skip mercurial repos
                    continue
                all_repos.append(repo)
            next_url = data.get("next")
            if not next_url:
                break
        except Exception as e:
            log.debug("bitbucket list_public err: %s", e)
            break

    return all_repos


_INTERESTING_ROOT_FILES = frozenset({
    ".env", ".env.local", ".env.example", ".env.production",
    ".env.development", ".env.staging",
    "config.py", "settings.py", "api_config.py",
    "config.yaml", "config.yml", "config.json", "config.toml",
    "config.ts", "config.js",
    "docker-compose.yml", "docker-compose.yaml",
    "bitbucket-pipelines.yml",
    "Makefile", "application.yml", "application.yaml",
    "application.properties", "appsettings.json",
    "llm_config.yaml", "model_config.json",
})
_INTERESTING_ROOT_DIRS = frozenset({
    "config", "src", "app", "core", "deploy",
    "conf", "settings",
})


async def _has_interesting_root(client: httpx.AsyncClient,
                                full_name: str, branch: str,
                                auth: tuple[str, str]) -> bool:
    """Pre-check repo root listing to skip empty/docs-only repos."""
    try:
        r = await client.get(
            f"{_BASE}/repositories/{full_name}/src/{branch}/?pagelen=50",
            auth=auth, timeout=10,
        )
        if r.status_code != 200:
            return True
        data = r.json()
        values = data.get("values", []) if isinstance(data, dict) else []
        for entry in values:
            # Bitbucket returns "path" like "config.py" and "type" "commit_file"|"commit_directory"
            path = entry.get("path", "")
            etype = entry.get("type", "")
            # path can be "config.yaml" or "src/" — extract leaf
            leaf = path.rstrip("/").split("/")[-1]
            if etype == "commit_file" and leaf in _INTERESTING_ROOT_FILES:
                return True
            if etype == "commit_directory" and leaf in _INTERESTING_ROOT_DIRS:
                return True
        return False
    except Exception:
        return True


async def _get_file(client: httpx.AsyncClient,
                    full_name: str, branch: str, path: str,
                    auth: tuple[str, str]) -> str | None:
    """Fetch raw file content from a Bitbucket repo."""
    ck = _claim_key(full_name, path)
    if not db.try_claim_file(ck):
        return None

    try:
        r = await client.get(
            f"{_BASE}/repositories/{full_name}/src/{branch}/{path}",
            auth=auth, timeout=15,
        )
        if r.status_code != 200:
            return None
        # Bitbucket returns raw text for files, not JSON-wrapped
        if len(r.content) > 512_000:  # skip files > 512KB
            return None
        return r.text
    except Exception as e:
        log.debug("bitbucket get_file err [%s/%s]: %s", full_name, path, e)
        return None


async def _scan_file(full_name: str, path: str, content: str, file_url: str):
    has_ai    = any(t in content for t in AI_TRIGGER)
    has_infra = any(t in content for t in INFRA_TRIGGER)
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
                    0, "", "bitbucket", is_valid,
                )
                if saved:
                    await notify_found(
                        prov, key, full_name, path, file_url,
                        0, "", "bitbucket", is_valid,
                    )
                    log.info("[bitbucket %s] %s from %s/%s",
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
                    0, "", "bitbucket", destination, risk_level, risk_reasons,
                )
                await notify_infra_found(
                    iprov, cred, full_name, path, file_url,
                    0, "", "bitbucket", destination, risk_level, risk_reasons,
                )


async def _scan_repo(client: httpx.AsyncClient, repo: dict,
                     sem: asyncio.Semaphore, auth: tuple[str, str]):
    full_name = repo.get("full_name", "")
    if not full_name:
        return

    branch = (repo.get("mainbranch") or {}).get("name") or "main"

    async with sem:
        interesting = await _has_interesting_root(client, full_name, branch, auth)
    if not interesting:
        log.debug("bitbucket skip (no interesting root): %s", full_name)
        return

    base_url = f"https://bitbucket.org/{full_name}/src/{branch}"

    async def fetch_one(path: str):
        if is_skippable_path(path):
            return
        async with sem:
            content = await _get_file(client, full_name, branch, path, auth)
        if content:
            file_url = f"{base_url}/{path}"
            await _scan_file(full_name, path, content, file_url)

    tasks = [asyncio.create_task(fetch_one(p)) for p in _TARGET_PATHS]
    await asyncio.gather(*tasks, return_exceptions=True)


async def _run_worker(client: httpx.AsyncClient, auth: tuple[str, str],
                      sem: asyncio.Semaphore, worker_id: int):
    email = auth[0]
    tid = _token_id(email)

    alive = await _check_token(client, auth)
    if not alive:
        if tid not in _DEAD_ALERTED:
            _DEAD_ALERTED.add(tid)
            await notify_dead_token(f"bitbucket:{tid}")
        log.error("[bitbucket w%d email=%s] DEAD — skipped", worker_id, email)
        return

    log.info("[bitbucket w%d email=%s] fetching recent public repos", worker_id, email)
    repos = await _list_public_repos(client, auth)
    log.info("[bitbucket w%d] %d public repos to scan", worker_id, len(repos))

    for repo in repos:
        try:
            await _scan_repo(client, repo, sem, auth)
            await asyncio.sleep(_REPO_SLEEP)
        except Exception as e:
            log.debug("[bitbucket w%d] scan err %s: %s",
                      worker_id, repo.get("full_name"), e)


async def run_bitbucket_cycle():
    if not BITBUCKET_TOKENS:
        return

    auths: list[tuple[str, str]] = []
    for entry in BITBUCKET_TOKENS:
        parsed = _parse_token(entry)
        if parsed:
            auths.append(parsed)
        else:
            log.warning("bitbucket: malformed token entry, expected 'email:token'")

    if not auths:
        log.warning("bitbucket: no valid tokens — skipping cycle")
        return

    log.info("=== bitbucket cycle start | %d accounts ===", len(auths))

    sem = asyncio.Semaphore(_CONCURRENT_ITEMS)

    async with httpx.AsyncClient(follow_redirects=True, limits=_LIMITS) as client:
        workers = [
            asyncio.create_task(
                _run_worker(client, auth, sem, i),
                name=f"bitbucket_w{i}",
            )
            for i, auth in enumerate(auths)
        ]
        results = await asyncio.gather(*workers, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                log.error("bitbucket worker crashed: %s", r)

    log.info("=== bitbucket cycle done ===")


async def bitbucket_loop():
    if not BITBUCKET_TOKENS:
        log.info("bitbucket: no BITBUCKET_TOKENS configured — skipping")
        return

    log.info("bitbucket scanner started | %d accounts | interval=%ds",
             len(BITBUCKET_TOKENS), BITBUCKET_SCAN_INTERVAL)

    while True:
        try:
            await run_bitbucket_cycle()
        except Exception as e:
            log.error("bitbucket cycle crashed: %s", e)
        log.info("bitbucket sleeping %ds until next cycle", BITBUCKET_SCAN_INTERVAL)
        await asyncio.sleep(BITBUCKET_SCAN_INTERVAL)
