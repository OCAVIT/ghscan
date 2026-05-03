"""
npm registry scanner — finds leaked AI API keys in published packages.

Why npm:
  - Anonymous access to entire registry (no token needed)
  - Devs accidentally publish `.claude/settings.local.json` (Claude Code creds!)
    — Check Point research, April 2026: 30 of 428 packages had live credentials
  - `.env` files routinely included in tarballs by `npm publish`
  - Bundled minified JS often has hardcoded keys baked in at build time

Architecture:
  - Search npm registry for AI-related keywords (`/-/v1/search?text=...`)
  - Fetch package metadata via /{package} → get tarball URL
  - Stream-download tarball directly (NOT unpkg — unpkg caches & misses dotfiles)
  - Extract only target paths from tarball (.claude/, .env, config files)
  - Dedup via try_claim_file(sha256("npm:{package}@{version}"))
"""

import asyncio
import gzip
import hashlib
import io
import logging
import re
import tarfile

import httpx

import db
from config import NPM_ENABLED, NPM_SCAN_INTERVAL
from patterns import EXTRACTORS, AI_TRIGGER
from deobfuscate import expand as _deobf_expand
from validators import validate
from notifier import notify_found

log = logging.getLogger(__name__)

_REGISTRY = "https://registry.npmjs.org"

_SEARCH_SLEEP    = 0.5
_PKG_SLEEP       = 0.3
_CONCURRENT      = 4
_TARBALL_MAX     = 5_000_000      # 5MB cap — bigger packages skipped
_FILE_SIZE_MAX   = 256_000        # 256 KB cap on per-file scan

_LIMITS = httpx.Limits(
    max_connections=40,
    max_keepalive_connections=15,
    keepalive_expiry=30,
)

# Files to probe in every package — `.claude/settings.local.json` is the
# headline 2026 vector (Claude Code writes API tokens here, devs forget to
# add it to .npmignore).
_TARGET_PATHS: list[str] = [
    ".claude/settings.local.json",      # ⭐ Claude Code creds (April 2026 vector)
    ".claude/settings.json",
    "claude_desktop_config.json",       # Claude Desktop MCP config
    "mcp.json",                         # generic MCP config
    ".mcp.json",
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".env.example",
    ".env.test",
    "config.json",
    "config.js",
    "config.ts",
    "settings.json",
    "secrets.json",
    "credentials.json",
    "src/config.js",
    "src/config.ts",
    "dist/config.js",
    "lib/config.js",
    "package.json",                     # sometimes has hardcoded keys in scripts
]

# npm search queries — target packages that interact with AI providers.
# These devs are most likely to have hardcoded API keys.
_SEARCH_QUERIES: list[str] = [
    # Claude / Anthropic specific
    "claude-code",
    "claude-mcp",
    "anthropic-sdk",
    "@anthropic-ai",
    "anthropic-claude",
    # MCP servers (often bundle config with multi-provider keys)
    "mcp-server",
    "@modelcontextprotocol",
    "mcp-client",
    # OpenAI ecosystem
    "openai-api",
    "openai-wrapper",
    "openai-client",
    "chatgpt-api",
    "openai-streaming",
    # Multi-provider frameworks
    "langchain",
    "@langchain",
    "llamaindex",
    "vercel-ai",
    "ai-sdk",
    "llm-client",
    "llm-wrapper",
    # Gemini
    "gemini-api",
    "google-genai",
    "gemini-pro",
    # Other frequent leakers
    "groq-sdk",
    "together-ai",
    "perplexity-api",
    "replicate-api",
    "huggingface-inference",
    "elevenlabs",
    "openrouter",
    # Generic AI tooling
    "ai-assistant",
    "chatbot-cli",
    "llm-cli",
    "ai-agent",
]


def _claim_key(pkg: str, version: str, path: str) -> str:
    return hashlib.sha256(f"npm:{pkg}@{version}:{path}".encode()).hexdigest()[:40]


async def _search_packages(client: httpx.AsyncClient, query: str) -> list[dict]:
    """Search npm registry. Returns up to 100 most-relevant packages."""
    try:
        r = await client.get(
            f"{_REGISTRY}/-/v1/search",
            params={"text": query, "size": 100, "popularity": 0.5},
            timeout=20,
        )
        if r.status_code != 200:
            log.debug("npm search status=%d query=%r", r.status_code, query[:40])
            return []
        data = r.json()
        objs = data.get("objects", []) if isinstance(data, dict) else []
        # Normalise: each entry has .package.name / .package.version
        return [o.get("package", {}) for o in objs if isinstance(o, dict)]
    except Exception as e:
        log.debug("npm search err [%s]: %s", query[:40], e)
        return []


_TARGET_FILE_RE = re.compile(
    r"(?:^|/)("
    r"\.claude/settings(?:\.local)?\.json"
    r"|claude_desktop_config\.json"
    r"|\.?mcp\.json"
    r"|\.cursor/mcp\.json"
    r"|\.continue/config\.(?:json|yaml)"
    r"|\.aider\.conf\.yml"
    r"|\.env(?:\.[a-zA-Z]+)?"
    r"|config\.(?:json|js|ts|cjs|mjs|yaml|yml|toml)"
    r"|settings\.(?:json|js|ts)"
    r"|secrets\.(?:json|yaml|yml|js|ts)"
    r"|credentials\.(?:json|yaml|yml)"
    r"|api_keys?\.(?:json|js|ts)"
    r"|README\.md"
    r"|package\.json"
    r"|litellm_config\.(?:yaml|json)"
    r")$",
    re.IGNORECASE,
)
_SKIP_DIR_RE = re.compile(
    r"(?:^|/)(?:tests?|examples?|docs?|\.git|node_modules|"
    r"build|dist/test|coverage|\.idea|\.vscode)/",
    re.IGNORECASE,
)


async def _get_metadata(client: httpx.AsyncClient, package: str) -> dict | None:
    """Fetch npm package metadata (gives latest version + tarball URL)."""
    try:
        r = await client.get(f"{_REGISTRY}/{package}", timeout=15)
        if r.status_code != 200:
            return None
        return r.json()
    except Exception as e:
        log.debug("npm metadata err [%s]: %s", package, e)
        return None


def _pick_tarball(meta: dict) -> tuple[str, str] | None:
    """Return (tarball_url, version) for the latest non-deprecated version."""
    info = meta.get("dist-tags", {}) or {}
    latest = info.get("latest", "")
    if not latest:
        return None
    versions = meta.get("versions", {}) or {}
    v = versions.get(latest)
    if not v or not isinstance(v, dict):
        return None
    if v.get("deprecated"):
        return None
    dist = v.get("dist", {}) or {}
    url = dist.get("tarball", "")
    return (url, latest) if url else None


async def _download_tarball(client: httpx.AsyncClient, url: str) -> bytes | None:
    """Stream-download tarball with size cap."""
    try:
        async with client.stream("GET", url, timeout=30) as r:
            if r.status_code != 200:
                return None
            cl = r.headers.get("content-length")
            if cl and int(cl) > _TARBALL_MAX:
                return None
            buf = bytearray()
            async for chunk in r.aiter_bytes():
                buf.extend(chunk)
                if len(buf) > _TARBALL_MAX:
                    return None
            return bytes(buf)
    except Exception as e:
        log.debug("npm tarball download err: %s", e)
        return None


def _extract_target_files(tarball: bytes) -> dict[str, str]:
    """Extract only target config files from npm tarball."""
    out: dict[str, str] = {}
    try:
        tf = tarfile.open(fileobj=io.BytesIO(tarball), mode="r:gz")
    except Exception as e:
        log.debug("npm tar open err: %s", e)
        return out

    try:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            if member.size > _FILE_SIZE_MAX:
                continue
            name = member.name
            # npm tarballs prefix everything with "package/"
            rel = name.split("/", 1)[1] if "/" in name else name
            if _SKIP_DIR_RE.search(rel):
                continue
            if not _TARGET_FILE_RE.search(rel):
                continue
            try:
                f = tf.extractfile(member)
                if not f:
                    continue
                raw = f.read()
                out[rel] = raw.decode("utf-8", errors="replace")
            except Exception:
                continue
    except Exception as e:
        log.debug("npm tar walk err: %s", e)
    finally:
        tf.close()

    return out


async def _scan_content(pkg: str, version: str, path: str, content: str):
    """Run AI extractors on file content from an npm package."""
    content = _deobf_expand(content)
    if not any(t in content for t in AI_TRIGGER):
        return

    repo_label = pkg                                    # use bare pkg name as "repo"
    file_url   = f"https://www.npmjs.com/package/{pkg}/v/{version}?activeTab=code"

    for prov, fn in EXTRACTORS.items():
        for key in fn(content):
            if db.key_exists(key):
                continue
            is_valid = await validate(prov, key)
            saved = db.save_key(
                prov, key, repo_label, path, file_url,
                0, "", "npm", is_valid,
            )
            if saved:
                await notify_found(
                    prov, key, repo_label, path, file_url,
                    0, "", "npm", is_valid,
                )
                log.info("[npm %s] %s from %s@%s/%s",
                         "VALID" if is_valid else "found", prov, pkg, version, path)


async def _scan_package(client: httpx.AsyncClient, package: dict,
                        sem: asyncio.Semaphore):
    pkg = package.get("name", "")
    if not pkg:
        return

    async with sem:
        # Get metadata to find tarball URL + canonical version
        meta = await _get_metadata(client, pkg)
        if not meta:
            return
        picked = _pick_tarball(meta)
        if not picked:
            return
        url, version = picked

        # Dedup at package@version level
        if not db.try_claim_file(_claim_key(pkg, version, "_tarball")):
            return

        tarball = await _download_tarball(client, url)
        if not tarball:
            return
        await asyncio.sleep(_PKG_SLEEP)

    files = _extract_target_files(tarball)
    if not files:
        return

    for path, content in files.items():
        await _scan_content(pkg, version, path, content)


async def run_npm_cycle():
    if not NPM_ENABLED:
        return

    log.info("=== npm cycle start | %d queries × 100 pkgs ===", len(_SEARCH_QUERIES))

    sem = asyncio.Semaphore(_CONCURRENT)
    seen_pkgs: set[str] = set()

    async with httpx.AsyncClient(follow_redirects=True, limits=_LIMITS,
                                 headers={"User-Agent": "ghscan-npm/1.0"}) as client:
        for query in _SEARCH_QUERIES:
            packages = await _search_packages(client, query)
            new_pkgs = [p for p in packages
                        if (p.get("name", "") not in seen_pkgs) and p.get("name")]
            if not new_pkgs:
                await asyncio.sleep(_SEARCH_SLEEP)
                continue

            log.info("[npm] query '%s' → %d new packages", query, len(new_pkgs))

            for pkg in new_pkgs:
                seen_pkgs.add(pkg.get("name", ""))
                try:
                    await _scan_package(client, pkg, sem)
                except Exception as e:
                    log.debug("[npm] scan err %s: %s", pkg.get("name"), e)

            await asyncio.sleep(_SEARCH_SLEEP)

    log.info("=== npm cycle done | %d unique packages scanned ===", len(seen_pkgs))


async def npm_loop():
    if not NPM_ENABLED:
        log.info("npm: disabled (NPM_ENABLED=0)")
        return

    log.info("npm scanner started | %d queries | %d paths/pkg | interval=%ds",
             len(_SEARCH_QUERIES), len(_TARGET_PATHS), NPM_SCAN_INTERVAL)

    while True:
        try:
            await run_npm_cycle()
        except Exception as e:
            log.error("npm cycle crashed: %s", e)
        log.info("npm sleeping %ds until next cycle", NPM_SCAN_INTERVAL)
        await asyncio.sleep(NPM_SCAN_INTERVAL)
