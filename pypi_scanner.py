"""
PyPI scanner — finds leaked AI API keys in published Python packages.

Why PyPI:
  - GitGuardian: 56,866 occurrences of secrets across PyPI package releases
  - litellm compromise (2024): SSH keys, cloud creds, API keys leaked in tarballs
  - chatllm: 209 OpenAI keys in an internal markdown file shipped in sdist
  - AI-adjacent Python libs (langchain wrappers, MCP servers) are dense targets
  - No auth required — public registry

Architecture:
  - Pull "newest packages" RSS feed (40 latest publishes, refreshed every cycle)
  - Plus search a curated list of AI-related package name patterns
  - For each package, fetch sdist (.tar.gz) URL from JSON API
  - Stream-download with size cap, extract specific config files
  - Scan extracted text content with AI_TRIGGER + EXTRACTORS
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
from config import PYPI_ENABLED, PYPI_SCAN_INTERVAL
from patterns import EXTRACTORS, AI_TRIGGER
from deobfuscate import expand as _deobf_expand
from validators import validate
from notifier import notify_found

log = logging.getLogger(__name__)

_BASE     = "https://pypi.org"
_RSS      = "https://pypi.org/rss/packages.xml"  # 40 newest packages

_PKG_SLEEP       = 0.6
_CONCURRENT      = 4
_TARBALL_MAX     = 5_000_000      # 5 MB cap on tarball download (skip wheels with bundled binaries)
_FILE_SIZE_MAX   = 256_000        # 256 KB cap on per-file scan

_LIMITS = httpx.Limits(
    max_connections=20,
    max_keepalive_connections=8,
    keepalive_expiry=30,
)

# Curated AI-related package patterns (regex). Pulled directly via JSON API.
_CURATED_PATTERNS: list[str] = [
    "openai-",
    "anthropic-",
    "langchain-",
    "llama-index",
    "llama_index",
    "llamaindex-",
    "fireworks-",
    "perplexity-",
    "replicate-",
    "huggingface_hub",
    "transformers-",
    "claude-",
    "mcp-",
    "modelcontextprotocol",
    "litellm",
    "chatllm",
    "llmware",
    "instructor",
    "guidance",
    "semantic-kernel",
    "ollama-",
    "vllm-",
    "vertexai-",
    "gemini-",
    "google-genai",
]

# Targets inside extracted tarball — same vector as npm scanner.
_TARGET_FILE_RE = re.compile(
    r"(?:^|/)("
    r"\.claude/settings(?:\.local)?\.json"           # Claude Code creds
    r"|claude_desktop_config\.json"
    r"|\.?mcp\.json"
    r"|\.env(?:\.[a-zA-Z]+)?"                         # .env, .env.example, .env.local…
    r"|config\.(?:py|json|yaml|yml|toml)"
    r"|settings\.(?:py|json|yaml|yml)"
    r"|secrets\.(?:json|yaml|yml|py)"
    r"|credentials\.(?:json|yaml|yml)"
    r"|api_keys?\.(?:json|yaml|yml|py)"
    r"|README\.md"                                    # often has hardcoded examples
    r"|setup\.py"
    r"|setup\.cfg"
    r"|pyproject\.toml"
    r")$",
    re.IGNORECASE,
)

# Skip noisy paths inside tarball
_SKIP_DIR_RE = re.compile(
    r"(?:^|/)(?:tests?|examples?|docs?|\.git|__pycache__|\.tox|build|"
    r"node_modules|\.idea|\.vscode|venv|env)/",
    re.IGNORECASE,
)


def _claim_key(pkg: str, version: str, path: str) -> str:
    return hashlib.sha256(f"pypi:{pkg}@{version}:{path}".encode()).hexdigest()[:40]


def _parse_rss_newest(xml: str) -> list[str]:
    """Extract package names from the PyPI newest-packages RSS feed."""
    # Each <item><title>pkgname version</title>...</item> — extract first word
    titles = re.findall(r"<title>([^<]+)</title>", xml)
    pkgs: list[str] = []
    for t in titles[1:]:  # skip first <title> which is the channel title
        name = t.strip().split()[0]
        if name and name.lower() != "pypi":
            pkgs.append(name)
    return pkgs


async def _fetch_curated(client: httpx.AsyncClient) -> list[str]:
    """Resolve curated patterns to actual package names via PyPI JSON API.

    PyPI doesn't offer a search API — we use the patterns as exact-prefix
    candidates. For each pattern we try the bare name first (e.g. 'litellm'),
    which catches the canonical package. Variations (-py, -python) are also
    probed cheaply.
    """
    candidates: list[str] = []
    for pat in _CURATED_PATTERNS:
        # Strip trailing dash placeholder
        bare = pat.rstrip("-_")
        for variant in (bare, f"{bare}-py", f"{bare}-python", f"{bare}_python"):
            candidates.append(variant)

    # Deduplicate, preserve order
    seen: set[str] = set()
    out: list[str] = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


async def _get_metadata(client: httpx.AsyncClient, package: str) -> dict | None:
    """Fetch PyPI JSON metadata for a package."""
    try:
        r = await client.get(f"{_BASE}/pypi/{package}/json", timeout=15)
        if r.status_code != 200:
            return None
        return r.json()
    except Exception as e:
        log.debug("pypi metadata err [%s]: %s", package, e)
        return None


def _pick_sdist_url(meta: dict) -> tuple[str, str] | None:
    """Find the sdist (source tarball) URL + version from package metadata."""
    info    = meta.get("info", {}) or {}
    version = info.get("version", "")
    urls    = meta.get("urls", []) or []
    for entry in urls:
        if entry.get("packagetype") == "sdist":
            url = entry.get("url", "")
            if url:
                return url, version
    return None


async def _download_tarball(client: httpx.AsyncClient, url: str) -> bytes | None:
    """Stream-download a tarball with size cap. Returns bytes or None."""
    try:
        async with client.stream("GET", url, timeout=30) as r:
            if r.status_code != 200:
                return None
            # Pre-flight content-length check
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
        log.debug("pypi download err: %s", e)
        return None


def _extract_target_files(tarball: bytes) -> dict[str, str]:
    """Decompress tarball in memory, return {relative_path: text_content}
    for files matching _TARGET_FILE_RE."""
    out: dict[str, str] = {}
    try:
        # Some sdists are .tar.gz, some .tar.bz2 — let tarfile auto-detect
        tf = tarfile.open(fileobj=io.BytesIO(tarball), mode="r:*")
    except Exception as e:
        log.debug("pypi tar open err: %s", e)
        return out

    try:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            if member.size > _FILE_SIZE_MAX:
                continue
            name = member.name
            if _SKIP_DIR_RE.search(name):
                continue
            if not _TARGET_FILE_RE.search(name):
                continue
            try:
                f = tf.extractfile(member)
                if not f:
                    continue
                raw = f.read()
                # Strip leading "{pkg}-{ver}/" prefix for cleaner paths
                rel = name.split("/", 1)[1] if "/" in name else name
                out[rel] = raw.decode("utf-8", errors="replace")
            except Exception:
                continue
    except Exception as e:
        log.debug("pypi tar walk err: %s", e)
    finally:
        tf.close()

    return out


async def _scan_content(pkg: str, version: str, path: str, content: str):
    content = _deobf_expand(content)
    if not any(t in content for t in AI_TRIGGER):
        return

    file_url = f"https://pypi.org/project/{pkg}/{version}/"

    for prov, fn in EXTRACTORS.items():
        for key in fn(content):
            if db.key_exists(key):
                continue
            is_valid = await validate(prov, key)
            saved = db.save_key(
                prov, key, pkg, path, file_url,
                0, "", "pypi", is_valid,
            )
            if saved:
                await notify_found(
                    prov, key, pkg, path, file_url,
                    0, "", "pypi", is_valid,
                )
                log.info("[pypi %s] %s from %s@%s/%s",
                         "VALID" if is_valid else "found", prov, pkg, version, path)


async def _scan_package(client: httpx.AsyncClient, package: str,
                        sem: asyncio.Semaphore):
    async with sem:
        meta = await _get_metadata(client, package)
        if not meta:
            return

        picked = _pick_sdist_url(meta)
        if not picked:
            return
        sdist_url, version = picked

        # Dedup at package@version level — skip if already scanned this version
        if not db.try_claim_file(_claim_key(package, version, "_sdist")):
            return

        tarball = await _download_tarball(client, sdist_url)
        if not tarball:
            return

    files = _extract_target_files(tarball)
    if not files:
        return

    for path, content in files.items():
        await _scan_content(package, version, path, content)


async def _list_newest(client: httpx.AsyncClient) -> list[str]:
    """Pull the 40 newest PyPI packages from RSS."""
    try:
        r = await client.get(_RSS, timeout=15)
        if r.status_code != 200:
            return []
        return _parse_rss_newest(r.text)
    except Exception as e:
        log.debug("pypi rss err: %s", e)
        return []


async def run_pypi_cycle():
    if not PYPI_ENABLED:
        return

    sem = asyncio.Semaphore(_CONCURRENT)

    async with httpx.AsyncClient(follow_redirects=True, limits=_LIMITS,
                                 headers={"User-Agent": "ghscan-pypi/1.0"}) as client:

        newest  = await _list_newest(client)
        curated = await _fetch_curated(client)

        # Combine, deduplicate (newest first so they take priority)
        seen: set[str] = set()
        all_pkgs: list[str] = []
        for p in newest + curated:
            if p not in seen:
                seen.add(p)
                all_pkgs.append(p)

        log.info("=== pypi cycle start | %d packages (newest=%d, curated=%d) ===",
                 len(all_pkgs), len(newest), len(curated))

        for pkg in all_pkgs:
            try:
                await _scan_package(client, pkg, sem)
                await asyncio.sleep(_PKG_SLEEP)
            except Exception as e:
                log.debug("pypi pkg err [%s]: %s", pkg, e)

    log.info("=== pypi cycle done ===")


async def pypi_loop():
    if not PYPI_ENABLED:
        log.info("pypi: disabled (PYPI_ENABLED=0)")
        return

    log.info("pypi scanner started | interval=%ds", PYPI_SCAN_INTERVAL)

    while True:
        try:
            await run_pypi_cycle()
        except Exception as e:
            log.error("pypi cycle crashed: %s", e)
        log.info("pypi sleeping %ds until next cycle", PYPI_SCAN_INTERVAL)
        await asyncio.sleep(PYPI_SCAN_INTERVAL)
