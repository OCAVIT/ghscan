"""
Common Crawl scanner — finds leaked AI API keys in petabyte-scale web crawl.

Why Common Crawl:
  - 3B+ pages per monthly crawl, free public bucket (s3://commoncrawl/)
  - NOT in GitHub Secret Scanning Partner Program — keys stay valid
  - Captures pages no other scanner sees: dev blogs, tutorials, leaked
    pages, GitLab/Bitbucket/SourceForge mirrors, archived APIs, etc.
  - Free bandwidth — public S3 read

Architecture:
  - Get latest crawl id from collinfo.json (e.g. CC-MAIN-2026-19)
  - For each URL pattern (.env, config.json, mcp.json, etc.) query CDX API
  - Each match has WARC filename + byte offset + length
  - Range-fetch JUST that record from data.commoncrawl.org
  - Decompress gzipped WARC, extract HTTP response body
  - Run our standard AI_TRIGGER + EXTRACTORS pipeline
  - Save with file_type="commoncrawl"; dedup via sha256("cc:{url}:{digest}")

Tradeoff: data is 1-3 months old (latest CC dump lag). Some keys may have
been revoked by Anthropic/OpenAI's own web scanners by the time we get to
them, but plenty stay alive — providers don't scan everything.
"""

import asyncio
import gzip
import hashlib
import json
import logging
from urllib.parse import urlparse

import httpx

import db
from config import CC_ENABLED, CC_SCAN_INTERVAL, CC_PER_PATTERN_CAP
from patterns import EXTRACTORS, AI_TRIGGER, INFRA_TRIGGER
from deobfuscate import expand as _deobf_expand
from infra_patterns import INFRA_EXTRACTORS, assess_risk, extract_destination
from validators import validate
from notifier import notify_found, notify_infra_found

log = logging.getLogger(__name__)

_CDX_BASE  = "https://index.commoncrawl.org"
_DATA_BASE = "https://data.commoncrawl.org"

_CONCURRENT      = 6
_FILE_SIZE_MAX   = 256_000        # 256 KB cap on extracted body
_RECORD_MAX      = 2_000_000      # 2 MB cap on raw WARC record
_PATTERN_SLEEP   = 2.0            # cooldown between url-pattern sweeps

_LIMITS = httpx.Limits(
    max_connections=20,
    max_keepalive_connections=10,
    keepalive_expiry=30,
)

# Target URL patterns — files most likely to contain leaked AI provider keys.
# CDX wildcards: '*' matches any chars including / so '*.env' matches everything
# ending in .env (any path). Patterns ordered by expected key density.
_URL_PATTERNS: list[str] = [
    # Modern AI assistant configs (highest density)
    "*claude_desktop_config.json",
    "*.claude/settings.local.json",
    "*.claude/settings.json",
    "*mcp.json",
    "*.mcp.json",
    "*.cursor/mcp.json",
    "*.continue/config.json",
    "*.continue/config.yaml",
    "*.aider.conf.yml",
    "*litellm_config.yaml",
    "*litellm_config.json",
    # .env family
    "*.env",
    "*.env.local",
    "*.env.production",
    "*.env.development",
    "*.env.example",
    "*.env.docker",
    "*.envrc",
    # Generic config files
    "*config.json",
    "*config.yaml",
    "*config.yml",
    "*config.toml",
    "*settings.json",
    "*secrets.json",
    "*secrets.yaml",
    "*credentials.json",
    "*api_keys.json",
    # Cloud deploy configs
    "*wrangler.toml",
    "*vercel.json",
    "*netlify.toml",
    "*serverless.yml",
    "*fly.toml",
    "*railway.toml",
    "*Procfile",
    "*app.yaml",
    # Spring / Java / .NET
    "*application.yml",
    "*application.yaml",
    "*application.properties",
    "*appsettings.json",
    # Streamlit / Gradio
    "*.streamlit/secrets.toml",
    # Notebooks (often have hardcoded keys in cells)
    "*.ipynb",
]


def _claim_key(url: str, digest: str) -> str:
    return hashlib.sha256(f"cc:{url}:{digest}".encode()).hexdigest()[:40]


async def _get_latest_crawl(client: httpx.AsyncClient) -> str | None:
    """Fetch list of crawls and return the most recent crawl ID."""
    try:
        r = await client.get(f"{_CDX_BASE}/collinfo.json", timeout=15)
        if r.status_code != 200:
            return None
        crawls = r.json()
        if not isinstance(crawls, list) or not crawls:
            return None
        # Most recent crawl is typically first
        return crawls[0].get("id", "")
    except Exception as e:
        log.debug("cc collinfo err: %s", e)
        return None


async def _search_cdx(client: httpx.AsyncClient,
                      crawl_id: str, url_pattern: str, cap: int):
    """Query CDX index, yield raw records {url, filename, offset, length, digest}.

    CDX endpoint is famously flaky — wildcard queries can take 60+ seconds
    or return 504/502/503 under load. We retry with exponential backoff and
    skip the pattern if all retries fail.
    """
    base = f"{_CDX_BASE}/{crawl_id}-index"
    yielded = 0
    page = 0
    consecutive_failures = 0

    while yielded < cap:
        params = {
            "url":      url_pattern,
            "output":   "json",
            "page":     page,
            "pageSize": 5,   # CDX default; smaller pages = faster timeout if pattern is rare
        }
        # Retry with backoff on 502/503/504 (gateway timeouts)
        text = None
        for attempt in range(3):
            try:
                r = await client.get(base, params=params, timeout=90)
                if r.status_code == 404:
                    return
                if r.status_code in (502, 503, 504):
                    backoff = 5 * (attempt + 1) ** 2  # 5s, 20s, 45s
                    log.info("cc cdx %d pattern=%s page=%d retry in %ds",
                             r.status_code, url_pattern, page, backoff)
                    await asyncio.sleep(backoff)
                    continue
                if r.status_code != 200:
                    log.debug("cc cdx status=%d pattern=%s page=%d body=%s",
                              r.status_code, url_pattern, page, r.text[:120])
                    return
                text = r.text
                break
            except Exception as e:
                backoff = 5 * (attempt + 1)
                log.debug("cc cdx err [%s p=%d a=%d]: %s — retry in %ds",
                          url_pattern, page, attempt, e, backoff)
                await asyncio.sleep(backoff)
        if text is None:
            consecutive_failures += 1
            if consecutive_failures >= 2:
                log.warning("cc cdx pattern '%s' failed twice — skipping", url_pattern)
                return
            page += 1
            continue
        consecutive_failures = 0

        if not text.strip():
            return
        page_records = 0
        for line in text.split("\n"):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            yield rec
            yielded += 1
            page_records += 1
            if yielded >= cap:
                return
        if page_records == 0:
            return  # empty page → no more results
        page += 1


async def _fetch_warc_record(client: httpx.AsyncClient,
                             filename: str, offset: int, length: int) -> bytes | None:
    """Range-fetch a single gzipped WARC record from data.commoncrawl.org."""
    if length <= 0 or length > _RECORD_MAX:
        return None
    try:
        r = await client.get(
            f"{_DATA_BASE}/{filename}",
            headers={"Range": f"bytes={offset}-{offset+length-1}"},
            timeout=30,
        )
        if r.status_code not in (200, 206):
            return None
        return r.content
    except Exception as e:
        log.debug("cc fetch err [%s @%d]: %s", filename, offset, e)
        return None


def _extract_body(warc_gzip: bytes) -> str | None:
    """Decompress WARC record and pull out the HTTP response body as text.

    Format:
      WARC/1.0\\r\\n
      WARC-Type: response\\r\\n
      ...
      \\r\\n\\r\\n              ← end of WARC headers
      HTTP/1.1 200 OK\\r\\n
      Content-Type: ...\\r\\n
      ...
      \\r\\n\\r\\n              ← end of HTTP headers
      <body bytes>
    """
    try:
        raw = gzip.decompress(warc_gzip)
    except Exception:
        return None
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        return None
    # Skip WARC headers, then HTTP headers
    parts = text.split("\r\n\r\n", 2)
    if len(parts) < 3:
        return None
    body = parts[2]
    if len(body) > _FILE_SIZE_MAX:
        body = body[:_FILE_SIZE_MAX]
    return body


async def _scan_content(url: str, content: str):
    """Run the standard AI + infra extractor pipeline on a CC page body."""
    content   = _deobf_expand(content)
    has_ai    = any(t in content for t in AI_TRIGGER)
    has_infra = any(t in content for t in INFRA_TRIGGER)
    if not has_ai and not has_infra:
        return

    parsed     = urlparse(url)
    repo_label = (parsed.hostname or "cc-unknown")[:80]
    path       = parsed.path[:200] or "/"
    file_url   = url[:500]

    if has_ai:
        for prov, fn in EXTRACTORS.items():
            for key in fn(content):
                if db.key_exists(key):
                    continue
                is_valid = await validate(prov, key)
                saved = db.save_key(
                    prov, key, repo_label, path, file_url,
                    0, "", "commoncrawl", is_valid,
                )
                if saved:
                    await notify_found(
                        prov, key, repo_label, path, file_url,
                        0, "", "commoncrawl", is_valid,
                    )
                    log.info("[cc %s] %s from %s",
                             "VALID" if is_valid else "found", prov, url[:80])

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
                    iprov, cred, repo_label, path, file_url,
                    0, "", "commoncrawl", destination, risk_level, risk_reasons,
                )
                await notify_infra_found(
                    iprov, cred, repo_label, path, file_url,
                    0, "", "commoncrawl", destination, risk_level, risk_reasons,
                )


_TEXTY_MIMES = ("text/", "application/json", "application/yaml",
                "application/x-yaml", "application/toml",
                "application/x-ipynb+json", "application/javascript",
                "application/xhtml+xml", "application/xml")


def _is_texty(mime: str) -> bool:
    if not mime:
        return True  # unknown — try anyway
    mime = mime.lower()
    return any(mime.startswith(t) for t in _TEXTY_MIMES)


async def _scan_record(client: httpx.AsyncClient,
                       sem: asyncio.Semaphore, rec: dict):
    """Process one CDX record: dedup → range-fetch → extract → scan."""
    url      = rec.get("url", "")
    filename = rec.get("filename", "")
    digest   = rec.get("digest", "")
    try:
        offset = int(rec.get("offset", 0) or 0)
        length = int(rec.get("length", 0) or 0)
    except (TypeError, ValueError):
        return

    if not url or not filename:
        return
    if not _is_texty(rec.get("mime-detected", "") or rec.get("mime", "")):
        return
    if not db.try_claim_file(_claim_key(url, digest)):
        return

    async with sem:
        warc_data = await _fetch_warc_record(client, filename, offset, length)
    if not warc_data:
        return
    body = _extract_body(warc_data)
    if body:
        await _scan_content(url, body)


async def run_cc_cycle():
    if not CC_ENABLED:
        return

    sem = asyncio.Semaphore(_CONCURRENT)

    async with httpx.AsyncClient(follow_redirects=True, limits=_LIMITS,
                                 headers={"User-Agent": "ghscan-cc/1.0"}) as client:

        crawl_id = await _get_latest_crawl(client)
        if not crawl_id:
            log.error("commoncrawl: failed to fetch latest crawl id")
            return

        log.info("=== commoncrawl cycle start | crawl=%s | %d patterns | cap=%d/pat ===",
                 crawl_id, len(_URL_PATTERNS), CC_PER_PATTERN_CAP)

        total_records = 0
        for pattern in _URL_PATTERNS:
            count = 0
            tasks: list[asyncio.Task] = []
            async for rec in _search_cdx(client, crawl_id, pattern, CC_PER_PATTERN_CAP):
                tasks.append(asyncio.create_task(_scan_record(client, sem, rec)))
                count += 1
                # Drain in batches of 50 to keep memory bounded
                if len(tasks) >= 50:
                    await asyncio.gather(*tasks, return_exceptions=True)
                    tasks = []
                    if count % 500 == 0:
                        log.info("[cc] %s: %d processed", pattern, count)
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            log.info("[cc] pattern '%s' done: %d records", pattern, count)
            total_records += count
            await asyncio.sleep(_PATTERN_SLEEP)

    log.info("=== commoncrawl cycle done | %d records total ===", total_records)


async def cc_loop():
    if not CC_ENABLED:
        log.info("commoncrawl: disabled (CC_ENABLED=0)")
        return

    log.info("commoncrawl scanner started | %d url-patterns | interval=%ds",
             len(_URL_PATTERNS), CC_SCAN_INTERVAL)

    while True:
        try:
            await run_cc_cycle()
        except Exception as e:
            log.error("commoncrawl cycle crashed: %s", e)
        log.info("commoncrawl sleeping %ds until next cycle", CC_SCAN_INTERVAL)
        await asyncio.sleep(CC_SCAN_INTERVAL)
