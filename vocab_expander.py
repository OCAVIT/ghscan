"""
AI vocabulary expander — discovers new env-var-names / filenames /
context-words from real valid-key files via DeepSeek.

Runs every 24 hours (separate cadence from the 8h combinatorial generator).
For each provider with at least one is_valid=1 key in the DB:

  1. Pull last 20 valid-key file URLs from db.get_recent_valid_files
  2. Fetch their raw contents via GitHub API (uses scanner's GITHUB_TOKENS)
  3. Pre-extract env-name candidates with regex so DeepSeek sees the
     candidate set + can confirm/reject + suggest filenames it noticed
  4. Send to DeepSeek (deepseek-v4-pro, JSON-mode response)
  5. Insert deltas into axis_extensions — picked up by the next combinatorial
     generator cycle automatically

Cost per 24h: ~30 providers × ~5K input tokens × $0.27/MT input ≈ $0.04
                                + ~30 × 1K output tokens × $1.10/MT ≈ $0.03
                                = ~$0.07/day  ≈  $2/month
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
from typing import Any

import httpx

import db
from config import GITHUB_TOKENS
from deepseek_client import call_deepseek, extract_text
from query_axes import PROVIDER_AXES

log = logging.getLogger(__name__)


# Regex pre-extractor — gives DeepSeek a concrete candidate set to evaluate
# rather than hoping it spots names from raw file noise.
_ENV_NAME_RE = re.compile(
    r'(?m)^\s*(?:export\s+)?'
    r'([A-Z][A-Z0-9_]{4,40})'                # candidate name
    r'\s*[=:]'                               # = (env) or : (yaml/json-style)
)
# Filename hints in code: imports, file opens, dotenv path args, etc.
_FILENAME_HINT_RE = re.compile(
    r'(?:open|read_file|load_dotenv|dotenv|require|from|fs\.read\w*)'
    r'\s*\(?\s*["\']'
    r'([\.\w\-/]{3,80}\.(?:env|ya?ml|toml|json|properties|cfg|ini)[\.\w]*)',
    re.IGNORECASE,
)

_MAX_FILE_BYTES = 8192     # truncate per file — names live in the first KB anyway
_MAX_FILES_PER_PROVIDER = 20
_MIN_VALID_KEYS_GATE = 1   # don't bother running for providers with no live data


def _normalize_blob_url(file_url: str) -> str | None:
    """Convert https://github.com/owner/repo/blob/HEAD/path → raw API URL.

    The scanner stores file_url as the github.com HTML URL. To fetch via the
    GitHub API we want /repos/{owner}/{repo}/contents/{path}. Falls back to
    None on unrecognized formats."""
    m = re.match(
        r"https?://github\.com/([^/]+)/([^/]+)/blob/[^/]+/(.+)$",
        file_url,
    )
    if not m:
        return None
    owner, repo, path = m.group(1), m.group(2), m.group(3)
    return f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"


async def _fetch_file(client: httpx.AsyncClient, file_url: str,
                      gh_token: str) -> str | None:
    api_url = _normalize_blob_url(file_url)
    if not api_url:
        return None
    try:
        r = await client.get(
            api_url,
            headers={
                "Authorization": f"Bearer {gh_token}",
                "Accept":        "application/vnd.github+json",
                "User-Agent":    "ghscan-vocab/1.0",
            },
            timeout=20,
        )
        if r.status_code != 200:
            return None
        body = r.json()
        if body.get("encoding") == "base64":
            try:
                raw = base64.b64decode(body.get("content", "")).decode(
                    "utf-8", errors="replace"
                )
            except Exception:
                return None
        else:
            raw = body.get("content", "")
        return raw[:_MAX_FILE_BYTES]
    except Exception as e:
        log.debug("vocab fetch err %s: %s", file_url[:60], e)
        return None


def _pre_extract(content: str) -> tuple[set[str], set[str]]:
    """Pull candidate env-names and filenames from the file body. Cheap
    pre-pass narrows the surface DeepSeek has to consider."""
    env_candidates = {m.group(1) for m in _ENV_NAME_RE.finditer(content)}
    file_candidates = {m.group(1).lstrip("./") for m in _FILENAME_HINT_RE.finditer(content)}
    return env_candidates, file_candidates


def _build_prompt(provider: str, current_axes: dict[str, list[str]],
                  bundles: list[dict]) -> list[dict]:
    """Build the chat-completion message list for vocab discovery on one
    provider. `bundles` is a list of {repo, file_path, content,
    env_candidates, file_candidates}."""
    sys_msg = (
        "You analyze leaked .env / config / source files to discover NEW "
        "naming conventions for AI-provider API keys. Your job is to extract:\n"
        "  • env_names — env-var spellings developers use for THIS provider's key\n"
        "  • filenames — config/env files where keys appear (basename only)\n"
        "  • context_words — distinctive function/SDK call strings near the key\n"
        "    (e.g. 'openai.AsyncOpenAI', 'gpt-image-2')\n"
        "Return ONLY items that are NOT already in the current vocabulary list. "
        "Reject obvious garbage, generic names (API_KEY, SECRET, TOKEN), or "
        "names belonging to other providers (e.g. STRIPE_KEY in an OpenAI file)."
    )

    current_envs   = current_axes.get("env_names", [])
    current_files  = current_axes.get("filenames", [])    # may be empty (global axis)
    current_ctx    = current_axes.get("context_words", [])

    user_parts = [
        f"PROVIDER: {provider}",
        "",
        f"CURRENT VOCABULARY (do NOT repeat these):",
        f"  env_names:     {sorted(current_envs)[:60]}",
        f"  filenames:     {sorted(current_files)[:60] if current_files else '(none — using global FILENAMES list)'}",
        f"  context_words: {sorted(current_ctx)[:60] if current_ctx else '(none yet)'}",
        "",
        "FILE SAMPLES (real repos that leaked a VALIDATED key for this provider):",
    ]

    for i, b in enumerate(bundles, 1):
        user_parts.append(
            f"\n--- File {i}: {b['repo']}/{b['file_path']} ---"
        )
        if b["env_candidates"]:
            user_parts.append(
                f"Pre-extracted env-name candidates: {sorted(b['env_candidates'])[:40]}"
            )
        if b["file_candidates"]:
            user_parts.append(
                f"Pre-extracted filename candidates: {sorted(b['file_candidates'])[:20]}"
            )
        user_parts.append("Content:")
        user_parts.append(b["content"])

    user_parts.extend([
        "",
        "Respond ONLY with this JSON shape (no prose, no markdown fences):",
        '{"env_names": [...], "filenames": [...], "context_words": [...]}',
        "",
        "Each list contains 0-15 NEW items. Empty list if nothing new found.",
        "Filenames must be plain basenames (e.g. '.env.docker', 'wrangler.toml'), "
        "no path prefixes.",
    ])

    return [
        {"role": "system", "content": sys_msg},
        {"role": "user",   "content": "\n".join(user_parts)},
    ]


def _parse_response(text: str | None) -> dict[str, list[str]]:
    """Tolerant JSON-extract — DeepSeek sometimes wraps JSON in ```json fences
    despite response_format=json_object."""
    if not text:
        return {}
    # Strip code fences if present
    txt = text.strip()
    if txt.startswith("```"):
        txt = re.sub(r'^```(?:json)?\s*', '', txt)
        txt = re.sub(r'\s*```$', '', txt)
    try:
        data = json.loads(txt)
    except json.JSONDecodeError:
        # Try to extract a {...} substring
        m = re.search(r'\{[\s\S]*\}', txt)
        if not m:
            return {}
        try:
            data = json.loads(m.group(0))
        except json.JSONDecodeError:
            return {}
    out: dict[str, list[str]] = {}
    for axis in ("env_names", "filenames", "context_words"):
        v = data.get(axis, [])
        if isinstance(v, list):
            out[axis] = [str(x).strip() for x in v if isinstance(x, (str, int))]
    return out


def _filter_new(provider: str, axis: str, values: list[str],
                current: set[str]) -> list[str]:
    """Final guard — drop anything that's already in current vocab + axis
    extensions, plus shape-based junk."""
    seen = set()
    out = []
    for v in values:
        v = v.strip().strip(',').strip('"').strip("'")
        if not v or v in seen or v in current:
            continue
        # Reject junk: too short, all-numeric, contains spaces
        if len(v) < 3 or len(v) > 80 or " " in v:
            continue
        # For env_names: enforce ALL_CAPS_WITH_UNDERSCORES shape
        if axis == "env_names":
            if not re.match(r'^[A-Z][A-Z0-9_]+$', v):
                continue
            # Block obvious non-provider-specific names
            if v in ("API_KEY", "SECRET_KEY", "TOKEN", "ACCESS_TOKEN",
                     "AUTH_TOKEN", "SECRET", "PASSWORD", "USER", "USERNAME"):
                continue
        seen.add(v)
        out.append(v)
    return out[:15]   # hard cap regardless of model output


async def expand_provider(provider: str, gh_token: str,
                          httpx_client: httpx.AsyncClient) -> dict[str, int]:
    """Run vocab discovery for one provider. Returns counts inserted per axis."""
    if provider not in PROVIDER_AXES:
        return {}

    rows = db.get_recent_valid_files(provider, limit=_MAX_FILES_PER_PROVIDER)
    if len(rows) < _MIN_VALID_KEYS_GATE:
        log.debug("vocab_expand[%s]: only %d valid-key files — skipping",
                  provider, len(rows))
        return {}

    bundles: list[dict] = []
    for row in rows:
        content = await _fetch_file(httpx_client, row["file_url"], gh_token)
        if not content:
            continue
        envs, files = _pre_extract(content)
        bundles.append({
            "repo":             row["repo"],
            "file_path":        row["file_path"],
            "content":          content,
            "env_candidates":   envs,
            "file_candidates":  files,
        })

    if not bundles:
        log.warning("vocab_expand[%s]: 0 files fetched — skipping", provider)
        return {}

    # Merge static axes + existing extensions for the "do not repeat" prompt
    existing_ext = db.get_axis_extensions(provider)
    current_axes: dict[str, list[str]] = {
        axis: list(PROVIDER_AXES[provider].get(axis, []))
              + existing_ext.get(axis, [])
        for axis in ("env_names", "filenames", "context_words")
    }

    messages = _build_prompt(provider, current_axes, bundles)
    response = await call_deepseek(
        messages,
        response_format={"type": "json_object"},
        reasoning_effort="high",   # extraction task — high is plenty
    )
    text = extract_text(response)
    if not text:
        log.warning("vocab_expand[%s]: DeepSeek returned no text", provider)
        return {}

    parsed = _parse_response(text)
    if not parsed:
        log.warning("vocab_expand[%s]: failed to parse DeepSeek response: %s",
                    provider, text[:200])
        return {}

    inserted: dict[str, int] = {}
    for axis in ("env_names", "filenames", "context_words"):
        proposed = parsed.get(axis, [])
        if not proposed:
            continue
        current_set = set(current_axes.get(axis, []))
        new_values = _filter_new(provider, axis, proposed, current_set)
        if not new_values:
            continue
        n = db.add_axis_extensions(provider, axis, new_values)
        if n:
            inserted[axis] = n
            log.info("vocab_expand[%s.%s]: +%d new values: %s",
                     provider, axis, n, new_values)

    return inserted


async def run_expansion_cycle() -> dict[str, Any]:
    """Iterate every provider in PROVIDER_AXES; bail per-provider on errors
    so one failure doesn't kill the cycle."""
    if not GITHUB_TOKENS:
        log.error("vocab_expand: no GITHUB_TOKENS configured — cannot fetch files")
        return {"error": "no_github_tokens"}

    valid_count = db.get_valid_count_by_provider()
    if valid_count.get("deepseek", 0) == 0:
        log.warning("vocab_expand: no valid DeepSeek keys in DB — skipping cycle")
        return {"error": "no_deepseek_keys"}

    gh_token = GITHUB_TOKENS[0]   # any token works; we just need GH read
    summary: dict[str, Any] = {"providers": {}, "total_inserted": 0}

    async with httpx.AsyncClient(follow_redirects=True) as c:
        for provider in PROVIDER_AXES:
            # Skip providers without ANY valid keys — vocab discovery
            # needs concrete source examples
            if valid_count.get(provider, 0) == 0:
                continue
            try:
                inserted = await expand_provider(provider, gh_token, c)
                if inserted:
                    summary["providers"][provider] = inserted
                    summary["total_inserted"] += sum(inserted.values())
            except Exception as e:
                log.error("vocab_expand[%s] crashed: %s", provider, e)
                summary["providers"][provider] = {"error": str(e)[:100]}

    log.info("vocab_expand cycle done — %d total new vocab items across %d providers",
             summary["total_inserted"], len(summary["providers"]))
    return summary
