"""
Custom extractor synthesis — when a jackpot repo (10+ valid keys) is found,
ask DeepSeek/GLM to analyze its file structure and generate a custom regex
parser tuned for that repo's specific leak format.

Why: generic AI_TRIGGER + EXTRACTORS catch ~95% of leaks but miss niche
patterns:
  - Encoded keys (base64-wrapped, hex-encoded)
  - Multi-line declarations (key split across YAML/JSON lines)
  - Custom env-var schemas (CFG__OPENAI__KEY style nested)
  - Obfuscated configs (rot13'd, gzip'd, etc.)

This module fires ONLY on jackpot detection (rare, ~1-3/week) so cost is
negligible. Quality model required (deepseek-v4-pro reasoning_effort=max +
GLM-5.1 fallback) — code generation needs deep reasoning.

Output: list of custom regex patterns + provider hints to apply via
walk_repo_tree's _scan_blob ONLY for that specific repo's remaining files.

NOTE: This is the lowest-ROI of the 5 pipelines (per analysis). Implemented
for completeness but rarely fires. Disabled by default — set
EXTRACTOR_SYNTH_ENABLED=1 to activate.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

import httpx

import db
from llm_client import call_creative

log = logging.getLogger(__name__)


# Disabled by default. Enable via env. When triggered we burn ~1 LLM call
# per jackpot repo (~$0.10 paid, $0 on our pool) but produce niche regex
# patterns that may catch 5-15 additional keys per jackpot.
ENABLED = os.environ.get("EXTRACTOR_SYNTH_ENABLED", "0") == "1"

# Trigger threshold: repo had >=N valid keys found via standard pipeline →
# good signal it has more, possibly in non-standard formats.
_JACKPOT_THRESHOLD_VALID_KEYS = 10

# In-process cache so we don't re-synthesize for the same repo across cycles.
_SYNTHESIZED: set[str] = set()


_SYSTEM_PROMPT = (
    "You analyze a high-yielding leak repo and synthesize CUSTOM regex "
    "patterns to catch additional API keys in non-standard formats.\n\n"
    "Output JSON only:\n"
    '{"patterns":[{"regex":"...","provider":"openai|...|generic","explain":"why"}]}\n\n'
    "Constraints:\n"
    "  - Each regex MUST compile in Python re module (no PCRE-only features).\n"
    "  - Each regex MUST have ONE capture group containing just the key.\n"
    "  - Each regex MUST be sufficiently anchored to avoid false matches "
    "(don't match 100K random hex strings).\n"
    "  - Provider must be lowercase. Use 'generic' for ambiguous patterns.\n"
    "  - 3-8 patterns total. Quality > quantity."
)


_VALID_PROVIDERS = {
    "openai", "openai_image", "anthropic", "google", "deepseek", "kimi", "glm",
    "grok", "perplexity", "openrouter", "huggingface", "ark", "ark_fast",
    "happyhorse", "higgsfield", "kling", "fal", "replicate", "fireworks",
    "elevenlabs", "inworld", "aimlapi", "deepinfra", "hyperbolic",
    "novita", "commonstack", "serper", "stability", "luma", "pika",
    "twelvelabs", "pixverse", "siliconflow", "firecrawl", "portkey", "krea",
    "hedra", "wavespeed", "generic", "multi",
}


async def _fetch_jackpot_evidence(client: httpx.AsyncClient, full_name: str,
                                    token: str) -> str:
    """Fetch ~3-5 sample files from the jackpot repo for LLM analysis."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept":        "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent":    "ghscan-extractor-synth/1.0",
    }
    parts = [f"REPO: {full_name}\n"]

    # Pull files where ghscan found valid keys for this repo
    try:
        with db._conn() as c:
            rows = c.execute(
                """SELECT file_path, file_url, provider FROM found_keys
                   WHERE repo = ? AND is_valid = 1
                   ORDER BY discovered_at DESC LIMIT 8""",
                (full_name,),
            ).fetchall()
            file_samples = [dict(r) for r in rows]
    except Exception:
        return ""

    parts.append(f"valid keys found in: {[r['file_path'] for r in file_samples]}")
    parts.append(f"providers seen: {sorted({r['provider'] for r in file_samples})}")

    # Fetch top of each file (~2KB) to give LLM concrete leak context
    import base64
    for r in file_samples[:5]:
        try:
            url_path = r["file_url"]
            # Convert blob URL to API contents URL
            m = re.match(
                r"https?://github\.com/([^/]+)/([^/]+)/blob/[^/]+/(.+)$",
                url_path,
            )
            if not m:
                continue
            api_url = f"https://api.github.com/repos/{m.group(1)}/{m.group(2)}/contents/{m.group(3)}"
            resp = await client.get(api_url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("encoding") == "base64":
                    content = base64.b64decode(data["content"]).decode(
                        "utf-8", errors="ignore")[:2000]
                    parts.append(f"\n--- {r['file_path']} (provider hint: {r['provider']}) ---")
                    parts.append(content)
        except Exception:
            continue

    return "\n".join(parts)


def _parse_response(text: str | None) -> list[dict]:
    if not text:
        return []
    txt = text.strip()
    if txt.startswith("```"):
        txt = re.sub(r"^```(?:json)?\s*", "", txt)
        txt = re.sub(r"\s*```$", "", txt)
    try:
        d = json.loads(txt)
    except json.JSONDecodeError:
        m = re.search(r"\{[\s\S]*\}", txt)
        if not m:
            return []
        try:
            d = json.loads(m.group(0))
        except json.JSONDecodeError:
            return []
    return [p for p in d.get("patterns", []) if isinstance(p, dict)]


def _validate_pattern(p: dict) -> tuple[Any, str] | None:
    """Compile + sanity-check the regex. Return (compiled_re, provider) or
    None if invalid."""
    rgx = (p.get("regex") or "").strip()
    if not rgx or len(rgx) > 500:
        return None
    try:
        compiled = re.compile(rgx)
    except re.error:
        return None
    # Must have at least one capture group
    if compiled.groups < 1:
        return None
    provider = (p.get("provider") or "generic").strip().lower()
    if provider not in _VALID_PROVIDERS:
        provider = "generic"
    return compiled, provider


async def synthesize_for_jackpot(client: httpx.AsyncClient, full_name: str,
                                   token: str) -> list[tuple[Any, str]]:
    """Single-repo synthesis. Returns list of (compiled_regex, provider)
    tuples. Empty list if synthesis disabled, repo already done, or LLM
    failed.

    Caller (scanner.py post-jackpot) can apply these regexes to remaining
    files in the repo to catch non-standard leaks.
    """
    if not ENABLED:
        return []
    if full_name in _SYNTHESIZED:
        return []  # already done this process lifetime

    # Verify jackpot threshold met
    try:
        with db._conn() as c:
            cnt = c.execute(
                "SELECT COUNT(*) FROM found_keys WHERE repo=? AND is_valid=1",
                (full_name,),
            ).fetchone()[0]
        if cnt < _JACKPOT_THRESHOLD_VALID_KEYS:
            return []
    except Exception:
        return []

    log.info("extractor_synth: jackpot %s detected (%d valid keys), synthesizing custom patterns",
             full_name, cnt)
    _SYNTHESIZED.add(full_name)

    evidence = await _fetch_jackpot_evidence(client, full_name, token)
    if not evidence:
        return []

    text, source = await call_creative(
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user",   "content": evidence},
        ],
        response_format={"type": "json_object"},
        timeout=600,
    )
    if not text:
        log.warning("extractor_synth: LLM unavailable for %s", full_name)
        return []

    raw = _parse_response(text)
    compiled: list[tuple[Any, str]] = []
    for p in raw[:8]:
        v = _validate_pattern(p)
        if v:
            compiled.append(v)

    log.info("extractor_synth: %s → %d valid patterns (source=%s, raw=%d)",
             full_name, len(compiled), source, len(raw))
    return compiled
