"""
Repo prioritizer — pre-treewalk classification.

When a key is found in a repo, ghscan triggers walk_repo_tree to exhaustively
scan all files. ~30-40% of these repos turn out to be templates/tutorials/
example projects with placeholder keys (sk-XXXXXXXX, AIzaSy<your-key>) that
waste 40-100 file fetches each.

This module asks the cheap LLM (deepseek-v4-flash / glm-4.5-air) to classify
the repo as production / template / tutorial / example using only metadata
(README first chunk + file list + topics + stars). Treewalk is skipped on
template/tutorial.

Cost: ~500 bytes input + 100 bytes output × ~200 calls/h = trivial.

Architecture: scanner.py calls should_walk_repo() before walk_repo_tree().
If it returns False, the repo is logged with class+confidence and skipped.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

import httpx

import db
from llm_client import call_fast

log = logging.getLogger(__name__)


# In-memory cache so we don't re-classify the same repo across cycles. Keyed
# by full_name. Values: {"class": str, "confidence": int, "ts": float}.
# Cleared on process restart — that's fine, classifier is cheap to retry.
_CACHE: dict[str, dict] = {}
_CACHE_TTL_SEC = 24 * 3600  # 24h — repo classification rarely changes


_SYSTEM_PROMPT = (
    "You classify GitHub repositories as production / template / tutorial / "
    "example based on README + file structure + topics. Output JSON only:\n"
    '{"class":"production|template|tutorial|example","confidence":0-100}\n\n'
    "Definitions:\n"
    "- production: real app/service deployed somewhere; specific business "
    "logic; not generic boilerplate. Has chance of leaked PRODUCTION keys.\n"
    "- template: 'starter-kit', 'awesome-X', 'X-template', curated lists. "
    "Keys here are placeholders or example values.\n"
    "- tutorial: course material, '101 guide', 'getting started with X'. "
    "Keys here are tutorial-only or YOUR_KEY_HERE patterns.\n"
    "- example: official SDK examples, demo apps, 'try it yourself' repos. "
    "Same: placeholder keys.\n\n"
    "Confidence: 0-100. Use ≥70 only when STRONG signals present "
    "(repo name keywords, README explicit framing, topic tags)."
)


async def _build_user_prompt(client: httpx.AsyncClient, full_name: str,
                              token: str) -> str | None:
    """Fetch lightweight metadata (~3KB) from GitHub: top-level files, topics,
    README first chunk, repo description, stars. Returns assembled prompt
    string or None if metadata unavailable."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept":        "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent":    "ghscan-repo-prioritizer/1.0",
    }
    parts: list[str] = [f"REPO: {full_name}\n"]

    # Repo metadata
    try:
        r = await client.get(
            f"https://api.github.com/repos/{full_name}",
            headers=headers, timeout=10,
        )
        if r.status_code == 200:
            meta = r.json()
            parts.append(f"description: {meta.get('description') or '(none)'}")
            parts.append(f"stars: {meta.get('stargazers_count', 0)}")
            parts.append(f"language: {meta.get('language') or '?'}")
            parts.append(f"is_fork: {meta.get('fork', False)}")
            parts.append(f"is_template: {meta.get('is_template', False)}")
            parts.append(f"created: {meta.get('created_at', '?')[:10]}")
        else:
            return None
    except Exception:
        return None

    # Topics
    try:
        r = await client.get(
            f"https://api.github.com/repos/{full_name}/topics",
            headers={**headers, "Accept": "application/vnd.github.mercy-preview+json"},
            timeout=10,
        )
        if r.status_code == 200:
            topics = r.json().get("names", [])
            parts.append(f"topics: {topics[:20]}")
    except Exception:
        pass

    # Top-level file list
    try:
        r = await client.get(
            f"https://api.github.com/repos/{full_name}/contents/",
            headers=headers, timeout=10,
        )
        if r.status_code == 200:
            files = [e.get("name", "")[:50] for e in r.json()[:30]]
            parts.append(f"top_level_files: {files}")
    except Exception:
        pass

    # README (first 2KB)
    for readme_name in ("README.md", "README.rst", "README.txt", "Readme.md", "readme.md"):
        try:
            r = await client.get(
                f"https://api.github.com/repos/{full_name}/contents/{readme_name}",
                headers=headers, timeout=10,
            )
            if r.status_code == 200:
                import base64
                data = r.json()
                if data.get("encoding") == "base64":
                    try:
                        readme_text = base64.b64decode(data["content"]).decode(
                            "utf-8", errors="ignore")[:2000]
                        parts.append(f"\nREADME:\n{readme_text}")
                        break
                    except Exception:
                        pass
        except Exception:
            continue

    return "\n".join(parts)


def _parse_classification(text: str | None) -> tuple[str, int] | None:
    """Parse LLM output → ('class_name', confidence). None on parse failure."""
    if not text:
        return None
    txt = text.strip()
    if txt.startswith("```"):
        txt = re.sub(r"^```(?:json)?\s*", "", txt)
        txt = re.sub(r"\s*```$", "", txt)
    try:
        d = json.loads(txt)
    except json.JSONDecodeError:
        m = re.search(r"\{[^{}]*\}", txt)
        if not m:
            return None
        try:
            d = json.loads(m.group(0))
        except json.JSONDecodeError:
            return None
    cls = (d.get("class") or "").strip().lower()
    if cls not in ("production", "template", "tutorial", "example"):
        return None
    try:
        conf = int(d.get("confidence", 50))
    except (ValueError, TypeError):
        conf = 50
    return cls, max(0, min(100, conf))


async def should_walk_repo(client: httpx.AsyncClient, full_name: str,
                            token: str) -> bool:
    """Returns True if repo should be tree-walked, False to skip.

    Skip rules:
      - class='template' AND confidence>=70 → skip
      - class='tutorial' AND confidence>=70 → skip
      - class='example' AND confidence>=80 → skip (some 'examples' are real)
      - production OR low confidence → walk

    On classifier failure, defaults to True (don't lose finds on errors)."""
    import time as _time

    # In-memory cache — avoid re-classifying the same repo across cycles.
    cached = _CACHE.get(full_name)
    if cached and (_time.time() - cached["ts"] < _CACHE_TTL_SEC):
        return _decide(cached["class"], cached["confidence"])

    prompt = await _build_user_prompt(client, full_name, token)
    if not prompt:
        # Couldn't fetch metadata — default walk (be conservative)
        return True

    text, source = await call_fast(
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user",   "content": prompt},
        ],
        response_format={"type": "json_object"},
        max_tokens=128,
        timeout=20,
    )
    parsed = _parse_classification(text)
    if not parsed:
        # LLM unavailable or unparseable — walk by default
        log.debug("repo_prioritizer: %s could not classify (source=%s) — walking",
                  full_name, source)
        return True

    cls, conf = parsed
    _CACHE[full_name] = {"class": cls, "confidence": conf, "ts": _time.time()}
    decision = _decide(cls, conf)
    log.info("repo_prioritizer: %s → %s (conf=%d, source=%s) → %s",
             full_name, cls, conf, source, "WALK" if decision else "SKIP")
    return decision


def _decide(cls: str, confidence: int) -> bool:
    """Skip-or-walk decision logic."""
    if cls == "template"  and confidence >= 70: return False
    if cls == "tutorial"  and confidence >= 70: return False
    if cls == "example"   and confidence >= 80: return False
    return True


def cache_stats() -> dict:
    """For /admin diagnostics."""
    by_class: dict[str, int] = {}
    for v in _CACHE.values():
        by_class[v["class"]] = by_class.get(v["class"], 0) + 1
    return {
        "cached_repos": len(_CACHE),
        "by_class":     by_class,
    }
