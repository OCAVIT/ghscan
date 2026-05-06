"""
Author psychology profile — predicts recidivism likelihood for an author who
just leaked an API key.

Why: serial leakers exist. ~20% of leakers leak again within 30 days. Current
author_walk_loop walks watched authors ~daily. With LLM-priority scoring we
can:
  - Watch HIGH-priority authors every 5 min (catch fresh leaks before SS
    Partner auto-revoke kills them)
  - Watch LOW-priority authors weekly (saves API budget)
  - Filter "one-time hackathon student" from "production engineer who just
    pushed real keys to public repo"

Cheap LLM (deepseek-v4-flash / glm-4.5-air) reads:
  - Author profile metadata (login, public_repos, followers, account age)
  - Last 30 commits across all their repos
  - README style of their main repo (production framework? tutorial?)
  - Topic tags of their repos

Output: {recidivism_score: 0-100, watch_priority: low|medium|high, next_check_hours}

Score interpretation:
  - 80-100: production engineer, watch every 5 min for 7 days, then daily
  - 50-80:  active dev, watch hourly
  - 20-50:  occasional pusher, watch every 6h
  - 0-20:   one-time hackathon/student, watch weekly
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone

import httpx

import db
from llm_client import call_fast

log = logging.getLogger(__name__)


_SYSTEM_PROMPT = (
    "You score the recidivism likelihood of a GitHub user who just leaked an "
    "API key. Output JSON only:\n"
    '{"recidivism_score":0-100,"watch_priority":"low|medium|high","next_check_hours":N,"reason":"short"}\n\n'
    "Scoring rubric:\n"
    "  - 80-100: production developer (active commits, real apps, work email "
    "in profile). Watch HIGH priority every 5min × 7 days.\n"
    "  - 50-79: active hobbyist, multiple real repos, moderate commit cadence. "
    "Watch MEDIUM hourly.\n"
    "  - 20-49: occasional pusher, mostly forks/templates. Watch LOW every 6h.\n"
    "  - 0-19:  one-time hackathon student, single tutorial fork, no real "
    "production work. Watch LOW weekly.\n\n"
    "Signals INCREASING score: many real repos, recent active commits, work "
    "email, large followers, README mentions production, framework-specific "
    "real apps (Next.js prod sites, Django apps, Rails APIs).\n"
    "Signals DECREASING score: only forks, only tutorial-named repos, "
    "'student' / 'cs101' / 'hackathon' in profile, single-commit repos."
)


async def _build_user_prompt(client: httpx.AsyncClient, login: str,
                              token: str) -> str | None:
    """Fetch lightweight metadata about the author. ~5KB total."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept":        "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent":    "ghscan-author-profiler/1.0",
    }
    parts = [f"AUTHOR: {login}"]

    # User profile
    try:
        r = await client.get(
            f"https://api.github.com/users/{login}",
            headers=headers, timeout=10,
        )
        if r.status_code == 200:
            u = r.json()
            parts.append(f"public_repos: {u.get('public_repos', 0)}")
            parts.append(f"followers: {u.get('followers', 0)}")
            parts.append(f"following: {u.get('following', 0)}")
            parts.append(f"created: {u.get('created_at', '?')[:10]}")
            parts.append(f"bio: {(u.get('bio') or '')[:200]}")
            parts.append(f"company: {u.get('company') or '(none)'}")
            parts.append(f"email: {u.get('email') or '(private)'}")
            parts.append(f"blog: {u.get('blog') or '(none)'}")
        else:
            return None
    except Exception:
        return None

    # Top 10 repos with metadata (lightweight, no contents)
    try:
        r = await client.get(
            f"https://api.github.com/users/{login}/repos?per_page=20&sort=updated",
            headers=headers, timeout=10,
        )
        if r.status_code == 200:
            repos = r.json()
            parts.append("\nTOP 20 REPOS (sorted by recent update):")
            for repo in repos[:20]:
                parts.append(
                    f"  - {repo.get('name','?'):40s} "
                    f"stars={repo.get('stargazers_count',0):4d}  "
                    f"fork={repo.get('fork',False):1}  "
                    f"lang={repo.get('language') or '?':10s}  "
                    f"desc={(repo.get('description') or '')[:80]}"
                )
    except Exception:
        pass

    # Recent events (commit cadence indicator)
    try:
        r = await client.get(
            f"https://api.github.com/users/{login}/events/public?per_page=20",
            headers=headers, timeout=10,
        )
        if r.status_code == 200:
            events = r.json()
            event_types: dict[str, int] = {}
            for e in events[:20]:
                event_types[e.get("type", "?")] = event_types.get(e.get("type", "?"), 0) + 1
            parts.append(f"\nrecent_events_distribution: {event_types}")
    except Exception:
        pass

    return "\n".join(parts)


def _parse_response(text: str | None) -> dict | None:
    if not text:
        return None
    txt = text.strip()
    if txt.startswith("```"):
        txt = re.sub(r"^```(?:json)?\s*", "", txt)
        txt = re.sub(r"\s*```$", "", txt)
    try:
        d = json.loads(txt)
    except json.JSONDecodeError:
        m = re.search(r"\{[\s\S]*\}", txt)
        if not m:
            return None
        try:
            d = json.loads(m.group(0))
        except json.JSONDecodeError:
            return None
    try:
        return {
            "recidivism_score":   max(0, min(100, int(d.get("recidivism_score", 50)))),
            "watch_priority":     str(d.get("watch_priority", "medium")).lower(),
            "next_check_hours":   max(1, min(168, int(d.get("next_check_hours", 24)))),
            "reason":             str(d.get("reason", ""))[:200],
        }
    except (ValueError, TypeError):
        return None


async def profile_author(client: httpx.AsyncClient, login: str,
                          token: str) -> dict | None:
    """Single-author profiling. Returns dict with score + priority + check
    interval, or None if classification unavailable.

    Use this in author_walk_loop to set per-author check cadence: high =
    every 5 min, medium = hourly, low = every 24h+.
    """
    prompt = await _build_user_prompt(client, login, token)
    if not prompt:
        return None

    text, source = await call_fast(
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user",   "content": prompt},
        ],
        response_format={"type": "json_object"},
        max_tokens=200,
        timeout=20,
    )
    parsed = _parse_response(text)
    if parsed:
        parsed["source"] = source
        log.info("author_profiler: %s → score=%d priority=%s next=%dh (%s)",
                 login, parsed["recidivism_score"], parsed["watch_priority"],
                 parsed["next_check_hours"], parsed.get("reason", "")[:80])
    return parsed
