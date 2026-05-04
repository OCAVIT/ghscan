"""
Combinatorial GitHub-search query generator.

Runs every 8 hours. For each provider, builds a Cartesian product of:
  env_names × filenames × languages × key_prefixes × domains × model_names
  + global axes (TIME_WINDOW_OFFSETS, SIZE_BUCKETS) for freshness/cap-busting.

15-day non-repeat is enforced by:
  1. db.get_recent_query_hashes(15) → set of forbidden hashes
  2. Pre-filter candidates BEFORE INSERT
  3. INSERT OR IGNORE as a race-safety belt

Per cycle we register at most BATCH_SIZE queries balanced across providers.
With ~30 providers × ~80 queries/cycle × 3 cycles/day = 7200 fresh queries/day
in flight, decaying out of the active pool after 15 days. Compares to the
1562 static QUERIES that run on every cycle.

Themes (for telemetry — what kind of permutation generated this query):
  env_file       — "ENV_NAME" filename:NAME
  env_lang       — "ENV_NAME" language:L
  prefix_file    — "key-prefix" filename:NAME
  prefix_lang    — "key-prefix" language:L
  domain_lang    — "api.domain" language:L
  domain_file    — "api.domain" filename:NAME
  model_file     — "model-name" filename:NAME
  model_lang     — "model-name" language:L
  env_path       — "ENV_NAME" path:DIR
  time_window    — any-of-above + pushed:>YYYY-MM-DD
  size_bucket    — any-of-above + size:N..M (cap-busting)
"""

from __future__ import annotations

import logging
import random
from datetime import datetime, timedelta, timezone

import db
from query_axes import (
    PROVIDER_AXES, FILENAMES, PATH_GLOBS, LANGUAGES,
    TIME_WINDOW_OFFSETS, TIME_QUALIFIERS, SIZE_BUCKETS,
    file_type_for, merged_axes_for,
)

log = logging.getLogger(__name__)


# How many fresh queries to register per 8h cycle. The scanner loops every
# SCAN_INTERVAL (default 30 min) — at 80 new queries/cycle and 16 cycles/day
# covered by 9 GitHub PATs we comfortably absorb the extra load.
BATCH_SIZE = 80

# Per-provider cap so heavy hitters (openai, ark) don't crowd out smaller
# providers. Generator round-robins across providers until BATCH_SIZE met.
PER_PROVIDER_MIN = 2
PER_PROVIDER_MAX = 6

# GH search query length cap — server returns 422 on overlong queries. 256
# is the documented limit; we leave 16 char safety margin for joining/escaping.
_QUERY_LEN_CAP = 240


def _fmt_date(days_back: int) -> str:
    d = datetime.now(timezone.utc).date() - timedelta(days=days_back)
    return d.isoformat()


def _quote(s: str) -> str:
    """Wrap in double quotes for GitHub code-search literal match. We only
    need to escape embedded double quotes — backslashes are not interpreted
    inside the q parameter."""
    return '"' + s.replace('"', '\\"') + '"'


def _build_one(provider: str, axes: dict[str, list[str]],
               theme: str, rnd: random.Random) -> tuple[str, str] | None:
    """Build a single (query_str, file_type) for the given theme.

    Returns None if the chosen axes are empty for this theme (e.g. provider
    has no key_prefixes — happens for shape-only providers like ark/fal)."""
    env_names     = axes.get("env_names", [])
    key_prefixes  = axes.get("key_prefixes", [])
    domains       = axes.get("domains", [])
    model_names   = axes.get("model_names", [])
    context_words = axes.get("context_words", [])     # AI-discovered, vocab_expander

    if theme == "env_file":
        if not env_names:
            return None
        e = rnd.choice(env_names)
        f = rnd.choice(FILENAMES)
        return f'{_quote(e)} filename:{f}', file_type_for(f)

    if theme == "env_lang":
        if not env_names:
            return None
        e = rnd.choice(env_names)
        l = rnd.choice(LANGUAGES)
        return f'{_quote(e)} language:{l}', "code"

    if theme == "prefix_file":
        if not key_prefixes:
            return None
        p = rnd.choice(key_prefixes)
        f = rnd.choice(FILENAMES)
        return f'{_quote(p)} filename:{f}', file_type_for(f)

    if theme == "prefix_lang":
        if not key_prefixes:
            return None
        p = rnd.choice(key_prefixes)
        l = rnd.choice(LANGUAGES)
        return f'{_quote(p)} language:{l}', "code"

    if theme == "domain_lang":
        if not domains:
            return None
        d = rnd.choice(domains)
        l = rnd.choice(LANGUAGES)
        return f'{_quote(d)} language:{l}', "code"

    if theme == "domain_file":
        if not domains:
            return None
        d = rnd.choice(domains)
        f = rnd.choice(FILENAMES)
        return f'{_quote(d)} filename:{f}', file_type_for(f)

    if theme == "model_file":
        if not model_names:
            return None
        m = rnd.choice(model_names)
        f = rnd.choice(FILENAMES)
        return f'{_quote(m)} filename:{f}', file_type_for(f)

    if theme == "model_lang":
        if not model_names:
            return None
        m = rnd.choice(model_names)
        l = rnd.choice(LANGUAGES)
        return f'{_quote(m)} language:{l}', "code"

    if theme == "env_path":
        if not env_names:
            return None
        e = rnd.choice(env_names)
        p = rnd.choice(PATH_GLOBS)
        return f'{_quote(e)} path:{p}', "config"

    if theme == "env_combo":
        # Two env_names + filename — picks files declaring multiple providers
        # at once (LLM template repos love this pattern).
        if len(env_names) < 2:
            return None
        e1, e2 = rnd.sample(env_names, 2)
        f = rnd.choice(FILENAMES)
        return f'{_quote(e1)} {_quote(e2)} filename:{f}', file_type_for(f)

    if theme == "ctx_file":
        # AI-discovered context word + filename — catches files that don't
        # declare a standard env-name but do reference distinctive SDK calls
        # (e.g. "openai.AsyncOpenAI" filename:.env).
        if not context_words:
            return None
        c = rnd.choice(context_words)
        f = rnd.choice(FILENAMES)
        return f'{_quote(c)} filename:{f}', file_type_for(f)

    if theme == "ctx_lang":
        if not context_words:
            return None
        c = rnd.choice(context_words)
        l = rnd.choice(LANGUAGES)
        return f'{_quote(c)} language:{l}', "code"

    if theme == "ctx_env":
        # Context word + env_name — anchors a real SDK reference next to a
        # variable name. Highest precision combo.
        if not context_words or not env_names:
            return None
        c = rnd.choice(context_words)
        e = rnd.choice(env_names)
        f = rnd.choice(FILENAMES)
        return f'{_quote(c)} {_quote(e)} filename:{f}', file_type_for(f)

    return None


# Themes ordered roughly by historical hit-density. The generator iterates
# this list and rolls each theme's dice once per provider per cycle.
_THEMES = [
    "env_file", "env_lang", "prefix_file", "prefix_lang",
    "domain_lang", "domain_file", "model_file", "model_lang",
    "env_path", "env_combo",
    # AI-vocab-driven (context_words from vocab_expander)
    "ctx_file", "ctx_lang", "ctx_env",
]

# Providers that are part of GitHub Secret Scanning Partner Program.
# Their leaked keys get auto-revoked within 24h. To stand a chance of
# catching live ones we MUST attach pushed:>(yesterday) and bias toward
# fresh-indexed content.
_SS_PARTNER_PROVIDERS = {
    "anthropic", "openai", "openai_image", "google",   # confirmed in program
    "suno", "perplexity", "huggingface",                # in program
    "fireworks",                                         # uncertain but treated similarly
}


def _maybe_add_modifier(query: str, rnd: random.Random,
                        provider: str = "") -> tuple[str, str]:
    """Roll for time-window or size-bucket modifier.

    For SS-Partner-Program providers (anthropic/openai/suno/perplexity/etc),
    auto-revoke happens within 24h. We FORCE pushed:>(yesterday) on these
    queries — without that they'd waste rate-limit on guaranteed-revoked
    keys. The 24h-window catches keys in the pre-revoke race.
    """
    if provider in _SS_PARTNER_PROVIDERS:
        # Always attach the freshest-possible time window
        days = rnd.choice([1, 2, 3])    # 1-3 days back
        qual = "pushed:>"
        modifier = f"{qual}{_fmt_date(days)}"
        # 30% also add a size bucket to bypass 1000-result cap on broad
        # queries when the time-window doesn't narrow enough
        if rnd.random() < 0.3:
            modifier = f"{modifier} {rnd.choice(SIZE_BUCKETS)}"
            return f"{query} {modifier}", "+time-revoke-race+size"
        return f"{query} {modifier}", "+time-revoke-race"

    roll = rnd.random()
    if roll < 0.40:
        # Time window — pushed:>YYYY-MM-DD or created:>YYYY-MM-DD
        days = rnd.choice(TIME_WINDOW_OFFSETS)
        qual = rnd.choice(TIME_QUALIFIERS)
        modifier = f"{qual}{_fmt_date(days)}"
        return f"{query} {modifier}", "+time"
    if roll < 0.60:
        # Size bucket — splits cap-bound broad queries into sub-1000 slices
        modifier = rnd.choice(SIZE_BUCKETS)
        return f"{query} {modifier}", "+size"
    return query, ""


def generate_batch(batch_size: int = BATCH_SIZE, seed: int | None = None) -> int:
    """
    Generate one batch of fresh queries and INSERT them into dynamic_queries.

    Returns count of NEW rows inserted (already-seen hashes skipped).
    Caller is the 8h rotation loop in main.py.
    """
    rnd = random.Random(seed)
    forbidden = db.get_recent_query_hashes(days=15)
    log.info("query_gen: starting batch — %d hashes in 15-day exclusion window",
             len(forbidden))

    providers = list(PROVIDER_AXES.keys())
    rnd.shuffle(providers)

    candidates: list[dict] = []
    seen_in_batch: set[str] = set()
    per_provider_count: dict[str, int] = {p: 0 for p in providers}

    # Multi-pass: keep cycling providers until BATCH_SIZE met or we hit
    # an effective ceiling (every provider exhausted). Per-pass cap of
    # PER_PROVIDER_MAX prevents runaway concentration.
    max_passes = 12
    for pass_no in range(max_passes):
        if len(candidates) >= batch_size:
            break
        added_this_pass = 0
        for prov in providers:
            if len(candidates) >= batch_size:
                break
            if per_provider_count[prov] >= PER_PROVIDER_MAX:
                continue

            ext = db.get_axis_extensions(prov) or {}
            axes = merged_axes_for(prov, ext)

            # Skip providers with no usable axes (no env_names AND no prefixes
            # AND no domains AND no models — true for none of our 30 providers
            # but defensive).
            if not (axes.get("env_names") or axes.get("key_prefixes") or
                    axes.get("domains") or axes.get("model_names")):
                continue

            # Roll a theme that's compatible with this provider's axes.
            # We try up to 8 themes before giving up this pass for this prov.
            for _ in range(8):
                theme = rnd.choice(_THEMES)
                built = _build_one(prov, axes, theme, rnd)
                if built is None:
                    continue
                query, file_type = built
                # 50/50 modifier (forced to pushed:>recent for SS-Partner providers)
                query, mod_suffix = _maybe_add_modifier(query, rnd, provider=prov)
                # Length guard
                if len(query) > _QUERY_LEN_CAP:
                    continue

                from db import _query_hash
                h = _query_hash(query)
                if h in forbidden or h in seen_in_batch:
                    continue
                seen_in_batch.add(h)
                candidates.append({
                    "query_str": query,
                    "provider":  prov,
                    "file_type": file_type,
                    "theme":     theme + mod_suffix,
                })
                per_provider_count[prov] += 1
                added_this_pass += 1
                break   # one query per provider per pass

        # Floor enforcement — make sure each provider gets at least PER_PROVIDER_MIN
        # before we stop early.
        if added_this_pass == 0:
            below_floor = [p for p in providers
                           if per_provider_count[p] < PER_PROVIDER_MIN]
            if not below_floor:
                # Everyone met the floor; stop early
                break

    if not candidates:
        log.warning("query_gen: produced 0 candidates — every combination "
                    "in the rolling axes is already in the 15-day window")
        return 0

    inserted = db.register_dynamic_queries(candidates)
    log.info(
        "query_gen: inserted %d/%d new queries this batch | "
        "by provider: %s",
        inserted, len(candidates),
        {p: c for p, c in per_provider_count.items() if c > 0},
    )
    return inserted


def auto_blacklist_dead() -> int:
    """Convenience wrapper — call at the end of each 8h rotation cycle so
    queries that have been tried 5+ times with zero yield drop out of
    rotation for 30 days."""
    n = db.auto_blacklist_dead_queries(min_uses=5, blacklist_days=30)
    if n:
        log.info("query_gen: auto-blacklisted %d dead queries (5+ uses, 0 yield)", n)
    return n
