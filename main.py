"""
FastAPI app with background scanner loop.
Web UI at /results and /stats.
"""

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, JSONResponse

import db
from config import SCAN_INTERVAL
from scanner import run_cycle

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger(__name__)


async def _loop():
    """Background task: runs forever, one cycle per SCAN_INTERVAL seconds."""
    while True:
        try:
            await run_cycle()
        except Exception as e:
            log.error("cycle crashed: %s", e)
        log.info("sleeping %ds until next cycle", SCAN_INTERVAL)
        await asyncio.sleep(SCAN_INTERVAL)


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    task = asyncio.create_task(_loop())
    yield
    task.cancel()


app = FastAPI(title="GitHub Key Scanner", lifespan=lifespan)


@app.get("/", response_class=HTMLResponse)
async def root():
    stats = db.get_stats()
    rows = db.get_results(valid_only=False, limit=50)
    rows_html = ""
    for r in rows:
        valid_badge = "✅" if r["is_valid"] else "⚠️"
        rows_html += (
            f"<tr><td>{valid_badge}</td>"
            f"<td>{r['provider']}</td>"
            f"<td><code>{r['key_preview']}</code></td>"
            f"<td><a href='https://github.com/{r['repo']}' target='_blank'>{r['repo']}</a></td>"
            f"<td>⭐{r['repo_stars']}</td>"
            f"<td>{r['file_type']}</td>"
            f"<td>{r['discovered_at'][:16]}</td></tr>\n"
        )
    return f"""<!DOCTYPE html><html><head><meta charset='utf-8'>
<title>Key Scanner</title>
<style>body{{font-family:monospace;background:#111;color:#eee;padding:20px}}
table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #333;padding:6px 10px;text-align:left}}
th{{background:#222}}tr:hover{{background:#1a1a1a}}a{{color:#58a6ff}}code{{background:#222;padding:2px 5px}}</style>
</head><body>
<h2>🔍 GitHub Key Scanner</h2>
<p>Repos scanned: <b>{stats['repos_scanned']}</b> &nbsp;|&nbsp;
   Files: <b>{stats['files_scanned']}</b> &nbsp;|&nbsp;
   Keys found: <b>{stats['keys_found']}</b> &nbsp;|&nbsp;
   Valid: <b style='color:#4caf50'>{stats['keys_valid']}</b></p>
<table><thead><tr><th>Status</th><th>Provider</th><th>Key</th>
<th>Repo</th><th>Stars</th><th>Type</th><th>Found at</th></tr></thead>
<tbody>{rows_html}</tbody></table>
</body></html>"""


@app.get("/stats")
async def stats():
    return db.get_stats()


@app.get("/results")
async def results(valid_only: bool = Query(False), limit: int = Query(200)):
    return db.get_results(valid_only=valid_only, limit=limit)


@app.get("/health")
async def health():
    return {"ok": True}
