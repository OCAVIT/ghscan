"""
Master-side: pull per-query yield stats from each mirror into local DB
so kaggle_themer's positive-example (top yielders) and negative-example
(confirmed dead queries) feedback paths see real numbers.

Why this exists:
  - Kaggle scanner runs ONLY on mirrors (master's Railway IP is on
    Cloudflare's DC blocklist for Kaggle, m1/m2 IPs pass).
  - Themer runs ONLY on master (uses DeepSeek for query generation).
  - Without this sync, master's kaggle_dynamic_queries has yield=0 for
    every row, themer's `_top_yielders()` returns an empty list, and the
    prompt has no real-world feedback signal.

Flow:
  1. Every MIRROR_YIELD_SYNC_SEC seconds, master fetches
     /admin/kaggle_yield_export from each MIRROR_URL.
  2. Merges rows into local kaggle_dynamic_queries using MAX semantics
     (db.kaggle_merge_mirror_yield).
  3. Themer reads top yielders + dead queries on next batch.

MAX semantics rationale: two mirrors scan independently, so each kernel
returned by query Q is double-counted if we SUM. MAX gives "best yield
seen on any mirror" — good enough for the binary question "is Q dead?".
"""

from __future__ import annotations

import asyncio
import logging

import httpx

from config import MIRROR_URLS, MIRROR_YIELD_SYNC_SEC, MASTER_API_TOKEN

log = logging.getLogger(__name__)


async def _pull_one(client: httpx.AsyncClient, url: str) -> tuple[int, int]:
    """Returns (rows_pulled, rows_merged). Logs on failure but doesn't raise
    — one bad mirror shouldn't block the others."""
    try:
        r = await client.get(
            f"{url}/admin/kaggle_yield_export",
            headers={"Authorization": f"Bearer {MASTER_API_TOKEN}"},
            timeout=120,
        )
        if r.status_code != 200:
            log.warning("yield_sync %s: HTTP %d body=%s",
                        url, r.status_code, r.text[:200])
            return 0, 0
        body = r.json()
        rows = body.get("rows", [])
        if not rows:
            return 0, 0
        import db
        merged = db.kaggle_merge_mirror_yield(rows)
        return len(rows), merged
    except Exception as e:
        log.warning("yield_sync %s failed: %s: %s", url, type(e).__name__, e)
        return 0, 0


async def yield_sync_loop() -> None:
    """Background task — run on master only. Pulls yield from every mirror
    every MIRROR_YIELD_SYNC_SEC. No-op when MIRROR_URLS is empty."""
    if not MIRROR_URLS:
        log.info("yield_sync: MIRROR_URLS empty — sync disabled")
        return
    if not MASTER_API_TOKEN:
        log.warning("yield_sync: MASTER_API_TOKEN empty — cannot authenticate "
                    "to mirror admin endpoints, sync disabled")
        return

    log.info("yield_sync started — pulling from %d mirror(s) every %ds",
             len(MIRROR_URLS), MIRROR_YIELD_SYNC_SEC)

    async with httpx.AsyncClient() as client:
        while True:
            try:
                tasks = [_pull_one(client, u) for u in MIRROR_URLS]
                results = await asyncio.gather(*tasks, return_exceptions=False)
                total_pulled = sum(p for p, _ in results)
                total_merged = sum(m for _, m in results)
                log.info("yield_sync tick: pulled=%d merged=%d across %d mirror(s)",
                         total_pulled, total_merged, len(MIRROR_URLS))
            except Exception as e:
                log.error("yield_sync tick crashed: %s", e)
            await asyncio.sleep(MIRROR_YIELD_SYNC_SEC)
