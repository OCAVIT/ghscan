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

import os
import logging
import httpx

log = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(15.0)

# Evomi residential proxy — only for validation calls, not GitHub API calls.
# Format: http://user:pass@rp.evomi.com:1000  (HTTP residential)
#         http://user:pass@rp.evomi.com:1001  (HTTPS residential)
#         http://user:pass@rp.evomi.com:1002  (SOCKS5 residential)
_PROXY_URL = os.environ.get("EVOMI_PROXY", "")


def _client(**kwargs) -> httpx.AsyncClient:
    """Return an AsyncClient optionally routed through Evomi proxy."""
    if _PROXY_URL:
        return httpx.AsyncClient(
            timeout=_TIMEOUT,
            proxy=_PROXY_URL,
            **kwargs,
        )
    return httpx.AsyncClient(timeout=_TIMEOUT, **kwargs)


async def validate_openai(key: str) -> bool:
    try:
        async with _client() as c:
            r = await c.get(
                "https://api.openai.com/v1/models",
                headers={"Authorization": f"Bearer {key}"},
            )
            return r.status_code in (200, 403, 429)
    except Exception as e:
        log.debug("openai validate err: %s", e)
        return False


async def validate_anthropic(key: str) -> bool:
    try:
        async with _client() as c:
            r = await c.get(
                "https://api.anthropic.com/v1/models",
                headers={
                    "x-api-key": key,
                    "anthropic-version": "2023-06-01",
                },
            )
            return r.status_code in (200, 403, 429)
    except Exception as e:
        log.debug("anthropic validate err: %s", e)
        return False


async def validate_google(key: str) -> bool:
    if key.startswith("sa:"):
        return False
    try:
        async with _client() as c:
            r = await c.get(
                "https://generativelanguage.googleapis.com/v1/models",
                params={"key": key},
            )
            return r.status_code in (200, 403, 429)
    except Exception as e:
        log.debug("google validate err: %s", e)
        return False


async def validate_deepseek(key: str) -> bool:
    try:
        async with _client() as c:
            r = await c.get(
                "https://api.deepseek.com/models",
                headers={"Authorization": f"Bearer {key}"},
            )
            return r.status_code in (200, 403, 429)
    except Exception as e:
        log.debug("deepseek validate err: %s", e)
        return False


async def validate_elevenlabs(key: str) -> bool:
    try:
        async with _client() as c:
            r = await c.get(
                "https://api.elevenlabs.io/v1/user",
                headers={"xi-api-key": key},
            )
            return r.status_code in (200, 403, 429)
    except Exception as e:
        log.debug("elevenlabs validate err: %s", e)
        return False


async def validate_ark(key: str) -> bool:
    urls = [
        "https://ark.cn-beijing.volces.com/api/v3/models",
        "https://ark.ap-southeast.volces.com/api/v3/models",
    ]
    for url in urls:
        try:
            async with _client() as c:
                r = await c.get(url, headers={"Authorization": f"Bearer {key}"})
                if r.status_code in (200, 403, 429):
                    return True
                if r.status_code == 401:
                    continue
        except Exception as e:
            log.debug("ark validate err (%s): %s", url, e)
    return False


async def validate_happyhorse(key: str) -> bool:
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
