"""
Live validation of found keys against provider APIs.
Returns True if key is confirmed active.
"""

import asyncio
import logging
import httpx

log = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(12.0)


async def validate_openai(key: str) -> bool:
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            r = await c.get(
                "https://api.openai.com/v1/models",
                headers={"Authorization": f"Bearer {key}"},
            )
            # 200 = valid key with models access
            # 401 = invalid / revoked
            # 403 = valid key, org restrictions  → still a live key
            # 429 = rate-limited but key exists  → also live
            return r.status_code in (200, 403, 429)
    except Exception as e:
        log.debug("openai validate err: %s", e)
        return False


async def validate_ark(key: str) -> bool:
    """
    ARK / Volcengine endpoint — UUID bearer token.
    Tries the models list endpoint (no-op, low cost).
    """
    urls = [
        "https://ark.cn-beijing.volces.com/api/v3/models",
        "https://ark.ap-southeast.volces.com/api/v3/models",
    ]
    for url in urls:
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
                r = await c.get(url, headers={"Authorization": f"Bearer {key}"})
                if r.status_code in (200, 403, 429):
                    return True
                if r.status_code == 401:
                    continue  # try next endpoint
        except Exception as e:
            log.debug("ark validate err (%s): %s", url, e)
    return False


VALIDATORS = {
    "openai": validate_openai,
    "ark": validate_ark,
}


async def validate(provider: str, key: str) -> bool:
    fn = VALIDATORS.get(provider)
    if fn is None:
        return False
    return await fn(key)
