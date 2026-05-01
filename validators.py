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
import logging
import urllib.parse

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


_ARK_ENDPOINTS = [
    # China mainland (highest traffic)
    "https://ark.cn-beijing.volces.com/api/v3/models",
    "https://ark.cn-shanghai.volces.com/api/v3/models",
    "https://ark.cn-guangzhou.volces.com/api/v3/models",
    # International
    "https://ark.ap-southeast.volces.com/api/v3/models",   # Singapore
    "https://ark.us-east-1.volces.com/api/v3/models",      # Virginia
    "https://ark.eu-central-1.volces.com/api/v3/models",   # Frankfurt
    "https://ark.ap-northeast-1.volces.com/api/v3/models", # Tokyo
]

# Volcengine requires the Host header matching the region endpoint.
# Without it some regions return 400/ERR with SNI-based routing.
async def validate_ark(key: str) -> bool:
    for url in _ARK_ENDPOINTS:
        host = urllib.parse.urlparse(url).hostname or ""
        try:
            async with _client() as c:
                r = await c.get(
                    url,
                    headers={"Authorization": f"Bearer {key}", "Host": host},
                )
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
