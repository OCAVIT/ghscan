"""
Infrastructure credential patterns — DATABASE_URL, SSH keys, cloud provider
access keys, deploy tokens, CI/CD secrets.

Separate from patterns.py (AI provider keys) to keep concerns clean.
All providers here route to infra_findings table (not found_keys).

Coverage:
  database  — PostgreSQL, MySQL, MongoDB, Redis, MSSQL, CockroachDB, Supabase,
               PlanetScale, Neon, Turso, ClickHouse, Cassandra, Elasticsearch
  ssh       — RSA/EC/Ed25519/DSA/OPENSSH private keys
  aws       — AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY
  alibaba   — Alibaba Cloud / Aliyun LTAI* keys
  gcp       — GCP service account JSON (private_key in JSON blob)
  azure     — Azure connection strings, SAS tokens, client secrets
  infra     — Railway, Heroku, Vercel, Fly.io, Netlify, Cloudflare,
               Terraform Cloud, Doppler, Vault, DigitalOcean, Linode,
               Hetzner, OVH, Vultr
  database  covers: connection strings leaked in CI/CD, docker-compose,
               .env, k8s secrets, ansible vars
"""

import re
import urllib.parse
from datetime import datetime, timezone


# ══════════════════════════════════════════════════════════════════════════════
# SHARED HELPERS
# ══════════════════════════════════════════════════════════════════════════════

_FAKE = re.compile(
    r'(?:your_|your-|example|placeholder|xxx+|REPLACE|localhost|127\.0\.0\.1'
    r'|<db|<your|>|\.\.\.|\bfake\b|\bmock\b|\bdummy\b|\bsample\b|password123'
    r'|changeme|secret_here|key_here|insert_key|TODO|FIXME'
    r'|root:root|admin:admin|user:password|test:test|postgres:postgres'
    r'|user:pass@|user:pass$|host\.docker\.internal|dein_projekt'
    r'|\$\{[A-Z_][A-Z0-9_]*\}'                # ${ENV_VAR} interpolation
    r'|<%=|<\?php\s+echo|<<\s*[A-Z_]+\s*>>'    # template interpolation tokens
    r'|user:password@host|user:password@db)',
    re.IGNORECASE,
)


def _is_fake(s: str) -> bool:
    return bool(_FAKE.search(s))


# Detects URL-style creds without password (template patterns like
# postgres://postgres:5432, postgres://db:5432, redis://redis:6379).
# Real URLs always have password before @host.
_TEMPLATE_DSN = re.compile(
    r'^[a-zA-Z][a-zA-Z0-9+]*://'              # scheme://
    r'(?!.*@)'                                 # NO @ symbol anywhere = no password
    r'[a-zA-Z0-9._-]+'                         # user/host
    r':[0-9]+'                                 # :port
    r'(?:/|$)',                                # / or end
)


def _is_template_dsn(s: str) -> bool:
    return bool(_TEMPLATE_DSN.match(s))


def extract_destination(connection_string: str) -> str:
    """Pull host:port from a connection string for the 'where does this connect' log."""
    try:
        p = urllib.parse.urlparse(connection_string)
        if p.hostname and p.hostname not in ("localhost", "127.0.0.1", "::1"):
            port = f":{p.port}" if p.port else ""
            return f"{p.scheme}://{p.hostname}{port}"
    except Exception:
        pass
    return ""


# ══════════════════════════════════════════════════════════════════════════════
# DATABASE / CONNECTION STRINGS
# ══════════════════════════════════════════════════════════════════════════════

# Named env vars pointing to full DSN (highest precision)
_DB_NAMED = re.compile(
    r'(?:DATABASE_URL|DB_URL|POSTGRES(?:QL)?_URL|MYSQL_URL|MONGO(?:DB)?_URL'
    r'|MONGODB_URI|REDIS_URL|REDISCLOUD_URL|REDISTOGO_URL|REDIS_TLS_URL'
    r'|MSSQL_URL|COCKROACH_URL|NEON_DATABASE_URL|SUPABASE_DB_URL'
    r'|TURSO_DATABASE_URL|PLANETSCALE_URL|CLICKHOUSE_URL|CASSANDRA_URL'
    r'|ELASTICSEARCH_URL|CONNECTION_STRING|DATABASE_CONNECTION|DB_CONNECTION'
    r'|DATABASE_DSN|DB_DSN|SQLALCHEMY_DATABASE_URI|DJANGO_DATABASE_URL)'
    r'\s*[=:]\s*["\']?'
    r'([\w+.-]+://[^\s"\'\\]{10,})',
    re.IGNORECASE,
)

# Bare DSN anywhere in file (password must be present → @ in URL)
_DB_BARE = re.compile(
    r'\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis(?:s)?'
    r'|mssql|sqlserver|cockroachdb|clickhouse|cassandra|neo4j(?:\+s)?)'
    r'://[A-Za-z0-9_.%+-]+:[^@\s"\'`\\]{4,}@[A-Za-z0-9._-]+(?::\d+)?'
    r'/[A-Za-z0-9_.%-]*',
    re.IGNORECASE,
)

# Individual host/port/user/pass combos (lower precision, needs context)
_DB_HOST_CTX = re.compile(
    r'(?:DB_HOST|DATABASE_HOST|PGHOST|MYSQL_HOST|MONGO_HOST|REDIS_HOST)'
    r'\s*[=:]\s*["\']?([a-zA-Z0-9._-]{4,})["\']?',
    re.IGNORECASE,
)
_DB_PASS_CTX = re.compile(
    r'(?:DB_PASSWORD|DATABASE_PASSWORD|PGPASSWORD|MYSQL_PASSWORD'
    r'|MONGO_PASSWORD|REDIS_PASSWORD|DB_PASS|DATABASE_PASS)\s*[=:]\s*["\']?([^\s"\']{6,})["\']?',
    re.IGNORECASE,
)


def extract_database(content: str) -> list[str]:
    found = []

    # Named DSN vars (highest confidence)
    for m in _DB_NAMED.finditer(content):
        val = m.group(1).rstrip("'\"")
        if not _is_fake(val) and "@" in val:
            found.append(val)

    # Bare DSN in code — also reject template patterns (no password before @host)
    for m in _DB_BARE.finditer(content):
        val = m.group(0)
        if _is_fake(val) or _is_template_dsn(val):
            continue
        # Real DSN must have @ (separating creds from host); reject pure user:port
        if "@" not in val:
            continue
        found.append(val)

    # SPLIT-FORM RECONSTRUCTION
    # Devs often store DB creds as separate env vars in .env files:
    #   DB_HOST=prod.db.com
    #   DB_PORT=5432
    #   DB_USER=admin
    #   DB_PASSWORD=secret123
    #   DB_NAME=mydb
    # Our normal regex misses this entirely. Reconstruct DSN if all 3 of
    # (host, user, password) are present in the same file/block. Excluded
    # if any of them looks templated (${VAR}/{{var}}) or fake.
    fragments = _extract_db_fragments(content)
    if fragments.get("host") and fragments.get("password") and fragments.get("user"):
        scheme = fragments.get("scheme") or "postgres"
        host = fragments["host"]
        user = fragments["user"]
        pwd = fragments["password"]
        port = fragments.get("port") or "5432"
        dbname = fragments.get("name") or ""
        # Skip docker-internal hostnames (mock)
        if host.lower() in ("db", "postgres", "mongo", "redis", "mysql",
                             "mariadb", "localhost", "127.0.0.1", "0.0.0.0"):
            pass
        elif _is_fake(host) or _is_fake(pwd) or _is_fake(user):
            pass
        elif "${" in host or "${" in pwd or "{{" in host or "{{" in pwd:
            pass
        else:
            dsn = f"{scheme}://{user}:{pwd}@{host}:{port}/{dbname}"
            found.append(dsn)

    return list(dict.fromkeys(found))


_DB_FRAG_HOST = re.compile(
    r'(?m)^(?:export\s+)?'
    r'(?:DB_HOST|DATABASE_HOST|PGHOST|MYSQL_HOST|MONGO_HOST|REDIS_HOST'
    r'|POSTGRES_HOST|POSTGRESQL_HOST|MSSQL_HOST|MARIADB_HOST|HOST)'
    r'\s*[=:]\s*["\']?([A-Za-z0-9._\-]{4,80})["\']?\s*$'
)
_DB_FRAG_PORT = re.compile(
    r'(?m)^(?:export\s+)?'
    r'(?:DB_PORT|DATABASE_PORT|PGPORT|MYSQL_PORT|MONGO_PORT|REDIS_PORT'
    r'|POSTGRES_PORT|POSTGRESQL_PORT|PORT)'
    r'\s*[=:]\s*["\']?(\d{2,5})["\']?\s*$'
)
_DB_FRAG_USER = re.compile(
    r'(?m)^(?:export\s+)?'
    r'(?:DB_USER|DATABASE_USER|PGUSER|MYSQL_USER|MONGO_USER|REDIS_USER'
    r'|POSTGRES_USER|POSTGRESQL_USER|DB_USERNAME|DATABASE_USERNAME)'
    r'\s*[=:]\s*["\']?([A-Za-z0-9._\-]{2,40})["\']?\s*$'
)
_DB_FRAG_PASS = re.compile(
    r'(?m)^(?:export\s+)?'
    r'(?:DB_PASSWORD|DATABASE_PASSWORD|PGPASSWORD|MYSQL_PASSWORD|MONGO_PASSWORD'
    r'|REDIS_PASSWORD|POSTGRES_PASSWORD|POSTGRESQL_PASSWORD|DB_PASS|DATABASE_PASS|MYSQL_PASS)'
    r'\s*[=:]\s*["\']?([^\s"\']{6,80})["\']?\s*$'
)
_DB_FRAG_NAME = re.compile(
    r'(?m)^(?:export\s+)?'
    r'(?:DB_NAME|DATABASE_NAME|PGDATABASE|MYSQL_DATABASE|MONGO_DATABASE'
    r'|REDIS_DATABASE|POSTGRES_DB|POSTGRESQL_DB)'
    r'\s*[=:]\s*["\']?([A-Za-z0-9._\-]{1,40})["\']?\s*$'
)
# DB type hint — pick scheme based on what env vars are dominant
_DB_FRAG_TYPE_HINTS = [
    (re.compile(r'\bPG(?:HOST|PORT|USER|PASSWORD|DATABASE)\b'),  "postgres"),
    (re.compile(r'\bPOSTGRES(?:QL)?_(?:HOST|USER|PASSWORD|DB)\b'), "postgres"),
    (re.compile(r'\bMYSQL_(?:HOST|USER|PASSWORD|DATABASE)\b'),    "mysql"),
    (re.compile(r'\bMARIADB_(?:HOST|USER|PASSWORD)\b'),           "mysql"),
    (re.compile(r'\bMONGO_?(?:HOST|USER|PASSWORD|DATABASE)\b'),  "mongodb"),
    (re.compile(r'\bREDIS_(?:HOST|PASSWORD|PORT)\b'),             "redis"),
    (re.compile(r'\bMSSQL_'),                                     "mssql"),
]


def _extract_db_fragments(content: str) -> dict:
    """Pull split-form DB creds (DB_HOST/DB_PASSWORD/etc) from same content
    block. Returns dict with as many of {host, port, user, password, name,
    scheme} as can be found."""
    out: dict = {}
    if (m := _DB_FRAG_HOST.search(content)):
        out["host"] = m.group(1).strip()
    if (m := _DB_FRAG_PORT.search(content)):
        out["port"] = m.group(1).strip()
    if (m := _DB_FRAG_USER.search(content)):
        out["user"] = m.group(1).strip()
    if (m := _DB_FRAG_PASS.search(content)):
        out["password"] = m.group(1).strip()
    if (m := _DB_FRAG_NAME.search(content)):
        out["name"] = m.group(1).strip()
    # Pick scheme from dominant env-prefix
    for pat, scheme in _DB_FRAG_TYPE_HINTS:
        if pat.search(content):
            out["scheme"] = scheme
            break
    return out


# ══════════════════════════════════════════════════════════════════════════════
# SSH PRIVATE KEYS
# ══════════════════════════════════════════════════════════════════════════════

_SSH_KEY = re.compile(
    r'-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?:----- *\n?| BLOCK-----\n?)'
    r'(?:[A-Za-z0-9+/=\r\n ]{40,})'
    r'-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?:-----| BLOCK-----)',
    re.DOTALL,
)

# Env-var pointing to key content (base64 or literal)
_SSH_ENV = re.compile(
    r'(?:SSH_PRIVATE_KEY|DEPLOY_KEY|GIT_SSH_KEY|CI_SSH_KEY|ANSIBLE_PRIVATE_KEY'
    r'|PRIVATE_KEY_PEM|SSL_PRIVATE_KEY|TLS_PRIVATE_KEY)\s*[=:]\s*["\']?'
    r'(-----BEGIN[\s\S]{40,}?-----END[^-]+-----)',
    re.IGNORECASE | re.DOTALL,
)


def extract_ssh(content: str) -> list[str]:
    found = []
    for m in _SSH_KEY.finditer(content):
        key = m.group(0).strip()
        if len(key) > 100:
            found.append(key)
    for m in _SSH_ENV.finditer(content):
        key = m.group(1).strip()
        if key not in found and len(key) > 100:
            found.append(key)
    return found


# ══════════════════════════════════════════════════════════════════════════════
# AWS
# ══════════════════════════════════════════════════════════════════════════════

# Access key IDs: AKIA=long-term, AIPA=IAM, AIDA=IAM, AROA=role, ASIA=temp
_AWS_KEY_ID = re.compile(r'\b((?:AKIA|AIPA|AIDA|AROA|ASIA)[A-Z0-9]{16})\b')
_AWS_SECRET  = re.compile(
    r'(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key|secret_access_key)'
    r'\s*[=:]\s*["\']?([A-Za-z0-9+/]{40})["\']?',
    re.IGNORECASE,
)
_AWS_REGION = re.compile(
    r'(?:AWS_DEFAULT_REGION|AWS_REGION)\s*[=:]\s*["\']?([a-z]{2}-[a-z]+-\d)["\']?',
    re.IGNORECASE,
)


def extract_aws(content: str) -> list[str]:
    found   = []
    # Pre-collect all secrets and regions with their positions
    secrets = [(m.start(), m.group(1)) for m in _AWS_SECRET.finditer(content)]
    regions = [(m.start(), m.group(1)) for m in _AWS_REGION.finditer(content)]

    def _nearest(pos: int, items: list[tuple]) -> str | None:
        """Return the value of the item whose position is closest to pos."""
        return min(items, key=lambda t: abs(t[0] - pos))[1] if items else None

    for kid_m in _AWS_KEY_ID.finditer(content):
        kid = kid_m.group(1)
        if _is_fake(kid):
            continue
        secret = _nearest(kid_m.start(), secrets) if secrets else None
        region = _nearest(kid_m.start(), regions) if regions else "unknown-region"
        if secret:
            found.append(f"{kid}:{secret}@{region}")
        else:
            found.append(f"{kid}:secret_unknown@{region}")

    return list(dict.fromkeys(found))


# ══════════════════════════════════════════════════════════════════════════════
# ALIBABA CLOUD / ALIYUN
# ══════════════════════════════════════════════════════════════════════════════

# LTAI-prefix is the standard Alibaba access key shape (2017+).
# LTAI4G/5G are 2020+ versions. STS tokens are 'STS.NV...' for short-lived sessions.
_ALIYUN_KEY_ID = re.compile(r'\b(LTAI[A-Za-z0-9]{16,32}|STS\.[A-Za-z0-9]{20,160})\b')
_ALIYUN_SECRET  = re.compile(
    r'(?:'
    r'ALIBABA_CLOUD_ACCESS_KEY_SECRET|ALICLOUD_ACCESS_KEY_SECRET'
    r'|ALIYUN_ACCESS_KEY_SECRET|ALIYUN_AK_SECRET|ALI_ACCESS_KEY_SECRET'
    r'|ACCESS_KEY_SECRET|access_key_secret|accessKeySecret'
    r'|secretAccessKey|aliyunAccessKeySecret'
    # Chinese-language env naming patterns observed on Gitee
    r'|阿里云密钥|访问密钥SECRET|AccessKeySecret'
    r')'
    r'\s*[=:]\s*["\']?([A-Za-z0-9+/=_\-]{20,80})["\']?',
    re.IGNORECASE,
)
# Region values only — env-name anchors removed from this regex so we don't
# accidentally capture the variable name instead of the actual region string.
_ALIYUN_REGION = re.compile(
    r'\b('
    r'cn-(?:hangzhou|shanghai|beijing|shenzhen|qingdao|zhangjiakou'
    r'|huhehaote|chengdu|wulanchabu|guangzhou|hongkong)'
    r'|ap-(?:southeast-[1-6]|northeast-[12]|south-1)'
    r'|us-(?:east-1|west-1)'
    r'|eu-(?:central-1|west-1)'
    r'|me-east-1)\b',
    re.IGNORECASE,
)
# Chinese context words that strengthen confidence — used to RAISE score
# when a key-shape match has Chinese context near it.
_ALIYUN_CN_CONTEXT = re.compile(
    r'阿里云|访问密钥|密钥|接口密钥|AccessKey|aliyun|aliyuncs|oss-cn-|MaxCompute',
    re.IGNORECASE,
)
# Direct "aliyun://" or "oss://" URL-style creds (rare but real)
_ALIYUN_URL_DSN = re.compile(
    r'(?:aliyun|oss)://([A-Za-z0-9]+):([A-Za-z0-9+/=_\-]{20,80})@'
    r'([a-z0-9\-\.]+)',
    re.IGNORECASE,
)


def extract_alibaba(content: str) -> list[str]:
    found   = []
    secrets = [(m.start(), m.group(1)) for m in _ALIYUN_SECRET.finditer(content)]
    regions = [(m.start(), m.group(0)) for m in _ALIYUN_REGION.finditer(content)]
    has_cn_ctx = bool(_ALIYUN_CN_CONTEXT.search(content))

    def _nearest(pos: int, items: list[tuple]) -> str | None:
        return min(items, key=lambda t: abs(t[0] - pos))[1] if items else None

    # Standard LTAI/STS keys
    for kid_m in _ALIYUN_KEY_ID.finditer(content):
        kid = kid_m.group(1)
        if _is_fake(kid):
            continue
        # Skip raw kids in noisy contexts (logs, comments) unless CN context present
        ctx = content[max(0, kid_m.start()-100): kid_m.end()+100]
        if not has_cn_ctx and not _ALIYUN_CN_CONTEXT.search(ctx):
            # No alibaba/aliyun context within 200 chars — likely false positive
            # (LTAI in random base64). Require closer secret match.
            if not secrets or abs(_nearest_pos(kid_m.start(), secrets)) > 1000:
                continue
        secret = _nearest(kid_m.start(), secrets) if secrets else None
        region = _nearest(kid_m.start(), regions) if regions else "cn-unknown"
        if secret:
            found.append(f"{kid}:{secret}@{region}")
        else:
            found.append(f"{kid}:secret_unknown@{region}")

    # URL-style DSNs (direct creds, no need for nearest-secret lookup)
    for m in _ALIYUN_URL_DSN.finditer(content):
        kid, secret, host = m.group(1), m.group(2), m.group(3)
        if _is_fake(kid) or _is_fake(secret):
            continue
        # Guess region from host
        rm = re.search(r'(cn-[a-z]+|ap-[a-z]+-\d|us-[a-z]+-\d|eu-[a-z]+-\d)', host, re.I)
        region = rm.group(1) if rm else "cn-unknown"
        found.append(f"{kid}:{secret}@{region}")

    return list(dict.fromkeys(found))


def _nearest_pos(pos: int, items: list[tuple]) -> int:
    """Distance to nearest item position. Empty = inf-ish."""
    if not items:
        return 10**9
    return min(abs(t[0] - pos) for t in items)


# ══════════════════════════════════════════════════════════════════════════════
# AZURE
# ══════════════════════════════════════════════════════════════════════════════

_AZURE_CONN = re.compile(
    r'(?:AZURE_STORAGE_CONNECTION_STRING|AzureWebJobsStorage|'
    r'DefaultEndpointsProtocol=https;AccountName=)'
    r'[^\s"\']{30,}',
    re.IGNORECASE,
)
# SAS token: must have sv= (version), se= (expiry) and sig= (signature).
# Previous regex had sv=date&s[a-z]= with NO value — matched nothing real.
_AZURE_SAS = re.compile(
    r'sv=\d{4}-\d{2}-\d{2}[^\s"\'<>]{20,}&sig=[A-Za-z0-9+/=%]{20,}',
)
_AZURE_CLIENT_SECRET = re.compile(
    r'(?:AZURE_CLIENT_SECRET|ARM_CLIENT_SECRET)\s*[=:]\s*["\']?([A-Za-z0-9_\-~.]{30,})["\']?',
    re.IGNORECASE,
)
# Azure EventHub / Service Bus connection strings — high-value, often have
# unique keys with full namespace access.
_AZURE_EVENTHUB = re.compile(
    r'Endpoint=sb://[^;\s"\']+;SharedAccessKeyName=[^;\s"\']+;'
    r'SharedAccessKey=[A-Za-z0-9+/=]{30,}',
    re.IGNORECASE,
)
# Azure SQL connection string
_AZURE_SQL = re.compile(
    r'(?:Server|Data Source)=tcp:[^;,\s"\']+\.database\.windows\.net'
    r'[^"\']{20,}Password=[^;\s"\']+',
    re.IGNORECASE,
)
# Cosmos DB connection string. Real strings: "...azure.com:443/;AccountKey=..."
# (only 7 chars between azure.com and AccountKey).
_AZURE_COSMOS = re.compile(
    r'AccountEndpoint=https://[^;\s"\']+\.documents\.azure\.com'
    r'[^"\']*?AccountKey=[A-Za-z0-9+/=]{40,}',
    re.IGNORECASE,
)


def _azure_is_real_conn(conn: str) -> bool:
    """Reject extracted Azure conn-strings that are obviously placeholder/regex.

    Real Azure storage AccountKey is exactly 88 base64 chars ending in '=='
    (64 bytes encoded). We use that shape + entropy + canonical-account-name
    heuristics to filter trash extracted from leaked regex source code,
    documentation snippets, and obvious placeholders.
    """
    # 1) Regex source detection (someone committed their parser source)
    if any(marker in conn for marker in
           ("[A-Za-z", "[0-9]", "{40,", "[a-z]", "[0-9a-f]", "+/=]",
            "(?:", ")?", "\\d{")):
        return False

    # 2) AccountKey shape — should be 88 base64 chars (64 bytes raw).
    #    Accept 86-90 to allow padding-edge variations. <50 = placeholder.
    m = re.search(r'AccountKey=([^;\s"\']+)', conn, re.IGNORECASE)
    if m:
        key = m.group(1)
        # Length sanity
        if len(key) < 50 or len(key) > 200:
            return False
        # Placeholder words / env-var-name patterns
        if _PLACEHOLDER_WORDS.search(key) or _VALUE_IS_ENV_NAME.match(key):
            return False
        # Base64 character class — real keys only use A-Za-z0-9+/=
        if not re.match(r'^[A-Za-z0-9+/=]+$', key):
            return False
        # Entropy heuristic — placeholder keys are often runs of same char
        unique_chars = len(set(key))
        if unique_chars < 12:   # real base64 has ~50+ unique chars
            return False
        # AccountKey == AccountName (silly placeholder)
        m_acct = re.search(r'AccountName=([^;\s"\']+)', conn, re.IGNORECASE)
        if m_acct and m_acct.group(1) == key:
            return False

    # 3) AccountName must be lowercase-alphanumeric (Azure rule),
    #    3-24 chars, and not in placeholder set.
    m = re.search(r'AccountName=([^;\s"\']+)', conn, re.IGNORECASE)
    if m:
        name = m.group(1)
        # Azure rule: lowercase letters and numbers only, 3-24 chars
        if not re.match(r'^[a-z0-9]{3,24}$', name):
            return False
        # Known placeholder names (English + Portuguese + Russian)
        _PLACEHOLDER_NAMES = {
            "myaccount", "youraccount", "ouraccount", "storage", "store",
            "test", "demo", "example", "sample", "myaccountname",
            "seustorage", "sustorage", "tustorage",
            "imyastorage", "tvoyastorage",
            "mystoragecount", "mystorage", "demoaccount", "abc", "abcd",
            "abc123", "test123", "storage1", "storage123",
        }
        if name in _PLACEHOLDER_NAMES:
            return False
        # Trivial repetition: "aaaaa" / "12345"
        if len(set(name)) < 3:
            return False

    return True


def extract_azure(content: str) -> list[str]:
    found = []
    for m in _AZURE_CONN.finditer(content):
        val = m.group(0)
        if not _is_fake(val) and "AccountKey=" in val and _azure_is_real_conn(val):
            found.append(val[:300])
    for m in _AZURE_SAS.finditer(content):
        val = m.group(0)
        if not _is_fake(val):
            found.append(val[:200])
    for m in _AZURE_CLIENT_SECRET.finditer(content):
        val = m.group(1)
        if not _is_fake(val):
            found.append(f"client_secret:{val}")
    # EventHub / ServiceBus — both use SharedAccessKey
    for m in _AZURE_EVENTHUB.finditer(content):
        val = m.group(0)
        if not _is_fake(val):
            found.append(val[:300])
    # Azure SQL connection strings
    for m in _AZURE_SQL.finditer(content):
        val = m.group(0)
        if not _is_fake(val):
            found.append(val[:300])
    # Cosmos DB
    for m in _AZURE_COSMOS.finditer(content):
        val = m.group(0)
        if not _is_fake(val):
            found.append(val[:300])
    return list(dict.fromkeys(found))


# ══════════════════════════════════════════════════════════════════════════════
# INFRA DEPLOY TOKENS (PaaS / hosting / infrastructure-as-code)
# ══════════════════════════════════════════════════════════════════════════════

_INFRA_TOKENS = re.compile(
    r'(?:'
    # Railway
    r'RAILWAY_TOKEN|RAILWAY_API_TOKEN'
    r'|RAILWAY_SERVICE_ACCOUNT_TOKEN'
    # Heroku
    r'|HEROKU_API_KEY'
    # Vercel
    r'|VERCEL_TOKEN|VERCEL_ORG_ID'
    # Fly.io
    r'|FLY_API_TOKEN|FLY_ACCESS_TOKEN'
    # Netlify
    r'|NETLIFY_AUTH_TOKEN|NETLIFY_ACCESS_TOKEN'
    # Cloudflare
    r'|CLOUDFLARE_API_TOKEN|CF_API_TOKEN|CLOUDFLARE_API_KEY'
    # DigitalOcean
    r'|DIGITALOCEAN_ACCESS_TOKEN|DO_ACCESS_TOKEN|DIGITALOCEAN_TOKEN'
    # Linode / Akamai
    r'|LINODE_TOKEN|LINODE_CLI_TOKEN'
    # Hetzner
    r'|HETZNER_API_TOKEN|HCLOUD_TOKEN'
    # Vultr
    r'|VULTR_API_KEY'
    # OVH
    r'|OVH_APPLICATION_KEY|OVH_APPLICATION_SECRET|OVH_CONSUMER_KEY'
    # Terraform Cloud
    r'|TFC_TOKEN|TERRAFORM_CLOUD_TOKEN|TFE_TOKEN'
    # Doppler
    r'|DOPPLER_TOKEN|DOPPLER_SERVICE_TOKEN'
    # HashiCorp Vault
    r'|VAULT_TOKEN|VAULT_ROOT_TOKEN_ID'
    # Ansible
    r'|ANSIBLE_VAULT_PASSWORD|ANSIBLE_BECOME_PASSWORD'
    # Kubernetes / k8s
    r'|KUBECONFIG|K8S_TOKEN|KUBERNETES_TOKEN'
    # Generic deploy (GitHub/GH tokens excluded — trufflehog covers them natively
    # and including GITHUB_TOKEN here risks the scanner finding its own PAT)
    r'|DEPLOY_TOKEN|DEPLOYMENT_TOKEN|CI_DEPLOY_TOKEN|CD_TOKEN'
    r'|GITLAB_TOKEN|GL_TOKEN'
    r')\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]{10,200})["\']?',
    re.IGNORECASE,
)


# Reject token-values that are themselves env-var names — common placeholder
# pattern: `CF_API_TOKEN=CF_TUNNEL_TOKEN`, `CLOUDFLARE_API_TOKEN=ELEVENLABS_API_KEY`.
_VALUE_IS_ENV_NAME = re.compile(r'^[A-Z][A-Z0-9_]{4,}$')
# Reject obviously-placeholder words (Portuguese / English) that snuck past _is_fake.
_PLACEHOLDER_WORDS = re.compile(
    r'(?i)(?:^|[\s_\-])(?:'
    r'sua[_\-]?key|seu[_\-]?(?:storage|key)|tu[_\-]?clave'
    r'|optional|fallback|tunnel|migration|legacy|prod[_\-]?placeholder'
    r'|do[_\-]?not[_\-]?use|will[_\-]?be|todo|fixme|tbd'
    r')(?:[\s_\-]|$)',
)


def extract_infra(content: str) -> list[str]:
    found = []
    for m in _INFRA_TOKENS.finditer(content):
        env_name = m.group(0).split("=")[0].split(":")[0].strip()
        val = m.group(1).strip("\"' ")
        if len(val) < 10 or _is_fake(val):
            continue
        # Skip if value is itself an UPPERCASE env-var name (placeholder pattern)
        if _VALUE_IS_ENV_NAME.match(val):
            continue
        # Reject documented placeholder words
        if _PLACEHOLDER_WORDS.search(val):
            continue
        # Reject if value contains regex source code (literal char-class)
        if "[" in val and "]" in val and ("A-Z" in val or "0-9" in val or "a-z" in val):
            continue
        found.append(f"{env_name}={val}")
    return list(dict.fromkeys(found))


# ══════════════════════════════════════════════════════════════════════════════
# DISPATCHER
# ══════════════════════════════════════════════════════════════════════════════

INFRA_EXTRACTORS: dict[str, callable] = {
    "database": extract_database,
    "ssh":      extract_ssh,
    "aws":      extract_aws,
    "alibaba":  extract_alibaba,
    "azure":    extract_azure,
    "infra":    extract_infra,
    "replit":   None,  # placeholder, actual function defined below + reassigned
}


# ── Replit DB URL ─────────────────────────────────────────────────────────────
# REPLIT_DB_URL = https://kv.replit.com/v0/<long-token>. Anyone with this URL
# has full read+write to the Repl's K/V store — credentials, sessions,
# whatever the project caches there. Security through obscurity, no auth
# beyond URL itself. GitHub Secret Scanning Partner Program revokes these
# within 24h on github.com, but Kaggle/Gitee/Codeberg DON'T trigger
# auto-revoke → leaks persist for years there.
_REPLIT_DB_URL = re.compile(
    r'https://kv\.replit\.com/v0/[A-Za-z0-9_\-]{40,200}',
)
# REPLIT_API_TOKEN — Replit user API token. Format `repl_` prefix + ~32 chars.
_REPLIT_API_TOKEN = re.compile(
    r'(?:REPLIT_(?:API_)?TOKEN|REPL_API_TOKEN)\s*[=:]\s*["\']?'
    r'(repl_[A-Za-z0-9_\-]{20,128})',
)


def extract_replit(content: str) -> list[str]:
    """Extract Replit DB URLs (anon credentials to a Repl K/V store) and
    REPLIT_API_TOKEN values (user-level API auth)."""
    if "replit.com" not in content and "REPLIT_" not in content and "repl_" not in content:
        return []
    found = []
    for m in _REPLIT_DB_URL.finditer(content):
        url = m.group(0)
        if not _is_fake(url):
            found.append(url)
    for m in _REPLIT_API_TOKEN.finditer(content):
        tok = m.group(1)
        if not _is_fake(tok):
            found.append(tok)
    # Dedup preserving order
    return list(dict.fromkeys(found))


INFRA_EXTRACTORS["replit"] = extract_replit

INFRA_PROVIDERS = set(INFRA_EXTRACTORS.keys())


# ══════════════════════════════════════════════════════════════════════════════
# CI/CD RISK ASSESSMENT
# ══════════════════════════════════════════════════════════════════════════════

_CICD_PATHS = re.compile(
    r'(?:\.github/workflows|\.gitlab-ci|jenkinsfile|circleci/config'
    r'|\.travis\.yml|bitbucket-pipelines|azure-pipelines|\.drone\.yml'
    r'|\.circleci|codefresh\.yml|tekton|\.woodpecker)',
    re.IGNORECASE,
)
_DEPLOY_CMDS = re.compile(
    r'(?:kubectl\s+(?:apply|create|patch|replace)|helm\s+(?:upgrade|install|deploy)'
    r'|ansible-playbook|terraform\s+apply|docker\s+push|docker-compose\s+up'
    r'|fly\s+deploy|railway\s+up|heroku\s+container:push|eb\s+deploy'
    r'|aws\s+(?:s3\s+sync|ecs\s+update|eks\s+update|lambda\s+update)'
    r'|gcloud\s+(?:run\s+deploy|app\s+deploy)|az\s+(?:webapp|aks|acr)'
    r'|serverless\s+deploy|pulumi\s+up|cdktf\s+deploy)',
    re.IGNORECASE,
)
_PUSH_TRIGGER   = re.compile(r'on:\s*[\n\r\s]*(?:\[.*?push.*?\]|push\s*:)', re.DOTALL)
_PR_TRIGGER     = re.compile(r'\bpull_request\b(?!_target)')
_SECRETS_ACCESS = re.compile(r'\$\{\{\s*secrets\.[A-Z_]{3,}\s*\}\}')
_PRIV_SECRET    = re.compile(
    r'\$\{\{\s*secrets\.(.*?(?:KEY|TOKEN|PASSWORD|SECRET|URL|DSN|PRIVATE).*?)\s*\}\}',
    re.IGNORECASE,
)


def assess_risk(content: str, file_path: str,
                repo_stars: int, repo_created: str) -> tuple[str, list[str]]:
    """
    Score the "probability of CI/CD monitoring installation" for a found credential.

    Returns (level, reasons):
      level   — "high" / "medium" / "low"
      reasons — human-readable list of contributing factors (Russian)
    """
    score   = 0
    reasons = []
    is_cicd = bool(_CICD_PATHS.search(file_path))

    if is_cicd:
        if _PUSH_TRIGGER.search(content):
            score += 3
            reasons.append("push-триггер (любой commit запускает pipeline)")
        if _PR_TRIGGER.search(content) and "pull_request_target" not in content:
            score += 2
            reasons.append("pull_request-триггер (форки имеют доступ к secrets)")
        if _DEPLOY_CMDS.search(content):
            score += 2
            reasons.append("deploy-команда в pipeline")
        priv = _PRIV_SECRET.findall(content)
        if priv:
            score += 2
            reasons.append(f"привилегированные secrets: {', '.join(priv[:3])}")
        elif _SECRETS_ACCESS.search(content):
            score += 1
            reasons.append("workflow читает GitHub Secrets")

    # Dockerfile / docker-compose — writable image registry could be abused
    if "dockerfile" in file_path.lower() or "docker-compose" in file_path.lower():
        if re.search(r'(?:FROM|RUN|ENV|ARG)\s', content):
            score += 1
            reasons.append("Docker build file с credentials")

    # Ansible / Helm / Terraform — IaC with embedded secrets
    if re.search(r'(?:ansible|playbook|vars_files|vault_password)', file_path, re.I):
        score += 2
        reasons.append("Ansible файл (IaC credentials)")
    if re.search(r'(?:helm|values\.yaml|secrets\.yaml)', file_path, re.I):
        score += 1
        reasons.append("Helm values/secrets")
    if re.search(r'\.tf(?:vars)?$', file_path):
        score += 2
        reasons.append("Terraform файл (IaC secrets)")

    # Repo activity
    try:
        dt       = datetime.fromisoformat(repo_created.replace("Z", "+00:00"))
        age_days = (datetime.now(timezone.utc) - dt).days
        if age_days < 14:
            score += 3
            reasons.append(f"очень активное репо ({age_days}д)")
        elif age_days < 90:
            score += 2
            reasons.append(f"активное репо ({age_days}д)")
        elif age_days < 365:
            score += 1
            reasons.append(f"недавнее репо ({age_days}д)")
    except Exception:
        pass

    if repo_stars > 1000:
        score += 2
        reasons.append(f"популярное репо ({repo_stars}★)")
    elif repo_stars > 100:
        score += 1
        reasons.append(f"{repo_stars}★")

    level = "high" if score >= 6 else "medium" if score >= 3 else "low"
    return level, reasons


# ══════════════════════════════════════════════════════════════════════════════
# GITHUB CODE SEARCH QUERIES  (format: search_terms, provider, file_type_tag)
# ══════════════════════════════════════════════════════════════════════════════

INFRA_QUERIES: list[tuple[str, str, str]] = [

    # ── Replit DB URLs / API tokens ────────────────────────────────────────
    # Anyone with REPLIT_DB_URL has full read+write to that Repl's K/V store.
    # GitHub Secret Scanning Partner Program revokes these on github.com but
    # NOT on Kaggle/Gitee/Codeberg — leaks persist there. Also catches
    # REPLIT_API_TOKEN (repl_ prefix) for user-level Replit auth.
    ('"kv.replit.com/v0"',                                    "replit", "code"),
    ('"REPLIT_DB_URL" filename:.env',                         "replit", "env"),
    ('"REPLIT_DB_URL" filename:.env.local',                   "replit", "env"),
    ('"REPLIT_DB_URL" filename:.env.production',              "replit", "env"),
    ('"REPLIT_DB_URL" language:python',                       "replit", "code"),
    ('"REPLIT_DB_URL" language:javascript',                   "replit", "code"),
    ('"REPLIT_DB_URL" language:typescript',                   "replit", "code"),
    ('"REPLIT_DB_URL" extension:ipynb',                       "replit", "notebook"),
    ('"REPLIT_API_TOKEN" filename:.env',                      "replit", "env"),
    ('"repl_" "REPLIT_API_TOKEN"',                            "replit", "code"),
    ('"kv.replit.com" filename:.replit',                      "replit", "config"),
    ('"REPLIT_DB_URL" filename:replit.nix',                   "replit", "config"),

    # ── DATABASE_URL / connection strings ─────────────────────────────────
    ('"DATABASE_URL" filename:.env',                          "database", "env"),
    ('"DATABASE_URL" filename:.env.production',               "database", "env"),
    ('"DATABASE_URL" filename:.env.local',                    "database", "env"),
    ('"MONGODB_URI" filename:.env',                           "database", "env"),
    ('"REDIS_URL" filename:.env',                             "database", "env"),
    ('"POSTGRES" "password" filename:.env',                   "database", "env"),
    ('"DATABASE_URL" filename:docker-compose.yml',            "database", "docker"),
    ('"DATABASE_URL" filename:docker-compose.yaml',           "database", "docker"),
    ('"MONGODB_URI" filename:docker-compose.yml',             "database", "docker"),
    ('"DATABASE_URL" path:.github/workflows',                 "database", "cicd"),
    ('"DATABASE_URL" path:.gitlab-ci.yml',                    "database", "cicd"),
    ('"DATABASE_URL" filename:Jenkinsfile',                   "database", "cicd"),
    ('"DATABASE_URL" filename:values.yaml',                   "database", "helm"),
    ('"DATABASE_URL" filename:secrets.yaml',                  "database", "helm"),
    ('"DATABASE_URL" language:python',                        "database", "code"),
    ('"DATABASE_URL" language:go',                            "database", "code"),
    ('"DATABASE_URL" language:javascript',                    "database", "code"),
    ('"DATABASE_URL" language:java',                          "database", "code"),
    ('"DATABASE_URL" language:php',                           "database", "code"),
    ('"DATABASE_URL" language:ruby',                          "database", "code"),
    ('"SQLALCHEMY_DATABASE_URI" language:python',             "database", "code"),
    ('"DJANGO_DATABASE_URL" language:python',                 "database", "code"),
    ('"mongodb://" "password" language:javascript',           "database", "code"),
    ('"mongodb://" "password" language:python',               "database", "code"),
    ('"postgres://" language:python',                         "database", "code"),
    ('"postgres://" language:go',                             "database", "code"),
    ('"postgres://" language:javascript',                     "database", "code"),
    ('"redis://" "password" language:python',                 "database", "code"),
    ('"redis://" "password" filename:.env',                   "database", "env"),
    # Supabase / PlanetScale / Neon / Turso DSNs (cloud DBs)
    ('"supabase" "DATABASE_URL" filename:.env',               "database", "env"),
    ('"neon.tech" "DATABASE_URL"',                            "database", "env"),
    ('"planetscale" "DATABASE_URL"',                          "database", "env"),
    ('"turso" "DATABASE_URL"',                                "database", "env"),

    # ── SSH PRIVATE KEYS ──────────────────────────────────────────────────
    ('"BEGIN RSA PRIVATE KEY" filename:.env',                 "ssh", "env"),
    ('"BEGIN OPENSSH PRIVATE KEY" filename:.env',             "ssh", "env"),
    ('"BEGIN EC PRIVATE KEY" filename:.env',                  "ssh", "env"),
    ('"SSH_PRIVATE_KEY" "BEGIN" filename:.env',               "ssh", "env"),
    ('"BEGIN RSA PRIVATE KEY" path:.github/workflows',        "ssh", "cicd"),
    ('"BEGIN OPENSSH PRIVATE KEY" path:.github/workflows',    "ssh", "cicd"),
    ('"SSH_PRIVATE_KEY" path:.github/workflows',              "ssh", "cicd"),
    ('"BEGIN RSA PRIVATE KEY" path:.gitlab-ci.yml',           "ssh", "cicd"),
    ('"SSH_PRIVATE_KEY" filename:docker-compose.yml',         "ssh", "docker"),
    ('"BEGIN RSA PRIVATE KEY" language:python',               "ssh", "code"),
    ('"BEGIN OPENSSH PRIVATE KEY" language:python',           "ssh", "code"),
    ('"DEPLOY_KEY" "BEGIN" language:python',                  "ssh", "code"),
    ('"BEGIN RSA PRIVATE KEY" filename:id_rsa',               "ssh", "key"),
    ('"BEGIN OPENSSH PRIVATE KEY" filename:id_ed25519',       "ssh", "key"),

    # ── AWS ───────────────────────────────────────────────────────────────
    ('"AWS_ACCESS_KEY_ID" "AWS_SECRET_ACCESS_KEY" filename:.env',   "aws", "env"),
    ('"AKIA" "AWS_SECRET" filename:.env',                           "aws", "env"),
    ('"AWS_ACCESS_KEY_ID" filename:.env.production',                "aws", "env"),
    ('"AWS_ACCESS_KEY_ID" path:.github/workflows',                  "aws", "cicd"),
    ('"AWS_SECRET_ACCESS_KEY" path:.github/workflows',              "aws", "cicd"),
    ('"AWS_ACCESS_KEY_ID" path:.gitlab-ci.yml',                     "aws", "cicd"),
    ('"AWS_ACCESS_KEY_ID" filename:Jenkinsfile',                    "aws", "cicd"),
    ('"AWS_ACCESS_KEY_ID" filename:docker-compose.yml',             "aws", "docker"),
    ('"AWS_ACCESS_KEY_ID" filename:.travis.yml',                    "aws", "cicd"),
    ('"AWS_ACCESS_KEY_ID" filename:terraform.tfvars',               "aws", "terraform"),
    ('"AWS_ACCESS_KEY_ID" filename:values.yaml',                    "aws", "helm"),
    ('"AKIA" "SECRET" language:python',                             "aws", "code"),
    ('"AKIA" "SECRET" language:javascript',                         "aws", "code"),
    ('"AKIA" "SECRET" language:go',                                 "aws", "code"),
    ('"AKIA" "SECRET" language:java',                               "aws", "code"),
    ('"AKIA" "SECRET" language:php',                                "aws", "code"),
    ('"AKIA" "SECRET" language:ruby',                               "aws", "code"),
    ('"aws_access_key_id" language:python',                         "aws", "code"),
    ('"aws_access_key_id" language:go',                             "aws", "code"),
    # Terraform AWS provider
    ('"aws_access_key" filename:main.tf',                           "aws", "terraform"),
    ('"aws_access_key" filename:providers.tf',                      "aws", "terraform"),
    ('"aws_access_key" filename:variables.tf',                      "aws", "terraform"),

    # ── ALIBABA CLOUD / ALIYUN ────────────────────────────────────────────
    ('"LTAI" "ALIBABA_CLOUD" filename:.env',                  "alibaba", "env"),
    ('"ALICLOUD_ACCESS_KEY" filename:.env',                   "alibaba", "env"),
    ('"ALIBABA_CLOUD_ACCESS_KEY_ID" filename:.env',           "alibaba", "env"),
    ('"ALIBABA_CLOUD_ACCESS_KEY_ID" path:.github/workflows',  "alibaba", "cicd"),
    ('"ALICLOUD_ACCESS_KEY_ID" path:.github/workflows',       "alibaba", "cicd"),
    ('"LTAI" "access_key" language:python',                   "alibaba", "code"),
    ('"LTAI" "access_key" language:go',                       "alibaba", "code"),
    ('"LTAI" "access_key" language:java',                     "alibaba", "code"),
    ('"aliyun" "access_key_id" language:python',              "alibaba", "code"),
    ('"aliyuncs.com" "AccessKeyId" language:python',          "alibaba", "code"),
    ('"aliyuncs.com" "AccessKeyId" language:java',            "alibaba", "code"),
    ('"ALIBABA_CLOUD_ACCESS_KEY_ID" filename:docker-compose.yml', "alibaba", "docker"),

    # ── AZURE ─────────────────────────────────────────────────────────────
    ('"DefaultEndpointsProtocol=https;AccountName=" filename:.env', "azure", "env"),
    ('"AZURE_STORAGE_CONNECTION_STRING" filename:.env',             "azure", "env"),
    ('"AZURE_CLIENT_SECRET" filename:.env',                         "azure", "env"),
    ('"AZURE_CLIENT_SECRET" path:.github/workflows',                "azure", "cicd"),
    ('"AzureWebJobsStorage" filename:.env',                         "azure", "env"),
    ('"azure" "connection_string" language:python',                 "azure", "code"),
    ('"azure" "AccountKey" language:csharp',                        "azure", "code"),
    ('"ARM_CLIENT_SECRET" filename:terraform.tfvars',               "azure", "terraform"),

    # ── INFRA DEPLOY TOKENS ───────────────────────────────────────────────
    # Railway
    ('"RAILWAY_TOKEN" filename:.env',                         "infra", "env"),
    ('"RAILWAY_TOKEN" path:.github/workflows',                "infra", "cicd"),
    # Heroku
    ('"HEROKU_API_KEY" filename:.env',                        "infra", "env"),
    ('"HEROKU_API_KEY" path:.github/workflows',               "infra", "cicd"),
    ('"HEROKU_API_KEY" path:.gitlab-ci.yml',                  "infra", "cicd"),
    ('"HEROKU_API_KEY" filename:.travis.yml',                 "infra", "cicd"),
    # Vercel
    ('"VERCEL_TOKEN" filename:.env',                          "infra", "env"),
    ('"VERCEL_TOKEN" path:.github/workflows',                 "infra", "cicd"),
    # Fly.io
    ('"FLY_API_TOKEN" filename:.env',                         "infra", "env"),
    ('"FLY_API_TOKEN" path:.github/workflows',                "infra", "cicd"),
    # Netlify
    ('"NETLIFY_AUTH_TOKEN" filename:.env',                    "infra", "env"),
    ('"NETLIFY_AUTH_TOKEN" path:.github/workflows',           "infra", "cicd"),
    # Cloudflare
    ('"CLOUDFLARE_API_TOKEN" filename:.env',                  "infra", "env"),
    ('"CF_API_TOKEN" path:.github/workflows',                 "infra", "cicd"),
    # DigitalOcean
    ('"DIGITALOCEAN_ACCESS_TOKEN" filename:.env',             "infra", "env"),
    ('"DO_ACCESS_TOKEN" path:.github/workflows',              "infra", "cicd"),
    # Hetzner
    ('"HCLOUD_TOKEN" filename:.env',                          "infra", "env"),
    ('"HCLOUD_TOKEN" path:.github/workflows',                 "infra", "cicd"),
    # Terraform Cloud
    ('"TFE_TOKEN" filename:.env',                             "infra", "env"),
    ('"TFC_TOKEN" path:.github/workflows',                    "infra", "cicd"),
    # Vault
    ('"VAULT_TOKEN" filename:.env',                           "infra", "env"),
    ('"VAULT_TOKEN" path:.github/workflows',                  "infra", "cicd"),
    # k8s
    ('"KUBECONFIG" filename:docker-compose.yml',              "infra", "docker"),
    ('"K8S_TOKEN" path:.github/workflows',                    "infra", "cicd"),
    # Ansible Vault
    ('"ANSIBLE_VAULT_PASSWORD" filename:.env',                "infra", "env"),
    ('"vault_password_file" filename:ansible.cfg',            "infra", "ansible"),
    # Generic CD pipeline tokens
    ('"DEPLOY_TOKEN" path:.github/workflows',                 "infra", "cicd"),
    ('"CD_TOKEN" path:.gitlab-ci.yml',                        "infra", "cicd"),
]
