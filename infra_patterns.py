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

    return list(dict.fromkeys(found))


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

_ALIYUN_KEY_ID = re.compile(r'\b(LTAI[A-Za-z0-9]{16,24})\b')
_ALIYUN_SECRET  = re.compile(
    r'(?:ALIBABA_CLOUD_ACCESS_KEY_SECRET|ALICLOUD_ACCESS_KEY_SECRET'
    r'|ALIYUN_ACCESS_KEY_SECRET|access_key_secret)\s*[=:]\s*["\']?([A-Za-z0-9]{30,})["\']?',
    re.IGNORECASE,
)
_ALIYUN_REGION = re.compile(
    r'(?:ALIBABA_CLOUD_REGION|ALICLOUD_REGION|cn-[a-z]+-\d|ap-[a-z]+-\d)',
    re.IGNORECASE,
)


def extract_alibaba(content: str) -> list[str]:
    found   = []
    secrets = [(m.start(), m.group(1)) for m in _ALIYUN_SECRET.finditer(content)]
    regions = [(m.start(), m.group(0)) for m in _ALIYUN_REGION.finditer(content)]

    def _nearest(pos: int, items: list[tuple]) -> str | None:
        return min(items, key=lambda t: abs(t[0] - pos))[1] if items else None

    for kid_m in _ALIYUN_KEY_ID.finditer(content):
        kid = kid_m.group(1)
        if _is_fake(kid):
            continue
        secret = _nearest(kid_m.start(), secrets) if secrets else None
        region = _nearest(kid_m.start(), regions) if regions else "cn-unknown"
        if secret:
            found.append(f"{kid}:{secret}@{region}")
        else:
            found.append(f"{kid}:secret_unknown@{region}")
    return list(dict.fromkeys(found))


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


def extract_azure(content: str) -> list[str]:
    found = []
    for m in _AZURE_CONN.finditer(content):
        val = m.group(0)
        if not _is_fake(val) and "AccountKey=" in val:
            found.append(val[:120])
    for m in _AZURE_SAS.finditer(content):
        val = m.group(0)
        if not _is_fake(val):
            found.append(val[:120])
    for m in _AZURE_CLIENT_SECRET.finditer(content):
        val = m.group(1)
        if not _is_fake(val):
            found.append(f"client_secret:{val}")
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


def extract_infra(content: str) -> list[str]:
    found = []
    for m in _INFRA_TOKENS.finditer(content):
        env_name = m.group(0).split("=")[0].split(":")[0].strip()
        val = m.group(1).strip("\"' ")
        if len(val) < 10 or _is_fake(val):
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
}

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
