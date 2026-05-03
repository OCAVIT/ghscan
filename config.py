import os
from pathlib import Path

# ── GitHub token pool ──────────────────────────────────────────────────────
# GITHUB_TOKENS=tok1,tok2,...,tokN  → N parallel workers, 30N req/min total
# Falls back to single GITHUB_TOKEN
_multi  = os.environ.get("GITHUB_TOKENS", "")
_single = os.environ.get("GITHUB_TOKEN", "")

if _multi:
    GITHUB_TOKENS = [t.strip() for t in _multi.split(",") if t.strip()]
elif _single:
    GITHUB_TOKENS = [_single]
else:
    raise RuntimeError("Set GITHUB_TOKEN or GITHUB_TOKENS env var")

GITHUB_TOKEN = GITHUB_TOKENS[0]  # compat alias

# ── Telegram ───────────────────────────────────────────────────────────────
TELEGRAM_BOT_TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
TELEGRAM_CHAT_ID   = os.environ["TELEGRAM_CHAT_ID"]

# ── Storage ────────────────────────────────────────────────────────────────
# Check both existence AND writability — Railway creates /data mountpoint even
# when no volume is attached, so .exists() alone gives a false positive.
_data_dir = Path("/data")
if _data_dir.exists() and os.access(_data_dir, os.W_OK):
    _db_default = "/data/scanner.db"
else:
    _db_default = "./scanner.db"
DB_PATH = os.environ.get("DB_PATH", _db_default)

# ── Scan tuning ────────────────────────────────────────────────────────────
SCAN_INTERVAL     = int(os.environ.get("SCAN_INTERVAL",     "1800"))   # seconds between cycles
YOUNG_REPO_DAYS   = int(os.environ.get("YOUNG_REPO_DAYS",   "365"))   # repos newer than N days pass filter
BIG_SERVICE_STARS = int(os.environ.get("BIG_SERVICE_STARS", "100"))    # OR stars ≥ this
REPO_RESCAN_DAYS  = int(os.environ.get("REPO_RESCAN_DAYS",  "7"))     # re-check repo after N days
CONCURRENT_ITEMS  = int(os.environ.get("CONCURRENT_ITEMS",  "20"))    # parallel file fetches (was 50 — secondary 403 limit)
MAX_PAGES         = int(os.environ.get("MAX_PAGES",          "5"))     # pages per query (100 results each)
HOURLY_ALERT      = os.environ.get("HOURLY_ALERT", "1") == "1"

# ── DB maintenance ─────────────────────────────────────────────────────────
# Low-risk infra findings older than this many days are pruned automatically.
INFRA_LOW_RISK_MAX_DAYS = int(os.environ.get("INFRA_LOW_RISK_MAX_DAYS", "30"))

# ── Validation tuning ──────────────────────────────────────────────────────
# Model used by validate_openai for the 1-token quota probe. Default
# gpt-4o-mini = universal availability + microcent cost. Override if you
# want a cheaper newer model (gpt-4.1-nano) or a different one.
OPENAI_VALIDATION_MODEL = os.environ.get("OPENAI_VALIDATION_MODEL", "gpt-4o-mini")

# ── Gitee token pool ──────────────────────────────────────────────────────
_gitee_multi  = os.environ.get("GITEE_TOKENS", "")
_gitee_single = os.environ.get("GITEE_TOKEN", "")
if _gitee_multi:
    GITEE_TOKENS = [t.strip() for t in _gitee_multi.split(",") if t.strip()]
elif _gitee_single:
    GITEE_TOKENS = [_gitee_single]
else:
    GITEE_TOKENS = []

GITEE_SCAN_INTERVAL = int(os.environ.get("GITEE_SCAN_INTERVAL", "3600"))  # 1h default

# ── Evomi residential proxy (for Gitee — Chinese IPs only) ────────────────
# Two ways to configure:
#   Option A — full URL already in Railway (preferred):
#     EVOMI_PROXY=http://user:pass_country-US@core-residential.evomi.com:1000
#     The country suffix is replaced with EVOMI_COUNTRY (default "cn").
#   Option B — split credentials:
#     EVOMI_USER + EVOMI_PASS  →  built as http://user_country-cn:pass@rp.evomi.com:1000
# Only gitee.com traffic is proxied; validator calls go direct.
import re as _re

EVOMI_PROXY   = os.environ.get("EVOMI_PROXY",   "")
EVOMI_USER    = os.environ.get("EVOMI_USER",    "")
EVOMI_PASS    = os.environ.get("EVOMI_PASS",    "")
EVOMI_COUNTRY = os.environ.get("EVOMI_COUNTRY", "cn")

def evomi_proxy_url() -> str | None:
    """Return Evomi HTTP proxy URL (CN) or None if not configured."""
    if EVOMI_PROXY:
        # Replace any existing _country-XX suffix with the target country
        return _re.sub(r'_country-[A-Za-z]{2}', f"_country-{EVOMI_COUNTRY}", EVOMI_PROXY)
    if EVOMI_USER and EVOMI_PASS:
        return f"http://{EVOMI_USER}_country-{EVOMI_COUNTRY}:{EVOMI_PASS}@rp.evomi.com:1000"
    return None

# ── Trufflehog secondary scanner ──────────────────────────────────────────
# TRUFFLEHOG_ORGS=org1,org2,org3  — GitHub orgs to sweep with trufflehog
# TRUFFLEHOG_TOKEN — dedicated PAT for trufflehog (keeps it off the main quota pool).
#   Falls back to GITHUB_TOKENS[0] if not set, but quota will be shared.
# TRUFFLEHOG_PATH — override if binary not in /usr/local/bin
_th_default = "/usr/local/bin/trufflehog"
TRUFFLEHOG_PATH        = Path(os.environ.get("TRUFFLEHOG_PATH", _th_default))
TRUFFLEHOG_ORGS        = [o.strip() for o in os.environ.get("TRUFFLEHOG_ORGS", "").split(",") if o.strip()]
TRUFFLEHOG_USERS       = [u.strip() for u in os.environ.get("TRUFFLEHOG_USERS", "").split(",") if u.strip()]
TRUFFLEHOG_INTERVAL    = int(os.environ.get("TRUFFLEHOG_INTERVAL", "7200"))
TRUFFLEHOG_CONCURRENCY = int(os.environ.get("TRUFFLEHOG_CONCURRENCY", "50"))
TRUFFLEHOG_TOKEN       = os.environ.get("TRUFFLEHOG_TOKEN", "")  # dedicated PAT, optional

# ── Kaggle token pool ──────────────────────────────────────────────────────
# KAGGLE_TOKENS=KGAT_key1,KGAT_key2  — KGAT_ bearer tokens (new Kaggle format).
# Username is auto-introspected by the kaggle Python package; no need to specify it.
# Falls back to single KAGGLE_TOKEN.
_kaggle_multi  = os.environ.get("KAGGLE_TOKENS", "")
_kaggle_single = os.environ.get("KAGGLE_TOKEN", "")
if _kaggle_multi:
    KAGGLE_TOKENS = [t.strip() for t in _kaggle_multi.split(",") if t.strip()]
elif _kaggle_single:
    KAGGLE_TOKENS = [_kaggle_single]
else:
    KAGGLE_TOKENS = []

KAGGLE_SCAN_INTERVAL = int(os.environ.get("KAGGLE_SCAN_INTERVAL", "3600"))  # 1h default

# ── HuggingFace token ──────────────────────────────────────────────────────
# HF_TOKEN — read-scope token for HuggingFace Spaces API.
HF_TOKEN = os.environ.get("HF_TOKEN", "")
HF_SCAN_INTERVAL = int(os.environ.get("HF_SCAN_INTERVAL", "1800"))  # 30min default

# ── Codeberg token pool ────────────────────────────────────────────────────
# CODEBERG_TOKENS=token1,token2  — Forgejo/Codeberg API tokens (repository read scope).
# Rate limit: 300 req/min per token (much more generous than GitHub).
_codeberg_multi = os.environ.get("CODEBERG_TOKENS", "")
if _codeberg_multi:
    CODEBERG_TOKENS = [t.strip() for t in _codeberg_multi.split(",") if t.strip()]
else:
    CODEBERG_TOKENS = []

CODEBERG_SCAN_INTERVAL = int(os.environ.get("CODEBERG_SCAN_INTERVAL", "3600"))  # 1h default

# ── Bitbucket Cloud token pool ────────────────────────────────────────────
# BITBUCKET_TOKENS=email1:apitoken1,email2:apitoken2
# Atlassian API tokens (NOT legacy app passwords) — auth via Basic base64(email:token).
# Required scopes: read:repository:bitbucket, read:account.
# Rate limit: 1000 req/h per account.
_bb_multi = os.environ.get("BITBUCKET_TOKENS", "")
if _bb_multi:
    BITBUCKET_TOKENS = [t.strip() for t in _bb_multi.split(",") if t.strip() and ":" in t]
else:
    BITBUCKET_TOKENS = []

BITBUCKET_SCAN_INTERVAL = int(os.environ.get("BITBUCKET_SCAN_INTERVAL", "10800"))  # 3h default

# ── Postman API key pool ──────────────────────────────────────────────────
# POSTMAN_TOKENS=PMAK-xxx,PMAK-yyy — Postman API keys, auth via X-Api-Key header.
# Rate limit: free tier ~60 req/min per key.
_postman_multi = os.environ.get("POSTMAN_TOKENS", "")
if _postman_multi:
    POSTMAN_TOKENS = [t.strip() for t in _postman_multi.split(",") if t.strip()]
else:
    POSTMAN_TOKENS = []

POSTMAN_SCAN_INTERVAL = int(os.environ.get("POSTMAN_SCAN_INTERVAL", "10800"))  # 3h default

# ── npm registry scanner ──────────────────────────────────────────────────
# No auth needed — public registry. Scans `.claude/settings.local.json`,
# `.env`, and other config files via unpkg.com CDN.
# Set NPM_ENABLED=0 to disable.
NPM_ENABLED = os.environ.get("NPM_ENABLED", "1") == "1"
NPM_SCAN_INTERVAL = int(os.environ.get("NPM_SCAN_INTERVAL", "10800"))  # 3h default

# ── PyPI scanner ──────────────────────────────────────────────────────────
# No auth needed — public registry. Scans newest packages + AI-related libs
# via sdist tarball download + extraction.
PYPI_ENABLED = os.environ.get("PYPI_ENABLED", "1") == "1"
PYPI_SCAN_INTERVAL = int(os.environ.get("PYPI_SCAN_INTERVAL", "10800"))  # 3h default
