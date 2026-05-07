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
# Required on master (sends digests, runs key vault bot). Optional on mirror
# satellite services (set MIRROR_MODE=1) — mirror doesn't ship to Telegram,
# it posts finds back to master via mirror_relay. Use empty fallback so
# satellite deployments don't need to fake these envs.
_mirror_mode_early = os.environ.get("MIRROR_MODE", "0") == "1"
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "") if _mirror_mode_early else os.environ["TELEGRAM_BOT_TOKEN"]
TELEGRAM_CHAT_ID   = os.environ.get("TELEGRAM_CHAT_ID", "")   if _mirror_mode_early else os.environ["TELEGRAM_CHAT_ID"]

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

# Cap on how many queries one cycle is allowed to dispatch. With dynamic
# pool growing to ~6300 + 1562 static, running everything every cycle on
# 9 PATs × MAX_PAGES results in 4-hour cycles + heavy secondary 429.
# yield-priority selection (scanner.select_queries_for_cycle) honors this
# cap, always including the static baseline + proven yielders + newcomers,
# and sampling the long-tail. Set to 0 to disable cap (run everything).
SCAN_MAX_QUERIES_PER_CYCLE = int(os.environ.get("SCAN_MAX_QUERIES_PER_CYCLE", "3000"))

# Sample fraction of low-yield long-tail dynamic queries each cycle (after
# the mandatory portion). 0.25 = pick 1 in 4. Across ~4 cycles each long-tail
# query gets a turn; if it stays at 0 yield it falls into auto_blacklist
# territory (5+ uses, 0 keys → 30d cooldown).
SCAN_LONG_TAIL_SAMPLE = float(os.environ.get("SCAN_LONG_TAIL_SAMPLE", "0.25"))

# Between-page sleep inside _run_chunk. 2s was tuned for 1562 static queries;
# now we have 4x the load. Bump default to 3s — drops secondary 429 burst
# rate without meaningfully extending elapsed cycle time.
SCAN_PAGE_SLEEP_SEC = float(os.environ.get("SCAN_PAGE_SLEEP_SEC", "3"))

# ── Mirror mode ────────────────────────────────────────────────────────────
# Mirror mode = lightweight satellite Railway service that scans GitHub from
# a different egress IP using its own slice of GITHUB_TOKENS, then ships
# every find to the master via HTTP. The master keeps the single source of
# truth (DB, Telegram bot, DeepSeek pipelines, validators).
#
# When MIRROR_MODE=1:
#   • scan_cycle runs normally, using its own GITHUB_TOKENS env value
#   • all OTHER background tasks are disabled (telegram bot, infra_jackpot,
#     deepseek_themer/vocab/archetype, kaggle/postman/npm/pypi/hf/codeberg/
#     gitee/commoncrawl/trufflehog/issues/gist/events/author scanners)
#   • db.save_key still writes locally for dedup, then pushes the find to
#     master via mirror_relay
#   • master's existing /admin/validate_keys endpoint receives batches and
#     does its own validation + dedup (key_hash UNIQUE)
MIRROR_MODE       = os.environ.get("MIRROR_MODE", "0") == "1"
MASTER_API_URL    = os.environ.get("MASTER_API_URL", "").rstrip("/")
# Defaults to ADMIN_TOKEN — same secret on both services, no extra env needed
MASTER_API_TOKEN  = os.environ.get("MASTER_API_TOKEN", "") or os.environ.get("ADMIN_TOKEN", "")
MIRROR_FLUSH_SEC  = float(os.environ.get("MIRROR_FLUSH_SEC", "30"))   # how often to POST batched finds
MIRROR_BATCH_MAX  = int(os.environ.get("MIRROR_BATCH_MAX", "200"))    # max items per batch POST
# Pull master's dynamic_queries (DeepSeek + combinatorial) every N seconds so
# mirror's scan_cycle benefits from the same long-tail rotation. Default 30min —
# themer runs every 30-45min on master, so 30min sync keeps mirrors within one
# cycle of the latest queries. Set 0 to disable sync (mirrors use static only).
MIRROR_QUERY_SYNC_SEC = int(os.environ.get("MIRROR_QUERY_SYNC_SEC", "1800"))

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

KAGGLE_SCAN_INTERVAL = int(os.environ.get("KAGGLE_SCAN_INTERVAL", "1800"))  # 30min — was 10min but
                                                                             # Kaggle started rate-limiting
                                                                             # accounts (404 instead of 200)
                                                                             # at high scan frequency. 30min
                                                                             # gives accounts time to "cool down"
                                                                             # between cycles. Adjust via env if
                                                                             # we add more accounts (more headroom).

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

# Bitbucket scanner removed: Atlassian CHANGE-2770 deleted cross-workspace
# REST API endpoints (/2.0/repositories, /2.0/user) on 2026-04-14. Without
# random-fresh-public-repo discovery the scanner couldn't find leaks.

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

# ── Common Crawl scanner ──────────────────────────────────────────────────
# No auth needed — Common Crawl is fully public (s3://commoncrawl/ + https
# mirror). Petabyte-scale web crawl indexed monthly. NOT in any partner
# program — keys we find here aren't auto-revoked by AI providers.
# Bandwidth: ~5-20GB inbound per cycle (free on Railway).
CC_ENABLED       = os.environ.get("CC_ENABLED", "1") == "1"
CC_SCAN_INTERVAL = int(os.environ.get("CC_SCAN_INTERVAL", "86400"))  # 24h default
CC_PER_PATTERN_CAP = int(os.environ.get("CC_PER_PATTERN_CAP", "5000"))
