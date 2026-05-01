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
_db_default = "/data/scanner.db" if Path("/data").exists() else "./scanner.db"
DB_PATH = os.environ.get("DB_PATH", _db_default)

# ── Scan tuning ────────────────────────────────────────────────────────────
SCAN_INTERVAL     = int(os.environ.get("SCAN_INTERVAL",     "1800"))   # seconds between cycles
YOUNG_REPO_DAYS   = int(os.environ.get("YOUNG_REPO_DAYS",   "90"))    # repos newer than N days pass filter
BIG_SERVICE_STARS = int(os.environ.get("BIG_SERVICE_STARS", "500"))    # OR stars ≥ this
REPO_RESCAN_DAYS  = int(os.environ.get("REPO_RESCAN_DAYS",  "7"))     # re-check repo after N days
CONCURRENT_ITEMS  = int(os.environ.get("CONCURRENT_ITEMS",  "50"))    # parallel file fetches per worker
MAX_PAGES         = int(os.environ.get("MAX_PAGES",          "5"))     # pages per query (100 results each)
HOURLY_ALERT      = os.environ.get("HOURLY_ALERT", "1") == "1"

# ── DB maintenance ─────────────────────────────────────────────────────────
# Low-risk infra findings older than this many days are pruned automatically.
INFRA_LOW_RISK_MAX_DAYS = int(os.environ.get("INFRA_LOW_RISK_MAX_DAYS", "30"))

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
