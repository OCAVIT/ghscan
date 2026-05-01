import os
from pathlib import Path

GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]
TELEGRAM_BOT_TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
TELEGRAM_CHAT_ID = os.environ["TELEGRAM_CHAT_ID"]

# SQLite persists in Railway Volume mounted at /data
_db_default = "/data/scanner.db" if Path("/data").exists() else "./scanner.db"
DB_PATH = os.environ.get("DB_PATH", _db_default)

SCAN_INTERVAL = int(os.environ.get("SCAN_INTERVAL", "1800"))   # seconds between full cycles
YOUNG_REPO_DAYS = int(os.environ.get("YOUNG_REPO_DAYS", "60")) # repos newer than N days = "young"
BIG_SERVICE_STARS = int(os.environ.get("BIG_SERVICE_STARS", "1000"))
REPO_RESCAN_DAYS = int(os.environ.get("REPO_RESCAN_DAYS", "7"))  # re-check known repo after N days
