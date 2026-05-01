import sqlite3
import hashlib
from datetime import datetime, timezone, timedelta
from config import DB_PATH, REPO_RESCAN_DAYS


def _conn():
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with _conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS scanned_files (
            sha TEXT PRIMARY KEY,
            scanned_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS scanned_repos (
            full_name TEXT PRIMARY KEY,
            first_seen TEXT NOT NULL,
            last_scanned TEXT NOT NULL,
            stars INTEGER DEFAULT 0,
            created_at TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS found_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_hash TEXT UNIQUE NOT NULL,
            provider TEXT NOT NULL,
            key_preview TEXT NOT NULL,
            key_full TEXT NOT NULL,
            repo TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_url TEXT NOT NULL,
            repo_stars INTEGER DEFAULT 0,
            repo_created TEXT DEFAULT '',
            file_type TEXT DEFAULT '',
            is_valid INTEGER DEFAULT 0,
            discovered_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_found_valid ON found_keys(is_valid, discovered_at DESC);
        """)


def _now():
    return datetime.now(timezone.utc).isoformat()


# ── Files ──────────────────────────────────────────────────────────────────

def is_file_scanned(sha: str) -> bool:
    with _conn() as c:
        return c.execute("SELECT 1 FROM scanned_files WHERE sha=?", (sha,)).fetchone() is not None


def mark_file_scanned(sha: str):
    with _conn() as c:
        c.execute("INSERT OR IGNORE INTO scanned_files(sha, scanned_at) VALUES(?,?)", (sha, _now()))


# ── Repos ──────────────────────────────────────────────────────────────────

def should_scan_repo(full_name: str) -> bool:
    """True if repo has never been scanned or last scan was > REPO_RESCAN_DAYS ago."""
    with _conn() as c:
        row = c.execute("SELECT last_scanned FROM scanned_repos WHERE full_name=?", (full_name,)).fetchone()
    if row is None:
        return True
    last = datetime.fromisoformat(row["last_scanned"])
    return (datetime.now(timezone.utc) - last) > timedelta(days=REPO_RESCAN_DAYS)


def mark_repo_scanned(full_name: str, stars: int = 0, created_at: str = ""):
    now = _now()
    with _conn() as c:
        c.execute("""
            INSERT INTO scanned_repos(full_name, first_seen, last_scanned, stars, created_at)
            VALUES(?, ?, ?, ?, ?)
            ON CONFLICT(full_name) DO UPDATE SET last_scanned=excluded.last_scanned,
                stars=excluded.stars, created_at=excluded.created_at
        """, (full_name, now, now, stars, created_at))


# ── Keys ───────────────────────────────────────────────────────────────────

def key_exists(key: str) -> bool:
    h = hashlib.sha256(key.encode()).hexdigest()
    with _conn() as c:
        return c.execute("SELECT 1 FROM found_keys WHERE key_hash=?", (h,)).fetchone() is not None


def save_key(provider: str, key: str, repo: str, file_path: str,
             file_url: str, repo_stars: int, repo_created: str,
             file_type: str, is_valid: bool) -> bool:
    h = hashlib.sha256(key.encode()).hexdigest()
    # Store only a safe preview — full key goes to Telegram
    preview = key[:10] + "..." + key[-5:] if len(key) > 15 else key[:6] + "..."
    try:
        with _conn() as c:
            c.execute("""
                INSERT INTO found_keys(key_hash, provider, key_preview, key_full, repo,
                    file_path, file_url, repo_stars, repo_created, file_type, is_valid, discovered_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
            """, (h, provider, preview, key, repo, file_path, file_url,
                  repo_stars, repo_created, file_type, int(is_valid), _now()))
        return True
    except sqlite3.IntegrityError:
        return False


# ── Stats / Results ────────────────────────────────────────────────────────

def get_stats() -> dict:
    with _conn() as c:
        return {
            "repos_scanned": c.execute("SELECT COUNT(*) FROM scanned_repos").fetchone()[0],
            "files_scanned": c.execute("SELECT COUNT(*) FROM scanned_files").fetchone()[0],
            "keys_found":    c.execute("SELECT COUNT(*) FROM found_keys").fetchone()[0],
            "keys_valid":    c.execute("SELECT COUNT(*) FROM found_keys WHERE is_valid=1").fetchone()[0],
        }


def get_results(valid_only: bool = False, limit: int = 200) -> list[dict]:
    q = "SELECT * FROM found_keys"
    if valid_only:
        q += " WHERE is_valid=1"
    q += f" ORDER BY discovered_at DESC LIMIT {limit}"
    with _conn() as c:
        return [dict(r) for r in c.execute(q).fetchall()]
