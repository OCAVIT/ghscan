import sqlite3
import hashlib
from datetime import datetime, timezone, timedelta
from config import DB_PATH, REPO_RESCAN_DAYS


def _conn():
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    # WAL mode: multiple concurrent readers + serialized writers — critical for
    # N parallel workers all writing to same DB
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA synchronous=NORMAL")   # safe + fast with WAL
    c.execute("PRAGMA cache_size=-32000")    # 32MB page cache
    c.execute("PRAGMA temp_store=MEMORY")
    return c


def init_db():
    with _conn() as c:
        c.executescript("""
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=NORMAL;

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
        CREATE INDEX IF NOT EXISTS idx_found_valid    ON found_keys(is_valid, discovered_at DESC);
        CREATE INDEX IF NOT EXISTS idx_found_provider ON found_keys(provider, discovered_at DESC);
        CREATE INDEX IF NOT EXISTS idx_found_at       ON found_keys(discovered_at DESC);

        -- Infrastructure credentials: DB connection strings, SSH keys, cloud keys, deploy tokens.
        -- Separate table from found_keys (AI provider keys) so we can query/display them
        -- independently and apply different logic (risk assessment, destination logging).
        CREATE TABLE IF NOT EXISTS infra_findings (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            cred_hash     TEXT UNIQUE NOT NULL,
            cred_type     TEXT NOT NULL,        -- database/ssh/aws/alibaba/azure/infra
            cred_preview  TEXT NOT NULL,        -- first 20 + last 8 chars
            cred_full     TEXT NOT NULL,        -- full credential (connection string / key)
            repo          TEXT NOT NULL,
            file_path     TEXT NOT NULL,
            file_url      TEXT NOT NULL,
            repo_stars    INTEGER DEFAULT 0,
            repo_created  TEXT DEFAULT '',
            file_type     TEXT DEFAULT '',      -- env/cicd/docker/helm/terraform/ansible/code
            destination   TEXT DEFAULT '',      -- extracted host from DSN (where this connects)
            risk_level    TEXT DEFAULT 'low',   -- high / medium / low
            risk_reasons  TEXT DEFAULT '',      -- JSON array of contributing factors
            discovered_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_infra_type     ON infra_findings(cred_type, discovered_at DESC);
        CREATE INDEX IF NOT EXISTS idx_infra_risk     ON infra_findings(risk_level, discovered_at DESC);
        CREATE INDEX IF NOT EXISTS idx_infra_dest     ON infra_findings(destination);
        CREATE INDEX IF NOT EXISTS idx_infra_at       ON infra_findings(discovered_at DESC);
        """)


def _now():
    return datetime.now(timezone.utc).isoformat()


# ── Files ──────────────────────────────────────────────────────────────────

def try_claim_file(sha: str) -> bool:
    """
    Atomically claim a file SHA for processing.
    Returns True  → this caller is the first to see it (go ahead and process).
    Returns False → already claimed by another worker (skip, no race).

    Replaces the old is_file_scanned() + mark_file_scanned() two-step which
    had a TOCTOU race: two parallel workers could both read False, both proceed
    to fetch/validate the same file, wasting an HTTP round-trip.
    SQLite INSERT OR IGNORE is atomic — rowcount=1 means "I inserted it first".
    """
    with _conn() as c:
        cur = c.execute(
            "INSERT OR IGNORE INTO scanned_files(sha, scanned_at) VALUES(?,?)",
            (sha, _now()),
        )
        return cur.rowcount == 1  # 1 = new insert (claim granted), 0 = already existed


# kept for backward compat with any external callers
def is_file_scanned(sha: str) -> bool:
    with _conn() as c:
        return c.execute("SELECT 1 FROM scanned_files WHERE sha=?", (sha,)).fetchone() is not None


def mark_file_scanned(sha: str):
    with _conn() as c:
        c.execute("INSERT OR IGNORE INTO scanned_files(sha, scanned_at) VALUES(?,?)", (sha, _now()))


# ── Repos ──────────────────────────────────────────────────────────────────

def should_scan_repo(full_name: str) -> bool:
    with _conn() as c:
        row = c.execute("SELECT last_scanned FROM scanned_repos WHERE full_name=?",
                        (full_name,)).fetchone()
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
            ON CONFLICT(full_name) DO UPDATE SET
                last_scanned=excluded.last_scanned,
                stars=excluded.stars,
                created_at=excluded.created_at
        """, (full_name, now, now, stars, created_at))


def get_repo_cached(full_name: str) -> tuple[int, str] | None:
    with _conn() as c:
        row = c.execute("SELECT stars, created_at FROM scanned_repos WHERE full_name=?",
                        (full_name,)).fetchone()
    return (row["stars"], row["created_at"]) if row else None


# ── Keys ───────────────────────────────────────────────────────────────────

def key_exists(key: str) -> bool:
    h = hashlib.sha256(key.encode()).hexdigest()
    with _conn() as c:
        return c.execute("SELECT 1 FROM found_keys WHERE key_hash=?", (h,)).fetchone() is not None


def save_key(provider: str, key: str, repo: str, file_path: str,
             file_url: str, repo_stars: int, repo_created: str,
             file_type: str, is_valid: bool) -> bool:
    h = hashlib.sha256(key.encode()).hexdigest()
    preview = key[:12] + "..." + key[-6:] if len(key) > 18 else key[:8] + "..."
    try:
        with _conn() as c:
            c.execute("""
                INSERT INTO found_keys
                    (key_hash, provider, key_preview, key_full, repo,
                     file_path, file_url, repo_stars, repo_created,
                     file_type, is_valid, discovered_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
            """, (h, provider, preview, key, repo, file_path, file_url,
                  repo_stars, repo_created, file_type, int(is_valid), _now()))
        return True
    except sqlite3.IntegrityError:
        return False


# ── Stats / Results ────────────────────────────────────────────────────────

def get_stats() -> dict:
    with _conn() as c:
        by_prov = [dict(r) for r in c.execute(
            "SELECT provider, COUNT(*) as total, COALESCE(SUM(is_valid),0) as valid "
            "FROM found_keys GROUP BY provider ORDER BY total DESC"
        ).fetchall()]
        return {
            "repos_scanned": c.execute("SELECT COUNT(*) FROM scanned_repos").fetchone()[0],
            "files_scanned": c.execute("SELECT COUNT(*) FROM scanned_files").fetchone()[0],
            "keys_found":    c.execute("SELECT COUNT(*) FROM found_keys").fetchone()[0],
            "keys_valid":    c.execute("SELECT COUNT(*) FROM found_keys WHERE is_valid=1").fetchone()[0],
            "by_provider":   by_prov,
        }


def get_keys_since(since_iso: str) -> list[dict]:
    with _conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT provider, COUNT(*) as cnt, COALESCE(SUM(is_valid),0) as valid_cnt "
            "FROM found_keys WHERE discovered_at > ? "
            "GROUP BY provider ORDER BY cnt DESC",
            (since_iso,)
        ).fetchall()]


def get_valid_since(since_iso: str) -> list[dict]:
    with _conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT provider, key_preview, repo, file_url, discovered_at "
            "FROM found_keys WHERE is_valid=1 AND discovered_at > ? "
            "ORDER BY discovered_at DESC LIMIT 10",
            (since_iso,)
        ).fetchall()]


def get_results(valid_only: bool = False, limit: int = 200) -> list[dict]:
    q = "SELECT * FROM found_keys"
    if valid_only:
        q += " WHERE is_valid=1"
    q += f" ORDER BY discovered_at DESC LIMIT {limit}"
    with _conn() as c:
        return [dict(r) for r in c.execute(q).fetchall()]


# ── Infra findings ──────────────────────────────────────────────────────────

def infra_exists(cred: str) -> bool:
    h = hashlib.sha256(cred.encode()).hexdigest()
    with _conn() as c:
        return c.execute("SELECT 1 FROM infra_findings WHERE cred_hash=?",
                         (h,)).fetchone() is not None


def save_infra(cred_type: str, cred: str, repo: str, file_path: str,
               file_url: str, repo_stars: int, repo_created: str,
               file_type: str, destination: str,
               risk_level: str, risk_reasons: list[str]) -> bool:
    import json
    h = hashlib.sha256(cred.encode()).hexdigest()
    # Preview: first 20 + last 8, never expose DB passwords/SSH keys in full in preview
    preview = cred[:20] + "..." + cred[-8:] if len(cred) > 28 else cred[:16] + "..."
    try:
        with _conn() as c:
            c.execute("""
                INSERT INTO infra_findings
                    (cred_hash, cred_type, cred_preview, cred_full, repo,
                     file_path, file_url, repo_stars, repo_created,
                     file_type, destination, risk_level, risk_reasons, discovered_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (h, cred_type, preview, cred, repo, file_path, file_url,
                  repo_stars, repo_created, file_type, destination,
                  risk_level, json.dumps(risk_reasons, ensure_ascii=False), _now()))
        return True
    except sqlite3.IntegrityError:
        return False


def get_infra_results(risk_filter: str | None = None, limit: int = 200) -> list[dict]:
    """risk_filter: 'high' | 'medium' | 'low' | None (all)"""
    if risk_filter:
        q = f"SELECT * FROM infra_findings WHERE risk_level=? ORDER BY discovered_at DESC LIMIT {limit}"
        with _conn() as c:
            return [dict(r) for r in c.execute(q, (risk_filter,)).fetchall()]
    q = f"SELECT * FROM infra_findings ORDER BY discovered_at DESC LIMIT {limit}"
    with _conn() as c:
        return [dict(r) for r in c.execute(q).fetchall()]


def get_infra_stats() -> dict:
    with _conn() as c:
        by_type = [dict(r) for r in c.execute(
            "SELECT cred_type, COUNT(*) as total, "
            "SUM(CASE WHEN risk_level='high' THEN 1 ELSE 0 END) as high_risk, "
            "SUM(CASE WHEN risk_level='medium' THEN 1 ELSE 0 END) as med_risk "
            "FROM infra_findings GROUP BY cred_type ORDER BY total DESC"
        ).fetchall()]
        by_dest = [dict(r) for r in c.execute(
            "SELECT destination, COUNT(*) as cnt, cred_type "
            "FROM infra_findings WHERE destination != '' "
            "GROUP BY destination ORDER BY cnt DESC LIMIT 20"
        ).fetchall()]
        return {
            "total":   c.execute("SELECT COUNT(*) FROM infra_findings").fetchone()[0],
            "high":    c.execute("SELECT COUNT(*) FROM infra_findings WHERE risk_level='high'").fetchone()[0],
            "medium":  c.execute("SELECT COUNT(*) FROM infra_findings WHERE risk_level='medium'").fetchone()[0],
            "by_type": by_type,
            "by_dest": by_dest,
        }


def get_infra_since(since_iso: str) -> list[dict]:
    with _conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT cred_type, COUNT(*) as cnt, "
            "SUM(CASE WHEN risk_level='high' THEN 1 ELSE 0 END) as high_cnt "
            "FROM infra_findings WHERE discovered_at > ? "
            "GROUP BY cred_type ORDER BY cnt DESC",
            (since_iso,)
        ).fetchall()]
