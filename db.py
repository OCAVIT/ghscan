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

        -- Author tracking — serial leaker watchlist.
        -- Auto-populated by track_leak() on every save_key insert. Promotes
        -- to is_watched=1 once leak_count >= 3 (deliberate threshold —
        -- 1-2 leaks is noise, 3+ is a habit). Watched authors get their
        -- public repos walked periodically to capture future leaks within
        -- hours rather than days.
        CREATE TABLE IF NOT EXISTS watched_authors (
            login            TEXT NOT NULL,
            platform         TEXT NOT NULL DEFAULT 'github',
            leak_count       INTEGER DEFAULT 0,
            valid_count      INTEGER DEFAULT 0,
            repos_with_leaks INTEGER DEFAULT 0,
            first_leak_at    TEXT NOT NULL,
            last_leak_at     TEXT NOT NULL,
            last_walked_at   TEXT,
            is_watched       INTEGER DEFAULT 0,
            PRIMARY KEY(login, platform)
        );
        CREATE INDEX IF NOT EXISTS idx_authors_count   ON watched_authors(leak_count DESC);
        CREATE INDEX IF NOT EXISTS idx_authors_watched ON watched_authors(is_watched, last_leak_at DESC);
        CREATE INDEX IF NOT EXISTS idx_authors_walk    ON watched_authors(is_watched, last_walked_at);

        -- Tree-walk dedup — repos already exhaustively scanned.
        -- Prevents re-walking when subsequent keys are found in the same repo.
        CREATE TABLE IF NOT EXISTS tree_walked_repos (
            repo_full_name TEXT PRIMARY KEY,
            walked_at      TEXT NOT NULL,
            files_scanned  INTEGER DEFAULT 0,
            keys_found     INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_treewalk_at ON tree_walked_repos(walked_at DESC);
        """)
        # Migrations — add columns if they don't exist yet (idempotent)
        for col, defn in [
            ("is_validated",     "INTEGER DEFAULT -1"),   # -1=pending, 0=invalid, 1=valid
            ("validation_result", "TEXT DEFAULT ''"),
        ]:
            try:
                c.execute(f"ALTER TABLE infra_findings ADD COLUMN {col} {defn}")
            except Exception:
                pass  # already exists
        # found_keys migrations
        for col, defn in [
            ("last_validated_at", "TEXT DEFAULT NULL"),  # last re-validation timestamp
        ]:
            try:
                c.execute(f"ALTER TABLE found_keys ADD COLUMN {col} {defn}")
            except Exception:
                pass


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


def clear_scanned_files() -> int:
    """Delete all rows from scanned_files. Returns count of deleted rows."""
    with _conn() as c:
        cnt = c.execute("SELECT COUNT(*) FROM scanned_files").fetchone()[0]
        c.execute("DELETE FROM scanned_files")
        return cnt


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
        # Track author leak (best-effort — never raise on tracking failure)
        try:
            track_leak(repo, bool(is_valid))
        except Exception:
            pass
        return True
    except sqlite3.IntegrityError:
        return False


# ── Author tracking (serial leaker watchlist) ─────────────────────────────────

# leak_count threshold above which an author is auto-promoted to is_watched=1.
# Conservative: 1-2 leaks is noise (one-off accident), 3+ is a habit.
_WATCHLIST_THRESHOLD = 3


def _parse_repo(repo: str) -> tuple[str, str]:
    """Parse `owner/name` from various scanner repo formats.

    Handles plain GitHub `owner/name`, gitee/codeberg/bitbucket which all use
    the same format, plus prefixed variants like `postman:ws_name` or
    `kaggle:owner/slug`. Returns (platform, login). Empty login = skip.
    """
    if not repo:
        return ("github", "")
    # Stripped prefixes for non-github platforms
    for pfx, plat in (
        ("postman:",  "postman"),
        ("kaggle:",   "kaggle"),
        ("hf:",       "huggingface"),
        ("npm:",      "npm"),
        ("pypi:",     "pypi"),
        ("cc:",       "commoncrawl"),
    ):
        if repo.startswith(pfx):
            rest = repo[len(pfx):]
            login = rest.split("/", 1)[0] if "/" in rest else rest
            return (plat, login.strip())
    # Default: assume `owner/name` GitHub-shape (also valid for gitee/codeberg)
    parts = repo.split("/", 1)
    if len(parts) == 2 and parts[0]:
        return ("github", parts[0])
    return ("github", "")


def track_leak(repo: str, is_valid: bool):
    """Auto-populate watched_authors on every save_key. UPSERT pattern:
    increment counters and bump timestamps for the leak's author.
    Promotes to is_watched=1 once leak_count >= threshold."""
    platform, login = _parse_repo(repo)
    if not login:
        return
    now = _now()
    with _conn() as c:
        # First check if owner already had a leak in this exact repo
        # (so repos_with_leaks counts unique repos, not unique keys).
        prior = c.execute(
            "SELECT 1 FROM found_keys WHERE repo=? LIMIT 1",
            (repo,),
        ).fetchone()
        # `prior` reflects the just-inserted row too, so compare counts:
        # if there's exactly 1 row for this repo, this leak introduces a
        # new repo; otherwise the repo already counted previously.
        prior_count = c.execute(
            "SELECT COUNT(*) FROM found_keys WHERE repo=?",
            (repo,),
        ).fetchone()[0]
        first_in_repo = (prior_count == 1)

        c.execute("""
            INSERT INTO watched_authors
                (login, platform, leak_count, valid_count, repos_with_leaks,
                 first_leak_at, last_leak_at, is_watched)
            VALUES (?, ?, 1, ?, 1, ?, ?, 0)
            ON CONFLICT(login, platform) DO UPDATE SET
                leak_count       = leak_count + 1,
                valid_count      = valid_count + ?,
                repos_with_leaks = repos_with_leaks + ?,
                last_leak_at     = excluded.last_leak_at,
                is_watched       = CASE WHEN leak_count + 1 >= ?
                                        THEN 1 ELSE is_watched END
        """, (
            login, platform,
            1 if is_valid else 0,
            now, now,
            1 if is_valid else 0,
            1 if first_in_repo else 0,
            _WATCHLIST_THRESHOLD,
        ))


def get_watched_authors(limit: int = 100, only_watched: bool = True) -> list[dict]:
    """Top leakers ranked by leak_count (or valid_count if available)."""
    where = "WHERE is_watched=1" if only_watched else ""
    with _conn() as c:
        return [dict(r) for r in c.execute(
            f"""SELECT login, platform, leak_count, valid_count,
                       repos_with_leaks, first_leak_at, last_leak_at,
                       last_walked_at, is_watched
                FROM watched_authors
                {where}
                ORDER BY valid_count DESC, leak_count DESC
                LIMIT ?""",
            (limit,),
        ).fetchall()]


def get_authors_to_walk(limit: int = 20, max_age_hours: int = 24) -> list[dict]:
    """Watched authors whose last_walked_at is older than max_age_hours.
    NULLs (never walked) come first."""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=max_age_hours)).isoformat()
    with _conn() as c:
        return [dict(r) for r in c.execute(
            """SELECT login, platform, leak_count, last_walked_at
               FROM watched_authors
               WHERE is_watched=1
                 AND (last_walked_at IS NULL OR last_walked_at < ?)
               ORDER BY
                 CASE WHEN last_walked_at IS NULL THEN 0 ELSE 1 END,
                 leak_count DESC,
                 last_walked_at ASC
               LIMIT ?""",
            (cutoff, limit),
        ).fetchall()]


def mark_author_walked(login: str, platform: str = "github"):
    """Stamp last_walked_at after a successful repo enumeration."""
    with _conn() as c:
        c.execute(
            "UPDATE watched_authors SET last_walked_at=? WHERE login=? AND platform=?",
            (_now(), login, platform),
        )


# ── Tree-walk dedup ────────────────────────────────────────────────────────────

def try_claim_repo_tree(repo_full_name: str) -> bool:
    """Atomic claim: True if this repo hasn't been tree-walked yet.

    Inserting a placeholder row first prevents two concurrent workers from
    both walking the same repo. The `walked_at` is overwritten by
    mark_repo_walked on completion.
    """
    if not repo_full_name:
        return False
    try:
        with _conn() as c:
            c.execute(
                "INSERT INTO tree_walked_repos (repo_full_name, walked_at) VALUES(?, ?)",
                (repo_full_name, _now()),
            )
        return True
    except sqlite3.IntegrityError:
        return False


def mark_repo_walked(repo_full_name: str, files_scanned: int, keys_found: int):
    """Update stats on a tree-walked repo (placeholder row already exists
    via try_claim_repo_tree)."""
    with _conn() as c:
        c.execute(
            """UPDATE tree_walked_repos
               SET walked_at=?, files_scanned=?, keys_found=?
               WHERE repo_full_name=?""",
            (_now(), files_scanned, keys_found, repo_full_name),
        )


def update_key_validity(key_hash: str, is_valid: bool):
    """Update is_valid and stamp last_validated_at. Called by revalidation loop."""
    with _conn() as c:
        c.execute(
            "UPDATE found_keys SET is_valid=?, last_validated_at=? WHERE key_hash=?",
            (int(is_valid), _now(), key_hash),
        )


def update_key_provider(key_hash: str, provider: str):
    """Reclassify an existing key to a new provider label (e.g. ark → ark_fast)."""
    with _conn() as c:
        c.execute(
            "UPDATE found_keys SET provider=? WHERE key_hash=?",
            (provider, key_hash),
        )


def get_valid_keys_by_provider(provider: str) -> list[dict]:
    """Return all is_valid=1 keys for a given provider."""
    with _conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT id, key_hash, provider, key_full, key_preview, repo, file_url "
            "FROM found_keys WHERE is_valid=1 AND provider=?",
            (provider,),
        ).fetchall()]


def get_valid_count_by_provider() -> dict[str, int]:
    """Return {provider: count} for all is_valid=1 keys."""
    with _conn() as c:
        rows = c.execute(
            "SELECT provider, COUNT(*) as cnt FROM found_keys WHERE is_valid=1 GROUP BY provider"
        ).fetchall()
    return {row["provider"]: row["cnt"] for row in rows}


def get_valid_keys_to_revalidate(max_age_hours: int = 12, limit: int = 200) -> list[dict]:
    """
    Return up to `limit` keys currently marked valid that haven't been
    re-validated within `max_age_hours`. NULLs (never re-validated) come first.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=max_age_hours)).isoformat()
    with _conn() as c:
        return [dict(r) for r in c.execute(
            """SELECT id, key_hash, provider, key_full FROM found_keys
               WHERE is_valid=1
                 AND (last_validated_at IS NULL OR last_validated_at < ?)
               ORDER BY
                 CASE WHEN last_validated_at IS NULL THEN 0 ELSE 1 END,
                 last_validated_at ASC
               LIMIT ?""",
            (cutoff, limit),
        ).fetchall()]


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
    if valid_only:
        q = "SELECT * FROM found_keys WHERE is_valid=1 ORDER BY discovered_at DESC LIMIT ?"
    else:
        q = "SELECT * FROM found_keys ORDER BY discovered_at DESC LIMIT ?"
    with _conn() as c:
        return [dict(r) for r in c.execute(q, (limit,)).fetchall()]


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
        q = "SELECT * FROM infra_findings WHERE risk_level=? ORDER BY discovered_at DESC LIMIT ?"
        with _conn() as c:
            return [dict(r) for r in c.execute(q, (risk_filter, limit)).fetchall()]
    q = "SELECT * FROM infra_findings ORDER BY discovered_at DESC LIMIT ?"
    with _conn() as c:
        return [dict(r) for r in c.execute(q, (limit,)).fetchall()]


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


def update_infra_validation(cred_hash: str, is_validated: int, result: str = ""):
    with _conn() as c:
        c.execute(
            "UPDATE infra_findings SET is_validated=?, validation_result=? WHERE cred_hash=?",
            (is_validated, result, cred_hash),
        )


def cleanup_old_low_risk(older_than_days: int = 30) -> int:
    """Delete low-risk infra findings older than N days. Returns deleted count."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=older_than_days)).isoformat()
    with _conn() as c:
        cur = c.execute(
            "DELETE FROM infra_findings WHERE risk_level='low' AND discovered_at < ?",
            (cutoff,),
        )
        deleted = cur.rowcount
    if deleted:
        # Reclaim disk space after bulk delete
        with _conn() as c:
            c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    return deleted


def get_infra_since(since_iso: str) -> list[dict]:
    with _conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT cred_type, COUNT(*) as cnt, "
            "SUM(CASE WHEN risk_level='high' THEN 1 ELSE 0 END) as high_cnt "
            "FROM infra_findings WHERE discovered_at > ? "
            "GROUP BY cred_type ORDER BY cnt DESC",
            (since_iso,)
        ).fetchall()]
