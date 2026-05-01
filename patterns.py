"""
Key extraction regexes and search query definitions.

NOTE on query format: each tuple is (search_terms, provider, file_type_tag).
search_terms is the raw GitHub code-search query — NO "q=" prefix, NO "&sort=..."
suffix. Those are added as separate httpx params in scanner.search_code().
Previous code had these baked in, causing malformed requests (BUG FIXED).

Providers covered:
  openai      — sk-proj-*, sk-svcacct-*, sk-[48]
  anthropic   — sk-ant-api03-*  (Claude)
  google      — AIzaSy[33] (Gemini / Veo) + service-account JSON
  deepseek    — sk-[hex32+] near deepseek context
  elevenlabs  — 32-char hex / sk_ prefix near XI/ELEVENLABS context
  ark         — UUID v4 near Volcengine/Doubao/Seedance context
  happyhorse  — runhappyhorse.net API keys (owner's own service)
"""

import re

# ── Shared fake-key filter ──────────────────────────────────────────────────
_FAKE = re.compile(
    r'(?:your[_\-]?(?:api[_\-]?)?key|example|placeholder|xxx+|REPLACE'
    r'|<api|>|\.\.\.|\bfake\b|\bdummy\b|\bsample\b|\bdemo\b|test_key'
    r'|00000000-0000-0000-0000-000000000000|1234567890abcdef|key_here'
    r'|insert_key|your_token|changeme|secret_key_here)',
    re.IGNORECASE,
)

# ── Path filters ────────────────────────────────────────────────────────────
_SKIP_PATH = re.compile(
    r'/(?:node_modules|vendor|dist|build|\.next|out|coverage|__pycache__|\.git)/',
    re.IGNORECASE,
)
_TEST_PATH = re.compile(
    r'(?:test_|_test\.|\.test\.|\.spec\.|__tests__|/tests?/|/mock|/fixture)',
    re.IGNORECASE,
)
_SERVER_PATH = re.compile(
    r'(?:route|api/|server|backend|controller|service|handler|worker|'
    r'config|settings|\.env(?:$|[^a-zA-Z])|docker|compose|Dockerfile)',
    re.IGNORECASE,
)


def is_skippable_path(path: str) -> bool:
    return bool(_SKIP_PATH.search(path)) or bool(_TEST_PATH.search(path))


def is_server_path(path: str) -> bool:
    return bool(_SERVER_PATH.search(path)) or path.endswith((
        '.py', '.go', '.rs', '.rb', '.php', '.env', '.yaml', '.yml',
        '.json', '.ipynb', '.java', '.kt', '.cs', '.dart', '.swift',
        '.ts', '.tsx', '.toml', '.ini', '.cfg',
    ))


# ── OpenAI ──────────────────────────────────────────────────────────────────
_OAI_PATTERNS = [
    re.compile(r'sk-proj-[A-Za-z0-9_\-]{40,220}'),
    re.compile(r'sk-svcacct-[A-Za-z0-9_\-]{40,220}'),
    re.compile(r'sk-[A-Za-z0-9]{48}'),
]


def extract_openai(content: str) -> list[str]:
    found = []
    for pat in _OAI_PATTERNS:
        for m in pat.finditer(content):
            key = m.group(0)
            ctx = content[max(0, m.start() - 80): m.end() + 40]
            if _FAKE.search(ctx):
                continue
            # Exclude keys that have deepseek context nearby (provider overlap)
            if re.search(r'deepseek', ctx, re.IGNORECASE):
                continue
            found.append(key)
    return list(dict.fromkeys(found))


# ── Anthropic / Claude ───────────────────────────────────────────────────────
_ANT_PATTERNS = [
    re.compile(r'sk-ant-api03-[A-Za-z0-9_\-]{90,130}'),
    re.compile(r'sk-ant-[A-Za-z0-9_\-]{40,200}'),
]


def extract_anthropic(content: str) -> list[str]:
    found = []
    for pat in _ANT_PATTERNS:
        for m in pat.finditer(content):
            key = m.group(0)
            ctx = content[max(0, m.start() - 80): m.end() + 40]
            if _FAKE.search(ctx):
                continue
            found.append(key)
    return list(dict.fromkeys(found))


# ── Google / Gemini / Veo ────────────────────────────────────────────────────
_GOOGLE_SIMPLE = re.compile(r'AIzaSy[A-Za-z0-9_\-]{33}')
# Service account JSON: match client_email + private_key_id as composite key
_GOOGLE_SA_CTX = re.compile(
    r'"type"\s*:\s*"service_account"'
    r'[\s\S]{0,2000}'
    r'"client_email"\s*:\s*"([^"]+@[^"]+\.iam\.gserviceaccount\.com)"',
    re.DOTALL,
)
_GOOGLE_SA_KID = re.compile(r'"private_key_id"\s*:\s*"([0-9a-f]{40})"')


def extract_google(content: str) -> list[str]:
    found = []
    for m in _GOOGLE_SIMPLE.finditer(content):
        key = m.group(0)
        ctx = content[max(0, m.start() - 100): m.end() + 40]
        if _FAKE.search(ctx):
            continue
        found.append(key)
    # Service account JSON blobs
    for m in _GOOGLE_SA_CTX.finditer(content):
        email = m.group(1)
        snippet = content[m.start(): m.end() + 500]
        kid_m = _GOOGLE_SA_KID.search(snippet)
        kid = kid_m.group(1) if kid_m else "unknown"
        found.append(f"sa:{email}:{kid}")
    return list(dict.fromkeys(found))


# ── DeepSeek ─────────────────────────────────────────────────────────────────
# DS keys: sk-[alphanumeric, typically 32-64 chars], always with DS context
_DS_CTX = re.compile(
    r'(?:deepseek|DEEPSEEK_API_KEY|api\.deepseek\.com|DeepSeek)'
    r'[\s\S]{0,400}'
    r'(sk-[A-Za-z0-9]{20,80})',
    re.IGNORECASE,
)
_DS_DIRECT = re.compile(
    r'DEEPSEEK_API_KEY\s*[=:]\s*["\']?(sk-[A-Za-z0-9]{20,80})',
    re.IGNORECASE,
)


def extract_deepseek(content: str) -> list[str]:
    found = []
    for m in _DS_DIRECT.finditer(content):
        key = m.group(1)
        if not _FAKE.search(key):
            found.append(key)
    if re.search(r'(?i)deepseek|api\.deepseek\.com', content):
        for m in _DS_CTX.finditer(content):
            key = m.group(1)
            if not _FAKE.search(key) and key not in found:
                found.append(key)
    return list(dict.fromkeys(found))


# ── ElevenLabs ───────────────────────────────────────────────────────────────
_EL_CTX = re.compile(
    r'(?:ELEVEN(?:LABS)?_API_KEY|XI_API_KEY|elevenlabs_api_key|xi.api.key|ELEVENLABS)'
    r'\s*[=:]\s*["\']?'
    r'([A-Za-z0-9_\-]{20,80})',
    re.IGNORECASE,
)
_EL_SK = re.compile(r'\bsk_[a-f0-9]{32,64}\b')


def extract_elevenlabs(content: str) -> list[str]:
    found = []
    for m in _EL_CTX.finditer(content):
        key = m.group(1)
        if len(key) >= 20 and not _FAKE.search(key):
            found.append(key)
    for m in _EL_SK.finditer(content):
        key = m.group(0)
        if not _FAKE.search(key):
            found.append(key)
    return list(dict.fromkeys(found))


# ── ARK / Volcengine / Doubao / Seedance ─────────────────────────────────────
_UUID = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
_ARK_CTX = re.compile(
    r'(?:ARK_API_KEY|VOLCENGINE_API_KEY|DOUBAO_API_KEY|VOLC_API_KEY'
    r'|SEEDANCE_API_KEY|VOLC_ACCESSKEY|ARK_KEY'
    r'|ark\.cn-beijing\.volces\.com|ark\.ap-southeast\.volces\.com'
    r'|volces\.com|seedance\.ai|doubao)'
    r'[\s\S]{0,300}'
    r'(' + _UUID + r')',
    re.IGNORECASE,
)


def extract_ark(content: str) -> list[str]:
    found = []
    for m in _ARK_CTX.finditer(content):
        key = m.group(1)
        ctx = content[max(0, m.start() - 40): m.end() + 40]
        if _FAKE.search(ctx):
            continue
        found.append(key)
    return list(dict.fromkeys(found))


# ── Happy Horse / RunHappyHorse ───────────────────────────────────────────────
_HH_CTX = re.compile(
    r'(?:HAPPY_HORSE_API_KEY|RUNHAPPYHORSE_API_KEY|HAPPYHORSE_API_KEY'
    r'|HH_API_KEY|happy_horse_key|runhappyhorse\.net|happyhorse\.ai)'
    r'[\s\S]{0,300}'
    r'([A-Za-z0-9_\-]{20,120})',
    re.IGNORECASE,
)


def extract_happyhorse(content: str) -> list[str]:
    found = []
    for m in _HH_CTX.finditer(content):
        key = m.group(1)
        if len(key) >= 20 and not _FAKE.search(key):
            found.append(key)
    return list(dict.fromkeys(found))


# ── Dispatcher ───────────────────────────────────────────────────────────────
EXTRACTORS: dict[str, callable] = {
    "openai":      extract_openai,
    "anthropic":   extract_anthropic,
    "google":      extract_google,
    "deepseek":    extract_deepseek,
    "elevenlabs":  extract_elevenlabs,
    "ark":         extract_ark,
    "happyhorse":  extract_happyhorse,
}


# ── GitHub code search queries ────────────────────────────────────────────────
# Format: (search_terms, provider, file_type_tag)
# search_terms: raw query string passed as ?q= value (no q= prefix, no sort= suffix)
# scanner.search_code() adds sort=indexed&order=desc automatically.
#
# Language coverage rationale:
#   python     — global, data science, AI startups everywhere
#   javascript — global web devs
#   typescript — same + stronger in Korea/Japan/Eastern EU
#   go         — strong in China, Russia, US infra teams
#   java       — India, China, enterprise Eastern Europe
#   php        — Russia, Eastern Europe, Southeast Asia, legacy web
#   csharp     — Eastern Europe, .NET shops
#   ruby        — mixed global, Japanese devs
#   kotlin     — Android, strong in Korea/Japan
#   rust       — growing everywhere, Berlin/Tokyo/SF
#   dart       — Flutter, Southeast Asia/India/China
#   swift      — iOS devs, Japan/Korea/US

QUERIES: list[tuple[str, str, str]] = [

    # ═══════════════════════════════════════════════════════════════════════
    # OPENAI  (highest density, run first)
    # ═══════════════════════════════════════════════════════════════════════

    # .env — devs forget to gitignore; highest precision
    ('"OPENAI_API_KEY" "sk-" filename:.env',           "openai", "env"),
    ('"sk-proj-" filename:.env',                        "openai", "env"),
    ('"OPENAI_API_KEY" filename:.env.local',            "openai", "env"),
    ('"OPENAI_API_KEY" filename:.env.production',       "openai", "env"),
    ('"OPENAI_API_KEY" filename:.env.example "sk-"',    "openai", "env"),  # forgot to replace placeholder

    # Jupyter notebooks — data scientists hardcode and forget
    ('"OPENAI_API_KEY" "sk-" extension:ipynb',          "openai", "notebook"),
    ('"sk-proj-" extension:ipynb',                      "openai", "notebook"),

    # Docker / CI — ops engineers bake into pipelines
    ('"OPENAI_API_KEY" "sk-" filename:docker-compose.yml', "openai", "docker"),
    ('"OPENAI_API_KEY" "sk-" filename:Dockerfile',      "openai", "docker"),
    ('"OPENAI_API_KEY" "sk-" path:.github',             "openai", "ci"),
    ('"OPENAI_API_KEY" "sk-" filename:.gitlab-ci.yml',  "openai", "ci"),

    # Language-specific config files
    ('"sk-proj-" filename:config.py',                   "openai", "config"),
    ('"sk-proj-" filename:settings.py',                 "openai", "config"),
    ('"sk-proj-" filename:config.js',                   "openai", "config"),
    ('"sk-proj-" filename:config.ts',                   "openai", "config"),
    ('"OPENAI_API_KEY" filename:appsettings.json',      "openai", "config"),   # .NET
    ('"OPENAI_API_KEY" filename:application.yml',       "openai", "config"),   # Spring/Java
    ('"OPENAI_API_KEY" filename:application.properties',"openai", "config"),   # Spring

    # Code — broad multi-language sweep
    ('"sk-proj-" language:python',                      "openai", "code"),
    ('"sk-proj-" language:javascript',                  "openai", "code"),
    ('"sk-proj-" language:typescript',                  "openai", "code"),
    ('"sk-proj-" language:go',                          "openai", "code"),
    ('"sk-proj-" language:java',                        "openai", "code"),
    ('"sk-proj-" language:php',                         "openai", "code"),
    ('"sk-proj-" language:csharp',                      "openai", "code"),
    ('"sk-proj-" language:ruby',                        "openai", "code"),
    ('"sk-proj-" language:rust',                        "openai", "code"),
    ('"sk-proj-" language:kotlin',                      "openai", "code"),
    ('"sk-svcacct-" language:python',                   "openai", "code"),
    ('"sk-svcacct-" language:javascript',               "openai", "code"),
    ('"OPENAI_API_KEY=sk-" language:python',            "openai", "code"),
    ('"OPENAI_API_KEY=sk-" language:javascript',        "openai", "code"),
    ('"OPENAI_API_KEY=sk-" language:go',                "openai", "code"),
    ('"OPENAI_API_KEY=sk-" language:java',              "openai", "code"),
    ('"OPENAI_API_KEY=sk-" language:php',               "openai", "code"),

    # ═══════════════════════════════════════════════════════════════════════
    # ANTHROPIC / CLAUDE
    # ═══════════════════════════════════════════════════════════════════════

    ('"ANTHROPIC_API_KEY" "sk-ant-" filename:.env',     "anthropic", "env"),
    ('"sk-ant-api03-" filename:.env',                   "anthropic", "env"),
    ('"CLAUDE_API_KEY" "sk-ant-" filename:.env',        "anthropic", "env"),
    ('"ANTHROPIC_API_KEY" filename:.env.local',         "anthropic", "env"),
    ('"sk-ant-api03-" extension:ipynb',                 "anthropic", "notebook"),
    ('"sk-ant-api03-" filename:config.py',              "anthropic", "config"),
    ('"sk-ant-api03-" filename:config.ts',              "anthropic", "config"),
    ('"ANTHROPIC_API_KEY" filename:docker-compose.yml', "anthropic", "docker"),
    ('"sk-ant-api03-" language:python',                 "anthropic", "code"),
    ('"sk-ant-api03-" language:javascript',             "anthropic", "code"),
    ('"sk-ant-api03-" language:typescript',             "anthropic", "code"),
    ('"sk-ant-api03-" language:go',                     "anthropic", "code"),
    ('"sk-ant-api03-" language:java',                   "anthropic", "code"),
    ('"sk-ant-api03-" language:php',                    "anthropic", "code"),
    ('"sk-ant-api03-" language:ruby',                   "anthropic", "code"),
    ('"ANTHROPIC_API_KEY=sk-ant-" language:python',     "anthropic", "code"),
    ('"ANTHROPIC_API_KEY=sk-ant-" language:javascript', "anthropic", "code"),

    # ═══════════════════════════════════════════════════════════════════════
    # GOOGLE / GEMINI / VEO
    # ═══════════════════════════════════════════════════════════════════════

    ('"GOOGLE_API_KEY" "AIzaSy" filename:.env',         "google", "env"),
    ('"GEMINI_API_KEY" "AIzaSy" filename:.env',         "google", "env"),
    ('"GOOGLE_AI_API_KEY" filename:.env',               "google", "env"),
    ('"VERTEX_AI" "AIzaSy" filename:.env',              "google", "env"),
    # Service account JSON blobs — leaked as committed credential files
    ('"service_account" "private_key" filename:credentials.json', "google", "sa_json"),
    ('"service_account" "private_key" filename:service_account.json', "google", "sa_json"),
    ('"client_email" "private_key" "iam.gserviceaccount.com"', "google", "sa_json"),
    # Gemini-specific
    ('"GEMINI_API_KEY" language:python',                "google", "code"),
    ('"GEMINI_API_KEY" language:javascript',            "google", "code"),
    ('"GEMINI_API_KEY" language:typescript',            "google", "code"),
    ('"GEMINI_API_KEY" language:go',                    "google", "code"),
    ('"GEMINI_API_KEY" language:java',                  "google", "code"),
    ('"google.generativeai" "AIzaSy" language:python',  "google", "code"),
    ('"generativelanguage.googleapis.com" "AIzaSy"',    "google", "code"),
    # Veo / Vertex AI
    ('"GOOGLE_APPLICATION_CREDENTIALS" filename:docker-compose.yml', "google", "docker"),
    ('"aiplatform" "service_account" language:python',  "google", "code"),

    # ═══════════════════════════════════════════════════════════════════════
    # DEEPSEEK
    # ═══════════════════════════════════════════════════════════════════════

    ('"DEEPSEEK_API_KEY" "sk-" filename:.env',          "deepseek", "env"),
    ('"DEEPSEEK_API_KEY" filename:.env',                "deepseek", "env"),
    ('"api.deepseek.com" "sk-" filename:.env',          "deepseek", "env"),
    ('"DEEPSEEK_API_KEY" extension:ipynb',              "deepseek", "notebook"),
    ('"DEEPSEEK_API_KEY" language:python',              "deepseek", "code"),
    ('"DEEPSEEK_API_KEY" language:javascript',          "deepseek", "code"),
    ('"DEEPSEEK_API_KEY" language:typescript',          "deepseek", "code"),
    ('"DEEPSEEK_API_KEY" language:go',                  "deepseek", "code"),
    ('"DEEPSEEK_API_KEY" language:java',                "deepseek", "code"),
    ('"DEEPSEEK_API_KEY" language:php',                 "deepseek", "code"),
    ('"api.deepseek.com" language:python',              "deepseek", "code"),
    ('"api.deepseek.com" language:go',                  "deepseek", "code"),
    ('"deepseek" "sk-" filename:config.py',             "deepseek", "config"),

    # ═══════════════════════════════════════════════════════════════════════
    # ELEVENLABS
    # ═══════════════════════════════════════════════════════════════════════

    ('"ELEVENLABS_API_KEY" filename:.env',              "elevenlabs", "env"),
    ('"ELEVEN_API_KEY" filename:.env',                  "elevenlabs", "env"),
    ('"XI_API_KEY" filename:.env',                      "elevenlabs", "env"),
    ('"elevenlabs" "xi-api-key" filename:.env',         "elevenlabs", "env"),
    ('"ELEVENLABS_API_KEY" language:python',            "elevenlabs", "code"),
    ('"ELEVENLABS_API_KEY" language:javascript',        "elevenlabs", "code"),
    ('"ELEVENLABS_API_KEY" language:typescript',        "elevenlabs", "code"),
    ('"XI_API_KEY" language:python',                    "elevenlabs", "code"),
    ('"elevenlabs.io" "api_key" language:python',       "elevenlabs", "code"),
    ('"ELEVENLABS_API_KEY" filename:docker-compose.yml',"elevenlabs", "docker"),

    # ═══════════════════════════════════════════════════════════════════════
    # ARK / VOLCENGINE / DOUBAO / SEEDANCE 2.0
    # ═══════════════════════════════════════════════════════════════════════

    ('"ARK_API_KEY" filename:.env',                     "ark", "env"),
    ('"VOLCENGINE_API_KEY" filename:.env',              "ark", "env"),
    ('"DOUBAO_API_KEY" filename:.env',                  "ark", "env"),
    ('"SEEDANCE_API_KEY" filename:.env',                "ark", "env"),
    ('"VOLC_ACCESSKEY" filename:.env',                  "ark", "env"),
    ('"ARK_API_KEY" extension:ipynb',                   "ark", "notebook"),
    ('"DOUBAO_API_KEY" extension:ipynb',                "ark", "notebook"),
    ('"ark.cn-beijing.volces.com" language:python',     "ark", "code"),
    ('"ark.cn-beijing.volces.com" language:javascript', "ark", "code"),
    ('"ark.cn-beijing.volces.com" language:typescript', "ark", "code"),
    ('"ark.cn-beijing.volces.com" language:go',         "ark", "code"),
    ('"ark.cn-beijing.volces.com" language:java',       "ark", "code"),
    ('"ark.ap-southeast.volces.com" language:python',   "ark", "code"),
    ('"VOLCENGINE_API_KEY" language:python',            "ark", "code"),
    ('"DOUBAO_API_KEY" language:python',                "ark", "code"),
    ('"ARK_API_KEY" language:python',                   "ark", "code"),
    ('"ARK_API_KEY" language:javascript',               "ark", "code"),
    ('"ARK_API_KEY" language:go',                       "ark", "code"),
    ('"ARK_API_KEY" language:java',                     "ark", "code"),
    ('"seedance" "api_key" language:python',            "ark", "code"),
    ('"ARK_API_KEY" filename:docker-compose.yml',       "ark", "docker"),
    ('"VOLCENGINE_API_KEY" filename:docker-compose.yml',"ark", "docker"),

    # ═══════════════════════════════════════════════════════════════════════
    # HAPPY HORSE / RUNHAPPYHORSE  (owner's own service — defensive scan)
    # ═══════════════════════════════════════════════════════════════════════

    ('"HAPPY_HORSE_API_KEY" filename:.env',             "happyhorse", "env"),
    ('"RUNHAPPYHORSE" filename:.env',                   "happyhorse", "env"),
    ('"runhappyhorse.net" "api_key"',                   "happyhorse", "code"),
    ('"runhappyhorse.net" "api_key" language:python',   "happyhorse", "code"),
    ('"runhappyhorse.net" "api_key" language:javascript',"happyhorse", "code"),
    ('"happyhorse" "api_key" filename:.env',            "happyhorse", "env"),
]
