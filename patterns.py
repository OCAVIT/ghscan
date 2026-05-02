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
# sk_[hex] pattern MUST have elevenlabs context nearby — without it we'd match
# Stripe test keys (sk_test_…), Supabase service keys, and other sk_ namespaces.
_EL_SK_CTX = re.compile(
    r'(?:elevenlabs|xi[_\-]api[_\-]key|xi\.api\.key|ELEVEN)'
    r'[\s\S]{0,300}'
    r'(sk_[a-f0-9]{32,64})',
    re.IGNORECASE,
)


def extract_elevenlabs(content: str) -> list[str]:
    found = []
    for m in _EL_CTX.finditer(content):
        key = m.group(1)
        if len(key) >= 20 and not _FAKE.search(key):
            found.append(key)
    if re.search(r'(?i)elevenlabs|xi[_\-]api[_\-]key', content):
        for m in _EL_SK_CTX.finditer(content):
            key = m.group(1)
            if not _FAKE.search(key) and key not in found:
                found.append(key)
    return list(dict.fromkeys(found))


# ── ARK / Volcengine / Doubao / Seedance ─────────────────────────────────────
_UUID = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
_ARK_CTX = re.compile(
    r'(?:ARK_API_KEY|VOLCENGINE_API_KEY|DOUBAO_API_KEY|VOLC_API_KEY'
    r'|SEEDANCE_API_KEY|VOLC_ACCESSKEY|ARK_KEY'
    r'|BYTEPLUS_API_KEY|BYTEPLUS_ACCESS_KEY|BYTEPLUS_SECRET_KEY'
    r'|ark\.cn-beijing\.volces\.com|ark\.ap-southeast\.volces\.com'
    r'|ark\.cn-shanghai\.volces\.com|ark\.us-east-1\.volces\.com'
    r'|maas-api\.byteplus\.com|byteplus\.com'
    r'|volces\.com|seedance|doubao-seedance)'
    r'[\s\S]{0,300}'
    r'(' + _UUID + r')',
    re.IGNORECASE,
)


def _extract_ark_uuids(content: str) -> list[str]:
    found = []
    for m in _ARK_CTX.finditer(content):
        key = m.group(1)
        ctx = content[max(0, m.start() - 40): m.end() + 40]
        if _FAKE.search(ctx):
            continue
        found.append(key)
    return list(dict.fromkeys(found))


def extract_ark_fast(content: str) -> list[str]:
    """Same extraction as ark — validator decides if 2.0-fast is accessible."""
    return _extract_ark_uuids(content)


def extract_ark(content: str) -> list[str]:
    return _extract_ark_uuids(content)


# ── OpenAI Image (gpt-image-2) ───────────────────────────────────────────────
# Keys in gpt-image-2 repos look identical to regular OpenAI keys (sk-proj-/sk-*)
# but require org verification. Tracking separately (provider="openai_image") so
# the image-specific validator runs instead of the cheaper chat-completions probe.
_OAI_IMG_CTX = re.compile(
    r'(?:gpt-image-2|OPENAI_IMAGE_API_KEY|GPT_IMAGE_API_KEY|IMAGE_API_KEY'
    r'|images\.generations|images/generations|image_generation)'
    r'[\s\S]{0,400}'
    r'(sk-(?:proj-|svcacct-)[A-Za-z0-9_\-]{40,220}|sk-[A-Za-z0-9]{48})',
    re.IGNORECASE,
)


def extract_openai_image(content: str) -> list[str]:
    if not re.search(r'(?i)gpt-image-2|gpt_image_2|OPENAI_IMAGE', content):
        return []
    found = []
    for m in _OAI_IMG_CTX.finditer(content):
        key = m.group(1)
        ctx = content[max(0, m.start() - 80): m.end() + 40]
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


# ── Grok / xAI ───────────────────────────────────────────────────────────────
# xAI keys have a unique "xai-" prefix followed by ~70 base62 chars.
# Long enough to scan standalone (false-positive rate near zero).
_GROK_STANDALONE = re.compile(r'(?<![A-Za-z0-9_\-])(xai-[A-Za-z0-9]{60,90})(?![A-Za-z0-9])')
_GROK_CTX = re.compile(
    r'(?:XAI_API_KEY|GROK_API_KEY|xAI_KEY|api\.x\.ai|grok-[23]|grok_api)'
    r'[\s\S]{0,200}'
    r'(xai-[A-Za-z0-9]{60,90})',
    re.IGNORECASE,
)


def extract_grok(content: str) -> list[str]:
    found = []
    for m in _GROK_CTX.finditer(content):
        key = m.group(1)
        if not _FAKE.search(key):
            found.append(key)
    for m in _GROK_STANDALONE.finditer(content):
        key = m.group(1)
        if key not in found and not _FAKE.search(key):
            found.append(key)
    return list(dict.fromkeys(found))


# ── Suno AI ───────────────────────────────────────────────────────────────────
# No unique key prefix — context-only extraction near SUNO_API_KEY / suno.com.
_SUNO_CTX = re.compile(
    r'(?:SUNO_API_KEY|SUNO_SECRET|SUNO_TOKEN|suno\.ai|sunoapi\.org|api\.suno\.com)'
    r'[\s\S]{0,200}'
    r'([A-Za-z0-9_\-]{32,120})',
    re.IGNORECASE,
)


def extract_suno(content: str) -> list[str]:
    if not re.search(r'(?i)suno', content):
        return []
    found = []
    for m in _SUNO_CTX.finditer(content):
        key = m.group(1)
        if len(key) >= 32 and not _FAKE.search(key):
            found.append(key)
    return list(dict.fromkeys(found))


# ── Inworld AI ────────────────────────────────────────────────────────────────
# Inworld uses Basic Auth with base64(api_key:api_secret). We look for the
# pre-encoded base64 string stored near INWORLD_BASE64/INWORLD_AUTH context.
_INWORLD_CTX = re.compile(
    r'(?:INWORLD_BASE64|INWORLD_AUTH|INWORLD_KEY_SECRET|inworld\.ai)'
    r'[\s\S]{0,200}'
    r'([A-Za-z0-9+/=]{40,160})',
    re.IGNORECASE,
)


def extract_inworld(content: str) -> list[str]:
    if not re.search(r'(?i)inworld', content):
        return []
    found = []
    for m in _INWORLD_CTX.finditer(content):
        key = m.group(1)
        if len(key) >= 40 and not _FAKE.search(key):
            found.append(key)
    return list(dict.fromkeys(found))


# ── Dispatcher ───────────────────────────────────────────────────────────────
EXTRACTORS: dict[str, callable] = {
    "openai":        extract_openai,
    "openai_image":  extract_openai_image,
    "anthropic":     extract_anthropic,
    "google":        extract_google,
    "deepseek":      extract_deepseek,
    "elevenlabs":    extract_elevenlabs,
    "ark_fast":      extract_ark_fast,   # Seedance 2.0-fast — BEFORE ark (hash-dedup priority)
    "ark":           extract_ark,        # Seedance 2.0-standard
    "happyhorse":    extract_happyhorse,
    "grok":          extract_grok,
    "suno":          extract_suno,
    "inworld":       extract_inworld,
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
    # OPENAI IMAGE (gpt-image-2) — requires org verification, separate validator
    # ═══════════════════════════════════════════════════════════════════════

    ('"gpt-image-2" "sk-" filename:.env',                  "openai_image", "env"),
    ('"GPT_IMAGE_API_KEY" filename:.env',                  "openai_image", "env"),
    ('"OPENAI_IMAGE_API_KEY" filename:.env',               "openai_image", "env"),
    ('"gpt-image-2" language:python',                      "openai_image", "code"),
    ('"gpt-image-2" language:javascript',                  "openai_image", "code"),
    ('"gpt-image-2" language:typescript',                  "openai_image", "code"),
    ('"gpt-image-2" language:go',                          "openai_image", "code"),
    ('"gpt-image-2" language:java',                        "openai_image", "code"),
    ('"gpt-image-2" extension:ipynb',                      "openai_image", "notebook"),
    ('"images/generations" "gpt-image-2" language:python', "openai_image", "code"),
    ('"images/generations" "gpt-image-2" language:javascript', "openai_image", "code"),

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
    # Veo / Vertex AI video generation — model names and env var patterns
    ('"VEO_API_KEY" filename:.env',                      "google", "env"),
    ('"GOOGLE_VEO_API_KEY" filename:.env',               "google", "env"),
    ('"veo-2" "AIzaSy" language:python',                 "google", "code"),
    ('"veo-3" "AIzaSy" language:python',                 "google", "code"),
    ('"veo-2" "GOOGLE_API_KEY" language:python',         "google", "code"),
    ('"veo-3" "GOOGLE_API_KEY" language:python',         "google", "code"),
    ('"veo-2" "generate_video" language:python',         "google", "code"),
    ('"veo-3" "generate_video" language:python',         "google", "code"),
    ('"veo-2.0-generate-001" language:python',           "google", "code"),
    ('"veo-3.0-generate-001" language:python',           "google", "code"),
    ('"generate_video" "GEMINI_API_KEY" language:python', "google", "code"),
    ('"generate_video" "GOOGLE_API_KEY" language:python', "google", "code"),
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
    # ELEVENLABS  (voice/TTS/speech context — text-to-speech API)
    # ═══════════════════════════════════════════════════════════════════════

    # .env — all common var names
    ('"ELEVENLABS_API_KEY" filename:.env',              "elevenlabs", "env"),
    ('"ELEVEN_API_KEY" filename:.env',                  "elevenlabs", "env"),
    ('"XI_API_KEY" filename:.env',                      "elevenlabs", "env"),
    ('"TTS_API_KEY" "elevenlabs" filename:.env',        "elevenlabs", "env"),
    ('"VOICE_API_KEY" "elevenlabs" filename:.env',      "elevenlabs", "env"),
    ('"elevenlabs" "xi-api-key" filename:.env',         "elevenlabs", "env"),
    ('"ELEVENLABS_API_KEY" filename:.env.local',        "elevenlabs", "env"),
    ('"ELEVENLABS_API_KEY" filename:.env.production',   "elevenlabs", "env"),

    # TTS/voice config files — devs often keep TTS settings separate
    ('"ELEVENLABS_API_KEY" filename:tts_config.py',    "elevenlabs", "config"),
    ('"ELEVENLABS_API_KEY" filename:voice_config.py',  "elevenlabs", "config"),
    ('"XI_API_KEY" filename:voice_settings.json',      "elevenlabs", "config"),
    ('"elevenlabs" "api_key" filename:config.py',      "elevenlabs", "config"),
    ('"elevenlabs" "api_key" filename:config.ts',      "elevenlabs", "config"),
    ('"elevenlabs" "api_key" filename:config.yaml',    "elevenlabs", "config"),
    ('"elevenlabs" "api_key" filename:settings.py',    "elevenlabs", "config"),

    # Code — multi-language
    ('"ELEVENLABS_API_KEY" language:python',            "elevenlabs", "code"),
    ('"ELEVENLABS_API_KEY" language:javascript',        "elevenlabs", "code"),
    ('"ELEVENLABS_API_KEY" language:typescript',        "elevenlabs", "code"),
    ('"ELEVENLABS_API_KEY" language:go',                "elevenlabs", "code"),
    ('"ELEVENLABS_API_KEY" language:java',              "elevenlabs", "code"),
    ('"ELEVENLABS_API_KEY" language:php',               "elevenlabs", "code"),
    ('"ELEVENLABS_API_KEY" language:ruby',              "elevenlabs", "code"),
    ('"XI_API_KEY" language:python',                    "elevenlabs", "code"),
    ('"XI_API_KEY" language:javascript',                "elevenlabs", "code"),
    ('"elevenlabs.io" "api_key" language:python',       "elevenlabs", "code"),
    ('"elevenlabs.io" "api_key" language:javascript',   "elevenlabs", "code"),
    ('"api.elevenlabs.io" language:python',             "elevenlabs", "code"),
    ('"api.elevenlabs.io" language:go',                 "elevenlabs", "code"),
    ('"api.elevenlabs.io" language:typescript',         "elevenlabs", "code"),
    ('"text_to_speech" "elevenlabs" language:python',   "elevenlabs", "code"),
    ('"voice_id" "xi-api-key" language:python',         "elevenlabs", "code"),
    ('"voice_id" "xi-api-key" language:javascript',     "elevenlabs", "code"),

    # Notebooks — data science TTS experiments
    ('"ELEVENLABS_API_KEY" extension:ipynb',            "elevenlabs", "notebook"),
    ('"XI_API_KEY" extension:ipynb',                    "elevenlabs", "notebook"),

    # CI/CD + Docker
    ('"ELEVENLABS_API_KEY" filename:docker-compose.yml',"elevenlabs", "docker"),
    ('"ELEVENLABS_API_KEY" path:.github/workflows',     "elevenlabs", "ci"),

    # ═══════════════════════════════════════════════════════════════════════
    # ARK / VOLCENGINE / DOUBAO / SEEDANCE 2.0  (video/image generation)
    # ═══════════════════════════════════════════════════════════════════════

    # .env — all var names
    ('"ARK_API_KEY" filename:.env',                         "ark", "env"),
    ('"VOLCENGINE_API_KEY" filename:.env',                  "ark", "env"),
    ('"DOUBAO_API_KEY" filename:.env',                      "ark", "env"),
    ('"SEEDANCE_API_KEY" filename:.env',                    "ark", "env"),
    ('"VOLC_ACCESSKEY" filename:.env',                      "ark", "env"),
    ('"BYTEDANCE_API_KEY" filename:.env',                   "ark", "env"),
    ('"VOLC_API_KEY" filename:.env',                        "ark", "env"),
    ('"ARK_API_KEY" filename:.env.local',                   "ark", "env"),
    ('"ARK_API_KEY" filename:.env.production',              "ark", "env"),

    # Video/image gen config files
    ('"ARK_API_KEY" filename:video_config.py',              "ark", "config"),
    ('"SEEDANCE_API_KEY" filename:video_config.py',         "ark", "config"),
    ('"ARK_API_KEY" filename:config.py',                    "ark", "config"),
    ('"ARK_API_KEY" filename:config.yaml',                  "ark", "config"),
    ('"ARK_API_KEY" filename:config.ts',                    "ark", "config"),

    # Notebooks
    ('"ARK_API_KEY" extension:ipynb',                       "ark", "notebook"),
    ('"DOUBAO_API_KEY" extension:ipynb',                    "ark", "notebook"),
    ('"VOLCENGINE_API_KEY" extension:ipynb',                "ark", "notebook"),

    # All Volcengine regional endpoints (Beijing, Shanghai, Guangzhou, intl)
    ('"ark.cn-beijing.volces.com" language:python',         "ark", "code"),
    ('"ark.cn-beijing.volces.com" language:javascript',     "ark", "code"),
    ('"ark.cn-beijing.volces.com" language:typescript',     "ark", "code"),
    ('"ark.cn-beijing.volces.com" language:go',             "ark", "code"),
    ('"ark.cn-beijing.volces.com" language:java',           "ark", "code"),
    ('"ark.cn-beijing.volces.com" language:php',            "ark", "code"),
    ('"ark.cn-beijing.volces.com" language:rust',           "ark", "code"),
    ('"ark.cn-shanghai.volces.com" language:python',        "ark", "code"),
    ('"ark.cn-shanghai.volces.com" language:go',            "ark", "code"),
    ('"ark.cn-guangzhou.volces.com" language:python',       "ark", "code"),
    ('"ark.ap-southeast.volces.com" language:python',       "ark", "code"),
    ('"ark.ap-southeast.volces.com" language:javascript',   "ark", "code"),
    ('"ark.us-east-1.volces.com" language:python',          "ark", "code"),
    ('"ark.eu-central-1.volces.com" language:python',       "ark", "code"),

    # Named env vars in code
    ('"VOLCENGINE_API_KEY" language:python',                "ark", "code"),
    ('"DOUBAO_API_KEY" language:python',                    "ark", "code"),
    ('"DOUBAO_API_KEY" language:javascript',                "ark", "code"),
    ('"DOUBAO_API_KEY" language:typescript',                "ark", "code"),
    ('"DOUBAO_API_KEY" language:java',                      "ark", "code"),
    ('"DOUBAO_API_KEY" language:go',                        "ark", "code"),
    ('"ARK_API_KEY" language:python',                       "ark", "code"),
    ('"ARK_API_KEY" language:javascript',                   "ark", "code"),
    ('"ARK_API_KEY" language:typescript',                   "ark", "code"),
    ('"ARK_API_KEY" language:go',                           "ark", "code"),
    ('"ARK_API_KEY" language:java',                         "ark", "code"),
    ('"ARK_API_KEY" language:php',                          "ark", "code"),
    ('"ARK_API_KEY" language:rust',                         "ark", "code"),
    ('"ARK_API_KEY" language:kotlin',                       "ark", "code"),
    ('"seedance" "api_key" language:python',                "ark", "code"),
    ('"text_to_video" "ARK_API_KEY" language:python',       "ark", "code"),
    ('"image_generation" "ARK_API_KEY" language:python',    "ark", "code"),
    ('"doubao" "api_key" language:python',                  "ark", "code"),
    ('"doubao" "api_key" language:javascript',              "ark", "code"),
    ('"doubao" "api_key" language:java',                    "ark", "code"),

    # Seedance model names literally in code — very high precision
    # 1.0 + 2.0: devs hardcode model IDs like doubao-seedance-*-260128
    ('"doubao-seedance" language:python',                   "ark", "code"),
    ('"doubao-seedance" language:javascript',               "ark", "code"),
    ('"doubao-seedance" language:typescript',               "ark", "code"),
    ('"doubao-seedance" language:go',                       "ark", "code"),
    ('"doubao-seedance" language:java',                     "ark", "code"),
    ('"doubao-seedance" language:rust',                     "ark", "code"),
    ('"doubao-seedance" filename:.env',                     "ark", "env"),
    ('"doubao-seedance-1-0" extension:ipynb',               "ark", "notebook"),
    # Seedance 2.0 — exact model IDs (released Apr 2026)
    ('"doubao-seedance-2-0-260128" language:python',        "ark", "code"),
    ('"doubao-seedance-2-0-260128" language:javascript',    "ark", "code"),
    ('"doubao-seedance-2-0-260128" language:typescript',    "ark", "code"),
    ('"doubao-seedance-2-0-fast-260128" language:python',   "ark", "code"),
    ('"doubao-seedance-2-0-fast-260128" language:javascript', "ark", "code"),
    ('"doubao-seedance-2-0" extension:ipynb',               "ark", "notebook"),
    ('"doubao-seedance-2-0" filename:.env',                 "ark", "env"),

    # BytePlus — ByteDance international brand (same ARK/Volcengine backend)
    ('"BYTEPLUS_API_KEY" filename:.env',                    "ark", "env"),
    ('"BYTEPLUS_ACCESS_KEY" filename:.env',                 "ark", "env"),
    ('"byteplus.com" "api_key" language:python',            "ark", "code"),
    ('"byteplus.com" "api_key" language:javascript',        "ark", "code"),
    ('"maas-api.byteplus.com" language:python',             "ark", "code"),
    ('"maas-api.byteplus.com" language:javascript',         "ark", "code"),
    ('"byteplus" "secret_key" filename:.env',               "ark", "env"),

    # Docker / CI
    ('"ARK_API_KEY" filename:docker-compose.yml',           "ark", "docker"),
    ('"VOLCENGINE_API_KEY" filename:docker-compose.yml',    "ark", "docker"),
    ('"ARK_API_KEY" path:.github/workflows',                "ark", "ci"),
    ('"DOUBAO_API_KEY" path:.github/workflows',             "ark", "ci"),

    # ═══════════════════════════════════════════════════════════════════════
    # HAPPY HORSE / RUNHAPPYHORSE  (image/video gen — owner's own service)
    # ═══════════════════════════════════════════════════════════════════════

    # .env
    ('"HAPPY_HORSE_API_KEY" filename:.env',               "happyhorse", "env"),
    ('"HH_API_KEY" filename:.env',                        "happyhorse", "env"),
    ('"HAPPYHORSE_API_KEY" filename:.env',                "happyhorse", "env"),
    ('"RUNHAPPYHORSE_API_KEY" filename:.env',             "happyhorse", "env"),
    ('"RUNHAPPYHORSE" filename:.env',                     "happyhorse", "env"),
    ('"happyhorse" "api_key" filename:.env',              "happyhorse", "env"),

    # Image/video gen config patterns
    ('"runhappyhorse.net" "api_key" filename:config.py',  "happyhorse", "config"),
    ('"runhappyhorse.net" "api_key" filename:config.ts',  "happyhorse", "config"),
    ('"happyhorse" "api_key" filename:video_config.py',   "happyhorse", "config"),
    ('"happyhorse" "image_generation" language:python',   "happyhorse", "code"),
    ('"happyhorse" "text_to_video" language:python',      "happyhorse", "code"),

    # Code — multi-language
    ('"runhappyhorse.net" "api_key"',                     "happyhorse", "code"),
    ('"runhappyhorse.net" "api_key" language:python',     "happyhorse", "code"),
    ('"runhappyhorse.net" "api_key" language:javascript', "happyhorse", "code"),
    ('"runhappyhorse.net" "api_key" language:typescript', "happyhorse", "code"),
    ('"runhappyhorse.net" "api_key" language:go',         "happyhorse", "code"),
    ('"runhappyhorse.net" "api_key" language:java',       "happyhorse", "code"),
    ('"HAPPY_HORSE_API_KEY" language:python',             "happyhorse", "code"),
    ('"HAPPY_HORSE_API_KEY" language:javascript',         "happyhorse", "code"),
    ('"HH_API_KEY" language:python',                      "happyhorse", "code"),

    # Notebooks
    ('"HAPPY_HORSE_API_KEY" extension:ipynb',             "happyhorse", "notebook"),
    ('"runhappyhorse" extension:ipynb',                   "happyhorse", "notebook"),

    # Happy Horse — Alibaba image-to-video context (HH is often used alongside Alibaba video APIs)
    ('"happyhorse" "alibaba" filename:.env',              "happyhorse", "env"),
    ('"HH_API_KEY" "ALIBABA" filename:.env',             "happyhorse", "env"),
    ('"runhappyhorse" "image_to_video" language:python',  "happyhorse", "code"),
    ('"runhappyhorse" "text_to_video" language:python',   "happyhorse", "code"),
    ('"runhappyhorse" "video_generation" language:python',"happyhorse", "code"),
    ('"runhappyhorse.net" language:javascript',           "happyhorse", "code"),
    ('"runhappyhorse.net" language:typescript',           "happyhorse", "code"),

    # ═══════════════════════════════════════════════════════════════════════
    # GROK / xAI  (unique "xai-" prefix — high precision)
    # ═══════════════════════════════════════════════════════════════════════

    ('"XAI_API_KEY" filename:.env',                       "grok", "env"),
    ('"XAI_API_KEY" filename:.env.local',                 "grok", "env"),
    ('"XAI_API_KEY" filename:.env.production',            "grok", "env"),
    ('"GROK_API_KEY" filename:.env',                      "grok", "env"),
    ('"XAI_API_KEY" filename:.env.example "xai-"',        "grok", "env"),
    ('"xai-" "XAI_API_KEY" filename:.env',                "grok", "env"),
    ('"xai-" filename:.env',                              "grok", "env"),

    ('"XAI_API_KEY" extension:ipynb',                     "grok", "notebook"),
    ('"xai-" "grok" extension:ipynb',                     "grok", "notebook"),

    ('"api.x.ai" language:python',                        "grok", "code"),
    ('"api.x.ai" language:javascript',                    "grok", "code"),
    ('"api.x.ai" language:typescript',                    "grok", "code"),
    ('"api.x.ai" language:go',                            "grok", "code"),
    ('"api.x.ai" language:java',                          "grok", "code"),
    ('"api.x.ai" language:rust',                          "grok", "code"),
    ('"XAI_API_KEY" language:python',                     "grok", "code"),
    ('"XAI_API_KEY" language:javascript',                 "grok", "code"),
    ('"XAI_API_KEY" language:typescript',                 "grok", "code"),
    ('"XAI_API_KEY" language:go',                         "grok", "code"),
    ('"xai-" "grok-3" language:python',                   "grok", "code"),
    ('"xai-" "grok-2" language:python',                   "grok", "code"),
    ('"XAI_API_KEY" filename:config.py',                  "grok", "config"),
    ('"XAI_API_KEY" filename:config.ts',                  "grok", "config"),
    ('"XAI_API_KEY" filename:docker-compose.yml',         "grok", "docker"),
    ('"XAI_API_KEY" path:.github/workflows',              "grok", "ci"),
    ('"GROK_API_KEY" path:.github/workflows',             "grok", "ci"),

    # ═══════════════════════════════════════════════════════════════════════
    # SUNO AI  (music generation — no prefix, context-only)
    # ═══════════════════════════════════════════════════════════════════════

    ('"SUNO_API_KEY" filename:.env',                      "suno", "env"),
    ('"SUNO_API_KEY" filename:.env.local',                "suno", "env"),
    ('"SUNO_API_KEY" filename:.env.example',              "suno", "env"),
    ('"SUNO_API_KEY" filename:.env.production',           "suno", "env"),
    ('"suno" "api_key" filename:.env',                    "suno", "env"),

    ('"SUNO_API_KEY" language:python',                    "suno", "code"),
    ('"SUNO_API_KEY" language:javascript',                "suno", "code"),
    ('"SUNO_API_KEY" language:typescript',                "suno", "code"),
    ('"sunoapi.org" language:python',                     "suno", "code"),
    ('"sunoapi.org" language:javascript',                 "suno", "code"),
    ('"sunoapi.org" language:typescript',                 "suno", "code"),
    ('"api.suno.com" language:python',                    "suno", "code"),
    ('"api.suno.com" language:javascript',                "suno", "code"),
    ('"SUNO_API_KEY" extension:ipynb',                    "suno", "notebook"),
    ('"SUNO_API_KEY" filename:config.py',                 "suno", "config"),
    ('"SUNO_API_KEY" filename:config.ts',                 "suno", "config"),
    ('"SUNO_API_KEY" path:.github/workflows',             "suno", "ci"),

    # ═══════════════════════════════════════════════════════════════════════
    # INWORLD AI TTS  (Basic auth base64 key:secret pair)
    # ═══════════════════════════════════════════════════════════════════════

    ('"INWORLD_API_KEY" filename:.env',                   "inworld", "env"),
    ('"INWORLD_SECRET" filename:.env',                    "inworld", "env"),
    ('"INWORLD_BASE64" filename:.env',                    "inworld", "env"),
    ('"INWORLD_AUTH" filename:.env',                      "inworld", "env"),
    ('"INWORLD_KEY_SECRET" filename:.env',                "inworld", "env"),
    ('"inworld.ai" "api_key" language:python',            "inworld", "code"),
    ('"inworld.ai" "api_key" language:javascript',        "inworld", "code"),
    ('"inworld.ai" "api_key" language:typescript',        "inworld", "code"),
    ('"INWORLD_API_KEY" language:python',                 "inworld", "code"),
    ('"INWORLD_API_KEY" language:javascript',             "inworld", "code"),
    ('"INWORLD_API_KEY" extension:ipynb',                 "inworld", "notebook"),

    # ═══════════════════════════════════════════════════════════════════════
    # NANO BANANA PRO  (Google Gemini model — uses standard AIzaSy keys)
    # ═══════════════════════════════════════════════════════════════════════

    ('"NANOBANANA_GEMINI_API_KEY" filename:.env',         "google", "env"),
    ('"NANOBANANA_API_KEY" filename:.env',                "google", "env"),
    ('"nano-banana" "GEMINI_API_KEY"',                    "google", "env"),
    ('"google-nano-banana-pro" language:python',          "google", "code"),
    ('"google-nano-banana-pro" language:javascript',      "google", "code"),
    ('"google-nano-banana-pro" language:typescript',      "google", "code"),
    ('"nano_banana" "api_key" language:python',           "google", "code"),
    ('"nano-banana-pro" extension:ipynb',                 "google", "notebook"),
    ('"NANOBANANA_GEMINI_API_KEY" extension:ipynb',       "google", "notebook"),
]
