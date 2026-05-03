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
# Current 2026 key formats:
#   sk-proj-{156 chars}   — project keys (now default for new accounts)
#   sk-svcacct-{...}      — service account keys (rare)
#   sk-admin-{124 chars}  — admin keys, only call admin endpoints (org owner)
#   sk-{48}               — legacy account keys (still issued for old accounts)
_OAI_PATTERNS = [
    re.compile(r'sk-proj-[A-Za-z0-9_\-]{40,220}'),
    re.compile(r'sk-svcacct-[A-Za-z0-9_\-]{40,220}'),
    re.compile(r'sk-admin-[A-Za-z0-9_\-]{100,200}'),
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
    r'|VOLCSTACK_ACCESS_KEY_ID|VOLCSTACK_SECRET_ACCESS_KEY'
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


# ── HuggingFace ──────────────────────────────────────────────────────────────
# hf_ prefix is unique and 37 chars total — very low false-positive rate.
# Scan standalone; also context-anchor for broader env-var names without prefix.
_HF_STANDALONE = re.compile(r'(?<![A-Za-z0-9])(hf_[A-Za-z0-9]{34,50})(?![A-Za-z0-9])')
_HF_CTX = re.compile(
    r'(?:HF_TOKEN|HUGGINGFACE_TOKEN|HUGGING_FACE_HUB_TOKEN|HF_API_KEY|HF_API_TOKEN)'
    r'\s*[=:]\s*["\']?'
    r'([A-Za-z0-9_\-]{34,80})',
    re.IGNORECASE,
)


def extract_huggingface(content: str) -> list[str]:
    found = []
    for m in _HF_STANDALONE.finditer(content):
        key = m.group(1)
        ctx = content[max(0, m.start() - 80): m.end() + 40]
        if not _FAKE.search(ctx):
            found.append(key)
    if re.search(r'(?i)huggingface|HF_TOKEN|HF_API', content):
        for m in _HF_CTX.finditer(content):
            key = m.group(1)
            if not key.startswith("hf_"):
                key = "hf_ctx:" + key  # distinguish non-prefixed ctx matches
            if key not in found and not _FAKE.search(key):
                found.append(key)
    return list(dict.fromkeys(found))


# ── Perplexity AI ─────────────────────────────────────────────────────────────
# pplx- prefix is unique — low false-positive, standalone scan safe.
_PPLX_STANDALONE = re.compile(r'(?<![A-Za-z0-9])(pplx-[a-f0-9]{48,64})(?![A-Za-z0-9])')
_PPLX_CTX = re.compile(
    r'(?:PERPLEXITY_API_KEY|PPLX_API_KEY|PPLX_KEY|api\.perplexity\.ai)'
    r'[\s\S]{0,200}'
    r'(pplx-[a-f0-9]{48,64})',
    re.IGNORECASE,
)


def extract_perplexity(content: str) -> list[str]:
    found = []
    for m in _PPLX_STANDALONE.finditer(content):
        key = m.group(1)
        ctx = content[max(0, m.start() - 80): m.end() + 40]
        if not _FAKE.search(ctx):
            found.append(key)
    for m in _PPLX_CTX.finditer(content):
        key = m.group(1)
        if key not in found and not _FAKE.search(key):
            found.append(key)
    return list(dict.fromkeys(found))


# ── Runway ML ─────────────────────────────────────────────────────────────────
# Keys stored as RUNWAYML_API_SECRET — no unique prefix, context-only.
_RUNWAY_DIRECT = re.compile(
    r'RUNWAYML_API_SECRET\s*[=:]\s*["\']?([A-Za-z0-9_\-]{32,120})',
    re.IGNORECASE,
)
_RUNWAY_CTX = re.compile(
    r'(?:RUNWAYML_API_SECRET|RUNWAY_API_KEY|RUNWAY_API_SECRET|RUNWAY_TOKEN'
    r'|api\.dev\.runwayml\.com|api\.runwayml\.com)'
    r'[\s\S]{0,200}'
    r'([A-Za-z0-9_\-]{32,120})',
    re.IGNORECASE,
)


def extract_runway(content: str) -> list[str]:
    if not re.search(r'(?i)runwayml|RUNWAY_API|runway\.ml|runwayml\.com', content):
        return []
    found = []
    for m in _RUNWAY_DIRECT.finditer(content):
        key = m.group(1)
        if not _FAKE.search(key):
            found.append(key)
    for m in _RUNWAY_CTX.finditer(content):
        key = m.group(1)
        if len(key) >= 32 and key not in found and not _FAKE.search(key):
            found.append(key)
    return list(dict.fromkeys(found))


# ── Happy Horse / RunHappyHorse / LimeAI ─────────────────────────────────────
# AI video generation service (image-to-video / text-to-video).
# Also exposed under limeai.top domain. Alibaba wan-video / i2v context.
_HH_CTX = re.compile(
    r'(?:HAPPY_HORSE_API_KEY|RUNHAPPYHORSE_API_KEY|HAPPYHORSE_API_KEY'
    r'|HH_API_KEY|LIMEAI_API_KEY|LIME_AI_KEY|happy_horse_key'
    r'|runhappyhorse\.net|happyhorse\.ai|limeai\.top|lime-ai\.com)'
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


# ── Replicate ────────────────────────────────────────────────────────────────
# Keys have a unique "r8_" prefix + ~40 alphanumeric chars.
_REPLICATE_RE = re.compile(r'(?<![A-Za-z0-9_\-])(r8_[A-Za-z0-9]{38,55})(?![A-Za-z0-9])')
_REPLICATE_CTX = re.compile(
    r'(?:REPLICATE_API_TOKEN|REPLICATE_API_KEY|REPLICATE_TOKEN|replicate\.com)'
    r'[\s\S]{0,200}'
    r'(r8_[A-Za-z0-9]{38,55})',
    re.IGNORECASE,
)


def extract_replicate(content: str) -> list[str]:
    found = []
    for m in _REPLICATE_CTX.finditer(content):
        key = m.group(1)
        if not _FAKE.search(key):
            found.append(key)
    for m in _REPLICATE_RE.finditer(content):
        key = m.group(1)
        if key not in found and not _FAKE.search(key):
            found.append(key)
    return list(dict.fromkeys(found))


# ── Fal.ai ────────────────────────────────────────────────────────────────────
# Keys are "key_id:key_secret" hex pairs stored in FAL_KEY / FAL_SECRET_KEY.
# Pattern: two hex segments separated by colon (total ~80-120 chars).
_FAL_KEY_RE = re.compile(
    r'(?<![A-Za-z0-9_\-])([0-9a-f]{8,16}:[0-9a-f]{40,80})(?![A-Za-z0-9])',
    re.IGNORECASE,
)
_FAL_CTX = re.compile(
    r'(?:FAL_API_KEY|FAL_KEY|FAL_SECRET_KEY|fal\.ai|fal\.run|api\.fal\.ai)'
    r'[\s\S]{0,200}'
    r'([0-9a-f]{8,16}:[0-9a-f]{40,80})',
    re.IGNORECASE,
)


def extract_fal(content: str) -> list[str]:
    if not re.search(r'(?i)fal[._-]', content):
        return []
    found = []
    for m in _FAL_CTX.finditer(content):
        key = m.group(1)
        if not _FAKE.search(key):
            found.append(key)
    for m in _FAL_KEY_RE.finditer(content):
        key = m.group(1)
        ctx = content[max(0, m.start()-100): m.end()+40]
        if re.search(r'(?i)fal', ctx) and key not in found and not _FAKE.search(key):
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


# ── Kimi / Moonshot AI ───────────────────────────────────────────────────────
# Keys: sk-[alphanumeric 20+] — overlaps with OpenAI prefix, context-only.
# Two platforms: api.moonshot.cn (China) and api.moonshot.ai (international).
_KIMI_DIRECT = re.compile(
    r'(?:MOONSHOT_API_KEY|KIMI_API_KEY|KIMI_KEY)\s*[=:]\s*["\']?(sk-[A-Za-z0-9]{20,80})',
    re.IGNORECASE,
)
_KIMI_CTX = re.compile(
    r'(?:MOONSHOT_API_KEY|KIMI_API_KEY|KIMI_KEY|api\.moonshot\.cn|api\.moonshot\.ai'
    r'|moonshot-v1|kimi-latest)'
    r'[\s\S]{0,400}'
    r'(sk-[A-Za-z0-9]{20,80})',
    re.IGNORECASE,
)


def extract_kimi(content: str) -> list[str]:
    if not re.search(r'(?i)moonshot|kimi[_\-]?api|api\.moonshot', content):
        return []
    found = []
    for m in _KIMI_DIRECT.finditer(content):
        key = m.group(1)
        if not _FAKE.search(key):
            found.append(key)
    for m in _KIMI_CTX.finditer(content):
        key = m.group(1)
        if key not in found and not _FAKE.search(key):
            found.append(key)
    return list(dict.fromkeys(found))


# ── GLM / Zhipu AI / ChatGLM ──────────────────────────────────────────────────
# Key format: {32 hex chars}.{16 base62 chars} — unique dot-separated structure.
# Example: a1b2c3d4e5f6...1234.ABCDabcd12345678
_GLM_STANDALONE = re.compile(
    r'(?<![A-Za-z0-9\.\-])([a-f0-9]{32}\.[A-Za-z0-9]{16})(?![A-Za-z0-9\.])',
)
_GLM_DIRECT = re.compile(
    r'(?:ZHIPUAI_API_KEY|ZHIPU_API_KEY|GLM_API_KEY|BIGMODEL_API_KEY)'
    r'\s*[=:]\s*["\']?([A-Za-z0-9_\-.]{32,80})',
    re.IGNORECASE,
)
_GLM_CTX = re.compile(
    r'(?:ZHIPUAI_API_KEY|ZHIPU_API_KEY|GLM_API_KEY|open\.bigmodel\.cn|zhipuai|chatglm)'
    r'[\s\S]{0,300}'
    r'([A-Za-z0-9_\-.]{32,80})',
    re.IGNORECASE,
)


def extract_glm(content: str) -> list[str]:
    found = []
    # Standalone: unique hex.base62 format — very low false-positive
    for m in _GLM_STANDALONE.finditer(content):
        key = m.group(1)
        ctx = content[max(0, m.start() - 80): m.end() + 40]
        if not _FAKE.search(ctx):
            found.append(key)
    if re.search(r'(?i)zhipuai|zhipu|bigmodel|chatglm|glm[_\-]?api', content):
        for m in _GLM_DIRECT.finditer(content):
            key = m.group(1)
            if key not in found and not _FAKE.search(key):
                found.append(key)
        for m in _GLM_CTX.finditer(content):
            key = m.group(1)
            if len(key) >= 32 and key not in found and not _FAKE.search(key):
                found.append(key)
    return list(dict.fromkeys(found))


# ── KLING / Kuaishou AI ───────────────────────────────────────────────────────
# Auth model: AccessKey + SecretKey pair → developer generates short-lived JWT
# server-side (HS256, iss=access_key, exp=now+1800). No bare key in headers.
# We extract BOTH keys from the same file and store as "access:secret" pair.
_KLING_ACCESS = re.compile(
    r'(?:KLING_ACCESS_KEY|KLING_AK|KUAISHOU_ACCESS_KEY)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,60})',
    re.IGNORECASE,
)
_KLING_SECRET = re.compile(
    r'(?:KLING_SECRET_KEY|KLING_SK|KUAISHOU_SECRET_KEY)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{30,80})',
    re.IGNORECASE,
)
_KLING_TRIGGER = re.compile(
    r'(?:kling|klingai|api\.klingai\.com|KLING_ACCESS|KLING_SECRET|kuaishou)',
    re.IGNORECASE,
)


def extract_kling(content: str) -> list[str]:
    if not _KLING_TRIGGER.search(content):
        return []
    access_keys = [m.group(1) for m in _KLING_ACCESS.finditer(content)
                   if not _FAKE.search(m.group(1))]
    secret_keys = [m.group(1) for m in _KLING_SECRET.finditer(content)
                   if not _FAKE.search(m.group(1))]
    if not access_keys or not secret_keys:
        return []
    # Pair first access with first secret found in same file
    return [f"{access_keys[0]}:{secret_keys[0]}"]


# ── Fireworks AI ──────────────────────────────────────────────────────────────
# Keys: fw_ + alphanumeric 30-50 chars. NOT in GitHub secret scanning.
_FW_STANDALONE = re.compile(r'(?<![A-Za-z0-9_])(fw_[A-Za-z0-9]{30,60})(?![A-Za-z0-9])')
_FW_CTX = re.compile(
    r'(?:FIREWORKS_API_KEY|FIREWORKS_AI_API_KEY|api\.fireworks\.ai)'
    r'[\s\S]{0,200}'
    r'(fw_[A-Za-z0-9]{30,60})',
    re.IGNORECASE,
)


def extract_fireworks(content: str) -> list[str]:
    found = []
    for m in _FW_CTX.finditer(content):
        key = m.group(1)
        if not _FAKE.search(key):
            found.append(key)
    for m in _FW_STANDALONE.finditer(content):
        key = m.group(1)
        ctx = content[max(0, m.start() - 100): m.end() + 40]
        if re.search(r'(?i)fireworks', ctx) and key not in found and not _FAKE.search(key):
            found.append(key)
    return list(dict.fromkeys(found))


# ── OpenRouter ────────────────────────────────────────────────────────────────
# Keys: sk-or-v1- + 64 hex chars = 73 total. Extremely distinctive.
# NOT in GitHub secret scanning — routes to 20+ upstream providers.
_OR_STANDALONE = re.compile(r'(?<![A-Za-z0-9_])(sk-or-v1-[a-f0-9]{64})(?![A-Za-z0-9])')
_OR_CTX = re.compile(
    r'(?:OPENROUTER_API_KEY|OR_API_KEY|OPENROUTER_KEY|openrouter\.ai)'
    r'[\s\S]{0,200}'
    r'(sk-or-v1-[a-f0-9]{64})',
    re.IGNORECASE,
)


def extract_openrouter(content: str) -> list[str]:
    found = []
    for m in _OR_CTX.finditer(content):
        key = m.group(1)
        if not _FAKE.search(key):
            found.append(key)
    for m in _OR_STANDALONE.finditer(content):
        key = m.group(1)
        if key not in found and not _FAKE.search(key):
            found.append(key)
    return list(dict.fromkeys(found))


# ── Cerebras ─────────────────────────────────────────────────────────────────
# Keys: csk- + ~48 alphanumeric chars. Unique prefix → near-zero false positives.
# NOT in GitHub secret scanning → very high validity rate.
# Cerebras Cloud: ultra-fast inference (100k+ tokens/sec on Llama/Mistral).
_CEREBRAS_STANDALONE = re.compile(
    r'(?<![A-Za-z0-9_])(csk-[A-Za-z0-9]{32,80})(?![A-Za-z0-9])',
)
_CEREBRAS_CTX = re.compile(
    r'(?:CEREBRAS_API_KEY|CEREBRAS_KEY|api\.cerebras\.ai)'
    r'[\s\S]{0,200}'
    r'(csk-[A-Za-z0-9]{32,80})',
    re.IGNORECASE,
)


def extract_cerebras(content: str) -> list[str]:
    found = []
    for m in _CEREBRAS_CTX.finditer(content):
        key = m.group(1)
        if not _FAKE.search(key):
            found.append(key)
    for m in _CEREBRAS_STANDALONE.finditer(content):
        key = m.group(1)
        if key not in found and not _FAKE.search(key):
            found.append(key)
    return list(dict.fromkeys(found))


# ─────────────────────────────────────────────────────────────────────────────
# Aggregator providers (one key → access to Claude, Gemini, GPT, GPT Image…)
# Critical for finding LIVE keys to closed providers since their direct keys
# get auto-revoked by GitHub Secret Scanning Partner Program.
# ─────────────────────────────────────────────────────────────────────────────

# AIMLAPI — direct OpenRouter competitor, 400+ models including Claude/Gemini/GPT
# Key format: typically 32-char lowercase hex or UUID-like. Always context-bound.
# Boundary class before key prevents greedy match swallowing prefix bytes.
_AIMLAPI_CTX = re.compile(
    r'(?:AIMLAPI_(?:API_)?KEY|AIML_API_KEY|aimlapi\.com|api\.aimlapi)'
    r'[\s\S]{0,150}?'
    r'[=:\s"\'`,>]'
    r'([A-Za-z0-9]{32,80})'
    r'(?![A-Za-z0-9])',
    re.IGNORECASE,
)


def extract_aimlapi(content: str) -> list[str]:
    if not re.search(r'(?i)aimlapi|aiml_api', content):
        return []
    found = []
    for m in _AIMLAPI_CTX.finditer(content):
        key = m.group(1)
        if len(key) < 32 or _FAKE.search(key):
            continue
        # Filter out obvious non-keys (must contain digit + letter mix)
        if not re.search(r'[0-9]', key) or not re.search(r'[a-zA-Z]', key):
            continue
        found.append(key)
    return list(dict.fromkeys(found))


# DeepInfra — corporate prox to many models. Two key formats: standard hex
# and scoped JWT (eyJ...).
_DEEPINFRA_CTX = re.compile(
    r'(?:DEEPINFRA_(?:API_)?(?:KEY|TOKEN)|deepinfra\.com|api\.deepinfra)'
    r'[\s\S]{0,150}?'
    r'[=:\s"\'`,>]'
    r'([A-Za-z0-9_\-]{40,120})'
    r'(?![A-Za-z0-9_\-])',
    re.IGNORECASE,
)
_DEEPINFRA_JWT_CTX = re.compile(
    r'(?:DEEPINFRA_(?:API_)?(?:KEY|TOKEN)|deepinfra\.com|api\.deepinfra)'
    r'[\s\S]{0,150}?'
    r'(eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,})',
    re.IGNORECASE,
)


def extract_deepinfra(content: str) -> list[str]:
    if not re.search(r'(?i)deepinfra', content):
        return []
    found = []
    # JWT format first (more specific)
    for m in _DEEPINFRA_JWT_CTX.finditer(content):
        key = m.group(1)
        if not _FAKE.search(key):
            found.append(key)
    # Standard token format
    for m in _DEEPINFRA_CTX.finditer(content):
        key = m.group(1)
        if key in found:
            continue
        # Skip JWT-shaped strings (already matched above) and obvious junk
        if key.startswith("eyJ") or _FAKE.search(key):
            continue
        if not re.search(r'[0-9]', key) or not re.search(r'[a-zA-Z]', key):
            continue
        found.append(key)
    return list(dict.fromkeys(found))


# Hyperbolic — JWT-format keys (eyJhbGciOi...).
_HYPERBOLIC_CTX = re.compile(
    r'(?:HYPERBOLIC_(?:API_)?KEY|api\.hyperbolic\.xyz|hyperbolic\.ai|hyperbolic\.xyz)'
    r'[\s\S]{0,200}?'
    r'(eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,})',
    re.IGNORECASE,
)


def extract_hyperbolic(content: str) -> list[str]:
    if not re.search(r'(?i)hyperbolic', content):
        return []
    found = []
    for m in _HYPERBOLIC_CTX.finditer(content):
        key = m.group(1)
        if not _FAKE.search(key):
            found.append(key)
    return list(dict.fromkeys(found))


# NovitaAI — Chinese aggregator with image gen (GPT Image, Nano Banana, FLUX).
# Key prefix: sk_ followed by 40+ alnum chars (note underscore, not dash like OpenAI).
_NOVITA_STANDALONE = re.compile(
    r'(?<![A-Za-z0-9_])(sk_[A-Za-z0-9]{40,80})(?![A-Za-z0-9])',
)
_NOVITA_CTX = re.compile(
    r'(?:NOVITA_(?:AI_)?(?:API_)?KEY|novita\.ai|api\.novita)'
    r'[\s\S]{0,200}'
    r'(sk_[A-Za-z0-9]{40,80})',
    re.IGNORECASE,
)


def extract_novita(content: str) -> list[str]:
    found = []
    # Context-bound first (lower false-positive)
    for m in _NOVITA_CTX.finditer(content):
        key = m.group(1)
        if not _FAKE.search(key):
            found.append(key)
    # Standalone — only if "novita" string appears somewhere in content
    # (avoids matching unrelated sk_-prefixed strings in random files)
    if re.search(r'(?i)novita', content):
        for m in _NOVITA_STANDALONE.finditer(content):
            key = m.group(1)
            if key not in found and not _FAKE.search(key):
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
    "ark":           extract_ark,        # Seedance 2.0-standard — BEFORE ark_fast (higher value)
    "ark_fast":      extract_ark_fast,   # Seedance 2.0-fast
    "happyhorse":    extract_happyhorse,
    "grok":          extract_grok,
    "suno":          extract_suno,
    "inworld":       extract_inworld,
    "replicate":     extract_replicate,
    "fal":           extract_fal,
    "huggingface":   extract_huggingface,
    "perplexity":    extract_perplexity,
    "runway":        extract_runway,
    "kimi":          extract_kimi,
    "glm":           extract_glm,
    "kling":         extract_kling,
    "fireworks":     extract_fireworks,
    "openrouter":    extract_openrouter,
    "cerebras":      extract_cerebras,
    # Aggregators — single key gives access to multiple closed providers
    "aimlapi":       extract_aimlapi,
    "deepinfra":     extract_deepinfra,
    "hyperbolic":    extract_hyperbolic,
    "novita":        extract_novita,
}


# ── Fast-path content triggers ───────────────────────────────────────────────
# Single source of truth for "does this file contain anything worth running
# regex on?" — imported by every scanner (scanner.py, gitee_scanner.py,
# events_scanner.py, gist_scanner.py, kaggle_scanner.py, hf_scanner.py,
# codeberg_scanner.py). When adding a new provider to EXTRACTORS, also add
# its key prefix + env var names here.
#
# Includes:
#   - All key prefixes (sk-, AIzaSy, eyJ, hf_, pplx-, xai-, r8_, gsk_, fw_,
#     sk-or-v1, csk-)
#   - Both UPPER and lowercase env-var spellings (catch URL-style refs like
#     "api.openrouter.ai" lowercase as well as "OPENROUTER_API_KEY" upper)
#   - Provider domains (api.openai.com, api.deepseek.com, openrouter.ai…)
AI_TRIGGER: tuple[str, ...] = (
    # ── Key prefixes ────────────────────────────────────────────────────
    "sk-",          # OpenAI / Anthropic / DeepSeek / Mistral / many others
    "AIzaSy",       # Google
    "eyJ",          # JWT — Inworld base64, Google SA, generic
    "hf_",          # HuggingFace
    "pplx-",        # Perplexity
    "xai-",         # xAI / Grok
    "r8_",          # Replicate
    "fw_",          # Fireworks
    "sk-or-v1",     # OpenRouter
    "csk-",         # Cerebras

    # ── OpenAI / OpenAI Image ───────────────────────────────────────────
    "OPENAI_API_KEY", "openai", "api.openai.com",
    "OPENAI_IMAGE_API_KEY", "GPT_IMAGE_API_KEY", "gpt-image",

    # ── Anthropic ───────────────────────────────────────────────────────
    "ANTHROPIC_API_KEY", "anthropic", "api.anthropic.com",

    # ── Google / Gemini ─────────────────────────────────────────────────
    "GOOGLE_API_KEY", "GEMINI_API_KEY", "GOOGLE_GENAI",
    "generativelanguage", "googleapis.com",

    # ── DeepSeek ────────────────────────────────────────────────────────
    "DEEPSEEK_API_KEY", "DEEPSEEK", "deepseek", "api.deepseek.com",

    # ── ElevenLabs ──────────────────────────────────────────────────────
    "ELEVENLABS_API_KEY", "ELEVEN_API_KEY", "XI_API_KEY",
    "ELEVENLABS", "elevenlabs",

    # ── Volcengine / ARK / Doubao / Seedance ────────────────────────────
    "ARK_API_KEY", "ARK_API", "ark_api",
    "DOUBAO_API_KEY", "DOUBAO", "doubao",
    "VOLCENGINE_API", "VOLC_API_KEY", "VOLCSTACK", "VOLC_ACCESSKEY",
    "seedance",

    # ── HuggingFace ─────────────────────────────────────────────────────
    "HF_TOKEN", "HUGGINGFACE_TOKEN", "HUGGING_FACE_HUB_TOKEN",
    "HF_API_KEY", "HF_API_TOKEN", "huggingface_hub", "huggingface.co",

    # ── Perplexity ──────────────────────────────────────────────────────
    "PERPLEXITY_API_KEY", "PPLX_API_KEY", "PPLX_KEY",
    "perplexity", "api.perplexity.ai",

    # ── Runway ──────────────────────────────────────────────────────────
    "RUNWAYML_API_SECRET", "RUNWAY_API_KEY", "RUNWAY_TOKEN",
    "runway", "runwayml",

    # ── Happyhorse / RunHappyHorse ──────────────────────────────────────
    "HAPPY_HORSE_API_KEY", "HAPPYHORSE_API_KEY", "RUNHAPPYHORSE_API_KEY",
    "happyhorse", "runhappyhorse",

    # ── Replicate ───────────────────────────────────────────────────────
    "REPLICATE_API_TOKEN", "REPLICATE_API_KEY", "REPLICATE_TOKEN",
    "replicate.com",

    # ── Fal.ai ──────────────────────────────────────────────────────────
    "FAL_API_KEY", "FAL_KEY", "FAL_SECRET_KEY",
    "fal.ai", "fal.run", "api.fal.ai",

    # ── xAI / Grok ──────────────────────────────────────────────────────
    "XAI_API_KEY", "GROK_API_KEY", "xAI_KEY",
    "api.x.ai", "grok-2", "grok-3", "grok_api",

    # ── Suno ────────────────────────────────────────────────────────────
    "SUNO_API_KEY", "SUNO_SECRET", "SUNO_TOKEN",
    "suno.ai", "sunoapi.org", "api.suno.com",

    # ── Inworld ─────────────────────────────────────────────────────────
    "INWORLD_BASE64", "INWORLD_AUTH", "INWORLD_KEY_SECRET",
    "INWORLD_KEY", "inworld.ai",

    # ── Moonshot / Kimi ─────────────────────────────────────────────────
    "MOONSHOT_API_KEY", "KIMI_API_KEY", "KIMI_KEY",
    "moonshot", "MOONSHOT", "api.moonshot.cn", "api.moonshot.ai",

    # ── Zhipu / GLM / ChatGLM ───────────────────────────────────────────
    "ZHIPUAI_API_KEY", "ZHIPU_API_KEY", "GLM_API_KEY", "BIGMODEL_API_KEY",
    "ZHIPUAI", "zhipuai", "chatglm", "open.bigmodel.cn",

    # ── Kling / Kuaishou ────────────────────────────────────────────────
    "KLING_ACCESS_KEY", "KLING_AK", "KUAISHOU_ACCESS_KEY",
    "KLING_SECRET_KEY", "KLING_SK", "KUAISHOU_SECRET_KEY",
    "KLING_ACCESS", "KLING_SECRET", "KLING_",
    "klingai", "KLINGAI", "kuaishou", "api.klingai.com",

    # ── Fireworks ───────────────────────────────────────────────────────
    "FIREWORKS_API_KEY", "FIREWORKS_AI_API_KEY",
    "FIREWORKS", "fireworks", "api.fireworks.ai",

    # ── OpenRouter ──────────────────────────────────────────────────────
    "OPENROUTER_API_KEY", "OR_API_KEY", "OPENROUTER_KEY",
    "OPENROUTER", "openrouter", "openrouter.ai",

    # ── Cerebras ────────────────────────────────────────────────────────
    "CEREBRAS_API_KEY", "CEREBRAS_KEY", "cerebras", "api.cerebras.ai",

    # ── Aggregators (Claude/Gemini/GPT/GPT Image proxy) ─────────────────
    "AIMLAPI", "aimlapi", "AIML_API_KEY", "api.aimlapi.com",
    "DEEPINFRA", "deepinfra", "DEEPINFRA_API_KEY", "DEEPINFRA_TOKEN",
    "api.deepinfra.com",
    "HYPERBOLIC", "hyperbolic", "HYPERBOLIC_API_KEY", "api.hyperbolic.xyz",
    "NOVITA_API_KEY", "NOVITA_AI", "novita.ai", "api.novita.ai",
)

# Same role for infra extractors (DB URLs, AWS keys, private keys).
INFRA_TRIGGER: tuple[str, ...] = (
    "://",                                              # any URL-style cred
    "BEGIN PRIVATE KEY", "BEGIN RSA", "BEGIN OPENSSH",  # PEM blocks
    "AKIA", "AIPA", "AIDA", "AROA", "ASIA",             # AWS access-key prefixes
)


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

    # VolcStack — alternate ARK/Volcengine credential names used by Chinese devs
    ('"VOLCSTACK_ACCESS_KEY_ID" filename:.env',             "ark", "env"),
    ('"VOLCSTACK_SECRET_ACCESS_KEY" filename:.env',         "ark", "env"),
    ('"VOLCSTACK_ACCESS_KEY_ID" filename:.env.local',       "ark", "env"),
    ('"VOLCSTACK_ACCESS_KEY_ID" filename:config.py',        "ark", "config"),
    ('"VOLCSTACK_ACCESS_KEY_ID" language:python',           "ark", "code"),
    ('"VOLCSTACK_ACCESS_KEY_ID" language:go',               "ark", "code"),
    ('"VOLCSTACK_ACCESS_KEY_ID" language:java',             "ark", "code"),
    ('"VOLCSTACK_ACCESS_KEY_ID" path:.github/workflows',    "ark", "ci"),

    # Docker / CI
    ('"ARK_API_KEY" filename:docker-compose.yml',           "ark", "docker"),
    ('"VOLCENGINE_API_KEY" filename:docker-compose.yml',    "ark", "docker"),
    ('"ARK_API_KEY" path:.github/workflows',                "ark", "ci"),
    ('"DOUBAO_API_KEY" path:.github/workflows',             "ark", "ci"),

    # ═══════════════════════════════════════════════════════════════════════
    # HAPPY HORSE / RUNHAPPYHORSE / LIMEAI  (AI video gen — i2v / t2v)
    # ═══════════════════════════════════════════════════════════════════════

    # .env — primary key names
    ('"HAPPY_HORSE_API_KEY" filename:.env',               "happyhorse", "env"),
    ('"HH_API_KEY" filename:.env',                        "happyhorse", "env"),
    ('"HAPPYHORSE_API_KEY" filename:.env',                "happyhorse", "env"),
    ('"RUNHAPPYHORSE_API_KEY" filename:.env',             "happyhorse", "env"),
    ('"LIMEAI_API_KEY" filename:.env',                    "happyhorse", "env"),
    ('"LIME_AI_KEY" filename:.env',                       "happyhorse", "env"),
    ('"RUNHAPPYHORSE" filename:.env',                     "happyhorse", "env"),
    ('"happyhorse" "api_key" filename:.env',              "happyhorse", "env"),
    ('"limeai" "api_key" filename:.env',                  "happyhorse", "env"),

    # .env — Alibaba video gen (wan-video / i2v) context alongside HH key
    ('"happyhorse" "alibaba" filename:.env',              "happyhorse", "env"),
    ('"HH_API_KEY" "ALIBABA" filename:.env',              "happyhorse", "env"),
    ('"wan-video" "api_key" filename:.env',               "happyhorse", "env"),
    ('"image_to_video" "HH_API_KEY" filename:.env',       "happyhorse", "env"),

    # Config files
    ('"runhappyhorse.net" "api_key" filename:config.py',  "happyhorse", "config"),
    ('"runhappyhorse.net" "api_key" filename:config.ts',  "happyhorse", "config"),
    ('"limeai.top" "api_key" filename:config.py',         "happyhorse", "config"),
    ('"happyhorse" "api_key" filename:video_config.py',   "happyhorse", "config"),
    ('"happyhorse" "api_key" filename:config.yaml',       "happyhorse", "config"),

    # Code — HH domain, multi-language
    ('"runhappyhorse.net" language:python',               "happyhorse", "code"),
    ('"runhappyhorse.net" language:javascript',           "happyhorse", "code"),
    ('"runhappyhorse.net" language:typescript',           "happyhorse", "code"),
    ('"runhappyhorse.net" language:go',                   "happyhorse", "code"),
    ('"runhappyhorse.net" language:java',                 "happyhorse", "code"),
    ('"runhappyhorse.net" language:rust',                 "happyhorse", "code"),
    ('"limeai.top" language:python',                      "happyhorse", "code"),
    ('"limeai.top" language:javascript',                  "happyhorse", "code"),
    ('"limeai.top" language:typescript',                  "happyhorse", "code"),

    # Code — env var names
    ('"HAPPY_HORSE_API_KEY" language:python',             "happyhorse", "code"),
    ('"HAPPY_HORSE_API_KEY" language:javascript',         "happyhorse", "code"),
    ('"HAPPY_HORSE_API_KEY" language:typescript',         "happyhorse", "code"),
    ('"HAPPY_HORSE_API_KEY" language:go',                 "happyhorse", "code"),
    ('"HH_API_KEY" language:python',                      "happyhorse", "code"),
    ('"HH_API_KEY" language:javascript',                  "happyhorse", "code"),
    ('"LIMEAI_API_KEY" language:python',                  "happyhorse", "code"),
    ('"LIMEAI_API_KEY" language:javascript',              "happyhorse", "code"),

    # Code — video generation actions
    ('"happyhorse" "image_to_video" language:python',     "happyhorse", "code"),
    ('"happyhorse" "text_to_video" language:python',      "happyhorse", "code"),
    ('"happyhorse" "video_generation" language:python',   "happyhorse", "code"),
    ('"happyhorse" "image_to_video" language:javascript', "happyhorse", "code"),
    ('"limeai" "image_to_video" language:python',         "happyhorse", "code"),
    ('"limeai" "text_to_video" language:python',          "happyhorse", "code"),

    # Notebooks
    ('"HAPPY_HORSE_API_KEY" extension:ipynb',             "happyhorse", "notebook"),
    ('"runhappyhorse" extension:ipynb',                   "happyhorse", "notebook"),
    ('"limeai" extension:ipynb',                          "happyhorse", "notebook"),

    # CI/CD
    ('"HAPPY_HORSE_API_KEY" path:.github/workflows',      "happyhorse", "ci"),
    ('"HH_API_KEY" path:.github/workflows',               "happyhorse", "ci"),
    ('"HAPPY_HORSE_API_KEY" filename:docker-compose.yml', "happyhorse", "docker"),

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

    # ═══════════════════════════════════════════════════════════════════════
    # REPLICATE  (r8_ prefix — high precision)
    # ═══════════════════════════════════════════════════════════════════════

    ('"REPLICATE_API_TOKEN" filename:.env',               "replicate", "env"),
    ('"REPLICATE_API_TOKEN" filename:.env.local',         "replicate", "env"),
    ('"REPLICATE_API_TOKEN" filename:.env.production',    "replicate", "env"),
    ('"REPLICATE_API_KEY" filename:.env',                 "replicate", "env"),
    ('"REPLICATE_API_TOKEN" filename:.env.example "r8_"', "replicate", "env"),
    ('"r8_" "REPLICATE_API_TOKEN" filename:.env',         "replicate", "env"),

    ('"REPLICATE_API_TOKEN" language:python',             "replicate", "code"),
    ('"REPLICATE_API_TOKEN" language:javascript',         "replicate", "code"),
    ('"REPLICATE_API_TOKEN" language:typescript',         "replicate", "code"),
    ('"REPLICATE_API_TOKEN" language:go',                 "replicate", "code"),
    ('"REPLICATE_API_TOKEN" language:java',               "replicate", "code"),
    ('"REPLICATE_API_TOKEN" language:rust',               "replicate", "code"),
    ('"replicate.com/run" language:python',               "replicate", "code"),
    ('"replicate.com/run" language:javascript',           "replicate", "code"),
    ('"replicate.com/run" language:typescript',           "replicate", "code"),

    ('"REPLICATE_API_TOKEN" extension:ipynb',             "replicate", "notebook"),
    ('"r8_" extension:ipynb',                             "replicate", "notebook"),
    ('"REPLICATE_API_TOKEN" filename:config.py',          "replicate", "config"),
    ('"REPLICATE_API_TOKEN" filename:config.ts',          "replicate", "config"),
    ('"REPLICATE_API_TOKEN" path:.github/workflows',      "replicate", "ci"),
    ('"REPLICATE_API_TOKEN" filename:docker-compose.yml', "replicate", "docker"),

    # ═══════════════════════════════════════════════════════════════════════
    # FAL.AI  (hex key_id:key_secret format)
    # ═══════════════════════════════════════════════════════════════════════

    ('"FAL_KEY" filename:.env',                           "fal", "env"),
    ('"FAL_API_KEY" filename:.env',                       "fal", "env"),
    ('"FAL_SECRET_KEY" filename:.env',                    "fal", "env"),
    ('"FAL_KEY" filename:.env.local',                     "fal", "env"),
    ('"FAL_KEY" filename:.env.production',                "fal", "env"),
    ('"fal.ai" "FAL_KEY"',                                "fal", "env"),

    ('"FAL_KEY" language:python',                         "fal", "code"),
    ('"FAL_KEY" language:javascript',                     "fal", "code"),
    ('"FAL_KEY" language:typescript',                     "fal", "code"),
    ('"FAL_KEY" language:go',                             "fal", "code"),
    ('"FAL_API_KEY" language:python',                     "fal", "code"),
    ('"FAL_API_KEY" language:javascript',                 "fal", "code"),
    ('"fal.run" language:python',                         "fal", "code"),
    ('"fal.run" language:javascript',                     "fal", "code"),
    ('"fal.run" language:typescript',                     "fal", "code"),
    ('"api.fal.ai" language:python',                      "fal", "code"),
    ('"api.fal.ai" language:javascript',                  "fal", "code"),
    ('"api.fal.ai" language:typescript',                  "fal", "code"),

    ('"FAL_KEY" extension:ipynb',                         "fal", "notebook"),
    ('"fal" "image_to_video" extension:ipynb',            "fal", "notebook"),
    ('"FAL_KEY" filename:config.py',                      "fal", "config"),
    ('"FAL_KEY" filename:config.ts',                      "fal", "config"),
    ('"FAL_KEY" path:.github/workflows',                  "fal", "ci"),
    ('"FAL_KEY" filename:docker-compose.yml',             "fal", "docker"),

    # ═══════════════════════════════════════════════════════════════════════
    # HUGGINGFACE  (hf_ prefix — high density, unique, low false-positive)
    # ═══════════════════════════════════════════════════════════════════════

    ('"HF_TOKEN" "hf_" filename:.env',                   "huggingface", "env"),
    ('"HUGGINGFACE_TOKEN" filename:.env',                 "huggingface", "env"),
    ('"HUGGING_FACE_HUB_TOKEN" filename:.env',            "huggingface", "env"),
    ('"HF_API_TOKEN" filename:.env',                      "huggingface", "env"),
    ('"HF_TOKEN" filename:.env.local',                    "huggingface", "env"),
    ('"HF_TOKEN" filename:.env.production',               "huggingface", "env"),
    ('"HF_TOKEN" filename:.env.example "hf_"',            "huggingface", "env"),

    ('"HF_TOKEN" language:python',                        "huggingface", "code"),
    ('"HF_TOKEN" language:javascript',                    "huggingface", "code"),
    ('"HF_TOKEN" language:typescript',                    "huggingface", "code"),
    ('"HF_TOKEN" language:go',                            "huggingface", "code"),
    ('"HF_TOKEN" language:java',                          "huggingface", "code"),
    ('"HUGGING_FACE_HUB_TOKEN" language:python',          "huggingface", "code"),
    ('"HUGGING_FACE_HUB_TOKEN" language:javascript',      "huggingface", "code"),
    ('"HUGGINGFACE_TOKEN" language:python',               "huggingface", "code"),
    ('"HUGGINGFACE_TOKEN" language:typescript',           "huggingface", "code"),
    ('"hf_" "huggingface_hub" language:python',           "huggingface", "code"),
    ('"hf_" "transformers" language:python',              "huggingface", "code"),
    ('"hf_" "pipeline" language:python',                  "huggingface", "code"),
    ('"HF_TOKEN" extension:ipynb',                        "huggingface", "notebook"),
    ('"HUGGING_FACE_HUB_TOKEN" extension:ipynb',          "huggingface", "notebook"),
    ('"hf_" "InferenceClient" extension:ipynb',           "huggingface", "notebook"),
    ('"HF_TOKEN" filename:config.py',                     "huggingface", "config"),
    ('"HF_TOKEN" filename:config.ts',                     "huggingface", "config"),
    ('"HF_TOKEN" filename:docker-compose.yml',            "huggingface", "docker"),
    ('"HF_TOKEN" path:.github/workflows',                 "huggingface", "ci"),
    ('"HUGGING_FACE_HUB_TOKEN" path:.github/workflows',   "huggingface", "ci"),

    # ═══════════════════════════════════════════════════════════════════════
    # TOGETHER AI  (64-char hex — context-only, moderate density)
    # ═══════════════════════════════════════════════════════════════════════



    # ═══════════════════════════════════════════════════════════════════════
    # PERPLEXITY AI  (pplx- prefix — unique, moderate density)
    # ═══════════════════════════════════════════════════════════════════════

    ('"PERPLEXITY_API_KEY" filename:.env',                "perplexity", "env"),
    ('"PPLX_API_KEY" filename:.env',                      "perplexity", "env"),
    ('"PPLX_KEY" filename:.env',                          "perplexity", "env"),
    ('"PERPLEXITY_API_KEY" filename:.env.local',          "perplexity", "env"),
    ('"pplx-" filename:.env',                             "perplexity", "env"),

    ('"PERPLEXITY_API_KEY" language:python',              "perplexity", "code"),
    ('"PERPLEXITY_API_KEY" language:javascript',          "perplexity", "code"),
    ('"PERPLEXITY_API_KEY" language:typescript',          "perplexity", "code"),
    ('"api.perplexity.ai" language:python',               "perplexity", "code"),
    ('"api.perplexity.ai" language:javascript',           "perplexity", "code"),
    ('"api.perplexity.ai" language:typescript',           "perplexity", "code"),
    ('"pplx-" "perplexity" language:python',              "perplexity", "code"),
    ('"PERPLEXITY_API_KEY" extension:ipynb',              "perplexity", "notebook"),
    ('"pplx-" extension:ipynb',                           "perplexity", "notebook"),
    ('"PERPLEXITY_API_KEY" filename:config.py',           "perplexity", "config"),
    ('"PERPLEXITY_API_KEY" path:.github/workflows',       "perplexity", "ci"),

    # ═══════════════════════════════════════════════════════════════════════
    # RUNWAY ML  (context-only — RUNWAYML_API_SECRET, no unique key prefix)
    # ═══════════════════════════════════════════════════════════════════════

    ('"RUNWAYML_API_SECRET" filename:.env',               "runway", "env"),
    ('"RUNWAY_API_KEY" filename:.env',                    "runway", "env"),
    ('"RUNWAY_API_SECRET" filename:.env',                 "runway", "env"),
    ('"RUNWAY_TOKEN" filename:.env',                      "runway", "env"),
    ('"RUNWAYML_API_SECRET" filename:.env.local',         "runway", "env"),

    ('"RUNWAYML_API_SECRET" language:python',             "runway", "code"),
    ('"RUNWAYML_API_SECRET" language:javascript',         "runway", "code"),
    ('"RUNWAYML_API_SECRET" language:typescript',         "runway", "code"),
    ('"api.dev.runwayml.com" language:python',            "runway", "code"),
    ('"api.dev.runwayml.com" language:javascript',        "runway", "code"),
    ('"api.dev.runwayml.com" language:typescript',        "runway", "code"),
    ('"runwayml" "gen-3" language:python',                "runway", "code"),
    ('"runwayml" "gen-3" language:javascript',            "runway", "code"),
    ('"RUNWAYML_API_SECRET" extension:ipynb',             "runway", "notebook"),
    ('"RUNWAYML_API_SECRET" filename:config.py',          "runway", "config"),
    ('"RUNWAYML_API_SECRET" filename:docker-compose.yml', "runway", "docker"),
    ('"RUNWAYML_API_SECRET" path:.github/workflows',      "runway", "ci"),

    # ═══════════════════════════════════════════════════════════════════════
    # KIMI / MOONSHOT AI  (sk- prefix, context-only)
    # ═══════════════════════════════════════════════════════════════════════

    ('"MOONSHOT_API_KEY" filename:.env',                  "kimi", "env"),
    ('"KIMI_API_KEY" filename:.env',                      "kimi", "env"),
    ('"MOONSHOT_API_KEY" filename:.env.local',            "kimi", "env"),
    ('"moonshot" "sk-" filename:.env',                    "kimi", "env"),

    ('"MOONSHOT_API_KEY" language:python',                "kimi", "code"),
    ('"MOONSHOT_API_KEY" language:javascript',            "kimi", "code"),
    ('"MOONSHOT_API_KEY" language:typescript',            "kimi", "code"),
    ('"MOONSHOT_API_KEY" language:go',                    "kimi", "code"),
    ('"MOONSHOT_API_KEY" language:java',                  "kimi", "code"),
    ('"api.moonshot.cn" language:python',                 "kimi", "code"),
    ('"api.moonshot.cn" language:javascript',             "kimi", "code"),
    ('"api.moonshot.cn" language:typescript',             "kimi", "code"),
    ('"api.moonshot.cn" language:go',                     "kimi", "code"),
    ('"api.moonshot.ai" language:python',                 "kimi", "code"),
    ('"api.moonshot.ai" language:javascript',             "kimi", "code"),
    ('"moonshot-v1" language:python',                     "kimi", "code"),
    ('"moonshot-v1" language:javascript',                 "kimi", "code"),
    ('"MOONSHOT_API_KEY" extension:ipynb',                "kimi", "notebook"),
    ('"moonshot" "sk-" extension:ipynb',                  "kimi", "notebook"),
    ('"MOONSHOT_API_KEY" filename:config.py',             "kimi", "config"),
    ('"MOONSHOT_API_KEY" filename:config.ts',             "kimi", "config"),
    ('"MOONSHOT_API_KEY" filename:docker-compose.yml',    "kimi", "docker"),
    ('"MOONSHOT_API_KEY" path:.github/workflows',         "kimi", "ci"),

    # ═══════════════════════════════════════════════════════════════════════
    # GLM / ZHIPU AI / ChatGLM  (unique hex32.base62_16 key format)
    # ═══════════════════════════════════════════════════════════════════════

    ('"ZHIPUAI_API_KEY" filename:.env',                   "glm", "env"),
    ('"ZHIPU_API_KEY" filename:.env',                     "glm", "env"),
    ('"GLM_API_KEY" filename:.env',                       "glm", "env"),
    ('"ZHIPUAI_API_KEY" filename:.env.local',             "glm", "env"),
    ('"zhipuai" "api_key" filename:.env',                 "glm", "env"),

    ('"ZHIPUAI_API_KEY" language:python',                 "glm", "code"),
    ('"ZHIPUAI_API_KEY" language:javascript',             "glm", "code"),
    ('"ZHIPUAI_API_KEY" language:typescript',             "glm", "code"),
    ('"ZHIPUAI_API_KEY" language:go',                     "glm", "code"),
    ('"ZHIPUAI_API_KEY" language:java',                   "glm", "code"),
    ('"open.bigmodel.cn" language:python',                "glm", "code"),
    ('"open.bigmodel.cn" language:javascript',            "glm", "code"),
    ('"open.bigmodel.cn" language:typescript',            "glm", "code"),
    ('"open.bigmodel.cn" language:go',                    "glm", "code"),
    ('"zhipuai" "api_key" language:python',               "glm", "code"),
    ('"zhipuai" "api_key" language:javascript',           "glm", "code"),
    ('"glm-4" "api_key" language:python',                 "glm", "code"),
    ('"chatglm" "api_key" language:python',               "glm", "code"),
    ('"ZHIPUAI_API_KEY" extension:ipynb',                 "glm", "notebook"),
    ('"zhipuai" extension:ipynb',                         "glm", "notebook"),
    ('"ZHIPUAI_API_KEY" filename:config.py',              "glm", "config"),
    ('"ZHIPUAI_API_KEY" filename:docker-compose.yml',     "glm", "docker"),
    ('"ZHIPUAI_API_KEY" path:.github/workflows',          "glm", "ci"),

    # ═══════════════════════════════════════════════════════════════════════
    # KLING / KUAISHOU AI  (AccessKey+SecretKey pair → JWT)
    # ═══════════════════════════════════════════════════════════════════════

    ('"KLING_ACCESS_KEY" filename:.env',                  "kling", "env"),
    ('"KLING_SECRET_KEY" filename:.env',                  "kling", "env"),
    ('"KLING_AK" filename:.env',                          "kling", "env"),
    ('"KLING_SK" filename:.env',                          "kling", "env"),
    ('"KLING_ACCESS_KEY" "KLING_SECRET_KEY"',             "kling", "env"),

    ('"KLING_ACCESS_KEY" language:python',                "kling", "code"),
    ('"KLING_ACCESS_KEY" language:javascript',            "kling", "code"),
    ('"KLING_ACCESS_KEY" language:typescript',            "kling", "code"),
    ('"KLING_ACCESS_KEY" language:go',                    "kling", "code"),
    ('"api.klingai.com" language:python',                 "kling", "code"),
    ('"api.klingai.com" language:javascript',             "kling", "code"),
    ('"api.klingai.com" language:typescript',             "kling", "code"),
    ('"klingai" "access_key" language:python',            "kling", "code"),
    ('"klingai" "secret_key" language:python',            "kling", "code"),
    ('"KLING_ACCESS_KEY" extension:ipynb',                "kling", "notebook"),
    ('"api.klingai.com" extension:ipynb',                 "kling", "notebook"),
    ('"KLING_ACCESS_KEY" filename:config.py',             "kling", "config"),
    ('"KLING_ACCESS_KEY" filename:config.ts',             "kling", "config"),
    ('"KLING_ACCESS_KEY" filename:docker-compose.yml',    "kling", "docker"),
    ('"KLING_ACCESS_KEY" path:.github/workflows',         "kling", "ci"),

    # ═══════════════════════════════════════════════════════════════════════
    # GROQ AI  (gsk_ prefix — unique, high validity, NOT in secret scanning)
    # ═══════════════════════════════════════════════════════════════════════




    # ═══════════════════════════════════════════════════════════════════════
    # FIREWORKS AI  (fw_ prefix — NOT in secret scanning)
    # ═══════════════════════════════════════════════════════════════════════

    ('"FIREWORKS_API_KEY" filename:.env',                   "fireworks", "env"),
    ('"FIREWORKS_AI_API_KEY" filename:.env',                "fireworks", "env"),
    ('"FIREWORKS_API_KEY" filename:.env.local',             "fireworks", "env"),
    ('"FIREWORKS_API_KEY" filename:.env.production',        "fireworks", "env"),

    ('"FIREWORKS_API_KEY" language:python',                 "fireworks", "code"),
    ('"FIREWORKS_API_KEY" language:javascript',             "fireworks", "code"),
    ('"FIREWORKS_API_KEY" language:typescript',             "fireworks", "code"),
    ('"FIREWORKS_API_KEY" language:go',                     "fireworks", "code"),
    ('"api.fireworks.ai" language:python',                  "fireworks", "code"),
    ('"api.fireworks.ai" language:javascript',              "fireworks", "code"),
    ('"api.fireworks.ai" language:typescript',              "fireworks", "code"),

    ('"FIREWORKS_API_KEY" extension:ipynb',                 "fireworks", "notebook"),
    ('"fireworks" "fw_" extension:ipynb',                   "fireworks", "notebook"),
    ('"FIREWORKS_API_KEY" filename:config.py',              "fireworks", "config"),
    ('"FIREWORKS_API_KEY" filename:config.ts',              "fireworks", "config"),
    ('"FIREWORKS_API_KEY" filename:docker-compose.yml',     "fireworks", "docker"),
    ('"FIREWORKS_API_KEY" path:.github/workflows',          "fireworks", "ci"),

    # ═══════════════════════════════════════════════════════════════════════
    # OPENROUTER  (sk-or-v1- prefix — extremely distinctive, NOT in scanning)
    # ═══════════════════════════════════════════════════════════════════════

    ('"OPENROUTER_API_KEY" filename:.env',                  "openrouter", "env"),
    ('"OR_API_KEY" filename:.env',                          "openrouter", "env"),
    ('"OPENROUTER_API_KEY" filename:.env.local',            "openrouter", "env"),
    ('"OPENROUTER_API_KEY" filename:.env.production',       "openrouter", "env"),
    ('"sk-or-v1-" filename:.env',                           "openrouter", "env"),

    ('"OPENROUTER_API_KEY" language:python',                "openrouter", "code"),
    ('"OPENROUTER_API_KEY" language:javascript',            "openrouter", "code"),
    ('"OPENROUTER_API_KEY" language:typescript',            "openrouter", "code"),
    ('"OPENROUTER_API_KEY" language:go',                    "openrouter", "code"),
    ('"openrouter.ai" "sk-or" language:python',             "openrouter", "code"),
    ('"openrouter.ai" "sk-or" language:javascript',         "openrouter", "code"),
    ('"openrouter.ai" "sk-or" language:typescript',         "openrouter", "code"),
    ('"openrouter.ai/api" language:python',                 "openrouter", "code"),
    ('"openrouter.ai/api" language:javascript',             "openrouter", "code"),

    ('"OPENROUTER_API_KEY" extension:ipynb',                "openrouter", "notebook"),
    ('"sk-or-v1-" extension:ipynb',                         "openrouter", "notebook"),
    ('"OPENROUTER_API_KEY" filename:config.py',             "openrouter", "config"),
    ('"OPENROUTER_API_KEY" filename:config.ts',             "openrouter", "config"),
    ('"OPENROUTER_API_KEY" filename:docker-compose.yml',    "openrouter", "docker"),
    ('"OPENROUTER_API_KEY" path:.github/workflows',         "openrouter", "ci"),

    # ═══════════════════════════════════════════════════════════════════════
    # MISTRAL AI  (context-only — MISTRAL_API_KEY, no unique prefix)
    # ═══════════════════════════════════════════════════════════════════════




    # ═══════════════════════════════════════════════════════════════════════
    # COHERE  (context-only — COHERE_API_KEY, no unique prefix)
    # ═══════════════════════════════════════════════════════════════════════




    # ═══════════════════════════════════════════════════════════════════════
    # BLANKET (no language filter) — unique prefixes, near-zero false positives
    # Catches Rust, C++, Dart, Swift, Scala, Shell, HCL, Lua, Elixir, etc.
    # ═══════════════════════════════════════════════════════════════════════

    # Groq  (gsk_ is globally unique to Groq)

    # OpenRouter  (sk-or-v1- is the most unique prefix in the ecosystem)
    ('"sk-or-v1-"',                                         "openrouter",  "code"),
    ('"sk-or-v1-" extension:env',                           "openrouter",  "env"),
    ('"OPENROUTER_API_KEY" extension:env',                  "openrouter",  "env"),
    ('"OPENROUTER_API_KEY" extension:yaml',                 "openrouter",  "yaml"),

    # Fireworks  (fw_ needs context to avoid noise)
    ('"fw_" "fireworks"',                                   "fireworks",   "code"),
    ('"fw_" "FIREWORKS_API_KEY"',                           "fireworks",   "env"),
    ('"FIREWORKS_API_KEY" extension:env',                   "fireworks",   "env"),
    ('"FIREWORKS_API_KEY" extension:yaml',                  "fireworks",   "yaml"),
    ('"FIREWORKS_API_KEY" extension:toml',                  "fireworks",   "code"),

    # Perplexity  (pplx- is unique)
    ('"pplx-"',                                             "perplexity",  "code"),
    ('"pplx-" extension:env',                               "perplexity",  "env"),
    ('"PERPLEXITY_API_KEY" extension:env',                  "perplexity",  "env"),
    ('"PERPLEXITY_API_KEY" extension:yaml',                 "perplexity",  "yaml"),

    # Replicate  (r8_ is unique)
    ('"r8_"',                                               "replicate",   "code"),
    ('"r8_" extension:env',                                 "replicate",   "env"),
    ('"REPLICATE_API_TOKEN" extension:env',                 "replicate",   "env"),
    ('"REPLICATE_API_TOKEN" extension:yaml',                "replicate",   "yaml"),
    ('"REPLICATE_API_TOKEN" extension:toml',                "replicate",   "code"),

    # HuggingFace  (hf_ well-known prefix)
    ('"hf_" extension:env',                                 "huggingface", "env"),
    ('"HF_TOKEN" extension:env',                            "huggingface", "env"),
    ('"HF_TOKEN" extension:yaml',                           "huggingface", "yaml"),
    ('"HF_TOKEN" extension:toml',                           "huggingface", "code"),
    ('"HUGGING_FACE_HUB_TOKEN" extension:env',              "huggingface", "env"),

    # Grok / xAI  (xai- is unique)
    ('"xai-"',                                              "grok",        "code"),
    ('"xai-" extension:env',                                "grok",        "env"),
    ('"XAI_API_KEY" extension:env',                         "grok",        "env"),
    ('"XAI_API_KEY" extension:yaml',                        "grok",        "yaml"),
    ('"XAI_API_KEY" extension:toml',                        "grok",        "code"),

    # ─── extension:env / yaml / toml blanket for remaining providers ──────
    ('"sk-proj-" extension:env',                            "openai",      "env"),
    ('"sk-proj-" extension:yaml',                           "openai",      "yaml"),
    ('"OPENAI_API_KEY" extension:toml',                     "openai",      "code"),
    ('"sk-ant-api03-" extension:env',                       "anthropic",   "env"),
    ('"ANTHROPIC_API_KEY" extension:yaml',                  "anthropic",   "yaml"),
    ('"ANTHROPIC_API_KEY" extension:toml',                  "anthropic",   "code"),
    ('"AIzaSy" extension:env',                              "google",      "env"),
    ('"GEMINI_API_KEY" extension:yaml',                     "google",      "yaml"),
    ('"DEEPSEEK_API_KEY" extension:env',                    "deepseek",    "env"),
    ('"DEEPSEEK_API_KEY" extension:yaml',                   "deepseek",    "yaml"),

    # ═══════════════════════════════════════════════════════════════════════
    # CEREBRAS  (csk- unique prefix — ultra-fast inference, NOT in secret scanning)
    # ═══════════════════════════════════════════════════════════════════════

    ('"csk-" filename:.env',                                "cerebras",    "env"),
    ('"CEREBRAS_API_KEY" filename:.env',                    "cerebras",    "env"),
    ('"CEREBRAS_API_KEY" filename:.env.local',              "cerebras",    "env"),
    ('"csk-" filename:.env.local',                          "cerebras",    "env"),
    ('"csk-" extension:env',                                "cerebras",    "env"),
    ('"CEREBRAS_API_KEY" extension:env',                    "cerebras",    "env"),
    ('"csk-" language:python',                              "cerebras",    "code"),
    ('"csk-" language:javascript',                          "cerebras",    "code"),
    ('"csk-" language:typescript',                          "cerebras",    "code"),
    ('"csk-" language:go',                                  "cerebras",    "code"),
    ('"csk-" language:Shell',                               "cerebras",    "code"),
    ('"csk-"',                                              "cerebras",    "code"),
    ('"CEREBRAS_API_KEY" language:python',                  "cerebras",    "code"),
    ('"CEREBRAS_API_KEY" language:javascript',              "cerebras",    "code"),
    ('"api.cerebras.ai" language:python',                   "cerebras",    "code"),
    ('"api.cerebras.ai" language:javascript',               "cerebras",    "code"),
    ('"csk-" extension:ipynb',                              "cerebras",    "notebook"),
    ('"CEREBRAS_API_KEY" extension:ipynb',                  "cerebras",    "notebook"),
    ('"CEREBRAS_API_KEY" filename:config.py',               "cerebras",    "config"),
    ('"CEREBRAS_API_KEY" filename:docker-compose.yml',      "cerebras",    "docker"),
    ('"CEREBRAS_API_KEY" path:.github/workflows',           "cerebras",    "ci"),

    # ═══════════════════════════════════════════════════════════════════════
    # SHELL SCRIPTS  (language:Shell — ops automation, CI pipelines, deploy scripts)
    # DevOps engineers hardcode keys in bash/sh for quick automation; these files
    # are almost never flagged by IDE secret scanners.
    # ═══════════════════════════════════════════════════════════════════════

    ('"OPENAI_API_KEY" "sk-" language:Shell',               "openai",      "code"),
    ('"sk-proj-" language:Shell',                           "openai",      "code"),
    ('"sk-ant-api03-" language:Shell',                      "anthropic",   "code"),
    ('"ANTHROPIC_API_KEY" "sk-ant-" language:Shell',        "anthropic",   "code"),
    ('"AIzaSy" language:Shell',                             "google",      "code"),
    ('"GOOGLE_API_KEY" "AIzaSy" language:Shell',            "google",      "code"),
    ('"DEEPSEEK_API_KEY" language:Shell',                   "deepseek",    "code"),
    ('"ARK_API_KEY" language:Shell',                        "ark",         "code"),
    ('"DOUBAO_API_KEY" language:Shell',                     "ark",         "code"),
    ('"HF_TOKEN" language:Shell',                           "huggingface", "code"),
    ('"hf_" "HF_TOKEN" language:Shell',                     "huggingface", "code"),
    ('"xai-" language:Shell',                               "grok",        "code"),
    ('"XAI_API_KEY" language:Shell',                        "grok",        "code"),
    ('"fw_" "FIREWORKS" language:Shell',                    "fireworks",   "code"),
    ('"FIREWORKS_API_KEY" language:Shell',                  "fireworks",   "code"),
    ('"sk-or-v1-" language:Shell',                          "openrouter",  "code"),
    ('"OPENROUTER_API_KEY" language:Shell',                 "openrouter",  "code"),
    ('"REPLICATE_API_TOKEN" language:Shell',                "replicate",   "code"),
    ('"MOONSHOT_API_KEY" language:Shell',                   "kimi",        "code"),
    ('"ZHIPUAI_API_KEY" language:Shell',                    "glm",         "code"),
    ('"pplx-" language:Shell',                              "perplexity",  "code"),
    ('"PERPLEXITY_API_KEY" language:Shell',                 "perplexity",  "code"),

    # ═══════════════════════════════════════════════════════════════════════
    # AIMLAPI — aggregator (Claude / Gemini / GPT / GPT Image / Nano Banana)
    # ═══════════════════════════════════════════════════════════════════════
    ('"AIMLAPI_API_KEY" language:python',                   "aimlapi",     "code"),
    ('"AIML_API_KEY" language:python',                      "aimlapi",     "code"),
    ('"AIMLAPI_KEY" language:python',                       "aimlapi",     "code"),
    ('"api.aimlapi.com" language:python',                   "aimlapi",     "code"),
    ('"AIMLAPI_API_KEY" language:javascript',               "aimlapi",     "code"),
    ('"AIML_API_KEY" language:javascript',                  "aimlapi",     "code"),
    ('"api.aimlapi.com" language:javascript',               "aimlapi",     "code"),
    ('"AIMLAPI_API_KEY" language:typescript',               "aimlapi",     "code"),
    ('"AIMLAPI_API_KEY" filename:.env',                     "aimlapi",     "env"),
    ('"AIML_API_KEY" filename:.env',                        "aimlapi",     "env"),
    ('"aimlapi" filename:.env.example',                     "aimlapi",     "env"),
    ('"AIMLAPI_API_KEY" extension:ipynb',                   "aimlapi",     "notebook"),
    ('"aimlapi.com" extension:ipynb',                       "aimlapi",     "notebook"),

    # ═══════════════════════════════════════════════════════════════════════
    # DeepInfra — aggregator (Claude / Gemini / Llama / GPT proxy)
    # ═══════════════════════════════════════════════════════════════════════
    ('"DEEPINFRA_API_KEY" language:python',                 "deepinfra",   "code"),
    ('"DEEPINFRA_TOKEN" language:python',                   "deepinfra",   "code"),
    ('"api.deepinfra.com" language:python',                 "deepinfra",   "code"),
    ('"DEEPINFRA_API_KEY" language:javascript',             "deepinfra",   "code"),
    ('"DEEPINFRA_TOKEN" language:javascript',               "deepinfra",   "code"),
    ('"api.deepinfra.com" language:javascript',             "deepinfra",   "code"),
    ('"DEEPINFRA_API_KEY" language:typescript',             "deepinfra",   "code"),
    ('"DEEPINFRA_API_KEY" filename:.env',                   "deepinfra",   "env"),
    ('"DEEPINFRA_TOKEN" filename:.env',                     "deepinfra",   "env"),
    ('"deepinfra" filename:.env.example',                   "deepinfra",   "env"),
    ('"DEEPINFRA_API_KEY" extension:ipynb',                 "deepinfra",   "notebook"),
    ('"deepinfra" extension:ipynb',                         "deepinfra",   "notebook"),
    ('"DEEPINFRA_API_KEY" filename:docker-compose.yml',     "deepinfra",   "code"),

    # ═══════════════════════════════════════════════════════════════════════
    # Hyperbolic — JWT-format keys, hot 2025-2026 startup
    # ═══════════════════════════════════════════════════════════════════════
    ('"HYPERBOLIC_API_KEY" language:python',                "hyperbolic",  "code"),
    ('"api.hyperbolic.xyz" language:python',                "hyperbolic",  "code"),
    ('"HYPERBOLIC_API_KEY" language:javascript',            "hyperbolic",  "code"),
    ('"api.hyperbolic.xyz" language:javascript',            "hyperbolic",  "code"),
    ('"HYPERBOLIC_API_KEY" language:typescript',            "hyperbolic",  "code"),
    ('"HYPERBOLIC_API_KEY" filename:.env',                  "hyperbolic",  "env"),
    ('"hyperbolic.xyz" filename:.env',                      "hyperbolic",  "env"),
    ('"hyperbolic" filename:.env.example',                  "hyperbolic",  "env"),
    ('"HYPERBOLIC_API_KEY" extension:ipynb',                "hyperbolic",  "notebook"),
    ('"api.hyperbolic.xyz" extension:ipynb',                "hyperbolic",  "notebook"),

    # ═══════════════════════════════════════════════════════════════════════
    # NovitaAI — Chinese aggregator (Stable Diffusion + GPT Image + Nano Banana)
    # ═══════════════════════════════════════════════════════════════════════
    ('"NOVITA_API_KEY" language:python',                    "novita",      "code"),
    ('"NOVITA_AI_API_KEY" language:python',                 "novita",      "code"),
    ('"api.novita.ai" language:python',                     "novita",      "code"),
    ('"NOVITA_API_KEY" language:javascript',                "novita",      "code"),
    ('"api.novita.ai" language:javascript',                 "novita",      "code"),
    ('"NOVITA_API_KEY" language:typescript',                "novita",      "code"),
    ('"NOVITA_API_KEY" filename:.env',                      "novita",      "env"),
    ('"NOVITA_AI_API_KEY" filename:.env',                   "novita",      "env"),
    ('"novita.ai" filename:.env.example',                   "novita",      "env"),
    ('"NOVITA_API_KEY" extension:ipynb',                    "novita",      "notebook"),
    ('"novita.ai" extension:ipynb',                         "novita",      "notebook"),
]


# ── Gitee-optimised queries ───────────────────────────────────────────────────
# Gitee search API uses simple keyword/phrase search — no filename:/language:
# operators. Language filter is passed separately as &language= API param.
# Format: (query_str, provider, file_type)
# Focused on Chinese AI ecosystem (GLM, Kimi, KLING, DeepSeek, ARK) +
# universal providers common in Chinese dev repos.
GITEE_QUERIES: list[tuple[str, str, str]] = [

    # ── OpenAI ────────────────────────────────────────────────────────────
    ('"OPENAI_API_KEY" "sk-"',                            "openai",      "env"),
    ('"sk-proj-"',                                        "openai",      "code"),
    ('"OPENAI_API_KEY=sk-"',                              "openai",      "code"),
    ('"openai" "sk-proj-"',                               "openai",      "code"),

    # ── Anthropic ─────────────────────────────────────────────────────────
    ('"sk-ant-api03-"',                                   "anthropic",   "code"),
    ('"ANTHROPIC_API_KEY" "sk-ant-"',                     "anthropic",   "env"),

    # ── Google / Gemini ───────────────────────────────────────────────────
    ('"GEMINI_API_KEY" "AIzaSy"',                         "google",      "env"),
    ('"GOOGLE_API_KEY" "AIzaSy"',                         "google",      "env"),
    ('"generativelanguage.googleapis.com" "AIzaSy"',      "google",      "code"),

    # ── DeepSeek ──────────────────────────────────────────────────────────
    ('"DEEPSEEK_API_KEY" "sk-"',                          "deepseek",    "env"),
    ('"api.deepseek.com" "sk-"',                          "deepseek",    "code"),
    ('"deepseek" "sk-"',                                  "deepseek",    "code"),

    # ── Kimi / Moonshot ── HIGH PRIORITY on Gitee ─────────────────────────
    ('"MOONSHOT_API_KEY"',                                "kimi",        "env"),
    ('"KIMI_API_KEY"',                                    "kimi",        "env"),
    ('"api.moonshot.cn"',                                 "kimi",        "code"),
    ('"api.moonshot.ai"',                                 "kimi",        "code"),
    ('"moonshot-v1"',                                     "kimi",        "code"),
    ('"moonshot" "sk-"',                                  "kimi",        "code"),
    ('"kimi" "api_key"',                                  "kimi",        "code"),

    # ── GLM / Zhipu AI ── HIGH PRIORITY on Gitee ──────────────────────────
    ('"ZHIPUAI_API_KEY"',                                 "glm",         "env"),
    ('"ZHIPU_API_KEY"',                                   "glm",         "env"),
    ('"GLM_API_KEY"',                                     "glm",         "env"),
    ('"open.bigmodel.cn"',                                "glm",         "code"),
    ('"zhipuai"',                                         "glm",         "code"),
    ('"glm-4"',                                           "glm",         "code"),
    ('"chatglm" "api_key"',                               "glm",         "code"),

    # ── KLING / Kuaishou ── HIGH PRIORITY on Gitee ────────────────────────
    ('"KLING_ACCESS_KEY"',                                "kling",       "env"),
    ('"KLING_SECRET_KEY"',                                "kling",       "env"),
    ('"api.klingai.com"',                                 "kling",       "code"),
    ('"klingai" "access_key"',                            "kling",       "code"),
    ('"kling" "secret_key"',                              "kling",       "code"),
    ('"KLING_AK" "KLING_SK"',                             "kling",       "env"),

    # ── ARK / Doubao / Volcengine ─────────────────────────────────────────
    ('"ARK_API_KEY"',                                     "ark",         "env"),
    ('"DOUBAO_API_KEY"',                                  "ark",         "env"),
    ('"VOLCENGINE_API_KEY"',                              "ark",         "env"),
    ('"VOLCSTACK_ACCESS_KEY_ID"',                         "ark",         "env"),
    ('"VOLCSTACK_SECRET_ACCESS_KEY"',                     "ark",         "env"),
    ('"ark.cn-beijing.volces.com"',                       "ark",         "code"),
    ('"doubao-seedance"',                                 "ark",         "code"),
    ('"doubao" "api_key"',                                "ark",         "code"),

    # ── HuggingFace ───────────────────────────────────────────────────────
    ('"HF_TOKEN" "hf_"',                                  "huggingface", "env"),
    ('"HUGGING_FACE_HUB_TOKEN"',                          "huggingface", "env"),
    ('"hf_" "transformers"',                              "huggingface", "code"),
    ('"hf_" "pipeline"',                                  "huggingface", "code"),

    # ── ElevenLabs ────────────────────────────────────────────────────────
    ('"ELEVENLABS_API_KEY"',                              "elevenlabs",  "env"),
    ('"XI_API_KEY"',                                      "elevenlabs",  "env"),
    ('"api.elevenlabs.io"',                               "elevenlabs",  "code"),

    # ── Grok / xAI ────────────────────────────────────────────────────────
    ('"XAI_API_KEY" "xai-"',                              "grok",        "env"),
    ('"api.x.ai"',                                        "grok",        "code"),

    # ── Together AI ───────────────────────────────────────────────────────

    # ── Replicate ─────────────────────────────────────────────────────────
    ('"REPLICATE_API_TOKEN" "r8_"',                       "replicate",   "env"),
    ('"r8_"',                                             "replicate",   "code"),

    # ── Runway ────────────────────────────────────────────────────────────
    ('"RUNWAYML_API_SECRET"',                             "runway",      "env"),
    ('"api.dev.runwayml.com"',                            "runway",      "code"),

    # ── Fal.ai ────────────────────────────────────────────────────────────
    ('"FAL_KEY"',                                         "fal",         "env"),
    ('"fal.run"',                                         "fal",         "code"),

    # ── Suno ──────────────────────────────────────────────────────────────
    ('"SUNO_API_KEY"',                                    "suno",        "env"),

    # ── Perplexity ────────────────────────────────────────────────────────
    ('"PERPLEXITY_API_KEY"',                              "perplexity",  "env"),
    ('"pplx-"',                                           "perplexity",  "code"),

    # ── Groq AI ─────────────────────────────────────────────────────────

    # ── Fireworks AI ────────────────────────────────────────────────────
    ('"FIREWORKS_API_KEY"',                               "fireworks",   "env"),
    ('"api.fireworks.ai"',                                "fireworks",   "code"),

    # ── OpenRouter ──────────────────────────────────────────────────────
    ('"OPENROUTER_API_KEY"',                              "openrouter",  "env"),
    ('"sk-or-v1-"',                                       "openrouter",  "code"),
    ('"openrouter.ai"',                                   "openrouter",  "code"),

    # ── Mistral AI ──────────────────────────────────────────────────────

    # ── Cohere ──────────────────────────────────────────────────────────
]
