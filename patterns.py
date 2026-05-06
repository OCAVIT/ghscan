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
            ctx = content[max(0, m.start() - 200): m.end() + 200]
            if _FAKE.search(ctx):
                continue
            # Exclude keys that have deepseek context nearby (provider overlap)
            if re.search(r'deepseek', ctx, re.IGNORECASE):
                continue
            # Stability AI uses `sk-[A-Za-z0-9]{48}` — exact same shape as legacy
            # OpenAI keys. Disambiguate via context: skip if stability hints around.
            if re.search(r'stability(?:\.ai|_api)?|STABILITY_API_KEY|api\.stability\.ai',
                         ctx, re.IGNORECASE):
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


# ── Higgsfield AI ─────────────────────────────────────────────────────────────
# AI video/image generator; v1 API uses Bearer token auth at platform.higgsfield.ai.
# No unique key prefix — keys are opaque tokens (32-128 chars, base64/hex/alnum).
# v2 SDK uses `key_id:key_secret` paired format (HF_KEY env), but v1 Bearer is
# what most leaked .env will carry. Also recognise the paired form near HF_KEY.
# Note: HF_ prefix collides with HuggingFace's HF_TOKEN convention, so we anchor
# on Higgsfield-specific markers (higgsfield, platform.higgsfield.ai, HIGGSFIELD_*).
_HIGGSFIELD_DIRECT = re.compile(
    # Direct env-style assignment — anchors on `=` or `:` separator so we don't
    # need a 200-char window and don't get greedy-matched to a tail substring.
    r'(?:HIGGSFIELD_API_KEY|HIGGSFIELD_KEY|HIGGSFIELD_TOKEN|HIGGSFIELD_SECRET)'
    r'\s*[=:]\s*["\']?'
    r'([A-Za-z0-9_\-]{32,128}(?::[A-Za-z0-9_\-]{16,128})?)',
    re.IGNORECASE,
)
_HIGGSFIELD_CTX = re.compile(
    # Lazy 0-200 window so the {32,128} group captures the FIRST 32-128 chars
    # after the marker, not a 32-char tail of a longer string.
    r'(?:HIGGSFIELD_API_KEY|HIGGSFIELD_KEY|HIGGSFIELD_TOKEN|HIGGSFIELD_SECRET'
    r'|higgsfield\.ai|platform\.higgsfield\.ai|cloud\.higgsfield\.ai)'
    r'[\s\S]{0,200}?'
    r'([A-Za-z0-9_\-]{32,128}(?::[A-Za-z0-9_\-]{16,128})?)',
    re.IGNORECASE,
)
_HIGGSFIELD_HFKEY = re.compile(
    # HF_KEY paired format (key_id:key_secret) — gated by higgsfield context
    # elsewhere in file (checked in extract_higgsfield()).
    r'(?:HF_KEY|HF_API_KEY)\s*[=:]\s*["\']?'
    r'([A-Za-z0-9_\-]{16,80}:[A-Za-z0-9_\-]{16,128})',
)


def extract_higgsfield(content: str) -> list[str]:
    if not re.search(r'(?i)higgsfield', content):
        return []
    found = []
    for m in _HIGGSFIELD_DIRECT.finditer(content):
        key = m.group(1)
        if not _FAKE.search(key):
            found.append(key)
    for m in _HIGGSFIELD_CTX.finditer(content):
        key = m.group(1)
        if key not in found and len(key) >= 32 and not _FAKE.search(key):
            found.append(key)
    for m in _HIGGSFIELD_HFKEY.finditer(content):
        key = m.group(1)
        if key not in found and not _FAKE.search(key):
            found.append(key)
    return list(dict.fromkeys(found))


# ── Happy Horse / RunHappyHorse / LimeAI ─────────────────────────────────────
# AI video generation service (image-to-video / text-to-video).
# Also exposed under limeai.top domain. Alibaba wan-video / i2v context.
#
# 2026-05-05: tightened after false-positive audit revealed honeyhiveai/* repos
# triggering matches via 'HH_API_KEY' (too short prefix — collides with
# section headers like "HH/INTEGRATION_CHECKLIST" in issue bodies) and
# 'happy_horse_key' (generic English words). 300-char window also too wide
# for issue-body content. Now requires env-style assignment immediately after
# trigger, with only 60-char gap.
_HH_CTX = re.compile(
    r'(?:HAPPY_HORSE_API_KEY|RUNHAPPYHORSE_API_KEY|HAPPYHORSE_API_KEY'
    r'|LIMEAI_API_KEY|LIME_AI_KEY'
    r'|runhappyhorse\.net|happyhorse\.ai|limeai\.top|lime-ai\.com)'
    r'[\s\S]{0,60}?'                    # tightened from 300 to 60, non-greedy
    r'[=:]\s*["\']?'                    # MUST have =/: separator (env-var style)
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
# Keys have a unique "r8_" prefix + 35-55 alnum chars (varies — observed 37 chars
# in iafactory leak 2026-05). Lower bound was 38 (too tight) → widened to 35.
_REPLICATE_RE = re.compile(r'(?<![A-Za-z0-9_\-])(r8_[A-Za-z0-9]{35,55})(?![A-Za-z0-9])')
_REPLICATE_CTX = re.compile(
    r'(?:REPLICATE_API_TOKEN|REPLICATE_API_KEY|REPLICATE_TOKEN|replicate\.com)'
    r'[\s\S]{0,200}'
    r'(r8_[A-Za-z0-9]{35,55})',
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


# ── Stability AI (image gen — SD/SDXL/SD3) ────────────────────────────────────
# Format: `sk-[A-Za-z0-9]{48}` — IDENTICAL shape to legacy OpenAI account keys.
# Disambiguation: REQUIRE stability context anywhere in the file. The OpenAI
# extractor was patched to skip matches whose 200-char context contains
# stability hints, so there's no double-counting.
_STABILITY_CTX = re.compile(
    r'(?:STABILITY_API_KEY|STABILITY_KEY|api\.stability\.ai|stability\.ai|stabilityai)'
    r'[\s\S]{0,300}'
    r'(sk-[A-Za-z0-9]{48})',
    re.IGNORECASE,
)


def extract_stability(content: str) -> list[str]:
    if not re.search(r'(?i)stability', content):
        return []
    found = []
    for m in _STABILITY_CTX.finditer(content):
        key = m.group(1)
        if not _FAKE.search(key):
            found.append(key)
    return list(dict.fromkeys(found))


# ── Commonstack (Claude/GPT/DeepSeek/Kimi/GLM aggregator) ─────────────────────
# Format: `ak-[a-f0-9]{64}` — `ak-` prefix is also used by Alibaba LTAI for some
# services, so REQUIRE commonstack context for the standalone hits.
_COMMONSTACK_RE = re.compile(
    r'(?<![A-Za-z0-9_\-])(ak-[a-f0-9]{64})(?![A-Za-z0-9])',
    re.IGNORECASE,
)
_COMMONSTACK_CTX = re.compile(
    r'(?:COMMONSTACK_API_KEY|api\.commonstack\.ai|commonstack\.ai|commonstack)'
    r'[\s\S]{0,300}'
    r'(ak-[a-f0-9]{64})',
    re.IGNORECASE,
)


def extract_commonstack(content: str) -> list[str]:
    if not re.search(r'(?i)commonstack', content):
        return []
    found = []
    for m in _COMMONSTACK_CTX.finditer(content):
        key = m.group(1)
        if not _FAKE.search(key):
            found.append(key)
    for m in _COMMONSTACK_RE.finditer(content):
        key = m.group(1)
        if key not in found and not _FAKE.search(key):
            found.append(key)
    return list(dict.fromkeys(found))


# ── Serper.dev (Google Search API for agent stacks) ────────────────────────────
# Format: 40 lowercase hex chars (one segment, no prefix). Standalone shape is
# too generic (= any SHA-1) — REQUIRE serper context anywhere in the file.
_SERPER_CTX = re.compile(
    r'(?:SERPER_API_KEY|SERPER_KEY|google\.serper\.dev|serper\.dev|api\.serper)'
    r'[\s\S]{0,300}'
    r'\b([a-f0-9]{40})\b',
    re.IGNORECASE,
)


def extract_serper(content: str) -> list[str]:
    if not re.search(r'(?i)serper', content):
        return []
    found = []
    for m in _SERPER_CTX.finditer(content):
        key = m.group(1)
        if not _FAKE.search(key):
            found.append(key)
    return list(dict.fromkeys(found))


# ── Luma AI (Dream Machine video gen) ──────────────────────────────────────────
# Format: `luma-{8-4-4-4-12}-{8-4-4-4-12}` — `luma-` prefix + double UUID.
# Unique enough for standalone matching (no context required).
_LUMA_RE = re.compile(
    r'(?<![A-Za-z0-9_\-])(luma-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-'
    r'[0-9a-f]{4}-[0-9a-f]{12}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-'
    r'[0-9a-f]{4}-[0-9a-f]{12})(?![A-Za-z0-9])',
    re.IGNORECASE,
)


def extract_luma(content: str) -> list[str]:
    found = []
    for m in _LUMA_RE.finditer(content):
        key = m.group(1)
        if not _FAKE.search(key):
            found.append(key)
    return list(dict.fromkeys(found))


# ── Pika Labs (short-form video gen) ──────────────────────────────────────────
# Format: `<UUID-with-dashes>:<hex32>`. Fal extractor uses `[hex8-16]:[hex40-80]`
# WITHOUT dashes, so they don't actually conflict in practice — UUID dashes
# break Fal's regex. We still gate on pika context to be safe.
_PIKA_CTX = re.compile(
    r'(?:PIKA_API_KEY|PIKA_KEY|api\.pika\.art|pika\.art|pikalabs)'
    r'[\s\S]{0,300}'
    r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    r':[0-9a-f]{32})',
    re.IGNORECASE,
)


def extract_pika(content: str) -> list[str]:
    if not re.search(r'(?i)pika', content):
        return []
    found = []
    for m in _PIKA_CTX.finditer(content):
        key = m.group(1)
        if not _FAKE.search(key):
            found.append(key)
    return list(dict.fromkeys(found))


# ── TwelveLabs (video understanding API — Marengo/Pegasus) ────────────────────
# Format: `tlk_[A-Za-z0-9]{20,40}`. Prefix is unique enough for standalone.
_TWELVELABS_RE = re.compile(
    r'(?<![A-Za-z0-9_\-])(tlk_[A-Za-z0-9]{20,40})(?![A-Za-z0-9])',
)


def extract_twelvelabs(content: str) -> list[str]:
    found = []
    for m in _TWELVELABS_RE.finditer(content):
        key = m.group(1)
        ctx = content[max(0, m.start() - 80): m.end() + 40]
        if not _FAKE.search(ctx):
            found.append(key)
    return list(dict.fromkeys(found))


# ── PixVerse (AI text-to-video / image-to-video) ─────────────────────────────
# Auth: 'API-KEY' header (NOT Bearer) + 'Ai-Trace-Id' UUID per request.
# Domain: app-api.pixverse.ai. Key shape: generic 20-80 char alnum (no
# specific prefix observed in 2026-05 docs).
_PIXVERSE_CTX = re.compile(
    r'(?:PIXVERSE_API_KEY|PIXVERSE_KEY|PIXVERSE_TOKEN|PIXVERSE_SECRET'
    r'|app-api\.pixverse\.ai|platform\.pixverse\.ai)'
    r'\s*[=:]\s*["\']?'
    r'([A-Za-z0-9_\-]{20,80})',
    re.IGNORECASE,
)


def extract_pixverse(content: str) -> list[str]:
    if not re.search(r'(?i)pixverse', content):
        return []
    found = []
    for m in _PIXVERSE_CTX.finditer(content):
        key = m.group(1)
        if len(key) >= 20 and not _FAKE.search(key):
            found.append(key)
    return list(dict.fromkeys(found))


# ── SiliconFlow / SiliconCloud (Chinese multi-model aggregator) ──────────────
# OpenAI-compatible at api.siliconflow.cn/v1. Frontier: DeepSeek/Qwen/GLM/Yi.
# Key shape: sk-* 48 chars (mirrors OpenAI exactly — disambiguation via context).
_SF_DIRECT = re.compile(
    r'(?:SILICONFLOW_API_KEY|SILICONCLOUD_API_KEY|SILICON_FLOW_KEY'
    r'|SILICONFLOW_KEY|SILICONCLOUD_KEY)'
    r'\s*[=:]\s*["\']?(sk-[A-Za-z0-9]{48})',
    re.IGNORECASE,
)
_SF_CTX = re.compile(
    r'(?:api\.siliconflow\.cn|siliconflow\.cn|siliconcloud|siliconflow)'
    r'[\s\S]{0,300}'
    r'(sk-[A-Za-z0-9]{48})',
    re.IGNORECASE,
)


def extract_siliconflow(content: str) -> list[str]:
    if not re.search(r'(?i)siliconflow|siliconcloud', content):
        return []
    found = []
    for m in _SF_DIRECT.finditer(content):
        key = m.group(1)
        if not _FAKE.search(key):
            found.append(key)
    for m in _SF_CTX.finditer(content):
        key = m.group(1)
        if key not in found and not _FAKE.search(key):
            found.append(key)
    return list(dict.fromkeys(found))


# ── Firecrawl (web scraping API for AI agents) ───────────────────────────────
# Key: 'fc-' + 32 hex chars (UUID without dashes). Auth: Bearer.
# Used heavily in 2025-26 AI-agent stacks (Mastra, LiteLLM tools, n8n).
_FC_STANDALONE = re.compile(r'(?<![A-Za-z0-9])(fc-[a-f0-9]{32})(?![A-Za-z0-9])')
_FC_CTX = re.compile(
    r'(?:FIRECRAWL_API_KEY|FIRECRAWL_KEY|FIRECRAWL_TOKEN'
    r'|api\.firecrawl\.dev|firecrawl\.dev|firecrawl)'
    r'[\s\S]{0,200}'
    r'(fc-[a-f0-9]{32})',
    re.IGNORECASE,
)


def extract_firecrawl(content: str) -> list[str]:
    found = []
    for m in _FC_STANDALONE.finditer(content):
        key = m.group(1)
        ctx = content[max(0, m.start() - 80): m.end() + 40]
        if not _FAKE.search(ctx):
            found.append(key)
    for m in _FC_CTX.finditer(content):
        key = m.group(1)
        if key not in found and not _FAKE.search(key):
            found.append(key)
    return list(dict.fromkeys(found))


# ── Portkey AI (LLM gateway / one-key access to user's stored upstream keys) ─
# Critical: Portkey users store their OpenAI/Anthropic/etc keys in Portkey
# dashboard. Leaking PORTKEY_API_KEY = access to all stored upstream keys
# via /v1/api-keys/* endpoints. Per-user balance can be huge.
# Auth: 'x-portkey-api-key' header (NOT Bearer).
# Virtual keys (per-provider) use 'pk-*' prefix.
_PORTKEY_PK = re.compile(r'(?<![A-Za-z0-9])(pk-[A-Za-z0-9_\-]{20,60})(?![A-Za-z0-9])')
_PORTKEY_CTX = re.compile(
    r'(?:PORTKEY_API_KEY|PORTKEY_KEY|PORTKEY_TOKEN|x-portkey-api-key'
    r'|x-portkey-virtual-key|api\.portkey\.ai|portkey\.ai)'
    r'[\s\S]{0,150}?'
    r'[=:\s"\']'
    r'([A-Za-z0-9_\-]{30,80})',
    re.IGNORECASE,
)


def extract_portkey(content: str) -> list[str]:
    if not re.search(r'(?i)portkey', content):
        return []
    found = []
    # pk- prefix (virtual keys) — strong signal
    for m in _PORTKEY_PK.finditer(content):
        key = m.group(1)
        ctx = content[max(0, m.start() - 100): m.end() + 50]
        if 'portkey' in ctx.lower() and not _FAKE.search(key):
            found.append(key)
    # ENV-name context (main account API key)
    for m in _PORTKEY_CTX.finditer(content):
        key = m.group(1)
        if len(key) < 30 or _FAKE.search(key) or key in found:
            continue
        # Filter junk: must contain digit + letter mix
        if not re.search(r'[0-9]', key) or not re.search(r'[a-zA-Z]', key):
            continue
        found.append(key)
    return list(dict.fromkeys(found))


# ── Krea AI (image + video generation, popular in creative-dev tools) ────────
# Auth: Bearer (or KEY_ID:SECRET pair stored together).
_KREA_CTX = re.compile(
    r'(?:KREA_API_KEY|KREA_KEY|KREA_TOKEN|KREA_SECRET'
    r'|api\.krea\.ai|krea\.ai/api)'
    r'\s*[=:]\s*["\']?'
    r'([A-Za-z0-9_\-:.]{30,120})',
    re.IGNORECASE,
)


def extract_krea(content: str) -> list[str]:
    if not re.search(r'(?i)krea\.ai|KREA_API', content):
        return []
    found = []
    for m in _KREA_CTX.finditer(content):
        key = m.group(1)
        if len(key) >= 30 and not _FAKE.search(key):
            found.append(key)
    return list(dict.fromkeys(found))


# ── Hedra AI (character video gen — Character-3, Omnia, etc) ─────────────────
# Auth: 'X-API-Key' header. Domain: api.hedra.com.
# Launched full Platform API Feb 2026 — high freshness, popular among
# YouTube tutorial repos.
_HEDRA_CTX = re.compile(
    r'(?:HEDRA_API_KEY|HEDRA_KEY|HEDRA_TOKEN|HEDRA_SECRET'
    r'|api\.hedra\.com|hedra\.com/api|hedra-labs)'
    r'\s*[=:]\s*["\']?'
    r'([A-Za-z0-9_\-]{30,120})',
    re.IGNORECASE,
)


def extract_hedra(content: str) -> list[str]:
    if not re.search(r'(?i)hedra', content):
        return []
    found = []
    for m in _HEDRA_CTX.finditer(content):
        key = m.group(1)
        if len(key) >= 30 and not _FAKE.search(key):
            found.append(key)
    return list(dict.fromkeys(found))


# ── WaveSpeed AI (multimodal acceleration platform — WAN, Z-Image, etc) ──────
# Auth: Bearer. Domain: api.wavespeed.ai. Has /api/v3/balance for validation.
# Note: keys require top-up to activate per docs.
_WAVESPEED_CTX = re.compile(
    r'(?:WAVESPEED_API_KEY|WAVESPEED_KEY|WAVESPEED_TOKEN|WAVESPEED_SECRET'
    r'|api\.wavespeed\.ai|wavespeed\.ai)'
    r'\s*[=:]\s*["\']?'
    r'([A-Za-z0-9_\-]{30,120})',
    re.IGNORECASE,
)


def extract_wavespeed(content: str) -> list[str]:
    if not re.search(r'(?i)wavespeed', content):
        return []
    found = []
    for m in _WAVESPEED_CTX.finditer(content):
        key = m.group(1)
        if len(key) >= 30 and not _FAKE.search(key):
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
    "higgsfield":    extract_higgsfield,
    "grok":          extract_grok,
    "inworld":       extract_inworld,
    "replicate":     extract_replicate,
    "fal":           extract_fal,
    "huggingface":   extract_huggingface,
    "perplexity":    extract_perplexity,
    "kimi":          extract_kimi,
    "glm":           extract_glm,
    "kling":         extract_kling,
    "fireworks":     extract_fireworks,
    "openrouter":    extract_openrouter,
    # Aggregators — single key gives access to multiple closed providers
    "aimlapi":       extract_aimlapi,
    "deepinfra":     extract_deepinfra,
    "hyperbolic":    extract_hyperbolic,
    "novita":        extract_novita,
    "commonstack":   extract_commonstack,    # Claude/GPT/DeepSeek/Kimi/GLM aggregator
    # Search/tools
    "serper":        extract_serper,         # Google Search API for agent stacks
    # AI Image
    "stability":     extract_stability,      # SD/SDXL/SD3 (sk-*48 — disambiguated against OpenAI)
    # AI Video
    "luma":          extract_luma,           # Dream Machine
    "pika":          extract_pika,           # Pika Labs
    # AI Video understanding
    "twelvelabs":    extract_twelvelabs,
    # 2026-05 additions — multi-model aggregators + agent search + new video gen
    "siliconflow":   extract_siliconflow,    # CN aggregator: DeepSeek/Qwen/GLM/Yi
    "firecrawl":     extract_firecrawl,      # web-scrape API for AI agents (fc-*)
    "portkey":       extract_portkey,        # AI gateway — leaks user's upstream keys
    "krea":          extract_krea,           # image+video gen
    "hedra":         extract_hedra,          # character video (Character-3/Omnia)
    "wavespeed":     extract_wavespeed,      # WAN, Z-Image multimodal accel
    "pixverse":      extract_pixverse,       # AI text-to-video / image-to-video
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

    # ── Higgsfield ──────────────────────────────────────────────────────
    "HIGGSFIELD_API_KEY", "HIGGSFIELD_KEY", "HIGGSFIELD_TOKEN",
    "HIGGSFIELD_SECRET", "higgsfield", "platform.higgsfield.ai",

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


    # ── Aggregators (Claude/Gemini/GPT/GPT Image proxy) ─────────────────
    "AIMLAPI", "aimlapi", "AIML_API_KEY", "api.aimlapi.com",
    "DEEPINFRA", "deepinfra", "DEEPINFRA_API_KEY", "DEEPINFRA_TOKEN",
    "api.deepinfra.com",
    "HYPERBOLIC", "hyperbolic", "HYPERBOLIC_API_KEY", "api.hyperbolic.xyz",
    "NOVITA_API_KEY", "NOVITA_AI", "novita.ai", "api.novita.ai",

    # ── Commonstack (Claude/GPT/DeepSeek/Kimi/GLM aggregator) ───────────
    "COMMONSTACK_API_KEY", "commonstack", "COMMONSTACK", "api.commonstack.ai",
    "commonstack.ai",

    # ── Serper.dev (Google Search) ──────────────────────────────────────
    "SERPER_API_KEY", "SERPER_KEY", "serper", "google.serper.dev",
    "serper.dev",

    # ── Stability AI (image gen) ────────────────────────────────────────
    "STABILITY_API_KEY", "STABILITY_KEY", "stability.ai", "api.stability.ai",
    "stabilityai",

    # ── Luma AI (Dream Machine video gen) ───────────────────────────────
    "LUMA_API_KEY", "LUMA_KEY", "lumalabs.ai", "api.lumalabs",
    "dream-machine", "luma-",

    # ── Pika Labs (video gen) ───────────────────────────────────────────
    "PIKA_API_KEY", "PIKA_KEY", "pika.art", "api.pika", "pikalabs",

    # ── TwelveLabs (video understanding) ────────────────────────────────
    "tlk_", "TWELVELABS_API_KEY", "twelvelabs", "api.twelvelabs.io",

    # ── 2026-05 additions ───────────────────────────────────────────────
    # PixVerse — text-to-video / image-to-video
    "PIXVERSE_API_KEY", "PIXVERSE", "pixverse", "app-api.pixverse.ai",
    # SiliconFlow — Chinese multi-model aggregator (DeepSeek/Qwen/GLM/Yi)
    "SILICONFLOW_API_KEY", "SILICONCLOUD_API_KEY",
    "siliconflow", "siliconcloud", "api.siliconflow.cn",
    # Firecrawl — agent web-scraping API (fc-* prefix unique)
    "fc-", "FIRECRAWL_API_KEY", "firecrawl", "firecrawl.dev",
    # Portkey AI gateway — pk-* virtual keys + main API key
    "PORTKEY_API_KEY", "portkey", "api.portkey.ai",
    "x-portkey-api-key", "x-portkey-virtual-key",
    # Krea AI — image+video gen
    "KREA_API_KEY", "krea.ai", "api.krea.ai",
    # Hedra — character video generation
    "HEDRA_API_KEY", "hedra", "api.hedra.com", "hedra.com",
    # WaveSpeed AI — multimodal acceleration
    "WAVESPEED_API_KEY", "wavespeed", "api.wavespeed.ai",
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
    # HIGGSFIELD AI  (video/image generator, Bearer auth, platform.higgsfield.ai)
    # ═══════════════════════════════════════════════════════════════════════

    ('"HIGGSFIELD_API_KEY" filename:.env',                "higgsfield", "env"),
    ('"HIGGSFIELD_API_KEY" filename:.env.local',          "higgsfield", "env"),
    ('"HIGGSFIELD_API_KEY" filename:.env.example',        "higgsfield", "env"),
    ('"HIGGSFIELD_KEY" filename:.env',                    "higgsfield", "env"),
    ('"HIGGSFIELD_TOKEN" filename:.env',                  "higgsfield", "env"),
    ('"higgsfield" "api_key" filename:.env',              "higgsfield", "env"),

    ('"HIGGSFIELD_API_KEY" language:python',              "higgsfield", "code"),
    ('"HIGGSFIELD_API_KEY" language:javascript',          "higgsfield", "code"),
    ('"HIGGSFIELD_API_KEY" language:typescript',          "higgsfield", "code"),
    ('"platform.higgsfield.ai" language:python',          "higgsfield", "code"),
    ('"platform.higgsfield.ai" language:javascript',      "higgsfield", "code"),
    ('"platform.higgsfield.ai" language:typescript',      "higgsfield", "code"),
    ('"higgsfield-client" language:python',               "higgsfield", "code"),
    ('"higgsfield-js" language:javascript',               "higgsfield", "code"),
    ('"HIGGSFIELD_API_KEY" extension:ipynb',              "higgsfield", "notebook"),
    ('"HIGGSFIELD_API_KEY" filename:config.py',           "higgsfield", "config"),
    ('"HIGGSFIELD_API_KEY" filename:config.ts',           "higgsfield", "config"),
    ('"HIGGSFIELD_API_KEY" path:.github/workflows',       "higgsfield", "ci"),

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
    # ── BIG BATCH: modern AI configs, deploy, dotfiles, langs (auto-generated) ──
    ('"OPENAI_API_KEY" filename:.cursor/mcp.json',	"openai",	"cursor_mcp"),
    ('"OPENAI_API_KEY" filename:.continue/config.json',	"openai",	"continue_cfg"),
    ('"OPENAI_API_KEY" filename:.continue/config.yaml',	"openai",	"continue_cfg"),
    ('"OPENAI_API_KEY" filename:.aider.conf.yml',	"openai",	"aider_cfg"),
    ('"OPENAI_API_KEY" filename:.claude/settings.local.json',	"openai",	"claude_code"),
    ('"OPENAI_API_KEY" filename:.claude/settings.json',	"openai",	"claude_code"),
    ('"OPENAI_API_KEY" filename:claude_desktop_config.json',	"openai",	"mcp_config"),
    ('"OPENAI_API_KEY" filename:mcp.json',	"openai",	"mcp_config"),
    ('"ANTHROPIC_API_KEY" filename:.cursor/mcp.json',	"anthropic",	"cursor_mcp"),
    ('"ANTHROPIC_API_KEY" filename:.continue/config.json',	"anthropic",	"continue_cfg"),
    ('"ANTHROPIC_API_KEY" filename:.continue/config.yaml',	"anthropic",	"continue_cfg"),
    ('"ANTHROPIC_API_KEY" filename:.aider.conf.yml',	"anthropic",	"aider_cfg"),
    ('"ANTHROPIC_API_KEY" filename:.claude/settings.local.json',	"anthropic",	"claude_code"),
    ('"ANTHROPIC_API_KEY" filename:.claude/settings.json',	"anthropic",	"claude_code"),
    ('"ANTHROPIC_API_KEY" filename:claude_desktop_config.json',	"anthropic",	"mcp_config"),
    ('"ANTHROPIC_API_KEY" filename:mcp.json',	"anthropic",	"mcp_config"),
    ('"GOOGLE_API_KEY" filename:.cursor/mcp.json',	"google",	"cursor_mcp"),
    ('"GOOGLE_API_KEY" filename:.continue/config.json',	"google",	"continue_cfg"),
    ('"GOOGLE_API_KEY" filename:.continue/config.yaml',	"google",	"continue_cfg"),
    ('"GOOGLE_API_KEY" filename:.aider.conf.yml',	"google",	"aider_cfg"),
    ('"GOOGLE_API_KEY" filename:.claude/settings.local.json',	"google",	"claude_code"),
    ('"GOOGLE_API_KEY" filename:.claude/settings.json',	"google",	"claude_code"),
    ('"GOOGLE_API_KEY" filename:claude_desktop_config.json',	"google",	"mcp_config"),
    ('"GOOGLE_API_KEY" filename:mcp.json',	"google",	"mcp_config"),
    ('"GEMINI_API_KEY" filename:.cursor/mcp.json',	"google",	"cursor_mcp"),
    ('"GEMINI_API_KEY" filename:.continue/config.json',	"google",	"continue_cfg"),
    ('"GEMINI_API_KEY" filename:.continue/config.yaml',	"google",	"continue_cfg"),
    ('"GEMINI_API_KEY" filename:.aider.conf.yml',	"google",	"aider_cfg"),
    ('"GEMINI_API_KEY" filename:.claude/settings.local.json',	"google",	"claude_code"),
    ('"GEMINI_API_KEY" filename:.claude/settings.json',	"google",	"claude_code"),
    ('"GEMINI_API_KEY" filename:claude_desktop_config.json',	"google",	"mcp_config"),
    ('"GEMINI_API_KEY" filename:mcp.json',	"google",	"mcp_config"),
    ('"DEEPSEEK_API_KEY" filename:.cursor/mcp.json',	"deepseek",	"cursor_mcp"),
    ('"DEEPSEEK_API_KEY" filename:.continue/config.json',	"deepseek",	"continue_cfg"),
    ('"DEEPSEEK_API_KEY" filename:.continue/config.yaml',	"deepseek",	"continue_cfg"),
    ('"DEEPSEEK_API_KEY" filename:.aider.conf.yml',	"deepseek",	"aider_cfg"),
    ('"DEEPSEEK_API_KEY" filename:.claude/settings.local.json',	"deepseek",	"claude_code"),
    ('"DEEPSEEK_API_KEY" filename:.claude/settings.json',	"deepseek",	"claude_code"),
    ('"DEEPSEEK_API_KEY" filename:claude_desktop_config.json',	"deepseek",	"mcp_config"),
    ('"DEEPSEEK_API_KEY" filename:mcp.json',	"deepseek",	"mcp_config"),
    ('"OPENROUTER_API_KEY" filename:.cursor/mcp.json',	"openrouter",	"cursor_mcp"),
    ('"OPENROUTER_API_KEY" filename:.continue/config.json',	"openrouter",	"continue_cfg"),
    ('"OPENROUTER_API_KEY" filename:.continue/config.yaml',	"openrouter",	"continue_cfg"),
    ('"OPENROUTER_API_KEY" filename:.aider.conf.yml',	"openrouter",	"aider_cfg"),
    ('"OPENROUTER_API_KEY" filename:.claude/settings.local.json',	"openrouter",	"claude_code"),
    ('"OPENROUTER_API_KEY" filename:.claude/settings.json',	"openrouter",	"claude_code"),
    ('"OPENROUTER_API_KEY" filename:claude_desktop_config.json',	"openrouter",	"mcp_config"),
    ('"OPENROUTER_API_KEY" filename:mcp.json',	"openrouter",	"mcp_config"),
    ('"HF_TOKEN" filename:.cursor/mcp.json',	"huggingface",	"cursor_mcp"),
    ('"HF_TOKEN" filename:.continue/config.json',	"huggingface",	"continue_cfg"),
    ('"HF_TOKEN" filename:.continue/config.yaml',	"huggingface",	"continue_cfg"),
    ('"HF_TOKEN" filename:.aider.conf.yml',	"huggingface",	"aider_cfg"),
    ('"HF_TOKEN" filename:.claude/settings.local.json',	"huggingface",	"claude_code"),
    ('"HF_TOKEN" filename:.claude/settings.json',	"huggingface",	"claude_code"),
    ('"HF_TOKEN" filename:claude_desktop_config.json',	"huggingface",	"mcp_config"),
    ('"HF_TOKEN" filename:mcp.json',	"huggingface",	"mcp_config"),
    ('"HUGGINGFACE_TOKEN" filename:.cursor/mcp.json',	"huggingface",	"cursor_mcp"),
    ('"HUGGINGFACE_TOKEN" filename:.continue/config.json',	"huggingface",	"continue_cfg"),
    ('"HUGGINGFACE_TOKEN" filename:.continue/config.yaml',	"huggingface",	"continue_cfg"),
    ('"HUGGINGFACE_TOKEN" filename:.aider.conf.yml',	"huggingface",	"aider_cfg"),
    ('"HUGGINGFACE_TOKEN" filename:.claude/settings.local.json',	"huggingface",	"claude_code"),
    ('"HUGGINGFACE_TOKEN" filename:.claude/settings.json',	"huggingface",	"claude_code"),
    ('"HUGGINGFACE_TOKEN" filename:claude_desktop_config.json',	"huggingface",	"mcp_config"),
    ('"HUGGINGFACE_TOKEN" filename:mcp.json',	"huggingface",	"mcp_config"),
    ('"REPLICATE_API_TOKEN" filename:.cursor/mcp.json',	"replicate",	"cursor_mcp"),
    ('"REPLICATE_API_TOKEN" filename:.continue/config.json',	"replicate",	"continue_cfg"),
    ('"REPLICATE_API_TOKEN" filename:.continue/config.yaml',	"replicate",	"continue_cfg"),
    ('"REPLICATE_API_TOKEN" filename:.aider.conf.yml',	"replicate",	"aider_cfg"),
    ('"REPLICATE_API_TOKEN" filename:.claude/settings.local.json',	"replicate",	"claude_code"),
    ('"REPLICATE_API_TOKEN" filename:.claude/settings.json',	"replicate",	"claude_code"),
    ('"REPLICATE_API_TOKEN" filename:claude_desktop_config.json',	"replicate",	"mcp_config"),
    ('"REPLICATE_API_TOKEN" filename:mcp.json',	"replicate",	"mcp_config"),
    ('"FAL_KEY" filename:.cursor/mcp.json',	"fal",	"cursor_mcp"),
    ('"FAL_KEY" filename:.continue/config.json',	"fal",	"continue_cfg"),
    ('"FAL_KEY" filename:.continue/config.yaml',	"fal",	"continue_cfg"),
    ('"FAL_KEY" filename:.aider.conf.yml',	"fal",	"aider_cfg"),
    ('"FAL_KEY" filename:.claude/settings.local.json',	"fal",	"claude_code"),
    ('"FAL_KEY" filename:.claude/settings.json',	"fal",	"claude_code"),
    ('"FAL_KEY" filename:claude_desktop_config.json',	"fal",	"mcp_config"),
    ('"FAL_KEY" filename:mcp.json',	"fal",	"mcp_config"),
    ('"FIREWORKS_API_KEY" filename:.cursor/mcp.json',	"fireworks",	"cursor_mcp"),
    ('"FIREWORKS_API_KEY" filename:.continue/config.json',	"fireworks",	"continue_cfg"),
    ('"FIREWORKS_API_KEY" filename:.continue/config.yaml',	"fireworks",	"continue_cfg"),
    ('"FIREWORKS_API_KEY" filename:.aider.conf.yml',	"fireworks",	"aider_cfg"),
    ('"FIREWORKS_API_KEY" filename:.claude/settings.local.json',	"fireworks",	"claude_code"),
    ('"FIREWORKS_API_KEY" filename:.claude/settings.json',	"fireworks",	"claude_code"),
    ('"FIREWORKS_API_KEY" filename:claude_desktop_config.json',	"fireworks",	"mcp_config"),
    ('"FIREWORKS_API_KEY" filename:mcp.json',	"fireworks",	"mcp_config"),
    ('"PERPLEXITY_API_KEY" filename:.cursor/mcp.json',	"perplexity",	"cursor_mcp"),
    ('"PERPLEXITY_API_KEY" filename:.continue/config.json',	"perplexity",	"continue_cfg"),
    ('"PERPLEXITY_API_KEY" filename:.continue/config.yaml',	"perplexity",	"continue_cfg"),
    ('"PERPLEXITY_API_KEY" filename:.aider.conf.yml',	"perplexity",	"aider_cfg"),
    ('"PERPLEXITY_API_KEY" filename:.claude/settings.local.json',	"perplexity",	"claude_code"),
    ('"PERPLEXITY_API_KEY" filename:.claude/settings.json',	"perplexity",	"claude_code"),
    ('"PERPLEXITY_API_KEY" filename:claude_desktop_config.json',	"perplexity",	"mcp_config"),
    ('"PERPLEXITY_API_KEY" filename:mcp.json',	"perplexity",	"mcp_config"),
    ('"XAI_API_KEY" filename:.cursor/mcp.json',	"grok",	"cursor_mcp"),
    ('"XAI_API_KEY" filename:.continue/config.json',	"grok",	"continue_cfg"),
    ('"XAI_API_KEY" filename:.continue/config.yaml',	"grok",	"continue_cfg"),
    ('"XAI_API_KEY" filename:.aider.conf.yml',	"grok",	"aider_cfg"),
    ('"XAI_API_KEY" filename:.claude/settings.local.json',	"grok",	"claude_code"),
    ('"XAI_API_KEY" filename:.claude/settings.json',	"grok",	"claude_code"),
    ('"XAI_API_KEY" filename:claude_desktop_config.json',	"grok",	"mcp_config"),
    ('"XAI_API_KEY" filename:mcp.json',	"grok",	"mcp_config"),
    ('"HIGGSFIELD_API_KEY" filename:.cursor/mcp.json',	"higgsfield",	"cursor_mcp"),
    ('"HIGGSFIELD_API_KEY" filename:.continue/config.json',	"higgsfield",	"continue_cfg"),
    ('"HIGGSFIELD_API_KEY" filename:.continue/config.yaml',	"higgsfield",	"continue_cfg"),
    ('"HIGGSFIELD_API_KEY" filename:.aider.conf.yml',	"higgsfield",	"aider_cfg"),
    ('"HIGGSFIELD_API_KEY" filename:.claude/settings.local.json',	"higgsfield",	"claude_code"),
    ('"HIGGSFIELD_API_KEY" filename:.claude/settings.json',	"higgsfield",	"claude_code"),
    ('"HIGGSFIELD_API_KEY" filename:claude_desktop_config.json',	"higgsfield",	"mcp_config"),
    ('"HIGGSFIELD_API_KEY" filename:mcp.json',	"higgsfield",	"mcp_config"),
    ('"ELEVENLABS_API_KEY" filename:.cursor/mcp.json',	"elevenlabs",	"cursor_mcp"),
    ('"ELEVENLABS_API_KEY" filename:.continue/config.json',	"elevenlabs",	"continue_cfg"),
    ('"ELEVENLABS_API_KEY" filename:.continue/config.yaml',	"elevenlabs",	"continue_cfg"),
    ('"ELEVENLABS_API_KEY" filename:.aider.conf.yml',	"elevenlabs",	"aider_cfg"),
    ('"ELEVENLABS_API_KEY" filename:.claude/settings.local.json',	"elevenlabs",	"claude_code"),
    ('"ELEVENLABS_API_KEY" filename:.claude/settings.json',	"elevenlabs",	"claude_code"),
    ('"ELEVENLABS_API_KEY" filename:claude_desktop_config.json',	"elevenlabs",	"mcp_config"),
    ('"ELEVENLABS_API_KEY" filename:mcp.json',	"elevenlabs",	"mcp_config"),
    ('"MOONSHOT_API_KEY" filename:.cursor/mcp.json',	"kimi",	"cursor_mcp"),
    ('"MOONSHOT_API_KEY" filename:.continue/config.json',	"kimi",	"continue_cfg"),
    ('"MOONSHOT_API_KEY" filename:.continue/config.yaml',	"kimi",	"continue_cfg"),
    ('"MOONSHOT_API_KEY" filename:.aider.conf.yml',	"kimi",	"aider_cfg"),
    ('"MOONSHOT_API_KEY" filename:.claude/settings.local.json',	"kimi",	"claude_code"),
    ('"MOONSHOT_API_KEY" filename:.claude/settings.json',	"kimi",	"claude_code"),
    ('"MOONSHOT_API_KEY" filename:claude_desktop_config.json',	"kimi",	"mcp_config"),
    ('"MOONSHOT_API_KEY" filename:mcp.json',	"kimi",	"mcp_config"),
    ('"ZHIPUAI_API_KEY" filename:.cursor/mcp.json',	"glm",	"cursor_mcp"),
    ('"ZHIPUAI_API_KEY" filename:.continue/config.json',	"glm",	"continue_cfg"),
    ('"ZHIPUAI_API_KEY" filename:.continue/config.yaml',	"glm",	"continue_cfg"),
    ('"ZHIPUAI_API_KEY" filename:.aider.conf.yml',	"glm",	"aider_cfg"),
    ('"ZHIPUAI_API_KEY" filename:.claude/settings.local.json',	"glm",	"claude_code"),
    ('"ZHIPUAI_API_KEY" filename:.claude/settings.json',	"glm",	"claude_code"),
    ('"ZHIPUAI_API_KEY" filename:claude_desktop_config.json',	"glm",	"mcp_config"),
    ('"ZHIPUAI_API_KEY" filename:mcp.json',	"glm",	"mcp_config"),
    ('"ARK_API_KEY" filename:.cursor/mcp.json',	"ark",	"cursor_mcp"),
    ('"ARK_API_KEY" filename:.continue/config.json',	"ark",	"continue_cfg"),
    ('"ARK_API_KEY" filename:.continue/config.yaml',	"ark",	"continue_cfg"),
    ('"ARK_API_KEY" filename:.aider.conf.yml',	"ark",	"aider_cfg"),
    ('"ARK_API_KEY" filename:.claude/settings.local.json',	"ark",	"claude_code"),
    ('"ARK_API_KEY" filename:.claude/settings.json',	"ark",	"claude_code"),
    ('"ARK_API_KEY" filename:claude_desktop_config.json',	"ark",	"mcp_config"),
    ('"ARK_API_KEY" filename:mcp.json',	"ark",	"mcp_config"),
    ('"AIMLAPI_API_KEY" filename:.cursor/mcp.json',	"aimlapi",	"cursor_mcp"),
    ('"AIMLAPI_API_KEY" filename:.continue/config.json',	"aimlapi",	"continue_cfg"),
    ('"AIMLAPI_API_KEY" filename:.continue/config.yaml',	"aimlapi",	"continue_cfg"),
    ('"AIMLAPI_API_KEY" filename:.aider.conf.yml',	"aimlapi",	"aider_cfg"),
    ('"AIMLAPI_API_KEY" filename:.claude/settings.local.json',	"aimlapi",	"claude_code"),
    ('"AIMLAPI_API_KEY" filename:.claude/settings.json',	"aimlapi",	"claude_code"),
    ('"AIMLAPI_API_KEY" filename:claude_desktop_config.json',	"aimlapi",	"mcp_config"),
    ('"AIMLAPI_API_KEY" filename:mcp.json',	"aimlapi",	"mcp_config"),
    ('"DEEPINFRA_API_KEY" filename:.cursor/mcp.json',	"deepinfra",	"cursor_mcp"),
    ('"DEEPINFRA_API_KEY" filename:.continue/config.json',	"deepinfra",	"continue_cfg"),
    ('"DEEPINFRA_API_KEY" filename:.continue/config.yaml',	"deepinfra",	"continue_cfg"),
    ('"DEEPINFRA_API_KEY" filename:.aider.conf.yml',	"deepinfra",	"aider_cfg"),
    ('"DEEPINFRA_API_KEY" filename:.claude/settings.local.json',	"deepinfra",	"claude_code"),
    ('"DEEPINFRA_API_KEY" filename:.claude/settings.json',	"deepinfra",	"claude_code"),
    ('"DEEPINFRA_API_KEY" filename:claude_desktop_config.json',	"deepinfra",	"mcp_config"),
    ('"DEEPINFRA_API_KEY" filename:mcp.json',	"deepinfra",	"mcp_config"),
    ('"HYPERBOLIC_API_KEY" filename:.cursor/mcp.json',	"hyperbolic",	"cursor_mcp"),
    ('"HYPERBOLIC_API_KEY" filename:.continue/config.json',	"hyperbolic",	"continue_cfg"),
    ('"HYPERBOLIC_API_KEY" filename:.continue/config.yaml',	"hyperbolic",	"continue_cfg"),
    ('"HYPERBOLIC_API_KEY" filename:.aider.conf.yml',	"hyperbolic",	"aider_cfg"),
    ('"HYPERBOLIC_API_KEY" filename:.claude/settings.local.json',	"hyperbolic",	"claude_code"),
    ('"HYPERBOLIC_API_KEY" filename:.claude/settings.json',	"hyperbolic",	"claude_code"),
    ('"HYPERBOLIC_API_KEY" filename:claude_desktop_config.json',	"hyperbolic",	"mcp_config"),
    ('"HYPERBOLIC_API_KEY" filename:mcp.json',	"hyperbolic",	"mcp_config"),
    ('"NOVITA_API_KEY" filename:.cursor/mcp.json',	"novita",	"cursor_mcp"),
    ('"NOVITA_API_KEY" filename:.continue/config.json',	"novita",	"continue_cfg"),
    ('"NOVITA_API_KEY" filename:.continue/config.yaml',	"novita",	"continue_cfg"),
    ('"NOVITA_API_KEY" filename:.aider.conf.yml',	"novita",	"aider_cfg"),
    ('"NOVITA_API_KEY" filename:.claude/settings.local.json',	"novita",	"claude_code"),
    ('"NOVITA_API_KEY" filename:.claude/settings.json',	"novita",	"claude_code"),
    ('"NOVITA_API_KEY" filename:claude_desktop_config.json',	"novita",	"mcp_config"),
    ('"NOVITA_API_KEY" filename:mcp.json',	"novita",	"mcp_config"),
    ('"OPENAI_API_KEY" filename:litellm_config.yaml',	"openai",	"litellm"),
    ('"OPENAI_API_KEY" filename:litellm.yaml',	"openai",	"litellm"),
    ('"OPENAI_API_KEY" filename:litellm_config.json',	"openai",	"litellm"),
    ('"ANTHROPIC_API_KEY" filename:litellm_config.yaml',	"anthropic",	"litellm"),
    ('"ANTHROPIC_API_KEY" filename:litellm.yaml',	"anthropic",	"litellm"),
    ('"ANTHROPIC_API_KEY" filename:litellm_config.json',	"anthropic",	"litellm"),
    ('"GOOGLE_API_KEY" filename:litellm_config.yaml',	"google",	"litellm"),
    ('"GOOGLE_API_KEY" filename:litellm.yaml',	"google",	"litellm"),
    ('"GOOGLE_API_KEY" filename:litellm_config.json',	"google",	"litellm"),
    ('"GEMINI_API_KEY" filename:litellm_config.yaml',	"google",	"litellm"),
    ('"GEMINI_API_KEY" filename:litellm.yaml',	"google",	"litellm"),
    ('"GEMINI_API_KEY" filename:litellm_config.json',	"google",	"litellm"),
    ('"DEEPSEEK_API_KEY" filename:litellm_config.yaml',	"deepseek",	"litellm"),
    ('"DEEPSEEK_API_KEY" filename:litellm.yaml',	"deepseek",	"litellm"),
    ('"DEEPSEEK_API_KEY" filename:litellm_config.json',	"deepseek",	"litellm"),
    ('"OPENROUTER_API_KEY" filename:litellm_config.yaml',	"openrouter",	"litellm"),
    ('"OPENROUTER_API_KEY" filename:litellm.yaml',	"openrouter",	"litellm"),
    ('"OPENROUTER_API_KEY" filename:litellm_config.json',	"openrouter",	"litellm"),
    ('"HF_TOKEN" filename:litellm_config.yaml',	"huggingface",	"litellm"),
    ('"HF_TOKEN" filename:litellm.yaml',	"huggingface",	"litellm"),
    ('"HF_TOKEN" filename:litellm_config.json',	"huggingface",	"litellm"),
    ('"HUGGINGFACE_TOKEN" filename:litellm_config.yaml',	"huggingface",	"litellm"),
    ('"HUGGINGFACE_TOKEN" filename:litellm.yaml',	"huggingface",	"litellm"),
    ('"HUGGINGFACE_TOKEN" filename:litellm_config.json',	"huggingface",	"litellm"),
    ('"REPLICATE_API_TOKEN" filename:litellm_config.yaml',	"replicate",	"litellm"),
    ('"REPLICATE_API_TOKEN" filename:litellm.yaml',	"replicate",	"litellm"),
    ('"REPLICATE_API_TOKEN" filename:litellm_config.json',	"replicate",	"litellm"),
    ('"FAL_KEY" filename:litellm_config.yaml',	"fal",	"litellm"),
    ('"FAL_KEY" filename:litellm.yaml',	"fal",	"litellm"),
    ('"FAL_KEY" filename:litellm_config.json',	"fal",	"litellm"),
    ('"FIREWORKS_API_KEY" filename:litellm_config.yaml',	"fireworks",	"litellm"),
    ('"FIREWORKS_API_KEY" filename:litellm.yaml',	"fireworks",	"litellm"),
    ('"FIREWORKS_API_KEY" filename:litellm_config.json',	"fireworks",	"litellm"),
    ('"PERPLEXITY_API_KEY" filename:litellm_config.yaml',	"perplexity",	"litellm"),
    ('"PERPLEXITY_API_KEY" filename:litellm.yaml',	"perplexity",	"litellm"),
    ('"PERPLEXITY_API_KEY" filename:litellm_config.json',	"perplexity",	"litellm"),
    ('"XAI_API_KEY" filename:litellm_config.yaml',	"grok",	"litellm"),
    ('"XAI_API_KEY" filename:litellm.yaml',	"grok",	"litellm"),
    ('"XAI_API_KEY" filename:litellm_config.json',	"grok",	"litellm"),
    ('"HIGGSFIELD_API_KEY" filename:litellm_config.yaml',	"higgsfield",	"litellm"),
    ('"HIGGSFIELD_API_KEY" filename:litellm.yaml',	"higgsfield",	"litellm"),
    ('"HIGGSFIELD_API_KEY" filename:litellm_config.json',	"higgsfield",	"litellm"),
    ('"ELEVENLABS_API_KEY" filename:litellm_config.yaml',	"elevenlabs",	"litellm"),
    ('"ELEVENLABS_API_KEY" filename:litellm.yaml',	"elevenlabs",	"litellm"),
    ('"ELEVENLABS_API_KEY" filename:litellm_config.json',	"elevenlabs",	"litellm"),
    ('"MOONSHOT_API_KEY" filename:litellm_config.yaml',	"kimi",	"litellm"),
    ('"MOONSHOT_API_KEY" filename:litellm.yaml',	"kimi",	"litellm"),
    ('"MOONSHOT_API_KEY" filename:litellm_config.json',	"kimi",	"litellm"),
    ('"ZHIPUAI_API_KEY" filename:litellm_config.yaml',	"glm",	"litellm"),
    ('"ZHIPUAI_API_KEY" filename:litellm.yaml',	"glm",	"litellm"),
    ('"ZHIPUAI_API_KEY" filename:litellm_config.json',	"glm",	"litellm"),
    ('"ARK_API_KEY" filename:litellm_config.yaml',	"ark",	"litellm"),
    ('"ARK_API_KEY" filename:litellm.yaml',	"ark",	"litellm"),
    ('"ARK_API_KEY" filename:litellm_config.json',	"ark",	"litellm"),
    ('"AIMLAPI_API_KEY" filename:litellm_config.yaml',	"aimlapi",	"litellm"),
    ('"AIMLAPI_API_KEY" filename:litellm.yaml',	"aimlapi",	"litellm"),
    ('"AIMLAPI_API_KEY" filename:litellm_config.json',	"aimlapi",	"litellm"),
    ('"DEEPINFRA_API_KEY" filename:litellm_config.yaml',	"deepinfra",	"litellm"),
    ('"DEEPINFRA_API_KEY" filename:litellm.yaml',	"deepinfra",	"litellm"),
    ('"DEEPINFRA_API_KEY" filename:litellm_config.json',	"deepinfra",	"litellm"),
    ('"HYPERBOLIC_API_KEY" filename:litellm_config.yaml',	"hyperbolic",	"litellm"),
    ('"HYPERBOLIC_API_KEY" filename:litellm.yaml',	"hyperbolic",	"litellm"),
    ('"HYPERBOLIC_API_KEY" filename:litellm_config.json',	"hyperbolic",	"litellm"),
    ('"NOVITA_API_KEY" filename:litellm_config.yaml',	"novita",	"litellm"),
    ('"NOVITA_API_KEY" filename:litellm.yaml',	"novita",	"litellm"),
    ('"NOVITA_API_KEY" filename:litellm_config.json',	"novita",	"litellm"),
    ('"OPENAI_API_KEY" filename:vercel.json',	"openai",	"vercel"),
    ('"OPENAI_API_KEY" filename:netlify.toml',	"openai",	"netlify"),
    ('"OPENAI_API_KEY" filename:wrangler.toml',	"openai",	"wrangler"),
    ('"OPENAI_API_KEY" filename:railway.toml',	"openai",	"railway"),
    ('"OPENAI_API_KEY" filename:fly.toml',	"openai",	"fly"),
    ('"OPENAI_API_KEY" filename:Procfile',	"openai",	"heroku"),
    ('"OPENAI_API_KEY" filename:serverless.yml',	"openai",	"serverless"),
    ('"OPENAI_API_KEY" filename:serverless.yaml',	"openai",	"serverless"),
    ('"OPENAI_API_KEY" filename:app.yaml',	"openai",	"gae"),
    ('"ANTHROPIC_API_KEY" filename:vercel.json',	"anthropic",	"vercel"),
    ('"ANTHROPIC_API_KEY" filename:netlify.toml',	"anthropic",	"netlify"),
    ('"ANTHROPIC_API_KEY" filename:wrangler.toml',	"anthropic",	"wrangler"),
    ('"ANTHROPIC_API_KEY" filename:railway.toml',	"anthropic",	"railway"),
    ('"ANTHROPIC_API_KEY" filename:fly.toml',	"anthropic",	"fly"),
    ('"ANTHROPIC_API_KEY" filename:Procfile',	"anthropic",	"heroku"),
    ('"ANTHROPIC_API_KEY" filename:serverless.yml',	"anthropic",	"serverless"),
    ('"ANTHROPIC_API_KEY" filename:serverless.yaml',	"anthropic",	"serverless"),
    ('"ANTHROPIC_API_KEY" filename:app.yaml',	"anthropic",	"gae"),
    ('"GOOGLE_API_KEY" filename:vercel.json',	"google",	"vercel"),
    ('"GOOGLE_API_KEY" filename:netlify.toml',	"google",	"netlify"),
    ('"GOOGLE_API_KEY" filename:wrangler.toml',	"google",	"wrangler"),
    ('"GOOGLE_API_KEY" filename:railway.toml',	"google",	"railway"),
    ('"GOOGLE_API_KEY" filename:fly.toml',	"google",	"fly"),
    ('"GOOGLE_API_KEY" filename:Procfile',	"google",	"heroku"),
    ('"GOOGLE_API_KEY" filename:serverless.yml',	"google",	"serverless"),
    ('"GOOGLE_API_KEY" filename:serverless.yaml',	"google",	"serverless"),
    ('"GOOGLE_API_KEY" filename:app.yaml',	"google",	"gae"),
    ('"GEMINI_API_KEY" filename:vercel.json',	"google",	"vercel"),
    ('"GEMINI_API_KEY" filename:netlify.toml',	"google",	"netlify"),
    ('"GEMINI_API_KEY" filename:wrangler.toml',	"google",	"wrangler"),
    ('"GEMINI_API_KEY" filename:railway.toml',	"google",	"railway"),
    ('"GEMINI_API_KEY" filename:fly.toml',	"google",	"fly"),
    ('"GEMINI_API_KEY" filename:Procfile',	"google",	"heroku"),
    ('"GEMINI_API_KEY" filename:serverless.yml',	"google",	"serverless"),
    ('"GEMINI_API_KEY" filename:serverless.yaml',	"google",	"serverless"),
    ('"GEMINI_API_KEY" filename:app.yaml',	"google",	"gae"),
    ('"DEEPSEEK_API_KEY" filename:vercel.json',	"deepseek",	"vercel"),
    ('"DEEPSEEK_API_KEY" filename:netlify.toml',	"deepseek",	"netlify"),
    ('"DEEPSEEK_API_KEY" filename:wrangler.toml',	"deepseek",	"wrangler"),
    ('"DEEPSEEK_API_KEY" filename:railway.toml',	"deepseek",	"railway"),
    ('"DEEPSEEK_API_KEY" filename:fly.toml',	"deepseek",	"fly"),
    ('"DEEPSEEK_API_KEY" filename:Procfile',	"deepseek",	"heroku"),
    ('"DEEPSEEK_API_KEY" filename:serverless.yml',	"deepseek",	"serverless"),
    ('"DEEPSEEK_API_KEY" filename:serverless.yaml',	"deepseek",	"serverless"),
    ('"DEEPSEEK_API_KEY" filename:app.yaml',	"deepseek",	"gae"),
    ('"OPENROUTER_API_KEY" filename:vercel.json',	"openrouter",	"vercel"),
    ('"OPENROUTER_API_KEY" filename:netlify.toml',	"openrouter",	"netlify"),
    ('"OPENROUTER_API_KEY" filename:wrangler.toml',	"openrouter",	"wrangler"),
    ('"OPENROUTER_API_KEY" filename:railway.toml',	"openrouter",	"railway"),
    ('"OPENROUTER_API_KEY" filename:fly.toml',	"openrouter",	"fly"),
    ('"OPENROUTER_API_KEY" filename:Procfile',	"openrouter",	"heroku"),
    ('"OPENROUTER_API_KEY" filename:serverless.yml',	"openrouter",	"serverless"),
    ('"OPENROUTER_API_KEY" filename:serverless.yaml',	"openrouter",	"serverless"),
    ('"OPENROUTER_API_KEY" filename:app.yaml',	"openrouter",	"gae"),
    ('"HF_TOKEN" filename:vercel.json',	"huggingface",	"vercel"),
    ('"HF_TOKEN" filename:netlify.toml',	"huggingface",	"netlify"),
    ('"HF_TOKEN" filename:wrangler.toml',	"huggingface",	"wrangler"),
    ('"HF_TOKEN" filename:railway.toml',	"huggingface",	"railway"),
    ('"HF_TOKEN" filename:fly.toml',	"huggingface",	"fly"),
    ('"HF_TOKEN" filename:Procfile',	"huggingface",	"heroku"),
    ('"HF_TOKEN" filename:serverless.yml',	"huggingface",	"serverless"),
    ('"HF_TOKEN" filename:serverless.yaml',	"huggingface",	"serverless"),
    ('"HF_TOKEN" filename:app.yaml',	"huggingface",	"gae"),
    ('"HUGGINGFACE_TOKEN" filename:vercel.json',	"huggingface",	"vercel"),
    ('"HUGGINGFACE_TOKEN" filename:netlify.toml',	"huggingface",	"netlify"),
    ('"HUGGINGFACE_TOKEN" filename:wrangler.toml',	"huggingface",	"wrangler"),
    ('"HUGGINGFACE_TOKEN" filename:railway.toml',	"huggingface",	"railway"),
    ('"HUGGINGFACE_TOKEN" filename:fly.toml',	"huggingface",	"fly"),
    ('"HUGGINGFACE_TOKEN" filename:Procfile',	"huggingface",	"heroku"),
    ('"HUGGINGFACE_TOKEN" filename:serverless.yml',	"huggingface",	"serverless"),
    ('"HUGGINGFACE_TOKEN" filename:serverless.yaml',	"huggingface",	"serverless"),
    ('"HUGGINGFACE_TOKEN" filename:app.yaml',	"huggingface",	"gae"),
    ('"REPLICATE_API_TOKEN" filename:vercel.json',	"replicate",	"vercel"),
    ('"REPLICATE_API_TOKEN" filename:netlify.toml',	"replicate",	"netlify"),
    ('"REPLICATE_API_TOKEN" filename:wrangler.toml',	"replicate",	"wrangler"),
    ('"REPLICATE_API_TOKEN" filename:railway.toml',	"replicate",	"railway"),
    ('"REPLICATE_API_TOKEN" filename:fly.toml',	"replicate",	"fly"),
    ('"REPLICATE_API_TOKEN" filename:Procfile',	"replicate",	"heroku"),
    ('"REPLICATE_API_TOKEN" filename:serverless.yml',	"replicate",	"serverless"),
    ('"REPLICATE_API_TOKEN" filename:serverless.yaml',	"replicate",	"serverless"),
    ('"REPLICATE_API_TOKEN" filename:app.yaml',	"replicate",	"gae"),
    ('"FAL_KEY" filename:vercel.json',	"fal",	"vercel"),
    ('"FAL_KEY" filename:netlify.toml',	"fal",	"netlify"),
    ('"FAL_KEY" filename:wrangler.toml',	"fal",	"wrangler"),
    ('"FAL_KEY" filename:railway.toml',	"fal",	"railway"),
    ('"FAL_KEY" filename:fly.toml',	"fal",	"fly"),
    ('"FAL_KEY" filename:Procfile',	"fal",	"heroku"),
    ('"FAL_KEY" filename:serverless.yml',	"fal",	"serverless"),
    ('"FAL_KEY" filename:serverless.yaml',	"fal",	"serverless"),
    ('"FAL_KEY" filename:app.yaml',	"fal",	"gae"),
    ('"FIREWORKS_API_KEY" filename:vercel.json',	"fireworks",	"vercel"),
    ('"FIREWORKS_API_KEY" filename:netlify.toml',	"fireworks",	"netlify"),
    ('"FIREWORKS_API_KEY" filename:wrangler.toml',	"fireworks",	"wrangler"),
    ('"FIREWORKS_API_KEY" filename:railway.toml',	"fireworks",	"railway"),
    ('"FIREWORKS_API_KEY" filename:fly.toml',	"fireworks",	"fly"),
    ('"FIREWORKS_API_KEY" filename:Procfile',	"fireworks",	"heroku"),
    ('"FIREWORKS_API_KEY" filename:serverless.yml',	"fireworks",	"serverless"),
    ('"FIREWORKS_API_KEY" filename:serverless.yaml',	"fireworks",	"serverless"),
    ('"FIREWORKS_API_KEY" filename:app.yaml',	"fireworks",	"gae"),
    ('"PERPLEXITY_API_KEY" filename:vercel.json',	"perplexity",	"vercel"),
    ('"PERPLEXITY_API_KEY" filename:netlify.toml',	"perplexity",	"netlify"),
    ('"PERPLEXITY_API_KEY" filename:wrangler.toml',	"perplexity",	"wrangler"),
    ('"PERPLEXITY_API_KEY" filename:railway.toml',	"perplexity",	"railway"),
    ('"PERPLEXITY_API_KEY" filename:fly.toml',	"perplexity",	"fly"),
    ('"PERPLEXITY_API_KEY" filename:Procfile',	"perplexity",	"heroku"),
    ('"PERPLEXITY_API_KEY" filename:serverless.yml',	"perplexity",	"serverless"),
    ('"PERPLEXITY_API_KEY" filename:serverless.yaml',	"perplexity",	"serverless"),
    ('"PERPLEXITY_API_KEY" filename:app.yaml',	"perplexity",	"gae"),
    ('"XAI_API_KEY" filename:vercel.json',	"grok",	"vercel"),
    ('"XAI_API_KEY" filename:netlify.toml',	"grok",	"netlify"),
    ('"XAI_API_KEY" filename:wrangler.toml',	"grok",	"wrangler"),
    ('"XAI_API_KEY" filename:railway.toml',	"grok",	"railway"),
    ('"XAI_API_KEY" filename:fly.toml',	"grok",	"fly"),
    ('"XAI_API_KEY" filename:Procfile',	"grok",	"heroku"),
    ('"XAI_API_KEY" filename:serverless.yml',	"grok",	"serverless"),
    ('"XAI_API_KEY" filename:serverless.yaml',	"grok",	"serverless"),
    ('"XAI_API_KEY" filename:app.yaml',	"grok",	"gae"),
    ('"HIGGSFIELD_API_KEY" filename:vercel.json',	"higgsfield",	"vercel"),
    ('"HIGGSFIELD_API_KEY" filename:netlify.toml',	"higgsfield",	"netlify"),
    ('"HIGGSFIELD_API_KEY" filename:wrangler.toml',	"higgsfield",	"wrangler"),
    ('"HIGGSFIELD_API_KEY" filename:railway.toml',	"higgsfield",	"railway"),
    ('"HIGGSFIELD_API_KEY" filename:fly.toml',	"higgsfield",	"fly"),
    ('"HIGGSFIELD_API_KEY" filename:Procfile',	"higgsfield",	"heroku"),
    ('"HIGGSFIELD_API_KEY" filename:serverless.yml',	"higgsfield",	"serverless"),
    ('"HIGGSFIELD_API_KEY" filename:serverless.yaml',	"higgsfield",	"serverless"),
    ('"HIGGSFIELD_API_KEY" filename:app.yaml',	"higgsfield",	"gae"),
    ('"ELEVENLABS_API_KEY" filename:vercel.json',	"elevenlabs",	"vercel"),
    ('"ELEVENLABS_API_KEY" filename:netlify.toml',	"elevenlabs",	"netlify"),
    ('"ELEVENLABS_API_KEY" filename:wrangler.toml',	"elevenlabs",	"wrangler"),
    ('"ELEVENLABS_API_KEY" filename:railway.toml',	"elevenlabs",	"railway"),
    ('"ELEVENLABS_API_KEY" filename:fly.toml',	"elevenlabs",	"fly"),
    ('"ELEVENLABS_API_KEY" filename:Procfile',	"elevenlabs",	"heroku"),
    ('"ELEVENLABS_API_KEY" filename:serverless.yml',	"elevenlabs",	"serverless"),
    ('"ELEVENLABS_API_KEY" filename:serverless.yaml',	"elevenlabs",	"serverless"),
    ('"ELEVENLABS_API_KEY" filename:app.yaml',	"elevenlabs",	"gae"),
    ('"MOONSHOT_API_KEY" filename:vercel.json',	"kimi",	"vercel"),
    ('"MOONSHOT_API_KEY" filename:netlify.toml',	"kimi",	"netlify"),
    ('"MOONSHOT_API_KEY" filename:wrangler.toml',	"kimi",	"wrangler"),
    ('"MOONSHOT_API_KEY" filename:railway.toml',	"kimi",	"railway"),
    ('"MOONSHOT_API_KEY" filename:fly.toml',	"kimi",	"fly"),
    ('"MOONSHOT_API_KEY" filename:Procfile',	"kimi",	"heroku"),
    ('"MOONSHOT_API_KEY" filename:serverless.yml',	"kimi",	"serverless"),
    ('"MOONSHOT_API_KEY" filename:serverless.yaml',	"kimi",	"serverless"),
    ('"MOONSHOT_API_KEY" filename:app.yaml',	"kimi",	"gae"),
    ('"ZHIPUAI_API_KEY" filename:vercel.json',	"glm",	"vercel"),
    ('"ZHIPUAI_API_KEY" filename:netlify.toml',	"glm",	"netlify"),
    ('"ZHIPUAI_API_KEY" filename:wrangler.toml',	"glm",	"wrangler"),
    ('"ZHIPUAI_API_KEY" filename:railway.toml',	"glm",	"railway"),
    ('"ZHIPUAI_API_KEY" filename:fly.toml',	"glm",	"fly"),
    ('"ZHIPUAI_API_KEY" filename:Procfile',	"glm",	"heroku"),
    ('"ZHIPUAI_API_KEY" filename:serverless.yml',	"glm",	"serverless"),
    ('"ZHIPUAI_API_KEY" filename:serverless.yaml',	"glm",	"serverless"),
    ('"ZHIPUAI_API_KEY" filename:app.yaml',	"glm",	"gae"),
    ('"ARK_API_KEY" filename:vercel.json',	"ark",	"vercel"),
    ('"ARK_API_KEY" filename:netlify.toml',	"ark",	"netlify"),
    ('"ARK_API_KEY" filename:wrangler.toml',	"ark",	"wrangler"),
    ('"ARK_API_KEY" filename:railway.toml',	"ark",	"railway"),
    ('"ARK_API_KEY" filename:fly.toml',	"ark",	"fly"),
    ('"ARK_API_KEY" filename:Procfile',	"ark",	"heroku"),
    ('"ARK_API_KEY" filename:serverless.yml',	"ark",	"serverless"),
    ('"ARK_API_KEY" filename:serverless.yaml',	"ark",	"serverless"),
    ('"ARK_API_KEY" filename:app.yaml',	"ark",	"gae"),
    ('"AIMLAPI_API_KEY" filename:vercel.json',	"aimlapi",	"vercel"),
    ('"AIMLAPI_API_KEY" filename:netlify.toml',	"aimlapi",	"netlify"),
    ('"AIMLAPI_API_KEY" filename:wrangler.toml',	"aimlapi",	"wrangler"),
    ('"AIMLAPI_API_KEY" filename:railway.toml',	"aimlapi",	"railway"),
    ('"AIMLAPI_API_KEY" filename:fly.toml',	"aimlapi",	"fly"),
    ('"AIMLAPI_API_KEY" filename:Procfile',	"aimlapi",	"heroku"),
    ('"AIMLAPI_API_KEY" filename:serverless.yml',	"aimlapi",	"serverless"),
    ('"AIMLAPI_API_KEY" filename:serverless.yaml',	"aimlapi",	"serverless"),
    ('"AIMLAPI_API_KEY" filename:app.yaml',	"aimlapi",	"gae"),
    ('"DEEPINFRA_API_KEY" filename:vercel.json',	"deepinfra",	"vercel"),
    ('"DEEPINFRA_API_KEY" filename:netlify.toml',	"deepinfra",	"netlify"),
    ('"DEEPINFRA_API_KEY" filename:wrangler.toml',	"deepinfra",	"wrangler"),
    ('"DEEPINFRA_API_KEY" filename:railway.toml',	"deepinfra",	"railway"),
    ('"DEEPINFRA_API_KEY" filename:fly.toml',	"deepinfra",	"fly"),
    ('"DEEPINFRA_API_KEY" filename:Procfile',	"deepinfra",	"heroku"),
    ('"DEEPINFRA_API_KEY" filename:serverless.yml',	"deepinfra",	"serverless"),
    ('"DEEPINFRA_API_KEY" filename:serverless.yaml',	"deepinfra",	"serverless"),
    ('"DEEPINFRA_API_KEY" filename:app.yaml',	"deepinfra",	"gae"),
    ('"HYPERBOLIC_API_KEY" filename:vercel.json',	"hyperbolic",	"vercel"),
    ('"HYPERBOLIC_API_KEY" filename:netlify.toml',	"hyperbolic",	"netlify"),
    ('"HYPERBOLIC_API_KEY" filename:wrangler.toml',	"hyperbolic",	"wrangler"),
    ('"HYPERBOLIC_API_KEY" filename:railway.toml',	"hyperbolic",	"railway"),
    ('"HYPERBOLIC_API_KEY" filename:fly.toml',	"hyperbolic",	"fly"),
    ('"HYPERBOLIC_API_KEY" filename:Procfile',	"hyperbolic",	"heroku"),
    ('"HYPERBOLIC_API_KEY" filename:serverless.yml',	"hyperbolic",	"serverless"),
    ('"HYPERBOLIC_API_KEY" filename:serverless.yaml',	"hyperbolic",	"serverless"),
    ('"HYPERBOLIC_API_KEY" filename:app.yaml',	"hyperbolic",	"gae"),
    ('"NOVITA_API_KEY" filename:vercel.json',	"novita",	"vercel"),
    ('"NOVITA_API_KEY" filename:netlify.toml',	"novita",	"netlify"),
    ('"NOVITA_API_KEY" filename:wrangler.toml',	"novita",	"wrangler"),
    ('"NOVITA_API_KEY" filename:railway.toml',	"novita",	"railway"),
    ('"NOVITA_API_KEY" filename:fly.toml',	"novita",	"fly"),
    ('"NOVITA_API_KEY" filename:Procfile',	"novita",	"heroku"),
    ('"NOVITA_API_KEY" filename:serverless.yml',	"novita",	"serverless"),
    ('"NOVITA_API_KEY" filename:serverless.yaml',	"novita",	"serverless"),
    ('"NOVITA_API_KEY" filename:app.yaml',	"novita",	"gae"),
    ('"OPENAI_API_KEY" filename:.envrc',	"openai",	"envrc"),
    ('"OPENAI_API_KEY" filename:.zshrc',	"openai",	"zshrc"),
    ('"OPENAI_API_KEY" filename:.bashrc',	"openai",	"bashrc"),
    ('"OPENAI_API_KEY" filename:.bash_profile',	"openai",	"bashrc"),
    ('"OPENAI_API_KEY" filename:.profile',	"openai",	"profile"),
    ('"ANTHROPIC_API_KEY" filename:.envrc',	"anthropic",	"envrc"),
    ('"ANTHROPIC_API_KEY" filename:.zshrc',	"anthropic",	"zshrc"),
    ('"ANTHROPIC_API_KEY" filename:.bashrc',	"anthropic",	"bashrc"),
    ('"ANTHROPIC_API_KEY" filename:.bash_profile',	"anthropic",	"bashrc"),
    ('"ANTHROPIC_API_KEY" filename:.profile',	"anthropic",	"profile"),
    ('"GOOGLE_API_KEY" filename:.envrc',	"google",	"envrc"),
    ('"GOOGLE_API_KEY" filename:.zshrc',	"google",	"zshrc"),
    ('"GOOGLE_API_KEY" filename:.bashrc',	"google",	"bashrc"),
    ('"GOOGLE_API_KEY" filename:.bash_profile',	"google",	"bashrc"),
    ('"GOOGLE_API_KEY" filename:.profile',	"google",	"profile"),
    ('"GEMINI_API_KEY" filename:.envrc',	"google",	"envrc"),
    ('"GEMINI_API_KEY" filename:.zshrc',	"google",	"zshrc"),
    ('"GEMINI_API_KEY" filename:.bashrc',	"google",	"bashrc"),
    ('"GEMINI_API_KEY" filename:.bash_profile',	"google",	"bashrc"),
    ('"GEMINI_API_KEY" filename:.profile',	"google",	"profile"),
    ('"DEEPSEEK_API_KEY" filename:.envrc',	"deepseek",	"envrc"),
    ('"DEEPSEEK_API_KEY" filename:.zshrc',	"deepseek",	"zshrc"),
    ('"DEEPSEEK_API_KEY" filename:.bashrc',	"deepseek",	"bashrc"),
    ('"DEEPSEEK_API_KEY" filename:.bash_profile',	"deepseek",	"bashrc"),
    ('"DEEPSEEK_API_KEY" filename:.profile',	"deepseek",	"profile"),
    ('"OPENROUTER_API_KEY" filename:.envrc',	"openrouter",	"envrc"),
    ('"OPENROUTER_API_KEY" filename:.zshrc',	"openrouter",	"zshrc"),
    ('"OPENROUTER_API_KEY" filename:.bashrc',	"openrouter",	"bashrc"),
    ('"OPENROUTER_API_KEY" filename:.bash_profile',	"openrouter",	"bashrc"),
    ('"OPENROUTER_API_KEY" filename:.profile',	"openrouter",	"profile"),
    ('"HF_TOKEN" filename:.envrc',	"huggingface",	"envrc"),
    ('"HF_TOKEN" filename:.zshrc',	"huggingface",	"zshrc"),
    ('"HF_TOKEN" filename:.bashrc',	"huggingface",	"bashrc"),
    ('"HF_TOKEN" filename:.bash_profile',	"huggingface",	"bashrc"),
    ('"HF_TOKEN" filename:.profile',	"huggingface",	"profile"),
    ('"HUGGINGFACE_TOKEN" filename:.envrc',	"huggingface",	"envrc"),
    ('"HUGGINGFACE_TOKEN" filename:.zshrc',	"huggingface",	"zshrc"),
    ('"HUGGINGFACE_TOKEN" filename:.bashrc',	"huggingface",	"bashrc"),
    ('"HUGGINGFACE_TOKEN" filename:.bash_profile',	"huggingface",	"bashrc"),
    ('"HUGGINGFACE_TOKEN" filename:.profile',	"huggingface",	"profile"),
    ('"REPLICATE_API_TOKEN" filename:.envrc',	"replicate",	"envrc"),
    ('"REPLICATE_API_TOKEN" filename:.zshrc',	"replicate",	"zshrc"),
    ('"REPLICATE_API_TOKEN" filename:.bashrc',	"replicate",	"bashrc"),
    ('"REPLICATE_API_TOKEN" filename:.bash_profile',	"replicate",	"bashrc"),
    ('"REPLICATE_API_TOKEN" filename:.profile',	"replicate",	"profile"),
    ('"FAL_KEY" filename:.envrc',	"fal",	"envrc"),
    ('"FAL_KEY" filename:.zshrc',	"fal",	"zshrc"),
    ('"FAL_KEY" filename:.bashrc',	"fal",	"bashrc"),
    ('"FAL_KEY" filename:.bash_profile',	"fal",	"bashrc"),
    ('"FAL_KEY" filename:.profile',	"fal",	"profile"),
    ('"OPENAI_API_KEY" filename:.streamlit/secrets.toml',	"openai",	"streamlit"),
    ('"OPENAI_API_KEY" filename:streamlit_app.py',	"openai",	"streamlit"),
    ('"OPENAI_API_KEY" filename:gradio_app.py',	"openai",	"gradio"),
    ('"ANTHROPIC_API_KEY" filename:.streamlit/secrets.toml',	"anthropic",	"streamlit"),
    ('"ANTHROPIC_API_KEY" filename:streamlit_app.py',	"anthropic",	"streamlit"),
    ('"ANTHROPIC_API_KEY" filename:gradio_app.py',	"anthropic",	"gradio"),
    ('"GOOGLE_API_KEY" filename:.streamlit/secrets.toml',	"google",	"streamlit"),
    ('"GOOGLE_API_KEY" filename:streamlit_app.py',	"google",	"streamlit"),
    ('"GOOGLE_API_KEY" filename:gradio_app.py',	"google",	"gradio"),
    ('"GEMINI_API_KEY" filename:.streamlit/secrets.toml',	"google",	"streamlit"),
    ('"GEMINI_API_KEY" filename:streamlit_app.py',	"google",	"streamlit"),
    ('"GEMINI_API_KEY" filename:gradio_app.py',	"google",	"gradio"),
    ('"DEEPSEEK_API_KEY" filename:.streamlit/secrets.toml',	"deepseek",	"streamlit"),
    ('"DEEPSEEK_API_KEY" filename:streamlit_app.py',	"deepseek",	"streamlit"),
    ('"DEEPSEEK_API_KEY" filename:gradio_app.py',	"deepseek",	"gradio"),
    ('"OPENROUTER_API_KEY" filename:.streamlit/secrets.toml',	"openrouter",	"streamlit"),
    ('"OPENROUTER_API_KEY" filename:streamlit_app.py',	"openrouter",	"streamlit"),
    ('"OPENROUTER_API_KEY" filename:gradio_app.py',	"openrouter",	"gradio"),
    ('"HF_TOKEN" filename:.streamlit/secrets.toml',	"huggingface",	"streamlit"),
    ('"HF_TOKEN" filename:streamlit_app.py',	"huggingface",	"streamlit"),
    ('"HF_TOKEN" filename:gradio_app.py',	"huggingface",	"gradio"),
    ('"HUGGINGFACE_TOKEN" filename:.streamlit/secrets.toml',	"huggingface",	"streamlit"),
    ('"HUGGINGFACE_TOKEN" filename:streamlit_app.py',	"huggingface",	"streamlit"),
    ('"HUGGINGFACE_TOKEN" filename:gradio_app.py',	"huggingface",	"gradio"),
    ('"REPLICATE_API_TOKEN" filename:.streamlit/secrets.toml',	"replicate",	"streamlit"),
    ('"REPLICATE_API_TOKEN" filename:streamlit_app.py',	"replicate",	"streamlit"),
    ('"REPLICATE_API_TOKEN" filename:gradio_app.py',	"replicate",	"gradio"),
    ('"FAL_KEY" filename:.streamlit/secrets.toml',	"fal",	"streamlit"),
    ('"FAL_KEY" filename:streamlit_app.py',	"fal",	"streamlit"),
    ('"FAL_KEY" filename:gradio_app.py',	"fal",	"gradio"),
    ('"OPENAI_API_KEY" filename:.gitlab-ci.yml',	"openai",	"gitlab_ci"),
    ('"OPENAI_API_KEY" filename:.travis.yml',	"openai",	"travis"),
    ('"OPENAI_API_KEY" filename:.circleci/config.yml',	"openai",	"circleci"),
    ('"OPENAI_API_KEY" filename:bitbucket-pipelines.yml',	"openai",	"bb_pipelines"),
    ('"OPENAI_API_KEY" filename:azure-pipelines.yml',	"openai",	"azure_pipelines"),
    ('"ANTHROPIC_API_KEY" filename:.gitlab-ci.yml',	"anthropic",	"gitlab_ci"),
    ('"ANTHROPIC_API_KEY" filename:.travis.yml',	"anthropic",	"travis"),
    ('"ANTHROPIC_API_KEY" filename:.circleci/config.yml',	"anthropic",	"circleci"),
    ('"ANTHROPIC_API_KEY" filename:bitbucket-pipelines.yml',	"anthropic",	"bb_pipelines"),
    ('"ANTHROPIC_API_KEY" filename:azure-pipelines.yml',	"anthropic",	"azure_pipelines"),
    ('"GOOGLE_API_KEY" filename:.gitlab-ci.yml',	"google",	"gitlab_ci"),
    ('"GOOGLE_API_KEY" filename:.travis.yml',	"google",	"travis"),
    ('"GOOGLE_API_KEY" filename:.circleci/config.yml',	"google",	"circleci"),
    ('"GOOGLE_API_KEY" filename:bitbucket-pipelines.yml',	"google",	"bb_pipelines"),
    ('"GOOGLE_API_KEY" filename:azure-pipelines.yml',	"google",	"azure_pipelines"),
    ('"GEMINI_API_KEY" filename:.gitlab-ci.yml',	"google",	"gitlab_ci"),
    ('"GEMINI_API_KEY" filename:.travis.yml',	"google",	"travis"),
    ('"GEMINI_API_KEY" filename:.circleci/config.yml',	"google",	"circleci"),
    ('"GEMINI_API_KEY" filename:bitbucket-pipelines.yml',	"google",	"bb_pipelines"),
    ('"GEMINI_API_KEY" filename:azure-pipelines.yml',	"google",	"azure_pipelines"),
    ('"DEEPSEEK_API_KEY" filename:.gitlab-ci.yml',	"deepseek",	"gitlab_ci"),
    ('"DEEPSEEK_API_KEY" filename:.travis.yml',	"deepseek",	"travis"),
    ('"DEEPSEEK_API_KEY" filename:.circleci/config.yml',	"deepseek",	"circleci"),
    ('"DEEPSEEK_API_KEY" filename:bitbucket-pipelines.yml',	"deepseek",	"bb_pipelines"),
    ('"DEEPSEEK_API_KEY" filename:azure-pipelines.yml',	"deepseek",	"azure_pipelines"),
    ('"OPENROUTER_API_KEY" filename:.gitlab-ci.yml',	"openrouter",	"gitlab_ci"),
    ('"OPENROUTER_API_KEY" filename:.travis.yml',	"openrouter",	"travis"),
    ('"OPENROUTER_API_KEY" filename:.circleci/config.yml',	"openrouter",	"circleci"),
    ('"OPENROUTER_API_KEY" filename:bitbucket-pipelines.yml',	"openrouter",	"bb_pipelines"),
    ('"OPENROUTER_API_KEY" filename:azure-pipelines.yml',	"openrouter",	"azure_pipelines"),
    ('"HF_TOKEN" filename:.gitlab-ci.yml',	"huggingface",	"gitlab_ci"),
    ('"HF_TOKEN" filename:.travis.yml',	"huggingface",	"travis"),
    ('"HF_TOKEN" filename:.circleci/config.yml',	"huggingface",	"circleci"),
    ('"HF_TOKEN" filename:bitbucket-pipelines.yml',	"huggingface",	"bb_pipelines"),
    ('"HF_TOKEN" filename:azure-pipelines.yml',	"huggingface",	"azure_pipelines"),
    ('"HUGGINGFACE_TOKEN" filename:.gitlab-ci.yml',	"huggingface",	"gitlab_ci"),
    ('"HUGGINGFACE_TOKEN" filename:.travis.yml',	"huggingface",	"travis"),
    ('"HUGGINGFACE_TOKEN" filename:.circleci/config.yml',	"huggingface",	"circleci"),
    ('"HUGGINGFACE_TOKEN" filename:bitbucket-pipelines.yml',	"huggingface",	"bb_pipelines"),
    ('"HUGGINGFACE_TOKEN" filename:azure-pipelines.yml',	"huggingface",	"azure_pipelines"),
    ('"REPLICATE_API_TOKEN" filename:.gitlab-ci.yml',	"replicate",	"gitlab_ci"),
    ('"REPLICATE_API_TOKEN" filename:.travis.yml',	"replicate",	"travis"),
    ('"REPLICATE_API_TOKEN" filename:.circleci/config.yml',	"replicate",	"circleci"),
    ('"REPLICATE_API_TOKEN" filename:bitbucket-pipelines.yml',	"replicate",	"bb_pipelines"),
    ('"REPLICATE_API_TOKEN" filename:azure-pipelines.yml',	"replicate",	"azure_pipelines"),
    ('"FAL_KEY" filename:.gitlab-ci.yml',	"fal",	"gitlab_ci"),
    ('"FAL_KEY" filename:.travis.yml',	"fal",	"travis"),
    ('"FAL_KEY" filename:.circleci/config.yml',	"fal",	"circleci"),
    ('"FAL_KEY" filename:bitbucket-pipelines.yml',	"fal",	"bb_pipelines"),
    ('"FAL_KEY" filename:azure-pipelines.yml',	"fal",	"azure_pipelines"),
    ('"OPENAI_API_KEY" language:ruby',	"openai",	"code"),
    ('"OPENAI_API_KEY" language:kotlin',	"openai",	"code"),
    ('"OPENAI_API_KEY" language:scala',	"openai",	"code"),
    ('"OPENAI_API_KEY" language:lua',	"openai",	"code"),
    ('"OPENAI_API_KEY" language:elixir',	"openai",	"code"),
    ('"OPENAI_API_KEY" language:dart',	"openai",	"code"),
    ('"ANTHROPIC_API_KEY" language:ruby',	"anthropic",	"code"),
    ('"ANTHROPIC_API_KEY" language:kotlin',	"anthropic",	"code"),
    ('"ANTHROPIC_API_KEY" language:scala',	"anthropic",	"code"),
    ('"ANTHROPIC_API_KEY" language:lua',	"anthropic",	"code"),
    ('"ANTHROPIC_API_KEY" language:elixir',	"anthropic",	"code"),
    ('"ANTHROPIC_API_KEY" language:dart',	"anthropic",	"code"),
    ('"GOOGLE_API_KEY" language:ruby',	"google",	"code"),
    ('"GOOGLE_API_KEY" language:kotlin',	"google",	"code"),
    ('"GOOGLE_API_KEY" language:scala',	"google",	"code"),
    ('"GOOGLE_API_KEY" language:lua',	"google",	"code"),
    ('"GOOGLE_API_KEY" language:elixir',	"google",	"code"),
    ('"GOOGLE_API_KEY" language:dart',	"google",	"code"),
    ('"GEMINI_API_KEY" language:ruby',	"google",	"code"),
    ('"GEMINI_API_KEY" language:kotlin',	"google",	"code"),
    ('"GEMINI_API_KEY" language:scala',	"google",	"code"),
    ('"GEMINI_API_KEY" language:lua',	"google",	"code"),
    ('"GEMINI_API_KEY" language:elixir',	"google",	"code"),
    ('"GEMINI_API_KEY" language:dart',	"google",	"code"),
    ('"DEEPSEEK_API_KEY" language:ruby',	"deepseek",	"code"),
    ('"DEEPSEEK_API_KEY" language:kotlin',	"deepseek",	"code"),
    ('"DEEPSEEK_API_KEY" language:scala',	"deepseek",	"code"),
    ('"DEEPSEEK_API_KEY" language:lua',	"deepseek",	"code"),
    ('"DEEPSEEK_API_KEY" language:elixir',	"deepseek",	"code"),
    ('"DEEPSEEK_API_KEY" language:dart',	"deepseek",	"code"),
    ('"OPENROUTER_API_KEY" language:ruby',	"openrouter",	"code"),
    ('"OPENROUTER_API_KEY" language:kotlin',	"openrouter",	"code"),
    ('"OPENROUTER_API_KEY" language:scala',	"openrouter",	"code"),
    ('"OPENROUTER_API_KEY" language:lua',	"openrouter",	"code"),
    ('"OPENROUTER_API_KEY" language:elixir',	"openrouter",	"code"),
    ('"OPENROUTER_API_KEY" language:dart',	"openrouter",	"code"),
    ('"OPENAI_API_KEY" filename:pyproject.toml',	"openai",	"deps"),
    ('"OPENAI_API_KEY" filename:Cargo.toml',	"openai",	"deps"),
    ('"OPENAI_API_KEY" filename:composer.json',	"openai",	"deps"),
    ('"OPENAI_API_KEY" filename:pubspec.yaml',	"openai",	"deps"),
    ('"ANTHROPIC_API_KEY" filename:pyproject.toml',	"anthropic",	"deps"),
    ('"ANTHROPIC_API_KEY" filename:Cargo.toml',	"anthropic",	"deps"),
    ('"ANTHROPIC_API_KEY" filename:composer.json',	"anthropic",	"deps"),
    ('"ANTHROPIC_API_KEY" filename:pubspec.yaml',	"anthropic",	"deps"),
    ('"GOOGLE_API_KEY" filename:pyproject.toml',	"google",	"deps"),
    ('"GOOGLE_API_KEY" filename:Cargo.toml',	"google",	"deps"),
    ('"GOOGLE_API_KEY" filename:composer.json',	"google",	"deps"),
    ('"GOOGLE_API_KEY" filename:pubspec.yaml',	"google",	"deps"),
    ('"GEMINI_API_KEY" filename:pyproject.toml',	"google",	"deps"),
    ('"GEMINI_API_KEY" filename:Cargo.toml',	"google",	"deps"),
    ('"GEMINI_API_KEY" filename:composer.json',	"google",	"deps"),
    ('"GEMINI_API_KEY" filename:pubspec.yaml',	"google",	"deps"),
    ('"sk-proj-" filename:.cursor/mcp.json',	"openai",	"cursor_mcp"),
    ('"sk-ant-api03-" filename:.cursor/mcp.json',	"anthropic",	"cursor_mcp"),
    ('"sk-or-v1-" filename:.cursor/mcp.json',	"openrouter",	"cursor_mcp"),
    ('"sk-proj-" filename:claude_desktop_config.json',	"openai",	"claude_desktop"),
    ('"sk-ant-api03-" filename:claude_desktop_config.json',	"anthropic",	"claude_desktop"),
    ('"sk-or-v1-" filename:litellm_config.yaml',	"openrouter",	"litellm"),
    ('"sk-proj-" filename:litellm_config.yaml',	"openai",	"litellm"),
    ('"sk-ant-api03-" filename:litellm_config.yaml',	"anthropic",	"litellm"),
    ('"AIzaSy" filename:.cursor/mcp.json',	"google",	"cursor_mcp"),
    ('"AIzaSy" filename:claude_desktop_config.json',	"google",	"claude_desktop"),
    ('"hf_" filename:litellm_config.yaml',	"huggingface",	"litellm"),
    ('"r8_" filename:litellm_config.yaml',	"replicate",	"litellm"),
    ('"fw_" filename:litellm_config.yaml',	"fireworks",	"litellm"),
    ('"xai-" filename:.cursor/mcp.json',	"grok",	"cursor_mcp"),
    ('"OPENAI_API_KEY" path:mcp-servers',	"openai",	"mcp_dir"),
    ('"ANTHROPIC_API_KEY" path:mcp-servers',	"anthropic",	"mcp_dir"),
    ('"OPENAI_API_KEY" path:.crewai',	"openai",	"crewai"),
    ('"ANTHROPIC_API_KEY" path:.crewai',	"anthropic",	"crewai"),
    ('"OPENAI_API_KEY" filename:autogen_config.json',	"openai",	"autogen"),

    # ─────────────────────────────────────────────────────────────────────
    # Bootcamp / course / hackathon templates (proven yield 2026-05-03:
    # 2/2 hits in 10academy template-fork audit; both students leaked
    # GEMINI + AIMLAPI in identical .env.example structure).
    # ─────────────────────────────────────────────────────────────────────
    ('"AIMLAPI_KEY" "KLINGAI_API_KEY" filename:.env.example',	"aimlapi",	"10academy_template"),
    ('"AIMLAPI_KEY" "GEMINI_API_KEY" filename:.env.example',	"aimlapi",	"bootcamp_template"),
    ('"AIMLAPI_KEY" "GEMINI_API_KEY" filename:.env',	"aimlapi",	"bootcamp_env"),
    ('"AIMLAPI_KEY" filename:.env.example',	"aimlapi",	"env_example"),
    ('"AIMLAPI_KEY" filename:.env.template',	"aimlapi",	"env_template"),
    ('"GEMINI_API_KEY" filename:.env.example',	"google",	"env_example"),
    ('"GEMINI_API_KEY" filename:.env.template',	"google",	"env_template"),
    ('"OPENAI_API_KEY" "AIMLAPI_KEY" filename:.env',	"openai",	"multi_provider_template"),
    ('"OPENAI_API_KEY" "GEMINI_API_KEY" filename:.env.example',	"openai",	"bootcamp_multi"),
    ('"week0" "OPENAI_API_KEY" filename:.env',	"openai",	"course_week0"),
    ('"week_0" "OPENAI_API_KEY" filename:.env',	"openai",	"course_week0"),
    ('"week0" "GEMINI_API_KEY" filename:.env',	"google",	"course_week0"),
    ('"bootcamp" "OPENAI_API_KEY" filename:.env',	"openai",	"bootcamp_env"),
    ('"hackathon" "OPENAI_API_KEY" filename:.env',	"openai",	"hackathon"),
    ('"capstone" "OPENAI_API_KEY" filename:.env',	"openai",	"capstone"),
    ('"submission" "OPENAI_API_KEY" filename:.env',	"openai",	"course_submission"),

    # ─────────────────────────────────────────────────────────────────────
    # LLM aggregator / proxy / multi-provider chat UI projects (highest
    # density of keys per repo; one repo can yield 50+ keys).
    # ─────────────────────────────────────────────────────────────────────
    ('"model_list:" filename:litellm_config.yaml',	"openai",	"litellm_proxy"),
    ('"model_list:" filename:litellm_config.yaml',	"anthropic",	"litellm_proxy"),
    ('"model_list:" filename:litellm_config.yaml',	"google",	"litellm_proxy"),
    ('"OPENAI_API_KEYS" filename:.env',	"openai",	"key_pool"),
    ('"ANTHROPIC_API_KEYS" filename:.env',	"anthropic",	"key_pool"),
    ('"NEXT_PUBLIC_OPENAI_API_KEY" filename:.env',	"openai",	"nextchat"),
    ('"OPENAI_API_KEY" "ANTHROPIC_API_KEY" "GOOGLE_API_KEY" filename:.env',	"openai",	"multi_provider_chat"),
    ('"OPENAI_API_KEY" "ANTHROPIC_API_KEY" "GROQ_API_KEY" filename:.env',	"openai",	"multi_provider_chat"),
    ('"lobe-chat" filename:.env',	"openai",	"lobechat"),
    ('"open-webui" filename:.env',	"openai",	"openwebui"),
    ('"anythingllm" filename:.env',	"openai",	"anythingllm"),
    ('"librechat" filename:.env',	"openai",	"librechat"),
    ('"big-AGI" filename:.env',	"openai",	"bigagi"),
    ('"chatgpt-next-web" filename:.env',	"openai",	"chatgpt_next_web"),
    ('"helicone" filename:.env',	"openai",	"helicone"),
    ('"portkey" filename:.env',	"openai",	"portkey"),
    # Agent frameworks (each = many tool keys at once)
    ('"langchain" "TAVILY_API_KEY" "OPENAI_API_KEY" filename:.env',	"openai",	"langchain_agent"),
    ('"crewai" "OPENAI_API_KEY" filename:.env',	"openai",	"crewai_env"),
    ('"langgraph" "OPENAI_API_KEY" filename:.env',	"openai",	"langgraph"),
    ('"smolagents" "OPENAI_API_KEY" filename:.env',	"openai",	"smolagents"),
    # RAG / vector DB starter kits
    ('"PINECONE_API_KEY" "OPENAI_API_KEY" filename:.env',	"openai",	"rag_pinecone"),
    ('"WEAVIATE_API_KEY" "OPENAI_API_KEY" filename:.env',	"openai",	"rag_weaviate"),
    ('"QDRANT_API_KEY" "OPENAI_API_KEY" filename:.env',	"openai",	"rag_qdrant"),
    # Discord/TG/Slack AI bots (BOT_TOKEN + LLM key)
    ('"DISCORD_TOKEN" "OPENAI_API_KEY" filename:.env',	"openai",	"discord_bot"),
    ('"TELEGRAM_BOT_TOKEN" "OPENAI_API_KEY" filename:.env',	"openai",	"telegram_bot"),
    ('"SLACK_BOT_TOKEN" "OPENAI_API_KEY" filename:.env',	"openai",	"slack_bot"),

    # ─────────────────────────────────────────────────────────────────────
    # Markdown coverage (~12% of leaks live in .md files — internal docs,
    # CONFIG_REPORT.md, migration_*.md, memory/*.md). Currently 0 of our
    # queries use extension:md. Adding targeted top-yield providers.
    # ─────────────────────────────────────────────────────────────────────
    ('"OPENAI_API_KEY" extension:md',	"openai",	"markdown"),
    ('"sk-proj-" extension:md',	"openai",	"markdown"),
    ('"ANTHROPIC_API_KEY" extension:md',	"anthropic",	"markdown"),
    ('"sk-ant-api03-" extension:md',	"anthropic",	"markdown"),
    ('"GOOGLE_API_KEY" extension:md',	"google",	"markdown"),
    ('"GEMINI_API_KEY" extension:md',	"google",	"markdown"),
    ('"OPENROUTER_API_KEY" extension:md',	"openrouter",	"markdown"),
    ('"sk-or-v1-" extension:md',	"openrouter",	"markdown"),
    ('"DEEPSEEK_API_KEY" extension:md',	"deepseek",	"markdown"),
    ('"MOONSHOT_API_KEY" extension:md',	"kimi",	"markdown"),
    ('"KIMI_API_KEY" extension:md',	"kimi",	"markdown"),
    ('"ZHIPUAI_API_KEY" extension:md',	"glm",	"markdown"),
    ('"REPLICATE_API_TOKEN" extension:md',	"replicate",	"markdown"),
    ('"FAL_KEY" extension:md',	"fal",	"markdown"),
    ('"HF_TOKEN" extension:md',	"huggingface",	"markdown"),
    ('"HUGGINGFACE_TOKEN" extension:md',	"huggingface",	"markdown"),
    ('"hf_" extension:md',	"huggingface",	"markdown"),
    ('"AIMLAPI_KEY" extension:md',	"aimlapi",	"markdown"),
    ('"AIMLAPI_API_KEY" extension:md',	"aimlapi",	"markdown"),

    # ── Markdown expansion 2026-05-06 (path showed 60% conv, undertapped) ──
    # AI text providers
    ('"GROQ_API_KEY" extension:md',	"grok",	"markdown"),
    ('"gsk_" extension:md',	"grok",	"markdown"),
    ('"XAI_API_KEY" extension:md',	"grok",	"markdown"),
    ('"xai-" extension:md',	"grok",	"markdown"),
    ('"PERPLEXITY_API_KEY" extension:md',	"perplexity",	"markdown"),
    ('"pplx-" extension:md',	"perplexity",	"markdown"),
    ('"MISTRAL_API_KEY" extension:md',	"openai",	"markdown"),
    ('"COHERE_API_KEY" extension:md',	"openai",	"markdown"),
    ('"TOGETHER_API_KEY" extension:md',	"openai",	"markdown"),
    ('"FIREWORKS_API_KEY" extension:md',	"fireworks",	"markdown"),
    ('"OPENROUTER_API_KEY" extension:md',	"openrouter",	"markdown"),
    # CN providers (highest under-coverage)
    ('"ARK_API_KEY" extension:md',	"ark",	"markdown"),
    ('"DOUBAO_API_KEY" extension:md',	"ark",	"markdown"),
    ('"VOLC_ACCESSKEY" extension:md',	"ark",	"markdown"),
    ('"GLM_API_KEY" extension:md',	"glm",	"markdown"),
    ('"BIGMODEL_API_KEY" extension:md',	"glm",	"markdown"),
    ('"DASHSCOPE_API_KEY" extension:md',	"openai",	"markdown"),
    ('"QWEN_API_KEY" extension:md',	"openai",	"markdown"),
    ('"SILICONFLOW_API_KEY" extension:md',	"siliconflow",	"markdown"),
    ('"KLING_ACCESS_KEY" extension:md',	"kling",	"markdown"),
    ('"KLING_SECRET_KEY" extension:md',	"kling",	"markdown"),
    # Aggregators
    ('"DEEPINFRA_TOKEN" extension:md',	"deepinfra",	"markdown"),
    ('"HYPERBOLIC_API_KEY" extension:md',	"hyperbolic",	"markdown"),
    ('"NOVITA_API_KEY" extension:md',	"novita",	"markdown"),
    ('"PORTKEY_API_KEY" extension:md',	"portkey",	"markdown"),
    # Voice / video / image
    ('"ELEVENLABS_API_KEY" extension:md',	"elevenlabs",	"markdown"),
    ('"XI_API_KEY" extension:md',	"elevenlabs",	"markdown"),
    ('"INWORLD_BASE64" extension:md',	"inworld",	"markdown"),
    ('"INWORLD_AUTH" extension:md',	"inworld",	"markdown"),
    ('"WAVESPEED_API_KEY" extension:md',	"wavespeed",	"markdown"),
    ('"HEDRA_API_KEY" extension:md',	"hedra",	"markdown"),
    ('"KREA_API_KEY" extension:md',	"krea",	"markdown"),
    ('"PIXVERSE_API_KEY" extension:md',	"pixverse",	"markdown"),
    ('"HIGGSFIELD_API_KEY" extension:md',	"higgsfield",	"markdown"),
    ('"HIGGSFIELD_KEY" extension:md',	"higgsfield",	"markdown"),
    ('"HAPPY_HORSE_API_KEY" extension:md',	"happyhorse",	"markdown"),
    ('"RUNHAPPYHORSE_API_KEY" extension:md',	"happyhorse",	"markdown"),
    # Tools
    ('"FIRECRAWL_API_KEY" extension:md',	"firecrawl",	"markdown"),
    # Replit
    ('"REPLIT_DB_URL" extension:md',	"replit",	"markdown"),
    ('"REPLIT_API_TOKEN" extension:md',	"replit",	"markdown"),
    # Infra creds in markdown — very common in deploy guides
    ('"DATABASE_URL=postgres" extension:md',	"infra",	"markdown"),
    ('"DATABASE_URL=mysql" extension:md',	"infra",	"markdown"),
    ('"MONGODB_URI=mongodb" extension:md',	"infra",	"markdown"),
    ('"REDIS_URL=redis" extension:md',	"infra",	"markdown"),
    ('"AKIA" extension:md',	"infra",	"markdown"),
    ('"SUPABASE_KEY" extension:md',	"infra",	"markdown"),
    ('"SUPABASE_URL" extension:md',	"infra",	"markdown"),
    ('"PINECONE_API_KEY" extension:md',	"infra",	"markdown"),
    ('"STRIPE_SECRET_KEY" extension:md',	"infra",	"markdown"),
    ('"DISCORD_TOKEN" extension:md',	"infra",	"markdown"),
    ('"TELEGRAM_BOT_TOKEN" extension:md',	"infra",	"markdown"),
    ('"TWILIO_AUTH_TOKEN" extension:md',	"infra",	"markdown"),
    ('"SENDGRID_API_KEY" extension:md',	"infra",	"markdown"),
    # Niche docs paths
    ('"OPENAI_API_KEY" path:docs filename:configuration.md',	"openai",	"docs_dir"),
    ('"OPENAI_API_KEY" path:docs/setup',	"openai",	"docs_dir"),
    ('"OPENAI_API_KEY" filename:GETTING_STARTED.md',	"openai",	"setup_md"),
    ('"OPENAI_API_KEY" filename:DEPLOYMENT.md',	"openai",	"setup_md"),
    ('"OPENAI_API_KEY" filename:CONTRIBUTING.md',	"openai",	"docs_dir"),
    ('"GEMINI_API_KEY" path:docs',	"google",	"docs_dir"),
    ('"DEEPSEEK_API_KEY" path:docs',	"deepseek",	"docs_dir"),
    ('"sk-ant-api03-" path:docs',	"anthropic",	"docs_dir"),
    # README — most common "I added a tutorial" file
    ('"OPENAI_API_KEY" filename:README.md',	"openai",	"readme_md"),
    ('"sk-proj-" filename:README.md',	"openai",	"readme_md"),
    ('"ANTHROPIC_API_KEY" filename:README.md',	"anthropic",	"readme_md"),
    ('"GEMINI_API_KEY" filename:README.md',	"google",	"readme_md"),
    ('"DEEPSEEK_API_KEY" filename:README.md',	"deepseek",	"readme_md"),
    ('"REPLICATE_API_TOKEN" filename:README.md',	"replicate",	"readme_md"),
    ('"HF_TOKEN" filename:README.md',	"huggingface",	"readme_md"),
    ('"GROQ_API_KEY" filename:README.md',	"grok",	"readme_md"),

    # Filename-targeted high-density doc files
    ('"sk-proj-" filename:CONFIG_REPORT.md',	"openai",	"config_report_md"),
    ('"OPENAI_API_KEY" filename:CONFIG_REPORT.md',	"openai",	"config_report_md"),
    ('"OPENAI_API_KEY" filename:SETUP.md',	"openai",	"setup_md"),
    ('"OPENAI_API_KEY" filename:INSTALL.md',	"openai",	"install_md"),
    ('"OPENAI_API_KEY" filename:migration.md',	"openai",	"migration_md"),
    ('"ANTHROPIC_API_KEY" filename:CONFIG_REPORT.md',	"anthropic",	"config_report_md"),
    ('"GEMINI_API_KEY" filename:SETUP.md',	"google",	"setup_md"),
    ('"OPENAI_API_KEY" path:docs',	"openai",	"docs_dir"),
    ('"OPENAI_API_KEY" path:memory',	"openai",	"memory_dir"),

    # ─────────────────────────────────────────────────────────────────────
    # New providers (2026-05): Commonstack / Serper / Stability / Luma /
    # Pika / TwelveLabs. Each ships ~10 targeted queries by env var name,
    # domain, key prefix, file location.
    # ─────────────────────────────────────────────────────────────────────
    # Commonstack — Claude/GPT/DeepSeek/Kimi/GLM aggregator
    ('"COMMONSTACK_API_KEY" filename:.env',	"commonstack",	"env"),
    ('"COMMONSTACK_API_KEY" language:python',	"commonstack",	"code"),
    ('"COMMONSTACK_API_KEY" language:javascript',	"commonstack",	"code"),
    ('"COMMONSTACK_API_KEY" language:typescript',	"commonstack",	"code"),
    ('"api.commonstack.ai" language:python',	"commonstack",	"code"),
    ('"api.commonstack.ai" language:javascript',	"commonstack",	"code"),
    ('"COMMONSTACK_API_KEY" extension:ipynb',	"commonstack",	"notebook"),
    ('"api.commonstack.ai" extension:ipynb',	"commonstack",	"notebook"),
    ('"COMMONSTACK_API_KEY" filename:litellm_config.yaml',	"commonstack",	"litellm"),
    ('"COMMONSTACK_API_KEY" filename:.cursor/mcp.json',	"commonstack",	"cursor_mcp"),
    ('"commonstack" filename:.env.example',	"commonstack",	"env_example"),
    ('"COMMONSTACK_API_KEY" extension:md',	"commonstack",	"markdown"),
    # Serper.dev
    ('"SERPER_API_KEY" filename:.env',	"serper",	"env"),
    ('"SERPER_API_KEY" language:python',	"serper",	"code"),
    ('"SERPER_API_KEY" language:javascript',	"serper",	"code"),
    ('"SERPER_API_KEY" language:typescript',	"serper",	"code"),
    ('"google.serper.dev" language:python',	"serper",	"code"),
    ('"google.serper.dev" language:javascript',	"serper",	"code"),
    ('"SERPER_API_KEY" extension:ipynb',	"serper",	"notebook"),
    ('"google.serper.dev" extension:ipynb',	"serper",	"notebook"),
    ('"SERPER_API_KEY" filename:litellm_config.yaml',	"serper",	"litellm"),
    ('"SERPER_API_KEY" filename:.cursor/mcp.json',	"serper",	"cursor_mcp"),
    ('"SERPER_API_KEY" extension:md',	"serper",	"markdown"),
    # Stability AI
    ('"STABILITY_API_KEY" filename:.env',	"stability",	"env"),
    ('"STABILITY_API_KEY" language:python',	"stability",	"code"),
    ('"STABILITY_API_KEY" language:javascript',	"stability",	"code"),
    ('"STABILITY_API_KEY" language:typescript',	"stability",	"code"),
    ('"api.stability.ai" language:python',	"stability",	"code"),
    ('"api.stability.ai" language:javascript',	"stability",	"code"),
    ('"STABILITY_API_KEY" extension:ipynb',	"stability",	"notebook"),
    ('"stability.ai" extension:ipynb',	"stability",	"notebook"),
    ('"STABILITY_API_KEY" filename:litellm_config.yaml',	"stability",	"litellm"),
    ('"STABILITY_API_KEY" extension:md',	"stability",	"markdown"),
    # Luma AI
    ('"LUMA_API_KEY" filename:.env',	"luma",	"env"),
    ('"LUMA_API_KEY" language:python',	"luma",	"code"),
    ('"LUMA_API_KEY" language:javascript',	"luma",	"code"),
    ('"LUMA_API_KEY" language:typescript',	"luma",	"code"),
    ('"lumalabs.ai" language:python',	"luma",	"code"),
    ('"api.lumalabs.ai" language:javascript',	"luma",	"code"),
    ('"LUMA_API_KEY" extension:ipynb',	"luma",	"notebook"),
    ('"luma-" filename:.env',	"luma",	"env"),
    ('"dream-machine" language:python',	"luma",	"code"),
    ('"LUMA_API_KEY" extension:md',	"luma",	"markdown"),
    # Pika Labs
    ('"PIKA_API_KEY" filename:.env',	"pika",	"env"),
    ('"PIKA_API_KEY" language:python',	"pika",	"code"),
    ('"PIKA_API_KEY" language:javascript',	"pika",	"code"),
    ('"PIKA_API_KEY" language:typescript',	"pika",	"code"),
    ('"api.pika.art" language:python',	"pika",	"code"),
    ('"api.pika.art" language:javascript',	"pika",	"code"),
    ('"PIKA_API_KEY" extension:ipynb',	"pika",	"notebook"),
    ('"PIKA_API_KEY" extension:md',	"pika",	"markdown"),
    # TwelveLabs
    ('"TWELVELABS_API_KEY" filename:.env',	"twelvelabs",	"env"),
    ('"TWELVELABS_API_KEY" language:python',	"twelvelabs",	"code"),
    ('"TWELVELABS_API_KEY" language:javascript',	"twelvelabs",	"code"),
    ('"TWELVELABS_API_KEY" language:typescript',	"twelvelabs",	"code"),
    ('"api.twelvelabs.io" language:python',	"twelvelabs",	"code"),
    ('"twelvelabs" language:python',	"twelvelabs",	"code"),
    ('"tlk_" language:python',	"twelvelabs",	"code"),
    ('"tlk_" filename:.env',	"twelvelabs",	"env"),
    ('"TWELVELABS_API_KEY" extension:ipynb',	"twelvelabs",	"notebook"),
    ('"TWELVELABS_API_KEY" extension:md',	"twelvelabs",	"markdown"),

    # ═══════════════════════════════════════════════════════════════════════
    # 2026-05 NEW PROVIDERS — pixverse, siliconflow, firecrawl, portkey,
    # krea, hedra, wavespeed
    # ═══════════════════════════════════════════════════════════════════════

    # ── PixVerse (text-to-video / image-to-video) ──────────────────────
    ('"PIXVERSE_API_KEY" filename:.env',                  "pixverse", "env"),
    ('"PIXVERSE_API_KEY" filename:.env.local',            "pixverse", "env"),
    ('"PIXVERSE_API_KEY" filename:.env.production',       "pixverse", "env"),
    ('"PIXVERSE_API_KEY" language:python',                "pixverse", "code"),
    ('"PIXVERSE_API_KEY" language:javascript',            "pixverse", "code"),
    ('"PIXVERSE_API_KEY" language:typescript',            "pixverse", "code"),
    ('"PIXVERSE_API_KEY" extension:ipynb',                "pixverse", "notebook"),
    ('"app-api.pixverse.ai" language:python',             "pixverse", "code"),
    ('"app-api.pixverse.ai" language:javascript',         "pixverse", "code"),
    ('"PIXVERSE_API_KEY" filename:docker-compose.yml',    "pixverse", "docker"),

    # ── SiliconFlow (CN aggregator: DeepSeek/Qwen/GLM/Yi via one key) ──
    ('"SILICONFLOW_API_KEY" filename:.env',               "siliconflow", "env"),
    ('"SILICONFLOW_API_KEY" "sk-" filename:.env',         "siliconflow", "env"),
    ('"SILICONCLOUD_API_KEY" filename:.env',              "siliconflow", "env"),
    ('"SILICONFLOW_API_KEY" filename:.env.local',         "siliconflow", "env"),
    ('"SILICONFLOW_API_KEY" filename:.env.production',    "siliconflow", "env"),
    ('"SILICONFLOW_API_KEY" language:python',             "siliconflow", "code"),
    ('"SILICONFLOW_API_KEY" language:javascript',         "siliconflow", "code"),
    ('"SILICONFLOW_API_KEY" language:typescript',         "siliconflow", "code"),
    ('"SILICONFLOW_API_KEY" language:go',                 "siliconflow", "code"),
    ('"SILICONFLOW_API_KEY" extension:ipynb',             "siliconflow", "notebook"),
    ('"api.siliconflow.cn" "sk-" language:python',        "siliconflow", "code"),
    ('"api.siliconflow.cn" "sk-" language:javascript',    "siliconflow", "code"),
    ('"siliconflow" "sk-" filename:config.py',            "siliconflow", "config"),
    ('"SILICONFLOW_API_KEY" filename:docker-compose.yml', "siliconflow", "docker"),

    # ── Firecrawl (fc-* prefix unique) ──────────────────────────────────
    ('"FIRECRAWL_API_KEY" filename:.env',                 "firecrawl", "env"),
    ('"FIRECRAWL_API_KEY" "fc-" filename:.env',           "firecrawl", "env"),
    ('"FIRECRAWL_API_KEY" filename:.env.local',           "firecrawl", "env"),
    ('"FIRECRAWL_API_KEY" filename:.env.production',      "firecrawl", "env"),
    ('"fc-" filename:.env',                               "firecrawl", "env"),
    ('"FIRECRAWL_API_KEY" language:python',               "firecrawl", "code"),
    ('"FIRECRAWL_API_KEY" language:typescript',           "firecrawl", "code"),
    ('"FIRECRAWL_API_KEY" language:javascript',           "firecrawl", "code"),
    ('"FIRECRAWL_API_KEY" extension:ipynb',               "firecrawl", "notebook"),
    ('"api.firecrawl.dev" language:python',               "firecrawl", "code"),
    ('"firecrawl" "fc-" filename:config.py',              "firecrawl", "config"),

    # ── Portkey AI gateway (pk-* virtual keys, gateway to upstream) ────
    ('"PORTKEY_API_KEY" filename:.env',                   "portkey", "env"),
    ('"PORTKEY_API_KEY" filename:.env.local',             "portkey", "env"),
    ('"PORTKEY_API_KEY" filename:.env.production',        "portkey", "env"),
    ('"PORTKEY_API_KEY" "pk-" filename:.env',             "portkey", "env"),
    ('"x-portkey-api-key" language:javascript',           "portkey", "code"),
    ('"x-portkey-api-key" language:python',               "portkey", "code"),
    ('"x-portkey-virtual-key" language:python',           "portkey", "code"),
    ('"PORTKEY_API_KEY" language:python',                 "portkey", "code"),
    ('"PORTKEY_API_KEY" language:typescript',             "portkey", "code"),
    ('"PORTKEY_API_KEY" extension:ipynb',                 "portkey", "notebook"),
    ('"api.portkey.ai" "pk-" language:python',            "portkey", "code"),

    # ── Krea AI (image+video gen) ──────────────────────────────────────
    ('"KREA_API_KEY" filename:.env',                      "krea", "env"),
    ('"KREA_API_KEY" filename:.env.local',                "krea", "env"),
    ('"KREA_API_KEY" language:python',                    "krea", "code"),
    ('"KREA_API_KEY" language:typescript',                "krea", "code"),
    ('"KREA_API_KEY" language:javascript',                "krea", "code"),
    ('"api.krea.ai" "Bearer" language:python',            "krea", "code"),
    ('"api.krea.ai" "Bearer" language:typescript',        "krea", "code"),

    # ── Hedra AI (Character-3, Omnia, Veo 3.1 unified) ─────────────────
    ('"HEDRA_API_KEY" filename:.env',                     "hedra", "env"),
    ('"HEDRA_API_KEY" filename:.env.local',               "hedra", "env"),
    ('"HEDRA_API_KEY" language:python',                   "hedra", "code"),
    ('"HEDRA_API_KEY" language:typescript',               "hedra", "code"),
    ('"HEDRA_API_KEY" language:javascript',               "hedra", "code"),
    ('"X-API-Key" "api.hedra.com" language:python',       "hedra", "code"),
    ('"X-API-Key" "api.hedra.com" language:typescript',   "hedra", "code"),
    ('"HEDRA_API_KEY" extension:ipynb',                   "hedra", "notebook"),

    # ── WaveSpeed AI (WAN 2.7, Z-Image multimodal) ─────────────────────
    ('"WAVESPEED_API_KEY" filename:.env',                 "wavespeed", "env"),
    ('"WAVESPEED_API_KEY" filename:.env.local',           "wavespeed", "env"),
    ('"WAVESPEED_API_KEY" language:python',               "wavespeed", "code"),
    ('"WAVESPEED_API_KEY" language:typescript',           "wavespeed", "code"),
    ('"WAVESPEED_API_KEY" language:javascript',           "wavespeed", "code"),
    ('"api.wavespeed.ai" "Bearer" language:python',       "wavespeed", "code"),
    ('"api.wavespeed.ai" "Bearer" language:typescript',   "wavespeed", "code"),

    # ─────────────────────────────────────────────────────────────────────
    # Archetype queries B (multi-provider chat UIs), C (agent frameworks),
    # E (Discord/TG/Slack bots), F (RAG kits), G (image/video frontend),
    # H (coding assistants), I (prompt playgrounds), J (browser ext),
    # K (SaaS clones). ~50 queries total.
    # ─────────────────────────────────────────────────────────────────────
    # B. Multi-provider chat UIs (already partially covered, expand)
    ('"BIG_AGI" filename:.env',	"openai",	"bigagi"),
    ('"OPENAI_API_KEY" "OLLAMA_BASE_URL" filename:.env',	"openai",	"webui_combo"),
    ('"OPENAI_API_KEY" "PROXY_URL" filename:.env',	"openai",	"chat_ui_proxy"),
    # C. Agent frameworks expansion
    ('"haystack" "OPENAI_API_KEY" filename:.env',	"openai",	"haystack"),
    ('"autogen" "config_list" extension:json',	"openai",	"autogen_config"),
    ('"semantic-kernel" "OPENAI_API_KEY" filename:.env',	"openai",	"sk_agent"),
    ('"agno" "OPENAI_API_KEY" filename:.env',	"openai",	"agno"),
    ('"phidata" "OPENAI_API_KEY" filename:.env',	"openai",	"phidata"),
    ('"swarm" "OPENAI_API_KEY" filename:.env',	"openai",	"swarm"),
    ('"LANGSMITH_API_KEY" "OPENAI_API_KEY" filename:.env',	"openai",	"langsmith"),
    # E. Discord / TG / Slack bots — expand
    ('"discord.py" "OPENAI_API_KEY" extension:py',	"openai",	"discord_py"),
    ('"discord.js" "OPENAI_API_KEY" extension:js',	"openai",	"discord_js"),
    ('"aiogram" "OPENAI_API_KEY" extension:py',	"openai",	"aiogram"),
    ('"telegraf" "OPENAI_API_KEY" extension:js',	"openai",	"telegraf"),
    ('"python-telegram-bot" "OPENAI_API_KEY" extension:py',	"openai",	"ptb"),
    ('"slack-bolt" "OPENAI_API_KEY" extension:py',	"openai",	"slack_bolt"),
    ('"DISCORD_TOKEN" "ANTHROPIC_API_KEY" filename:.env',	"anthropic",	"discord_bot"),
    ('"TELEGRAM_BOT_TOKEN" "ANTHROPIC_API_KEY" filename:.env',	"anthropic",	"tg_bot"),
    # F. RAG / vector DB kits
    ('"PINECONE_API_KEY" "ANTHROPIC_API_KEY" filename:.env',	"anthropic",	"rag_pinecone"),
    ('"WEAVIATE_API_KEY" "ANTHROPIC_API_KEY" filename:.env',	"anthropic",	"rag_weaviate"),
    ('"CHROMA_SERVER_AUTHN_CREDENTIALS" filename:.env',	"openai",	"chroma"),
    ('"llamaindex" "OPENAI_API_KEY" filename:.env',	"openai",	"llamaindex"),
    ('"llama-index" "OPENAI_API_KEY" filename:.env',	"openai",	"llamaindex"),
    ('"upstash" "OPENAI_API_KEY" filename:.env',	"openai",	"upstash_rag"),
    ('"MILVUS_HOST" "OPENAI_API_KEY" filename:.env',	"openai",	"milvus"),
    # G. AI image/video gen frontend (Vite/Next/CRA leaks)
    ('"VITE_FAL_KEY" filename:.env',	"fal",	"vite_frontend"),
    ('"VITE_FAL_API_KEY" filename:.env',	"fal",	"vite_frontend"),
    ('"VITE_REPLICATE_API_TOKEN" filename:.env',	"replicate",	"vite_frontend"),
    ('"VITE_AIMLAPI_API_KEY" filename:.env',	"aimlapi",	"vite_frontend"),
    ('"VITE_AIMLAPI_KEY" filename:.env',	"aimlapi",	"vite_frontend"),
    ('"VITE_OPENAI_API_KEY" filename:.env',	"openai",	"vite_frontend"),
    ('"VITE_ELEVENLABS_API_KEY" filename:.env',	"elevenlabs",	"vite_frontend"),
    ('"VITE_PINATA_API_KEY" filename:.env',	"openai",	"vite_pinata"),
    ('"NEXT_PUBLIC_FAL_KEY" filename:.env',	"fal",	"next_frontend"),
    ('"NEXT_PUBLIC_REPLICATE_API_TOKEN" filename:.env',	"replicate",	"next_frontend"),
    ('"NEXT_PUBLIC_AIMLAPI_KEY" filename:.env',	"aimlapi",	"next_frontend"),
    ('"NEXT_PUBLIC_ELEVENLABS_API_KEY" filename:.env',	"elevenlabs",	"next_frontend"),
    ('"REACT_APP_FAL_KEY" filename:.env',	"fal",	"cra_frontend"),
    ('"REACT_APP_REPLICATE_API_TOKEN" filename:.env',	"replicate",	"cra_frontend"),
    ('"REACT_APP_OPENAI_API_KEY" filename:.env',	"openai",	"cra_frontend"),
    # H. AI coding assistants
    ('"continue.dev" filename:config.json',	"openai",	"continue_dev"),
    ('"continue" filename:config.yaml',	"openai",	"continue_yaml"),
    ('"aider" filename:.env',	"openai",	"aider"),
    ('"AIDER_OPENAI_API_KEY" filename:.env',	"openai",	"aider_specific"),
    ('"cline" filename:settings.json',	"openai",	"cline"),
    ('"roo-cline" filename:settings.json',	"openai",	"roo_cline"),
    ('"zed" "openai" extension:json',	"openai",	"zed_editor"),
    # I. Prompt engineering playgrounds
    ('"promptfoo" filename:.env',	"openai",	"promptfoo"),
    ('"langfuse" filename:.env',	"openai",	"langfuse"),
    ('"phoenix" "OPENAI_API_KEY" filename:.env',	"openai",	"arize_phoenix"),
    ('"mlflow" "OPENAI_API_KEY" filename:.env',	"openai",	"mlflow"),
    ('"helicone" "OPENAI_API_KEY" filename:.env',	"openai",	"helicone_env"),
    # J. Browser extensions
    ('"manifest_version" "OPENAI_API_KEY" extension:json',	"openai",	"browser_ext"),
    ('"chrome.runtime" "OPENAI_API_KEY" extension:js',	"openai",	"chrome_ext"),
    ('"chrome.runtime" "ANTHROPIC_API_KEY" extension:js',	"anthropic",	"chrome_ext"),
    # K. SaaS clones
    ('"chatgpt-clone" filename:.env',	"openai",	"chatgpt_clone"),
    ('"midjourney-clone" filename:.env',	"openai",	"mj_clone"),
    ('"clerk" "OPENAI_API_KEY" filename:.env',	"openai",	"clerk_saas"),
    ('"stripe" "OPENAI_API_KEY" filename:.env',	"openai",	"stripe_ai_saas"),
    ('"supabase" "OPENAI_API_KEY" filename:.env',	"openai",	"supabase_ai_saas"),
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

    # ── Higgsfield ────────────────────────────────────────────────────────
    ('"HIGGSFIELD_API_KEY"',                              "higgsfield",  "env"),
    ('"platform.higgsfield.ai"',                          "higgsfield",  "code"),

    # ── Fal.ai ────────────────────────────────────────────────────────────
    ('"FAL_KEY"',                                         "fal",         "env"),
    ('"fal.run"',                                         "fal",         "code"),

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
