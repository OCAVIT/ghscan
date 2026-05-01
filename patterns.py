"""
Key extraction regexes and search query definitions.

ARK (Volcengine/Doubao/Seedance) key format: UUID v4
  e.g.  d47a1b2c-4f3e-4c1a-9b2e-d6e012340fd7
  must appear near ARK context words (env var names, base URL, endpoint prefix)

OpenAI key formats:
  sk-proj-<base64url>          new project keys
  sk-svcacct-<base64url>       service account keys
  sk-<48 alphanum>             legacy keys (51 chars total)
"""

import re

# ── OpenAI patterns ────────────────────────────────────────────────────────
_OAI_PATTERNS = [
    re.compile(r'sk-proj-[A-Za-z0-9_\-]{40,220}'),
    re.compile(r'sk-svcacct-[A-Za-z0-9_\-]{40,220}'),
    re.compile(r'sk-[A-Za-z0-9]{48}'),               # exactly 48 chars (legacy)
]

# ── ARK (Volcengine) patterns ───────────────────────────────────────────────
_UUID = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
_ARK_CTX = re.compile(
    r'(?:ARK_API_KEY|VOLCENGINE_API_KEY|DOUBAO_API_KEY|VOLC_API_KEY'
    r'|ark\.cn-beijing\.volces\.com|ark\.ap-southeast\.volces\.com'
    r'|volces\.com|ark_api_key|doubao_api_key)'
    r'[\s\S]{0,300}'        # allow some distance
    r'(' + _UUID + r')',
    re.IGNORECASE,
)

# Standalone UUID near ep- endpoint (secondary signal)
_ARK_EP = re.compile(r'ep-\d{10,14}-[a-z0-9]{3,8}')

# ── Fake / placeholder filter ──────────────────────────────────────────────
_FAKE = re.compile(
    r'(?:your[_\-]?(?:api[_\-]?)?key|example|placeholder|xxx+|REPLACE|'
    r'<api|>|\.\.\.|\bfake\b|\bdummy\b|\bsample\b|\bdemo\b|test_key|'
    r'00000000-0000-0000-0000-000000000000)',
    re.IGNORECASE,
)

# ── Skip paths ────────────────────────────────────────────────────────────
_SKIP_PATH = re.compile(
    r'/(?:node_modules|vendor|dist|build|\.next|out|coverage|__pycache__)/',
    re.IGNORECASE,
)
_TEST_PATH = re.compile(
    r'(?:test_|_test\.|\.test\.|\.spec\.|__tests__|/tests?/)',
    re.IGNORECASE,
)

# ── Server-side path signals ───────────────────────────────────────────────
_SERVER_PATH = re.compile(
    r'(?:route|api/|server|backend|controller|service|handler|worker|'
    r'config|settings|\.env(?:$|[^a-zA-Z])|docker|compose|Dockerfile)',
    re.IGNORECASE,
)


def is_skippable_path(path: str) -> bool:
    return bool(_SKIP_PATH.search(path)) or bool(_TEST_PATH.search(path))


def is_server_path(path: str) -> bool:
    """Heuristic: file looks server-side."""
    return bool(_SERVER_PATH.search(path)) or path.endswith(
        ('.py', '.go', '.rs', '.rb', '.php', '.env', '.yaml', '.yml', '.json', '.ipynb')
    )


def extract_openai(content: str) -> list[str]:
    found = []
    for pat in _OAI_PATTERNS:
        for m in pat.finditer(content):
            key = m.group(0)
            ctx = content[max(0, m.start() - 80): m.end() + 40]
            if _FAKE.search(ctx):
                continue
            found.append(key)
    return list(dict.fromkeys(found))  # dedupe, preserve order


def extract_ark(content: str) -> list[str]:
    found = []
    for m in _ARK_CTX.finditer(content):
        key = m.group(1)
        ctx = content[max(0, m.start() - 40): m.end() + 40]
        if _FAKE.search(ctx):
            continue
        found.append(key)
    return list(dict.fromkeys(found))


# ── GitHub code search queries ─────────────────────────────────────────────
# Each entry: (query_string, provider, file_type_tag)
# Sort results by indexed desc = freshest commits first (live keys more likely)
QUERIES = [
    # ── OpenAI ──────────────────────────────────────────────────────────
    # .env files — devs accidentally commit them; keys almost always live
    ('q="OPENAI_API_KEY" "sk-" filename:.env&sort=indexed&order=desc', 'openai', 'env'),
    ('q="sk-proj-" filename:.env&sort=indexed&order=desc',              'openai', 'env'),
    # Jupyter notebooks — data scientists hardcode and forget
    ('q="OPENAI_API_KEY" "sk-" extension:ipynb&sort=indexed&order=desc', 'openai', 'notebook'),
    ('q="sk-proj-" extension:ipynb&sort=indexed&order=desc',             'openai', 'notebook'),
    # Docker / CI — ops engineers hardcode in pipelines
    ('q="OPENAI_API_KEY" "sk-" filename:docker-compose.yml&sort=indexed&order=desc', 'openai', 'docker'),
    ('q="OPENAI_API_KEY" "sk-" filename:Dockerfile&sort=indexed&order=desc',         'openai', 'docker'),
    ('q="OPENAI_API_KEY" "sk-" filename:.github&sort=indexed&order=desc',            'openai', 'ci'),
    # Config files
    ('q="sk-proj-" filename:config.py&sort=indexed&order=desc',    'openai', 'config'),
    ('q="sk-proj-" filename:settings.py&sort=indexed&order=desc',  'openai', 'config'),
    ('q="sk-proj-" filename:config.js&sort=indexed&order=desc',    'openai', 'config'),
    ('q="sk-proj-" filename:config.ts&sort=indexed&order=desc',    'openai', 'config'),
    # Hardcoded in source (broad — gets young/big repos)
    ('q="sk-proj-" language:python&sort=indexed&order=desc',     'openai', 'code'),
    ('q="sk-proj-" language:javascript&sort=indexed&order=desc', 'openai', 'code'),
    ('q="sk-proj-" language:typescript&sort=indexed&order=desc', 'openai', 'code'),
    ('q="sk-proj-" language:go&sort=indexed&order=desc',         'openai', 'code'),
    ('q="sk-svcacct-" language:python&sort=indexed&order=desc',  'openai', 'code'),
    # Legacy sk- with explicit OPENAI context
    ('q="OPENAI_API_KEY=sk-" language:python&sort=indexed&order=desc',  'openai', 'code'),
    ('q="OPENAI_API_KEY=sk-" language:javascript&sort=indexed&order=desc', 'openai', 'code'),
    ('q=openai_api_key "sk-" filename:requirements.txt&sort=indexed&order=desc', 'openai', 'config'),

    # ── ARK / Volcengine / Doubao ────────────────────────────────────────
    ('q="ARK_API_KEY" filename:.env&sort=indexed&order=desc',         'ark', 'env'),
    ('q="VOLCENGINE_API_KEY" filename:.env&sort=indexed&order=desc',  'ark', 'env'),
    ('q="DOUBAO_API_KEY" filename:.env&sort=indexed&order=desc',      'ark', 'env'),
    ('q="ARK_API_KEY" extension:ipynb&sort=indexed&order=desc',       'ark', 'notebook'),
    ('q="ark.cn-beijing.volces.com" language:python&sort=indexed&order=desc', 'ark', 'code'),
    ('q="ark.cn-beijing.volces.com" language:javascript&sort=indexed&order=desc', 'ark', 'code'),
    ('q="VOLCENGINE_API_KEY" language:python&sort=indexed&order=desc', 'ark', 'code'),
    ('q="DOUBAO_API_KEY" language:python&sort=indexed&order=desc',     'ark', 'code'),
    ('q="ARK_API_KEY" language:python&sort=indexed&order=desc',        'ark', 'code'),
    ('q="ARK_API_KEY" filename:docker-compose.yml&sort=indexed&order=desc', 'ark', 'docker'),
]
