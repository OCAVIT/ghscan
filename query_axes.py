"""
Orthogonal axis definitions per provider — single source of truth for the
combinatorial query generator (query_generator.py).

Each provider has:
  env_names     — env-var spellings devs use ("OPENAI_API_KEY", "OPENAI_KEY", …)
  key_prefixes  — distinguishable literal fragments of the actual key
  domains       — API hostnames that anchor context
  model_names   — distinctive model IDs (only added when the literal name is
                  itself rare enough to be a discriminator — e.g. "doubao-seedance"
                  but NOT "gpt-4" which appears in every AI tutorial)

Global axes (FILENAMES, LANGUAGES, PATH_GLOBS) are shared across all providers
and cross-multiplied with each provider's own axes by the generator.

Axis extensions discovered by vocab_expander.py are stored in the
axis_extensions DB table and merged on top of these defaults at generation
time — so we never have to hot-patch this file when DeepSeek spots a new
naming convention.
"""

from __future__ import annotations


# ── Global axes (shared across all providers) ────────────────────────────────

FILENAMES: list[str] = [
    # Env files
    ".env", ".env.local", ".env.production", ".env.development",
    ".env.staging", ".env.test", ".env.example", ".env.template",
    ".env.sample", ".env.docker", ".env.docker.local", ".env.vault",
    ".env.ready", ".env.bak", ".envrc", ".env.dist",
    # Generic configs
    "config.py", "settings.py", "config.js", "config.ts", "config.json",
    "config.yaml", "config.yml", "config.toml", "settings.json",
    "settings.toml", "settings.yaml",
    # Framework-specific
    "appsettings.json", "appsettings.Development.json",          # .NET
    "application.yml", "application.yaml", "application.properties",  # Spring/Java
    "local.settings.json",                                        # Azure Functions
    "secrets.toml",                                               # Streamlit
    "secrets.json", "secrets.yaml", "secrets.yml",
    "wrangler.toml", "wrangler.jsonc",                           # Cloudflare Workers
    "fly.toml",                                                   # Fly.io
    "vercel.json",                                                # Vercel
    "netlify.toml",                                               # Netlify
    "railway.toml", "railway.json",                               # Railway
    "render.yaml",                                                # Render
    "amplify.yml",                                                # AWS Amplify
    "firebase.json", ".firebaserc",                              # Firebase
    "supabase/config.toml",                                       # Supabase
    "turbo.json",                                                 # Turborepo
    # Docker / CI
    "docker-compose.yml", "docker-compose.yaml",
    "docker-compose.dev.yml", "docker-compose.prod.yml",
    "Dockerfile", "compose.yml", "compose.yaml",
]

# `path:` globs (different from filename: — match directory location)
PATH_GLOBS: list[str] = [
    ".github", ".github/workflows",
    ".vscode",
    "config", "configs", "settings",
    "src/config", "src/configs", "src/settings",
    "app/config", "app/configs",
    "deploy", "deployment",
    "secrets", "credentials",
    ".devcontainer",
    "infra", "infrastructure",
    "k8s", "kubernetes", "helm",
    "terraform", "tf",
]

LANGUAGES: list[str] = [
    "python", "javascript", "typescript", "go", "java",
    "php", "csharp", "ruby", "rust", "kotlin",
    "dart", "swift", "scala", "elixir", "shell",
]

# Time-window suffixes — generator rotates these per batch so the same base
# combination yields a new hash every batch. Window values are computed at
# generation time (today minus 7d / 30d / 90d).
TIME_WINDOW_OFFSETS: list[int] = [3, 7, 14, 30, 60]   # days back
TIME_QUALIFIERS: list[str] = ["pushed:>", "created:>"]

# Size buckets — bypass GH's 1000-result-per-query cap by partitioning
# broad queries into size slices.
SIZE_BUCKETS: list[str] = ["size:<1000", "size:1000..5000", "size:>5000"]


# ── Per-provider axes ────────────────────────────────────────────────────────
# Convention: only providers that have a quotable, distinctive content marker
# get axes here. Shape-only matchers (luma- UUID, tlk_*, etc.) without a
# meaningful literal "trigger word" rely on the static QUERIES alone.

PROVIDER_AXES: dict[str, dict[str, list[str]]] = {

    "openai": {
        "env_names": [
            "OPENAI_API_KEY", "OPENAI_KEY", "OPENAI_TOKEN", "OPENAI_SECRET",
            "OPENAI_API_TOKEN", "OPENAI_API", "OAI_KEY", "OAI_API_KEY",
            "OPEN_AI_KEY", "OPEN_AI_API_KEY", "OPENAI_PROJECT_KEY",
            "OPENAI_ORG_KEY", "GPT_API_KEY", "GPT_KEY", "GPT4_API_KEY",
            "CHATGPT_API_KEY", "CHAT_GPT_KEY",
        ],
        "key_prefixes": ["sk-proj-", "sk-svcacct-", "sk-admin-"],
        "domains": ["api.openai.com", "platform.openai.com"],
        "model_names": [
            # Only IDs distinctive enough to anchor a search (not "gpt-4")
            "gpt-4o-realtime", "gpt-image-2", "o3-pro", "o4-mini-high",
            "gpt-5-preview",
        ],
    },

    "anthropic": {
        "env_names": [
            "ANTHROPIC_API_KEY", "CLAUDE_API_KEY", "ANTHROPIC_KEY",
            "CLAUDE_KEY", "ANTHROPIC_TOKEN", "CLAUDE_TOKEN",
            "ANTHROPIC_SECRET", "CLAUDE_SECRET_KEY",
        ],
        "key_prefixes": ["sk-ant-api03-", "sk-ant-"],
        "domains": ["api.anthropic.com"],
        "model_names": [
            "claude-opus-4", "claude-sonnet-4", "claude-haiku-4",
            "claude-4-opus", "claude-4-sonnet",
        ],
    },

    "google": {
        "env_names": [
            "GOOGLE_API_KEY", "GEMINI_API_KEY", "GOOGLE_AI_API_KEY",
            "GOOGLE_GENAI_API_KEY", "GOOGLE_GEMINI_KEY", "GEMINI_KEY",
            "VEO_API_KEY", "GOOGLE_VEO_API_KEY", "GOOGLE_PALM_KEY",
            "VERTEX_AI_KEY", "VERTEX_API_KEY", "GOOGLE_AISTUDIO_KEY",
            "GOOGLE_APPLICATION_CREDENTIALS",
        ],
        "key_prefixes": ["AIzaSy"],
        "domains": [
            "generativelanguage.googleapis.com",
            "aiplatform.googleapis.com",
            "iam.gserviceaccount.com",
        ],
        "model_names": [
            "veo-2.0-generate-001", "veo-3.0-generate-001",
            "gemini-2.5-pro", "gemini-3-pro", "gemini-2.0-flash-exp",
            "imagen-3.0", "imagen-4.0",
        ],
    },

    "deepseek": {
        "env_names": [
            "DEEPSEEK_API_KEY", "DEEPSEEK_KEY", "DEEPSEEK_TOKEN",
            "DS_API_KEY", "DEEPSEEK_SECRET",
        ],
        "key_prefixes": [],   # sk- shape overlaps with OpenAI; rely on context
        "domains": ["api.deepseek.com", "platform.deepseek.com"],
        "model_names": [
            "deepseek-chat", "deepseek-reasoner", "deepseek-v3",
            "deepseek-v4", "deepseek-v4-pro",
        ],
    },

    "elevenlabs": {
        "env_names": [
            "ELEVENLABS_API_KEY", "ELEVEN_API_KEY", "XI_API_KEY",
            "ELEVENLABS_KEY", "ELEVEN_LABS_KEY", "ELEVEN_TOKEN",
            "ELEVENLABS_SECRET", "TTS_API_KEY", "VOICE_API_KEY",
        ],
        "key_prefixes": ["sk_"],   # context-gated, sk_[hex]
        "domains": ["api.elevenlabs.io", "elevenlabs.io"],
        "model_names": [
            "eleven_multilingual_v2", "eleven_turbo_v2_5", "eleven_flash_v2_5",
        ],
    },

    "ark": {
        "env_names": [
            "ARK_API_KEY", "ARK_KEY", "VOLCENGINE_API_KEY", "VOLC_API_KEY",
            "VOLC_ACCESSKEY", "VOLC_SECRETKEY", "DOUBAO_API_KEY",
            "DOUBAO_KEY", "SEEDANCE_API_KEY", "SEEDANCE_KEY",
            "BYTEDANCE_API_KEY", "BYTEPLUS_API_KEY", "BYTEPLUS_ACCESS_KEY",
            "BYTEPLUS_SECRET_KEY", "VOLCSTACK_ACCESS_KEY_ID",
            "VOLCSTACK_SECRET_ACCESS_KEY",
        ],
        "key_prefixes": [],   # UUID v4 shape — too generic
        "domains": [
            "ark.cn-beijing.volces.com", "ark.cn-shanghai.volces.com",
            "ark.cn-guangzhou.volces.com", "ark.ap-southeast.volces.com",
            "ark.us-east-1.volces.com", "ark.eu-central-1.volces.com",
            "maas-api.byteplus.com", "byteplus.com", "volces.com",
        ],
        "model_names": [
            "doubao-seedance", "doubao-seedance-1-0", "doubao-seedance-2-0",
            "doubao-seedance-2-0-260128", "doubao-seedance-2-0-fast-260128",
            "doubao-pro", "doubao-1.5-pro",
        ],
    },

    "ark_fast": {   # Same content surface as ark — separate provider for validator routing
        "env_names": [
            "ARK_API_KEY", "VOLCENGINE_API_KEY", "DOUBAO_API_KEY",
            "SEEDANCE_API_KEY",
        ],
        "key_prefixes": [],
        "domains": ["ark.cn-beijing.volces.com", "maas-api.byteplus.com"],
        "model_names": [
            "doubao-seedance-2-0-fast-260128", "doubao-seedance-fast",
        ],
    },

    "openai_image": {
        "env_names": [
            "OPENAI_IMAGE_API_KEY", "GPT_IMAGE_API_KEY", "IMAGE_API_KEY",
            "OPENAI_VISION_KEY", "GPT_IMAGE_KEY",
        ],
        "key_prefixes": ["sk-proj-"],   # gated via gpt-image-2 context elsewhere
        "domains": ["api.openai.com/v1/images"],
        "model_names": ["gpt-image-2", "gpt-image-1"],
    },

    "huggingface": {
        "env_names": [
            "HF_TOKEN", "HUGGINGFACE_TOKEN", "HUGGING_FACE_HUB_TOKEN",
            "HF_API_KEY", "HF_API_TOKEN", "HUGGINGFACE_API_KEY",
            "HUGGINGFACE_HUB_TOKEN",
        ],
        "key_prefixes": ["hf_"],
        "domains": ["huggingface.co", "api-inference.huggingface.co"],
        "model_names": [],
    },

    "perplexity": {
        "env_names": [
            "PERPLEXITY_API_KEY", "PPLX_API_KEY", "PPLX_KEY",
            "PERPLEXITY_KEY", "PERPLEXITY_TOKEN",
        ],
        "key_prefixes": ["pplx-"],
        "domains": ["api.perplexity.ai"],
        "model_names": ["llama-3.1-sonar", "sonar-large", "sonar-pro"],
    },

    "runway": {
        "env_names": [
            "RUNWAYML_API_SECRET", "RUNWAY_API_KEY", "RUNWAY_API_SECRET",
            "RUNWAY_TOKEN", "RUNWAYML_KEY", "RUNWAY_KEY",
        ],
        "key_prefixes": ["key_"],   # shape gated by runway context
        "domains": ["api.dev.runwayml.com", "api.runwayml.com"],
        "model_names": ["gen-3-alpha", "gen-3", "gen-4"],
    },

    "happyhorse": {
        "env_names": [
            "HAPPY_HORSE_API_KEY", "RUNHAPPYHORSE_API_KEY",
            "HAPPYHORSE_API_KEY", "HH_API_KEY",
            "LIMEAI_API_KEY", "LIME_AI_KEY",
        ],
        "key_prefixes": [],
        "domains": [
            "runhappyhorse.net", "happyhorse.ai",
            "limeai.top", "lime-ai.com",
        ],
        "model_names": [],
    },

    "replicate": {
        "env_names": [
            "REPLICATE_API_TOKEN", "REPLICATE_API_KEY", "REPLICATE_TOKEN",
            "REPLICATE_KEY",
        ],
        "key_prefixes": ["r8_"],
        "domains": ["api.replicate.com", "replicate.com"],
        "model_names": [],
    },

    "fal": {
        "env_names": [
            "FAL_API_KEY", "FAL_KEY", "FAL_SECRET_KEY", "FAL_TOKEN",
        ],
        "key_prefixes": [],   # hex:hex shape
        "domains": ["fal.ai", "fal.run", "api.fal.ai"],
        "model_names": [],
    },

    "grok": {
        "env_names": [
            "XAI_API_KEY", "GROK_API_KEY", "XAI_KEY", "GROK_KEY",
            "GROK_TOKEN",
        ],
        "key_prefixes": ["xai-"],
        "domains": ["api.x.ai"],
        "model_names": ["grok-2", "grok-3", "grok-4"],
    },

    "suno": {
        "env_names": [
            "SUNO_API_KEY", "SUNO_KEY", "SUNO_SECRET", "SUNO_TOKEN",
        ],
        "key_prefixes": [],
        "domains": ["suno.ai", "sunoapi.org", "api.suno.com"],
        "model_names": ["chirp-v3-5", "chirp-v4"],
    },

    "inworld": {
        "env_names": [
            "INWORLD_BASE64", "INWORLD_AUTH", "INWORLD_KEY_SECRET",
            "INWORLD_API_KEY", "INWORLD_KEY",
        ],
        "key_prefixes": [],
        "domains": ["inworld.ai", "api.inworld.ai", "studio.inworld.ai"],
        "model_names": [],
    },

    "kimi": {
        "env_names": [
            "MOONSHOT_API_KEY", "KIMI_API_KEY", "KIMI_KEY",
            "MOONSHOT_KEY", "MOONSHOT_TOKEN", "KIMI_TOKEN",
        ],
        "key_prefixes": [],   # sk- shape, context-gated
        "domains": ["api.moonshot.cn", "api.moonshot.ai"],
        "model_names": [
            "moonshot-v1", "moonshot-v1-128k", "kimi-latest",
            "kimi-k1.5", "kimi-k2",
        ],
    },

    "glm": {
        "env_names": [
            "ZHIPUAI_API_KEY", "ZHIPU_API_KEY", "GLM_API_KEY",
            "BIGMODEL_API_KEY", "GLM_KEY", "ZHIPU_KEY",
        ],
        "key_prefixes": [],   # hex32.base62-16 — covered by direct standalone scan
        "domains": ["open.bigmodel.cn", "api.zhipuai.cn"],
        "model_names": ["glm-4", "glm-4-plus", "glm-4.5", "chatglm-3"],
    },

    "kling": {
        "env_names": [
            "KLING_ACCESS_KEY", "KLING_AK", "KLING_SECRET_KEY", "KLING_SK",
            "KUAISHOU_ACCESS_KEY", "KUAISHOU_SECRET_KEY",
        ],
        "key_prefixes": [],
        "domains": ["api.klingai.com", "klingai.com"],
        "model_names": ["kling-v1", "kling-v1.6", "kling-v2"],
    },

    "fireworks": {
        "env_names": [
            "FIREWORKS_API_KEY", "FIREWORKS_AI_API_KEY", "FIREWORKS_KEY",
        ],
        "key_prefixes": ["fw_"],
        "domains": ["api.fireworks.ai", "fireworks.ai"],
        "model_names": [],
    },

    "openrouter": {
        "env_names": [
            "OPENROUTER_API_KEY", "OR_API_KEY", "OPENROUTER_KEY",
            "OPENROUTER_TOKEN", "OPEN_ROUTER_KEY",
        ],
        "key_prefixes": ["sk-or-v1-"],
        "domains": ["openrouter.ai", "api.openrouter.ai"],
        "model_names": [],
    },

    "aimlapi": {
        "env_names": [
            "AIMLAPI_API_KEY", "AIMLAPI_KEY", "AIML_API_KEY",
            "AIML_KEY",
        ],
        "key_prefixes": [],
        "domains": ["aimlapi.com", "api.aimlapi.com"],
        "model_names": [],
    },

    "deepinfra": {
        "env_names": [
            "DEEPINFRA_API_KEY", "DEEPINFRA_KEY", "DEEPINFRA_TOKEN",
            "DEEPINFRA_API_TOKEN",
        ],
        "key_prefixes": [],
        "domains": ["deepinfra.com", "api.deepinfra.com"],
        "model_names": [],
    },

    "hyperbolic": {
        "env_names": [
            "HYPERBOLIC_API_KEY", "HYPERBOLIC_KEY", "HYPERBOLIC_TOKEN",
        ],
        "key_prefixes": ["eyJ"],   # JWT shape
        "domains": ["api.hyperbolic.xyz", "hyperbolic.xyz", "hyperbolic.ai"],
        "model_names": [],
    },

    "novita": {
        "env_names": [
            "NOVITA_API_KEY", "NOVITA_AI_API_KEY", "NOVITA_KEY",
            "NOVITA_TOKEN",
        ],
        "key_prefixes": ["sk_"],   # context-gated
        "domains": ["novita.ai", "api.novita.ai"],
        "model_names": [],
    },

    "stability": {
        "env_names": [
            "STABILITY_API_KEY", "STABILITY_KEY", "STABILITY_AI_KEY",
            "SD_API_KEY", "SDXL_API_KEY",
        ],
        "key_prefixes": [],   # sk- shape — collides with OpenAI, gate via context
        "domains": ["api.stability.ai", "stability.ai", "stabilityai"],
        "model_names": ["stable-diffusion-3", "sd3-large", "sdxl-1.0"],
    },

    "commonstack": {
        "env_names": ["COMMONSTACK_API_KEY", "COMMONSTACK_KEY"],
        "key_prefixes": ["ak-"],
        "domains": ["commonstack.ai", "api.commonstack.ai"],
        "model_names": [],
    },

    "serper": {
        "env_names": ["SERPER_API_KEY", "SERPER_KEY"],
        "key_prefixes": [],
        "domains": ["serper.dev", "api.serper.dev", "google.serper.dev"],
        "model_names": [],
    },

    "luma": {
        "env_names": ["LUMA_API_KEY", "LUMAAI_API_KEY", "LUMA_KEY"],
        "key_prefixes": ["luma-"],
        "domains": ["lumalabs.ai", "api.lumalabs.ai"],
        "model_names": ["dream-machine", "ray-1.6", "ray-2"],
    },

    "pika": {
        "env_names": ["PIKA_API_KEY", "PIKA_KEY", "PIKALABS_API_KEY"],
        "key_prefixes": [],
        "domains": ["pika.art", "api.pika.art", "pikalabs"],
        "model_names": [],
    },

    "twelvelabs": {
        "env_names": [
            "TWELVELABS_API_KEY", "TWELVE_LABS_API_KEY", "TWELVELABS_KEY",
        ],
        "key_prefixes": ["tlk_"],
        "domains": ["api.twelvelabs.io", "twelvelabs.io"],
        "model_names": ["marengo", "pegasus"],
    },

    # ── Trufflehog-only providers ────────────────────────────────────────
    # These have no patterns.py extractor — they're saved to found_keys via
    # trufflehog_runner sweeping configured orgs/users. Adding them here lets
    # the dynamic query pool DISCOVER repos containing these keys, populating
    # scanned_repos. Author-tracking + trufflehog can then sweep those orgs
    # next cycle and capture the keys.
    "together": {
        "env_names": [
            "TOGETHER_API_KEY", "TOGETHER_AI_API_KEY", "TOGETHERAI_API_KEY",
            "TOGETHER_KEY", "TOGETHER_TOKEN",
        ],
        "key_prefixes": ["tgp_v1_"],
        "domains": ["api.together.xyz", "api.together.ai", "together.ai"],
        "model_names": [],
    },

    "groq": {
        "env_names": [
            "GROQ_API_KEY", "GROQ_KEY", "GROQ_TOKEN", "GROQ_SECRET",
        ],
        "key_prefixes": ["gsk_"],
        "domains": ["api.groq.com", "console.groq.com"],
        "model_names": [
            "llama-3.3-70b-versatile", "llama-3.1-70b-versatile",
            "mixtral-8x7b-32768", "gpt-oss-120b", "gemma2-9b-it",
        ],
    },

    "cerebras": {   # 50 valid / 179 found — high-precision (28%), top yielding
        "env_names": [
            "CEREBRAS_API_KEY", "CEREBRAS_KEY", "CEREBRAS_TOKEN",
            "CEREBRAS_SECRET",
        ],
        "key_prefixes": ["csk-"],
        "domains": ["api.cerebras.ai", "cerebras.ai", "inference.cerebras.ai"],
        "model_names": [
            "llama3.1-8b", "llama3.1-70b", "llama-3.3-70b",
            "gpt-oss-120b",
        ],
    },

    "mistral": {
        "env_names": [
            "MISTRAL_API_KEY", "MISTRAL_KEY", "MISTRAL_TOKEN",
            "MISTRAL_AI_API_KEY", "MISTRAL_SECRET",
            "CODESTRAL_API_KEY", "CODESTRAL_KEY",
        ],
        "key_prefixes": [],   # Mistral keys are 32-char alnum — context-only
        "domains": ["api.mistral.ai", "mistral.ai", "codestral.mistral.ai"],
        "model_names": [
            "mistral-large", "mistral-medium", "mistral-small",
            "codestral-latest", "ministral-8b", "pixtral-large",
            "mistral-large-2411", "mistral-large-2",
        ],
    },

    "cohere": {
        "env_names": [
            "COHERE_API_KEY", "COHERE_KEY", "COHERE_TOKEN", "CO_API_KEY",
            "COHERE_SECRET",
        ],
        "key_prefixes": [],   # Cohere keys are 40-char alnum — context-only
        "domains": ["api.cohere.com", "api.cohere.ai", "cohere.com"],
        "model_names": [
            "command-r", "command-r-plus", "command-light",
            "command-r7b", "embed-english-v3.0",
        ],
    },
}


# Filename → file_type tag (used for downstream stats). Keep aligned with
# the static QUERIES tags so the dashboard groupings stay consistent.
def file_type_for(filename: str) -> str:
    fl = filename.lower()
    if fl.startswith(".env") or fl == ".envrc":
        return "env"
    if fl.endswith((".ipynb",)):
        return "notebook"
    if "docker" in fl or "compose" in fl:
        return "docker"
    if fl.endswith((".yml", ".yaml", ".toml", ".json", ".properties")):
        return "config"
    return "config"


def merged_axes_for(provider: str, extensions: dict[str, list[str]] | None = None) -> dict[str, list[str]]:
    """Merge static PROVIDER_AXES[provider] with DB-stored axis_extensions.

    The vocab expander writes new env-names/filenames it discovers in real
    valid-key files into axis_extensions; this helper pulls them back at
    generation time. Returned dict has the same shape as PROVIDER_AXES values
    plus any axes that exist only in extensions (e.g. context_words)."""
    base = PROVIDER_AXES.get(provider, {})
    out: dict[str, list[str]] = {k: list(v) for k, v in base.items()}
    if not extensions:
        return out
    for axis, values in extensions.items():
        existing = set(out.get(axis, []))
        # Preserve order: base first, then new extensions
        out[axis] = list(out.get(axis, [])) + [v for v in values if v not in existing]
    return out
