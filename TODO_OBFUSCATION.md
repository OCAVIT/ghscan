# Obfuscation methods + new providers tracker

Tracker for credential-pool obfuscation patterns AND new AI providers we've
encountered in real public repos. Each entry: detection signal + decoding
approach + status.

**Rule:** new providers go in this file ONLY when the user explicitly asks
us to add them. Random observations of "yet another AI service" leak go
into a side-note at the bottom (or nowhere) — not into the actionable list.

## New providers — pending implementation (user-approved)

### Commonstack — Claude/GPT/DeepSeek/Kimi/GLM aggregator
- **Where seen:** `Wangtrotro/EduAgent/.env.example` (2026-05) — HARDCODED.
- **Endpoint:** `https://api.commonstack.ai/v1` (OpenAI-compatible)
- **Auth:** `Authorization: Bearer ak-...`  (key is `ak-` + 64 hex chars)
- **Available models** (live as of 2026-05-03):
  `anthropic/claude-opus-4-7`, `anthropic/claude-sonnet-4-6`,
  `openai/gpt-5.5`, `deepseek/deepseek-v4-pro`, `deepseek/deepseek-v4-flash`,
  `moonshotai/kimi-k2.6`, `zai-org/glm-5.1`,
  `xiaomi/mimo-v2-pro`, `xiaomi/mimo-v2-omni`, more.
- **Why valuable:** one key → Claude Opus 4.7 (newest!) + GPT 5.5 + GLM 5.1
  + Kimi K2.6 + DeepSeek v4-pro all through ONE aggregator. Much like
  OpenRouter but smaller/less-scanned.

#### Pending validated key to ingest after provider is added
- `ak-aa2901d47f8a79297eb18548438eec02c8fb195d28edfca7753021ac439a245d`
  - Source: `Wangtrotro/EduAgent/.env.example` @ commit
    `30fe2f656bee8b10e4fd71534b063286acf8c749`
  - Tested 2026-05-03: HTTP 200 on `/chat/completions` with
    `anthropic/claude-sonnet-4-6` — **VALID**.
  - When provider is added, POST to `/admin/validate_keys`:
    ```json
    {"source":"manual_commonstack","items":[{
      "provider":"commonstack",
      "key":"ak-aa2901d47f8a79297eb18548438eec02c8fb195d28edfca7753021ac439a245d",
      "repo":"Wangtrotro/EduAgent",
      "path":".env.example",
      "file_url":"https://github.com/Wangtrotro/EduAgent/blob/30fe2f656bee8b10e4fd71534b063286acf8c749/.env.example"
    }]}
    ```

#### Implementation spec (when adding to EXTRACTORS/VALIDATORS)
- **Extractor (`extract_commonstack` in patterns.py)** — context-bound:
  ```python
  _COMMONSTACK_RE = re.compile(
      r'(?<![A-Za-z0-9_\-])(ak-[a-f0-9]{64})(?![A-Za-z0-9])',
  )
  _COMMONSTACK_CTX = re.compile(
      r'(?:COMMONSTACK_API_KEY|api\.commonstack\.ai|commonstack\.ai)'
      r'[\s\S]{0,200}'
      r'(ak-[a-f0-9]{64})',
      re.IGNORECASE,
  )
  ```
  Standalone `ak-` is too generic (Alibaba LTAI also uses `ak-` for some
  services) — REQUIRE commonstack context for the standalone hits, mirror
  perplexity/cerebras pattern.
- **Validator (`validate_commonstack` in validators.py):**
  ```python
  async def validate_commonstack(key: str) -> bool:
      """Commonstack — GET /v1/models. 200 = key auth OK; key reveals
      model catalog with per-token pricing. /chat/completions probe is
      authoritative for billing-dead detection but costs 1 token (≈ $1e-7)."""
      try:
          async with _client() as c:
              r = await c.get(
                  "https://api.commonstack.ai/v1/models",
                  headers={"Authorization": f"Bearer {key}"},
              )
          if r.status_code == 200:
              p = await c.post(
                  "https://api.commonstack.ai/v1/chat/completions",
                  headers={"Authorization": f"Bearer {key}"},
                  json={
                      "model":      "deepseek/deepseek-v4-flash",
                      "messages":   [{"role":"user","content":"hi"}],
                      "max_tokens": 1,
                  },
              )
              if p.status_code == 200:
                  return True
              if p.status_code in (401, 402, 403):
                  return False
              return p.status_code == 429
          if r.status_code in (401, 403):
              return False
          return r.status_code == 429
      except Exception as e:
          log.debug("commonstack validate err: %s", e)
          return False
  ```
- **AI_TRIGGER additions:** `"COMMONSTACK_API_KEY"`, `"commonstack"`,
  `"api.commonstack.ai"`, `"commonstack.ai"`.
- **TG bot metadata:** `"commonstack": {"e": "🪙", "n": "Commonstack"}`,
  add to "Aggregators" category alongside openrouter/aimlapi/etc.
- **QUERIES** (~12 entries):
  ```
  ('"COMMONSTACK_API_KEY" filename:.env',           "commonstack", "env"),
  ('"COMMONSTACK_API_KEY" language:python',         "commonstack", "code"),
  ('"COMMONSTACK_API_KEY" language:javascript',     "commonstack", "code"),
  ('"COMMONSTACK_API_KEY" language:typescript',     "commonstack", "code"),
  ('"api.commonstack.ai" language:python',          "commonstack", "code"),
  ('"api.commonstack.ai" language:javascript',      "commonstack", "code"),
  ('"COMMONSTACK_API_KEY" extension:ipynb',         "commonstack", "notebook"),
  ('"api.commonstack.ai" extension:ipynb',          "commonstack", "notebook"),
  ('"COMMONSTACK_API_KEY" filename:litellm_config.yaml', "commonstack", "litellm"),
  ('"COMMONSTACK_API_KEY" filename:.cursor/mcp.json',    "commonstack", "cursor_mcp"),
  ('"COMMONSTACK_API_KEY" filename:claude_desktop_config.json', "commonstack", "claude_desktop"),
  ('"commonstack" filename:.env.example',           "commonstack", "env"),
  ```

- **Status:** ❌ NOT yet a provider in EXTRACTORS/VALIDATORS. Pending add.
- **Add when:** we have ≥3 leaked Commonstack keys observed, OR user
  explicitly wants it now.


### Luma AI — Dream Machine video gen
- **Where seen:** `bensalemboualem/Saas-iFactory-Algeria/iafactory-core-apps/video-studio/.env.ready` (2026-05) — 2 hardcoded keys.
- **Endpoint:** `https://api.lumalabs.ai/dream-machine/v1/...`
- **Auth:** `Authorization: Bearer luma-...`
- **Key format:** `luma-{8-4-4-4-12}-{8-4-4-4-12}` — `luma-` prefix + UUID + `-` + UUID
- **Validation:** `GET https://api.lumalabs.ai/dream-machine/v1/generations` (200 = alive)
- **Why valuable:** top-tier text-to-video model. $30+/mo paid plans.
  Used by professional video producers.

#### Pending validated keys to ingest after provider is added
**Key 1 (Suisse plan):**
- `luma-ea5617eb-1a5d-4c05-af8e-91aafa4a000c-df1a8424-3446-41ec-88f1-f85714981375`
  - Source: `bensalemboualem/Saas-iFactory-Algeria/iafactory-core-apps/video-studio/.env.ready` @ commit
    `d8a455ea4f6a40455e4771ba0121cf31516f7bea`
  - Not yet tested — validate when provider added.

**Key 2 (default plan):**
- `luma-ec9feb49-902e-4bd9-9985-3af2683b204f-42104104-4d46-4b92-83e7-d1e3b9c5f8c9`
  - Same source.
  - Not yet tested.

#### Implementation spec
- **Extractor (`extract_luma`):**
  ```python
  _LUMA_RE = re.compile(
      r'(?<![A-Za-z0-9_\-])(luma-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-'
      r'[0-9a-f]{4}-[0-9a-f]{12}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-'
      r'[0-9a-f]{4}-[0-9a-f]{12})(?![A-Za-z0-9])',
  )
  # Standalone safe — luma- prefix + double UUID is unique
  def extract_luma(content: str) -> list[str]:
      found = []
      for m in _LUMA_RE.finditer(content):
          k = m.group(1)
          if not _FAKE.search(k):
              found.append(k)
      return list(dict.fromkeys(found))
  ```
- **Validator (`validate_luma`):**
  ```python
  async def validate_luma(key: str) -> bool:
      try:
          async with _client() as c:
              r = await c.get(
                  "https://api.lumalabs.ai/dream-machine/v1/generations",
                  headers={"Authorization": f"Bearer {key}"},
                  params={"limit": 1},
              )
          if r.status_code == 200:
              return True
          if r.status_code in (401, 403):
              return False
          return r.status_code == 429
      except Exception as e:
          log.debug("luma validate err: %s", e)
          return False
  ```
- **AI_TRIGGER additions:** `"LUMA_API_KEY"`, `"luma-"`, `"lumalabs.ai"`,
  `"api.lumalabs"`, `"dream-machine"`.
- **TG bot metadata:** `"luma": {"e": "🌙", "n": "Luma Dream Machine"}`,
  add to AI Video category.
- **QUERIES** (~10):
  ```
  ('"LUMA_API_KEY" filename:.env',                  "luma", "env"),
  ('"LUMA_API_KEY" language:python',                "luma", "code"),
  ('"LUMA_API_KEY" language:javascript',            "luma", "code"),
  ('"LUMA_API_KEY" language:typescript',            "luma", "code"),
  ('"lumalabs.ai" language:python',                 "luma", "code"),
  ('"api.lumalabs.ai" language:javascript',         "luma", "code"),
  ('"luma-" filename:.env',                         "luma", "env"),
  ('"LUMA_API_KEY" extension:ipynb',                "luma", "notebook"),
  ('"LUMA_API_KEY" filename:litellm_config.yaml',   "luma", "litellm"),
  ('"dream-machine" language:python',               "luma", "code"),
  ```
- **Status:** ❌ pending.


### Pika Labs — short-form video gen
- **Where seen:** `bensalemboualem/Saas-iFactory-Algeria/iafactory-core-apps/video-studio/.env.ready` (2026-05) — `PIKA_API_KEY=9aca55bd-7c0a-4e61-81b2-4efa77f3a04c:3d3f299c0a6e57f58a66682a1342620e`
- **Endpoint:** `https://api.pika.art/v1/...`
- **Auth:** `X-API-Key: <UUID:hex>` header
- **Key format:** `<UUID>:<hex32>` — IDENTICAL to fal.ai format!
- **⚠️ CONFLICT with Fal extractor:** our `extract_fal` will catch these
  but the Fal validator returns dead. To fix: tighten Fal extractor to
  REQUIRE `fal` context, AND add explicit Pika extractor that triggers
  on `pika`/`PIKA_API_KEY` context first.

#### Pending validated key to ingest after provider is added
- `9aca55bd-7c0a-4e61-81b2-4efa77f3a04c:3d3f299c0a6e57f58a66682a1342620e`
  - Source: `bensalemboualem/Saas-iFactory-Algeria/iafactory-core-apps/video-studio/.env.ready` @ commit
    `d8a455ea4f6a40455e4771ba0121cf31516f7bea`
  - Not yet tested.

#### Implementation spec
- **Extractor (`extract_pika`):** context-bound — runs BEFORE fal extractor
  in EXTRACTORS dict ordering, so Pika keys claim ownership first when
  PIKA_API_KEY context exists.
  ```python
  _PIKA_CTX = re.compile(
      r'(?:PIKA_API_KEY|PIKA_KEY|api\.pika\.art|pika\.art|pikalabs)'
      r'[\s\S]{0,200}'
      r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
      r':[0-9a-f]{32})',
      re.IGNORECASE,
  )
  def extract_pika(content: str) -> list[str]:
      if not re.search(r'(?i)pika', content):
          return []
      found = []
      for m in _PIKA_CTX.finditer(content):
          k = m.group(1)
          if not _FAKE.search(k):
              found.append(k)
      return list(dict.fromkeys(found))
  ```
  Also need to **tighten Fal extractor**: skip matches whose context
  contains `pika` (negative lookaround on surrounding text).
- **Validator (`validate_pika`):**
  ```python
  async def validate_pika(key: str) -> bool:
      try:
          async with _client() as c:
              r = await c.get(
                  "https://api.pika.art/v1/projects",  # may need adjustment
                  headers={"X-API-Key": key},
              )
          if r.status_code == 200:
              return True
          if r.status_code in (401, 403):
              return False
          return r.status_code == 429
      except Exception as e:
          log.debug("pika validate err: %s", e)
          return False
  ```
  ⚠️ Pika's public API is poorly documented — endpoint may need verification.
- **AI_TRIGGER additions:** `"PIKA_API_KEY"`, `"pika.art"`, `"api.pika"`,
  `"pikalabs"`.
- **TG bot:** `"pika": {"e": "🎬", "n": "Pika Labs"}`, AI Video category.
- **Status:** ❌ pending. Conflicts with Fal — ordering matters.


### Stability AI — image generation (SD/SDXL/SD3)
- **Where seen:** `bensalemboualem/Saas-iFactory-Algeria/iafactory-core-apps/video-studio/.env.ready` (2026-05) — 2 keys (`STABILITY_API_KEY` + `STABILITY_API_KEY_ALT`).
- **Format:** `sk-` + 48 alnum chars (= IDENTICAL to legacy OpenAI key prefix!)
- **Endpoint:** `https://api.stability.ai/v1/user/account` (account info) or `/v2beta/`
- **Auth:** `Authorization: Bearer sk-...`
- **⚠️ CRITICAL CONFLICT with OpenAI extractor:** our `_OAI_PATTERNS` includes
  `re.compile(r'sk-[A-Za-z0-9]{48}')` which catches legacy 48-char OpenAI keys.
  Stability AI keys MATCH this pattern exactly. Currently they get tagged as
  `openai`, validated against `api.openai.com` → ALWAYS dead. **All Stability
  keys we've ever found are saved as dead OpenAI keys in our DB.**

#### Pending validated keys to ingest after provider is added
**Key 1 (primary):**
- `sk-IPRlR6nimTAgBaLHd7KKWkGyIowhqu7wQlNLapFunTpwrGoF`
  - Source: `bensalemboualem/Saas-iFactory-Algeria/iafactory-core-apps/video-studio/.env.ready`
  - Not yet tested as Stability (currently classified as OpenAI=dead).

**Key 2 (alt):**
- `sk-XTqekFfTaGEt6sfDiBgqNfvnxTorWdpk4VNu6WZHMaaQQEME`
  - Same source.

#### Implementation spec
- **Disambiguation logic:** before running `extract_openai`, scan for
  `STABILITY_API_KEY` / `stability.ai` / `api.stability.ai` context.
  If a `sk-[A-Za-z0-9]{48}` key has stability context within 200 chars,
  classify as `stability` and SKIP the OpenAI extractor for that match.
- **Extractor (`extract_stability`):**
  ```python
  _STABILITY_CTX = re.compile(
      r'(?:STABILITY_API_KEY|STABILITY_KEY|api\.stability\.ai|stability\.ai)'
      r'[\s\S]{0,200}'
      r'(sk-[A-Za-z0-9]{48})',
      re.IGNORECASE,
  )
  def extract_stability(content: str) -> list[str]:
      if not re.search(r'(?i)stability', content):
          return []
      found = []
      for m in _STABILITY_CTX.finditer(content):
          k = m.group(1)
          if not _FAKE.search(k):
              found.append(k)
      return list(dict.fromkeys(found))
  ```
  **Also need to update `extract_openai`** to exclude matches whose 200-char
  context contains `stability`.
- **Validator (`validate_stability`):**
  ```python
  async def validate_stability(key: str) -> bool:
      try:
          async with _client() as c:
              r = await c.get(
                  "https://api.stability.ai/v1/user/account",
                  headers={"Authorization": f"Bearer {key}"},
              )
          if r.status_code == 200:
              return True
          if r.status_code in (401, 403):
              return False
          return r.status_code == 429
      except Exception as e:
          log.debug("stability validate err: %s", e)
          return False
  ```
  /v1/user/account returns `{credits: N}` — could also gate on credits>0.
- **AI_TRIGGER additions:** `"STABILITY_API_KEY"`, `"stability.ai"`,
  `"api.stability"`.
- **TG bot:** `"stability": {"e": "🎨", "n": "Stability AI"}`, AI Image cat.
- **QUERIES** (~10): standard pattern as Serper/Commonstack.
- **Status:** ❌ pending. **CRITICAL — disambiguation against OpenAI required**;
  many of our existing "OpenAI dead" keys may actually be live Stability keys.
  When implemented, run a one-time backfill: query DB for `provider='openai'`
  + `is_valid=0`, retest against Stability endpoint, reclassify hits.


### TwelveLabs — video understanding API
- **Where seen:** `kanno321-create/naberal_game/.env` (2026-05).
- **Endpoint:** `https://api.twelvelabs.io/v1.3/...`
- **Auth:** `x-api-key: tlk_...` header (lowercase)
- **Key format:** `tlk_` + base62 24-32 chars
- **Why valuable:** TwelveLabs is the leading video-understanding/RAG API
  (Marengo, Pegasus models). Used in agent stacks doing video search and
  question-answering over video content. Paid plans only.

#### Pending validated key to ingest after provider is added
- `tlk_2KCTAYW0YARGPV2MHDW552D8JDP9`
  - Source: `kanno321-create/naberal_game/.env` @ commit
    `89d79a4b8945dfaba3b78f8cfd782a6ec8295bd5`
  - Not yet tested.

#### Implementation spec
- **Extractor (`extract_twelvelabs`):** prefix is unique — standalone safe.
  ```python
  _TWELVELABS_RE = re.compile(
      r'(?<![A-Za-z0-9_\-])(tlk_[A-Za-z0-9]{20,40})(?![A-Za-z0-9])',
  )
  def extract_twelvelabs(content: str) -> list[str]:
      found = []
      for m in _TWELVELABS_RE.finditer(content):
          k = m.group(1)
          ctx = content[max(0, m.start()-80):m.end()+40]
          if not _FAKE.search(ctx):
              found.append(k)
      return list(dict.fromkeys(found))
  ```
- **Validator (`validate_twelvelabs`):**
  ```python
  async def validate_twelvelabs(key: str) -> bool:
      try:
          async with _client() as c:
              r = await c.get(
                  "https://api.twelvelabs.io/v1.3/indexes",
                  headers={"x-api-key": key},
                  params={"page_limit": 1},
              )
          if r.status_code == 200:
              return True
          if r.status_code in (401, 403):
              return False
          return r.status_code == 429
      except Exception as e:
          log.debug("twelvelabs validate err: %s", e)
          return False
  ```
- **AI_TRIGGER additions:** `"tlk_"`, `"TWELVELABS_API_KEY"`, `"twelvelabs"`,
  `"api.twelvelabs.io"`.
- **TG bot:** `"twelvelabs": {"e": "📹", "n": "TwelveLabs"}`, can land in
  AI Video category.
- **QUERIES** (~10): standard pattern.
- **Status:** ❌ pending.


### Serper.dev — Google Search API (verified live keys found)
- **Endpoint:** `https://google.serper.dev/search`
- **Auth:** `X-API-KEY: <key>` header (NOT `Authorization` — header name is
  literally `X-API-KEY`)
- **Key format:** 40 lowercase hex chars (one segment, no prefix)
- **Why valuable:** $50/mo per key, used in agent stacks (LangChain/CrewAI/
  AutoGen tools). Free tier 2500 lookups/mo, paid up to 500K/mo. Not in any
  partner-program scanner.

#### Pending validated keys to ingest after provider is added (2/3 toward threshold)

**Key 1 — naberal_game (2026-05-03):**
- `a4cae1b486169deaacd4d55f06b178f12a910904`
  - Source: `kanno321-create/naberal_game/.env` @ commit
    `89d79a4b8945dfaba3b78f8cfd782a6ec8295bd5`
  - Tested 2026-05-03: **VALID** — got real Google search results,
    `x-ratelimit-remaining: 24/25` per minute.

**Key 2 — mind-agent (2026-05-03):**
- `ccfc4bf4ffb87d124bda2112c9f37b19f49dae08`
  - Source: `seymaakrs/mind-agent/.env` @ commit
    `f5830200d107337d67bb756dd525f625f5a4aa29`
  - Tested 2026-05-03: **VALID** — same Google search response,
    `x-ratelimit-remaining: 24/25` per minute.

When provider is added, POST both via `/admin/validate_keys`:
```json
{"source":"manual_serper","items":[
  {"provider":"serper","key":"a4cae1b486169deaacd4d55f06b178f12a910904",
   "repo":"kanno321-create/naberal_game","path":".env",
   "file_url":"https://github.com/kanno321-create/naberal_game/blob/89d79a4b8945dfaba3b78f8cfd782a6ec8295bd5/.env"},
  {"provider":"serper","key":"ccfc4bf4ffb87d124bda2112c9f37b19f49dae08",
   "repo":"seymaakrs/mind-agent","path":".env",
   "file_url":"https://github.com/seymaakrs/mind-agent/blob/f5830200d107337d67bb756dd525f625f5a4aa29/.env"}
]}
```

#### Implementation spec
- **Extractor (`extract_serper`):**
  ```python
  _SERPER_CTX = re.compile(
      r'(?:SERPER_API_KEY|SERPER_KEY|google\.serper\.dev|serper\.dev)'
      r'[\s\S]{0,200}'
      r'\b([a-f0-9]{40})\b',
      re.IGNORECASE,
  )

  def extract_serper(content: str) -> list[str]:
      if not re.search(r'(?i)serper', content):
          return []
      found = []
      for m in _SERPER_CTX.finditer(content):
          k = m.group(1)
          if not _FAKE.search(k):
              found.append(k)
      return list(dict.fromkeys(found))
  ```
  Standalone `[a-f0-9]{40}` is too generic (= any SHA-1 / MD5×2.5) — REQUIRE
  `serper` context anywhere in the file.
- **Validator (`validate_serper`):**
  ```python
  async def validate_serper(key: str) -> bool:
      """Serper.dev — POST /search with cheapest 1-result query.
      Cost: 1 credit per call (free tier has 2500 credits)."""
      try:
          async with _client() as c:
              r = await c.post(
                  "https://google.serper.dev/search",
                  headers={"X-API-KEY": key, "Content-Type": "application/json"},
                  json={"q": "ping", "num": 1},
              )
          if r.status_code == 200:
              return True
          if r.status_code in (401, 403):
              return False
          if r.status_code == 402:
              return False  # out of credits
          return r.status_code == 429
      except Exception as e:
          log.debug("serper validate err: %s", e)
          return False
  ```
- **AI_TRIGGER additions:** `"SERPER_API_KEY"`, `"serper"`,
  `"google.serper.dev"`, `"serper.dev"`.
- **TG bot:** `"serper": {"e": "🔍", "n": "Serper.dev"}`, add to a new
  "Search/Tools" category alongside future search-tools.
- **QUERIES** (~10 entries):
  ```
  ('"SERPER_API_KEY" filename:.env',                  "serper", "env"),
  ('"SERPER_API_KEY" language:python',                "serper", "code"),
  ('"SERPER_API_KEY" language:javascript',            "serper", "code"),
  ('"SERPER_API_KEY" language:typescript',            "serper", "code"),
  ('"google.serper.dev" language:python',             "serper", "code"),
  ('"google.serper.dev" language:javascript',         "serper", "code"),
  ('"SERPER_API_KEY" extension:ipynb',                "serper", "notebook"),
  ('"google.serper.dev" extension:ipynb',             "serper", "notebook"),
  ('"SERPER_API_KEY" filename:litellm_config.yaml',   "serper", "litellm"),
  ('"SERPER_API_KEY" filename:.cursor/mcp.json',      "serper", "cursor_mcp"),
  ```

- **Status:** ❌ NOT yet a provider in EXTRACTORS/VALIDATORS. Pending add.


## Methods seen in the wild

### 1. base64 array decode (`Buffer.from(x, "base64")`)
- **Where seen:** `AyGemuy/api-wudysoft/configs/api-key.js` (2026-05)
- **Pattern:** `const decode = keys => keys.map(k => Buffer.from(k, "base64").toString("utf8"));`
  + `const xxxList = ["b64...", "b64...", ...]`
- **Decode:** for each string in array, `base64.b64decode(s + "==").decode("utf-8")`
  Sometimes wrapped — outer base64 decodes to inner `c2st...` which is itself another base64 layer (Z.AI/threezero Bearer tokens use double-b64).
- **Result example:** 119 keys recovered (49 OpenRouter + 28 Gemini + ...)
- **Status:** ❌ scanner does NOT auto-detect. Manual via `/admin/validate_keys`.
- **Plan:** add base64 pre-pass — if file has `Buffer.from(x,"base64")` or
  `atob(` or `base64.b64decode(` AND a long array of `[A-Za-z0-9+/=]{30,}`
  strings, decode each and re-run AI_TRIGGER + EXTRACTORS on the decode.

### 2. ORM/driver constructor split (Sequelize, psycopg2, etc.)
- **Where seen:** `yyupcompany/kyyupgame/k.yyup.com/add-correct-doubao.js` (2026-05)
- **Pattern:** DB credentials split across constructor args, NOT in DSN form:
  ```js
  new Sequelize('dbname', 'user', 'password', {
    host: 'host.example.com',
    port: 43906,
    dialect: 'mysql',
  });
  ```
  Same shape in Python `psycopg2.connect(host=, user=, password=, dbname=)`,
  Java `DataSource.setUrl/.setUsername/.setPassword`, Go's positional
  `sql.Open("mysql", "user:pass@tcp(host)/db")`.
- **Decode:** parse the constructor args + nearby option object, reassemble
  into canonical DSN, then run our existing infra extractors.
- **Status:** ❌ scanner pipeline does NOT detect — requires AST/heuristic parse.

### 3. JS string fragmentation (concat / template / array.join)
- **Pattern A (plus-concat):** `const k = "sk-" + "proj-" + "abc..." + "xyz";`
- **Pattern B (template literal):** `` `sk-proj-${"abc"+"def"}` ``
- **Pattern C (array join):** `["sk", "proj", "abc..."].join("-")`
- **Why used:** dodges naive grep but our regex still won't catch it because
  the string isn't whole in source. Common in obfuscator.io output and in
  hand-rolled "anti-leak" fragments.
- **Decode plan:** AST-pass via Babel/SWC to evaluate constant-foldable
  string expressions. Lighter heuristic — regex pre-pass that finds
  `"[A-Za-z0-9_\-]+"\s*\+\s*"[A-Za-z0-9_\-]+"` chains, concat them in
  order, re-run AI_TRIGGER. Bound to ≤10 concats per chain (longer = noise).
- **Status:** ❌ scanner does NOT auto-detect.

### 4. Char-code arrays (`String.fromCharCode(115,107,...)`)
- **Pattern:** `String.fromCharCode(115,107,45,112,114,111,106,45,...)`
  decodes to `sk-proj-...`
- **JS variant:** `[115,107,45].map(c=>String.fromCharCode(c)).join("")`
- **Python variant:** `"".join(chr(x) for x in [115,107,45,...])` /
  `bytes([115,107,...]).decode()`
- **Why used:** common in obfuscator.io and hand-rolled cryptominer-style
  obfuscation. Also seen in malware-adjacent "free key" projects.
- **Decode plan:** find `String.fromCharCode(<numlist>)` / `chr(...)` /
  `bytes([...])` patterns where numlist length ≥16 and all values 32-126,
  decode to ASCII string, re-run AI_TRIGGER.
- **Status:** ❌ scanner does NOT auto-detect.

### 5. Hex encoding (`bytes.fromhex` / `Buffer.from(x, "hex")`)
- **Pattern:** `key = bytes.fromhex("736b2d70726f6a2d...").decode()`
- **Why used:** trivial extra layer that defeats `grep -E "sk-"`.
- **Decode plan:** find hex strings ≥32 chars adjacent to `fromhex` /
  `unhexlify` / `"hex"` decoder calls, decode, re-run AI_TRIGGER.
- **Status:** ❌ scanner does NOT auto-detect.

### 6. Reversed strings + reverser call
- **Pattern A:** `k = "...uIdroF-evrCsiht".split("").reverse().join("")`
- **Pattern B (Python):** `k = "...iah-skla"[::-1]`
- **Why used:** ultra-cheap obfuscation, often paired with b64.
- **Decode plan:** detect `.reverse()` / `[::-1]` near a long string
  literal, reverse it, run AI_TRIGGER. Cheap heuristic.
- **Status:** ❌ scanner does NOT auto-detect.

### 7. CryptoJS / WebCrypto AES with hardcoded passphrase
- **Pattern:** `CryptoJS.AES.decrypt(b64_blob, "hardcoded-passphrase").toString(CryptoJS.enc.Utf8)`
  + a long ciphertext literal. Same shape with `crypto.createDecipheriv`
  in Node.js, `Fernet(KEY).decrypt(...)` in Python (`cryptography` lib),
  `AES.new(KEY, AES.MODE_CBC, IV).decrypt(...)` (PyCryptodome).
- **Why used:** dev wraps the key "for security" but ships passphrase
  in same file — security theater.
- **Decode plan:** detect decrypt call + adjacent string literal
  passphrase + b64 ciphertext. Use the SAME library to decrypt
  (subprocess to a small Node/Python helper), re-run AI_TRIGGER.
  Bound: only attempt when passphrase + ciphertext are both literals.
- **Status:** ❌ scanner does NOT auto-detect. Medium implementation cost.

### 8. XOR with hardcoded key (mostly malware-adjacent)
- **Pattern:** `''.join(chr(c ^ 0x42) for c in [...])` or JS variant.
- **Why used:** rare in legit projects; common in stealer / loader
  samples. Worth catching because some "free API key pool" projects
  copy stealer obfuscation patterns wholesale.
- **Decode plan:** detect XOR loop + numeric array + 1-byte constant,
  brute-force all 256 XOR keys, run AI_TRIGGER on each decode.
  Cap at 256 candidates per occurrence.
- **Status:** ❌ scanner does NOT auto-detect.

### 9. `eval` / `Function()` / `exec` wrapped string literals
- **Pattern:** `eval(atob("...b64_with_a_decoded_'sk-proj-...'..."))`
  or `Function("return " + atob("..."))()`. Python: `exec(base64.b64decode("..."))`.
- **Why used:** classic "load malware string at runtime" pattern.
  Some legit AI-pool projects use it to dodge GitHub's secret scanner.
- **Decode plan:** detect `eval(`/`Function(`/`exec(` + adjacent
  decoder call (atob / b64decode / fromhex), unwrap, re-run AI_TRIGGER.
  Treat as nested b64 case.
- **Status:** ❌ scanner does NOT auto-detect.

### 10. Webpack/Vite chunked split (key in different chunk than consumer)
- **Pattern:** built JS bundle ships key in `assets/index-XYZ.js` but
  the consumer code that uses it is in `assets/chunk-ABC.js`. `grep
  AIzaSy assets/` finds it, but our SHA-dedup may skip the chunk if
  we already scanned the consumer chunk under a different name.
- **Why happens:** Vite/Webpack split + content-hash file names mean
  every rebuild produces new file paths → our `tree_walked_repos`
  marker prevents re-scan even when chunks rotated.
- **Decode plan:** for repos with `dist/`, `build/`, `.next/`, `_next/`,
  `assets/`, `out/`, `.nuxt/` directories — ALWAYS run all `*.js` files
  through extractors, even if we've previously walked the repo.
  Use file content SHA, not path SHA, for dedup.
- **Status:** ❌ scanner pipeline currently dedupes by repo, would
  miss multi-chunk leaks across rebuilds. Affects every SPA-built repo.

### 11. SSR initial state hydration (`window.__NEXT_DATA__`, etc.)
- **Pattern:** Next.js / Nuxt / Remix dump server-side props into HTML:
  ```html
  <script id="__NEXT_DATA__" type="application/json">
    {"props":{"pageProps":{"apiKey":"sk-..."}}}
  </script>
  ```
- **Where seen:** Vercel-deployed SaaS that accidentally returns
  server env via `getServerSideProps`. Also seen in mobile webview
  apps embedding hydration JSON.
- **Decode plan:** when scanning HTML, parse `<script>` tags with
  `id="__NEXT_DATA__"` / `id="__NUXT__"` / `id="__INITIAL_STATE__"`,
  JSON-decode, recurse into all string values, run AI_TRIGGER per
  string. Same idea as JSON config files.
- **Status:** ❌ scanner does NOT auto-detect HTML hydration data.

### 12. Kubernetes Secret YAML / Docker base64 (committed manifests)
- **Pattern:** `apiVersion: v1\nkind: Secret\ndata:\n  api-key: c2stcHJvai0u...`
  — `data:` field of K8s Secret is base64. Devs commit these
  thinking "it's encrypted" — it's just b64.
- **Where:** `k8s/`, `manifests/`, `.k8s/`, `helm/`, `charts/` dirs
  + `*.yaml` with `kind: Secret`.
- **Decode plan:** YAML-parse, find `kind: Secret` blocks, b64-decode
  every value under `data:`, re-run AI_TRIGGER.
- **Status:** ❌ scanner does NOT auto-detect.

### 13. CI/CD literal env (people inline keys, removing `${{ secrets.X }}`)
- **Pattern:** `.github/workflows/*.yml` job env block where a secret
  reference was replaced by a literal during local debugging:
  ```yaml
  env:
    OPENAI_API_KEY: sk-proj-actualLeak  # was: ${{ secrets.OPENAI_API_KEY }}
  ```
- **Other paths:** `.gitlab-ci.yml`, `.circleci/config.yml`,
  `azure-pipelines.yml`, `.drone.yml`, `bitbucket-pipelines.yml`,
  `Jenkinsfile`, `.buildkite/pipeline.yml`.
- **Decode plan:** ALREADY caught by generic regex if file is
  scanned; confirm we have queries for these filenames specifically.
  Add `path:.github/workflows`, `path:.circleci`, etc.
- **Status:** ⚠️ partial — generic patterns match, but no targeted
  queries to surface CI-leak files separately at search-cap.

### 14. Test fixtures with real keys (`tests/fixtures/*.json`, `__mocks__/`)
- **Pattern:** integration test author copies prod env vars into
  fixture JSON: `tests/fixtures/openai_response.json` includes a
  real `Authorization` header captured during recording.
- **Where seen:** especially common for VCR-style cassettes
  (`tests/cassettes/*.yaml`, `tests/__recordings__/*.json`).
- **Decode plan:** add queries `path:tests/fixtures`, `path:__mocks__`,
  `path:cassettes`, `extension:cassette`. JSON-walk for `Authorization`
  / `headers.X-Api-Key` keys with literal values.
- **Status:** ❌ no targeted coverage.

### 15. Jupyter notebook OUTPUT cells (not inputs)
- **Pattern:** dev runs `print(os.environ)` or `!env | grep KEY`
  in a cell, key ends up in cell `outputs[].text` JSON, gets
  committed with the notebook.
- **Where seen:** any `.ipynb` with `outputs` arrays. Our extractors
  scan the `source` arrays of cells but **may not parse outputs**.
- **Decode plan:** when ipynb-parsing, extract BOTH `cells[].source`
  AND `cells[].outputs[].text` / `cells[].outputs[].data."text/plain"`,
  pass concatenated to extractors.
- **Status:** ❓ unverified — check what our current ipynb path does.
  If outputs aren't parsed, this is a 30-50% recall gain on notebooks.

### 16. Mobile artifacts (BuildConfig, AndroidManifest meta-data, sqlite)
- **Pattern:** decompiled APKs leak via:
  - `BuildConfig.java`: `public static final String API_KEY = "sk-...";`
  - `AndroidManifest.xml`: `<meta-data android:name="com.google.android.geo.API_KEY" android:value="AIza..."/>`
  - shipped sqlite/sqlitecipher DBs in `assets/` with key in a row
  - `.so` binaries with embedded strings (catch via `strings -a`)
  - shared_prefs XML (in extracted runtime data, not in repo)
- **Decode plan:** out of scope for GitHub scanner BUT useful to
  flag: queries `extension:smali "API_KEY"`, `filename:BuildConfig.java`
  catch the source side. APKs themselves require apkleaks/MobSF
  (already in our toolbox per CLAUDE.md).
- **Status:** ⚠️ partial — repos with decompiled-APK source committed
  would be caught by generic patterns, but no targeted queries.

### 17. Cloudflare Workers `wrangler.toml` `[vars]` section
- **Pattern:** `[vars]\nOPENAI_API_KEY = "sk-proj-..."`. Devs use
  this for "secrets" without realizing `[vars]` is plaintext-committed
  (Cloudflare's actual secrets go via `wrangler secret put` and
  never touch the toml).
- **Decode plan:** add queries `filename:wrangler.toml "OPENAI_API_KEY"`,
  `"ANTHROPIC_API_KEY"`, etc. Same for `wrangler.jsonc`.
- **Status:** ❌ no targeted queries.

### 18. Storybook / Playwright / e2e config files
- **Pattern:** `playwright.config.ts`, `cypress.config.js`,
  `.storybook/main.ts` — devs put real auth tokens for "preview"
  env to make staging tests work.
- **Decode plan:** add filename-targeted queries.
- **Status:** ❌ no coverage.

### 19. "Documentation example" / docstring camouflage ⚡ (proven yield)
- **Where seen 2026-05-03:** `ookok/LivingTreeAlAgent/client/src/business/encrypted_config.py:18`
  — DeepSeek key `sk-f05ded8271b74091a499831999d34437` placed inside a Python
  docstring as a "usage example" alongside fake-looking comment context.
  Validated **LIVE with ¥118.07 CNY (~$16.5) topped-up balance**.
- **Pattern:** dev wraps the real key in a docstring / triple-quoted
  comment / Markdown code-fence example, framed as "how to use"
  documentation. The key is real — they tested with it during dev,
  forgot to redact, committed it as "example".
- **Other shapes:**
  - JSDoc `/** @example const k = "sk-..." */` blocks
  - Sphinx/RST `.. code-block::` examples in `.rst` files
  - GoDoc `// Example: client.SetKey("sk-...")` lines
  - Markdown ` ```python\nopenai.api_key = "sk-..."` ``` fences
  - Jupyter notebook markdown cells "documenting" usage
- **Why high-yield:** ✅ already caught by generic regex (no decode
  needed — key is plain text). BUT priority de-ranks docstring matches
  in our current scoring? Verify: do we treat docstring/comment context
  as low-confidence? Should NOT — these have proven full validity.
- **Status:** ✅ extractors catch it, BUT worth a dedicated query
  bucket to surface them separately for prioritized validation:
  ```python
  ('"sk-" "Usage:" extension:py',                       "deepseek", "docstring"),
  ('"api_key" "@example" extension:js',                 "openai", "jsdoc_example"),
  ('"api_key" "Example:" extension:go',                 "openai", "godoc_example"),
  ('"OPENAI_API_KEY" "```python" extension:md',         "openai", "md_codefence"),
  ```

### 20. AES-GCM / Fernet / XOR encrypted in YAML/JSON config (homebrew vault)
- **Where seen:** `ookok/LivingTreeAlAgent/config/livingtree.yaml:6`
  — `api_key: "GVpfdR3wJDcJNgHFu3qC8znqFb6wnAl8n5GS8MwI87A4YgAV/yjO53i7SiBvCGUUSslc5y9QISbTgc52UDyV"`
  — 84-char base64 ciphertext.
  Dev rolled their own "vault" in [livingtree/infrastructure/encrypted_config.py]:
  - `LIVINGTREE_SECRET_KEY` env var → preferred decryption key
  - `data/.ltkey` file → fallback (✅ if committed = trivial decrypt)
  - `sha256(COMPUTERNAME or "livingtree")[:32]` → final fallback
  Encryption is AES-GCM (with `nonce + ct` packed) or Fernet (if AES-GCM
  module missing) or XOR-with-machine-key (if cryptography not installed).
- **Pattern:** dev imports `cryptography.hazmat.primitives.ciphers.aead.AESGCM`
  or `cryptography.fernet.Fernet`, encrypts API keys in YAML/JSON config,
  hardcodes machine-fingerprint password OR commits `.ltkey`/`.key` file.
- **Other shapes:**
  - SOPS-encrypted YAML (`encrypted_data_key:` + `sops:` block) — needs
    age/PGP key, but unencrypted SOPS files are sometimes committed.
  - `git-crypt` encrypted blobs (binary `.git-crypt-` magic prefix).
  - `ansible-vault` `$ANSIBLE_VAULT;1.1;AES256` headers — vault password
    sometimes committed as `.vault_pass.txt`.
  - `dotenv-vault` (`.env.vault` files) — DOTENV_KEY in commit messages.
- **Decode plan:**
  1. **Detect ciphertext shape:**
     - Fernet: `gAAAAAB[A-Za-z0-9_\-=]{60,}`
     - AES-GCM custom: `[A-Za-z0-9+/=]{40,200}` near keys named
       `api_key`/`secret`/`token` AND `cryptography.hazmat` import in
       same repo
     - SOPS: `^sops:\s*$` block header in YAML
     - Ansible Vault: `$ANSIBLE_VAULT;` magic
  2. **Hunt for decoder key in repo:**
     - `data/.ltkey`, `.ltkey`, `data/.key`, `secrets.key`, `master.key`,
       `.master_key`, `keystore`, `.vault_pass*`, `vault-password*`,
       `.env.vault`, `secret.key`, `config/key.txt`
     - Env-var name patterns: `*_SECRET_KEY`, `MASTER_KEY`, `VAULT_KEY`
       referenced in code with `os.environ.get(...)` — search for
       commits / CI files that set them.
  3. **Try fallback derivation:**
     - `sha256("livingtree")` (default fingerprint when COMPUTERNAME unset)
     - Common dev usernames pulled from `git log --format='%ae'`
     - `platform.node()` candidates from README hints
  4. **AES-GCM unwrap:**
     ```python
     from cryptography.hazmat.primitives.ciphers.aead import AESGCM
     import base64, hashlib
     key = hashlib.sha256(b"livingtree").digest()[:32]  # fallback
     blob = base64.b64decode(ciphertext)
     plaintext = AESGCM(key).decrypt(blob[:12], blob[12:], None)
     ```
- **Yield assumption:** when decoder key is committed (`.ltkey`,
  `.vault_pass.txt`, `dotenv.vault.key` in CI workflows), decrypt
  succeeds 100%. When only fallback fingerprint, ~5% (lucky default
  COMPUTERNAME match). Worth implementing because committed
  decoder-key files DO appear — many devs put them in `.gitignore`
  AFTER initial commit, so git history has them.
- **Status:** ❌ scanner does NOT detect or attempt decryption.
  Most useful when paired with `git log -p -- '.ltkey'` style search
  on found-leak repos.

---

## High-yield project archetypes (search expansion)

The single biggest insight from manual audits 2026-05-03: certain
PROJECT TYPES accumulate dozens of keys per repo. Targeting these
classes specifically (vs random `"OPENAI_API_KEY"` searches) gives
order-of-magnitude better yield/query.

### A. LLM aggregator / proxy / "free key pool" projects
**Why high-yield:** these projects literally exist to bundle many
keys into one endpoint. Some publish them as decorated arrays
(see wudysoft method 1). Examples seen:
- AyGemuy/api-wudysoft (119 keys recovered — 49 OR + 28 Gemini + ...)
- self-hosted LiteLLM proxies (`litellm_config.yaml` — already in queries)
- "ChatGPT-Next-Web" forks with admin-key arrays
- Helicone / Portkey / OpenRouter clones

**Search signals:**
```python
('"litellm_proxy" filename:config.yaml',          "any", "litellm"),
('"model_list:" filename:litellm_config.yaml',    "any", "litellm"),
('"providers" "openai" "anthropic" extension:json', "any", "aggregator"),
('"key_pool" language:python',                     "any", "key_pool"),
('"keyPool" language:javascript',                  "any", "key_pool"),
('"apiKeys: [" extension:js',                      "any", "key_array"),
('"apiKeys = [" extension:py',                     "any", "key_array"),
('"OPENAI_API_KEYS" filename:.env',                "openai", "multi_key"),
('"ANTHROPIC_API_KEYS" filename:.env',             "anthropic","multi_key"),
('"openai_keys" extension:json',                   "openai", "key_array"),
('"chatgpt-next-web" filename:.env',               "any", "next_web"),
('"helicone" filename:.env',                       "any", "helicone"),
('"portkey" filename:.env',                        "any", "portkey"),
('"AdminGate" "openai" extension:js',              "any", "admin_panel"),
```

### B. Multi-provider chat UIs (NextChat, LobeChat, OpenWebUI, Anything-LLM)
**Why high-yield:** users self-host these and embed personal keys
into config files committed to forks. Each install has
OpenAI + Anthropic + Google + Groq + many more.

**Search signals:**
```python
('"NEXT_PUBLIC_OPENAI_API_KEY" filename:.env',     "openai", "nextchat"),
('"OPENAI_API_KEY" "ANTHROPIC_API_KEY" "GOOGLE_API_KEY" filename:.env', "any", "multi_provider_chat"),
('"lobe-chat" filename:.env',                       "any", "lobechat"),
('"open-webui" filename:.env',                      "any", "openwebui"),
('"anythingllm" filename:.env',                     "any", "anythingllm"),
('"librechat" filename:.env',                       "any", "librechat"),
('"big-AGI" filename:.env',                         "any", "bigagi"),
```

### C. AI agent frameworks (LangChain, CrewAI, AutoGen, LangGraph, smolagents)
**Why high-yield:** agents call many tools (web search, code exec,
image gen, embedding) → many provider keys at once.

**Search signals:**
```python
('"langchain" "OPENAI_API_KEY" "TAVILY_API_KEY" filename:.env', "any", "langchain"),
('"crewai" filename:.env',                          "any", "crewai"),
('"autogen" "config_list" extension:json',          "any", "autogen"),
('"langgraph" filename:.env',                       "any", "langgraph"),
('"smolagents" filename:.env',                      "any", "smolagents"),
('"haystack" filename:.env',                        "any", "haystack"),
```

### D. AI bootcamp / course / hackathon templates
**Why high-yield:** N students each push a fork with their own keys.
Templates often have `.env.example` schema that students fill in
literally and commit. Today's audit found `tenx-10academy-bootcamp`
template re-leaked by 2 students with different keys each. Also:
- Microsoft Generative-AI for Beginners
- Stanford CS25 / CS324 student forks
- Hackathon submissions (Devpost-linked repos)

**Search signals:**
```python
('"AIMLAPI_KEY" "KLINGAI_API_KEY" filename:.env.example', "aimlapi", "10academy"),
('"AIMLAPI_KEY" "GEMINI_API_KEY" filename:.env',          "aimlapi", "bootcamp"),
('"bootcamp" filename:.env',                              "any", "bootcamp"),
('"hackathon" filename:.env',                             "any", "hackathon"),
('"week0" filename:.env',                                 "any", "course"),
('"week_0" filename:.env',                                "any", "course"),
('"assignment" "OPENAI_API_KEY" filename:.env',           "openai", "assignment"),
('"submission" "OPENAI_API_KEY" filename:.env',           "openai", "submission"),
('"capstone" "OPENAI_API_KEY" filename:.env',             "openai", "capstone"),
```

### E. Discord/Telegram/Slack AI bots (multi-provider)
**Why high-yield:** bot devs juggle BOT_TOKEN + LLM key + image
gen + TTS in one .env.

**Search signals:**
```python
('"DISCORD_TOKEN" "OPENAI_API_KEY" filename:.env',      "any", "discord_bot"),
('"TELEGRAM_BOT_TOKEN" "OPENAI_API_KEY" filename:.env', "any", "tg_bot"),
('"SLACK_BOT_TOKEN" "OPENAI_API_KEY" filename:.env',    "any", "slack_bot"),
('"discord.py" "OPENAI_API_KEY" extension:py',          "any", "discord_bot"),
('"aiogram" "OPENAI_API_KEY" extension:py',             "any", "tg_bot_aiogram"),
('"telegraf" "OPENAI_API_KEY" extension:js',            "any", "tg_bot_telegraf"),
```

### F. RAG / vector DB starter kits
**Why high-yield:** each kit ships LLM + embedding model + vector
DB key (Pinecone/Weaviate/Qdrant/Chroma). 3+ keys per repo.

**Search signals:**
```python
('"PINECONE_API_KEY" "OPENAI_API_KEY" filename:.env',   "any", "rag_pinecone"),
('"WEAVIATE_API_KEY" "OPENAI_API_KEY" filename:.env',   "any", "rag_weaviate"),
('"QDRANT_API_KEY" "OPENAI_API_KEY" filename:.env',     "any", "rag_qdrant"),
('"CHROMA_SERVER_AUTHN_CREDENTIALS" filename:.env',     "any", "chroma"),
('"llamaindex" filename:.env',                          "any", "llamaindex"),
```

### G. AI image/video gen sites (front-end leaks)
**Why high-yield:** SPA devs put image/video gen keys in client
JS bundles thinking they're "scoped". Each project has 1-3 keys.
Saw 4 already today.

**Search signals:**
```python
('"VITE_FAL_KEY" extension:env',                        "fal", "vite_frontend"),
('"VITE_REPLICATE_API_TOKEN" extension:env',            "replicate", "vite"),
('"VITE_AIMLAPI" extension:env',                        "aimlapi", "vite"),
('"NEXT_PUBLIC_FAL_KEY" extension:env',                 "fal", "next_frontend"),
('"NEXT_PUBLIC_REPLICATE" extension:env',               "replicate", "next"),
('"REACT_APP_FAL_KEY" extension:env',                   "fal", "cra_frontend"),
('"VITE_OPENAI_API_KEY" extension:env',                 "openai", "vite"),
```

### H. AI coding assistants (MCP / Continue / Aider / Cline configs)
**Why high-yield:** users put MULTIPLE LLM keys in MCP/Continue
configs to compare models. Seen up to 8 keys in one config.

**Search signals (some already exist for Cursor MCP, expand):**
```python
('"continue.dev" filename:config.json',                 "any", "continue"),
('"aider" filename:.env',                               "any", "aider"),
('"cline" filename:settings.json',                      "any", "cline"),
('"roo-cline" filename:settings.json',                  "any", "roo_cline"),
('"zed" "openai" extension:json',                       "any", "zed_editor"),
```

### I. "Prompt engineering" / AI playground sandboxes
**Why high-yield:** these are explicitly multi-provider for A/B
testing prompts. Each has 5+ keys.

**Search signals:**
```python
('"promptfoo" filename:.env',                           "any", "promptfoo"),
('"helicone" filename:.env',                            "any", "helicone"),
('"langfuse" filename:.env',                            "any", "langfuse"),
('"phoenix" "openai" filename:.env',                    "any", "phoenix"),
('"mlflow" "openai" filename:.env',                     "any", "mlflow"),
```

### J. Browser extensions for AI
**Why high-yield:** extension manifest + background.js often hold
LLM key in plaintext. Easy to find via `manifest.json` queries.

**Search signals:**
```python
('"manifest_version" "openai" extension:json',          "openai", "browser_ext"),
('"chrome.runtime" "OPENAI_API_KEY" extension:js',      "openai", "chrome_ext"),
```

### K. SaaS clones (ChatGPT, Midjourney, Sora, Runway clones)
**Why high-yield:** indie devs ship "SaaS in a box" with admin
keys committed. Each clone = 2-5 provider keys.

**Search signals:**
```python
('"chatgpt-clone" filename:.env',                       "any", "chatgpt_clone"),
('"midjourney-clone" filename:.env',                    "any", "mj_clone"),
('"sora-clone" filename:.env',                          "any", "sora_clone"),
('"saas" "openai" "stripe" filename:.env',              "any", "ai_saas"),
('"clerk" "openai" filename:.env',                      "any", "clerk_saas"),
('"supabase" "openai" filename:.env',                   "any", "supabase_saas"),
```

### Implementation priority
1. **D (bootcamp)** — proven yield (today), 2/2 hits in template-fork audit. Add first.
2. **A (aggregator)** — already proven via wudysoft (119 keys). Add second.
3. **C (agent frameworks)** — likely 5+ keys per hit, high density.
4. **B (multi-provider chat UIs)** — popular OSS, many self-hosters.
5. **F (RAG kits)** — guaranteed 2+ keys per hit (LLM + vector DB).
6. **E (Discord/TG bots)** — bot tokens + LLM keys, 2+ per hit.
7. **G/H/I/J/K** — incremental.

**Total query expansion budget:** ~80 new queries across A-K above
(currently 1374 queries, going to ~1454, +6%). One-time addition,
zero infra change.

---

## Scanner architecture improvements

### Markdown coverage — add `extension:md` queries (medium-impact)

**Evidence (collected 2026-05-03, manual repo audits):**
2 out of 17 manually-audited repos had hardcoded AI keys in `.md` files:
- `mdl-systems/cocoro-influencer/docs/migration_to_render01.md` — LipSync key
- `kbtime/openclaw-workspace/.opencode/CONFIG_REPORT.md` — 4 LLM keys
  (GLM/Qwen/Kimi/MiniMax) committed as a "config report" the dev wrote
- `kbtime/openclaw-workspace/memory/2026-02-10.md` — Bocha Search key

**Hit rate ≈ 12%** of repos with leaks have ≥1 key in markdown.
Pattern: dev internal-doc files (`migration_*.md`, `CONFIG_REPORT.md`,
`SETUP.md`, `INSTALL.md`, `memory/*.md`, `docs/*.md`) — written for
internal team reference and accidentally committed.

**Current coverage:** 22 of our 1374 queries use `extension:ipynb`
(notebooks) but **ZERO** use `extension:md`. Generic queries like
`"OPENAI_API_KEY"` (no extension filter) DO scan markdown, but at
GitHub Code Search's ~1000-result cap markdown loses priority to
`.py`/`.env` matches. Targeted `extension:md` queries would surface
markdown leaks separately.

**Plan:**
Add ~30 queries with `extension:md` for top-yield providers:
```python
('"OPENAI_API_KEY" extension:md',         "openai", "markdown"),
('"sk-proj-" extension:md',               "openai", "markdown"),
('"ANTHROPIC_API_KEY" extension:md',      "anthropic", "markdown"),
('"sk-ant-api03-" extension:md',          "anthropic", "markdown"),
('"GOOGLE_API_KEY" extension:md',         "google", "markdown"),
('"GEMINI_API_KEY" extension:md',         "google", "markdown"),
('"OPENROUTER_API_KEY" extension:md',     "openrouter", "markdown"),
('"sk-or-v1-" extension:md',              "openrouter", "markdown"),
('"DEEPSEEK_API_KEY" extension:md',       "deepseek", "markdown"),
('"MOONSHOT_API_KEY" extension:md',       "kimi", "markdown"),
('"KIMI_API_KEY" extension:md',           "kimi", "markdown"),
('"ZHIPUAI_API_KEY" extension:md',        "glm", "markdown"),
('"REPLICATE_API_TOKEN" extension:md',    "replicate", "markdown"),
('"FAL_KEY" extension:md',                "fal", "markdown"),
('"HF_TOKEN" extension:md',               "huggingface", "markdown"),
# Also filename-targeted hits — high-density file types
('"sk-proj-" filename:CONFIG_REPORT.md',  "openai", "config_report"),
('"OPENAI_API_KEY" filename:SETUP.md',    "openai", "setup_md"),
('"OPENAI_API_KEY" filename:INSTALL.md',  "openai", "install_md"),
('"OPENAI_API_KEY" filename:README.md',   "openai", "readme"),
('"OPENAI_API_KEY" filename:migration.md',"openai", "migration_md"),
# Same for top 3 providers (anthropic/google/openrouter) for filename: targets
```

Total: ~50 new queries, one-time addition.
Yield estimate: at 12% hit rate × ~1000 unique repos returned per query
× 0.3 keys/repo = ~360 additional keys per cycle.

**Cleanup also:** remove dead `is_server_path()` function from
`patterns.py:50` — defined but never imported anywhere.

- **Status:** ❌ pending. Low effort (~30 lines added to QUERIES list).


### Author tracking — continuous monitoring of serial leakers ⭐ (highest-impact)

**Insight:** secret-leaking is a habit, not a one-off accident. A dev who
commits `.env` to one repo without `.gitignore` very likely does it again
in their next project. Tracking these "serial leakers" gives us a high-
signal feed of where to look NEXT.

**Schema** — add to `db.py`:
```sql
CREATE TABLE IF NOT EXISTS watched_authors (
    login           TEXT PRIMARY KEY,
    platform        TEXT NOT NULL,           -- github/gitee/codeberg/bitbucket
    leak_count      INTEGER DEFAULT 0,        -- distinct keys we've found
    valid_count     INTEGER DEFAULT 0,        -- of those, currently valid
    repos_with_leaks INTEGER DEFAULT 0,
    first_leak_at   TEXT NOT NULL,
    last_leak_at    TEXT NOT NULL,
    last_walked_at  TEXT,                     -- last time we scanned all their repos
    is_watched      INTEGER DEFAULT 0         -- 1 = on auto-watch list
);
```

**Workflow:**

1. **Auto-population** — every time `db.save_key` inserts a row, parse
   `repo` field as `{owner}/{name}` and increment `watched_authors.leak_count`
   for that owner (UPSERT).

2. **Promotion to watch list** — when `leak_count >= 3` for an author,
   set `is_watched=1`. This is the signal that they're a serial leaker.

3. **New scanner: `author_scanner.py`** — every 24h:
   - For each `is_watched=1` author, list ALL their public repos:
     `GET /users/{login}/repos?type=public&per_page=100&sort=pushed`
   - Filter to repos updated since `last_walked_at` (incremental)
   - For each repo, run the SAME tree-walk logic from the
     "Repo tree-walk after key found" item above
   - Update `last_walked_at` after successful walk.

4. **Bot-feed integration** — add a `/admin/watched_authors` endpoint
   showing top leakers ranked by valid_count. Could expose to Telegram
   bot as a new menu category "🎯 Top leakers" with `/recent_from/{login}`
   commands to pull their latest keys on demand.

**Why this is high-yield:**
- A leaker with 10 public repos × ~0.3 keys/repo (our average) ≈ 3 keys
  per author. If `leak_count >= 3` they have on average 8-15 more repos
  worth scanning, each with elevated leak probability vs random.
- Continuous monitoring: every NEW commit by these users triggers
  re-scan. Captures keys within hours of leak (vs days/weeks for our
  current "search across all GitHub" approach).
- Compounds with tree-walk: tree-walk finds all keys in CURRENT repos;
  author-watch finds all keys in FUTURE repos.

**Yield estimate:**
- Conservative: assume 5% of authors with 1+ leak end up with 3+ leaks
  (= "watched"). With ~30K unique authors in our DB → ~1500 watched.
  Each watched author × 5 repos avg × 0.5 valid keys/repo → +3750 valid
  keys from this signal alone.
- Aggressive (if we backfill our existing 190K repos): could double
  the watched set and yield.

**Cross-platform extension:** same logic applies to Gitee/Codeberg/
Bitbucket — track per-platform `(platform, login)` tuples. Codeberg
especially valuable because account creation is anonymous and people
who use Codeberg deliberately tend to be less careful with secrets.

**Privacy / abuse considerations:**
- We're tracking PUBLIC GitHub usernames who PUBLISHED their leaks.
  No private data accessed.
- Don't auto-share author identities outside our system (no public
  shaming). Keep `watched_authors` table internal.

- **Status:** ❌ pending. Schema change + new background task in main.py.
  ~200 lines of new code (db function + scanner + tg menu).
  Synergy with tree-walk improvement above — implement together for max effect.

### Repo tree-walk after key found ⭐ (high-impact)

**Problem identified:** GitHub Code Search has 30s-6h indexing lag and a hard
result cap (~1000 per query). When we find one key in a repo via search, we
save it and move on — but the SAME repo often has **multiple keys in
different files** that we miss because:

1. The other file isn't in the search index yet (recent push)
2. Pagination cap was reached for that query before our file appeared
3. The other file uses different env-var names not in our query list
4. The repo is huge (>100MB code) and GitHub only indexes a subset

**Real example (2026-05-03):** `stenin15/mystic-whispers-us` — we found
OpenAI key in `vsl-production/add_subtitles.py` via search, but missed
OpenRouter in `vsl-production/gen_all.py` AND Replicate in
`vsl-production/pet_clipper/generate_product_images.py` from the same
repo. Both files our extractors handle correctly when given the content,
but Code Search never returned them. Repo was pushed 5 hours before scan.

**Solution: hybrid scan strategy** for `scanner.py`:

1. **Phase 1 (existing):** GitHub Code Search for query patterns. Save
   found keys + record `repo_full_name` per discovery.
2. **Phase 2 (new):** for each NEW repo discovered in Phase 1 (i.e. repo
   not previously tree-walked), call:
   ```
   GET /repos/{owner}/{name}/git/trees/{default_branch_sha}?recursive=1
   ```
   Filter blob entries to interesting paths (use existing
   `_INTERESTING_ROOT_FILES` + extensions `.py/.js/.ts/.json/.yaml/.yml/
   .toml/.env*/.ipynb/.md/.sh`), bounded to ~100 files per repo.
3. **Phase 3:** for each file from tree-walk that we haven't already
   claimed via SHA dedup, fetch its content and run AI_TRIGGER +
   EXTRACTORS as we do for search hits.

**Implementation notes:**
- Add `db.tree_walked_repos` table or column on `scanned_repos` to track
  "this repo had its tree fully walked at {timestamp}" — prevents
  re-walking on every new search hit.
- Cap per-repo file fetch at 100 files (most repos won't need more).
  Configurable via `TREEWALK_MAX_FILES_PER_REPO` env var.
- Skip large files (>256KB) — same as existing Gitee/Codeberg behaviour.
- Run tree-walk asynchronously after Phase 1 completes; don't block.
- Cost estimate: each new repo discovery → 1 tree-list request + ~10-30
  file fetches (most files won't be interesting). For our existing
  ~190K scanned repos this is N/A (one-time backfill optional); for
  NEW repos discovered going forward, ~30 extra fetches per repo.
- **Expected yield boost:** ad-hoc evidence shows 30-50% of repos with
  found keys have ≥1 additional key in another file. Conservative
  estimate: +20-30% total valid keys after rollout.

**Backfill option:** one-shot script that walks every repo currently in
`scanned_repos` table, runs tree-walk + scan. Costs ~6M GitHub API calls
(190K repos × ~30 files), spread over a week at our token budget. Worth
it ONLY if AI key value justifies — could yield thousands of additional
keys from existing repos.

- **Status:** ❌ pending. Architecture-level change to scanner.py.

---

## Implementation backlog

- [ ] **base64-array preprocessor** in scanner pipeline (all 11 scanners
      benefit). Heuristic:
      1. Detect decoder symbol (`Buffer.from(_, "base64")`, `atob(`,
         `base64.b64decode(`, `from base64 import b64decode`).
      2. Find string arrays where elements are `[A-Za-z0-9+/=]{30,}`.
      3. Decode each element; concat decodes; run AI_TRIGGER pre-check.
      4. If trigger hit → run EXTRACTORS on the decoded text and any
         double-decoded layers (handle inner `c2st` / etc.).
- [ ] **brute-force fallback** — on any file, scan ALL base64-looking
      tokens of length 30+ outside of common contexts (URLs, hashes).
      Decode and pre-check. Bound cost by capping at 200 candidates/file.
- [ ] **other encodings to consider** (file as we find samples):
      - hex-encoded (`bytes.fromhex(...)` / `Buffer.from(_, "hex")`)
      - rot13 / caesar (rare)
      - JS string fragmentation (`"sk-" + "proj-" + "abc..."` concat)
      - charcode arrays (`String.fromCharCode(115,107,...)`)
      - JSON object with `_decode`/`_decrypt` member functions
      - eval-wrapped string literals
      - XOR with a hardcoded key (rare, mostly malware)
- [ ] **language-specific extractors:**
      - Python `os.getenv` indirection (env var name in code, value in
        `.env` we may not have access to → still useful to flag)
      - Java/Kotlin `System.getenv` + `application.properties`
      - Go `os.Getenv` + viper config
- [ ] **ORM constructor reassembly** — Sequelize/psycopg2/Spring DataSource
      style where DB creds come as separate args. Heuristic: detect
      constructor name (`new Sequelize(`, `psycopg2.connect(`, etc.),
      collect adjacent string literals + option-object keys
      (host/port/user/password/database), assemble into canonical
      `dialect://user:pass@host:port/db`, run existing infra extractors.
- [ ] **rotated/multi-layer decode chains** — like wudysoft's threezero
      list which is `b64(b64(b64("Bearer sk-...")))`. Recurse 3 layers max.

## Extractor bugs found (fixed locally, not yet pushed)

### Replicate — too-tight length bound
- **Symptom:** real `r8_EXchgmp1L8xOTlQIarMaH0nbWaYicIy1bM11n` (37 chars after
  `r8_`) was NOT extracted. Our regex required `{38,55}` — minimum 38.
- **Where seen:** `bensalemboualem/Saas-iFactory-Algeria/.env.bak` (2026-05).
- **Root cause:** Replicate also issues 35-39 char keys in some tiers. We only
  saw 40+ in earlier samples and over-fit the bound.
- **Fix (applied):** widen `_REPLICATE_RE` and `_REPLICATE_CTX` to `{35,55}`.
- **Status:** ✅ patched in patterns.py (not pushed).

### Runway — captured tail-only, missed `key_` prefix
- **Symptom:** real `key_8e9b11a1...f5f3c26fe2ca` (128 hex chars after `key_`)
  was extracted as just `aed318154faf8e4c3a0df5f3c26fe2ca` (last 32 chars).
  Validator received truncated junk → always returned dead.
- **Where seen:** same iafactory repo.
- **Root cause:** old regex captured `[A-Za-z0-9_\-]{32,120}` WITHOUT requiring
  the `key_` prefix in the captured group. Greedy `{0,200}` filler ate the
  prefix and 100+ chars of the real key, then captured the trailing 32 chars.
- **Fix (applied):**
  - `_RUNWAY_PREFIXED` standalone regex: `(key_[a-fA-F0-9]{60,200})`
  - `_RUNWAY_DIRECT` and `_RUNWAY_CTX` updated to require `key_` prefix in
    capturing group, length bumped to 200 chars to fit 128-char real keys.
- **Status:** ✅ patched in patterns.py (not pushed).

## Patterns NOT requiring code changes (awareness only)

- **Commented-out credentials.** Devs comment out hardcoded keys before
  committing, thinking they're safe. Common in Python/JS:
  ```python
  # API_KEY = f64e5d17-8881-4974-a82a-5c7515273a72
  ```
  Seen in `yizhiqianbi/ReconSceneNet/Lasa1M/PreProcess/Script/stage_to_inpaint_by_api.py`.
  ✅ **Already caught** — our regex doesn't care about `#`/`//` prefixes;
  the key is matched as plain text and saved like a regular hardcoded one.

## Pivots / scanners learned

- `wudysoft` style is common in Indonesian / Southeast-Asian "API factory"
  side-projects that wrap free-tier accounts behind a paid proxy. Look
  for patterns like `koyeb-api-*`, `*.workers.dev/`, `*.vercel.app/api/`
  in other repos.
- ByteDance / Volcengine accounts often have `f25a15bc-...`-style UUIDs
  (8-4-4-4-12 hex) — our ARK regex catches them in known contexts but
  misses bare-UUID hardcoded as Python defaults.
