# Obfuscation methods + new providers tracker

Tracker for credential-pool obfuscation patterns AND new AI providers we've
encountered in real public repos. Each entry: detection signal + decoding
approach + status.

## New providers to add (verified seen with valid keys)

### Commonstack — Claude/GPT/DeepSeek/Kimi/GLM aggregator
- **Where seen:** `Wangtrotro/EduAgent/.env.example` (2026-05) — key was
  `ak-aa2901d47f8a79297eb18548438eec02c8fb195d28edfca7753021ac439a245d`
  (HARDCODED in .env.example, validated 200 OK on /chat/completions)
- **Endpoint:** `https://api.commonstack.ai/v1` (OpenAI-compatible)
- **Auth:** `Authorization: Bearer ak-...`  (key is `ak-` + 64 hex)
- **Available models:** `anthropic/claude-opus-4-7`, `anthropic/claude-sonnet-4-6`,
  `openai/gpt-5.5`, `deepseek/deepseek-v4-pro`, `moonshotai/kimi-k2.6`,
  `zai-org/glm-5.1`, `xiaomi/mimo-v2-pro`, `xiaomi/mimo-v2-omni`, more
- **Validation:** `GET /v1/models` (200 = alive). Per-token billing visible
  in /models response (pricing field). For dead/exhausted detection a
  /chat/completions probe with max_tokens=1 may be needed (cost: 1 token
  ≈ $0.0000005 on cheapest model).
- **Why valuable:** one key → Claude Opus 4.7 (newest!) + GPT 5.5 + GLM 5.1
  + Kimi K2.6 + DeepSeek v4-pro all through ONE aggregator. Much like
  OpenRouter but smaller/less-scanned.
- **Status:** ❌ NOT yet a provider in EXTRACTORS/VALIDATORS. Pending add.
- **Add when:** we have ≥3 leaked Commonstack keys observed, OR user
  explicitly wants it now.



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

### 3. (TBD — add as found)

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

## Pivots / scanners learned

- `wudysoft` style is common in Indonesian / Southeast-Asian "API factory"
  side-projects that wrap free-tier accounts behind a paid proxy. Look
  for patterns like `koyeb-api-*`, `*.workers.dev/`, `*.vercel.app/api/`
  in other repos.
- ByteDance / Volcengine accounts often have `f25a15bc-...`-style UUIDs
  (8-4-4-4-12 hex) — our ARK regex catches them in known contexts but
  misses bare-UUID hardcoded as Python defaults.
