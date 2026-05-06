"""
Pre-validation context filter — classifies a regex-matched key candidate as
real-or-placeholder BEFORE we burn a validation API call to the provider.

Why: ~30-40% of regex matches are placeholder/template strings:
  sk-XXXXXXXXXXXXXXXXXX
  sk-your-openai-key-here
  AIzaSy<replace-with-yours>
  ${OPENAI_API_KEY}
  sk-proj-1234567890abcdefg  (sequential digits, obviously fake)
  sk-test-abc123  (literally word "test")

Validating these costs:
  - 1 API call to provider (api.openai.com, etc) → 401
  - ~500ms latency per validation
  - GitHub Code Search rate-limit budget on subsequent searches

Pre-validator inspects: 200 chars context + filename + key pattern → cheap LLM
classifies "real production key OR placeholder/example/test?". Saves 30-40%
of validation calls.

Cost: ~500 bytes input × ~125 calls/h = trivial. Fires on every regex match
before validation.
"""

from __future__ import annotations

import json
import logging
import re

from llm_client import call_fast

log = logging.getLogger(__name__)


# Static heuristics that catch obvious placeholders WITHOUT an LLM call.
# These run first as a cheap pre-filter — if any match, we skip LLM entirely
# and return is_real=False. Saves cost on the most blatant garbage.
_PLACEHOLDER_REGEX = re.compile(
    r"("
    r"X{6,}"                                  # sk-XXXXXX (6+ X's in row)
    r"|<[a-z\-]+>"                            # <your-key>
    r"|\$\{[A-Z_]+\}"                         # ${OPENAI_API_KEY}
    r"|your[\-_](?:openai|anthropic|key|token|api)"  # your-openai-key
    r"|replace[\-_](?:me|with)"               # replace-me
    r"|insert[\-_]your"                       # insert-your-key
    r"|placeholder"                           # placeholder
    r"|example[\-_](?:key|token)"             # example-key
    # NOTE: alphabet/digit sequences like 'abcdef' / '123456' removed —
    # real keys (e.g. sk-proj-AbCdEfGh...) contain such substrings by
    # random chance, causing false positives.
    r")",
    re.IGNORECASE,
)

# Filename hints that suggest example/template/test contexts where placeholder
# keys live by convention.
_TEMPLATE_FILENAMES = {
    ".env.example", ".env.sample", ".env.template", ".env.dist",
    ".env.test",    ".env.dev.example", "config.example.js",
    "settings.example.py", "secrets.example.toml",
    "example.env", "template.env",
}


_SYSTEM_PROMPT = (
    "You decide if an API-key candidate found in a code file is REAL "
    "(production-grade, likely working) or a PLACEHOLDER (template/example/"
    "test/regex-pattern, will return 401 if validated). Output JSON only:\n"
    '{"is_real": true|false, "reason": "short"}\n\n'
    "REAL signals:\n"
    "  - Random-looking high-entropy chars matching provider key shape\n"
    "  - Found in production .env, app config, deploy scripts\n"
    "  - Surrounding code USES the key (passed to client init, fetch headers)\n"
    "REPLACEHOLDER signals:\n"
    "  - X's repeated, <your-key>, ${VAR}, sequential digits\n"
    "  - 'YOUR_KEY_HERE', 'replace-with-yours', 'insert-here'\n"
    "  - Filename has .example/.sample/.template/.dist suffix\n"
    "  - Repo description says 'tutorial' / 'example' / 'starter'\n"
    "  - Context has 'TODO:', '# replace this', or commented out\n"
    "When in doubt → is_real=true (don't lose real keys to false negatives)."
)


def _heuristic_pre_filter(key: str, file_path: str) -> bool | None:
    """Cheap regex-based check. Returns:
      True  → definitely placeholder (skip LLM, skip validation)
      False → not obviously placeholder (proceed to LLM check)
      None  → caller decides (currently same as False)"""
    if _PLACEHOLDER_REGEX.search(key):
        return True
    fname = (file_path or "").rsplit("/", 1)[-1].lower()
    if fname in _TEMPLATE_FILENAMES:
        return True
    return False


def _parse_classification(text: str | None) -> bool | None:
    """Parse LLM JSON output → True (real), False (placeholder), or None on
    parse failure. Conservative: parse failure → None (caller defaults to
    is_real=True)."""
    if not text:
        return None
    txt = text.strip()
    if txt.startswith("```"):
        txt = re.sub(r"^```(?:json)?\s*", "", txt)
        txt = re.sub(r"\s*```$", "", txt)
    try:
        d = json.loads(txt)
    except json.JSONDecodeError:
        m = re.search(r"\{[^{}]*\}", txt)
        if not m:
            return None
        try:
            d = json.loads(m.group(0))
        except json.JSONDecodeError:
            return None
    val = d.get("is_real")
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.lower() in ("true", "yes", "1", "real")
    return None


async def is_real_key(key: str, context: str, file_path: str,
                      file_url: str = "") -> bool:
    """Returns True if the key candidate looks like a real production key.
    Returns False if heuristics or LLM strongly suggest placeholder.

    Conservative: on LLM failure or ambiguity → True (don't lose real keys).
    Cheap: ~5-10ms per call when heuristic catches placeholder, ~2-3s with
    LLM call.
    """
    # 1) Cheap heuristic pre-filter
    h = _heuristic_pre_filter(key, file_path)
    if h is True:
        log.debug("pre_validator: %s heuristic-flagged placeholder",
                  key[:14] + "...")
        return False

    # 2) LLM call — context-aware classification
    # Truncate context to 400 chars (200 each side around the key)
    if len(context) > 400:
        # Try to center on the key if it's in the context
        idx = context.find(key)
        if idx >= 0:
            start = max(0, idx - 200)
            end   = min(len(context), idx + len(key) + 200)
            context = context[start:end]
        else:
            context = context[:400]

    user_msg = (
        f"KEY: {key}\n"
        f"FILE: {file_path}\n"
        f"URL: {file_url}\n"
        f"CONTEXT (~400 chars around key):\n{context}\n\n"
        "Is this a REAL production key or a PLACEHOLDER?"
    )

    text, source = await call_fast(
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user",   "content": user_msg},
        ],
        response_format={"type": "json_object"},
        max_tokens=80,
        timeout=15,
    )
    parsed = _parse_classification(text)
    if parsed is None:
        # LLM unavailable or unparseable — default to is_real=True (conservative)
        log.debug("pre_validator: classifier unreachable (source=%s) — assume real",
                  source)
        return True
    log.debug("pre_validator: %s → real=%s (source=%s)",
              key[:14] + "...", parsed, source)
    return parsed
