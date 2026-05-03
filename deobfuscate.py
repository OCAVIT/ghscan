"""
Content deobfuscation preprocessor.

Single entry point: `expand(content: str) -> str`. Returns the original content
PLUS all detected deobfuscated variants concatenated with separators. Existing
AI_TRIGGER + EXTRACTORS run on the result and find keys regardless of which
obfuscation layer they were hidden in.

Cheap heuristic: nothing runs unless a clear marker for that obfuscation method
is present in the content (Buffer.from / atob / fromCharCode / etc). Keeps the
fast-path scanner unaffected when files are plain.

Detected scenarios (TODO_OBFUSCATION.md sections):
  #1  base64-array decode (Buffer.from(x,"base64") / atob / b64decode)
  #3  JS string fragmentation ("sk-" + "proj-" + ... concat chains)
  #4  char-code arrays (String.fromCharCode(115,107,...) / chr / bytes)
  #5  hex encoding (bytes.fromhex / Buffer.from(x,"hex"))
  #6  reversed strings (.reverse() / [::-1])
  #11 SSR hydration (window.__NEXT_DATA__ / __INITIAL_STATE__)
  #12 Kubernetes Secret YAML (kind: Secret + data: + base64 values)

Bounds: cap added text per scenario at ~64KB to prevent pathological blowup.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Iterable

# ── Markers that gate each scenario ──────────────────────────────────────────
_B64_DECODE_MARKERS = re.compile(
    r'(?:Buffer\.from\s*\(\s*[^,)]+,\s*[\'"]base64[\'"]\s*\)'
    r'|atob\s*\('
    r'|base64\.b64decode\s*\('
    r'|from\s+base64\s+import\s+b64decode'
    r'|b64decode\s*\()',
    re.IGNORECASE,
)
_HEX_DECODE_MARKERS = re.compile(
    r'(?:bytes\.fromhex\s*\('
    r'|Buffer\.from\s*\(\s*[^,)]+,\s*[\'"]hex[\'"]\s*\)'
    r'|unhexlify\s*\()',
    re.IGNORECASE,
)
_CHARCODE_MARKERS = re.compile(
    r'(?:String\.fromCharCode\s*\([^)]{8,}\)'
    r'|\bchr\s*\(\s*\d+\s*\).*\bchr\s*\(\s*\d+\s*\)'
    r'|bytes\s*\(\s*\[[^\]]{20,}\]\s*\))',
    re.IGNORECASE,
)
_REVERSE_MARKERS = re.compile(
    r'(?:\.split\(""\)\.reverse\(\)\.join\(""\)|\[::-1\])',
)
_NEXT_HYDRATION = re.compile(
    r'<script[^>]*id\s*=\s*[\'"]__(?:NEXT_DATA|NUXT|INITIAL_STATE)__[\'"][^>]*>'
    r'(?P<body>[\s\S]{1,500000}?)</script>',
)
_K8S_SECRET = re.compile(
    r'kind\s*:\s*Secret[\s\S]{0,300}?\n\s*data\s*:\s*\n((?:\s+[\w.\-]+\s*:\s*[A-Za-z0-9+/=]+\s*\n)+)',
)

# ── Pattern matchers ────────────────────────────────────────────────────────
# Long base64-looking literals (≥30 chars, padding optional). Used both
# inside arrays and as standalone in Buffer.from arguments.
_B64_LITERAL = re.compile(r'[\'"]([A-Za-z0-9+/=_\-]{30,})[\'"]')
_HEX_LITERAL = re.compile(r'[\'"]([0-9a-fA-F]{30,})[\'"]')
_CHARCODE_ARR = re.compile(
    r'(?:String\.fromCharCode|bytes|chr)\s*[(\[]?\s*'
    r'((?:\d{1,3}\s*[,\s]\s*){8,}\d{1,3})',
)
# JS plus-concat chains: "sk-" + "proj-" + "foo" + "bar"
# At least 2 plus operators and the resulting concat has reasonable length.
_PLUS_CONCAT = re.compile(
    r'((?:[\'"][\w\-+/=:.~]{1,200}[\'"]\s*\+\s*){2,}[\'"][\w\-+/=:.~]{1,200}[\'"])',
)
# Reversed-string pattern: "...stringliteral..." followed by .reverse()/[::-1]
_REVERSE_TARGET = re.compile(
    r'[\'"]([A-Za-z0-9_\-+/=:]{20,200})[\'"]'
    r'(?:\s*\.split\(""\)\.reverse\(\)\.join\(""\)?'
    r'|\s*\[::-1\])',
)

_MAX_PER_SCENARIO = 64 * 1024  # 64 KB


def _safe_b64decode(s: str) -> str | None:
    """Try multiple b64 decode strategies; return decoded text or None."""
    s = s.strip()
    if not s or len(s) < 8:
        return None
    # Pad with `=` to multiple of 4
    padded = s + "=" * (-len(s) % 4)
    for variant in (padded, padded.replace("-", "+").replace("_", "/")):
        try:
            raw = base64.b64decode(variant, validate=False)
            text = raw.decode("utf-8", errors="strict")
            # Heuristic: skip if result is pure binary garbage
            if text and sum(1 for c in text if c.isprintable() or c in "\r\n\t") / len(text) >= 0.7:
                return text
        except Exception:
            continue
    return None


def _decode_b64_layer(content: str) -> str:
    """Layer 1: decode every b64-looking literal next to a decoder call."""
    out: list[str] = []
    seen: set[str] = set()
    for m in _B64_LITERAL.finditer(content):
        token = m.group(1)
        if token in seen:
            continue
        seen.add(token)
        decoded = _safe_b64decode(token)
        if decoded:
            out.append(decoded)
            # Try one more b64 layer (nested encoding observed in wudysoft)
            inner = _safe_b64decode(decoded.strip().strip('"\''))
            if inner:
                out.append(inner)
        if sum(len(o) for o in out) >= _MAX_PER_SCENARIO:
            break
    return "\n".join(out)


def _decode_hex_layer(content: str) -> str:
    out: list[str] = []
    seen: set[str] = set()
    for m in _HEX_LITERAL.finditer(content):
        token = m.group(1)
        if token in seen or len(token) % 2 != 0:
            continue
        seen.add(token)
        try:
            raw = binascii.unhexlify(token)
            text = raw.decode("utf-8", errors="strict")
            if text and sum(1 for c in text if c.isprintable()) / len(text) >= 0.7:
                out.append(text)
        except Exception:
            continue
        if sum(len(o) for o in out) >= _MAX_PER_SCENARIO:
            break
    return "\n".join(out)


def _decode_charcode_layer(content: str) -> str:
    out: list[str] = []
    for m in _CHARCODE_ARR.finditer(content):
        nums_text = m.group(1)
        try:
            nums = [int(x.strip()) for x in re.split(r'[,\s]+', nums_text) if x.strip()]
            if not nums:
                continue
            # Only ASCII printable range — rejects byte arrays unrelated to keys
            if all(0 <= n <= 0x10FFFF for n in nums) and any(32 <= n <= 126 for n in nums):
                text = "".join(chr(n) for n in nums if 0 <= n <= 0x10FFFF)
                if text and sum(1 for c in text if c.isprintable()) / max(len(text), 1) >= 0.6:
                    out.append(text)
        except Exception:
            continue
        if sum(len(o) for o in out) >= _MAX_PER_SCENARIO:
            break
    return "\n".join(out)


def _decode_concat_layer(content: str) -> str:
    """Constant-fold JS string-plus chains."""
    out: list[str] = []
    for m in _PLUS_CONCAT.finditer(content):
        chain = m.group(1)
        # Pull out each "..." or '...' literal and concat
        pieces = re.findall(r'[\'"]([\w\-+/=:.~]{1,200})[\'"]', chain)
        if pieces:
            joined = "".join(pieces)
            if len(joined) >= 16:
                out.append(joined)
        if sum(len(o) for o in out) >= _MAX_PER_SCENARIO:
            break
    return "\n".join(out)


def _decode_reverse_layer(content: str) -> str:
    out: list[str] = []
    for m in _REVERSE_TARGET.finditer(content):
        token = m.group(1)
        out.append(token[::-1])
        if sum(len(o) for o in out) >= _MAX_PER_SCENARIO:
            break
    return "\n".join(out)


def _decode_next_hydration(content: str) -> str:
    """Pull JSON hydration out of __NEXT_DATA__ / __NUXT__ / __INITIAL_STATE__."""
    out: list[str] = []
    for m in _NEXT_HYDRATION.finditer(content):
        body = m.group("body").strip()
        try:
            data = json.loads(body)
            # Walk recursively, append every string value
            def _walk(node: object) -> Iterable[str]:
                if isinstance(node, str):
                    if len(node) >= 16:
                        yield node
                elif isinstance(node, dict):
                    for v in node.values():
                        yield from _walk(v)
                elif isinstance(node, list):
                    for v in node:
                        yield from _walk(v)
            out.extend(_walk(data))
        except Exception:
            continue
        if sum(len(o) for o in out) >= _MAX_PER_SCENARIO:
            break
    return "\n".join(out)


def _decode_k8s_secret(content: str) -> str:
    """Pull `data:` block from kind: Secret YAML and b64-decode each value."""
    out: list[str] = []
    for m in _K8S_SECRET.finditer(content):
        block = m.group(1)
        for line in block.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            _, _, val = line.partition(":")
            val = val.strip()
            if val:
                decoded = _safe_b64decode(val)
                if decoded:
                    out.append(decoded)
        if sum(len(o) for o in out) >= _MAX_PER_SCENARIO:
            break
    return "\n".join(out)


# ── Public entry point ──────────────────────────────────────────────────────

def expand(content: str) -> str:
    """Return original content + all detected deobfuscated variants.

    Cheap when the file has no obfuscation markers (early-return paths).
    Bounded growth: each scenario contributes at most ~64KB.
    """
    if not content:
        return content

    parts: list[str] = [content]

    # Section separator — long enough (300+ chars) to push decoded keys past
    # extractor context windows (200 char each side). Keeps `_FAKE` triggers
    # like `>` from JS arrow funcs / HTML out of the decoded-section window.
    sep = "\n" + ("=" * 80 + "\n") * 4

    if _B64_DECODE_MARKERS.search(content):
        decoded = _decode_b64_layer(content)
        if decoded:
            parts.append(sep + "# b64 decode" + sep)
            parts.append(decoded)

    if _HEX_DECODE_MARKERS.search(content):
        decoded = _decode_hex_layer(content)
        if decoded:
            parts.append(sep + "# hex decode" + sep)
            parts.append(decoded)

    if _CHARCODE_MARKERS.search(content):
        decoded = _decode_charcode_layer(content)
        if decoded:
            parts.append(sep + "# charcode decode" + sep)
            parts.append(decoded)

    # Plus-concat chains are cheap to detect via regex pre-pass; gate on
    # presence of `+` operator near string literals.
    if "+" in content and re.search(r'[\'"][^\'"]+[\'"]\s*\+\s*[\'"]', content):
        decoded = _decode_concat_layer(content)
        if decoded:
            parts.append(sep + "# string concat" + sep)
            parts.append(decoded)

    if _REVERSE_MARKERS.search(content):
        decoded = _decode_reverse_layer(content)
        if decoded:
            parts.append(sep + "# reverse decode" + sep)
            parts.append(decoded)

    if "__NEXT_DATA__" in content or "__NUXT__" in content or "__INITIAL_STATE__" in content:
        decoded = _decode_next_hydration(content)
        if decoded:
            parts.append(sep + "# ssr hydration" + sep)
            parts.append(decoded)

    if "kind: Secret" in content or "kind:Secret" in content:
        decoded = _decode_k8s_secret(content)
        if decoded:
            parts.append(sep + "# k8s secret" + sep)
            parts.append(decoded)

    return "\n".join(parts)
