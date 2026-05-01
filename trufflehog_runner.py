"""
Secondary scanner using trufflehog — runs in parallel with the code-search loop.

Why trufflehog alongside ghscan?
  - Different API path: clones repos via git protocol, not code-search API
  - Scans ENTIRE repo history (finds keys that were deleted from HEAD)
  - 700+ built-in detectors with live verification
  - Org-sweep: covers every repo in an org, not just those that surface in search
  - No shared rate limits with our code-search token pool

Configuration (env vars):
  TRUFFLEHOG_ORGS=org1,org2,org3    — GitHub orgs to sweep
  TRUFFLEHOG_USERS=user1,user2      — individual GitHub users to sweep
  TRUFFLEHOG_INTERVAL=7200          — seconds between sweeps (default 2h)
  TRUFFLEHOG_CONCURRENCY=50         — --concurrency flag passed to trufflehog
  TRUFFLEHOG_PATH                   — override binary path
"""

import asyncio
import json
import logging
from pathlib import Path

import db
from config import (
    GITHUB_TOKENS,
    TRUFFLEHOG_PATH,
    TRUFFLEHOG_ORGS,
    TRUFFLEHOG_USERS,
    TRUFFLEHOG_INTERVAL,
    TRUFFLEHOG_CONCURRENCY,
    TRUFFLEHOG_TOKEN,
)
from notifier import notify_found
from scanner import _TOKEN_STATUS

log = logging.getLogger(__name__)

# trufflehog DetectorName → our provider key
_DETECTOR_MAP: dict[str, str] = {
    "OpenAI":          "openai",
    "Anthropic":       "anthropic",
    "Anthropic_key":   "anthropic",
    "GoogleAI":        "google",
    "Gemini":          "google",
    "GoogleCloudKeys": "google",
    "DeepSeek":        "deepseek",
    "ElevenLabs":      "elevenlabs",
    "HuggingFace":     "huggingface",
    "Cohere":          "cohere",
    "Replicate":       "replicate",
    "AWS":             "aws",
    "Stripe":          "stripe",
    "Twilio":          "twilio",
    "SendGrid":        "sendgrid",
    "Mailgun":         "mailgun",
}

# Providers we care most about (always notify regardless of verification status)
_PRIORITY = {"openai", "anthropic", "google", "deepseek", "elevenlabs", "ark"}


def _th_available() -> bool:
    return TRUFFLEHOG_PATH.exists() if TRUFFLEHOG_PATH else False


def _pick_token() -> str:
    """
    Return the trufflehog token.
    Prefers TRUFFLEHOG_TOKEN (dedicated PAT) to avoid eating the main scanner quota.
    Falls back to first alive token from the main pool.
    """
    if TRUFFLEHOG_TOKEN:
        return TRUFFLEHOG_TOKEN
    for tok in GITHUB_TOKENS:
        status = _TOKEN_STATUS.get(tok[:8], {})
        if status.get("alive", True):  # default True if unchecked yet
            return tok
    return GITHUB_TOKENS[0]


async def _run_trufflehog(args: list[str]) -> bytes:
    """Run trufflehog with given args, return stdout bytes."""
    token = _pick_token()
    cmd = [
        str(TRUFFLEHOG_PATH),
        *args,
        "--token", token,
        "--json",
        f"--concurrency={TRUFFLEHOG_CONCURRENCY}",
        "--no-update",           # don't check for updates (faster start)
    ]
    log.info("trufflehog: %s", " ".join(cmd[:6]) + " ...")
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        # Allow up to 3600s per target (big orgs take time)
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=3600)
        if stderr:
            log.debug("trufflehog stderr: %s", stderr[:500].decode(errors="replace"))
        return stdout
    except asyncio.TimeoutError:
        log.warning("trufflehog timed out for: %s", args)
        try:
            proc.kill()
        except Exception:
            pass
        return b""
    except Exception as e:
        log.error("trufflehog exec err: %s", e)
        return b""


async def _process_output(stdout: bytes, source_label: str):
    """Parse trufflehog JSON lines and push findings to DB + Telegram."""
    found = 0
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            result = json.loads(line)
        except json.JSONDecodeError:
            continue

        detector = result.get("DetectorName", "")
        provider = _DETECTOR_MAP.get(detector)
        if not provider:
            continue

        verified = bool(result.get("Verified", False))
        # Skip unverified non-priority finds to reduce noise
        if not verified and provider not in _PRIORITY:
            continue

        key = result.get("Raw", "") or result.get("RawV2", "")
        if not key or len(key) < 10:
            continue

        # Extract source metadata
        meta_data = result.get("SourceMetadata", {}).get("Data", {})
        gh = meta_data.get("Github", {})
        repo      = gh.get("repository", source_label)
        file_path = gh.get("file", "")
        link      = gh.get("link", "")
        commit    = gh.get("commit", "")

        if db.key_exists(key):
            continue

        saved = db.save_key(
            provider, key, repo, file_path, link or commit,
            0, "", f"trufflehog/{detector}", verified,
        )
        if saved:
            found += 1
            await notify_found(
                provider, key, repo, file_path, link or commit,
                0, "", f"th/{detector}", verified,
            )
            log.info("trufflehog [%s] %s in %s", "VALID" if verified else "found", provider, repo)

    if found:
        log.info("trufflehog processed %s → %d new keys", source_label, found)


async def scan_org(org: str):
    stdout = await _run_trufflehog(["github", "--org", org, "--only-verified"])
    if stdout:
        await _process_output(stdout, f"org:{org}")


async def scan_user(user: str):
    # --user sweeps ALL repos of a GitHub user (not a single repo URL)
    stdout = await _run_trufflehog(["github", "--user", user, "--only-verified"])
    if stdout:
        await _process_output(stdout, f"user:{user}")


async def trufflehog_loop():
    """Sweep configured orgs/users on a schedule. Independent of main scan loop."""
    if not (TRUFFLEHOG_ORGS or TRUFFLEHOG_USERS):
        log.info("trufflehog: no TRUFFLEHOG_ORGS/USERS configured — skipping")
        return

    if not _th_available():
        log.warning("trufflehog binary not found at %s — org sweep disabled", TRUFFLEHOG_PATH)
        return

    log.info("trufflehog runner started | orgs=%s users=%s interval=%ds",
             TRUFFLEHOG_ORGS, TRUFFLEHOG_USERS, TRUFFLEHOG_INTERVAL)

    while True:
        targets = (
            [("org", o) for o in TRUFFLEHOG_ORGS] +
            [("user", u) for u in TRUFFLEHOG_USERS]
        )
        for kind, name in targets:
            try:
                if kind == "org":
                    await scan_org(name)
                else:
                    await scan_user(name)
            except Exception as e:
                log.error("trufflehog scan err [%s %s]: %s", kind, name, e)
            await asyncio.sleep(5)

        log.info("trufflehog sweep complete, sleeping %ds", TRUFFLEHOG_INTERVAL)
        await asyncio.sleep(TRUFFLEHOG_INTERVAL)
