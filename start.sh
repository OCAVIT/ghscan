#!/bin/sh
# Pre-flight: validate required env vars BEFORE importing python modules,
# so user sees a clear one-line error instead of a 100-line uvicorn traceback.
missing=""
[ -z "${GITHUB_TOKEN}${GITHUB_TOKENS}" ] && missing="${missing} GITHUB_TOKEN(or GITHUB_TOKENS)"
# Telegram is required only on master. Mirror service (MIRROR_MODE=1) ships
# finds back to master via mirror_relay; it doesn't talk to Telegram itself.
if [ "${MIRROR_MODE}" != "1" ]; then
    [ -z "${TELEGRAM_BOT_TOKEN}" ]            && missing="${missing} TELEGRAM_BOT_TOKEN"
    [ -z "${TELEGRAM_CHAT_ID}" ]              && missing="${missing} TELEGRAM_CHAT_ID"
else
    [ -z "${MASTER_API_URL}" ]                && missing="${missing} MASTER_API_URL"
    [ -z "${MASTER_API_TOKEN}${ADMIN_TOKEN}" ] && missing="${missing} MASTER_API_TOKEN(or ADMIN_TOKEN)"
fi
if [ -n "$missing" ]; then
    echo "[start.sh] FATAL: missing required env vars on Railway:${missing}"
    echo "[start.sh] set them in Railway → Variables, then redeploy."
    sleep 30   # avoid CrashLoopBackoff hammering — give user time to see the log
    exit 1
fi
if [ "${MIRROR_MODE}" = "1" ]; then
    echo "[start.sh] === MIRROR MODE === relaying finds to ${MASTER_API_URL}"
fi

# Download trufflehog binary at container start (Nixpacks doesn't have it).
# Pinned to the version that's installed on dev machine for consistency.
TH_VERSION="v3.95.2"
TH_BIN="/usr/local/bin/trufflehog"

if [ ! -f "$TH_BIN" ]; then
    echo "[start.sh] downloading trufflehog ${TH_VERSION}..."
    curl -sSfL \
        "https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh" \
        | sh -s -- -b /usr/local/bin "${TH_VERSION}" 2>&1
    if [ -f "$TH_BIN" ]; then
        echo "[start.sh] trufflehog installed OK"
    else
        echo "[start.sh] trufflehog install FAILED — org sweep disabled"
    fi
else
    echo "[start.sh] trufflehog already present: $($TH_BIN --version 2>&1 | head -1)"
fi

# Ensure DB directory is writable (Railway volume may not be attached)
if [ -d "/data" ] && [ -w "/data" ]; then
    echo "[start.sh] /data volume mounted and writable — DB at /data/scanner.db"
else
    echo "[start.sh] /data not writable — DB at ./scanner.db (no persistence between deploys)"
fi

exec uvicorn main:app --host 0.0.0.0 --port "${PORT:-8000}" \
    --workers 1 \
    --loop uvloop \
    --http httptools
