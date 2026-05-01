#!/bin/sh
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

exec uvicorn main:app --host 0.0.0.0 --port "${PORT:-8000}" \
    --workers 1 \
    --loop uvloop \
    --http httptools
