#!/bin/sh
# Starts the sidecar, waits for it to bind, then runs the demo agent.
# Exits non-zero if the sidecar never comes up or the agent reports a failure,
# so `docker compose up` surfaces a broken demo instead of printing errors
# and exiting 0.
set -eu

# Demo-only: mint an ephemeral key when the environment does not supply one.
# Never ship a committed HMAC key in a real deployment.
if [ -z "${ACF_HMAC_KEY:-}" ]; then
    ACF_HMAC_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
    export ACF_HMAC_KEY
    echo "No ACF_HMAC_KEY supplied — generated an ephemeral demo key."
fi

SOCKET_PATH="${ACF_SOCKET_PATH:-/tmp/acf.sock}"

cd /app
acf-sidecar &
SIDECAR_PID=$!

echo "Waiting for sidecar on ${SOCKET_PATH}..."
i=0
while [ "$i" -lt 30 ]; do
    if [ -S "$SOCKET_PATH" ]; then
        break
    fi
    if ! kill -0 "$SIDECAR_PID" 2>/dev/null; then
        echo "ERROR: sidecar exited before binding ${SOCKET_PATH}" >&2
        exit 1
    fi
    i=$((i + 1))
    sleep 1
done

if [ ! -S "$SOCKET_PATH" ]; then
    echo "ERROR: sidecar did not bind ${SOCKET_PATH} within 30s" >&2
    kill "$SIDECAR_PID" 2>/dev/null || true
    exit 1
fi

python main.py && STATUS=0 || STATUS=$?
kill "$SIDECAR_PID" 2>/dev/null || true
exit "$STATUS"
