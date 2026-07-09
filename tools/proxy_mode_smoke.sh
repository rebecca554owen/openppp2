#!/usr/bin/env bash
# Smoke test: verify proxy-only mode starts and exposes local listeners.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PPP_BIN="${PPP_BIN:-${ROOT}/bin/ppp}"
CONFIG="${CONFIG:-}"
HTTP_PORT="${HTTP_PORT:-8080}"
SOCKS_PORT="${SOCKS_PORT:-1080}"
TIMEOUT_SEC="${TIMEOUT_SEC:-30}"

if [[ ! -x "${PPP_BIN}" ]]; then
    echo "error: PPP binary not found at ${PPP_BIN}" >&2
    exit 1
fi

if [[ -z "${CONFIG}" ]]; then
    CONFIG="$(mktemp "${TMPDIR:-/tmp}/openppp2-proxy-smoke.XXXXXX")"
    trap 'rm -f "${CONFIG}"' EXIT
    cat >"${CONFIG}" <<'EOF'
{
  "client": {
    "guid": "{00000000-0000-0000-0000-000000000001}",
    "server": "ppp://127.0.0.1:20000/",
    "proxy-only": true,
    "http-proxy": { "bind": "127.0.0.1", "port": 8080 },
    "socks-proxy": { "bind": "127.0.0.1", "port": 1080 }
  }
}
EOF
fi

echo "Starting proxy-only mode (config=${CONFIG})..."
"${PPP_BIN}" --mode=proxy --config="${CONFIG}" &
PID=$!
trap 'kill "${PID}" 2>/dev/null || true' EXIT

deadline=$((SECONDS + TIMEOUT_SEC))
while (( SECONDS < deadline )); do
    if curl -sS --max-time 1 -x "http://127.0.0.1:${HTTP_PORT}" http://127.0.0.1/ >/dev/null 2>&1; then
        echo "HTTP proxy listener responded on 127.0.0.1:${HTTP_PORT}"
        exit 0
    fi
    if nc -z 127.0.0.1 "${SOCKS_PORT}" 2>/dev/null; then
        echo "SOCKS proxy port ${SOCKS_PORT} is open"
        exit 0
    fi
    if ! kill -0 "${PID}" 2>/dev/null; then
        echo "error: ppp process exited before listeners were ready" >&2
        wait "${PID}" || true
        exit 1
    fi
    sleep 1
done

echo "error: timed out waiting for proxy listeners" >&2
exit 1
