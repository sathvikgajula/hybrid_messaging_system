#!/bin/sh
# You (the host) chatting as a user. Talks to the local relay so home-router
# hairpin NAT is not required. Friends still use the HTTPS GitHub builds.
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export SEALED_RELAY="${SEALED_RELAY:-http://127.0.0.1:8000}"
exec python3 "$ROOT/main.py"
