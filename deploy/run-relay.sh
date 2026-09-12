#!/bin/sh
# Run the Sealed relay on this machine (your VM / this Mac).
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
if [ ! -f deploy/.env ]; then
  echo "Missing deploy/.env"
  exit 1
fi
set -a
# shellcheck disable=SC1091
. "$ROOT/deploy/.env"
set +a
export SEALED_BIND="${SEALED_BIND:-0.0.0.0}"
export SEALED_PORT="${SEALED_PORT:-8000}"
export SEALED_TRUST_PROXY="${SEALED_TRUST_PROXY:-1}"
exec python3 "$ROOT/main.py" server
