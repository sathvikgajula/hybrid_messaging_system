#!/bin/sh
# TLS front door for friends. Needs your Mac password (ports 80/443).
# Copies the Caddyfile to /tmp because macOS may block root from reading Desktop.
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CADDY="$(command -v caddy || true)"
if [ -z "$CADDY" ]; then
  echo "Install Caddy first: brew install caddy"
  exit 1
fi
cp "$ROOT/deploy/Caddyfile.host" /tmp/sealed-Caddyfile.host
exec sudo "$CADDY" run --config /tmp/sealed-Caddyfile.host --adapter caddyfile
