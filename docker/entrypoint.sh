#!/usr/bin/env sh
set -eu

MODE="${1:-collector}"
CONFIG_PATH="${MESHVIEWLITE_CONFIG:-/config/meshviewlite.toml}"
WEB_PORT="${WEB_PORT:-8050}"

if [ "$MODE" = "collector" ]; then
  exec python /app/meshviewlite.py --config "$CONFIG_PATH"
fi

if [ "$MODE" = "web" ]; then
  exec python /app/meshviewlite_web.py --config "$CONFIG_PATH" --host 0.0.0.0 --port "$WEB_PORT"
fi

echo "Unknown mode: $MODE"
echo "Valid modes: collector | web"
exit 1
