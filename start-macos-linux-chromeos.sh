#!/usr/bin/env bash
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${1:-7474}"

echo "Starting Cloud Space Guard on http://127.0.0.1:${PORT} ..."
if command -v open >/dev/null 2>&1; then
  (sleep 1 && open "http://127.0.0.1:${PORT}") &
elif command -v xdg-open >/dev/null 2>&1; then
  (sleep 1 && xdg-open "http://127.0.0.1:${PORT}") &
fi

exec python3 "${DIR}/space_guard_agent.py" serve --port "${PORT}"
