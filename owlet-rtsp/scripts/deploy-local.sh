#!/usr/bin/env bash
# Start the portal and its two native processes on this host.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PY="${PY:-$ROOT/.venv/bin/python}"
export DATA_DIR="${DATA_DIR:-$ROOT/data}"
export PUBLIC_HOST="${PUBLIC_HOST:-127.0.0.1}"
export API_PORT="${API_PORT:-8000}"
export MEDIAMTX_BIN="${MEDIAMTX_BIN:-mediamtx}"
export OWLET_TUTK_BIN="${OWLET_TUTK_BIN:-$ROOT/../owlet-tutk/target/release/owlet-tutk}"

[ -x "$PY" ] || { echo "Create .venv and install requirements.txt first." >&2; exit 1; }
for binary in "$MEDIAMTX_BIN" "$OWLET_TUTK_BIN" ffmpeg; do
  command -v "$binary" >/dev/null || { echo "Missing executable: $binary" >&2; exit 1; }
done

mkdir -p "$DATA_DIR"
pid_file="$DATA_DIR/app.pid"
if [ -s "$pid_file" ]; then
  previous="$(cat "$pid_file")"
  if [[ "$previous" =~ ^[0-9]+$ ]] && kill -0 "$previous" 2>/dev/null; then
    command_line="$(ps -p "$previous" -o command=)"
    [[ "$command_line" == *"uvicorn app.main:app --host 0.0.0.0 --port "* ]] || {
      echo "The PID file points to another process." >&2; exit 1;
    }
    kill "$previous"
    for _ in {1..20}; do
      kill -0 "$previous" 2>/dev/null || break
      sleep 1
    done
    if kill -0 "$previous" 2>/dev/null; then
      echo "The previous portal is still running." >&2; exit 1
    fi
  fi
fi

nohup "$PY" -m uvicorn app.main:app --host 0.0.0.0 --port "$API_PORT" \
  </dev/null >>"$DATA_DIR/app.log" 2>&1 &
pid=$!
echo "$pid" > "$pid_file"
for _ in {1..60}; do
  sleep 1
  kill -0 "$pid" 2>/dev/null || break
  if curl -fsS --max-time 2 "http://127.0.0.1:$API_PORT/api/health" 2>/dev/null |
    "$PY" -c 'import json,sys; sys.exit(not json.load(sys.stdin)["media"])' 2>/dev/null; then
    echo "Open http://$PUBLIC_HOST:$API_PORT/"
    exit 0
  fi
done
echo "Portal or media server failed. See $DATA_DIR/app.log and $DATA_DIR/mediamtx.log." >&2
exit 1
