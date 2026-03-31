#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
STACK_DIR="${STACK_DIR:-$SCRIPT_DIR/runtime/safetydash_stack}"

FRONTEND_PID_FILE="$STACK_DIR/frontend.pid"
DASHBOARD_PID_FILE="$STACK_DIR/dashboard_api.pid"
JB_PID_FILE="$STACK_DIR/jb_demo.pid"

pid_is_running() {
  local pid="$1"
  kill -0 "$pid" >/dev/null 2>&1
}

stop_service() {
  local name="$1"
  local pid_file="$2"
  local pid
  local attempt

  if [ ! -f "$pid_file" ]; then
    echo "$name not running (missing pid file)"
    return 0
  fi

  pid=$(cat "$pid_file")
  if ! pid_is_running "$pid"; then
    echo "$name already stopped (stale pid file: $pid)"
    rm -f "$pid_file"
    return 0
  fi

  echo "Stopping $name (pid=$pid)"
  kill "$pid" >/dev/null 2>&1 || true
  for ((attempt = 1; attempt <= 15; attempt++)); do
    if ! pid_is_running "$pid"; then
      rm -f "$pid_file"
      echo "$name stopped"
      return 0
    fi
    sleep 1
  done

  echo "$name did not exit in time; forcing stop"
  kill -9 "$pid" >/dev/null 2>&1 || true
  rm -f "$pid_file"
}

main() {
  stop_service "safetydash-frontend" "$FRONTEND_PID_FILE"
  stop_service "dashboard-api" "$DASHBOARD_PID_FILE"
  stop_service "jb_demo" "$JB_PID_FILE"

  cat <<EOF

Stopped managed SafetyDash stack processes.

Runtime directory:
  $STACK_DIR
EOF
}

main "$@"
