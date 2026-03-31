#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
JB_DEMO_DIR="${JB_DEMO_DIR:-$SCRIPT_DIR}"
SAFETYDASH_DIR="${SAFETYDASH_DIR:-/data/ljc/safetydash}"
DASHBOARD_API_DIR="${DASHBOARD_API_DIR:-$SAFETYDASH_DIR/services/dashboard-api}"
FRONTEND_DIR="${FRONTEND_DIR:-$SAFETYDASH_DIR/frontend}"
DASHBOARD_VENV="${DASHBOARD_VENV:-/tmp/safetydash-dashboard-api-venv}"
JB_DEMO_CONDA_ENV="${JB_DEMO_CONDA_ENV:-jb_demo}"

STACK_DIR="${STACK_DIR:-$JB_DEMO_DIR/runtime/safetydash_stack}"
DB_FILE="${DB_FILE:-$STACK_DIR/safetydash-run.db}"

JB_PORT="${JB_PORT:-18013}"
DASHBOARD_PORT="${DASHBOARD_PORT:-18117}"
FRONTEND_PORT="${FRONTEND_PORT:-5173}"

JB_SERVICE_TOKEN="${JB_SERVICE_TOKEN:-sd-integration-token}"
JB_JWT_SECRET="${JB_JWT_SECRET:-jb-demo-dev-only-change-me}"
SEED_USERNAME="${SEED_USERNAME:-admin}"
SEED_PASSWORD="${SEED_PASSWORD:-admin}"

JB_PID_FILE="$STACK_DIR/jb_demo.pid"
DASHBOARD_PID_FILE="$STACK_DIR/dashboard_api.pid"
FRONTEND_PID_FILE="$STACK_DIR/frontend.pid"

JB_LOG_FILE="$STACK_DIR/jb_demo.log"
DASHBOARD_LOG_FILE="$STACK_DIR/dashboard_api.log"
FRONTEND_LOG_FILE="$STACK_DIR/frontend.log"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

pid_is_running() {
  local pid="$1"
  kill -0 "$pid" >/dev/null 2>&1
}

port_in_use() {
  local port="$1"
  ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)$port$"
}

wait_for_url() {
  local url="$1"
  local timeout="${2:-60}"
  local label="${3:-service}"
  local attempt
  for ((attempt = 1; attempt <= timeout; attempt++)); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done

  echo "Timed out waiting for $label: $url" >&2
  return 1
}

ensure_dashboard_venv() {
  if [ -x "$DASHBOARD_VENV/bin/python" ]; then
    return 0
  fi

  echo "Creating dashboard-api virtualenv: $DASHBOARD_VENV"
  require_cmd python3
  python3 -m venv "$DASHBOARD_VENV"
  "$DASHBOARD_VENV/bin/pip" install --upgrade pip
  "$DASHBOARD_VENV/bin/pip" install -e "$DASHBOARD_API_DIR"
}

ensure_frontend_dependencies() {
  if [ -d "$FRONTEND_DIR/node_modules" ]; then
    return 0
  fi

  echo "Installing frontend dependencies with npm"
  (cd "$FRONTEND_DIR" && npm install)
}

write_frontend_env() {
  cat >"$FRONTEND_DIR/.env" <<EOF
VITE_USE_MOCK=false
VITE_API_BASE_URL=http://127.0.0.1:$DASHBOARD_PORT
EOF
}

ensure_dashboard_seed_user() {
  # shellcheck disable=SC1090
  source "$DASHBOARD_VENV/bin/activate"
  export DATABASE_URL="sqlite+pysqlite:////$DB_FILE"
  export SEED_USERNAME
  export SEED_PASSWORD
  export JB_DEMO_BASE_URL="http://127.0.0.1:$JB_PORT"
  export JB_DEMO_USERNAME="$SEED_USERNAME"
  export JB_DEMO_PASSWORD="$SEED_PASSWORD"
  export JB_DEMO_SERVICE_TOKEN="$JB_SERVICE_TOKEN"
  (
    cd "$DASHBOARD_API_DIR"
    python -m app.scripts.init_db
  )
  deactivate >/dev/null 2>&1 || true
}

start_service() {
  local name="$1"
  local pid_file="$2"
  local log_file="$3"
  local port="$4"
  local health_url="$5"
  local command="$6"

  if [ -f "$pid_file" ]; then
    local existing_pid
    existing_pid=$(cat "$pid_file")
    if pid_is_running "$existing_pid"; then
      echo "$name already running (pid=$existing_pid)"
      return 0
    fi
    rm -f "$pid_file"
  fi

  if port_in_use "$port"; then
    echo "Port $port already in use; refusing to start $name" >&2
    exit 1
  fi

  echo "Starting $name on port $port"
  nohup bash -lc "$command" >"$log_file" 2>&1 &
  echo $! >"$pid_file"

  if ! wait_for_url "$health_url" 90 "$name"; then
    echo "Failed to start $name. Recent log output:" >&2
    tail -n 40 "$log_file" >&2 || true
    exit 1
  fi
}

main() {
  require_cmd conda
  require_cmd curl
  require_cmd npm
  require_cmd node
  require_cmd ss

  mkdir -p "$STACK_DIR"

  if ! conda env list | awk '{print $1}' | grep -Fxq "$JB_DEMO_CONDA_ENV"; then
    echo "Conda environment not found: $JB_DEMO_CONDA_ENV" >&2
    exit 1
  fi

  if [ ! -d "$JB_DEMO_DIR" ]; then
    echo "jb_demo directory not found: $JB_DEMO_DIR" >&2
    exit 1
  fi
  if [ ! -d "$DASHBOARD_API_DIR" ]; then
    echo "dashboard-api directory not found: $DASHBOARD_API_DIR" >&2
    exit 1
  fi
  if [ ! -d "$FRONTEND_DIR" ]; then
    echo "frontend directory not found: $FRONTEND_DIR" >&2
    exit 1
  fi

  ensure_dashboard_venv
  ensure_frontend_dependencies
  write_frontend_env
  ensure_dashboard_seed_user

  start_service \
    "jb_demo" \
    "$JB_PID_FILE" \
    "$JB_LOG_FILE" \
    "$JB_PORT" \
    "http://127.0.0.1:$JB_PORT/docs" \
    "cd \"$JB_DEMO_DIR\" && export JB_DEMO_SERVICE_TOKEN=\"$JB_SERVICE_TOKEN\" JB_DEMO_JWT_SECRET=\"$JB_JWT_SECRET\" JB_DEMO_JWT_ALG=HS256 JB_DEMO_ACCESS_TOKEN_EXPIRE_MINUTES=60 JB_DEMO_SEED_USERNAME=\"$SEED_USERNAME\" JB_DEMO_SEED_PASSWORD=\"$SEED_PASSWORD\" APP_CORS_ALLOW_ORIGINS=\"http://127.0.0.1:$FRONTEND_PORT,http://localhost:$FRONTEND_PORT\" && conda run -n \"$JB_DEMO_CONDA_ENV\" python -m uvicorn main:app --host 127.0.0.1 --port \"$JB_PORT\""

  start_service \
    "dashboard-api" \
    "$DASHBOARD_PID_FILE" \
    "$DASHBOARD_LOG_FILE" \
    "$DASHBOARD_PORT" \
    "http://127.0.0.1:$DASHBOARD_PORT/api/healthz" \
    "source \"$DASHBOARD_VENV/bin/activate\" && cd \"$DASHBOARD_API_DIR\" && export DATABASE_URL=\"sqlite+pysqlite:////$DB_FILE\" SEED_USERNAME=\"$SEED_USERNAME\" SEED_PASSWORD=\"$SEED_PASSWORD\" JB_DEMO_BASE_URL=\"http://127.0.0.1:$JB_PORT\" JB_DEMO_USERNAME=\"$SEED_USERNAME\" JB_DEMO_PASSWORD=\"$SEED_PASSWORD\" JB_DEMO_SERVICE_TOKEN=\"$JB_SERVICE_TOKEN\" && python -m uvicorn app.main:app --host 127.0.0.1 --port \"$DASHBOARD_PORT\""

  start_service \
    "safetydash-frontend" \
    "$FRONTEND_PID_FILE" \
    "$FRONTEND_LOG_FILE" \
    "$FRONTEND_PORT" \
    "http://127.0.0.1:$FRONTEND_PORT" \
    "cd \"$FRONTEND_DIR\" && npm run dev -- --host 127.0.0.1 --port \"$FRONTEND_PORT\""

  cat <<EOF

SafetyDash stack is ready.

Login URL:
  http://127.0.0.1:$FRONTEND_PORT/login

Credentials:
  username: $SEED_USERNAME
  password: $SEED_PASSWORD

Service URLs:
  jb_demo:       http://127.0.0.1:$JB_PORT
  dashboard-api: http://127.0.0.1:$DASHBOARD_PORT
  frontend:      http://127.0.0.1:$FRONTEND_PORT

Runtime files:
  $STACK_DIR
EOF
}

main "$@"
