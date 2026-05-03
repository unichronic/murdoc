#!/usr/bin/env bash

set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${LOG_DIR:-$ROOT_DIR/logs}"
ENV_FILE="${ENV_FILE:-$ROOT_DIR/.env}"
RUN_DIR="${RUN_DIR:-$ROOT_DIR/.murdoc}"
PID_FILE="$RUN_DIR/start.pid"
SERVICE_FILE="$RUN_DIR/services"

COMMAND=start
GATEWAY_ENABLED=true
UI_ENABLED=true
AGENT_TARGET_ENABLED=false
OBSERVABILITY_ENABLED="${START_OBSERVABILITY:-false}"

PYTHON_BIN="${PYTHON_BIN:-python}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN=python3
fi

usage() {
    cat <<'EOF'
Usage: ./start.sh [command] [options]

Commands:
  start            Start the local stack (default)
  stop             Stop the stack started by this script
  restart          Stop, then start
  status           Show stack status

Starts:
  - FastAPI gateway on GATEWAY_PORT, default 8000
  - Vite UI on UI_PORT, default 5173
  - No fixed target agent by default; Attack Lab starts targets per run

Options:
  --no-gateway       Do not start the FastAPI gateway
  --no-ui            Do not start the Vite UI
  --agent            Also start the standalone local target fixture
  --no-agent         Compatibility no-op; targets are off by default
  --observability    Start observability/docker-compose.yml in the background
  --help             Show this help

Environment:
  ENV_FILE=.env.local          Load a different env file
  LOG_DIR=logs/local           Write service logs somewhere else
  GATEWAY_HOST=127.0.0.1       Gateway bind host
  GATEWAY_PORT=8000            Gateway port
  UI_HOST=127.0.0.1            UI bind host
  UI_PORT=5173                 UI port
  AGENT_TARGET_PORT=8001       Local target agent port
  UVICORN_RELOAD=true          Run gateway with reload
  NPM_INSTALL=false            Run npm install before starting UI
EOF
}

if [[ $# -gt 0 ]]; then
    case "$1" in
        start|stop|restart|status)
            COMMAND="$1"
            shift
            ;;
    esac
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-gateway)
            GATEWAY_ENABLED=false
            ;;
        --no-ui)
            UI_ENABLED=false
            ;;
        --no-agent)
            AGENT_TARGET_ENABLED=false
            ;;
        --agent)
            AGENT_TARGET_ENABLED=true
            ;;
        --observability)
            OBSERVABILITY_ENABLED=true
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

if [[ -f "$ENV_FILE" ]]; then
    set -a
    # shellcheck source=/dev/null
    source "$ENV_FILE"
    set +a
fi

GATEWAY_HOST="${GATEWAY_HOST:-127.0.0.1}"
GATEWAY_PORT="${GATEWAY_PORT:-8000}"
UI_HOST="${UI_HOST:-127.0.0.1}"
UI_PORT="${UI_PORT:-5173}"
AGENT_TARGET_HOST="${AGENT_TARGET_HOST:-127.0.0.1}"
AGENT_TARGET_PORT="${AGENT_TARGET_PORT:-8001}"
UVICORN_RELOAD="${UVICORN_RELOAD:-true}"
NPM_INSTALL="${NPM_INSTALL:-false}"

mkdir -p "$LOG_DIR"
mkdir -p "$RUN_DIR"

PIDS=()
NAMES=()
LOGS=()
OBSERVABILITY_STARTED=false
CLEANED_UP=false

display_host() {
    local host="$1"
    if [[ "$host" == "0.0.0.0" || "$host" == "::" ]]; then
        echo "localhost"
    else
        echo "$host"
    fi
}

gateway_url="http://$(display_host "$GATEWAY_HOST"):$GATEWAY_PORT"
ui_url="http://$(display_host "$UI_HOST"):$UI_PORT"
agent_url="http://$(display_host "$AGENT_TARGET_HOST"):$AGENT_TARGET_PORT"

is_alive() {
    local pid="${1:-}"
    [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1
}

read_stack_pid() {
    if [[ -f "$PID_FILE" ]]; then
        sed -n '1p' "$PID_FILE"
    fi
}

record_state() {
    {
        echo "$$"
    } >"$PID_FILE"

    : >"$SERVICE_FILE"
    for i in "${!PIDS[@]}"; do
        printf '%s\t%s\t%s\n' "${NAMES[$i]}" "${PIDS[$i]}" "${LOGS[$i]}" >>"$SERVICE_FILE"
    done
}

clear_state() {
    rm -f "$PID_FILE" "$SERVICE_FILE"
}

http_ok() {
    "$PYTHON_BIN" - "$1" >/dev/null 2>&1 <<'PY'
import sys
import urllib.request

try:
    urllib.request.urlopen(sys.argv[1], timeout=1).read()
except Exception:
    raise SystemExit(1)
PY
}

status_stack() {
    local stack_pid
    stack_pid="$(read_stack_pid || true)"

    if is_alive "$stack_pid"; then
        echo "Murdoc local stack is running (manager pid $stack_pid)."
    else
        echo "Murdoc local stack manager is not running."
    fi

    if [[ -f "$SERVICE_FILE" ]]; then
        while IFS=$'\t' read -r name pid log_file; do
            [[ -z "${name:-}" ]] && continue
            if is_alive "$pid"; then
                echo "  $name: running (pid $pid, log $log_file)"
            else
                echo "  $name: stopped (pid $pid, log $log_file)"
            fi
        done <"$SERVICE_FILE"
    fi

    http_ok "$gateway_url/healthz" && echo "  Gateway API : $gateway_url" || true
    http_ok "$ui_url" && echo "  Web UI      : $ui_url" || true
    http_ok "$agent_url/health" && echo "  Agent target: $agent_url" || true
}

stop_stack() {
    local stack_pid
    stack_pid="$(read_stack_pid || true)"

    if is_alive "$stack_pid"; then
        echo "Stopping Murdoc local stack (manager pid $stack_pid)..."
        kill -TERM "$stack_pid" >/dev/null 2>&1 || true
        for _ in $(seq 1 20); do
            if ! is_alive "$stack_pid"; then
                clear_state
                echo "Stopped."
                return 0
            fi
            sleep 0.5
        done
        echo "Manager did not exit after TERM; stopping recorded services." >&2
    fi

    if [[ -f "$SERVICE_FILE" ]]; then
        while IFS=$'\t' read -r name pid _log_file; do
            [[ -z "${name:-}" ]] && continue
            if is_alive "$pid"; then
                echo "Stopping $name..."
                kill -TERM "-$pid" >/dev/null 2>&1 || kill -TERM "$pid" >/dev/null 2>&1 || true
            fi
        done <"$SERVICE_FILE"
    fi

    clear_state
    echo "Stopped."
}

require_command() {
    local command_name="$1"
    local install_hint="$2"
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "Missing required command: $command_name" >&2
        echo "$install_hint" >&2
        exit 1
    fi
}

port_in_use() {
    "$PYTHON_BIN" - "$1" <<'PY'
import socket
import sys

port = int(sys.argv[1])
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.settimeout(0.2)
    raise SystemExit(0 if sock.connect_ex(("127.0.0.1", port)) == 0 else 1)
PY
}

url_port_open() {
    "$PYTHON_BIN" - "$1" <<'PY'
import socket
import sys
from urllib.parse import urlparse

url = urlparse(sys.argv[1])
host = url.hostname
port = url.port or (443 if url.scheme == "https" else 80)
if not host:
    raise SystemExit(1)
try:
    with socket.create_connection((host, port), timeout=0.5):
        raise SystemExit(0)
except OSError:
    raise SystemExit(1)
PY
}

ensure_port_free() {
    local name="$1"
    local port="$2"
    if port_in_use "$port"; then
        echo "$name port $port is already in use. Stop the existing process or set a different port." >&2
        echo "If it is Murdoc, run: ./start.sh status, ./start.sh stop, or ./start.sh restart" >&2
        exit 1
    fi
}

start_service() {
    local name="$1"
    local workdir="$2"
    local log_file="$3"
    shift 3

    echo "Starting $name..."
    setsid bash -c 'cd "$1"; shift; exec "$@"' bash "$workdir" "$@" >"$log_file" 2>&1 &
    local pid=$!
    PIDS+=("$pid")
    NAMES+=("$name")
    LOGS+=("$log_file")
    record_state
    echo "  pid $pid, log $log_file"
}

wait_http() {
    local name="$1"
    local url="$2"
    local log_file="$3"
    local max_attempts="${4:-30}"

    for _ in $(seq 1 "$max_attempts"); do
        if "$PYTHON_BIN" - "$url" >/dev/null 2>&1 <<'PY'
import sys
import urllib.request

try:
    urllib.request.urlopen(sys.argv[1], timeout=1).read()
except Exception:
    raise SystemExit(1)
PY
        then
            echo "$name is ready: $url"
            return 0
        fi
        sleep 1
    done

    echo "$name did not become ready. Last log lines:" >&2
    tail -40 "$log_file" >&2 || true
    exit 1
}

cleanup() {
    local exit_code=$?
    if [[ "$CLEANED_UP" == "true" ]]; then
        exit "$exit_code"
    fi
    CLEANED_UP=true

    echo ""
    echo "Shutting down local services..."

    for i in "${!PIDS[@]}"; do
        local pid="${PIDS[$i]}"
        local name="${NAMES[$i]}"
        if kill -0 "$pid" >/dev/null 2>&1; then
            echo "Stopping $name..."
            kill -TERM "-$pid" >/dev/null 2>&1 || kill -TERM "$pid" >/dev/null 2>&1 || true
        fi
    done

    for pid in "${PIDS[@]}"; do
        wait "$pid" 2>/dev/null || true
    done

    if [[ "$OBSERVABILITY_STARTED" == "true" ]]; then
        echo "Stopping observability stack..."
        docker compose -f "$ROOT_DIR/observability/docker-compose.yml" down >/dev/null 2>&1 || true
    fi

    clear_state
    echo "Shutdown complete."
    exit "$exit_code"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

case "$COMMAND" in
    stop)
        stop_stack
        trap - EXIT
        exit 0
        ;;
    status)
        status_stack
        trap - EXIT
        exit 0
        ;;
    restart)
        stop_stack
        ;;
    start)
        existing_pid="$(read_stack_pid || true)"
        if is_alive "$existing_pid"; then
            echo "Murdoc local stack is already running."
            status_stack
            trap - EXIT
            exit 0
        fi
        clear_state
        ;;
    *)
        echo "Unknown command: $COMMAND" >&2
        usage >&2
        trap - EXIT
        exit 2
        ;;
esac

require_command "$PYTHON_BIN" "Install Python 3 and run: pip install -r requirements.txt"

if [[ "$GATEWAY_ENABLED" == "true" ]]; then
    ensure_port_free "Gateway" "$GATEWAY_PORT"
    if ! "$PYTHON_BIN" -m uvicorn --version >/dev/null 2>&1; then
        echo "Missing Python dependency: uvicorn" >&2
        echo "Run: pip install -r requirements.txt" >&2
        exit 1
    fi
fi

if [[ "$UI_ENABLED" == "true" ]]; then
    require_command npm "Install Node.js and npm, then run: cd ui && npm install"
    ensure_port_free "UI" "$UI_PORT"
    if [[ "$NPM_INSTALL" == "true" || ! -d "$ROOT_DIR/ui/node_modules" ]]; then
        echo "Installing UI dependencies..."
        npm --prefix "$ROOT_DIR/ui" install
    fi
fi

if [[ "$AGENT_TARGET_ENABLED" == "true" ]]; then
    ensure_port_free "Agent target" "$AGENT_TARGET_PORT"
    if ! "$PYTHON_BIN" - <<'PY' >/dev/null 2>&1
import flask
import requests
PY
    then
        echo "Missing Python dependencies for the local target agent: flask and requests" >&2
        echo "Run: pip install -r requirements.txt" >&2
        exit 1
    fi
fi

if [[ "$OBSERVABILITY_ENABLED" == "true" ]]; then
    require_command docker "Install Docker to start the optional observability stack."
fi

if [[ "$GATEWAY_ENABLED" == "true" && -n "${OPA_POLICY_URL:-}" ]] && ! url_port_open "$OPA_POLICY_URL"; then
    echo "Warning: OPA_POLICY_URL is set but unreachable: $OPA_POLICY_URL" >&2
    echo "         Local testing may fail closed. Leave OPA_POLICY_URL empty to use Murdoc's built-in policy evaluator." >&2
fi

echo "Starting Murdoc local stack..."

if [[ "$OBSERVABILITY_ENABLED" == "true" ]]; then
    echo "Starting observability stack..."
    docker compose -f "$ROOT_DIR/observability/docker-compose.yml" up -d
    OBSERVABILITY_STARTED=true
fi

if [[ "$AGENT_TARGET_ENABLED" == "true" ]]; then
    start_service \
        "local target agent" \
        "$ROOT_DIR" \
        "$LOG_DIR/agent-target.log" \
        "$PYTHON_BIN" tests/fixtures/targets/agno_bot.py --port "$AGENT_TARGET_PORT"
fi

if [[ "$GATEWAY_ENABLED" == "true" ]]; then
    gateway_args=(-m uvicorn murdoc.gateway.app:app --host "$GATEWAY_HOST" --port "$GATEWAY_PORT")
    if [[ "$UVICORN_RELOAD" == "true" ]]; then
        gateway_args+=(--reload)
    fi
    start_service "gateway" "$ROOT_DIR" "$LOG_DIR/gateway.log" "$PYTHON_BIN" "${gateway_args[@]}"
fi

if [[ "$UI_ENABLED" == "true" ]]; then
    start_service "ui" "$ROOT_DIR/ui" "$LOG_DIR/ui.log" npm run dev -- --host "$UI_HOST" --port "$UI_PORT"
fi

gateway_url="http://$(display_host "$GATEWAY_HOST"):$GATEWAY_PORT"
ui_url="http://$(display_host "$UI_HOST"):$UI_PORT"
agent_url="http://$(display_host "$AGENT_TARGET_HOST"):$AGENT_TARGET_PORT"

if [[ "$AGENT_TARGET_ENABLED" == "true" ]]; then
    wait_http "Local target agent" "$agent_url/health" "$LOG_DIR/agent-target.log" 20
fi
if [[ "$GATEWAY_ENABLED" == "true" ]]; then
    wait_http "Gateway" "$gateway_url/healthz" "$LOG_DIR/gateway.log" 30
fi
if [[ "$UI_ENABLED" == "true" ]]; then
    wait_http "UI" "$ui_url" "$LOG_DIR/ui.log" 30
fi

echo ""
echo "Murdoc local stack is running."
[[ "$GATEWAY_ENABLED" == "true" ]] && echo "  Gateway API : $gateway_url"
[[ "$GATEWAY_ENABLED" == "true" ]] && echo "  Metrics     : $gateway_url/metrics"
[[ "$GATEWAY_ENABLED" == "true" ]] && echo "  Control API : $gateway_url/api/control-plane/*"
[[ "$UI_ENABLED" == "true" ]] && echo "  Web UI      : $ui_url"
[[ "$AGENT_TARGET_ENABLED" == "true" ]] && echo "  Agent target: $agent_url"
[[ "$OBSERVABILITY_STARTED" == "true" ]] && echo "  Observability stack started with Docker Compose"
echo ""
echo "Logs are in $LOG_DIR."
echo "Press Ctrl+C to stop everything started by this script."

wait
