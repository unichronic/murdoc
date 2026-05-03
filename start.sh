#!/bin/bash

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Starting Murdoc services..."

echo "Starting Murdoc Gateway (Port 8000)..."
cd "$ROOT_DIR"
uvicorn murdoc.gateway.app:app --host 0.0.0.0 --port 8000 --reload > /dev/null 2>&1 &
GATEWAY_PID=$!

echo "Starting Vite UI Dev Server (Port 5173)..."
cd "$ROOT_DIR/ui"
npm run dev > /dev/null 2>&1 &
FRONTEND_PID=$!

echo "Starting Local Agent Target (Port 8001)..."
cd "$ROOT_DIR"
python tests/fixtures/targets/agno_bot.py --port 8001 > /dev/null 2>&1 &
TARGET_PID=$!

function cleanup() {
    echo ""
    echo "Shutting down services..."
    kill $GATEWAY_PID $FRONTEND_PID $TARGET_PID 2>/dev/null
    echo "Shutdown complete."
    exit 0
}

trap cleanup SIGINT SIGTERM

echo "=========================================="
echo "All services started successfully."
echo "   Gateway API : http://localhost:8000"
echo "   Agent Target: http://localhost:8001"
echo "   Web UI      : http://localhost:5173"
echo ""
echo "Press Ctrl+C to stop all services."
echo "=========================================="

wait
