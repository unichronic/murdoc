#!/bin/bash
# ==========================================
# AgentVault - Service Startup Script
# ==========================================
# Starts the HTTP gateway, the React frontend,
# and the vulnerable local agent target.
# Captures Ctrl+C to shut them all down cleanly.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Starting AgentVault services..."

# 1. Start gateway (FastAPI security gateway and control-plane API)
echo "Starting AgentVault Gateway (Port 8000)..."
cd "$ROOT_DIR"
uvicorn agentvault_gateway.app:app --host 0.0.0.0 --port 8000 --reload > /dev/null 2>&1 &
GATEWAY_PID=$!

# 2. Start frontend (Vite dev server)
echo "Starting Vite UI Dev Server (Port 5173)..."
cd "$ROOT_DIR/ui"
npm run dev > /dev/null 2>&1 &
FRONTEND_PID=$!

# 3. Start local agent target used by the attack lab
echo "Starting Local Agent Target (Port 8001)..."
cd "$ROOT_DIR"
python tests/fixtures/targets/agno_bot.py --port 8001 > /dev/null 2>&1 &
TARGET_PID=$!

# Handle Ctrl+C (SIGINT) to clean up all background jobs
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

# Keep script running to maintain the background processes
wait
