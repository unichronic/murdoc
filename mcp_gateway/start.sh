#!/usr/bin/env bash
# ============================================================
# start.sh — Quick launcher for the Notion MCP Client
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Check prerequisites ───────────────────────────────────────
if ! command -v node &>/dev/null; then
    echo "❌  Node.js is required (for npx / Notion MCP server)."
    echo "   Install it from https://nodejs.org/"
    exit 1
fi

if ! command -v python3 &>/dev/null; then
    echo "❌  Python 3 is required."
    exit 1
fi

# ── Check .env ─────────────────────────────────────────────────
if [ ! -f .env ]; then
    echo "⚠️  No .env file found. Copying from .env.example..."
    cp .env.example .env
    echo "   ✏️  Please edit .env and add your NOTION_TOKEN and OPENAI_API_KEY"
    exit 1
fi

# ── Create venv if needed ──────────────────────────────────────
if [ ! -d .venv ]; then
    echo "📦 Creating Python virtual environment..."
    python3 -m venv .venv
fi

source .venv/bin/activate

echo "📦 Installing Python dependencies..."
pip install -q -r requirements.txt

# ── Run ────────────────────────────────────────────────────────
echo ""
echo "Select mode:"
echo "  1) Single query     (notion_mcp_client.py)"
echo "  2) Interactive chat  (chat_app.py)"
echo "  3) List tools       (list_tools.py)"
echo ""
read -rp "Choice [1/2/3]: " choice

case "${choice}" in
    1) python notion_mcp_client.py "$@" ;;
    2) python chat_app.py ;;
    3) python list_tools.py ;;
    *) echo "Invalid choice"; exit 1 ;;
esac
