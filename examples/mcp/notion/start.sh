#!/usr/bin/env bash
# Quick launcher for the Notion MCP example.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if ! command -v node &>/dev/null; then
    echo "Node.js is required (for npx / Notion MCP server)."
    echo "   Install it from https://nodejs.org/"
    exit 1
fi

if ! command -v python3 &>/dev/null; then
    echo "Python 3 is required."
    exit 1
fi

if [ ! -f .env ]; then
    echo "No .env file found. Copying from .env.example..."
    cp .env.example .env
    echo "Please edit .env and add your NOTION_TOKEN and GEMINI_API_KEY"
    exit 1
fi

if [ ! -d .venv ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv .venv
fi

source .venv/bin/activate

echo "Installing Python dependencies..."
pip install -q -r requirements.txt

echo ""
echo "Select mode:"
echo "  1) Single query      (client.py)"
echo "  2) Interactive chat  (chat.py)"
echo "  3) List tools        (list_tools.py)"
echo ""
read -rp "Choice [1/2/3]: " choice

case "${choice}" in
    1) python client.py "$@" ;;
    2) python chat.py ;;
    3) python list_tools.py ;;
    *) echo "Invalid choice"; exit 1 ;;
esac
