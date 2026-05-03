# Notion MCP Example

This example shows how to run a downstream Notion MCP server through the
Murdoc MCP adapter or proxy.

## Setup

```bash
cd examples/mcp/notion
cp .env.example .env
```

Set:

```bash
NOTION_TOKEN=ntn_...
GEMINI_API_KEY=...
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Run The Demo Client

```bash
python client.py "What pages are in my workspace?"
```

Interactive mode:

```bash
python chat.py
```

List downstream tools:

```bash
python list_tools.py
```

## Run Through The Standalone Proxy

From the repo root:

```bash
export MCP_SERVER_ID=notion
export MCP_DOWNSTREAM_COMMAND=npx
export MCP_DOWNSTREAM_ARGS="-y @notionhq/notion-mcp-server"
export NOTION_TOKEN=ntn_...

python -m murdoc.mcp.proxy_server
```

Tool filtering can be configured with:

```bash
MCP_ENFORCE_TOOL_ALLOWLIST=true
MCP_ALLOWED_TOOLS=notion:notion-search,notion:notion-retrieve-a-page
MCP_BLOCKED_TOOLS=notion:notion-delete-a-block
MCP_READ_ONLY_MODE=true
```
