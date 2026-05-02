# 🛡️ MCP Gateway — Notion MCP Server + AI Client

> **Secure AI ↔ Notion integration** with data-leak prevention via Bifrost Gateway, Lakera Guard, OPA Policy Checker, and Presidio.

---

## Architecture

```
┌──────────┐     ┌──────────────────────────────────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│          │     │            Bifrost MCP Gateway               │     │                  │     │                  │
│          │     │  ┌────────────┐ ┌─────┐ ┌──────────┐        │     │   AI Client      │     │  Notion MCP      │
│   User   ├────►│  │Lakera Guard│►│ OPA │►│ Presidio │────────├────►│  (OpenAI GPT-4o) ├────►│  Server          │
│          │     │  │(Prompt Inj)│ │(Pol)│ │(PII/DLP) │        │     │                  │     │  (npx notion-mcp)│
│          │◄────│  └────────────┘ └─────┘ └──────────┘        │◄────│                  │◄────│                  │
│          │     │                                              │     │                  │     │                  │
└──────────┘     └──────────────────────────────────────────────┘     └──────────────────┘     └──────────────────┘
                          Security Layers                                AI Layer                  Data Layer
```

**Data flow:**
1. **User** sends a natural-language request
2. **Bifrost Gateway** intercepts and runs security checks:
   - **Lakera Guard** — blocks prompt injection attacks
   - **OPA Policy Checker** — enforces organisation policies
   - **Presidio** — detects/redacts PII and sensitive data
3. **AI Client** receives the sanitised request and plans tool calls
4. **Notion MCP Server** executes the actual Notion API calls
5. Response flows back through the same security layers

---

## Project Structure

```
mcp_gateway/
├── .env.example              # Environment variable template
├── .gitignore
├── requirements.txt          # Python dependencies
├── start.sh                  # Quick launcher script
│
├── notion_mcp_client.py      # Single-query AI client
├── chat_app.py               # Interactive chat REPL
├── list_tools.py             # Utility: list all Notion MCP tools
│
└── mcp_config/
    ├── mcp_servers.json       # Standard MCP server config (for Claude Desktop / Cursor)
    └── bifrost_mcp_config.json # Bifrost Gateway MCP config
```

---

## Prerequisites

| Requirement | Version | Purpose |
|---|---|---|
| **Node.js** | ≥ 18 | Runs the Notion MCP server via `npx` |
| **Python** | ≥ 3.10 | AI client and chat app |
| **Notion Integration Token** | — | API access to your Notion workspace |
| **OpenAI API Key** | — | Powers the AI model (GPT-4o) |

---

## Step-by-Step Setup

### Step 1 — Create a Notion Integration

1. Go to [notion.so/profile/integrations](https://www.notion.so/profile/integrations)
2. Click **"New integration"**
3. Give it a name (e.g. `MCP Gateway`)
4. Select your workspace
5. Under **Capabilities**, choose the permissions you need:
   - ✅ Read content
   - ✅ Update content (if you want write access)
   - ✅ Insert content
6. Click **Submit** and copy the **Internal Integration Secret** (`ntn_...`)

### Step 2 — Grant Page Access to the Integration

1. Open the Notion pages/databases you want the AI to access
2. Click **⋯** → **"Connect to"** → select your integration
3. Or go to the integration's **Access** tab and add pages there

### Step 3 — Clone and Configure

```bash
cd /home/shankhanil/Hackathon/sandbox/mcp_gateway

# Copy the environment template
cp .env.example .env

# Edit .env and fill in your tokens:
#   NOTION_TOKEN=ntn_your_actual_token
#   OPENAI_API_KEY=sk-your_actual_key
```

### Step 4 — Install Dependencies

```bash
# Create a Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install Python packages
pip install -r requirements.txt
```

### Step 5 — Verify the Connection

```bash
# List all available Notion MCP tools
python list_tools.py
```

You should see ~22 tools including `notion-search`, `notion-retrieve-a-page`, `notion-create-a-page`, etc.

### Step 6 — Run the AI Client

```bash
# Option A: Single query
python notion_mcp_client.py "What pages are in my Notion workspace?"

# Option B: Interactive chat
python chat_app.py

# Option C: Use the launcher
./start.sh
```

---

## Integrating with Bifrost Gateway

The Bifrost MCP Gateway sits **in front** of this AI client. It intercepts all user messages and AI responses, applying the security layers.

### How to connect

1. **Start the Notion MCP server in HTTP mode** (so Bifrost can reach it):

```bash
NOTION_TOKEN=ntn_**** npx -y @notionhq/notion-mcp-server --transport http --port 3001 --auth-token "your-secret-token"
```

2. **Point Bifrost Gateway** to the Notion MCP server using the config in `mcp_config/bifrost_mcp_config.json`

3. **Point your AI client** to the Bifrost Gateway URL instead of directly to the MCP server:
   - Set `BIFROST_GATEWAY_URL=http://localhost:8080` in your `.env`

4. The request flow becomes:
   ```
   User → Bifrost Gateway (port 8080)
        → Lakera Guard (prompt injection check)
        → OPA (policy check)
        → Presidio (PII redaction)
        → AI Client → Notion MCP Server (port 3001)
        → Response back through all layers
   ```

### MCP Config for Claude Desktop / Cursor

To use this with Claude Desktop or Cursor directly (without Bifrost), copy the config from `mcp_config/mcp_servers.json`:

**Claude Desktop** (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):
```json
{
  "mcpServers": {
    "notionApi": {
      "command": "npx",
      "args": ["-y", "@notionhq/notion-mcp-server"],
      "env": {
        "NOTION_TOKEN": "ntn_your_token_here"
      }
    }
  }
}
```

**Cursor** (`.cursor/mcp.json` in your project):
```json
{
  "mcpServers": {
    "notionApi": {
      "command": "npx",
      "args": ["-y", "@notionhq/notion-mcp-server"],
      "env": {
        "NOTION_TOKEN": "ntn_your_token_here"
      }
    }
  }
}
```

---

## Available Notion MCP Tools (22 total)

| Tool | Description |
|---|---|
| `notion-search` | Search pages and databases |
| `notion-retrieve-a-page` | Get page details |
| `notion-retrieve-a-page-property-item` | Get a specific property |
| `notion-retrieve-block-children` | Read page content blocks |
| `notion-create-a-page` | Create a new page |
| `notion-update-page-properties` | Update page properties |
| `notion-move-page` | Move a page |
| `notion-append-block-children` | Add content blocks |
| `notion-delete-a-block` | Delete a block |
| `notion-update-a-block` | Update a block |
| `notion-retrieve-a-database` | Get database metadata |
| `notion-query-data-source` | Query a database |
| `notion-retrieve-a-data-source` | Get data source schema |
| `notion-create-a-data-source` | Create a database |
| `notion-update-a-data-source` | Update database properties |
| `notion-list-data-source-templates` | List templates |
| `notion-create-comment` | Add a comment |
| `notion-retrieve-comments` | Get comments on a page |
| `notion-retrieve-a-user` | Get user info |
| `notion-list-all-users` | List workspace users |
| `notion-me` | Get current bot user |
| `notion-search` | Full-text search |

---

## Example Queries

```
"List all pages in my Notion workspace"
"Search for pages about 'project roadmap'"
"Create a new page titled 'Meeting Notes' under the 'Team' page"
"What databases do I have?"
"Add a comment 'Reviewed' to the 'Q1 Planning' page"
"Get the content of page 1a6b35e6e67f802fa7e1d27686f017f2"
```

---

## Security Layers (handled by Bifrost Gateway)

| Layer | Purpose | What it catches |
|---|---|---|
| **Lakera Guard** | Prompt injection detection | Malicious prompts trying to manipulate the AI |
| **OPA Policy Checker** | Policy enforcement | Unauthorized actions, role-based access control |
| **Presidio** | PII/DLP detection & redaction | SSNs, credit cards, emails, phone numbers in data flowing to/from Notion |

---

## Troubleshooting

| Issue | Solution |
|---|---|
| `npx: command not found` | Install Node.js ≥ 18 |
| `NOTION_TOKEN not set` | Add your token to `.env` |
| `Tool call failed` | Ensure the integration has access to the target pages |
| `Rate limit` | Notion API has rate limits; add delays between requests |
| MCP server won't start | Run `npx -y @notionhq/notion-mcp-server` manually to check |

---

## License

MIT
