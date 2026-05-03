# Examples

Examples should be clone-and-run references for specific integration paths.
Keep them small, explicit, and aligned with the production gateway modes.

## Notion MCP Example

The Notion MCP example lives under `examples/mcp/notion`.

```bash
cd examples/mcp/notion
cp .env.example .env
pip install -r requirements.txt
python client.py "What pages are in my workspace?"
```

Run the Notion MCP server through Murdoc from the repo root:

```bash
export MCP_SERVER_ID=notion
export MCP_DOWNSTREAM_COMMAND=npx
export MCP_DOWNSTREAM_ARGS="-y @notionhq/notion-mcp-server"
export NOTION_TOKEN=ntn_...

python -m murdoc.mcp.proxy_server
```

Tool filtering is controlled with:

- `MCP_ENFORCE_TOOL_ALLOWLIST`
- `MCP_ALLOWED_TOOLS`
- `MCP_BLOCKED_TOOLS`
- `MCP_READ_ONLY_MODE`

## Example Rules

- Do not require production secrets in committed files.
- Keep `.env.example` scoped to the example.
- Show the Murdoc gateway path, not only the direct provider path.
- Avoid adding broad framework demos that duplicate the same integration mode.
