"""
list_tools.py

Utility script that connects to the Notion MCP server and lists
all available tools with their descriptions and parameters.
Useful for debugging and verifying the MCP connection.
"""

import asyncio
import json
import os
import shutil
import sys

from dotenv import load_dotenv
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

load_dotenv()


def find_npx() -> tuple[str, str]:
    """Find npx binary, checking PATH and common nvm locations.
    Returns (npx_path, node_bin_dir) so node is also reachable."""
    npx = shutil.which("npx")
    if npx:
        return npx, os.path.dirname(os.path.realpath(npx))
    home = os.path.expanduser("~")
    nvm_dir = os.path.join(home, ".nvm", "versions", "node")
    if os.path.isdir(nvm_dir):
        for version in sorted(os.listdir(nvm_dir), reverse=True):
            bin_dir = os.path.join(nvm_dir, version, "bin")
            candidate = os.path.join(bin_dir, "npx")
            if os.path.isfile(candidate):
                return candidate, bin_dir
    sys.exit("ERROR: npx not found. Install Node.js >= 18.")


NOTION_TOKEN = os.getenv("NOTION_TOKEN", "")

if not NOTION_TOKEN:
    sys.exit("ERROR: NOTION_TOKEN is not set. Add it to your .env file.")


async def main():
    print("⏳ Starting Notion MCP server and discovering tools...\n")

    npx_path, node_bin_dir = find_npx()
    env = {**os.environ, "NOTION_TOKEN": NOTION_TOKEN}
    env["PATH"] = node_bin_dir + os.pathsep + env.get("PATH", "")

    server_params = StdioServerParameters(
        command=npx_path,
        args=["-y", "@notionhq/notion-mcp-server"],
        env=env,
    )

    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()

            tools_result = await session.list_tools()
            tools = tools_result.tools

            print(f"Found {len(tools)} tools:\n")
            print("=" * 70)

            for i, tool in enumerate(tools, 1):
                print(f"\n{i}. {tool.name}")
                print(f"   Description: {tool.description or 'N/A'}")
                if tool.inputSchema:
                    props = tool.inputSchema.get("properties", {})
                    required = tool.inputSchema.get("required", [])
                    if props:
                        print(f"   Parameters:")
                        for pname, pschema in props.items():
                            req_marker = " (required)" if pname in required else ""
                            ptype = pschema.get("type", "any")
                            pdesc = pschema.get("description", "")
                            print(f"     - {pname}: {ptype}{req_marker}")
                            if pdesc:
                                print(f"       {pdesc[:100]}")
                print("-" * 70)

            # Also dump full JSON for reference
            tools_json = [
                {
                    "name": t.name,
                    "description": t.description,
                    "inputSchema": t.inputSchema,
                }
                for t in tools
            ]
            with open("notion_tools.json", "w") as f:
                json.dump(tools_json, f, indent=2)
            print(f"\n📄 Full tool definitions saved to notion_tools.json")


if __name__ == "__main__":
    asyncio.run(main())
