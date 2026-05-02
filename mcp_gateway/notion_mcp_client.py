"""
notion_mcp_client.py

AI Client that connects to the official Notion MCP Server.
It spawns the Notion MCP server as a subprocess (via npx), discovers
available tools, and lets an OpenAI model call those tools in a
conversational loop.

Architecture:
  User ─► Bifrost Gateway (security) ─► This AI Client ─► Notion MCP Server
"""

import asyncio
import json
import os
import shutil
import sys

from dotenv import load_dotenv
from openai import OpenAI
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

load_dotenv()

# ── Configuration ──────────────────────────────────────────────────────────
NOTION_TOKEN = os.getenv("NOTION_TOKEN", "")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")

if not NOTION_TOKEN:
    sys.exit("ERROR: NOTION_TOKEN is not set. Add it to your .env file.")
if not GEMINI_API_KEY:
    sys.exit("ERROR: GEMINI_API_KEY is not set. Add it to your .env file.")


# ── Helpers ────────────────────────────────────────────────────────────────
def find_npx() -> tuple[str, str]:
    """Find npx binary, checking PATH and common nvm locations.
    Returns (npx_path, node_bin_dir) so node is also reachable."""
    npx = shutil.which("npx")
    if npx:
        return npx, os.path.dirname(os.path.realpath(npx))
    # Check common nvm install locations
    home = os.path.expanduser("~")
    nvm_dir = os.path.join(home, ".nvm", "versions", "node")
    if os.path.isdir(nvm_dir):
        for version in sorted(os.listdir(nvm_dir), reverse=True):
            bin_dir = os.path.join(nvm_dir, version, "bin")
            candidate = os.path.join(bin_dir, "npx")
            if os.path.isfile(candidate):
                return candidate, bin_dir
    sys.exit("ERROR: npx not found. Install Node.js >= 18.")


def mcp_tools_to_openai_tools(mcp_tools: list) -> list[dict]:
    """Convert MCP tool definitions to OpenAI function-calling format."""
    openai_tools = []
    for tool in mcp_tools:
        openai_tools.append(
            {
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description or "",
                    "parameters": tool.inputSchema if tool.inputSchema else {"type": "object", "properties": {}},
                },
            }
        )
    return openai_tools


async def run_agent(user_query: str) -> str:
    """
    Spawn the Notion MCP server, discover tools, and run a
    multi-turn conversation with the OpenAI model until it
    produces a final text answer (no more tool calls).
    """

    # 1. Define how to start the Notion MCP server
    npx_path, node_bin_dir = find_npx()
    env = {**os.environ, "NOTION_TOKEN": NOTION_TOKEN}
    # Ensure node's bin dir is in PATH so npx can find node
    env["PATH"] = node_bin_dir + os.pathsep + env.get("PATH", "")

    server_params = StdioServerParameters(
        command=npx_path,
        args=["-y", "@notionhq/notion-mcp-server"],
        env=env,
    )

    # 2. Launch MCP server & create a session
    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            # Initialize the MCP connection
            await session.initialize()

            # 3. Discover available tools from the Notion MCP server
            tools_result = await session.list_tools()
            mcp_tools = tools_result.tools
            openai_tools = mcp_tools_to_openai_tools(mcp_tools)

            print(f"\n🔧 Discovered {len(mcp_tools)} Notion MCP tools:")
            for t in mcp_tools:
                print(f"   • {t.name}")
            print()

            # 4. Build initial messages
            messages = [
                {
                    "role": "system",
                    "content": (
                        "You are a helpful assistant that can interact with Notion "
                        "through the available tools. Use the tools to answer the "
                        "user's questions about their Notion workspace. "
                        "Always search before trying to read or modify content."
                    ),
                },
                {"role": "user", "content": user_query},
            ]

            # 5. Conversation loop – keep going until the model stops calling tools
            client = OpenAI(
                api_key=GEMINI_API_KEY,
                base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
            )

            while True:
                print("🤖 Calling Gemini model...")
                response = client.chat.completions.create(
                    model=GEMINI_MODEL,
                    messages=messages,
                    tools=openai_tools if openai_tools else None,
                )

                choice = response.choices[0]
                assistant_message = choice.message

                # If no tool calls, we have our final answer
                if not assistant_message.tool_calls:
                    final_answer = assistant_message.content or "(No response)"
                    print(f"\n✅ Final Answer:\n{final_answer}")
                    return final_answer

                # 6. Process each tool call
                # Serialize assistant message, removing null values for Gemini compatibility
                msg_dict = {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments,
                            },
                        }
                        for tc in assistant_message.tool_calls
                    ],
                }
                if assistant_message.content:
                    msg_dict["content"] = assistant_message.content
                messages.append(msg_dict)

                for tool_call in assistant_message.tool_calls:
                    fn_name = tool_call.function.name
                    fn_args = json.loads(tool_call.function.arguments)

                    print(f"   🔨 Calling tool: {fn_name}")
                    print(f"      Args: {json.dumps(fn_args, indent=2)[:200]}")

                    # Execute the tool via MCP
                    try:
                        tool_result = await session.call_tool(fn_name, fn_args)
                        result_text = (
                            tool_result.content[0].text
                            if tool_result.content
                            else "(empty result)"
                        )
                    except Exception as e:
                        result_text = f"Error calling tool {fn_name}: {e}"

                    print(f"      ✓ Result length: {len(result_text)} chars")

                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "content": result_text,
                        }
                    )


# ── CLI Entry Point ────────────────────────────────────────────────────────
async def main():
    print("=" * 60)
    print("  Notion MCP Client — AI ↔ Notion via MCP")
    print("=" * 60)

    if len(sys.argv) > 1:
        query = " ".join(sys.argv[1:])
    else:
        query = input("\n📝 Enter your query: ").strip()
        if not query:
            print("No query provided. Exiting.")
            return

    await run_agent(query)


if __name__ == "__main__":
    asyncio.run(main())
