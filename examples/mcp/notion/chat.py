"""Interactive Notion MCP demo client."""

import asyncio
import json
import os
import shutil
import sys
import uuid

from dotenv import load_dotenv
from openai import OpenAI
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from mcp_gateway.mcp_interceptor import secure_call_tool
from mcp_gateway.security_config import filter_allowed_tools

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
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")


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


async def process_query(
    session: ClientSession,
    client: OpenAI,
    openai_tools: list[dict],
    messages: list[dict],
    user_query: str,
) -> str:
    """Process a single user query through the AI + MCP tool loop."""

    messages.append({"role": "user", "content": user_query})

    while True:
        response = client.chat.completions.create(
            model=GEMINI_MODEL,
            messages=messages,
            tools=openai_tools if openai_tools else None,
        )

        choice = response.choices[0]
        assistant_message = choice.message

        if not assistant_message.tool_calls:
            final = assistant_message.content or "(No response)"
            messages.append({"role": "assistant", "content": final})
            return final

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
            print(f"   {fn_name}({json.dumps(fn_args)[:120]}...)")

            try:
                result = await secure_call_tool(
                    session,
                    fn_name,
                    fn_args,
                    context={
                        "client": "chat_app",
                        "server_id": "notion",
                        "request_id": f"mcp-chat-{uuid.uuid4().hex}",
                        "tenant_id": os.getenv("MCP_TENANT_ID", "default"),
                        "user_id": os.getenv("MCP_USER_ID", ""),
                    },
                )
                result_text = (
                    result.content[0].text if result.content else "(empty)"
                )
            except Exception as e:
                result_text = f"Error: {e}"

            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": result_text,
                }
            )


async def main():
    if not NOTION_TOKEN:
        sys.exit("ERROR: NOTION_TOKEN not set in .env")
    if not GEMINI_API_KEY:
        sys.exit("ERROR: GEMINI_API_KEY not set in .env")

    npx_path, node_bin_dir = find_npx()
    env = {**os.environ, "NOTION_TOKEN": NOTION_TOKEN}
    env["PATH"] = node_bin_dir + os.pathsep + env.get("PATH", "")

    server_params = StdioServerParameters(
        command=npx_path,
        args=["-y", "@notionhq/notion-mcp-server"],
        env=env,
    )

    print("=" * 60)
    print("  Notion MCP Chat - Interactive AI to Notion")
    print("  Type 'quit' or 'exit' to stop")
    print("=" * 60)
    print("\nStarting Notion MCP server...")

    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()

            tools_result = await session.list_tools()
            discovered_tools = tools_result.tools
            mcp_tools = filter_allowed_tools(discovered_tools, server_id="notion")
            openai_tools = mcp_tools_to_openai_tools(mcp_tools)

            hidden_count = len(discovered_tools) - len(mcp_tools)
            print(f"Connected. {len(mcp_tools)} tools available after security filtering.")
            if hidden_count:
                print(f"   {hidden_count} tool(s) hidden by MCP security config.")
            print()

            client = OpenAI(
                api_key=GEMINI_API_KEY,
                base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
            )
            messages = [
                {
                    "role": "system",
                    "content": (
                        "You are a helpful assistant connected to the user's "
                        "Notion workspace. Use the available tools to search, "
                        "read, create, and update Notion pages and databases. "
                        "Always search before trying to access specific content."
                    ),
                }
            ]

            while True:
                try:
                    query = input("\nYou: ").strip()
                except (EOFError, KeyboardInterrupt):
                    print("\nGoodbye.")
                    break

                if not query:
                    continue
                if query.lower() in ("quit", "exit", "q"):
                    print("Goodbye.")
                    break

                answer = await process_query(
                    session, client, openai_tools, messages, query
                )
                print(f"\nAssistant: {answer}")


if __name__ == "__main__":
    asyncio.run(main())
