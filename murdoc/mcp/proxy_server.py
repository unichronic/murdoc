"""
Standalone Murdoc MCP proxy.

This process presents an MCP server to upstream clients and forwards allowed
tool traffic to a configured downstream MCP server through the shared Murdoc
MCP adapter.
"""

from __future__ import annotations

from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass, field
import os
import shlex
import sys
from typing import AsyncIterator, Callable

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server import Server
from mcp.server.stdio import stdio_server

try:
    from .adapter import MurdocMCPGateway, MCPGatewayContext
except ImportError:
    from adapter import MurdocMCPGateway, MCPGatewayContext


SessionFactory = Callable[[], AsyncIterator[ClientSession]]


@dataclass(frozen=True)
class DownstreamStdioConfig:
    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_env(cls) -> "DownstreamStdioConfig":
        command = os.getenv("MCP_DOWNSTREAM_COMMAND", "").strip()
        if not command:
            raise RuntimeError("MCP_DOWNSTREAM_COMMAND is required for standalone MCP proxy mode")
        args = shlex.split(os.getenv("MCP_DOWNSTREAM_ARGS", ""))
        env = dict(os.environ)
        return cls(command=command, args=args, env=env)


@asynccontextmanager
async def downstream_stdio_session(config: DownstreamStdioConfig) -> AsyncIterator[ClientSession]:
    params = StdioServerParameters(command=config.command, args=config.args, env=config.env)
    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            yield session


class MurdocMCPProxy:
    def __init__(
        self,
        *,
        session_factory: SessionFactory,
        adapter: MurdocMCPGateway | None = None,
        server_id: str | None = None,
        tenant_id: str | None = None,
        user_id: str | None = None,
        client_id: str = "mcp-proxy",
    ):
        self.session_factory = session_factory
        self.adapter = adapter or MurdocMCPGateway()
        self.server_id = server_id or os.getenv("MCP_SERVER_ID", "default")
        self.tenant_id = tenant_id or os.getenv("MCP_TENANT_ID", "default")
        self.user_id = user_id or os.getenv("MCP_USER_ID", "")
        self.client_id = client_id
        self._exit_stack: AsyncExitStack | None = None
        self._session: ClientSession | None = None

    async def __aenter__(self) -> "MurdocMCPProxy":
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        await self.stop()
        return False

    async def start(self) -> None:
        if self._session is not None:
            return
        self._exit_stack = AsyncExitStack()
        self._session = await self._exit_stack.enter_async_context(self.session_factory())

    async def stop(self) -> None:
        if self._exit_stack is not None:
            await self._exit_stack.aclose()
        self._exit_stack = None
        self._session = None

    @asynccontextmanager
    async def _session_scope(self) -> AsyncIterator[ClientSession]:
        if self._session is not None:
            yield self._session
            return
        async with self.session_factory() as session:
            yield session

    def context(self, request_id: str = "") -> MCPGatewayContext:
        return MCPGatewayContext(
            server_id=self.server_id,
            tenant_id=self.tenant_id,
            user_id=self.user_id,
            request_id=request_id,
            client_id=self.client_id,
        )

    async def list_tools(self):
        async with self._session_scope() as session:
            tools_result = await session.list_tools()
            return self.adapter.filter_tools(tools_result.tools, self.context("mcp-list-tools"))

    async def call_tool(self, name: str, arguments: dict):
        async with self._session_scope() as session:
            return await self.adapter.call_tool(
                session,
                name,
                arguments or {},
                self.context(f"mcp-tool-{name}"),
            )


def create_mcp_proxy_server(proxy: MurdocMCPProxy) -> Server:
    server = Server("murdoc-mcp-gateway")

    @server.list_tools()
    async def list_tools():
        return await proxy.list_tools()

    @server.call_tool(validate_input=True)
    async def call_tool(name: str, arguments: dict):
        return await proxy.call_tool(name, arguments)

    return server


async def run_stdio_proxy(proxy: MurdocMCPProxy) -> None:
    server = create_mcp_proxy_server(proxy)
    async with proxy:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options(),
            )


def main() -> None:
    import anyio

    try:
        config = DownstreamStdioConfig.from_env()
    except RuntimeError as exc:
        print(f"Murdoc MCP proxy configuration error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc

    @asynccontextmanager
    async def factory():
        async with downstream_stdio_session(config) as session:
            yield session

    proxy = MurdocMCPProxy(session_factory=factory, server_id=os.getenv("MCP_SERVER_ID", "default"))
    anyio.run(run_stdio_proxy, proxy)


if __name__ == "__main__":
    main()
