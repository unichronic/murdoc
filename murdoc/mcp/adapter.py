"""
Shared MCP adapter for the Murdoc runtime.

The adapter is the protocol boundary between MCP sessions and the shared
Murdoc runtime. It is intentionally independent from any specific MCP
server such as Notion, so both in-process clients and a standalone MCP proxy can
use the same enforcement path.
"""

from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import Any, Callable, Iterable

from murdoc.core import MurdocRuntime

try:
    from .security_config import CONFIG, MCPToolSecurityConfig
except ImportError:
    from murdoc.mcp.security_config import CONFIG, MCPToolSecurityConfig


logger = logging.getLogger("murdoc.mcp-adapter")


class MCPSecurityViolation(Exception):
    """Raised when an MCP request or response is blocked by Murdoc."""

    def __init__(self, layer: str, reason: str, tool_name: str):
        self.layer = layer
        self.reason = reason
        self.tool_name = tool_name
        super().__init__(f"[Murdoc/{layer}] Blocked tool '{tool_name}': {reason}")


@dataclass(frozen=True)
class MCPGatewayContext:
    server_id: str = "default"
    tenant_id: str = "default"
    user_id: str = ""
    request_id: str = ""
    client_id: str = ""
    route_id: str = "mcp-tool"
    app_id: str = "mcp"

    @classmethod
    def from_mapping(cls, data: dict[str, Any] | None = None) -> "MCPGatewayContext":
        data = data or {}
        return cls(
            server_id=str(data.get("server_id") or "default"),
            tenant_id=str(data.get("tenant_id") or "default"),
            user_id=str(data.get("user_id") or ""),
            request_id=str(data.get("request_id") or ""),
            client_id=str(data.get("client_id") or data.get("client") or ""),
            route_id=str(data.get("route_id") or "mcp-tool"),
            app_id=str(data.get("app_id") or "mcp"),
        )

    def to_policy_context(self) -> dict[str, str]:
        return {
            "server_id": self.server_id,
            "tenant_id": self.tenant_id,
            "user_id": self.user_id,
            "client_id": self.client_id,
            "route_id": self.route_id,
            "app_id": self.app_id,
        }


ToolAllowedFn = Callable[[str, str | None], tuple[bool, str]]


class MurdocMCPGateway:
    def __init__(
        self,
        *,
        runtime: MurdocRuntime | None = None,
        tool_config: MCPToolSecurityConfig = CONFIG,
        tool_allowed: ToolAllowedFn | None = None,
    ):
        self.runtime = runtime or MurdocRuntime()
        self.tool_config = tool_config
        self.tool_allowed = tool_allowed or self.tool_config.is_allowed

    def filter_tools(self, tools: Iterable, context: MCPGatewayContext | dict[str, Any] | None = None) -> list:
        ctx = context if isinstance(context, MCPGatewayContext) else MCPGatewayContext.from_mapping(context)
        return [
            tool
            for tool in tools
            if self.tool_allowed(getattr(tool, "name", ""), ctx.server_id)[0]
        ]

    async def authorize_tool_call(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        context: MCPGatewayContext | dict[str, Any] | None = None,
    ):
        ctx = context if isinstance(context, MCPGatewayContext) else MCPGatewayContext.from_mapping(context)
        allowed, reason = self.tool_allowed(tool_name, ctx.server_id)
        if not allowed:
            raise MCPSecurityViolation("mcp_config", reason, tool_name)

        outcome = await self.runtime.authorize_tool_call(
            tool_name,
            tool_args,
            ctx.to_policy_context(),
            request_id=ctx.request_id,
            tenant_id=ctx.tenant_id,
            route_id=ctx.route_id,
            app_id=ctx.app_id,
            user_id=ctx.user_id,
        )
        if outcome.blocked:
            raise MCPSecurityViolation(
                layer=outcome.blocked_layer or "runtime",
                reason=outcome.message or outcome.blocked_reason or "blocked",
                tool_name=tool_name,
            )
        return outcome

    async def inspect_tool_result(
        self,
        tool_name: str,
        result_text: str,
        context: MCPGatewayContext | dict[str, Any] | None = None,
    ) -> str:
        ctx = context if isinstance(context, MCPGatewayContext) else MCPGatewayContext.from_mapping(context)
        if not result_text:
            return result_text

        if hasattr(self.runtime, "inspect_tool_result"):
            outcome = await self.runtime.inspect_tool_result(
                tool_name,
                result_text,
                context=ctx.to_policy_context(),
                request_id=ctx.request_id,
                tenant_id=ctx.tenant_id,
                route_id=ctx.route_id,
                app_id=ctx.app_id,
                user_id=ctx.user_id,
            )
            if outcome.blocked:
                raise MCPSecurityViolation(
                    layer=outcome.blocked_layer or "runtime",
                    reason=outcome.message or outcome.blocked_reason or "blocked_tool_output",
                    tool_name=tool_name,
                )
            sanitized = outcome.payload.get("sanitized_text")
            if isinstance(sanitized, str):
                return sanitized

        scrubbed = await self.runtime.scrub_tool_result(tool_name, result_text)
        if scrubbed != result_text:
            logger.warning("MCP[presidio] tool=%s redacted output", tool_name)
        return scrubbed

    async def call_tool(
        self,
        session,
        tool_name: str,
        tool_args: dict[str, Any],
        context: MCPGatewayContext | dict[str, Any] | None = None,
    ) -> object:
        ctx = context if isinstance(context, MCPGatewayContext) else MCPGatewayContext.from_mapping(context)
        logger.info("MCP[gateway] authorize tool=%s server=%s", tool_name, ctx.server_id)
        await self.authorize_tool_call(tool_name, tool_args, ctx)

        logger.info("MCP[gateway] forward tool=%s server=%s", tool_name, ctx.server_id)
        tool_result = await session.call_tool(tool_name, tool_args)

        if getattr(tool_result, "content", None):
            for content_item in tool_result.content:
                if hasattr(content_item, "text") and content_item.text:
                    content_item.text = await self.inspect_tool_result(tool_name, content_item.text, ctx)

        return tool_result
