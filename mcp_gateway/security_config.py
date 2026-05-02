"""
MCP gateway security configuration.

This module keeps MCP tool filtering cheap on the request path by parsing
environment configuration once at import time. The interceptor still sends
per-call content through Bifrost for semantic and policy decisions.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
import re
from typing import Iterable


WRITE_TOOL_RE = re.compile(
    r"(^|[_\-.])(append|archive|create|delete|drop|insert|patch|publish|remove|send|share|update|write)([_\-.]|$)",
    re.IGNORECASE,
)


def _csv_set(name: str) -> set[str]:
    return {item.strip().lower() for item in os.getenv(name, "").split(",") if item.strip()}


def _qualified_names(server_id: str, tool_name: str) -> set[str]:
    server = (server_id or "default").strip().lower()
    tool = (tool_name or "").strip().lower()
    return {tool, f"{server}:{tool}"}


@dataclass(frozen=True)
class MCPToolSecurityConfig:
    server_id: str
    allowed_tools: frozenset[str]
    blocked_tools: frozenset[str]
    enforce_allowlist: bool
    read_only_mode: bool

    @classmethod
    def from_env(cls) -> "MCPToolSecurityConfig":
        return cls(
            server_id=os.getenv("MCP_SERVER_ID", "notion").strip() or "notion",
            allowed_tools=frozenset(_csv_set("MCP_ALLOWED_TOOLS")),
            blocked_tools=frozenset(_csv_set("MCP_BLOCKED_TOOLS")),
            enforce_allowlist=os.getenv("MCP_ENFORCE_TOOL_ALLOWLIST", "false").lower() == "true",
            read_only_mode=os.getenv("MCP_READ_ONLY_MODE", "false").lower() == "true",
        )

    def is_allowed(self, tool_name: str, server_id: str | None = None) -> tuple[bool, str]:
        names = _qualified_names(server_id or self.server_id, tool_name)
        if names & self.blocked_tools:
            return False, "blocked_by_mcp_tool_blocklist"
        if self.read_only_mode and WRITE_TOOL_RE.search(tool_name or ""):
            return False, "blocked_by_mcp_read_only_mode"
        if self.enforce_allowlist and not names & self.allowed_tools:
            return False, "blocked_by_mcp_tool_allowlist"
        return True, "allowed"


CONFIG = MCPToolSecurityConfig.from_env()


def is_tool_allowed(tool_name: str, server_id: str | None = None) -> tuple[bool, str]:
    return CONFIG.is_allowed(tool_name, server_id=server_id)


def filter_allowed_tools(tools: Iterable, server_id: str | None = None) -> list:
    return [tool for tool in tools if is_tool_allowed(getattr(tool, "name", ""), server_id=server_id)[0]]
