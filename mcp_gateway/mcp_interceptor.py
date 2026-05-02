"""
mcp_gateway/mcp_interceptor.py
==============================
AgentVault MCP Security Interceptor

ARGUS-style hook that wraps the MCP `session.call_tool()` method with security
checks BEFORE and AFTER the Notion (or any MCP server) database is touched.
"""

import logging
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bifrost_gateway import BifrostGateway
try:
    from .adapter import BifrostMCPGateway, MCPSecurityViolation
except ImportError:
    from adapter import BifrostMCPGateway, MCPSecurityViolation

logger = logging.getLogger("agentvault.mcp-interceptor")
bifrost = BifrostGateway()


async def secure_call_tool(
    session,
    fn_name: str,
    fn_args: dict,
    context: dict | None = None,
) -> object:
    logger.info("MCP interceptor: %s(%s)", fn_name, list(fn_args.keys()))
    return await BifrostMCPGateway(bifrost=bifrost).call_tool(session, fn_name, fn_args, context)
