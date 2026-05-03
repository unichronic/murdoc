"""In-process MCP tool interception helpers."""

import logging

from murdoc.core import MurdocRuntime

try:
    from .adapter import MurdocMCPGateway
except ImportError:
    from adapter import MurdocMCPGateway

logger = logging.getLogger("murdoc.mcp-interceptor")
runtime = MurdocRuntime()


async def secure_call_tool(
    session,
    fn_name: str,
    fn_args: dict,
    context: dict | None = None,
) -> object:
    logger.info("MCP interceptor tool=%s args=%s", fn_name, list(fn_args.keys()))
    return await MurdocMCPGateway(runtime=runtime).call_tool(session, fn_name, fn_args, context)
