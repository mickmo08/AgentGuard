"""MCP front door: expose AgentGuard-brokered actions as MCP tools.

Any MCP-capable agent (Claude Desktop, Claude Code, IDE agents, custom
clients) can use AgentGuard with no code changes. The MCP server runs next to
the agent over stdio and holds only the agent's AgentGuard key; every tool
call becomes a policy-checked action request.

    AGENTGUARD_URL=https://agentguard.example.com AGENTGUARD_KEY=ag_... agentguard mcp

Claude Code:   claude mcp add agentguard --env AGENTGUARD_URL=... --env AGENTGUARD_KEY=... -- agentguard mcp
"""
from __future__ import annotations

import json
import os
from typing import Any

import anyio
from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from agentguard.sdk.client import AgentGuard

INSTRUCTIONS = (
    "These tools act on real business systems through a policy gateway. A result with status "
    "'pending_approval' means a person must approve it first: tell the user it is awaiting review rather "
    "than retrying. A 'blocked' result is final: do not try to achieve the same effect another way."
)


def tool_name(action: str) -> str:
    return action.replace(".", "__")


def build_server(guard: AgentGuard, wait_for_approval: bool = False) -> Server:
    names: dict[str, str] = {}

    async def list_tools(ctx: Any, params: Any) -> types.ListToolsResult:
        catalog = await anyio.to_thread.run_sync(guard.tools)
        names.clear()
        tools = []
        for t in catalog:
            names[tool_name(t["name"])] = t["name"]
            tools.append(types.Tool(name=tool_name(t["name"]), title=t["name"], description=t["description"] or t["name"], inputSchema=t["input_schema"]))
        return types.ListToolsResult(tools=tools)

    async def call_tool(ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
        if not names:
            await list_tools(ctx, None)
        action = names.get(params.name)
        if action is None:
            return types.CallToolResult(content=[types.TextContent(type="text", text=f"unknown tool {params.name}")], isError=True)
        handler = guard.handler(action, wait=wait_for_approval)
        outcome = await anyio.to_thread.run_sync(lambda: handler(**(params.arguments or {})))
        is_error = not outcome["ok"] and outcome["status"] != "pending_approval"
        return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(outcome, default=str))], isError=is_error)

    return Server("agentguard", version="0.2.0", instructions=INSTRUCTIONS, on_list_tools=list_tools, on_call_tool=call_tool)


async def serve_stdio(url: str, key: str, wait_for_approval: bool = False) -> None:
    guard = AgentGuard(url, key)
    server = build_server(guard, wait_for_approval)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main() -> None:
    url = os.environ.get("AGENTGUARD_URL", "http://127.0.0.1:8080")
    key = os.environ.get("AGENTGUARD_KEY")
    if not key:
        raise SystemExit("AGENTGUARD_KEY is required (the agent's key from the AgentGuard dashboard)")
    anyio.run(serve_stdio, url, key, os.environ.get("AGENTGUARD_MCP_WAIT", "").lower() in ("1", "true"))


if __name__ == "__main__":
    main()
