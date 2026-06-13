"""
Bond investigation tools — registry + dispatch.

Tools are exposed to Claude via `tool_definitions()` and invoked by name via
`dispatch()`. Each is real-or-mock (see `base.Tool`). The agent loop (PR #4)
wraps `dispatch()` with the guardrail hooks (indicator safety before, output
sanitization after).
"""
from __future__ import annotations

from .base import Tool, ToolResult
from .network import DnsTool, GeoIpTool, WhoisTool
from .reputation import DomainReputationTool, HashReputationTool, IpReputationTool
from .search import WebSearchTool

# One instance per tool, keyed by name.
ALL_TOOLS: dict[str, Tool] = {
    t.name: t for t in (
        HashReputationTool(),
        IpReputationTool(),
        DomainReputationTool(),
        WhoisTool(),
        DnsTool(),
        GeoIpTool(),
        WebSearchTool(),
    )
}


def tool_definitions() -> list[dict]:
    """Claude tool-use definitions for every registered tool."""
    return [t.definition() for t in ALL_TOOLS.values()]


def dispatch(name: str, tool_input: dict) -> ToolResult:
    """Route a `tool_use` call to its tool. Raises KeyError on unknown tool."""
    if name not in ALL_TOOLS:
        raise KeyError(f"unknown tool: {name!r}")
    return ALL_TOOLS[name].run(**tool_input)


__all__ = ["ALL_TOOLS", "Tool", "ToolResult", "tool_definitions", "dispatch"]
