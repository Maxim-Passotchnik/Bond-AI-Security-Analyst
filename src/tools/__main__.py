"""
Standalone tool runner — exercise a single investigation tool without the agent.

    python -m src.tools --list
    python -m src.tools hash_reputation 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
    BOND_FORCE_MOCK=1 python -m src.tools ip_reputation 185.220.101.47
"""
from __future__ import annotations

import json
import sys

from . import ALL_TOOLS, dispatch


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help", "--list"):
        print("Available tools:\n")
        for name, t in ALL_TOOLS.items():
            print(f"  {name:18} <{t.arg}>  — {t.description.splitlines()[0]}")
        print("\nUsage: python -m src.tools <tool_name> <indicator>")
        return 0

    name, *rest = argv
    if name not in ALL_TOOLS:
        print(f"unknown tool: {name!r} (try --list)")
        return 1
    if not rest:
        print(f"usage: python -m src.tools {name} <{ALL_TOOLS[name].arg}>")
        return 1

    res = dispatch(name, {ALL_TOOLS[name].arg: rest[0]})
    print(json.dumps({
        "tool": res.tool,
        "query": res.query,
        "disposition": res.disposition.value,
        "summary": res.summary,
        "source": res.source,
        "is_mock": res.is_mock,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
