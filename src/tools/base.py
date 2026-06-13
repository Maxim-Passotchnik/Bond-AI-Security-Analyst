"""
src/tools/base.py — the uniform interface every Bond investigation tool implements.

Each tool:
  * exposes a JSON `input_schema` so Claude can call it via native tool-use;
  * accepts ONLY the single indicator it needs (data minimization, guardrail #6 —
    the raw alert / PII never leaves Bond);
  * returns a typed `ToolResult`;
  * uses the real API when available, otherwise a deterministic **mock** — so Bond
    always runs end-to-end and gets richer as API keys are added.

`run()` is the orchestrator: try real → on any failure fall back to mock (tagged
with the error), so a flaky provider degrades gracefully instead of crashing the loop.
Set `BOND_FORCE_MOCK=1` to force every tool onto its mock (used by tests and for
fully-deterministic demos).
"""
from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..models import Disposition


@dataclass
class ToolResult:
    """One tool observation. Maps cleanly onto an `Evidence` row in the loop."""
    tool: str
    query: str
    disposition: Disposition
    summary: str
    source: str = ""
    is_mock: bool = False
    raw: dict[str, Any] = field(default_factory=dict)


def _force_mock() -> bool:
    return os.getenv("BOND_FORCE_MOCK", "").strip().lower() not in ("", "0", "false")


class Tool(ABC):
    """Base class for investigation tools."""

    name: str = ""
    description: str = ""
    arg: str = "value"                       # the single indicator property name
    arg_description: str = "The indicator to look up"
    # Provider API keys; real mode needs ANY one of them. Empty => no key required.
    env_keys: tuple[str, ...] = ()

    # ----- Claude tool-use definition ----- #
    @property
    def input_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {self.arg: {"type": "string", "description": self.arg_description}},
            "required": [self.arg],
            "additionalProperties": False,    # data minimization: nothing but the indicator
        }

    def definition(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "input_schema": self.input_schema}

    # ----- real-or-mock orchestration ----- #
    def available(self) -> bool:
        """Real provider usable? False if forced to mock; a no-key tool is always
        attempted; a keyed tool needs *any* of its provider keys present."""
        if _force_mock():
            return False
        if not self.env_keys:
            return True
        return any(os.getenv(k) for k in self.env_keys)

    def run(self, **kwargs: Any) -> ToolResult:
        value = (kwargs.get(self.arg) or "").strip()
        if self.available():
            try:
                return self._run_real(value)
            except Exception as exc:  # noqa: BLE001 — degrade to mock, never crash the loop
                res = self._mock(value)
                res.raw = {**res.raw, "_real_error": str(exc)}
                return res
        return self._mock(value)

    @abstractmethod
    def _run_real(self, value: str) -> ToolResult: ...

    @abstractmethod
    def _mock(self, value: str) -> ToolResult: ...
