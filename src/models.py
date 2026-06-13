"""
Core data models for Bond — the AI Security Analyst.

These types define the contract that flows through the whole system:

    raw alert (JSON)  ->  Alert  ->  [IOCs]  ->  InvestigationState
                                                       |
                                                 (agent loop adds Evidence)
                                                       v
                                              InvestigationReport  ->  JSON / Markdown

Everything is plain dataclasses + enums so it serializes cleanly to JSON and
is trivial to reason about. No framework magic.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


# --------------------------------------------------------------------------- #
#  Enums
# --------------------------------------------------------------------------- #
class AlertType(str, Enum):
    """The kind of detection that triggered the investigation."""
    EDR_MALWARE = "edr_malware"            # flagship scenario
    SUSPICIOUS_LOGIN = "suspicious_login"  # identity / SIEM
    PHISHING_EMAIL = "phishing_email"
    WAF_BLOCK = "waf_block"
    GENERIC = "generic"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IOCType(str, Enum):
    """Indicator-of-compromise categories Bond knows how to investigate."""
    FILE_HASH = "file_hash"   # md5 / sha1 / sha256
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    HOSTNAME = "hostname"
    USERNAME = "username"
    FILE_PATH = "file_path"
    PROCESS = "process"


class Confidence(str, Enum):
    """Confidence in the overall investigation conclusion."""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class Action(str, Enum):
    """The terminal decision Bond must reach."""
    AUTO_CLOSE = "AUTO_CLOSE"   # benign / false positive — close without a human
    ESCALATE = "ESCALATE"       # hand to a human analyst with this report


class Disposition(str, Enum):
    """Verdict on a single piece of evidence or IOC."""
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"


class FindingSeverity(str, Enum):
    """Severity of a guardrail observation."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


# --------------------------------------------------------------------------- #
#  Helpers
# --------------------------------------------------------------------------- #
def _now() -> str:
    """UTC ISO-8601 timestamp."""
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
#  Indicators of Compromise
# --------------------------------------------------------------------------- #
@dataclass
class IOC:
    """A single indicator extracted from the alert (or discovered en route)."""
    type: IOCType
    value: str
    # free-form note on where/how this IOC showed up (e.g. "parent process")
    context: str = ""

    def key(self) -> str:
        return f"{self.type.value}:{self.value.lower()}"


# --------------------------------------------------------------------------- #
#  The alert (normalized input)
# --------------------------------------------------------------------------- #
@dataclass
class Alert:
    """Normalized representation of an incoming security alert."""
    id: str
    type: AlertType
    severity: Severity
    title: str
    description: str
    source_system: str                       # theoretical originating system
    detected_at: str                          # ISO timestamp from the source
    # Host / identity context the source system shipped with the alert
    entities: dict[str, Any] = field(default_factory=dict)
    # The original, untouched alert payload — preserved for the report
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Alert":
        return cls(
            id=data["id"],
            type=AlertType(data.get("type", AlertType.GENERIC.value)),
            severity=Severity(data.get("severity", Severity.MEDIUM.value)),
            title=data.get("title", ""),
            description=data.get("description", ""),
            source_system=data.get("source_system", "unknown"),
            detected_at=data.get("detected_at", _now()),
            entities=data.get("entities", {}),
            raw=data,
        )


# --------------------------------------------------------------------------- #
#  Evidence (one tool result)
# --------------------------------------------------------------------------- #
@dataclass
class Evidence:
    """
    A single observation produced by a tool call during the investigation.
    The accumulating list of these *is* the investigation's audit trail.
    """
    tool: str                                  # tool name that produced it
    query: str                                 # what was asked (e.g. the hash)
    summary: str                               # short human-readable finding
    disposition: Disposition = Disposition.UNKNOWN
    source: str = ""                           # citable source (URL / provider)
    is_mock: bool = False                      # was this from a mock fallback?
    raw: dict[str, Any] = field(default_factory=dict)
    observed_at: str = field(default_factory=_now)


# --------------------------------------------------------------------------- #
#  Guardrail finding (one trust-boundary observation)
# --------------------------------------------------------------------------- #
@dataclass
class GuardrailFinding:
    """
    A single observation from a guardrail (see ARCHITECTURE.md §5 and
    `src/guardrails.py`). When `forces_escalation` is True it hard-overrides the
    final verdict to ESCALATE — Bond fails safe, never open.
    """
    guardrail: str                              # "ingress" | "indicator_safety" | "output" | "decision"
    field: str                                  # where, e.g. "file.name", "tool:whois"
    message: str
    severity: FindingSeverity = FindingSeverity.WARNING
    forces_escalation: bool = False
    observed_at: str = field(default_factory=_now)


# --------------------------------------------------------------------------- #
#  Investigation state (mutable, lives for the duration of the loop)
# --------------------------------------------------------------------------- #
@dataclass
class InvestigationState:
    """
    Carries everything the agent loop needs and accumulates.
    Passed by reference through the loop; the tool dispatcher appends Evidence,
    the reasoner reads it back on the next turn.
    """
    alert: Alert
    iocs: list[IOC] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    guardrail_findings: list[GuardrailFinding] = field(default_factory=list)
    step: int = 0                              # reasoning steps consumed
    started_at: str = field(default_factory=_now)

    def add_ioc(self, ioc: IOC) -> None:
        """Add an IOC, de-duplicating on (type, value)."""
        if ioc.key() not in {i.key() for i in self.iocs}:
            self.iocs.append(ioc)

    def add_evidence(self, ev: Evidence) -> None:
        self.evidence.append(ev)

    def add_guardrail_findings(self, findings: list[GuardrailFinding]) -> None:
        self.guardrail_findings.extend(findings)

    def has_blocking_finding(self) -> bool:
        """True if any guardrail finding forces escalation (fail-safe trigger)."""
        return any(f.forces_escalation for f in self.guardrail_findings)

    def sources(self) -> list[str]:
        """Unique, ordered list of *citable* sources (mock:// fallbacks excluded —
        they're a degradation artifact, not a real source; the evidence trail still
        records each tool's `is_mock` flag for transparency)."""
        seen: list[str] = []
        for ev in self.evidence:
            s = ev.source
            if s and not s.startswith("mock://") and s not in seen:
                seen.append(s)
        return seen


# --------------------------------------------------------------------------- #
#  Final structured report (the deliverable)
# --------------------------------------------------------------------------- #
@dataclass
class InvestigationReport:
    """
    The structured output Bond produces. Fields map directly to the
    assignment's required report fields:
        - findings_summary  -> "Findings Summary"
        - confidence        -> "Confidence Level"
        - sources           -> "Sources"
        - next_steps        -> "Next Steps"
    plus the action taken and the full evidence trail / rationale.
    """
    alert_id: str
    alert_title: str
    action: Action
    confidence: Confidence
    findings_summary: str
    rationale: str
    sources: list[str]
    next_steps: list[str]
    iocs: list[IOC]
    evidence: list[Evidence]
    steps_taken: int
    # original-alert context (for the report's "Alert" section)
    alert_type: str = ""
    alert_severity: str = ""
    alert_source: str = ""
    alert_description: str = ""
    generated_at: str = field(default_factory=_now)

    # ----- serialization ----- #
    def to_dict(self) -> dict[str, Any]:
        """JSON-ready dict (enums collapsed to their string values)."""
        def encode(obj: Any) -> Any:
            if isinstance(obj, Enum):
                return obj.value
            if isinstance(obj, list):
                return [encode(x) for x in obj]
            if isinstance(obj, dict):
                return {k: encode(v) for k, v in obj.items()}
            return obj

        return encode(asdict(self))

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)
