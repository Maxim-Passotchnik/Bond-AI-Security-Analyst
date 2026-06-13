"""
src/report.py — render an InvestigationReport as human-readable Markdown.

(JSON rendering already lives on the model: `InvestigationReport.to_json()`.)
The Markdown mirrors the assignment's required fields — Findings Summary,
Confidence Level, Sources, Next Steps — plus the original alert, the per-tool
evidence trail, and the rationale.
"""
from __future__ import annotations

from .models import Action, Confidence, InvestigationReport

_ACTION_BADGE = {
    Action.AUTO_CLOSE: "🟢 AUTO-CLOSE",
    Action.ESCALATE: "🔴 ESCALATE",
}
_CONFIDENCE_BADGE = {
    Confidence.HIGH: "High",
    Confidence.MEDIUM: "Medium",
    Confidence.LOW: "Low",
}


def render_markdown(report: InvestigationReport) -> str:
    r = report
    lines: list[str] = []

    lines.append(f"# 🕵️ Bond Investigation Report — `{r.alert_id}`")
    lines.append("")
    lines.append(f"**Decision:** {_ACTION_BADGE.get(r.action, r.action.value)}  ·  "
                 f"**Confidence:** {_CONFIDENCE_BADGE.get(r.confidence, r.confidence.value)}  ·  "
                 f"**Steps:** {r.steps_taken}")
    lines.append("")
    if r.alert_title:
        lines.append(f"> {r.alert_title}")
        lines.append("")

    # Original alert context
    meta = [x for x in (
        f"**Type:** {r.alert_type}" if r.alert_type else "",
        f"**Severity:** {r.alert_severity}" if r.alert_severity else "",
        f"**Source:** {r.alert_source}" if r.alert_source else "",
    ) if x]
    if meta or r.alert_description:
        lines.append("## Original Alert")
        if meta:
            lines.append("  ·  ".join(meta))
            lines.append("")
        if r.alert_description:
            lines.append(r.alert_description)
            lines.append("")

    lines.append("## Findings Summary")
    lines.append(r.findings_summary or "_(none)_")
    lines.append("")

    lines.append("## Rationale")
    lines.append(r.rationale or "_(none)_")
    lines.append("")

    lines.append("## Indicators investigated")
    if r.iocs:
        lines.append("| Type | Value | Context |")
        lines.append("|---|---|---|")
        for i in r.iocs:
            lines.append(f"| {i.type.value} | `{i.value}` | {i.context or ''} |")
    else:
        lines.append("_(none extracted)_")
    lines.append("")

    lines.append("## Evidence trail")
    if r.evidence:
        lines.append("| Tool | Query | Disposition | Source | Mock? | Finding |")
        lines.append("|---|---|---|---|---|---|")
        for e in r.evidence:
            lines.append(
                f"| {e.tool} | `{e.query}` | {e.disposition.value} | {e.source} | "
                f"{'yes' if e.is_mock else 'no'} | {e.summary} |"
            )
    else:
        lines.append("_(no tool evidence gathered)_")
    lines.append("")

    lines.append("## Sources")
    if r.sources:
        for s in r.sources:
            lines.append(f"- {s}")
    else:
        lines.append("_(none)_")
    lines.append("")

    lines.append("## Next Steps")
    if r.next_steps:
        for s in r.next_steps:
            lines.append(f"- {s}")
    else:
        lines.append("_(none)_")
    lines.append("")

    lines.append("---")
    lines.append(f"_Generated {r.generated_at}_")
    return "\n".join(lines)
