"""Offline tests for the Markdown renderer and the CLI guard rails."""
import pytest

from src.main import main
from src.models import (
    Action,
    Confidence,
    Disposition,
    Evidence,
    IOC,
    IOCType,
    InvestigationReport,
)
from src.report import render_markdown


def _sample_report() -> InvestigationReport:
    return InvestigationReport(
        alert_id="EDR-2026-04127",
        alert_title="Malicious executable detected and quarantined",
        action=Action.ESCALATE,
        confidence=Confidence.HIGH,
        findings_summary="Known malware hash detected, contacting C2 infrastructure.",
        rationale="VirusTotal flagged the hash; the contacted domain is a known C2.",
        sources=["https://www.virustotal.com", "https://otx.alienvault.com"],
        next_steps=["Isolate FIN-WKS-0473", "Reset j.harlow credentials"],
        iocs=[IOC(IOCType.FILE_HASH, "275a021b", "file.sha256"),
              IOC(IOCType.DOMAIN, "secure-doc-update.ru", "network.contacted_domain")],
        evidence=[Evidence(tool="hash_reputation", query="275a021b", summary="flagged by 60 engines",
                           disposition=Disposition.MALICIOUS, source="https://www.virustotal.com")],
        steps_taken=3,
    )


def test_markdown_contains_required_sections():
    md = render_markdown(_sample_report())
    for heading in ("Findings Summary", "Rationale", "Indicators investigated",
                    "Evidence trail", "Sources", "Next Steps"):
        assert f"## {heading}" in md


def test_markdown_shows_decision_and_evidence():
    md = render_markdown(_sample_report())
    assert "ESCALATE" in md
    assert "High" in md
    assert "secure-doc-update.ru" in md          # an IOC
    assert "hash_reputation" in md               # the evidence row
    assert "https://www.virustotal.com" in md    # a source
    assert "Isolate FIN-WKS-0473" in md          # a next step


def test_markdown_handles_empty_lists():
    r = InvestigationReport(
        alert_id="X", alert_title="", action=Action.AUTO_CLOSE, confidence=Confidence.LOW,
        findings_summary="", rationale="", sources=[], next_steps=[], iocs=[], evidence=[],
        steps_taken=0,
    )
    md = render_markdown(r)                       # must not raise
    assert "AUTO-CLOSE" in md


# --------------------------------------------------------------------------- #
#  CLI guards (offline — no real run)
# --------------------------------------------------------------------------- #
def test_cli_requires_api_key(monkeypatch):
    # Empty (not deleted): load_dotenv(override=False) won't repopulate it from .env,
    # so this is robust whether or not .env / python-dotenv are present.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "")
    rc = main(["--alert", "alerts/edr_malware_malicious.json"])
    assert rc == 2


def test_cli_missing_alert_file(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    rc = main(["--alert", "alerts/does_not_exist.json"])
    assert rc == 2
