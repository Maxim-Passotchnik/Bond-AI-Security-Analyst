"""
Reputation tools — file-hash, IP, and domain reputation.

Real providers (used when their key is set, else mock):
  * Hash   — VirusTotal, then abuse.ch MalwareBazaar
  * IP     — AbuseIPDB
  * Domain — AlienVault OTX
"""
from __future__ import annotations

import os

from ..models import Disposition
from ._mockdata import mock_disposition
from .base import Tool, ToolResult


class HashReputationTool(Tool):
    name = "hash_reputation"
    description = (
        "Look up the reputation of a file hash (MD5/SHA-1/SHA-256) against malware "
        "intelligence (VirusTotal, MalwareBazaar). Use for EDR file detections."
    )
    arg = "file_hash"
    arg_description = "The file hash to look up (md5, sha1, or sha256)"
    env_keys = ("VIRUSTOTAL_API_KEY", "ABUSECH_AUTH_KEY")

    def _run_real(self, value: str) -> ToolResult:
        import requests

        vt_key = os.getenv("VIRUSTOTAL_API_KEY")
        if vt_key:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/files/{value}",
                headers={"x-apikey": vt_key}, timeout=15,
            )
            if r.status_code == 404:
                return ToolResult(self.name, value, Disposition.UNKNOWN,
                                  "Hash not found in VirusTotal",
                                  "https://www.virustotal.com", False, {"status": 404})
            r.raise_for_status()
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            mal = int(stats.get("malicious", 0))
            disp = Disposition.MALICIOUS if mal else Disposition.BENIGN
            return ToolResult(self.name, value, disp,
                              f"VirusTotal: {mal} engines flagged this file malicious",
                              f"https://www.virustotal.com/gui/file/{value}", False, {"stats": stats})

        # MalwareBazaar fallback
        r = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": value},
            headers={"Auth-Key": os.environ["ABUSECH_AUTH_KEY"]}, timeout=15,
        )
        r.raise_for_status()
        data = r.json()
        if data.get("query_status") == "ok":
            return ToolResult(self.name, value, Disposition.MALICIOUS,
                              "Hash listed in abuse.ch MalwareBazaar",
                              "https://bazaar.abuse.ch", False, data)
        return ToolResult(self.name, value, Disposition.UNKNOWN,
                          "Hash not found in MalwareBazaar", "https://bazaar.abuse.ch", False, data)

    def _mock(self, value: str) -> ToolResult:
        disp = mock_disposition(value)
        summary = {
            Disposition.MALICIOUS: "Hash matches a known malware sample (mock intel)",
            Disposition.BENIGN: "Hash matches known-good software (mock intel)",
        }.get(disp, "Hash not present in mock intel — unknown")
        return ToolResult(self.name, value, disp, summary, "mock://hash-reputation", True)


class IpReputationTool(Tool):
    name = "ip_reputation"
    description = (
        "Look up the abuse/reputation of an IPv4/IPv6 address (AbuseIPDB). "
        "Use for suspicious source/destination IPs."
    )
    arg = "ip"
    arg_description = "The IP address to look up"
    env_keys = ("ABUSEIPDB_API_KEY",)

    def _run_real(self, value: str) -> ToolResult:
        import requests

        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": os.environ["ABUSEIPDB_API_KEY"], "Accept": "application/json"},
            params={"ipAddress": value, "maxAgeInDays": 90}, timeout=15,
        )
        r.raise_for_status()
        data = r.json()["data"]
        score = int(data.get("abuseConfidenceScore", 0))
        disp = (Disposition.MALICIOUS if score >= 50
                else Disposition.SUSPICIOUS if score >= 15
                else Disposition.BENIGN)
        return ToolResult(self.name, value, disp,
                          f"AbuseIPDB confidence score {score}/100 "
                          f"({data.get('totalReports', 0)} reports)",
                          "https://www.abuseipdb.com", False, data)

    def _mock(self, value: str) -> ToolResult:
        disp = mock_disposition(value)
        summary = {
            Disposition.MALICIOUS: "IP reported for malicious activity (mock intel)",
            Disposition.SUSPICIOUS: "IP belongs to a hosting/VPN ASN — elevated risk (mock intel)",
            Disposition.BENIGN: "IP has a clean reputation (mock intel)",
        }.get(disp, "IP not present in mock intel — unknown")
        return ToolResult(self.name, value, disp, summary, "mock://ip-reputation", True)


class DomainReputationTool(Tool):
    name = "domain_reputation"
    description = (
        "Look up threat-intelligence on a domain (AlienVault OTX pulses). "
        "Use for contacted/sender domains and URLs."
    )
    arg = "domain"
    arg_description = "The domain to look up"
    env_keys = ("OTX_API_KEY",)

    def _run_real(self, value: str) -> ToolResult:
        import requests

        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{value}/general",
            headers={"X-OTX-API-KEY": os.environ["OTX_API_KEY"]}, timeout=15,
        )
        r.raise_for_status()
        data = r.json()
        pulses = int(data.get("pulse_info", {}).get("count", 0))
        disp = Disposition.MALICIOUS if pulses else Disposition.UNKNOWN
        return ToolResult(self.name, value, disp,
                          f"OTX: domain appears in {pulses} threat-intel pulse(s)",
                          "https://otx.alienvault.com", False, {"pulse_count": pulses})

    def _mock(self, value: str) -> ToolResult:
        disp = mock_disposition(value)
        summary = {
            Disposition.MALICIOUS: "Domain appears in threat-intel pulses (mock intel)",
            Disposition.BENIGN: "Domain is a known-good service (mock intel)",
        }.get(disp, "No threat-intel pulses for this domain (mock intel)")
        return ToolResult(self.name, value, disp, summary, "mock://domain-reputation", True)
