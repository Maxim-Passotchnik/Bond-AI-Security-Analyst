"""
Network / OSINT tools — WHOIS, DNS resolution, IP geolocation. All free, no key:
  * WHOIS  — python-whois          (a freshly-registered domain is a risk signal)
  * DNS    — dnspython             (resolution context)
  * GeoIP  — ip-api.com            (location / ASN context)
"""
from __future__ import annotations

from datetime import datetime, timezone

from ..models import Disposition
from ._mockdata import KNOWN_BENIGN, KNOWN_MALICIOUS, mock_disposition
from .base import Tool, ToolResult

_YOUNG_DOMAIN_DAYS = 30      # freshly-registered → risk signal
_AGED_DOMAIN_DAYS = 730      # ~2 years: long-established infrastructure → benign signal


class WhoisTool(Tool):
    name = "whois_lookup"
    description = (
        "WHOIS registration data for a domain. A very recently-registered domain is a "
        "common indicator of malicious infrastructure."
    )
    arg = "domain"
    arg_description = "The domain to look up"

    def _run_real(self, value: str) -> ToolResult:
        import whois  # python-whois

        w = whois.whois(value)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0] if created else None
        age_days = None
        if isinstance(created, datetime):
            ref = created if created.tzinfo else created.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - ref).days
        if age_days is None:
            disp, note = Disposition.UNKNOWN, "registration date unavailable"
        elif age_days < _YOUNG_DOMAIN_DAYS:
            disp, note = Disposition.SUSPICIOUS, f"registered only {age_days} days ago"
        elif age_days >= _AGED_DOMAIN_DAYS:
            disp, note = Disposition.BENIGN, f"long-established domain (registered ~{age_days} days ago)"
        else:
            disp, note = Disposition.UNKNOWN, f"registered ~{age_days} days ago"
        return ToolResult(self.name, value, disp, f"WHOIS: {note}",
                          "https://who.is", False,
                          {"registrar": str(w.registrar), "creation_date": str(created), "age_days": age_days})

    def _mock(self, value: str) -> ToolResult:
        v = (value or "").lower()
        if v in KNOWN_MALICIOUS:
            return ToolResult(self.name, value, Disposition.SUSPICIOUS,
                              "WHOIS: domain registered 6 days ago via a privacy proxy (mock)",
                              "mock://whois", True, {"age_days": 6})
        if v in KNOWN_BENIGN:
            return ToolResult(self.name, value, Disposition.BENIGN,
                              "WHOIS: domain registered over 10 years ago (mock)",
                              "mock://whois", True, {"age_days": 3800})
        return ToolResult(self.name, value, Disposition.UNKNOWN,
                          "WHOIS: registration age not notable (mock)", "mock://whois", True, {})


class DnsTool(Tool):
    name = "dns_lookup"
    description = "Resolve a domain's DNS records (A) for network context."
    arg = "domain"
    arg_description = "The domain to resolve"

    def _run_real(self, value: str) -> ToolResult:
        import dns.resolver

        answers = dns.resolver.resolve(value, "A")
        ips = [r.address for r in answers]
        return ToolResult(self.name, value, Disposition.UNKNOWN,
                          f"DNS A records: {', '.join(ips)}", "dns://resolver", False, {"a": ips})

    def _mock(self, value: str) -> ToolResult:
        return ToolResult(self.name, value, Disposition.UNKNOWN,
                          "DNS A records: 203.0.113.10 (mock)", "mock://dns", True,
                          {"a": ["203.0.113.10"]})


class GeoIpTool(Tool):
    name = "geoip_lookup"
    description = "Geolocate an IP and identify its ISP/ASN (ip-api.com)."
    arg = "ip"
    arg_description = "The IP address to geolocate"

    def _run_real(self, value: str) -> ToolResult:
        import requests

        r = requests.get(f"http://ip-api.com/json/{value}", timeout=10)
        r.raise_for_status()
        d = r.json()
        if d.get("status") != "success":
            return ToolResult(self.name, value, Disposition.UNKNOWN,
                              "GeoIP lookup failed", "http://ip-api.com", False, d)
        loc = f"{d.get('city')}, {d.get('country')} — {d.get('isp')} ({d.get('as')})"
        return ToolResult(self.name, value, Disposition.UNKNOWN, f"GeoIP: {loc}",
                          "http://ip-api.com", False, d)

    def _mock(self, value: str) -> ToolResult:
        disp = mock_disposition(value)
        note = ("Frankfurt, DE — M247 hosting ASN (mock)"
                if disp in (Disposition.SUSPICIOUS, Disposition.MALICIOUS)
                else "Austin, US — residential ISP (mock)")
        return ToolResult(self.name, value, Disposition.UNKNOWN, f"GeoIP: {note}",
                          "mock://geoip", True, {})
