"""
Web / news search — check for public threat reports, trending campaigns, CVEs.
  * Brave Search API   (if BRAVE_SEARCH_API_KEY set) — richer, keyed
  * DuckDuckGo (ddgs)  — no key, default
"""
from __future__ import annotations

import os

from ..models import Disposition
from ._mockdata import KNOWN_MALICIOUS
from .base import Tool, ToolResult

# Words in a result snippet that suggest the subject is reported as malicious.
_THREAT_TERMS = ("malware", "phishing", "c2", "command and control", "trojan", "ioc", "campaign")


class WebSearchTool(Tool):
    name = "web_search"
    description = (
        "Search the web/news for public reporting on an indicator or topic "
        "(threat reports, trending campaigns, CVEs). Returns top results."
    )
    arg = "query"
    arg_description = "The search query (e.g. a domain, hash, or campaign name)"
    env_keys = ("BRAVE_SEARCH_API_KEY",)   # optional; DuckDuckGo used when absent

    def available(self) -> bool:
        # No-key path (DuckDuckGo) is always a valid real provider, so attempt
        # real unless explicitly forced to mock.
        from .base import _force_mock
        return not _force_mock()

    def _run_real(self, value: str) -> ToolResult:
        brave_key = os.getenv("BRAVE_SEARCH_API_KEY")
        if brave_key:
            import requests
            r = requests.get(
                "https://api.search.brave.com/res/v1/web/search",
                headers={"X-Subscription-Token": brave_key, "Accept": "application/json"},
                params={"q": value, "count": 5}, timeout=15,
            )
            r.raise_for_status()
            hits = [{"title": w.get("title"), "url": w.get("url")}
                    for w in r.json().get("web", {}).get("results", [])]
            source = "https://search.brave.com"
        else:
            from ddgs import DDGS
            hits = [{"title": h.get("title"), "url": h.get("href")}
                    for h in DDGS().text(value, max_results=5)]
            source = "https://duckduckgo.com"

        blob = " ".join((h.get("title") or "") for h in hits).lower()
        disp = Disposition.SUSPICIOUS if any(t in blob for t in _THREAT_TERMS) else Disposition.UNKNOWN
        return ToolResult(self.name, value, disp,
                          f"{len(hits)} result(s); "
                          + ("threat-related reporting found" if disp == Disposition.SUSPICIOUS
                             else "no obvious threat reporting"),
                          source, False, {"results": hits})

    def _mock(self, value: str) -> ToolResult:
        v = (value or "").lower()
        if any(bad in v for bad in KNOWN_MALICIOUS):
            return ToolResult(self.name, value, Disposition.SUSPICIOUS,
                              "Public reports describe this indicator in a malware campaign (mock)",
                              "mock://web-search", True,
                              {"results": [{"title": "Threat report: indicator linked to malware C2",
                                            "url": "https://example.com/report"}]})
        return ToolResult(self.name, value, Disposition.UNKNOWN,
                          "No notable public reporting found (mock)", "mock://web-search", True,
                          {"results": []})
