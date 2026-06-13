"""
src/ioc_extractor.py — pull enrichable indicators out of a normalized Alert.

Walks every string in the alert's `entities` and classifies it by shape (hash / IP /
URL / email / domain). Being shape-based rather than schema-based means it works across
alert types and vendor formats without per-vendor field maps — which is also what makes
the multi-format ingestion roadmap (ARCHITECTURE §7) tractable.

Hostnames and usernames are intentionally *not* emitted as IOCs: they're context, not
externally-enrichable indicators. They remain visible to the agent in the alert payload.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Iterator, Optional
from urllib.parse import urlparse

from .models import Alert, IOC, IOCType

_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9](-?[a-zA-Z0-9])*\.)+[a-zA-Z]{2,}$")

# Last labels that look like a TLD but are really file extensions (avoid treating
# "invoice_update.exe" or "WINWORD.EXE" as domains).
_FILE_EXTS = {
    "exe", "dll", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "ps1", "bat",
    "cmd", "sh", "js", "vbs", "zip", "rar", "dat", "tmp", "bin", "msi", "jar", "py",
}


def _walk(obj, prefix: str = "") -> Iterator[tuple[str, str]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(v, f"{prefix}{k}.")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk(v, f"{prefix}{i}.")
    elif isinstance(obj, str):
        yield prefix.rstrip("."), obj.strip()


def _classify(value: str) -> Optional[tuple[IOCType, str]]:
    v = (value or "").strip()
    if not v:
        return None
    if _SHA256.match(v) or _SHA1.match(v) or _MD5.match(v):
        return IOCType.FILE_HASH, v.lower()
    if v.lower().startswith(("http://", "https://")):
        return IOCType.URL, v
    if _EMAIL.match(v):
        return IOCType.EMAIL, v.lower()
    try:
        ipaddress.ip_address(v)
        return IOCType.IP, v
    except ValueError:
        pass
    if _DOMAIN.match(v) and v.rsplit(".", 1)[-1].lower() not in _FILE_EXTS:
        return IOCType.DOMAIN, v.lower()
    return None


def extract_iocs(alert: Alert) -> list[IOC]:
    """De-duplicated IOC work-list extracted from the alert's entities."""
    iocs: list[IOC] = []
    seen: set[str] = set()

    def add(t: IOCType, val: str, ctx: str) -> None:
        key = f"{t.value}:{val.lower()}"
        if key not in seen:
            seen.add(key)
            iocs.append(IOC(type=t, value=val, context=ctx))

    for path, value in _walk(alert.entities):
        c = _classify(value)
        if not c:
            continue
        t, val = c
        add(t, val, path)
        if t == IOCType.URL:                       # also pull the URL's host as a domain
            host = urlparse(val).hostname
            if host:
                hc = _classify(host)
                if hc and hc[0] == IOCType.DOMAIN:
                    add(IOCType.DOMAIN, hc[1], f"{path} (host)")
    return iocs
