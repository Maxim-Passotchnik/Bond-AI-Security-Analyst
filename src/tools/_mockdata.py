"""
Deterministic mock threat-intel, keyed to the sample alerts in `alerts/` so the
offline demo produces sensible, reproducible verdicts. All keys are lowercased.
"""
from ..models import Disposition

KNOWN_MALICIOUS = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",  # EICAR sha256 (malicious EDR sample)
    "secure-doc-update.ru",      # C2 domain (malicious EDR sample)
    "185.220.101.47",            # C2 IP (malicious EDR sample)
    "micros0ft-secure.com",      # brand-spoof phishing domain
    "193.142.146.35",            # phishing sender IP
}

KNOWN_SUSPICIOUS = {
    "45.83.122.10",              # hosting-ASN sign-in IP (suspicious login sample)
}

KNOWN_BENIGN = {
    "fde343ee184953c1fa1185abddeaa8be61c6acbebae4eb54db5d6b55b09a5755",  # benign EDR sample hash (VT-known clean)
    "www.microsoft.com",
    "13.107.42.14",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # (legacy) empty-file hash
    "data.services.jetbrains.com",
}


def mock_disposition(value: str) -> Disposition:
    v = (value or "").lower()
    if v in KNOWN_MALICIOUS:
        return Disposition.MALICIOUS
    if v in KNOWN_SUSPICIOUS:
        return Disposition.SUSPICIOUS
    if v in KNOWN_BENIGN:
        return Disposition.BENIGN
    return Disposition.UNKNOWN
