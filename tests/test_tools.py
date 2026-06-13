"""
Offline tests for the tool layer (src/tools/).

Every test runs with BOND_FORCE_MOCK=1 (autouse fixture) so tools take their
deterministic mock path — no network, no API keys, reproducible verdicts keyed
to the sample alerts.
"""
import pytest

from src.models import Disposition
from src.tools import ALL_TOOLS, dispatch, tool_definitions

EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
BENIGN_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


@pytest.fixture(autouse=True)
def _force_mock(monkeypatch):
    monkeypatch.setenv("BOND_FORCE_MOCK", "1")


# --------------------------------------------------------------------------- #
#  Registry & definitions
# --------------------------------------------------------------------------- #
def test_registry_has_expected_tools():
    assert set(ALL_TOOLS) == {
        "hash_reputation", "ip_reputation", "domain_reputation",
        "whois_lookup", "dns_lookup", "geoip_lookup", "web_search",
    }


def test_tool_definitions_are_well_formed():
    for d in tool_definitions():
        assert d["name"] and d["description"]
        schema = d["input_schema"]
        assert schema["type"] == "object"
        # data minimization: exactly one indicator property, nothing else allowed
        assert len(schema["properties"]) == 1
        assert schema["additionalProperties"] is False
        assert len(schema["required"]) == 1


def test_dispatch_unknown_tool_raises():
    with pytest.raises(KeyError):
        dispatch("nope", {"value": "x"})


# --------------------------------------------------------------------------- #
#  Mock verdicts keyed to the sample alerts
# --------------------------------------------------------------------------- #
def test_hash_reputation_flags_eicar():
    res = dispatch("hash_reputation", {"file_hash": EICAR})
    assert res.disposition == Disposition.MALICIOUS and res.is_mock


def test_hash_reputation_benign_hash():
    res = dispatch("hash_reputation", {"file_hash": BENIGN_HASH})
    assert res.disposition == Disposition.BENIGN


def test_hash_reputation_unknown_hash():
    res = dispatch("hash_reputation", {"file_hash": "deadbeef" * 8})
    assert res.disposition == Disposition.UNKNOWN


def test_ip_reputation_c2_ip_malicious():
    res = dispatch("ip_reputation", {"ip": "185.220.101.47"})
    assert res.disposition == Disposition.MALICIOUS


def test_ip_reputation_hosting_asn_suspicious():
    res = dispatch("ip_reputation", {"ip": "45.83.122.10"})
    assert res.disposition == Disposition.SUSPICIOUS


def test_domain_reputation_c2_domain_malicious():
    res = dispatch("domain_reputation", {"domain": "secure-doc-update.ru"})
    assert res.disposition == Disposition.MALICIOUS


def test_whois_young_domain_suspicious():
    res = dispatch("whois_lookup", {"domain": "micros0ft-secure.com"})
    assert res.disposition == Disposition.SUSPICIOUS


def test_whois_aged_domain_benign():
    res = dispatch("whois_lookup", {"domain": "data.services.jetbrains.com"})
    assert res.disposition == Disposition.BENIGN


def test_web_search_flags_known_bad_indicator():
    res = dispatch("web_search", {"query": "secure-doc-update.ru malware"})
    assert res.disposition == Disposition.SUSPICIOUS


def test_geoip_is_informational():
    res = dispatch("geoip_lookup", {"ip": "185.220.101.47"})
    assert res.disposition == Disposition.UNKNOWN
    assert res.is_mock


def test_all_mock_results_flagged_is_mock():
    res = dispatch("dns_lookup", {"domain": "example.com"})
    assert res.is_mock is True
