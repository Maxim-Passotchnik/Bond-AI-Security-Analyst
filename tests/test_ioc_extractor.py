"""
Unit tests for IOC extraction — focused on the type-collision cases:
field context decides type when the value shape is ambiguous.
"""
from src.ioc_extractor import extract_iocs
from src.models import Alert, AlertType, IOCType, Severity


def _alert(entities: dict) -> Alert:
    return Alert(id="t", type=AlertType.GENERIC, severity=Severity.LOW,
                 title="", description="", source_system="t", detected_at="now",
                 entities=entities)


def _types_values(entities: dict):
    return {(i.type, i.value) for i in extract_iocs(_alert(entities))}


def test_domain_in_network_field_is_extracted():
    vals = _types_values({"network": {"contacted_domain": "evil.com"}})
    assert (IOCType.DOMAIN, "evil.com") in vals


def test_same_value_in_file_field_is_not_a_domain():
    # "malware.com" — .com is both a TLD and a DOS executable extension. Context wins:
    # in a file field it's a filename, not a domain.
    vals = _types_values({"file": {"name": "malware.com"}})
    assert not any(t == IOCType.DOMAIN for t, _ in vals)


def test_username_is_not_a_domain():
    vals = _types_values({"identity": {"logged_on_user": "j.harlow"}})
    assert not any(t == IOCType.DOMAIN for t, _ in vals)


def test_file_extensions_are_not_domains():
    for fn in ("readme.txt", "shortcut.lnk", "report.pdf", "backup.iso", "config.ini"):
        vals = _types_values({"misc": {"note": fn}})
        assert not any(t == IOCType.DOMAIN for t, _ in vals), fn


def test_url_is_extracted_even_in_a_pathy_field():
    # URLs require an http(s):// prefix, so they're unambiguous regardless of field name.
    vals = _types_values({"url": {"path": "http://evil.example/login"}})
    assert any(t == IOCType.URL for t, _ in vals)
    assert (IOCType.DOMAIN, "evil.example") in vals     # host pulled from the URL


def test_hash_and_ip_are_classified_by_shape():
    vals = _types_values({"file": {"sha256": "a" * 64}, "net": {"ip": "8.8.8.8"}})
    assert (IOCType.FILE_HASH, "a" * 64) in vals          # hash still extracted from a file field
    assert (IOCType.IP, "8.8.8.8") in vals
