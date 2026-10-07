"""Fase 5C: parsers, normalización, SSRF, frescura y prioridad. Sin base de datos.

Todos los datos son sintéticos (CVE-2099-*, IPs de documentación 203.0.113.0/24 y
198.51.100.0/24, dominios example): nada real.
"""

import gzip
import io
import json
import threading
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, ClassVar

import pytest

from app.threat_intel import epss, iocfile, kev, stix
from app.threat_intel.errors import IntelFormatError, IntelRecordError
from app.threat_intel.freshness import indicator_state, is_stale, source_state
from app.threat_intel.http import FetchError, FetchPolicy, blocked_reason, check_url, fetch
from app.threat_intel.indicators import normalize
from app.threat_intel.lookup import ExploitIntel, intel_cve
from app.threat_intel.providers import parse_import, parse_vulnerability_import
from app.vulnerabilities import priority

MIB = 1024 * 1024


# --- Indicadores -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "raw", "expected_type", "expected"),
    [
        ("ipv4", " 203.0.113.7 ", "ipv4", "203.0.113.7"),
        ("ipv6", "2001:DB8::0:1", "ipv6", "2001:db8::1"),
        # Una IPv6 mapeada se guarda como la IPv4 que es.
        ("ipv6", "::ffff:203.0.113.9", "ipv4", "203.0.113.9"),
        ("cidr", "198.51.100.17/24", "cidr", "198.51.100.0/24"),
        # Un /32 es una IP, no una red.
        ("cidr", "203.0.113.7/32", "ipv4", "203.0.113.7"),
        ("domain", "Evil.Example.COM.", "domain", "evil.example.com"),
        ("sha256", "A" * 64, "sha256", "a" * 64),
    ],
)
def test_indicators_are_normalized(kind: str, raw: str, expected_type: str, expected: str) -> None:
    result = normalize(kind, raw)
    assert (result.indicator_type, result.value) == (expected_type, expected)


@pytest.mark.parametrize(
    ("kind", "raw", "code"),
    [
        ("ipv4", "203.0.113.300", "invalid_indicator"),
        ("ipv4", "2001:db8::1", "invalid_indicator"),
        ("cidr", "10.0.0.0/4", "indicator_too_broad"),
        ("domain", "203.0.113.7", "invalid_indicator"),
        # Defanged ("hxxp", "[.]"): se importa en forma real o nada.
        ("domain", "evil[.]example[.]com", "defanged_indicator"),
        ("md5", "abc", "invalid_indicator"),
        ("registry_key", "HKLM\\x", "unsupported_indicator_type"),
        ("ipv4", "203.0.113.7\x00", "invalid_indicator"),
    ],
)
def test_invalid_indicators_are_rejected(kind: str, raw: str, code: str) -> None:
    with pytest.raises(IntelRecordError) as exc:
        normalize(kind, raw)
    assert exc.value.code == code


# --- CISA KEV ----------------------------------------------------------------------------------


def kev_feed(*cves: str, **extra: Any) -> bytes:
    return json.dumps(
        {
            "title": "CISA Catalog of Known Exploited Vulnerabilities",
            "catalogVersion": "2099.01.01",
            "dateReleased": "2099-01-01T12:00:00.000Z",
            "count": len(cves),
            "vulnerabilities": [
                {
                    "cveID": cve,
                    "vendorProject": "Example Corp",
                    "product": "ExampleApp",
                    "vulnerabilityName": f"ExampleApp issue {cve}",
                    "dateAdded": "2099-01-01",
                    "shortDescription": "Synthetic record.",
                    "requiredAction": "Apply updates per vendor instructions.",
                    "dueDate": "2099-01-22",
                    "knownRansomwareCampaignUse": "Unknown",
                    "notes": "",
                    "cwes": ["CWE-78"],
                    **extra,
                }
                for cve in cves
            ],
        }
    ).encode()


def test_kev_feed_is_parsed_with_semantics() -> None:
    parsed = kev.parse(kev_feed("CVE-2099-1001", "cve-2099-1002"), MIB)
    assert parsed.source_version == "2099.01.01"
    assert [r.cve_id for r in parsed.vulnerabilities] == ["CVE-2099-1001", "CVE-2099-1002"]
    data = parsed.vulnerabilities[0].data
    assert data["date_added"] == "2099-01-01" and data["due_date"] == "2099-01-22"
    # "Unknown" se conserva como desconocido, no como "no".
    assert data["known_ransomware_use"] == "unknown"


def test_kev_invalid_entries_are_counted_not_imported() -> None:
    raw = json.loads(kev_feed("CVE-2099-1001"))
    raw["vulnerabilities"].append({"cveID": "not-a-cve", "dateAdded": "2099-01-01"})
    raw["vulnerabilities"].append({"cveID": "CVE-2099-1003"})
    parsed = kev.parse(json.dumps(raw).encode(), MIB)
    assert len(parsed.vulnerabilities) == 1
    assert {i.code for i in parsed.invalid} == {"invalid_cve", "invalid_record"}


@pytest.mark.parametrize(
    "raw",
    [
        b"<html>captive portal</html>",
        b'{"vulnerabilities": "nope"}',
        b"[" * 5000 + b"]" * 5000,
    ],
)
def test_kev_hostile_or_wrong_documents_are_refused(raw: bytes) -> None:
    with pytest.raises(IntelFormatError):
        kev.parse(raw, MIB)


def test_kev_size_and_record_limits() -> None:
    with pytest.raises(IntelFormatError) as exc:
        kev.parse(kev_feed("CVE-2099-1001"), 100)
    assert exc.value.code == "intel_too_large"
    with pytest.raises(IntelFormatError):
        kev.parse(kev_feed("CVE-2099-1001", "CVE-2099-1002"), MIB, max_records=1)


# --- FIRST EPSS --------------------------------------------------------------------------------

EPSS_CSV = (
    "#model_version:v2099.01.01,score_date:2099-01-02T00:00:00+0000\n"
    "cve,epss,percentile\n"
    "CVE-2099-1001,0.91234,0.99876\n"
    "CVE-2099-1002,0.00042,0.05000\n"
    "CVE-2099-BAD,0.5,0.5\n"
    "CVE-2099-1003,1.5,0.2\n"
)


def _epss(raw: bytes, max_records: int = 1000) -> tuple[list[Any], Any]:
    feed = parse_vulnerability_import("first_epss", io.BytesIO(raw), MIB, max_records)
    return list(feed.vulnerabilities()), feed.parsed


@pytest.mark.parametrize("compress", [False, True])
def test_epss_csv_plain_or_gzip(compress: bool) -> None:
    raw = EPSS_CSV.encode()
    records, intel = _epss(gzip.compress(raw) if compress else raw)
    assert [(r.cve_id, r.epss_score) for r in records] == [
        ("CVE-2099-1001", 0.91234),
        ("CVE-2099-1002", 0.00042),
    ]
    assert records[0].data["model_version"] == "v2099.01.01"
    assert records[0].data["score_date"] == "2099-01-02"
    assert intel.invalid_total == 2


@pytest.mark.parametrize(
    "raw",
    [
        b"cve,score\nCVE-2099-1001,0.1\n",
        b"\x1f\x8b\x08 corrupt gzip",
        b"\xff\xfe\x00 not utf-8",
    ],
)
def test_epss_wrong_files_fail_as_a_whole(raw: bytes) -> None:
    with pytest.raises(IntelFormatError):
        _epss(raw)


def test_epss_row_limit() -> None:
    with pytest.raises(IntelFormatError) as exc:
        _epss(EPSS_CSV.encode(), max_records=1)
    assert exc.value.code == "intel_too_many_records"


def test_epss_bands_and_material_changes() -> None:
    assert epss.band(None) == "none"
    assert epss.band(0.6) == "high"
    assert not epss.is_material(0.010, 0.012)
    assert epss.is_material(0.2, 0.6)


# --- STIX e IOC ----------------------------------------------------------------------------


def _stix(*objects: dict[str, Any]) -> bytes:
    return json.dumps(
        {"type": "bundle", "id": "bundle--00000000-0000-4000-8000-000000000000", "objects": objects}
    ).encode()


def _indicator(n: int, pattern: str, **extra: Any) -> dict[str, Any]:
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--00000000-0000-4000-8000-{n:012d}",
        "created": "2099-01-01T00:00:00Z",
        "modified": "2099-01-01T00:00:00Z",
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": "2099-01-01T00:00:00Z",
        **extra,
    }


def test_stix_safe_subset_only() -> None:
    raw = _stix(
        _indicator(1, "[ipv4-addr:value = '203.0.113.7']", indicator_types=["malicious-activity"]),
        _indicator(2, "[domain-name:value = 'evil.example.com']", confidence=80),
        # Patrones compuestos u operadores: no se importan (unsupported).
        _indicator(3, "[ipv4-addr:value = '203.0.113.8' OR ipv4-addr:value = '203.0.113.9']"),
        _indicator(4, "[ipv4-addr:value MATCHES '^203']"),
        _indicator(5, "[process:name = 'evil.exe']"),
        {"type": "malware", "id": "malware--00000000-0000-4000-8000-000000000009", "name": "X"},
    )
    parsed = parse_import("stix", raw, MIB, 1000).parsed
    values = {(r.indicator_type, r.value): r for r in parsed.indicators}
    assert set(values) == {("ipv4", "203.0.113.7"), ("domain", "evil.example.com")}
    assert values[("ipv4", "203.0.113.7")].classification == "malicious"
    # Sin indicator_types: "unknown", nunca "malicious" por aparecer en el bundle.
    assert values[("domain", "evil.example.com")].classification == "unknown"
    assert values[("domain", "evil.example.com")].confidence == "high"
    assert sum(parsed.unsupported.values()) == 3


def test_stix_pattern_is_never_evaluated() -> None:
    assert stix.parse_pattern("[ipv4-addr:value = '203.0.113.7']") == ("ipv4", "203.0.113.7")
    for hostile in (
        "__import__('os').system('id')",
        "[ipv4-addr:value = '1.2.3.4'] WITHIN 5 SECONDS",
        "[file:hashes.'SHA-256' = 'x'] AND [ipv4-addr:value = '1.2.3.4']",
    ):
        assert stix.parse_pattern(hostile) is None


def test_stix_not_a_bundle_is_refused() -> None:
    with pytest.raises(IntelFormatError):
        parse_import("stix", b'{"type": "indicator"}', MIB, 1000)


def _ioc(*indicators: dict[str, Any]) -> bytes:
    return json.dumps({"format": iocfile.FORMAT, "indicators": list(indicators)}).encode()


def test_ioc_file_requires_classification_and_validates_references() -> None:
    raw = _ioc(
        {"type": "ipv4", "value": "203.0.113.7", "classification": "malicious"},
        {"type": "ipv4", "value": "203.0.113.8"},
        {
            "type": "domain",
            "value": "evil.example.com",
            "classification": "suspicious",
            "references": ["javascript:alert(1)"],
        },
        {"type": "ipv4", "value": "203.0.113.9", "classification": "malicious", "extra": 1},
    )
    parsed = parse_import("sentra-ioc", raw, MIB, 1000).parsed
    assert [r.value for r in parsed.indicators] == ["203.0.113.7"]
    assert parsed.indicators[0].confidence == "medium"
    assert parsed.invalid_total == 3


def test_ioc_file_wrong_format_is_refused() -> None:
    with pytest.raises(IntelFormatError):
        parse_import("sentra-ioc", b'{"format": "other/1", "indicators": []}', MIB, 1000)


# --- SSRF --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://example.org/feed.json",
        "https://user:pass@example.org/feed.json",
        "https://localhost/feed.json",
        "https://feeds.internal/feed.json",
        "https://127.0.0.1/feed.json",
        "https://169.254.169.254/latest/meta-data/",
        "https://10.0.0.5/feed.json",
        "https://[::1]/feed.json",
        "https://[::ffff:127.0.0.1]/feed.json",
        "https://100.64.0.1/feed.json",
        "http://example.org/feed.json",
        "https://example.org/feed.json\r\nHost: evil",
    ],
)
def test_ssrf_destinations_are_blocked(url: str) -> None:
    with pytest.raises(FetchError) as exc:
        check_url(url, FetchPolicy())
    assert exc.value.code == "blocked_destination"


def test_allowed_lan_mirror_needs_explicit_network() -> None:
    import ipaddress

    mirror = FetchPolicy(allowed_networks=(ipaddress.ip_network("10.20.0.0/16"),), allow_http=True)
    assert check_url("http://10.20.1.5/kev.json", mirror)[1] == "10.20.1.5"
    # Fuera de la red autorizada sigue bloqueado; http nunca en producción (allow_http=False).
    with pytest.raises(FetchError):
        check_url("http://10.30.1.5/kev.json", mirror)
    production = FetchPolicy(allowed_networks=mirror.allowed_networks, allow_http=False)
    with pytest.raises(FetchError):
        check_url("http://10.20.1.5/kev.json", production)
    assert blocked_reason(ipaddress.ip_address("10.20.1.5"), mirror) is None
    assert blocked_reason(ipaddress.ip_address("8.8.8.8"), FetchPolicy()) is None


class _Handler(BaseHTTPRequestHandler):
    routes: ClassVar[dict[str, tuple[int, dict[str, str], bytes]]] = {}

    def do_GET(self) -> None:
        status, headers, body = self.routes.get(self.path, (404, {}, b""))
        if self.headers.get("If-None-Match") and headers.get("ETag") == self.headers.get(
            "If-None-Match"
        ):
            status, body = 304, b""
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: Any) -> None:
        return None


@pytest.fixture
def mirror() -> Iterator[tuple[str, FetchPolicy]]:
    import ipaddress

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    policy = FetchPolicy(
        allowed_networks=(ipaddress.ip_network("127.0.0.0/8"),),
        allow_http=True,
        total_timeout=10,
        max_bytes=4096,
    )
    try:
        yield f"http://127.0.0.1:{server.server_port}", policy
    finally:
        server.shutdown()
        server.server_close()


def test_fetch_from_authorized_mirror_with_etag_and_limits(
    mirror: tuple[str, FetchPolicy],
) -> None:
    base, policy = mirror
    _Handler.routes = {
        "/kev.json": (200, {"ETag": '"v1"'}, b'{"ok": true}'),
        "/big": (200, {}, b"x" * 5000),
        "/redirect-out": (302, {"Location": "http://169.254.169.254/latest"}, b""),
        "/down": (503, {}, b""),
    }
    result = fetch(f"{base}/kev.json", policy)
    try:
        assert result.status == 200 and result.etag == '"v1"' and result.size == 12
        assert result.body is not None and result.body.read() == b'{"ok": true}'
        assert result.final_host == "127.0.0.1"
    finally:
        result.close()
    assert fetch(f"{base}/kev.json", policy, etag='"v1"').status == 304
    codes = {}
    for path in ("/big", "/redirect-out", "/down"):
        with pytest.raises(FetchError) as exc:
            fetch(f"{base}{path}", policy)
        codes[path] = exc.value.code
    assert codes == {
        "/big": "too_large",
        "/redirect-out": "blocked_destination",
        "/down": "unavailable",
    }
    # Sin la red autorizada, el mismo servidor local está prohibido.
    with pytest.raises(FetchError) as exc:
        fetch(f"{base}/kev.json", FetchPolicy(allow_http=True))
    assert exc.value.code == "blocked_destination"


# --- Frescura, CVE y vocabulario ---------------------------------------------------------------


class _Source:
    def __init__(self, **values: Any) -> None:
        self.enabled: bool = True
        self.archived_at: datetime | None = None
        self.network_required = True
        self.last_success_at: datetime | None = None
        self.stale_after_hours: int | None = 48
        self.sync_interval_hours: int | None = 24
        self.__dict__.update(values)


def test_source_freshness_states() -> None:
    now = datetime.now(UTC)
    assert source_state(_Source(), now) == "never_synced"
    assert source_state(_Source(last_success_at=now - timedelta(hours=1)), now) == "fresh"
    old = _Source(last_success_at=now - timedelta(hours=72))
    assert source_state(old, now) == "stale" and is_stale(old, now)
    assert source_state(_Source(enabled=False), now) == "disabled"
    assert source_state(_Source(archived_at=now), now) == "archived"


def test_indicator_states() -> None:
    now = datetime.now(UTC)
    assert indicator_state(False, None, None, now) == "active"
    assert indicator_state(True, None, None, now) == "revoked"
    assert indicator_state(False, None, now - timedelta(seconds=1), now) == "expired"
    assert indicator_state(False, now + timedelta(days=1), None, now) == "not_yet_valid"


def test_intel_cve_uses_cve_or_first_cve_alias_only() -> None:
    assert intel_cve("cve-2099-1001", None) == "CVE-2099-1001"
    assert intel_cve("GHSA-xxxx-yyyy-zzzz", ["OSV-1", "CVE-2099-1002"]) == "CVE-2099-1002"
    assert intel_cve("VENDOR-2099-01", ["VENDOR-ALIAS"]) is None


def test_exploit_context_never_claims_local_compromise() -> None:
    info = ExploitIntel(
        cve="CVE-2099-1001",
        known_exploited=True,
        kev={"date_added": "2099-01-01", "due_date": "2099-01-22"},
        kev_source="CISA KEV",
        epss_score=0.9,
        epss_percentile=0.99,
        epss_source="FIRST EPSS",
    )
    context = info.as_context()
    assert context["kev"]["known_ransomware_use"] == "unknown"
    assert context["epss"]["band"] == "high"
    text = json.dumps(context).lower()
    for forbidden in ("exploited on this", "compromised", "vulnerable"):
        assert forbidden not in text


# --- Prioridad 5B con inteligencia -------------------------------------------------------------


def _priority(**intel: Any) -> priority.Priority:
    return priority.calculate(priority.PriorityInputs("high", "confirmed", "unknown", **intel))


def test_kev_and_epss_raise_priority_with_explanation() -> None:
    base = _priority()
    kev_only = _priority(known_exploited=True)
    both = _priority(known_exploited=True, epss_score=0.95)
    assert base.score < kev_only.score <= both.score
    names = {f["factor"] for f in both.factors}
    assert {"known_exploited", "epss"} <= names
    (kev_factor,) = [f for f in both.factors if f["factor"] == "known_exploited"]
    assert "CISA KEV" in kev_factor["label"]
    # Tope: KEV + EPSS no suman sin límite.
    assert both.score - base.score <= priority.EXPLOIT_CAP


def test_low_epss_adds_nothing_and_stale_intel_counts_less() -> None:
    assert _priority(epss_score=0.001).score == _priority().score
    fresh = _priority(known_exploited=True)
    stale = _priority(known_exploited=True, intel_stale=True)
    assert _priority().score < stale.score < fresh.score


def test_potential_match_limits_intel_weight() -> None:
    confirmed = priority.calculate(
        priority.PriorityInputs("high", "confirmed", "unknown", known_exploited=True)
    )
    potential = priority.calculate(
        priority.PriorityInputs("high", "potential", "unknown", known_exploited=True)
    )
    base_potential = priority.calculate(priority.PriorityInputs("high", "potential", "unknown"))
    assert potential.score - base_potential.score < confirmed.score - _priority().score


def test_kev_vocabulary_in_errors() -> None:
    # IntelRecordError expone código estable (la API lo devuelve tal cual).
    with pytest.raises(IntelRecordError) as exc:
        normalize("ipv4", "")
    assert exc.value.code == "invalid_indicator"
