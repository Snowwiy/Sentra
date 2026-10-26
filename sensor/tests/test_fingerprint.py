"""Fase 7A.4: huellas de servicio del sensor (DNS-SD, HTTP, certificado TLS) y discovery v3.

Nada sale a la red: parsers con mensajes construidos aquí y un prober de huellas falso. Los
criterios son los del discovery local del servidor (backend/tests/test_device_intelligence.py).
"""

import ipaddress
import struct
from datetime import UTC, datetime
from typing import Any

import pytest

from sentra_sensor import fingerprint
from sentra_sensor.fingerprint import MdnsServices, WebFingerprint
from sentra_sensor.jobs import (
    JOB_TYPE_DISCOVERY_ADVANCED,
    DiscoveryParameters,
    JobRejectedError,
    validate_job,
)
from sentra_sensor.protocol import ServerConfig
from sentra_sensor.scanner import Scanner
from tests.conftest import SENSOR_ID, SITE_ID, FakeTcp, make_job, server_config

NOW = datetime.now(UTC)
CONFIG = ServerConfig.parse(
    server_config(
        advanced_max_timeout_ms=5000,
        max_dns_timeout_ms=5000,
        max_tcp_retries=2,
        max_dns_queries=4096,
        advanced_max_ports=256,
        max_deadline_seconds=1800,
    )
)


# --- Parsers --------------------------------------------------------------------------------------


def _encode(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"


def test_dns_sd_service_types_are_parsed() -> None:
    question = "_services._dns-sd._udp.local"
    answers = [b"_ipp._tcp.local", b"_printer._tcp.local", b"no-es-un-servicio.local"]
    header = struct.pack("!HHHHHH", 0x5151, 0x8400, 1, len(answers), 0, 0)
    body = _encode(question) + struct.pack("!HH", 12, 1)
    for target in answers:
        rdata = _encode(target.decode())
        body += b"\xc0\x0c" + struct.pack("!HHIH", 12, 1, 120, len(rdata)) + rdata
    services = fingerprint.parse_service_types(header + body, 0x5151)
    assert services == ("_ipp._tcp", "_printer._tcp")
    assert fingerprint.parse_service_types(header + body, 0x1111) == ()


def test_http_title_only_on_200() -> None:
    raw = b"HTTP/1.1 200 OK\r\nServer: App-webs/\r\n\r\n<title>Web Camera</title>"
    assert fingerprint.parse_http_response(raw) == (200, "App-webs/", "Web Camera")
    raw401 = b"HTTP/1.0 401 Unauthorized\r\nServer: lighttpd\r\n\r\n<title>x</title>"
    assert fingerprint.parse_http_response(raw401) == (401, "lighttpd", None)


def test_certificate_is_read_from_a_split_tls12_flight() -> None:
    der = b"\x30\x03\x02\x01\x01"  # basta para el reensamblado; los nombres no se leen aquí
    server_hello = bytes([2]) + (38).to_bytes(3, "big") + b"\x03\x03" + bytes(32)
    server_hello += b"\x00\xc0\x2b\x00"
    chain = len(der).to_bytes(3, "big") + der
    certificate = bytes([11]) + (len(chain) + 3).to_bytes(3, "big")
    certificate += len(chain).to_bytes(3, "big") + chain
    stream = server_hello + certificate
    flight = b"".join(
        bytes([22, 3, 3]) + len(p).to_bytes(2, "big") + p for p in (stream[:45], stream[45:])
    )
    assert fingerprint.certificate_from_handshake(flight[:20]) == (False, None)
    assert fingerprint.certificate_from_handshake(flight) == (True, der)
    assert fingerprint.certificate_from_handshake(bytes([21, 3, 3, 0, 2, 2, 40])) == (True, None)
    hello = fingerprint.build_client_hello(bytes(32))
    assert hello[0] == 22 and hello[5] == 1
    with pytest.raises(ValueError):
        fingerprint.build_client_hello(b"corto")


def test_only_open_web_ports_are_picked() -> None:
    assert fingerprint.pick_ports({22, 8080, 80, 443, 8443}) == [(80, False), (443, True)]
    assert fingerprint.pick_ports({22, 3389}) == []


# --- Esquema discovery_advanced v3 ----------------------------------------------------------------


def v3_job(**overrides: Any) -> dict[str, Any]:
    job = make_job(NOW, job_type=JOB_TYPE_DISCOVERY_ADVANCED)
    job["parameters"] = {
        "schema_version": 3,
        "profile": "standard",
        "target": "10.0.0.0/29",
        "ports": [80, 443],
        "timeout_ms": 800,
        "dns_timeout_ms": 1500,
        "concurrency": 16,
        "max_probes_per_second": 500,
        "tcp_retries": 0,
        "icmp": False,
        "arp": False,
        "reverse_dns": False,
        "forward_dns": False,
        "max_dns_queries": 100,
        "deadline_seconds": 600,
        "max_hosts": 256,
        "identify": True,
        "max_name_queries": 50,
        "fingerprint": True,
        **overrides,
    }
    return job


def validate(job: dict[str, Any]) -> Any:
    return validate_job(job, sensor_id=SENSOR_ID, site_id=SITE_ID, config=CONFIG, now=NOW)


def test_v3_job_enables_fingerprints() -> None:
    params = validate(v3_job()).parameters
    assert params.fingerprint is True and params.identify is True
    assert validate(v3_job(fingerprint=False)).parameters.fingerprint is False


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        # Las huellas comparten presupuesto con las sondas de nombre: sin identify, nada.
        ({"identify": False, "max_name_queries": None}, "invalid_schema"),
        ({"fingerprint": "yes"}, "invalid_schema"),
        ({"schema_version": 2}, "invalid_schema"),  # clave de v3 con versión 2
    ],
)
def test_v3_job_is_validated_exactly(overrides: dict[str, Any], code: str) -> None:
    with pytest.raises(JobRejectedError) as info:
        validate(v3_job(**overrides))
    assert info.value.code == code


def test_v3_job_without_the_fingerprint_key_is_rejected() -> None:
    job = v3_job()
    del job["parameters"]["fingerprint"]
    with pytest.raises(JobRejectedError) as info:
        validate(job)
    assert info.value.code == "invalid_schema"


# --- Scanner con huellas --------------------------------------------------------------------------


class FakeIdentity:
    async def mdns_name(self, address: str, timeout: float) -> str | None:
        return None

    async def netbios_name(self, address: str, timeout: float) -> str | None:
        return None

    async def ssdp_search(self, addresses: Any, window: float) -> dict[str, Any]:
        return {}

    async def upnp_description(self, response: Any, timeout: float) -> Any:
        return None


class FakeFingerprints:
    def __init__(self) -> None:
        self.mdns_calls: list[str] = []
        self.web_calls: list[tuple[str, int, bool]] = []

    async def mdns_services(self, address: str, timeout: float) -> MdnsServices | None:
        self.mdns_calls.append(address)
        if address == "10.0.0.2":
            return MdnsServices(services=("_rtsp._tcp",), model="M3046")
        return None

    async def web(
        self, address: str, port: int, tls: bool, timeout: float
    ) -> WebFingerprint | None:
        self.web_calls.append((address, port, tls))
        if tls:
            raise OSError("connection reset")
        return WebFingerprint(port=port, tls=tls, server="App-webs/", title="Web Camera")


def scan_params(**overrides: Any) -> DiscoveryParameters:
    values: dict[str, Any] = {
        "target": ipaddress.ip_network("10.0.0.0/29"),
        "ports": (22, 80, 443),
        "timeout_ms": 200,
        "concurrency": 8,
        "max_probes_per_second": 10_000,
        "icmp": False,
        "reverse_dns": False,
        "arp": False,
        "deadline_seconds": 30,
        "identify": True,
        "max_name_queries": 100,
        "fingerprint": True,
    }
    values.update(overrides)
    return DiscoveryParameters(**values)


def run(params: DiscoveryParameters, fakes: FakeFingerprints | None) -> tuple[Any, dict[str, Any]]:
    seen: list[dict[str, Any]] = []
    tcp = FakeTcp(
        {
            ("10.0.0.2", 80): "open",
            ("10.0.0.2", 443): "open",
            ("10.0.0.3", 22): "open",
            ("10.0.0.3", 80): "closed",
        }
    )
    scanner = Scanner(
        params,
        lambda obs: seen.extend(o.to_json() for o in obs),
        tcp=tcp,
        identity=FakeIdentity(),
        fingerprints=fakes,
    )
    report = scanner.run()
    return report, {o["address"]: o for o in seen}


def test_fingerprints_only_on_ports_the_scan_found_open() -> None:
    fakes = FakeFingerprints()
    report, found = run(scan_params(), fakes)
    # Un puerto web y uno TLS del host que los tiene abiertos; nada en puertos cerrados ni en SSH.
    assert sorted(fakes.web_calls) == [("10.0.0.2", 80, False), ("10.0.0.2", 443, True)]
    assert set(fakes.mdns_calls) == {"10.0.0.2", "10.0.0.3"}
    camera = found["10.0.0.2"]["identity"]
    assert camera["mdns_services"] == ["_rtsp._tcp"] and camera["mdns_model"] == "M3046"
    assert camera["web"] == [
        {"port": 80, "tls": False, "server": "App-webs/", "title": "Web Camera"}
    ]
    assert "identity" not in found["10.0.0.3"]
    # Una sonda que falla (el TLS) se informa y no tumba el resto.
    assert any("web 443" in error for error in report.errors)


def test_fingerprint_probes_share_the_name_budget() -> None:
    fakes = FakeFingerprints()
    report, _ = run(scan_params(max_name_queries=1), fakes)
    assert len(fakes.mdns_calls) + len(fakes.web_calls) <= 1
    assert any("name probe budget" in error for error in report.errors)


def test_without_fingerprint_no_probe_is_sent() -> None:
    fakes = FakeFingerprints()
    _, found = run(scan_params(fingerprint=False), fakes)
    assert fakes.mdns_calls == [] and fakes.web_calls == []
    assert all("web" not in o.get("identity", {}) for o in found.values())


def test_fingerprint_requested_without_prober_is_reported() -> None:
    report, _ = run(scan_params(), None)
    assert any("fingerprint probes requested" in error for error in report.errors)
