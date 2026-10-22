"""Corrección 6C: sondas de nombre del sensor (mDNS, NetBIOS, SSDP/UPnP) y discovery v2.

Nada sale a la red: parsers con mensajes construidos aquí y un prober de identidad falso.
Los casos de los parsers son los mismos que los del discovery local del servidor
(backend/tests/test_identification.py), porque el sensor replica sus criterios.
"""

import ipaddress
import struct
from collections.abc import Collection
from datetime import UTC, datetime
from typing import Any

import pytest

from sentra_sensor import names
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


# --- Parsers (mismos criterios que el servidor) ---------------------------------------------------


def _dns_response(query_id: int, question: str, answer: bytes) -> bytes:
    def encode(name: str) -> bytes:
        return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"

    header = struct.pack("!HHHHHH", query_id, 0x8400, 1, 1, 0, 0)
    body = encode(question) + struct.pack("!HH", 12, 1)
    record = b"\xc0\x0c" + struct.pack("!HHIH", 12, 1, 120, len(answer)) + answer
    return header + body + record


def test_mdns_ptr_round_trip_and_hostile_messages() -> None:
    question = names.reverse_pointer("192.168.50.78")
    response = _dns_response(0x4242, question, b"\x0aEcho-Salon\x05local\x00")
    assert names.parse_ptr_response(response, 0x4242) == "Echo-Salon"
    assert names.parse_ptr_response(response, 0x1111) is None  # otra pregunta
    assert names.parse_ptr_response(response[:20], 0x4242) is None  # truncada
    header = struct.pack("!HHHHHH", 1, 0x8400, 0, 1, 0, 0)
    looping = header + b"\xc0\x0c" + struct.pack("!HHIH", 12, 1, 0, 2) + b"\xc0\x0c"
    assert names.parse_ptr_response(looping, 1) is None


def test_netbios_status_response_skips_group_names() -> None:
    query = names.build_nbstat_query(7)
    entries = [(b"WORKGROUP      ", 0x00, 0x8400), (b"SALON-PC       ", 0x00, 0x0400)]
    rdata = bytes([len(entries)]) + b"".join(
        name + bytes([suffix]) + struct.pack("!H", flags) for name, suffix, flags in entries
    )
    message = (
        struct.pack("!HHHHHH", 7, 0x8400, 0, 1, 0, 0)
        + query[12:46]
        + struct.pack("!HHIH", 0x21, 1, 0, len(rdata))
        + rdata
    )
    assert names.parse_nbstat_response(message, 7) == "SALON-PC"
    assert names.parse_nbstat_response(message, 8) is None


def test_ssdp_location_never_leaves_the_responding_host() -> None:
    raw = (
        b"HTTP/1.1 200 OK\r\nSERVER: Linux/4.9 UPnP/1.0 Roku/9.4\r\n"
        b"LOCATION: http://192.168.50.30:8060/\r\n\r\n"
    )
    parsed = names.parse_ssdp_response("192.168.50.30", raw)
    assert parsed is not None and parsed.location == "http://192.168.50.30:8060/"
    for location in (
        "http://10.0.0.1/desc.xml",
        "https://192.168.50.30/desc.xml",
        "http://user:pw@192.168.50.30/",
        "file:///etc/passwd",
    ):
        assert names.safe_location("192.168.50.30", location) is None


def test_upnp_description_rejects_dtd_and_broken_xml() -> None:
    xml = (
        b"<root><device><friendlyName>Roku Salon</friendlyName>"
        b"<manufacturer>Roku, Inc.</manufacturer></device></root>"
    )
    description = names.parse_description(xml)
    assert description is not None and description.manufacturer == "Roku, Inc."
    bomb = b'<!DOCTYPE r [<!ENTITY a "aaaa">]><root><device><friendlyName>&a;</friendlyName>'
    assert names.parse_description(bomb + b"</device></root>") is None
    assert names.parse_description(b"<root><device>") is None


# --- Esquema discovery_advanced v2 ----------------------------------------------------------------


def v2_job(**overrides: Any) -> dict[str, Any]:
    job = make_job(NOW, job_type=JOB_TYPE_DISCOVERY_ADVANCED)
    job["parameters"] = {
        "schema_version": 2,
        "profile": "standard",
        "target": "10.0.0.0/29",
        "ports": [80],
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
        **overrides,
    }
    return job


def validate(job: dict[str, Any]) -> Any:
    return validate_job(job, sensor_id=SENSOR_ID, site_id=SITE_ID, config=CONFIG, now=NOW)


def test_v2_job_enables_name_probes_within_the_server_cap() -> None:
    params = validate(v2_job()).parameters
    assert params.identify is True and params.max_name_queries == 50


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"max_name_queries": 5000}, "invalid_schema"),  # por encima del tope DNS del servidor
        ({"identify": "yes"}, "invalid_schema"),
        ({"schema_version": 1}, "invalid_schema"),  # claves de v2 con versión 1
    ],
)
def test_v2_job_is_validated_exactly(overrides: dict[str, Any], code: str) -> None:
    with pytest.raises(JobRejectedError) as info:
        validate(v2_job(**overrides))
    assert info.value.code == code


# --- Scanner con sondas de nombre -----------------------------------------------------------------


class FakeIdentity:
    def __init__(self) -> None:
        self.searched: set[str] = set()
        self.calls: list[tuple[str, str]] = []

    async def mdns_name(self, address: str, timeout: float) -> str | None:
        self.calls.append(("mdns", address))
        return "Echo-Salon" if address == "10.0.0.2" else None

    async def netbios_name(self, address: str, timeout: float) -> str | None:
        self.calls.append(("netbios", address))
        raise OSError("port unreachable")

    async def ssdp_search(
        self, addresses: Collection[str], window: float
    ) -> dict[str, names.SsdpResponse]:
        self.searched = set(addresses)
        return {"10.0.0.2": names.SsdpResponse("10.0.0.2", "Roku/9", "http://10.0.0.2:8060/")}

    async def upnp_description(
        self, response: names.SsdpResponse, timeout: float
    ) -> names.UpnpDescription | None:
        self.calls.append(("upnp", response.address))
        return names.UpnpDescription(friendly_name="Roku Salon", manufacturer="Roku, Inc.")


def scan_params(**overrides: Any) -> DiscoveryParameters:
    values: dict[str, Any] = {
        "target": ipaddress.ip_network("10.0.0.0/29"),
        "ports": (80,),
        "timeout_ms": 200,
        "concurrency": 8,
        "max_probes_per_second": 10_000,
        "icmp": False,
        "reverse_dns": False,
        "arp": False,
        "deadline_seconds": 30,
        "identify": True,
        "max_name_queries": 100,
    }
    values.update(overrides)
    return DiscoveryParameters(**values)


def run(params: DiscoveryParameters, identity: FakeIdentity) -> tuple[Any, dict[str, Any]]:
    seen: list[dict[str, Any]] = []
    tcp = FakeTcp({("10.0.0.2", 80): "open", ("10.0.0.3", 80): "closed"})
    scanner = Scanner(
        params, lambda obs: seen.extend(o.to_json() for o in obs), tcp=tcp, identity=identity
    )
    report = scanner.run()
    return report, {o["address"]: o for o in seen}


def test_names_are_collected_only_for_live_hosts_and_errors_are_isolated() -> None:
    identity = FakeIdentity()
    report, found = run(scan_params(), identity)
    # El M-SEARCH se filtra con las direcciones del target; las sondas, solo a hosts vivos.
    assert identity.searched == {f"10.0.0.{i}" for i in range(1, 7)}
    assert {address for _, address in identity.calls} == {"10.0.0.2", "10.0.0.3"}
    echo = found["10.0.0.2"]["identity"]
    assert echo == {
        "mdns_name": "Echo-Salon",
        "ssdp_server": "Roku/9",
        "upnp": {"friendly_name": "Roku Salon", "manufacturer": "Roku, Inc."},
    }
    # Sin nada que informar no hay clave: el lote es igual al de un sensor 0.4.x.
    assert "identity" not in found["10.0.0.3"]
    assert any("netbios" in error for error in report.errors)


def test_name_probe_budget_is_respected() -> None:
    identity = FakeIdentity()
    report, _ = run(scan_params(max_name_queries=2), identity)
    # 1 consulta para el M-SEARCH + 1 sonda; el resto se omite y se informa una vez.
    assert len(identity.calls) == 1
    assert sum("name probe budget" in error for error in report.errors) == 1


def test_v1_job_sends_no_name_probes() -> None:
    identity = FakeIdentity()
    _, found = run(scan_params(identify=False, max_name_queries=None), identity)
    assert identity.calls == [] and identity.searched == set()
    assert all("identity" not in o for o in found.values())


def test_ipv6_hosts_skip_netbios_and_ssdp() -> None:
    identity = FakeIdentity()
    seen: list[dict[str, Any]] = []
    tcp = FakeTcp({("fd00::2", 80): "open"})
    params = scan_params(target=ipaddress.ip_network("fd00::/126"))
    scanner = Scanner(
        params, lambda obs: seen.extend(o.to_json() for o in obs), tcp=tcp, identity=identity
    )
    scanner.run()
    assert identity.searched == set()
    assert ("mdns", "fd00::2") in identity.calls
    assert not any(kind == "netbios" for kind, _ in identity.calls)
