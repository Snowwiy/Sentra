"""Identificación de dispositivos (Fase 4E): nombre, tipo, fabricante, confianza y evidencias.

Sin red ni base de datos: el motor (classify.identify), la base OUI, los parsers de las
sondas de nombre y el scanner con dobles de prueba. Los prefijos OUI de estos tests son
datos de prueba escritos en ficheros temporales, no el registro real del IEEE.
"""

import asyncio
import contextlib
import ipaddress
import socket
import struct
import threading
import time
from collections.abc import Collection
from pathlib import Path
from typing import Any

import pytest

from app.discovery import names
from app.discovery.classify import IdentityInput, identify
from app.discovery.oui import OuiDatabase, is_locally_administered, load_database, parse_paths
from app.discovery.probes import PortState
from app.discovery.scanner import NetworkScanner, ScanConfig
from app.discovery.vendors import display_vendor, profile_for
from app.models.asset import Asset, MonitoringMethod
from app.services.asset_service import evidence_items
from app.services.identification import identity_input, record_observation, refresh_identity

HUAWEI = "HUAWEI TECHNOLOGIES CO.,LTD"
AMAZON = "Amazon Technologies Inc."
REALTEK = "Realtek Semiconductor Corp."


def ident(**kwargs: Any) -> Any:
    return identify(IdentityInput(**kwargs))


# --- Criterios de éxito de la fase ------------------------------------------------------------


def test_huawei_phone_by_model_code_and_oui_is_high_confidence() -> None:
    result = ident(reverse_dns="MNA-LX9.lan", mac_vendor=HUAWEI)
    assert result.name == "MNA-LX9" and result.name_source == "reverse_dns"
    assert result.device_type == "mobile" and result.device_vendor == "Huawei"
    assert result.device_model == "MNA-LX9" and result.confidence == "high"
    assert {"source": "mac_vendor", "value": "Huawei"} in result.evidence
    assert {"source": "reverse_dns", "value": "MNA-LX9"} in result.evidence
    # Desde la red no se demuestra el SO de un Huawei (Android o HarmonyOS): no se inventa.
    assert result.probable_os is None


def test_same_name_without_vendor_confirmation_is_only_probable() -> None:
    # MAC aleatoria (privacidad): sin fabricante que confirme el código de modelo.
    result = ident(reverse_dns="MNA-LX9", mac="da:a1:19:00:00:01", mac_random=True)
    assert result.device_type == "mobile" and result.confidence == "medium"
    assert result.device_model is None  # el modelo no se afirma con una sola pista
    assert {"source": "mac_random", "value": "MAC aleatoria (privacidad): sin fabricante"} in (
        result.evidence
    )


def test_alexa_is_a_voice_assistant_from_amazon() -> None:
    result = ident(reverse_dns="Alexa", mac_vendor=AMAZON)
    assert (result.name, result.device_type, result.device_vendor) == (
        "Alexa",
        "voice_assistant",
        "Amazon",
    )
    assert result.confidence == "high"
    assert ident(reverse_dns="Alexa").confidence == "medium"  # sin OUI compatible


def test_default_gateway_is_a_router() -> None:
    result = ident(is_gateway=True, open_ports=frozenset({53, 80, 443}))
    assert result.device_type == "router" and result.confidence == "high"
    assert result.name is None  # la UI muestra "Router" + IP, no inventa un nombre


def test_realtek_nic_alone_says_nothing_about_the_device() -> None:
    result = ident(mac_vendor=REALTEK)
    assert result.network_adapter_vendor == "Realtek"
    assert result.device_vendor is None and result.device_type is None
    assert result.confidence is None
    # Ni con puertos de Windows se convierte en "PC Realtek".
    windows = ident(mac_vendor=REALTEK, open_ports=frozenset({135, 445}))
    assert windows.device_vendor is None and windows.confidence == "low"


def test_realtek_adapter_on_a_console_is_a_probable_console() -> None:
    result = ident(mac_vendor=REALTEK, reverse_dns="Nintendo-Switch")
    assert result.device_type == "console" and result.confidence == "medium"
    assert result.network_adapter_vendor == "Realtek"
    # El fabricante sale del nombre, no de la NIC; el modelo no se afirma.
    assert result.device_vendor == "Nintendo" and result.device_model is None


def test_unknown_device_stays_unknown() -> None:
    result = ident()
    assert (result.name, result.device_type, result.device_vendor, result.confidence) == (
        None,
        None,
        None,
        None,
    )
    assert result.evidence == []


# --- Prioridad del nombre ---------------------------------------------------------------------


def test_naming_priority() -> None:
    every = {
        "reverse_dns": "dns-name.lan",
        "mdns_name": "mdns-name",
        "netbios_name": "NETBIOSNAME",
        "upnp_friendly_name": "Salón TV",
    }
    assert ident(**every).name_source == "reverse_dns"
    assert ident(**{**every, "reverse_dns": None}).name == "mdns-name"
    assert ident(netbios_name="NETBIOSNAME", upnp_friendly_name="TV").name == "NETBIOSNAME"
    assert ident(upnp_friendly_name="Salón TV").name_source == "upnp"
    vendor_model = ident(upnp_manufacturer="Synology Inc.", upnp_model_name="DS920+")
    assert (vendor_model.name, vendor_model.name_source) == ("Synology DS920+", "vendor_model")
    managed = ident(managed=True, hostname="Ravenslg", reverse_dns="otro.lan", os_name="Linux")
    assert (managed.name, managed.name_source) == ("Ravenslg", "agent_hostname")


def test_reverse_dns_names_are_cleaned() -> None:
    assert ident(reverse_dns="mna-lx9.home.arpa").name == "mna-lx9"
    assert ident(reverse_dns="pc01.corp.example").name == "pc01.corp.example"  # FQDN real
    # Rellenos del router: la propia IP o nombres genéricos no son nombres.
    assert ident(reverse_dns="192-168-50-12.lan").name is None
    assert ident(reverse_dns="localhost").name is None
    assert ident(reverse_dns="dhcp-50-12").name is None


# --- Confianza ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({"open_ports": frozenset({3389})}, "low"),  # una pista débil
        ({"reverse_dns": "iphone-de-ana"}, "medium"),  # una pista clara
        ({"is_gateway": True}, "high"),  # fuente autoritativa
        ({"open_ports": frozenset({9100}), "mac_vendor": "Brother Industries, LTD."}, "high"),
    ],
)
def test_confidence_levels(kwargs: dict[str, Any], expected: str) -> None:
    assert ident(**kwargs).confidence == expected


def test_conflicting_evidence_is_not_resolved_by_guessing() -> None:
    # Un nombre de impresora y la marca de consola empatan: tipo desconocido, no al azar.
    result = ident(reverse_dns="printer-1", mac_vendor="Nintendo Co.,Ltd")
    assert result.device_type is None


def test_probable_os_needs_enough_evidence_and_never_has_a_version() -> None:
    assert ident(open_ports=frozenset({3389})).probable_os is None  # un solo puerto
    assert ident(open_ports=frozenset({135, 445})).probable_os == "Windows"
    assert ident(reverse_dns="android-1a2b3c4d5e6f").probable_os == "Android"
    assert ident(reverse_dns="iPhone").probable_os == "iOS"


def test_managed_data_overrides_network_inference() -> None:
    # Desde la red parecería una impresora; el agente dice que es un equipo Linux.
    result = ident(
        managed=True,
        hostname="Ravenslg",
        os_name="Linux",
        os_version="6.8",
        open_ports=frozenset({9100}),
        reverse_dns="printer.lan",
    )
    assert (result.device_type, result.confidence, result.name) == ("pc", "high", "Ravenslg")
    assert result.probable_os is None
    assert {"source": "agent_os", "value": "Linux 6.8"} in result.evidence
    server = ident(managed=True, hostname="SRV", os_name="Windows", os_version="Server 2022")
    assert server.device_type == "server"
    vm = ident(managed=True, hostname="lab", os_name="Linux", mac_vendor="VMware, Inc.")
    assert vm.device_type == "virtual_machine"


def test_evidence_and_texts_are_bounded() -> None:
    long = "x" * 500
    result = ident(upnp_friendly_name=long, upnp_manufacturer=long, ssdp_server=long)
    assert all(len(item["value"]) <= 128 for item in result.evidence)
    assert result.name is not None and len(result.name) <= 255


# --- OUI ----------------------------------------------------------------------------------------


def test_oui_database_loads_ieee_csv_and_txt(tmp_path: Path) -> None:
    csv_file = tmp_path / "oui.csv"
    csv_file.write_text(
        "Registry,Assignment,Organization Name,Organization Address\n"
        'MA-L,A40000,"HUAWEI TECHNOLOGIES CO.,LTD",Shenzhen\n'
        "MA-L,001122,IEEE Registration Authority,\n"
        "MA-M,0011223,Small Maker Ltd,\n"
        "MA-L,ZZZZZZ,Bad Row,\n",
        encoding="utf-8",
    )
    txt_file = tmp_path / "oui.txt"
    txt_file.write_text("D4-EE-FF   (hex)\t\tRealtek Semiconductor Corp.\n", encoding="utf-8")
    database = load_database(parse_paths(f"{csv_file}, {txt_file}"))
    assert database.lookup("a4:00:00:01:02:03") == HUAWEI
    assert database.lookup("00:11:22:30:00:01") == "Small Maker Ltd"  # prefijo más largo
    assert database.lookup("00:11:22:40:00:01") == "IEEE Registration Authority"
    assert database.lookup("d4:ee:ff:00:00:01") == REALTEK
    assert database.lookup("12:34:56:00:00:01") is None  # desconocido: no se inventa
    assert database.lookup("garbage") is None


def test_oui_missing_or_broken_file_never_breaks_discovery(tmp_path: Path) -> None:
    assert len(load_database([str(tmp_path / "missing.csv")])) == 0
    broken = tmp_path / "broken.csv"
    broken.write_bytes(b"\xff\xfe\x00garbage")
    assert len(load_database([str(broken)])) == 0


def test_random_and_virtual_macs() -> None:
    database = OuiDatabase({"DAA119": "Should Not Match"})
    assert is_locally_administered("da:a1:19:00:00:01")
    assert database.lookup("da:a1:19:00:00:01") is None
    # 52:54:00 es localmente administrado pero es la NIC por defecto de QEMU/KVM.
    assert not is_locally_administered("52:54:00:12:34:56")
    assert database.lookup("52:54:00:12:34:56") == "QEMU/KVM virtual NIC"
    assert ident(managed=True, hostname="vm", mac_vendor="QEMU/KVM virtual NIC").device_type == (
        "virtual_machine"
    )


def test_vendor_profiles() -> None:
    assert display_vendor(HUAWEI) == "Huawei"
    assert display_vendor("Foo Technologies Co., Ltd.") == "Foo"
    realtek = profile_for(REALTEK)
    assert realtek is not None and realtek.kind == "component"
    assert profile_for("Unknown Maker") is None


# --- Activos guardados ---------------------------------------------------------------------------


def _asset(**kwargs: Any) -> Asset:
    values: dict[str, Any] = {"primary_ip": "192.168.50.141", "monitoring_method": "discovered"}
    values.update(kwargs)
    return Asset(**values)


def test_refresh_identity_resolves_vendor_from_the_mac() -> None:
    database = OuiDatabase({"A40000": HUAWEI})
    asset = _asset(mac_address="a4:00:00:00:00:01", reverse_dns="MNA-LX9")
    change = refresh_identity(asset, (), database)
    assert asset.vendor == HUAWEI and asset.device_type == "mobile"
    assert asset.device_name == "MNA-LX9" and asset.classification_confidence == "high"
    # Primera clasificación (sin confianza previa): no es un "cambio" del dispositivo.
    assert not change.reclassified


def test_reclassification_is_reported_only_between_engine_results() -> None:
    database = OuiDatabase()
    asset = _asset()
    refresh_identity(asset, (), database)
    assert asset.device_type is None
    asset.reverse_dns = "android-0011aabb"
    change = refresh_identity(asset, (), database)
    # Antes "desconocido" sin confianza: tampoco es un cambio que registrar.
    assert change.previous_type is None and not change.reclassified
    asset.reverse_dns = "iphone-de-ana"
    change = refresh_identity(asset, (), database)
    assert change.device_type == "mobile" and not change.reclassified  # mismo tipo
    asset.identity_observations = {"gateway": True}
    asset.reverse_dns = None
    change = refresh_identity(asset, (), database)
    assert (change.previous_type, change.device_type, change.reclassified) == (
        "mobile",
        "router",
        True,
    )


def test_random_mac_clears_a_stale_vendor() -> None:
    asset = _asset(mac_address="da:a1:19:00:00:01", vendor="Old Vendor")
    refresh_identity(asset, (), OuiDatabase())
    assert asset.vendor is None


def test_observations_keep_previous_values() -> None:
    from app.discovery.scanner import HostObservation

    asset = _asset()
    first = HostObservation("192.168.50.141", mdns_name="tv-salon", netbios_name="TV")
    first.upnp = names.UpnpDescription(friendly_name="Salón", manufacturer="LG Electronics")
    record_observation(asset, first, is_gateway=False)
    # Un scan en el que no respondió a mDNS ni se pudo leer la tabla de rutas.
    record_observation(asset, HostObservation("192.168.50.141", netbios_name="TV2"), None)
    seen = asset.identity_observations or {}
    assert seen["mdns_name"] == "tv-salon" and seen["netbios_name"] == "TV2"
    assert seen["upnp"] == {"friendly_name": "Salón", "manufacturer": "LG Electronics"}
    assert seen["gateway"] is False
    data = identity_input(asset, [80])
    assert data.upnp_manufacturer == "LG Electronics" and data.open_ports == frozenset({80})


def test_malformed_stored_evidence_is_ignored() -> None:
    raw = [
        {"source": "mdns", "value": "tv"},
        {"source": 1, "value": "x"},
        "garbage",
        {"source": "ports"},
        None,
    ]
    assert [e.model_dump() for e in evidence_items(raw)] == [{"source": "mdns", "value": "tv"}]
    assert evidence_items({"not": "a list"}) == []
    assert evidence_items(None) == []


def test_managed_asset_identity() -> None:
    asset = Asset(
        primary_ip="192.168.50.66",
        monitoring_method=MonitoringMethod.AGENT,
        agent_id=__import__("uuid").uuid4(),
        hostname="Ravenslg",
        os_name="Linux",
        os_version="Ubuntu 24.04",
        probable_os="Windows",
    )
    refresh_identity(asset, [445, 135], OuiDatabase())
    assert asset.device_name == "Ravenslg" and asset.device_type == "pc"
    assert asset.probable_os is None  # con agente manda os_name


# --- Parsers de las sondas de nombre --------------------------------------------------------------


def _dns_response(query_id: int, question: str, answer: bytes, flags: int = 0x8400) -> bytes:
    def encode(name: str) -> bytes:
        return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"

    header = struct.pack("!HHHHHH", query_id, flags, 1, 1, 0, 0)
    body = encode(question) + struct.pack("!HH", 12, 1)
    # Respuesta con puntero de compresión a la pregunta (offset 12).
    record = b"\xc0\x0c" + struct.pack("!HHIH", 12, 1, 120, len(answer)) + answer
    return header + body + record


def test_mdns_ptr_round_trip() -> None:
    question = names.reverse_pointer("192.168.50.20")
    query = names.build_ptr_query(question, 0x1234)
    assert query[:2] == b"\x12\x34" and question.split(".")[0] == "20"
    answer = b"\x07MacBook\x05local\x00"
    response = _dns_response(0x1234, question, answer)
    assert names.parse_ptr_response(response, 0x1234) == "MacBook"
    assert names.parse_ptr_response(response, 0x9999) is None  # id distinto
    assert names.parse_ptr_response(response[:20], 0x1234) is None  # truncada
    assert names.parse_ptr_response(b"", 0x1234) is None


def test_dns_compression_loops_are_rejected() -> None:
    header = struct.pack("!HHHHHH", 1, 0x8400, 0, 1, 0, 0)
    looping = header + b"\xc0\x0c" + struct.pack("!HHIH", 12, 1, 0, 2) + b"\xc0\x0c"
    assert names.parse_ptr_response(looping, 1) is None


def test_netbios_status_response() -> None:
    query = names.build_nbstat_query(7)
    assert len(query) == 12 + 34 + 4 and query[12] == 0x20
    entries = [
        (b"WORKGROUP      ", 0x00, 0x8400),  # grupo: no es el nombre del equipo
        (b"SALON-PC       ", 0x00, 0x0400),
        (b"SALON-PC       ", 0x20, 0x0400),
    ]
    rdata = bytes([len(entries)]) + b"".join(
        name + bytes([suffix]) + struct.pack("!H", flags) for name, suffix, flags in entries
    )
    rdata += b"\x00" * 6  # MAC de la respuesta, ignorada
    message = (
        struct.pack("!HHHHHH", 7, 0x8400, 0, 1, 0, 0)
        + query[12:46]
        + struct.pack("!HHIH", 0x21, 1, 0, len(rdata))
        + rdata
    )
    assert names.parse_nbstat_response(message, 7) == "SALON-PC"
    assert names.parse_nbstat_response(message, 8) is None
    assert names.parse_nbstat_response(message[:60], 7) is None


def test_ssdp_response_and_location_safety() -> None:
    raw = (
        b"HTTP/1.1 200 OK\r\nSERVER: Linux/4.9 UPnP/1.0 Roku/9.4\r\n"
        b"LOCATION: http://192.168.50.30:8060/\r\nST: upnp:rootdevice\r\n\r\n"
    )
    parsed = names.parse_ssdp_response("192.168.50.30", raw)
    assert parsed is not None and parsed.location == "http://192.168.50.30:8060/"
    assert parsed.server == "Linux/4.9 UPnP/1.0 Roku/9.4"
    # Un LOCATION hacia otra IP, HTTPS, credenciales o algo que no es HTTP se descarta (SSRF).
    for location in (
        "http://10.0.0.1/desc.xml",
        "https://192.168.50.30/desc.xml",
        "http://user:pw@192.168.50.30/",
        "file:///etc/passwd",
        "http://192.168.50.30:99999/",
    ):
        assert names.safe_location("192.168.50.30", location) is None
    assert names.parse_ssdp_response("192.168.50.30", b"NOTIFY * HTTP/1.1\r\n\r\n") is None


def test_upnp_description_parsing_is_defensive() -> None:
    xml = (
        b'<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device>'
        b"<deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>"
        b"<friendlyName>[TV] Samsung 7 Series</friendlyName><manufacturer>Samsung Electronics"
        b"</manufacturer><modelName>UE55RU7105</modelName></device></root>"
    )
    description = names.parse_description(xml)
    assert description is not None and description.model_name == "UE55RU7105"
    result = ident(
        upnp_friendly_name=description.friendly_name,
        upnp_manufacturer=description.manufacturer,
        upnp_model_name=description.model_name,
        upnp_device_type=description.device_type,
    )
    assert (result.device_type, result.device_vendor, result.device_model) == (
        "smart_tv",
        "Samsung",
        "UE55RU7105",
    )
    bomb = b'<!DOCTYPE r [<!ENTITY a "aaaa">]><root><device><friendlyName>&a;</friendlyName>'
    assert names.parse_description(bomb + b"</device></root>") is None
    assert names.parse_description(b"<root><device>") is None  # XML roto
    assert names.parse_description(b"<root><other/></root>") is None


# --- Scanner con sondas de nombre -----------------------------------------------------------------


class FakeNetwork:
    async def tcp(self, address: Any, port: int, timeout: float) -> PortState:
        return PortState.OPEN if str(address) == "10.0.0.2" and port == 80 else PortState.FILTERED

    async def ping(self, address: Any, timeout_ms: int) -> bool | None:
        return str(address) in ("10.0.0.2", "10.0.0.3")

    def neighbours(self) -> dict[str, str]:
        return {}

    async def reverse_dns(self, address: Any, timeout: float) -> str | None:
        return None


class FakeIdentity:
    def __init__(self) -> None:
        self.searched: set[str] = set()

    async def mdns_name(self, address: str, timeout: float) -> str | None:
        return "tv-salon" if address == "10.0.0.2" else None

    async def netbios_name(self, address: str, timeout: float) -> str | None:
        raise OSError("port unreachable")

    async def ssdp_search(
        self, addresses: Collection[str], window: float
    ) -> dict[str, names.SsdpResponse]:
        self.searched = set(addresses)
        return {
            "10.0.0.2": names.SsdpResponse("10.0.0.2", "Roku/9", "http://10.0.0.2:8060/"),
        }

    async def upnp_description(
        self, response: names.SsdpResponse, timeout: float
    ) -> names.UpnpDescription | None:
        return names.UpnpDescription(friendly_name="Roku Salón", manufacturer="Roku, Inc.")


def test_scanner_collects_names_and_survives_probe_errors() -> None:
    identity = FakeIdentity()
    scanner = NetworkScanner(
        ScanConfig(ports=(80,), timeout=0.2, max_rate=10_000), FakeNetwork(), identity=identity
    )
    targets = [ipaddress.ip_address(f"10.0.0.{i}") for i in range(1, 5)]
    result = asyncio.run(scanner.scan(targets))
    found = {o.address: o for o in result.observations}
    assert identity.searched == {"10.0.0.2", "10.0.0.3"}  # solo hosts vivos del scan
    tv = found["10.0.0.2"]
    assert tv.mdns_name == "tv-salon" and tv.netbios_name is None
    assert tv.upnp is not None and tv.upnp.manufacturer == "Roku, Inc."
    assert found["10.0.0.3"].upnp is None
    # Un fallo de una sonda queda como error del job, no rompe el scan.
    assert any("netbios" in error for error in result.errors)


def test_scanner_without_injected_identity_sends_no_name_probes() -> None:
    # Con un prober de prueba y sin sondas de identidad inyectadas, nada sale a la red.
    scanner = NetworkScanner(ScanConfig(ports=(80,)), FakeNetwork())
    assert scanner._identity is None
    disabled = NetworkScanner(
        ScanConfig(ports=(80,), identify=False), FakeNetwork(), None, FakeIdentity()
    )
    assert disabled._identity is None


# --- Timeouts reales en loopback (sin Internet) ---------------------------------------------


def test_udp_query_times_out_and_answers_on_loopback() -> None:
    silent = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    silent.bind(("127.0.0.1", 0))
    echo.bind(("127.0.0.1", 0))

    def reply() -> None:
        data, addr = echo.recvfrom(512)
        echo.sendto(b"pong:" + data, addr)

    thread = threading.Thread(target=reply, daemon=True)
    thread.start()
    try:
        started = time.monotonic()
        assert asyncio.run(names.udp_query("127.0.0.1", silent.getsockname()[1], b"x", 0.2)) is None
        assert time.monotonic() - started < 2
        answer = asyncio.run(names.udp_query("127.0.0.1", echo.getsockname()[1], b"ping", 2))
        assert answer == b"pong:ping"
    finally:
        thread.join(timeout=2)
        silent.close()
        echo.close()


def test_http_get_is_bounded_and_requires_200() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen()
    port = server.getsockname()[1]
    responses = [
        b"HTTP/1.1 200 OK\r\n\r\n" + b"a" * (names.MAX_DESCRIPTION_BYTES * 2),
        b"HTTP/1.1 404 Not Found\r\n\r\n<root/>",
    ]

    def serve() -> None:
        for response in responses:
            conn, _ = server.accept()
            with conn:
                conn.recv(1024)
                with contextlib.suppress(OSError):
                    conn.sendall(response)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        body = asyncio.run(names.http_get(f"http://127.0.0.1:{port}/desc.xml", 2))
        assert body is not None and len(body) <= names.MAX_DESCRIPTION_BYTES + 8192
        assert asyncio.run(names.http_get(f"http://127.0.0.1:{port}/", 2)) is None
    finally:
        thread.join(timeout=2)
        server.close()


def test_ambiguous_names_do_not_trigger_hints() -> None:
    # "echo-server" no es un Echo de Amazon; "switch-salon" puede ser una consola o un switch.
    assert ident(reverse_dns="echo-server").device_type is None
    assert ident(reverse_dns="switch-salon").device_type is None
    assert ident(reverse_dns="srv-db1").device_type is None  # no es un código Huawei
    honor = ident(reverse_dns="ANY-LX1", mac_vendor="Honor Device Co., Ltd.")
    assert (honor.device_vendor, honor.device_model, honor.confidence) == (
        "Honor",
        "ANY-LX1",
        "high",
    )
    samsung = ident(reverse_dns="Galaxy-S21", mac_vendor="Samsung Electronics Co.,Ltd")
    assert samsung.device_type == "mobile" and samsung.device_model is None
