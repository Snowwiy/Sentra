"""Fase 7A.4: identificación de dispositivos sin agente ni SNMP (docs/device-intelligence.md).

Primero los parsers de las huellas (DNS-SD, HTTP, certificado) y el motor de clasificación,
sin red ni base de datos; después las sondas reales contra servidores en 127.0.0.1 y, con
PostgreSQL, el discovery con huellas, el tipo manual y la lectura DHCP automática.
"""

import asyncio
import datetime as dt
import ssl
import struct
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.discovery import fingerprint
from app.discovery import profiles as profile_mod
from app.discovery.classify import (
    CONFLICT,
    MANUAL,
    MDNS_SERVICE,
    WEB,
    IdentityInput,
    WebEvidence,
    identify,
)
from app.discovery.device_types import ClassificationConfidence, DeviceType, compatible
from app.discovery.fingerprint import MdnsServices, WebFingerprint
from app.discovery.scanner import ScanConfig
from app.discovery.targets import DiscoveryScope
from app.models.asset import Asset
from app.models.audit import AuditEvent
from app.models.dhcp import AssetIdentityHistory
from app.models.site import SensorJob
from app.schemas.site import SensorIdentityIn
from app.services.alert_service import AlertThresholds
from app.services.discovery_service import DiscoveryConfig, DiscoveryService
from app.services.sensor_service import _identity_fields
from tests.conftest import authenticate
from tests.test_dhcp_identity import _sensor, _sensor_source
from tests.test_discovery_service import Host, Lab

API = "/api/v1"
T = DeviceType


# --- Parsers --------------------------------------------------------------------------------


def _name(value: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in value.split(".")) + b"\x00"


def _rr(name: str, rtype: int, rdata: bytes) -> bytes:
    return _name(name) + struct.pack("!HHIH", rtype, 1, 120, len(rdata)) + rdata


def _response(qid: int, question: str, qtype: int, answers: list[bytes]) -> bytes:
    header = struct.pack("!HHHHHH", qid, 0x8400, 1, len(answers), 0, 0)
    return header + _name(question) + struct.pack("!HH", qtype, 1) + b"".join(answers)


def test_dns_sd_service_types_are_parsed_and_bounded() -> None:
    question = "_services._dns-sd._udp.local"
    answers = [
        _rr(question, 12, _name("_ipp._tcp.local")),
        _rr(question, 12, _name("_pdl-datastream._tcp.local")),
        _rr(question, 12, _name("_ipp._tcp.local")),  # duplicado
        _rr(question, 12, _name("not a service.local")),  # inválido
        _rr("otro.local", 12, _name("_hap._tcp.local")),  # otra pregunta
    ]
    message = _response(77, question, 12, answers)
    assert fingerprint.parse_service_types(message, 77) == ("_ipp._tcp", "_pdl-datastream._tcp")
    # Otro id (respuesta ajena o falsificada): nada.
    assert fingerprint.parse_service_types(message, 78) == ()
    assert fingerprint.parse_service_types(b"\x00" * 5, 77) == ()


def test_device_info_model_from_ptr_and_txt() -> None:
    question = "_device-info._tcp.local"
    instance = "Portatil de Ana._device-info._tcp.local"
    txt = b"".join(bytes([len(v)]) + v for v in (b"model=MacBookPro18,3", b"osxvers=23"))
    message = _response(
        5, question, 12, [_rr(question, 12, _name(instance)), _rr(instance, 16, txt)]
    )
    assert fingerprint.parse_device_info(message, 5) == (instance, "MacBookPro18,3")


def test_http_response_server_and_title() -> None:
    raw = (
        b"HTTP/1.1 200 OK\r\nServer: App-webs/\r\nContent-Type: text/html\r\n\r\n"
        b"<html><head><TITLE> Network &amp; Camera\n</title></head></html>"
    )
    assert fingerprint.parse_http_response(raw) == (200, "App-webs/", "Network & Camera")
    # Sin 200 no se lee título (una página de login genérica o un 401 no identifica).
    raw401 = b"HTTP/1.0 401 Unauthorized\r\nServer: lighttpd\x01\r\n\r\n<title>x</title>"
    assert fingerprint.parse_http_response(raw401) == (401, "lighttpd", None)
    assert fingerprint.parse_http_response(b"SSH-2.0-OpenSSH") == (None, None, None)


def _certificate(tmp_path: Path, cn: str, org: str) -> tuple[bytes, Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        ]
    )
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert.public_bytes(serialization.Encoding.DER), cert_path, key_path


def test_certificate_names_reads_subject_and_issuer(tmp_path: Path) -> None:
    der, _, _ = _certificate(tmp_path, "DS-2CD2143G0-I", "Hikvision")
    subject, issuer = fingerprint.certificate_names(der)
    assert subject == {"cn": "DS-2CD2143G0-I", "o": "Hikvision"} and issuer == subject
    # Un DER roto o truncado no rompe nada: solo "sin datos".
    assert fingerprint.certificate_names(der[:40]) == ({}, {})
    assert fingerprint.certificate_names(b"\x30\x84\xff\xff\xff\xff") == ({}, {})


def _server_flight(der: bytes, cut: int) -> bytes:
    """ServerHello + Certificate repartidos en dos registros TLS 1.2, como hacen muchos equipos."""
    server_hello = (
        bytes([2]) + (38).to_bytes(3, "big") + b"\x03\x03" + bytes(32) + b"\x00\xc0\x2b\x00"
    )
    chain = len(der).to_bytes(3, "big") + der
    certificate = bytes([11]) + (len(chain) + 3).to_bytes(3, "big")
    certificate += len(chain).to_bytes(3, "big") + chain
    stream = server_hello + certificate
    parts = (stream[:cut], stream[cut:])
    return b"".join(bytes([22, 3, 3]) + len(p).to_bytes(2, "big") + p for p in parts)


def test_tls_certificate_is_read_from_the_clear_handshake(tmp_path: Path) -> None:
    der, _, _ = _certificate(tmp_path, "AXIS M3046-V", "Axis Communications AB")
    hello = fingerprint.build_client_hello(bytes(32))
    # Un único registro de saludo con un ClientHello TLS 1.2.
    assert hello[0] == 22 and hello[5] == 1 and hello[9:11] == b"\x03\x03"
    assert int.from_bytes(hello[3:5], "big") == len(hello) - 5
    flight = _server_flight(der, 50)
    assert fingerprint.certificate_from_handshake(flight[:30]) == (False, None)
    assert fingerprint.certificate_from_handshake(flight) == (True, der)
    # Una alerta, un servicio que no es TLS o el fin del saludo sin certificado: se para ahí.
    assert fingerprint.certificate_from_handshake(bytes([21, 3, 3, 0, 2, 2, 40])) == (True, None)
    assert fingerprint.certificate_from_handshake(b"HTTP/1.1 400 Bad Request\r\n") == (
        True,
        None,
    )
    done = bytes([22, 3, 3, 0, 4, 14, 0, 0, 0])
    assert fingerprint.certificate_from_handshake(done) == (True, None)
    # Una cadena declarada más larga que el mensaje no se lee fuera de límites.
    broken = bytes([22, 3, 3, 0, 10, 11, 0, 0, 6, 0, 0, 3, 0, 0, 9])
    assert fingerprint.certificate_from_handshake(broken) == (True, None)


def test_sensor_schema_follows_declared_capabilities() -> None:
    """v3 solo para sensores 0.7.0 con la capability; los anteriores reciben su esquema exacto."""
    settings = get_settings()
    standard = profile_mod.resolve(settings, "standard", can_tune=False)
    old = standard.parameters("10.0.0.0/28", for_sensor=True)
    assert old["schema_version"] == 1 and "fingerprint" not in old
    names = standard.parameters("10.0.0.0/28", for_sensor=True, sensor_names=True)
    assert names["schema_version"] == 2 and "fingerprint" not in names
    full = standard.parameters(
        "10.0.0.0/28", for_sensor=True, sensor_names=True, sensor_fingerprint=True
    )
    assert full["schema_version"] == 3 and full["fingerprint"] is True
    # El perfil quick no toma huellas aunque el sensor sepa hacerlo.
    quick = profile_mod.resolve(settings, "quick", can_tune=False)
    assert "fingerprint" not in quick.parameters(
        "10.0.0.0/28", for_sensor=True, sensor_names=True, sensor_fingerprint=True
    )


def test_only_open_web_ports_are_fingerprinted() -> None:
    assert fingerprint.pick_ports({22, 8080, 80, 443, 8443}) == [(80, False), (443, True)]
    assert fingerprint.pick_ports({22, 3389}) == []


# --- Motor de clasificación -----------------------------------------------------------------


def test_new_types_and_families() -> None:
    assert {T.IP_CAMERA.value, T.DVR_NVR.value, T.NETWORK_DEVICE.value} <= {t.value for t in T}
    assert compatible(T.IP_CAMERA, T.IOT) and compatible(T.DVR_NVR, T.IP_CAMERA)
    assert not compatible(T.IP_CAMERA, T.SMART_TV)
    assert compatible(T.NETWORK_DEVICE, T.ROUTER)


def test_printer_from_dns_sd_services() -> None:
    result = identify(
        IdentityInput(mdns_services=frozenset({"_ipp._tcp", "_ipps._tcp", "_scanner._tcp"}))
    )
    assert result.device_type == T.PRINTER
    assert result.confidence in (ClassificationConfidence.MEDIUM, ClassificationConfidence.HIGH)
    assert any(e["source"] == MDNS_SERVICE for e in result.evidence)
    # Un servicio genérico no dice nada.
    assert identify(IdentityInput(mdns_services=frozenset({"_ssh._tcp"}))).device_type is None


def test_camera_and_recorder_from_web_fingerprints() -> None:
    camera = identify(
        IdentityInput(web=(WebEvidence(server="App-webs/"),), open_ports=frozenset({80, 554}))
    )
    assert camera.device_type == T.IP_CAMERA and camera.device_vendor == "Hikvision"
    assert any(e["source"] == WEB for e in camera.evidence)
    recorder = identify(IdentityInput(web=(WebEvidence(server="DNVRS-Webs"),)))
    assert recorder.device_type == T.DVR_NVR
    # Un servidor web genérico no identifica nada.
    plain = identify(IdentityInput(web=(WebEvidence(server="nginx", title="Welcome"),)))
    assert plain.device_type is None and plain.device_vendor is None
    # Una marca sola aporta la marca, nunca el tipo: Synology también fabrica routers.
    brand = identify(IdentityInput(web=(WebEvidence(title="Synology"),)))
    assert brand.device_type is None and brand.device_vendor == "Synology"
    router = identify(IdentityInput(web=(WebEvidence(title="Synology Router Manager"),)))
    assert router.device_type == T.ROUTER
    hik = identify(IdentityInput(web=(WebEvidence(cert_org="Hikvision"),)))
    assert hik.device_type is None and hik.device_vendor == "Hikvision"


def test_declared_model_names_the_device_without_inventing() -> None:
    result = identify(
        IdentityInput(mdns_model="MacBookPro18,3", mac="02:11:22:33:44:55", mac_random=True)
    )
    assert result.device_type == T.LAPTOP
    assert result.device_vendor == "Apple" and result.device_model == "MacBookPro18,3"
    assert result.probable_os == "macOS" or result.probable_os is None
    # Sin modelo declarado no se inventa uno a partir de una página web.
    web = identify(IdentityInput(web=(WebEvidence(title="Synology DiskStation"),)))
    assert web.device_type == T.NAS and web.device_model is None


def test_stale_fingerprints_are_kept_but_do_not_vote() -> None:
    result = identify(
        IdentityInput(
            mdns_services=frozenset({"_ipp._tcp"}),
            web=(WebEvidence(server="App-webs/"),),
            stale_sources=frozenset({MDNS_SERVICE, WEB}),
        )
    )
    assert result.device_type is None
    assert any("(antiguo)" in e["value"] for e in result.evidence)


def test_conflicting_fingerprints_leave_the_type_unknown() -> None:
    result = identify(
        IdentityInput(
            mdns_services=frozenset({"_ipp._tcp"}), web=(WebEvidence(server="App-webs/"),)
        )
    )
    # Impresora (3) frente a cámara (2): gana la impresora pero el conflicto queda visible.
    assert result.device_type == T.PRINTER
    assert any(e["source"] == CONFLICT for e in result.evidence)


def test_manual_type_wins_and_keeps_the_automatic_evidence() -> None:
    result = identify(IdentityInput(mdns_services=frozenset({"_ipp._tcp"}), manual_type=T.IOT))
    assert result.device_type == T.IOT and result.confidence == ClassificationConfidence.HIGH
    sources = [e["source"] for e in result.evidence]
    assert MANUAL in sources and CONFLICT in sources and MDNS_SERVICE in sources
    managed = identify(IdentityInput(managed=True, hostname="srv", manual_type=T.SERVER))
    assert managed.device_type == T.SERVER


# --- Sondas reales en 127.0.0.1 ---------------------------------------------------------------


async def _serve(handler: Any, ssl_context: ssl.SSLContext | None = None) -> tuple[Any, int]:
    server = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=ssl_context)
    return server, server.sockets[0].getsockname()[1]


def test_web_fingerprint_against_local_servers(tmp_path: Path) -> None:
    requests: list[bytes] = []

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        requests.append(await reader.readuntil(b"\r\n\r\n"))
        writer.write(
            b"HTTP/1.0 200 OK\r\nServer: Synology\r\nContent-Type: text/html\r\n\r\n"
            b"<title>DiskStation</title>" + b"x" * 100_000
        )
        await writer.drain()
        writer.close()

    _, cert_path, key_path = _certificate(tmp_path, "nas.lan", "Synology Inc.")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)

    (tmp_path / "cam").mkdir()
    camera_der, _, _ = _certificate(tmp_path / "cam", "ipcam", "Hikvision")
    received: list[bytes] = []

    async def raw_tls(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        received.append(await reader.read(4096))
        flight = _server_flight(camera_der, 60)
        writer.write(flight[:40])
        await writer.drain()
        await asyncio.sleep(0.05)
        writer.write(flight[40:])
        await writer.drain()
        # Lo que el cliente envíe después del certificado (debería ser nada).
        received.append(await reader.read())
        writer.close()

    async def scenario() -> tuple[WebFingerprint | None, ...]:
        plain, plain_port = await _serve(handler)
        secure, secure_port = await _serve(handler, context)
        raw, raw_port = await _serve(raw_tls)
        try:
            web = await fingerprint.web_fingerprint("127.0.0.1", plain_port, False, 2.0)
            tls = await fingerprint.web_fingerprint("127.0.0.1", secure_port, True, 2.0)
            camera = await fingerprint.web_fingerprint("127.0.0.1", raw_port, True, 2.0)
            # HTTP en un puerto que se esperaba TLS: sin huella, sin excepción.
            wrong = await fingerprint.web_fingerprint("127.0.0.1", plain_port, True, 1.0)
            closed = await fingerprint.web_fingerprint("127.0.0.1", 1, False, 1.0)
            await asyncio.sleep(0.1)
        finally:
            plain.close()
            secure.close()
            raw.close()
        return web, tls, camera, wrong, closed

    web, tls, camera, wrong, closed = asyncio.run(scenario())
    assert web == WebFingerprint(
        port=web.port if web else 0, tls=False, server="Synology", title="DiskStation"
    )
    # Un servidor TLS real (OpenSSL) entrega su certificado en el saludo TLS 1.2.
    assert tls is not None and tls.tls and tls.cert_cn == "nas.lan"
    assert tls.cert_org == "Synology Inc." and tls.self_signed is True
    assert tls.server is None and tls.title is None
    assert camera is not None and camera.cert_org == "Hikvision"
    # Solo se envió el ClientHello: la conexión se corta antes del intercambio de claves.
    assert len(received) == 2 and received[0][0] == 22 and received[1] == b""
    assert wrong is None and closed is None
    # Una sola petición GET / por puerto, sin credenciales ni cuerpo.
    assert all(r.startswith(b"GET / HTTP/1.0\r\n") and b"Authorization" not in r for r in requests)


# --- Discovery con huellas, tipo manual y DHCP automático (PostgreSQL) -------------------------


class FakeFingerprints:
    def __init__(self) -> None:
        self.web_calls: list[tuple[str, int, bool]] = []

    async def mdns_services(self, address: str, timeout: float) -> MdnsServices | None:
        if address.endswith(".7"):
            return MdnsServices(services=("_ipp._tcp", "_pdl-datastream._tcp"))
        return None

    async def web(
        self, address: str, port: int, tls: bool, timeout: float
    ) -> WebFingerprint | None:
        self.web_calls.append((address, port, tls))
        if address.endswith(".9"):
            return WebFingerprint(port=port, tls=tls, server="App-webs/", title="Web Camera")
        return None


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


def _discovery(engine: Engine, lab: Lab, fakes: FakeFingerprints) -> DiscoveryService:
    config = DiscoveryConfig(
        scope=DiscoveryScope.parse("10.20.0.0/28"),
        scan=ScanConfig(
            ports=(22, 80, 443, 554, 9100),
            timeout=0.5,
            concurrency=16,
            max_rate=5000,
            icmp=False,
            fingerprint=True,
        ),
        heartbeat_timeout=dt.timedelta(seconds=90),
    )
    thresholds = AlertThresholds(
        cpu_percent=90, ram_percent=90, disk_percent=90, sustained_samples=3,
        offline_after=dt.timedelta(seconds=90),
    )  # fmt: skip
    return DiscoveryService(
        sessionmaker(bind=engine, expire_on_commit=False),
        config,
        thresholds,
        prober_factory=lambda: lab,
        fingerprint_factory=lambda: fakes,
        gateways=lambda: set(),
    )


def test_discovery_identifies_printer_and_camera_automatically(engine: Engine, db: Session) -> None:
    lab = Lab(
        {
            "10.20.0.7": Host(ports={9100}, mac="00:00:00:00:00:07"),
            "10.20.0.9": Host(ports={80, 443, 554}, mac="00:00:00:00:00:09"),
            "10.20.0.11": Host(ports={22}, mac="00:00:00:00:00:11"),
        }
    )
    fakes = FakeFingerprints()
    _discovery(engine, lab, fakes).run()
    assets = {a.primary_ip: a for a in db.scalars(select(Asset))}
    printer, camera, other = assets["10.20.0.7"], assets["10.20.0.9"], assets["10.20.0.11"]
    assert printer.device_type == "printer"
    assert camera.device_type == "ip_camera" and camera.device_vendor == "Hikvision"
    assert other.device_type is None
    assert (camera.identity_observations or {})["web"][0]["server"] == "App-webs/"
    assert "web" in (camera.identity_observations or {})["seen_at"]
    # Solo puertos web abiertos de hosts vivos; nada en 22 ni en hosts sin web.
    assert sorted(fakes.web_calls) == [("10.20.0.9", 80, False), ("10.20.0.9", 443, True)]


def test_a_printer_maker_mac_conflicts_with_camera_evidence(
    engine: Engine, db: Session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Regresión de la validación en Windows: con el oui.csv del IEEE, la MAC 00:00:00:...
    # es de Xerox (impresoras) y contradice la huella web de cámara. Sentra no elige una de
    # las dos: deja el tipo sin decidir y registra el conflicto. El test anterior solo pasa
    # si la base OUI de los tests está fijada (conftest), no por el .env de desarrollo.
    oui_file = tmp_path / "oui.csv"
    oui_file.write_text(
        "Registry,Assignment,Organization Name,Organization Address\n"
        "MA-L,000000,XEROX CORPORATION,WEBSTER NY US\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("DISCOVERY_OUI_FILE", str(oui_file))
    get_settings.cache_clear()
    try:
        lab = Lab({"10.20.0.9": Host(ports={80, 443, 554}, mac="00:00:00:00:00:09")})
        _discovery(engine, lab, FakeFingerprints()).run()
    finally:
        monkeypatch.delenv("DISCOVERY_OUI_FILE")
        get_settings.cache_clear()
    camera = db.scalars(select(Asset)).one()
    assert camera.vendor == "XEROX CORPORATION"
    assert camera.device_type is None
    evidence = {item["source"]: item["value"] for item in camera.classification_evidence or []}
    assert evidence["mac_vendor"] == "Xerox" and "printer" in evidence["conflict"]
    assert "ip_camera" in evidence["conflict"]
    # La evidencia se conservó y llegó al clasificador: no se perdió por el camino.
    assert (camera.identity_observations or {})["web"][0]["server"] == "App-webs/"


def test_manual_device_type_endpoint(client: TestClient, engine: Engine, db: Session) -> None:
    lab = Lab({"10.20.0.7": Host(ports={9100}, mac="00:00:00:00:00:07")})
    _discovery(engine, lab, FakeFingerprints()).run()
    asset = db.scalars(select(Asset)).one()
    url = f"{API}/assets/{asset.public_id}/device-type"
    body = client.patch(url, json={"device_type": "iot", "version": 0})
    assert body.status_code == 200, body.text
    data = body.json()
    assert data["device_type"] == "iot" and data["manual_device_type"] == "iot"
    assert data["custom_label_version"] == 1
    stale = client.patch(url, json={"device_type": "pc", "version": 0})
    assert stale.status_code == 409 and stale.json()["error"]["code"] == "asset_label_conflict"
    invalid = client.patch(url, json={"device_type": "toaster", "version": 1})
    assert invalid.status_code == 422
    reset = client.patch(url, json={"device_type": None, "version": 1}).json()
    assert reset["device_type"] == "printer" and reset["manual_device_type"] is None
    events = db.scalars(
        select(AuditEvent).where(AuditEvent.action == "asset_device_type_changed")
    ).all()
    assert len(events) == 3 and {e.result for e in events} == {"success", "failure"}
    # El historial distingue el tipo puesto a mano del que vuelve a clasificar el motor.
    history = db.scalars(
        select(AssetIdentityHistory)
        .where(AssetIdentityHistory.field == "device_type")
        .order_by(AssetIdentityHistory.id)
    ).all()
    assert [(h.new_value, h.source) for h in history] == [
        ("iot", "manual"),
        ("printer", "classification"),
    ]
    with TestClient(client.app) as analyst:
        authenticate(analyst, engine, "analyst")
        denied = analyst.patch(url, json={"device_type": "pc", "version": 2})
        assert denied.status_code == 403


def test_sensor_fingerprints_are_validated_and_mapped() -> None:
    identity = SensorIdentityIn.model_validate(
        {
            "mdns_services": ["_ipp._tcp"],
            "mdns_model": "iPhone15,2",
            "web": [{"port": 443, "tls": True, "cert_cn": "cam01", "self_signed": True}],
        }
    )
    fields = _identity_fields("10.0.0.5", identity.model_dump(mode="json", exclude_none=True))
    assert fields["services"] == MdnsServices(services=("_ipp._tcp",), model="iPhone15,2")
    assert fields["web"] == [WebFingerprint(port=443, tls=True, cert_cn="cam01", self_signed=True)]
    with pytest.raises(ValueError):
        SensorIdentityIn.model_validate({"mdns_services": ["_ipp._tcp; rm -rf"]})
    with pytest.raises(ValueError):
        SensorIdentityIn.model_validate({"web": [{"port": 80, "tls": False}] * 3})


def test_dhcp_sources_are_read_after_a_complete_discovery(
    client: TestClient, engine: Engine, db: Session
) -> None:
    sensor = _sensor(client)
    _sensor_source(client, sensor)
    lab = Lab({"10.20.0.7": Host(ports={9100}, mac="00:00:00:00:00:07")})
    _discovery(engine, lab, FakeFingerprints()).run()
    jobs = db.scalars(select(SensorJob).where(SensorJob.job_type == "dhcp_leases")).all()
    assert len(jobs) == 1 and jobs[0].created_by == "discovery"
    # Un segundo discovery inmediato no relee el fichero (intervalo mínimo y job abierto).
    _discovery(engine, lab, FakeFingerprints()).run()
    db.expire_all()
    assert len(db.scalars(select(SensorJob).where(SensorJob.job_type == "dhcp_leases")).all()) == 1
