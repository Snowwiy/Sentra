"""Corrección 6C: identidad automática con procedencia y etiqueta personalizada de activos.

Red simulada (Lab de test_discovery_service), sondas de nombre falsas y base OUI de prueba
en memoria: nada sale a la red. El caso real que motivó la corrección es el de
192.168.50.78: DNS inverso `linux.local` y NIC Amazon (un Echo con Linux embebido).
"""

from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.discovery.classify import IdentityInput, identify
from app.discovery.oui import OuiDatabase
from app.discovery.scanner import HostObservation
from app.discovery.targets import DiscoveryScope
from app.models.asset import Asset
from app.models.audit import AuditEvent
from app.schemas.asset import normalize_label
from app.services import discovery_service, identification
from app.services.identification import record_observation, record_reverse_dns, refresh_identity
from tests.conftest import agent_payload, authenticate
from tests.test_discovery_service import Host, Lab
from tests.test_identification_discovery import _service as _home_service

API = "/api/v1/assets"
AMAZON = "Amazon Technologies Inc."
OUI = OuiDatabase({"A40002": AMAZON, "A40005": "Intel Corporate"})
ECHO_IP = "192.168.50.78"
ECHO_MAC = "a4:00:02:00:00:78"


@pytest.fixture(autouse=True)
def oui(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(identification, "oui_database", lambda: OUI)
    monkeypatch.setattr(discovery_service, "oui_database", lambda: OUI)


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


def _service(engine: Engine, lab: Lab) -> discovery_service.DiscoveryService:
    # El servicio de test_identification_discovery cubre 192.168.50.0/27; el caso real está
    # en la .78, así que se amplía el alcance sin tocar el resto de su configuración.
    service = _home_service(engine, lab)
    service._config = replace(service._config, scope=DiscoveryScope.parse("192.168.50.0/25"))
    return service


def echo_lab(**overrides: Any) -> Lab:
    host = Host(set(), mac=ECHO_MAC, name="linux.local")
    for key, value in overrides.items():
        setattr(host, key, value)
    return Lab({ECHO_IP: host})


def asset_by_ip(client: TestClient, ip: str) -> dict[str, Any]:
    items = client.get(API, params={"q": ip}).json()["items"]
    found: list[dict[str, Any]] = [a for a in items if a["primary_ip"] == ip]
    assert len(found) == 1, found
    return found[0]


def put_label(client: TestClient, asset_id: str, label: str | None, version: int) -> Any:
    return client.patch(f"{API}/{asset_id}/label", json={"label": label, "version": version})


# --- Clasificación con evidencia limitada -------------------------------------------------------


def test_amazon_nic_with_generic_linux_name_is_only_a_probable_iot() -> None:
    result = identify(IdentityInput(reverse_dns="linux.local", mac_vendor=AMAZON, mac=ECHO_MAC))
    # Ni PC con Linux, ni un nombre "Alexa" inventado a partir del fabricante de la NIC.
    assert result.device_type == "iot" and result.confidence == "low"
    assert result.name is None and result.probable_os is None
    assert result.device_vendor == "Amazon" and result.device_model is None
    assert result.names == [
        {
            "source": "reverse_dns",
            "value": "linux",
            "kind": "generic",
            "selected": False,
            "confirmed": None,
            "stale": False,
        }
    ]
    # La evidencia original se conserva aunque no se use como nombre.
    assert {"source": "reverse_dns", "value": "linux"} in result.evidence


@pytest.mark.parametrize("name", ["linux", "android", "ubuntu", "raspberrypi", "localhost.local"])
def test_default_os_names_never_vote(name: str) -> None:
    result = identify(IdentityInput(reverse_dns=name))
    assert result.name is None and result.device_type is None and result.probable_os is None


def test_name_kinds_distinguish_device_dhcp_and_domain_names() -> None:
    kinds = {
        raw: identify(IdentityInput(reverse_dns=raw)).names[0]["kind"]
        for raw in ("echo-salon.local", "echo-salon.lan", "echo-salon", "pc01.corp.example")
    }
    assert kinds == {
        "echo-salon.local": "device",
        "echo-salon.lan": "dhcp",
        "echo-salon": "dhcp",
        "pc01.corp.example": "dns",
    }
    assert identify(IdentityInput(mdns_name="Echo-Salon")).names[0]["kind"] == "device"


def test_specific_device_name_beats_generic_dns_and_unconfirmed_dns() -> None:
    both = identify(IdentityInput(reverse_dns="linux.local", mdns_name="Echo-Dot-Salon"))
    assert (both.name, both.name_source) == ("Echo-Dot-Salon", "mdns")
    unconfirmed = identify(
        IdentityInput(reverse_dns="old-name.lan", mdns_name="tv-salon", reverse_dns_confirmed=False)
    )
    assert unconfirmed.name == "tv-salon"
    assert {
        "source": "reverse_dns",
        "value": "no confirmado: el nombre no resuelve a esta IP",
    } in unconfirmed.evidence
    stale = identify(
        IdentityInput(
            reverse_dns="old-name.lan",
            mdns_name="tv-salon",
            stale_sources=frozenset({"reverse_dns"}),
        )
    )
    assert stale.name == "tv-salon"
    assert [n["stale"] for n in stale.names] == [True, False]


def test_single_port_or_ambiguous_vendor_never_decides_the_type() -> None:
    assert identify(IdentityInput(open_ports=frozenset({9100}))).device_type is None
    assert identify(IdentityInput(open_ports=frozenset({554}))).device_type is None
    assert identify(IdentityInput(open_ports=frozenset({445}))).device_type is None
    # Con otra fuente que ya apunta a ese tipo, el puerto sí refuerza.
    printer = identify(IdentityInput(open_ports=frozenset({9100}), reverse_dns="printer-2"))
    assert printer.device_type == "printer"
    camera = identify(IdentityInput(open_ports=frozenset({554}), mac_vendor="Reolink Innovation"))
    assert camera.device_type == "iot" and camera.confidence == "medium"
    # Samsung hace móviles y televisores: la marca sola no da tipo.
    assert identify(IdentityInput(mac_vendor="Samsung Electronics Co.,Ltd")).device_type is None


def test_contradictory_evidence_is_kept_not_resolved() -> None:
    result = identify(IdentityInput(mac_vendor=AMAZON, upnp_manufacturer="Sonos, Inc."))
    conflicts = [e["value"] for e in result.evidence if e["source"] == "conflict"]
    assert conflicts and "Amazon" in conflicts[0] and "Sonos" in conflicts[0]
    tie = identify(IdentityInput(reverse_dns="printer-1", mac_vendor="Nintendo Co.,Ltd"))
    assert tie.device_type is None
    assert any(e["source"] == "conflict" for e in tie.evidence)


# --- Actualización de identidad sin perder lo más fiable ----------------------------------------


def test_weaker_names_do_not_overwrite_better_ones() -> None:
    asset = Asset(primary_ip=ECHO_IP, mac_address=ECHO_MAC, first_seen_at=datetime.now(UTC))
    now = datetime.now(UTC)
    record_observation(asset, HostObservation(ECHO_IP, mdns_name="Echo-Dot-Salon"), None, now)
    record_observation(asset, HostObservation(ECHO_IP, mdns_name="linux"), None, now)
    assert asset.identity_observations is not None
    assert asset.identity_observations["mdns_name"] == "Echo-Dot-Salon"
    # Cuando el nombre bueno deja de estar vigente, lo nuevo sí lo sustituye.
    later = now + timedelta(days=identification.NAME_STALE_DAYS + 1)
    record_observation(asset, HostObservation(ECHO_IP, mdns_name="linux"), None, later)
    assert asset.identity_observations["mdns_name"] == "linux"

    record_reverse_dns(asset, "echo-salon.lan", True, now)
    record_reverse_dns(asset, "linux.local", None, now)  # genérico: no tapa al anterior
    record_reverse_dns(asset, "otro.lan", False, now)  # desmentido frente a confirmado
    assert asset.reverse_dns == "echo-salon.lan"
    assert asset.identity_observations["reverse_dns_confirmed"] is True
    record_reverse_dns(asset, "salon-echo.lan", None, now)  # renombrado normal
    assert asset.reverse_dns == "salon-echo.lan"
    assert "reverse_dns_confirmed" not in asset.identity_observations


def test_stale_names_are_flagged_after_the_window() -> None:
    asset = Asset(primary_ip=ECHO_IP, first_seen_at=datetime.now(UTC))
    old = datetime.now(UTC) - timedelta(days=identification.NAME_STALE_DAYS + 2)
    record_observation(asset, HostObservation(ECHO_IP, mdns_name="tv-viejo"), None, old)
    refresh_identity(asset, database=OUI)
    assert asset.observed_names is not None and asset.observed_names[0]["stale"] is True
    # Aun antiguo, es el único nombre: sigue siendo el automático (no se inventa otro).
    assert asset.device_name == "tv-viejo"


# --- Discovery de extremo a extremo -------------------------------------------------------------


def test_echo_regression_end_to_end(client: TestClient, engine: Engine) -> None:
    _service(engine, echo_lab()).run()
    echo = asset_by_ip(client, ECHO_IP)
    assert echo["device_type"] == "iot" and echo["classification_confidence"] == "low"
    assert echo["device_name"] is None and echo["probable_os"] is None
    assert echo["reverse_dns"] == "linux.local"
    assert echo["observed_names"][0]["kind"] == "generic"
    assert echo["custom_label"] is None and echo["custom_label_version"] == 0
    # Fase 6D.3: "linux.local" es evidencia real pero no identifica al equipo.
    assert echo["name_status"] == "generic_only"

    updated = put_label(client, echo["asset_id"], "Alexa Sala", 0)
    assert updated.status_code == 200, updated.text
    body = updated.json()
    assert body["custom_label"] == "Alexa Sala" and body["display_name"] == "Alexa Sala"
    assert body["custom_label_version"] == 1 and body["custom_label_updated_by"] == "admin"
    assert body["name_status"] == "labelled"
    # La evidencia original sigue ahí: el nombre DNS observado y la clasificación.
    assert body["reverse_dns"] == "linux.local" and body["device_name"] is None
    assert body["device_type"] == "iot" and body["observed_names"][0]["value"] == "linux"

    # Un nuevo discovery y un cambio de IP (misma MAC) no tocan la etiqueta.
    _service(engine, echo_lab()).run()
    lab = Lab({"192.168.50.79": Host(set(), mac=ECHO_MAC, name="linux.local")})
    _service(engine, lab).run()
    moved = asset_by_ip(client, "192.168.50.79")
    assert moved["asset_id"] == echo["asset_id"]
    assert moved["custom_label"] == "Alexa Sala" and moved["custom_label_version"] == 1

    # Búsqueda y orden por el nombre visible.
    found = client.get(API, params={"q": "alexa sala"}).json()["items"]
    assert [a["asset_id"] for a in found] == [echo["asset_id"]]


def test_label_edit_remove_and_audit(client: TestClient, engine: Engine, db: Session) -> None:
    _service(engine, echo_lab()).run()
    asset_id = asset_by_ip(client, ECHO_IP)["asset_id"]
    assert put_label(client, asset_id, "  Alexa   Sala ", 0).json()["custom_label"] == "Alexa Sala"
    assert put_label(client, asset_id, "Alexa Salón", 1).json()["custom_label_version"] == 2
    # Mismo valor: no es un cambio (ni versión nueva ni auditoría).
    same = put_label(client, asset_id, "Alexa Salón", 2).json()
    assert same["custom_label_version"] == 2
    removed = put_label(client, asset_id, None, 2).json()
    assert removed["custom_label"] is None and removed["custom_label_version"] == 3
    assert removed["display_name"] == "linux.local"  # vuelve el nombre automático
    assert removed["name_status"] == "generic_only"

    rows = db.scalars(
        select(AuditEvent).where(AuditEvent.action == "asset_label_changed").order_by(AuditEvent.id)
    ).all()
    assert [(r.details or {}).get("to") for r in rows] == ["Alexa Sala", "Alexa Salón", None]
    assert (rows[1].details or {}).get("from") == "Alexa Sala"
    assert all(r.result == "success" and r.target_id == asset_id for r in rows)


def test_label_conflict_is_409_and_never_overwrites(client: TestClient, engine: Engine) -> None:
    _service(engine, echo_lab()).run()
    asset_id = asset_by_ip(client, ECHO_IP)["asset_id"]
    assert put_label(client, asset_id, "Alexa Sala", 0).status_code == 200
    stale = put_label(client, asset_id, "Otra cosa", 0)
    assert stale.status_code == 409
    error = stale.json()["error"]
    assert error["code"] == "asset_label_conflict"
    assert error["details"] == [{"current_version": 1, "custom_label": "Alexa Sala"}]
    assert asset_by_ip(client, ECHO_IP)["custom_label"] == "Alexa Sala"


@pytest.mark.parametrize(
    "label",
    [
        "",
        "   ",
        "x" * 65,
        "Alexa‮ala S",  # cambio de dirección: disfraza el texto
        "Alexa​Sala",  # carácter invisible
        "Alexa\nSala",
        "Alexa\x07",
    ],
)
def test_label_validation(client: TestClient, engine: Engine, label: str) -> None:
    _service(engine, echo_lab()).run()
    asset_id = asset_by_ip(client, ECHO_IP)["asset_id"]
    response = put_label(client, asset_id, label, 0)
    assert response.status_code == 422, response.text
    assert asset_by_ip(client, ECHO_IP)["custom_label"] is None


def test_label_normalization_keeps_unicode_names() -> None:
    assert normalize_label("Cámara  Entrada ") == "Cámara Entrada"
    assert normalize_label("Café") == "Café"  # NFC: la misma etiqueta, un solo valor


@pytest.mark.parametrize("role", ["analyst", "viewer"])
def test_label_requires_assets_manage(
    client: TestClient, engine: Engine, db: Session, role: str
) -> None:
    _service(engine, echo_lab()).run()
    asset_id = asset_by_ip(client, ECHO_IP)["asset_id"]
    with TestClient(client.app) as other:
        authenticate(other, engine, role)
        response = put_label(other, asset_id, "Alexa Sala", 0)
        assert response.status_code == 403
        # Leer la etiqueta sí puede cualquier rol con monitoring:read.
        assert other.get(f"{API}/{asset_id}").json()["custom_label"] is None
    denied = db.scalars(select(AuditEvent).where(AuditEvent.action == "permission_denied")).all()
    assert denied


def test_unknown_asset_is_404(client: TestClient) -> None:
    response = put_label(client, "00000000-0000-0000-0000-000000000000", "x", 0)
    assert response.status_code == 404


def test_heartbeat_and_agent_merge_keep_the_label(client: TestClient, engine: Engine) -> None:
    _service(engine, echo_lab(name="pc-salon.lan", ports={135, 445})).run()
    discovered = asset_by_ip(client, ECHO_IP)
    assert put_label(client, discovered["asset_id"], "PC del salón", 0).status_code == 200

    # Al instalar el agente en ese equipo, el activo descubierto se fusiona con el del agente:
    # la etiqueta pasa al superviviente y el hostname del agente queda como nombre automático.
    payload = agent_payload(hostname="SALON-PC", primary_ip=ECHO_IP)
    assert client.post("/api/v1/agents/register", json=payload).status_code == 201
    inventory = {
        "agent_id": payload["agent_id"],
        "collected_at": datetime.now(UTC).isoformat(),
        "interfaces": [{"name": "eth0", "mac": ECHO_MAC, "addresses": [ECHO_IP], "is_up": True}],
    }
    assert client.post("/api/v1/inventory", json=inventory).status_code == 201
    for _ in range(2):
        response = client.post("/api/v1/agents/heartbeat", json={"agent_id": payload["agent_id"]})
        assert response.status_code == 200
    merged = asset_by_ip(client, ECHO_IP)
    assert merged["monitoring_method"] == "agent"
    assert merged["custom_label"] == "PC del salón" and merged["display_name"] == "PC del salón"
    assert merged["device_name"] == "SALON-PC"
    assert merged["observed_names"][0] == {
        "source": "agent_hostname",
        "value": "SALON-PC",
        "kind": "agent",
        "selected": True,
        "confirmed": None,
        "stale": False,
    }
