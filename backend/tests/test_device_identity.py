"""Fase 7B.2: identidad de dispositivos por niveles, MAC privada y asociaciones manuales.

Cubre:
- perfil de MAC (universal, privada con su cuadrante SLAP, multicast, virtual);
- ficha por niveles: un agente confirma, una MAC universal da "probable" y una MAC privada
  sin agente deja el activo `identity_unresolved`;
- sugerencias: nunca por IP, OUI, SO o nombre por sí solos; sí por la MAC que declara el
  propio agente, por el historial de MACs o por la identidad de máquina;
- comparación de dos registros con la misma IP (el duplicado 192.168.50.66 de la auditoría,
  con datos sintéticos): reutilización de IP frente a identidad reconciliable;
- asociación manual de un alias y de un cliente Wi-Fi: vista previa, bloqueos, auditoría,
  efecto en el discovery (la MAC asociada resuelve al activo destino) y revocación exacta.
"""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session, sessionmaker

from app.models.asset import Asset, AssetStatus, MonitoringMethod
from app.models.audit import AuditEvent
from app.models.dhcp import AssetIdentityHistory
from app.models.site import Site
from app.models.wlan import WlanAgentReport, WlanClient, WlanObservation
from app.services.identity_rules import mac_profile
from app.services.site_service import default_site_id
from tests.conftest import agent_payload, authenticate
from tests.test_asset_lifecycle_5c2 import _discovery
from tests.test_discovery_service import NETWORK, Host, Lab

API = "/api/v1"
LINKS = f"{API}/identity/links"
RANDOM_MAC = "da:a1:19:00:00:66"
UNIVERSAL_MAC = "00:1a:2b:3c:4d:66"


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    # `client` por su limpieza (TRUNCATE al terminar cada test).
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


def _discovered(db: Session, ip: str = "192.168.50.66", **fields: Any) -> Asset:
    now = datetime.now(UTC)
    values: dict[str, Any] = {
        "monitoring_method": MonitoringMethod.DISCOVERED,
        "primary_ip": ip,
        "status": AssetStatus.UNKNOWN,
        "network_status": AssetStatus.ONLINE,
        "last_network_seen_at": now,
        "first_seen_at": now,
        "discovered_at": now,
        **fields,
    }
    asset = Asset(**values)
    db.add(asset)
    db.commit()
    return asset


def _agent(client: TestClient, db: Session, **host: Any) -> Asset:
    payload = agent_payload(**host)
    response = client.post(f"{API}/agents/register", json=payload)
    assert response.status_code == 201, response.text
    asset = db.scalar(select(Asset).where(Asset.public_id == UUID(response.json()["asset_id"])))
    assert asset is not None
    return asset


def _wifi_report(db: Session, asset: Asset, mac: str) -> None:
    now = datetime.now(UTC)
    db.add(
        WlanAgentReport(
            asset_id=asset.id,
            site_id=asset.site_id,
            status="ok",
            source="netsh",
            collected_at=now,
            received_at=now,
            interfaces=[{"name": "Wi-Fi", "mac": mac, "mac_randomized": True}],
        )
    )
    db.commit()


def _client_row(db: Session, mac: str = RANDOM_MAC, **fields: Any) -> WlanClient:
    now = datetime.now(UTC)
    values: dict[str, Any] = {
        "site_id": default_site_id(db),
        "client_key": f"mac:{mac}",
        "mac": mac,
        "mac_randomized": True,
        "ssid": "Lab",
        "source": "snmp_airespace",
        "identity_confidence": "observation_only",
        "first_seen_at": now,
        "last_seen_at": now,
        **fields,
    }
    row = WlanClient(**values)
    db.add(row)
    db.commit()
    return row


# --- MAC ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("mac", "kind", "quadrant"),
    [
        ("00:1a:2b:3c:4d:5e", "universal", None),
        ("da:a1:19:00:00:01", "local", "eli"),
        ("de:a1:19:00:00:01", "local", "sai"),
        ("d2:a1:19:00:00:01", "local", "aai"),
        ("d6:a1:19:00:00:01", "local", "reserved"),
        ("52:54:00:12:34:56", "virtual", None),
        ("01:00:5e:00:00:01", "multicast", None),
        (None, "none", None),
    ],
)
def test_mac_profile(mac: str | None, kind: str, quadrant: str | None) -> None:
    profile = mac_profile(mac, "Intel")
    assert profile.kind == kind and profile.slap_quadrant == quadrant
    assert profile.randomized is (kind == "local")
    # El fabricante de la NIC solo se atribuye a una MAC universal.
    assert (profile.nic_vendor == "Intel") is (kind == "universal")


# --- Ficha por niveles --------------------------------------------------------------------


def test_random_mac_without_agent_is_identity_unresolved(client: TestClient, db: Session) -> None:
    phone = _discovered(
        db,
        mac_address=RANDOM_MAC,
        observed_names=[
            {"source": "mdns", "value": "iPhone", "kind": "generic", "selected": True},
        ],
    )
    body = client.get(f"{API}/assets/{phone.public_id}/identity/profile").json()
    assert body["state"] == "identity_unresolved" and body["reasons"] == ["random_mac"]
    assert body["mac"]["randomized"] is True and body["mac"]["nic_vendor"] is None
    assert body["vendor"]["state"] == "unresolved" and body["vendor"]["reasons"] == ["random_mac"]
    assert body["name"]["state"] == "unresolved" and body["name"]["reasons"] == ["generic_name"]


def test_tiers_are_independent(client: TestClient, db: Session) -> None:
    stale = (datetime.now(UTC) - timedelta(days=60)).isoformat()
    printer = _discovered(
        db,
        mac_address=UNIVERSAL_MAC,
        vendor="Hewlett Packard",
        device_vendor="HP",
        device_type="printer",
        classification_confidence="high",
        observed_names=[
            {"source": "mdns", "value": "HP-LaserJet", "kind": "device", "selected": True},
            {"source": "dhcp_lease", "value": "old-name", "kind": "dhcp", "stale": True},
        ],
        identity_observations={"seen_at": {"dhcp_lease": stale}},
    )
    body = client.get(f"{API}/assets/{printer.public_id}/identity/profile").json()
    assert body["state"] == "probable" and body["reasons"] == ["universal_mac"]
    assert body["name"]["value"] == "HP-LaserJet" and body["name"]["state"] == "probable"
    assert body["name"]["alternatives"][0]["freshness"] == "stale"
    assert body["vendor"]["value"] == "HP" and body["vendor"]["state"] == "probable"
    assert body["device_type"]["value"] == "printer" and body["device_type"]["state"] == "probable"
    assert body["os"]["state"] == "unresolved"

    agent = _agent(client, db, hostname="ravenslg", primary_ip="192.168.50.10")
    body = client.get(f"{API}/assets/{agent.public_id}/identity/profile").json()
    assert body["state"] == "confirmed" and body["os"]["state"] == "confirmed"
    assert body["os"]["source"] == "agent_os"


# --- Sugerencias --------------------------------------------------------------------------


def test_ip_name_or_os_alone_never_suggest_a_match(client: TestClient, db: Session) -> None:
    a = _discovered(db, mac_address="da:00:00:00:00:01")
    _discovered(db, mac_address="da:00:00:00:00:02")
    items = client.get(f"{API}/assets/{a.public_id}/identity/candidates").json()["items"]
    assert items == []


def test_agent_reported_private_mac_is_strong_evidence(client: TestClient, db: Session) -> None:
    laptop = _agent(client, db, hostname="portatil", primary_ip="192.168.50.20")
    _wifi_report(db, laptop, RANDOM_MAC)
    seen = _discovered(db, mac_address=RANDOM_MAC)
    items = client.get(f"{API}/assets/{seen.public_id}/identity/candidates").json()["items"]
    assert [i["asset"]["asset_id"] for i in items] == [str(laptop.public_id)]
    assert items[0]["strength"] == "strong"
    assert "agent_reported_mac" in {e["code"] for e in items[0]["evidence"]}


def test_mac_history_is_medium_evidence(client: TestClient, db: Session) -> None:
    old = _discovered(db, mac_address="da:00:00:00:00:10", ip="192.168.50.30")
    new = _discovered(db, mac_address="da:00:00:00:00:11", ip="192.168.50.31")
    db.add(
        AssetIdentityHistory(
            asset_id=old.id,
            field="mac",
            old_value="da:00:00:00:00:11",
            new_value="da:00:00:00:00:10",
            source="discovery",
            confidence="high",
            observed_at=datetime.now(UTC),
        )
    )
    db.commit()
    items = client.get(f"{API}/assets/{new.public_id}/identity/candidates").json()["items"]
    assert items and items[0]["strength"] == "medium"
    assert items[0]["evidence"][0]["code"] == "mac_in_history"


# --- Comparación (duplicado 192.168.50.66) -----------------------------------------------


def test_same_ip_different_devices_is_ip_reuse(client: TestClient, db: Session) -> None:
    phone = _discovered(db, mac_address=RANDOM_MAC)
    tv = _discovered(db, mac_address=UNIVERSAL_MAC)
    body = client.get(
        f"{API}/identity/compare", params={"left": str(phone.public_id), "right": str(tv.public_id)}
    ).json()
    assert body["classification"] == "ip_reuse" and body["recommended_action"] == "none"


def test_private_mac_reported_by_agent_is_reconcilable(client: TestClient, db: Session) -> None:
    laptop = _agent(client, db, hostname="portatil", primary_ip="192.168.50.66")
    _wifi_report(db, laptop, RANDOM_MAC)
    seen = _discovered(db, mac_address=RANDOM_MAC)
    body = client.get(
        f"{API}/identity/compare",
        params={"left": str(laptop.public_id), "right": str(seen.public_id)},
    ).json()
    assert body["classification"] == "reconcilable_identity"
    assert body["recommended_action"] == "link_alias"


def test_reinstalled_agent_points_to_reconciliation(client: TestClient, db: Session) -> None:
    old = _agent(client, db, hostname="DESKTOP-X", primary_ip="10.9.0.5", machine_id_hash="a" * 64)
    new = _agent(client, db, hostname="DESKTOP-X", primary_ip="10.9.0.5", machine_id_hash="a" * 64)
    body = client.get(
        f"{API}/identity/compare", params={"left": str(old.public_id), "right": str(new.public_id)}
    ).json()
    assert body["classification"] == "same_agent_reinstalled"
    assert "same_machine_id" in {e["code"] for e in body["evidence"]}


def test_records_of_different_sites_are_never_matched(client: TestClient, db: Session) -> None:
    suffix = uuid4().hex[:6]
    other = Site(name=f"Sede {suffix}", slug=f"sede-{suffix}")
    db.add(other)
    db.commit()
    a = _discovered(db, mac_address=UNIVERSAL_MAC)
    b = _discovered(db, mac_address=UNIVERSAL_MAC, site_id=other.id)
    body = client.get(
        f"{API}/identity/compare", params={"left": str(a.public_id), "right": str(b.public_id)}
    ).json()
    assert body["classification"] == "distinct_records"
    assert body["conflicts"] == ["different_site"]


# --- Asociación manual --------------------------------------------------------------------


def _alias_body(target: Asset, alias: Asset, **extra: Any) -> dict[str, Any]:
    return {
        "kind": "asset_alias",
        "target_asset_id": str(target.public_id),
        "alias_asset_id": str(alias.public_id),
        "reason": "El agente declara esa MAC privada",
        **extra,
    }


def test_alias_link_archives_maps_discovery_and_revokes_exactly(
    client: TestClient, engine: Engine, db: Session
) -> None:
    ip = "10.20.0.5"
    laptop = _agent(client, db, hostname="portatil", primary_ip="10.20.0.9")
    _wifi_report(db, laptop, RANDOM_MAC)
    alias = _discovered(db, ip=ip, mac_address=RANDOM_MAC, discovery_network=NETWORK)

    preview = client.post(f"{LINKS}/preview", json=_alias_body(laptop, alias)).json()
    assert preview["allowed"] is True
    assert {"archive_alias", "map_mac_to_target"} <= set(preview["effects"])
    assert preview["evidence"][0]["code"] == "agent_reported_mac"
    # La vista previa no escribe nada: no exige motivo. Crear sí lo exige.
    bare = {k: v for k, v in _alias_body(laptop, alias).items() if k != "reason"}
    assert client.post(f"{LINKS}/preview", json=bare).json()["allowed"] is True
    assert client.post(LINKS, json={**bare, "confirm": True}).status_code == 422
    # Sin confirmar tras la vista previa no se crea.
    assert client.post(LINKS, json=_alias_body(laptop, alias)).status_code == 422

    created = client.post(LINKS, json=_alias_body(laptop, alias, confirm=True))
    assert created.status_code == 201, created.text
    link = created.json()
    db.expire_all()
    assert db.get(Asset, alias.id).archived_at is not None  # type: ignore[union-attr]
    # Un segundo intento sobre el mismo alias se rechaza y queda auditado.
    again = client.post(LINKS, json=_alias_body(laptop, alias, confirm=True))
    assert again.status_code == 409
    profile = client.get(f"{API}/assets/{alias.public_id}/identity/profile").json()
    assert profile["state"] == "probable" and profile["reasons"] == ["manual_link"]

    # El discovery resuelve esa MAC al portátil: no crea un registro nuevo para la IP.
    before = db.scalar(select(func.count()).select_from(Asset))
    alias_seen = db.get(Asset, alias.id).last_network_seen_at  # type: ignore[union-attr]
    assert db.get(Asset, laptop.id).last_network_seen_at is None  # type: ignore[union-attr]
    _discovery(engine, Lab({ip: Host(ports={80}, mac=RANDOM_MAC)})).run()
    db.expire_all()
    assert db.scalar(select(func.count()).select_from(Asset)) == before
    assert db.get(Asset, laptop.id).last_network_seen_at is not None  # type: ignore[union-attr]
    assert db.get(Asset, alias.id).last_network_seen_at == alias_seen  # type: ignore[union-attr]

    revoked = client.post(f"{LINKS}/{link['link_id']}/revoke", json={"reason": "era otro equipo"})
    assert revoked.status_code == 200 and revoked.json()["active"] is False
    db.expire_all()
    assert db.get(Asset, alias.id).archived_at is None  # type: ignore[union-attr]
    actions = [
        e.action
        for e in db.scalars(select(AuditEvent).where(AuditEvent.action.like("identity_link_%")))
    ]
    assert actions.count("identity_link_created") == 2  # éxito + intento rechazado
    assert "identity_link_revoked" in actions


def test_alias_link_blockers(client: TestClient, db: Session) -> None:
    target = _agent(client, db, hostname="a", primary_ip="10.1.0.1")
    other_agent = _agent(client, db, hostname="b", primary_ip="10.1.0.2")
    preview = client.post(f"{LINKS}/preview", json=_alias_body(target, other_agent)).json()
    # Un registro con agente se reconcilia (5C.2), nunca se archiva como alias.
    assert preview["allowed"] is False and preview["blockers"] == ["alias_has_agent"]
    preview = client.post(f"{LINKS}/preview", json=_alias_body(target, target)).json()
    assert "same_asset" in preview["blockers"]
    bad = client.post(
        f"{LINKS}/preview",
        json={**_alias_body(target, target), "wlan_client_id": None, "alias_asset_id": None},
    )
    assert bad.status_code == 422


def test_wlan_client_link_survives_and_reverts(client: TestClient, db: Session) -> None:
    laptop = _agent(client, db, hostname="portatil", primary_ip="10.2.0.9")
    row = _client_row(db)
    now = datetime.now(UTC)
    db.add(
        WlanObservation(
            site_id=row.site_id, client_id=row.id, source="snmp_airespace",
            confidence="reported_by_device", observed_at=now, received_at=now,
            data={"state": "associated"},
        )
    )  # fmt: skip
    db.commit()
    detail = client.get(f"{API}/network/wlan/clients/{row.public_id}").json()
    assert detail["identity_confidence"] == "observation_only"
    history = client.get(f"{API}/network/wlan/clients/{row.public_id}/observations").json()
    assert history["total"] == 1

    body = {
        "kind": "wlan_client",
        "target_asset_id": str(laptop.public_id),
        "wlan_client_id": str(row.public_id),
        "reason": "Es el móvil de recepción",
        "confirm": True,
    }
    created = client.post(LINKS, json=body)
    assert created.status_code == 201, created.text
    detail = client.get(f"{API}/network/wlan/clients/{row.public_id}").json()
    assert detail["identity_confidence"] == "confirmed"
    assert detail["correlation_basis"] == "manual"
    assert detail["asset"]["asset_id"] == str(laptop.public_id)

    revoked = client.post(
        f"{LINKS}/{created.json()['link_id']}/revoke", json={"reason": "asociado por error"}
    )
    assert revoked.status_code == 200
    detail = client.get(f"{API}/network/wlan/clients/{row.public_id}").json()
    assert detail["identity_confidence"] == "observation_only" and detail["asset"] is None


def test_agent_confirmed_client_cannot_be_overridden(client: TestClient, db: Session) -> None:
    laptop = _agent(client, db, hostname="portatil", primary_ip="10.3.0.9")
    other = _agent(client, db, hostname="otro", primary_ip="10.3.0.10")
    row = _client_row(
        db, identity_confidence="confirmed", correlation_basis="agent_self", asset_id=laptop.id
    )
    preview = client.post(
        f"{LINKS}/preview",
        json={
            "kind": "wlan_client",
            "target_asset_id": str(other.public_id),
            "wlan_client_id": str(row.public_id),
            "reason": "prueba",
        },
    ).json()
    assert preview["blockers"] == ["client_confirmed_by_agent"]


def test_links_are_admin_only(client: TestClient, engine: Engine, db: Session) -> None:
    target = _agent(client, db, hostname="a", primary_ip="10.4.0.1")
    alias = _discovered(db, mac_address=RANDOM_MAC)
    with TestClient(client.app) as analyst:
        authenticate(analyst, engine, "analyst")
        assert analyst.get(f"{API}/assets/{alias.public_id}/identity/profile").status_code == 200
        assert analyst.post(f"{LINKS}/preview", json=_alias_body(target, alias)).status_code == 403
        denied = analyst.post(LINKS, json=_alias_body(target, alias, confirm=True))
        assert denied.status_code == 403


def test_asset_list_shows_the_same_identity_state(client: TestClient, db: Session) -> None:
    phone = _discovered(db, mac_address=RANDOM_MAC)
    printer = _discovered(db, mac_address=UNIVERSAL_MAC, ip="192.168.50.67")
    laptop = _agent(client, db, hostname="portatil", primary_ip="192.168.50.68")
    items = client.get(f"{API}/assets", params={"limit": 50}).json()["items"]
    state = {i["asset_id"]: (i["identity_state"], i["mac_randomized"]) for i in items}
    assert state[str(phone.public_id)] == ("identity_unresolved", True)
    assert state[str(printer.public_id)] == ("probable", False)
    assert state[str(laptop.public_id)][0] == "confirmed"
    profile = client.get(f"{API}/assets/{phone.public_id}/identity/profile").json()
    assert profile["state"] == state[str(phone.public_id)][0]
