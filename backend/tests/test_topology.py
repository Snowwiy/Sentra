"""Fase 6D: motor de topología con PostgreSQL y API (docs/topology-engine.md).

La evidencia (equipos, vecinos LLDP, tablas MAC, WLAN, inventarios) se inserta con el ORM:
estas pruebas fijan lo que el motor hace con ella (reconstrucción, upsert, revisión, API,
permisos, aislamiento por site); la ingesta SNMP y WLAN tiene sus propias pruebas. Las
reglas de derivación una a una están en test_topology_builder.py (sin base de datos).
"""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select, text, update
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.db.locks import topology_site_lock_key
from app.models.asset import Asset, MonitoringMethod
from app.models.audit import AuditEvent
from app.models.inventory import AssetInventory
from app.models.network import NetworkDevice, NetworkInterface, NetworkMacEntry, NetworkNeighbor
from app.models.site import Site, SiteNetwork
from app.models.topology import TopologyBuild, TopologyLink
from app.models.wlan import WlanAccessPoint, WlanClient
from app.topology.service import TopologyService, report_topology, run_scheduled_rebuilds
from tests.conftest import authenticate

API = "/api/v1/topology"


def now() -> datetime:
    # Dentro de cada prueba, nunca al recoger el módulo (convención de CLAUDE.md).
    return datetime.now(UTC)


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session
    # Las reconstrucciones referencian sites (RESTRICT): se vacían antes de que la limpieza
    # general de conftest borre los sites creados por la prueba.
    with engine.begin() as connection:
        connection.execute(text("TRUNCATE topology_links, topology_builds RESTART IDENTITY"))


def _ok(response: Any, status: int = 200) -> Any:
    assert response.status_code == status, response.text
    return response.json()


def _error(response: Any, status: int, code: str) -> None:
    assert response.status_code == status, response.text
    assert response.json()["error"]["code"] == code, response.text


def _audit(db: Session, action: str) -> list[AuditEvent]:
    db.expire_all()
    return list(db.scalars(select(AuditEvent).where(AuditEvent.action == action)))


# --- datos de prueba ----------------------------------------------------------------------------


def default_site(db: Session) -> Site:
    return db.scalars(select(Site).where(Site.is_default.is_(True))).one()


def new_site(db: Session, name: str, cidr: str | None = None) -> Site:
    site = Site(name=name, slug=f"{name.lower()}-{uuid4().hex[:6]}", is_default=False)
    db.add(site)
    db.flush()
    if cidr:
        db.add(SiteNetwork(site_id=site.id, cidr=cidr, name=f"LAN {name}", enabled=True))
    db.commit()
    return site


def add_asset(db: Session, site: Site, ip: str, mac: str | None = None, **fields: Any) -> Asset:
    row = Asset(
        site_id=site.id,
        primary_ip=ip,
        mac_address=mac,
        monitoring_method=fields.pop("monitoring_method", MonitoringMethod.DISCOVERED),
        first_seen_at=now(),
        **fields,
    )
    db.add(row)
    db.commit()
    return row


def add_device(db: Session, site: Site, address: str, **fields: Any) -> NetworkDevice:
    row = NetworkDevice(site_id=site.id, management_address=address, **fields)
    db.add(row)
    db.commit()
    return row


def add_interface(db: Session, device: NetworkDevice, name: str, index: int) -> NetworkInterface:
    row = NetworkInterface(
        device_id=device.id,
        site_id=device.site_id,
        stable_key=name,
        if_index=index,
        if_name=name,
        first_seen_at=now(),
        last_seen_at=now(),
    )
    db.add(row)
    db.commit()
    return row


def add_neighbor(
    db: Session, device: NetworkDevice, local_port: str, **fields: Any
) -> NetworkNeighbor:
    row = NetworkNeighbor(
        device_id=device.id,
        site_id=device.site_id,
        protocol=fields.pop("protocol", "lldp"),
        local_port_key=local_port,
        local_port_label=local_port,
        remote_key=uuid4().hex,
        first_seen_at=now(),
        last_seen_at=now(),
        **fields,
    )
    db.add(row)
    db.commit()
    return row


def add_mac(
    db: Session,
    device: NetworkDevice,
    mac: str,
    location: str,
    interface: NetworkInterface | None,
) -> NetworkMacEntry:
    row = NetworkMacEntry(
        device_id=device.id,
        site_id=device.site_id,
        mac=mac,
        fdb_key=0,
        status="learned",
        location=location,
        interface_id=interface.id if interface else None,
        first_seen_at=now(),
        last_seen_at=now(),
    )
    db.add(row)
    db.commit()
    return row


def add_gateway(db: Session, asset: Asset, *gateways: str) -> None:
    db.add(
        AssetInventory(
            asset_id=asset.id,
            collected_at=now(),
            data={"network": {"gateways": list(gateways), "dns_servers": []}},
        )
    )
    db.commit()


def add_ap(db: Session, site: Site, name: str, **fields: Any) -> WlanAccessPoint:
    row = WlanAccessPoint(
        site_id=site.id,
        ap_key=f"mac:{uuid4().hex[:12]}",
        name=name,
        source="snmp_airespace",
        first_seen_at=now(),
        last_seen_at=now(),
        **fields,
    )
    db.add(row)
    db.commit()
    return row


def add_client(
    db: Session, site: Site, ap: WlanAccessPoint, asset: Asset, identity: str
) -> WlanClient:
    row = WlanClient(
        site_id=site.id,
        client_key=f"mac:{uuid4().hex[:12]}",
        mac=asset.mac_address,
        access_point_id=ap.id,
        ssid="Corp",
        source="snmp_airespace",
        identity_confidence=identity,
        asset_id=asset.id,
        first_seen_at=now(),
        last_seen_at=now(),
    )
    db.add(row)
    db.commit()
    return row


def office(db: Session, site: Site) -> dict[str, Any]:
    """Oficina con dos switches LLDP recíprocos, un PC en un puerto de acceso, un router
    gateway, una impresora en un puerto compartido, un vecino externo y Wi-Fi."""
    router = add_asset(db, site, "192.168.50.1", "00:10:00:00:00:01", device_name="archer-gx90")
    pc = add_asset(
        db,
        site,
        "192.168.50.20",
        "00:10:00:00:00:20",
        agent_id=uuid4(),
        monitoring_method=MonitoringMethod.AGENT,
        hostname="PC-ADMIN-01",
    )
    printer = add_asset(db, site, "192.168.50.30", "00:10:00:00:00:30")
    camera = add_asset(db, site, "192.168.50.31", "00:10:00:00:00:31")
    laptop = add_asset(db, site, "192.168.50.40", "00:10:00:00:00:40", hostname="laptop-ana")
    core = add_device(db, site, "192.168.50.2", name="core", ip_forwarding=False)
    access = add_device(db, site, "192.168.50.3", sys_name="access-1")
    controller = add_device(db, site, "192.168.50.5", name="wlc")
    core_up = add_interface(db, core, "Gi1/0/1", 1)
    core_ext = add_interface(db, core, "Gi1/0/48", 48)
    access_up = add_interface(db, access, "Gi0/24", 24)
    access_pc = add_interface(db, access, "Gi0/3", 3)
    access_shared = add_interface(db, access, "Gi0/7", 7)
    add_neighbor(
        db,
        core,
        "Gi1/0/1",
        interface_id=core_up.id,
        remote_device_id=access.id,
        remote_port_id="Gi0/24",
        reciprocal=True,
    )
    add_neighbor(
        db,
        access,
        "Gi0/24",
        interface_id=access_up.id,
        remote_device_id=core.id,
        remote_port_id="Gi1/0/1",
        reciprocal=True,
    )
    add_neighbor(
        db,
        core,
        "Gi1/0/48",
        interface_id=core_ext.id,
        remote_chassis_id="00:cc:00:00:00:01",
        remote_sys_name="isp-cpe",
        remote_port_id="ge-0/0/0",
    )
    pc_mac = add_mac(db, access, "00:10:00:00:00:20", "edge_candidate", access_pc)
    add_mac(db, access, "00:10:00:00:00:30", "edge_candidate", access_shared)
    add_mac(db, access, "00:10:00:00:00:31", "edge_candidate", access_shared)
    add_mac(db, core, "00:10:00:00:00:20", "uplink_or_shared", core_up)
    add_gateway(db, pc, "192.168.50.1")
    ap = add_ap(db, site, "ap-hall", source_device_id=controller.id)
    add_client(db, site, ap, laptop, "probable")
    return {
        "router": router,
        "pc": pc,
        "printer": printer,
        "camera": camera,
        "laptop": laptop,
        "core": core,
        "access": access,
        "controller": controller,
        "ap": ap,
        "pc_mac": pc_mac,
    }


def links_of(db: Session, site: Site) -> list[TopologyLink]:
    db.expire_all()
    return list(
        db.scalars(
            select(TopologyLink).where(TopologyLink.site_id == site.id).order_by(TopologyLink.id)
        )
    )


def rebuild(client: TestClient, site: Site | None = None) -> dict[str, Any]:
    body = {"site_id": str(site.public_id)} if site is not None and not site.is_default else {}
    return _ok(client.post(f"{API}/rebuild", json=body))  # type: ignore[no-any-return]


def as_role(client: TestClient, engine: Engine, role: str) -> TestClient:
    browser = TestClient(client.app)
    authenticate(browser, engine, role)
    return browser


# --- reconstrucción -----------------------------------------------------------------------------


def test_empty_site_status_and_graph(client: TestClient, db: Session) -> None:
    add_asset(db, default_site(db), "192.168.1.10")
    status = _ok(client.get(f"{API}/status"))
    assert status["last_build"] is None and status["links_present"] == 0
    assert status["links_by_kind"] == {
        "physical": 0,
        "logical": 0,
        "observed": 0,
        "candidate": 0,
        "unknown": 0,
    }
    assert status["evidence_available"] == {
        "lldp_cdp": False,
        "fdb": False,
        "wlan": False,
        "agent_gateways": False,
    }
    graph = _ok(client.get(f"{API}/graph"))
    assert graph["site"]["name"] == "Local" and graph["last_build"] is None
    assert graph["links"] == [] and len(graph["nodes"]) == 1
    assert graph["groups"] == [
        {"id": "unassigned", "kind": "unassigned", "cidr": None, "name": None, "node_count": 1}
    ]
    assert graph["limits"] == {"max_nodes": 1500, "max_links": 5000}


def test_rebuild_derives_the_office(client: TestClient, db: Session) -> None:
    site = default_site(db)
    office(db, site)
    build = rebuild(client)
    assert build["status"] == "succeeded" and build["trigger"] == "manual"
    assert build["requested_by"] == "admin" and build["error_code"] is None
    assert build["site_id"] == str(site.public_id) and build["duration_ms"] >= 0
    counts = build["counts"]
    assert counts["links_created"] == counts["links_present"] == 8
    assert counts["links_absent"] == counts["links_updated"] == 0
    assert counts["ambiguous_macs"] == counts["skipped_cross_site"] == 0
    rows = sorted((r.kind, r.relation, r.confidence) for r in links_of(db, site))
    assert rows == [
        ("candidate", "fdb_shared", "low"),
        ("candidate", "fdb_shared", "low"),
        ("logical", "default_gateway", "medium"),
        ("logical", "wlan_managed_by", "high"),
        ("observed", "fdb_edge", "medium"),
        ("observed", "wlan_association", "medium"),
        ("physical", "lldp", "high"),
        ("physical", "lldp", "medium"),  # vecino externo
    ]
    # Sin SNMP de enlace por compartir red: el uplink del core no crea nada para el PC.
    assert all(len(r.link_key) == 64 for r in links_of(db, site))
    status = _ok(client.get(f"{API}/status"))
    assert status["evidence_available"] == {
        "lldp_cdp": True,
        "fdb": True,
        "wlan": True,
        "agent_gateways": True,
    }
    assert status["last_build"]["id"] == build["id"] and status["links_present"] == 8
    assert status["links_by_kind"] == {
        "physical": 2,
        "logical": 2,
        "observed": 2,
        "candidate": 2,
        "unknown": 0,
    }
    events = _audit(db, "topology_rebuilt")
    assert len(events) == 1 and events[0].result == "success"
    assert events[0].target_id == str(site.public_id)
    assert events[0].details and events[0].details["links_present"] == 8


def test_rebuild_is_idempotent(client: TestClient, db: Session) -> None:
    site = default_site(db)
    office(db, site)
    rebuild(client)
    first = {(r.link_key, r.public_id, r.version, r.first_seen_at) for r in links_of(db, site)}
    second = rebuild(client)["counts"]
    assert second["links_created"] == second["links_updated"] == second["links_absent"] == 0
    assert second["links_present"] == 8
    again = {(r.link_key, r.public_id, r.version, r.first_seen_at) for r in links_of(db, site)}
    assert again == first and len(again) == 8
    assert db.scalar(select(text("count(*)")).select_from(TopologyBuild)) == 2


def test_missing_evidence_marks_absent_and_keeps_review(client: TestClient, db: Session) -> None:
    site = default_site(db)
    data = office(db, site)
    rebuild(client)
    edge = next(r for r in links_of(db, site) if r.relation == "fdb_edge")
    _ok(
        client.patch(
            f"{API}/links/{edge.public_id}/review",
            json={"review_state": "accepted", "note": "verified on site", "version": 1},
        )
    )
    db.execute(
        update(NetworkMacEntry).where(NetworkMacEntry.id == data["pc_mac"].id).values(present=False)
    )
    db.commit()
    counts = rebuild(client)["counts"]
    assert counts["links_absent"] == 1 and counts["links_present"] == 7
    row = next(r for r in links_of(db, site) if r.id == edge.id)
    assert row.present is False and row.review_state == "accepted"
    assert row.review_note == "verified on site" and row.version == 3
    graph = _ok(client.get(f"{API}/graph"))
    assert str(edge.public_id) not in {link["id"] for link in graph["links"]}
    graph = _ok(client.get(f"{API}/graph", params={"include_absent": True}))
    absent = next(link for link in graph["links"] if link["id"] == str(edge.public_id))
    assert absent["present"] is False and absent["review_state"] == "accepted"
    listed = _ok(client.get(f"{API}/links", params={"present": False}))
    assert [item["id"] for item in listed["items"]] == [str(edge.public_id)]
    # La evidencia vuelve: misma fila, presente otra vez, revisión intacta.
    db.execute(
        update(NetworkMacEntry).where(NetworkMacEntry.id == data["pc_mac"].id).values(present=True)
    )
    db.commit()
    assert rebuild(client)["counts"]["links_updated"] == 1
    row = next(r for r in links_of(db, site) if r.id == edge.id)
    assert row.present is True and row.review_state == "accepted"


def test_rebuild_conflict_while_running(client: TestClient, db: Session, engine: Engine) -> None:
    site = default_site(db)
    with engine.connect() as other:
        other.execute(
            text("SELECT pg_advisory_xact_lock(:k)"), {"k": topology_site_lock_key(site.id)}
        )
        _error(client.post(f"{API}/rebuild", json={}), 409, "topology_build_running")
        other.rollback()
    assert rebuild(client)["status"] == "succeeded"


def test_scheduled_rebuild_respects_the_interval(client: TestClient, db: Session) -> None:
    site = default_site(db)
    other = new_site(db, "Branch")
    archived = new_site(db, "Old")
    db.execute(update(Site).where(Site.id == archived.id).values(status="archived"))
    db.commit()
    office(db, site)
    settings = get_settings()
    assert run_scheduled_rebuilds(db, settings) == 2
    assert run_scheduled_rebuilds(db, settings) == 0
    builds = db.scalars(select(TopologyBuild)).all()
    assert {(b.site_id, b.trigger, b.requested_by) for b in builds} == {
        (site.id, "scheduled", None),
        (other.id, "scheduled", None),
    }
    # La reconstrucción periódica no se audita (queda en topology_builds).
    assert _audit(db, "topology_rebuilt") == []
    off = settings.model_copy(update={"topology_rebuild_interval_minutes": 0})
    db.execute(
        update(TopologyBuild).values(started_at=TopologyBuild.started_at - timedelta(days=1))
    )
    db.commit()
    assert run_scheduled_rebuilds(db, off) == 0
    assert run_scheduled_rebuilds(db, settings) == 2


# --- aislamiento por site -----------------------------------------------------------------------


def test_same_mac_and_ip_in_two_sites_never_cross(client: TestClient, db: Session) -> None:
    home, branch = default_site(db), new_site(db, "Branch")
    for site in (home, branch):
        add_asset(db, site, "10.0.0.20", "00:20:00:00:00:20")
        add_asset(db, site, "10.0.0.1", "00:20:00:00:00:01")
    switch_home = add_device(db, home, "10.0.0.2")
    port = add_interface(db, switch_home, "Gi0/1", 1)
    add_mac(db, switch_home, "00:20:00:00:00:20", "edge_candidate", port)
    # Un equipo de la sede informa como vecino a un equipo del otro site: no se cruza.
    switch_branch = add_device(db, branch, "10.0.0.2")
    add_neighbor(db, switch_home, "Gi0/48", remote_device_id=switch_branch.id, remote_sys_name="x")
    counts = rebuild(client, home)["counts"]
    assert counts["skipped_cross_site"] == 1
    assert rebuild(client, branch)["counts"]["links_present"] == 0
    home_assets = {
        str(a.public_id) for a in db.scalars(select(Asset).where(Asset.site_id == home.id))
    }
    for row in links_of(db, home):
        for end in (row.source_node, row.target_node):
            assert not end.startswith("asset:") or end.removeprefix("asset:") in home_assets
        assert row.source_device_id != switch_branch.id and row.target_device_id != switch_branch.id
    assert links_of(db, branch) == []
    branch_graph = _ok(client.get(f"{API}/graph", params={"site_id": str(branch.public_id)}))
    assert branch_graph["links"] == [] and len(branch_graph["nodes"]) == 3


def test_duplicate_mac_in_the_same_site_is_ambiguous(client: TestClient, db: Session) -> None:
    site = default_site(db)
    add_asset(db, site, "10.0.0.20", "00:30:00:00:00:01")
    add_asset(db, site, "10.0.0.21", "00:30:00:00:00:01")
    switch = add_device(db, site, "10.0.0.2")
    add_mac(db, switch, "00:30:00:00:00:01", "edge_candidate", add_interface(db, switch, "p1", 1))
    counts = rebuild(client)["counts"]
    assert counts["ambiguous_macs"] == 1 and counts["links_present"] == 0
    # Nunca se fusionan: siguen siendo dos activos.
    assert len(_ok(client.get(f"{API}/graph"))["nodes"]) == 3


def test_archived_assets_are_not_nodes(client: TestClient, db: Session) -> None:
    site = default_site(db)
    data = office(db, site)
    rebuild(client)
    db.execute(update(Asset).where(Asset.id == data["laptop"].id).values(archived_at=now()))
    db.commit()
    graph = _ok(client.get(f"{API}/graph"))
    laptop = f"asset:{data['laptop'].public_id}"
    # Antes de reconstruir ya no se muestra (ni el nodo ni su enlace)...
    assert laptop not in {n["id"] for n in graph["nodes"]}
    assert all(laptop not in (link["source"], link["target"]) for link in graph["links"])
    _error(client.get(f"{API}/nodes/{laptop}"), 404, "topology_node_not_found")
    # ...y la reconstrucción marca su enlace ausente.
    assert rebuild(client)["counts"]["links_absent"] == 1


# --- grafo, nodos, búsqueda ---------------------------------------------------------------------


def test_graph_nodes_labels_groups_and_search(client: TestClient, db: Session) -> None:
    site = new_site(db, "Campus", "192.168.50.0/24")
    data = office(db, site)
    db.execute(
        update(Asset).where(Asset.id == data["router"].id).values(custom_label="Router oficina")
    )
    db.commit()
    rebuild(client, site)
    params = {"site_id": str(site.public_id)}
    graph = _ok(client.get(f"{API}/graph", params=params))
    nodes = {n["id"]: n for n in graph["nodes"]}
    assert [n["id"] for n in graph["nodes"]] == sorted(nodes)
    assert [link["id"] for link in graph["links"]] == sorted(link["id"] for link in graph["links"])
    router = nodes[f"asset:{data['router'].public_id}"]
    assert router["label"] == "Router oficina" and router["custom_label"] == "Router oficina"
    assert router["automatic_name"] == "archer-gx90"
    assert router["groups"] == ["network:192.168.50.0/24"] and router["link_count"] == 1
    assert router["identity_confidence"] == "high"
    pc = nodes[f"asset:{data['pc'].public_id}"]
    assert (pc["managed"], pc["identity_confidence"], pc["role"]) == (True, "high", "unknown")
    assert pc["link_count"] == 2 and "agent" in pc["sources"]
    # Nombre desconocido: la etiqueta es la IP (la UI pone su texto de reserva aparte).
    printer = nodes[f"asset:{data['printer'].public_id}"]
    assert printer["label"] == "192.168.50.30" and printer["custom_label"] is None
    core = nodes[f"network_device:{data['core'].public_id}"]
    assert (core["kind"], core["role"], core["sources"], core["label"]) == (
        "network_device",
        "infrastructure",
        ["snmp"],
        "core",
    )
    ap = nodes[f"wlan_ap:{data['ap'].public_id}"]
    assert (ap["kind"], ap["device_type"], ap["role"]) == (
        "wlan_ap",
        "access_point",
        "infrastructure",
    )
    external = next(n for n in graph["nodes"] if n["kind"] == "external")
    assert (external["label"], external["sources"], external["ip"]) == ("isp-cpe", ["lldp"], None)
    assert external["groups"] == ["unassigned"]
    groups = {g["id"]: g for g in graph["groups"]}
    assert groups["network:192.168.50.0/24"]["name"] == "LAN Campus"
    assert groups["network:192.168.50.0/24"]["node_count"] == 8
    assert graph["last_build"]["status"] == "succeeded" and graph["truncated"] is False

    def search(q: str) -> set[str]:
        found = _ok(client.get(f"{API}/graph", params={**params, "q": q}))
        return {n["id"] for n in found["nodes"]}

    router_id = f"asset:{data['router'].public_id}"
    assert router_id in search("router ofi")  # etiqueta personalizada
    assert router_id in search("archer")  # nombre automático
    assert router_id in search("00-10-00-00-00-01")  # MAC con guiones
    assert router_id in search("192.168.50.1")
    found = search("laptop-ana")
    # El nodo encontrado, sus enlaces y los extremos de esos enlaces.
    assert found == {f"asset:{data['laptop'].public_id}", f"wlan_ap:{data['ap'].public_id}"}
    assert search("no-such-thing") == set()
    kinds = _ok(client.get(f"{API}/graph", params={**params, "kinds": "physical,logical"}))
    assert {link["kind"] for link in kinds["links"]} == {"physical", "logical"}
    _error(
        client.get(f"{API}/graph", params={"kinds": "physical,bogus"}), 422, "topology_invalid_kind"
    )
    typed = _ok(client.get(f"{API}/graph", params={**params, "device_type": "access_point"}))
    assert f"wlan_ap:{data['ap'].public_id}" in {n["id"] for n in typed["nodes"]}


def test_node_detail_and_inventory_path(client: TestClient, db: Session) -> None:
    site = default_site(db)
    data = office(db, site)
    db.execute(
        update(Asset)
        .where(Asset.id == data["pc"].id)
        .values(
            observed_names=[
                {
                    "value": "PC-ADMIN-01",
                    "source": "agent",
                    "kind": "agent",
                    "selected": True,
                    "confirmed": None,
                    "stale": False,
                    "seen_at": now().isoformat(),
                }
            ]
        )
    )
    db.commit()
    rebuild(client)
    key = f"asset:{data['pc'].public_id}"
    detail = _ok(client.get(f"{API}/nodes/{key}"))
    assert (
        detail["node"]["id"] == key
        and detail["inventory_path"] == f"/assets/{data['pc'].public_id}"
    )
    assert {link["relation"] for link in detail["links"]} == {"fdb_edge", "default_gateway"}
    assert detail["node"]["link_count"] == 2
    assert [n["value"] for n in detail["observed_names"]] == ["PC-ADMIN-01"]
    # Mayúsculas en el UUID: misma clave canónica.
    assert (
        _ok(client.get(f"{API}/nodes/{key.upper().replace('ASSET', 'asset')}"))["node"]["id"] == key
    )
    external = next(r for r in links_of(db, site) if r.target_node.startswith("external:"))
    ext = _ok(client.get(f"{API}/nodes/{external.target_node}"))
    assert ext["node"]["kind"] == "external" and ext["inventory_path"] is None
    device = _ok(client.get(f"{API}/nodes/network_device:{data['core'].public_id}"))
    assert device["inventory_path"].startswith("/network")


def test_not_found_between_sites_and_malformed(client: TestClient, db: Session) -> None:
    home, branch = default_site(db), new_site(db, "Branch")
    data = office(db, branch)
    rebuild(client, branch)
    link = links_of(db, branch)[0]
    pc = f"asset:{data['pc'].public_id}"
    home_id, branch_id = str(home.public_id), str(branch.public_id)
    _error(client.get(f"{API}/nodes/{pc}"), 404, "topology_node_not_found")
    _error(
        client.get(f"{API}/nodes/{pc}", params={"site_id": home_id}), 404, "topology_node_not_found"
    )
    assert _ok(client.get(f"{API}/nodes/{pc}", params={"site_id": branch_id}))["node"]["id"] == pc
    for bad in ("asset:not-a-uuid", "router:1", "external:XYZ", "x" * 200, f"asset:{uuid4()}"):
        _error(client.get(f"{API}/nodes/{bad}"), 404, "topology_node_not_found")
    _error(
        client.get(f"{API}/links/{link.public_id}", params={"site_id": home_id}),
        404,
        "topology_link_not_found",
    )
    assert _ok(client.get(f"{API}/links/{link.public_id}", params={"site_id": branch_id}))
    for bad in ("1", "not-a-uuid", str(uuid4())):
        _error(client.get(f"{API}/links/{bad}"), 404, "topology_link_not_found")
    _error(
        client.patch(
            f"{API}/links/{link.public_id}/review",
            params={"site_id": home_id},
            json={"review_state": "rejected", "version": 1},
        ),
        404,
        "topology_link_not_found",
    )
    _error(client.get(f"{API}/graph", params={"site_id": str(uuid4())}), 404, "site_not_found")
    _error(client.post(f"{API}/rebuild", json={"site_id": str(uuid4())}), 404, "site_not_found")


# --- enlaces y revisión -------------------------------------------------------------------------


def test_links_list_filters_and_pagination(client: TestClient, db: Session) -> None:
    site = default_site(db)
    data = office(db, site)
    rebuild(client)
    full = _ok(client.get(f"{API}/links"))
    assert full["total"] == 8 and full["limit"] == 50 and full["offset"] == 0
    assert [i["id"] for i in full["items"]] == sorted(i["id"] for i in full["items"])
    page = _ok(client.get(f"{API}/links", params={"limit": 3, "offset": 6}))
    assert page["total"] == 8 and [i["id"] for i in page["items"]] == [
        i["id"] for i in full["items"][6:]
    ]
    shared = _ok(client.get(f"{API}/links", params={"kind": "candidate"}))
    assert shared["total"] == 2 and {i["confidence"] for i in shared["items"]} == {"low"}
    high = _ok(client.get(f"{API}/links", params={"confidence": "high"}))
    assert {i["relation"] for i in high["items"]} == {"lldp", "wlan_managed_by"}
    core = f"network_device:{data['core'].public_id}"
    by_node = _ok(client.get(f"{API}/links", params={"node": core}))
    assert by_node["total"] == 2
    for params in ({"limit": 0}, {"limit": 201}, {"offset": -1}, {"kind": "cable"}):
        _error(client.get(f"{API}/links", params=params), 422, "validation_error")
    detail = _ok(client.get(f"{API}/links/{high['items'][0]['id']}"))
    assert detail["version"] == 1 and detail["review_note"] is None
    assert detail["evidence"] and {"source", "detail", "observed_at"} <= set(detail["evidence"][0])
    external = next(r for r in links_of(db, site) if r.target_node.startswith("external:"))
    ext = _ok(client.get(f"{API}/links/{external.public_id}"))
    assert ext["target_external"]["sys_name"] == "isp-cpe"
    assert ext["target_external"]["chassis_id"] == "00:cc:00:00:00:01"


def test_review_conflict_rejected_hidden_and_audited(client: TestClient, db: Session) -> None:
    site = default_site(db)
    office(db, site)
    rebuild(client)
    candidate = next(r for r in links_of(db, site) if r.kind == "candidate")
    path = f"{API}/links/{candidate.public_id}/review"
    reviewed = _ok(
        client.patch(path, json={"review_state": "rejected", "note": "AP behind", "version": 1})
    )
    assert (reviewed["review_state"], reviewed["version"], reviewed["reviewed_by"]) == (
        "rejected",
        2,
        "admin",
    )
    # La revisión no cambia la clase ni la confianza.
    assert (reviewed["kind"], reviewed["confidence"]) == ("candidate", "low")
    _error(
        client.patch(path, json={"review_state": "accepted", "version": 1}),
        409,
        "topology_link_conflict",
    )
    graph = _ok(client.get(f"{API}/graph"))
    assert str(candidate.public_id) not in {link["id"] for link in graph["links"]}
    graph = _ok(client.get(f"{API}/graph", params={"include_rejected": True}))
    assert str(candidate.public_id) in {link["id"] for link in graph["links"]}
    # Sobrevive a la reconstrucción.
    rebuild(client)
    row = next(r for r in links_of(db, site) if r.id == candidate.id)
    assert (row.review_state, row.review_note, row.version) == ("rejected", "AP behind", 2)
    events = _audit(db, "topology_link_reviewed")
    assert len(events) == 1 and events[0].details
    assert (events[0].details["from"], events[0].details["to"]) == ("unreviewed", "rejected")
    for body in (
        {"review_state": "accepted", "note": "line\nbreak", "version": 2},
        {"review_state": "accepted", "note": "x" * 501, "version": 2},
        {"review_state": "maybe", "version": 2},
        {"review_state": "accepted", "version": 0},
        {"review_state": "accepted", "version": 2, "kind": "physical"},
    ):
        _error(client.patch(path, json=body), 422, "validation_error")
    back = _ok(client.patch(path, json={"review_state": "unreviewed", "note": "", "version": 2}))
    assert back["review_state"] == "unreviewed" and back["review_note"] is None


# --- permisos -----------------------------------------------------------------------------------


@pytest.mark.parametrize("role", ["viewer", "analyst"])
def test_read_roles_cannot_rebuild_or_review(
    client: TestClient, engine: Engine, db: Session, role: str
) -> None:
    site = default_site(db)
    office(db, site)
    rebuild(client)
    link = links_of(db, site)[0]
    with as_role(client, engine, role) as browser:
        assert _ok(browser.get(f"{API}/graph"))["links"]
        assert _ok(browser.get(f"{API}/status"))["links_present"] == 8
        assert _ok(browser.get(f"{API}/links"))["total"] == 8
        assert _ok(browser.get(f"{API}/links/{link.public_id}"))["id"] == str(link.public_id)
        _error(browser.post(f"{API}/rebuild", json={}), 403, "permission_denied")
        _error(
            browser.patch(
                f"{API}/links/{link.public_id}/review",
                json={"review_state": "accepted", "version": 1},
            ),
            403,
            "permission_denied",
        )
    denied = _audit(db, "permission_denied")
    assert len(denied) == 2 and {e.result for e in denied} == {"denied"}
    assert len(_audit(db, "topology_rebuilt")) == 1


def test_anonymous_gets_401(client: TestClient) -> None:
    with TestClient(client.app) as anonymous:
        _error(anonymous.get(f"{API}/graph"), 401, "not_authenticated")


# --- límites ------------------------------------------------------------------------------------


def test_limits_truncate_with_priority(client: TestClient, db: Session) -> None:
    site = default_site(db)
    data = office(db, site)
    for i in range(20):
        add_asset(db, site, f"192.168.60.{i + 10}")
    rebuild(client)
    settings = get_settings().model_copy(
        update={"topology_max_nodes": 10, "topology_max_links": 50}
    )
    service = TopologyService(db, settings)
    graph = service.graph(
        site, kinds=None, include_absent=False, include_rejected=False, device_type=None, q=None
    )
    assert graph.truncated is True and len(graph.nodes) == 10
    assert graph.limits.max_nodes == 10
    ids = {n.id for n in graph.nodes}
    # Primero los nodos con enlaces y la infraestructura; ningún enlace queda colgando.
    assert f"network_device:{data['core'].public_id}" in ids
    assert all(link.source in ids and link.target in ids for link in graph.links)
    few_links = get_settings().model_copy(update={"topology_max_links": 3})
    graph = TopologyService(db, few_links).graph(
        site, kinds=None, include_absent=False, include_rejected=False, device_type=None, q=None
    )
    assert graph.truncated is True and len(graph.links) <= 3
    assert sorted(link.kind for link in graph.links) == ["logical", "physical", "physical"]
    # El tope también acota la reconstrucción (links_dropped).
    build = TopologyService(db, few_links).rebuild(site, "manual")
    assert build.counts is not None
    assert build.counts["links_present"] == 3 and build.counts["links_dropped"] == 5


# --- informes v2 --------------------------------------------------------------------------------


def test_report_topology_shape_and_filters(client: TestClient, db: Session) -> None:
    site = default_site(db)
    data = office(db, site)
    assert report_topology(db, site.id) == {
        "nodes": [],
        "links": [],
        "truncated": False,
        "built_at": None,
    }
    rebuild(client)
    report = report_topology(db, site.public_id)
    assert set(report) == {"nodes", "links", "truncated", "built_at"}
    assert report["built_at"] is not None and report["truncated"] is False
    # Sin candidatos ni desconocidos: 8 enlaces menos los 2 fdb_shared.
    assert len(report["links"]) == 6
    assert {link["kind"] for link in report["links"]} == {"physical", "logical", "observed"}
    assert set(report["nodes"][0]) == {"id", "label", "kind", "device_type", "role"}
    assert set(report["links"][0]) == {"source", "target", "kind", "relation", "confidence"}
    assert [n["id"] for n in report["nodes"]] == sorted(n["id"] for n in report["nodes"])
    rejected = next(r for r in links_of(db, site) if r.relation == "default_gateway")
    db.execute(
        update(TopologyLink).where(TopologyLink.id == rejected.id).values(review_state="rejected")
    )
    db.commit()
    pc_only = report_topology(db, site.id, asset_ids=[data["pc"].id])
    assert [link["relation"] for link in pc_only["links"]] == ["fdb_edge"]
    by_uuid = report_topology(db, site.id, asset_ids=[data["pc"].public_id])
    assert by_uuid == pc_only
    assert report_topology(db, site.id, asset_ids=[])["links"] == []
    small = report_topology(db, site.id, max_nodes=2)
    assert small["truncated"] is True and len(small["nodes"]) == 2
    kept = {n["id"] for n in small["nodes"]}
    assert all(link["source"] in kept and link["target"] in kept for link in small["links"])


def test_report_v2_draws_the_real_topology(client: TestClient, db: Session) -> None:
    """Integración informe v2 + motor: el snapshot y el diagrama salen de la topología real
    persistida, solo con enlaces verificados y de forma determinista."""
    from app.reports import builders_v2
    from app.reports.document import Diagram
    from app.reports.templates_v2 import topology_blocks

    site = default_site(db)
    office(db, site)
    rebuild(client)
    [section] = builders_v2.topology(db, [site.id], None)
    assert section["status"] == "ok" and section["site"] == site.name
    assert len(section["links"]) == 6
    assert {link["kind"] for link in section["links"]} <= {"physical", "logical", "observed"}
    assert all(link["kind"] != "candidate" for link in section["links"])
    blocks = topology_blocks([section])
    diagrams = [b for b in blocks if isinstance(b, Diagram)]
    assert len(diagrams) == 1
    # Misma base, mismo resultado: el informe es reproducible.
    assert builders_v2.topology(db, [site.id], None) == [section]
    assert topology_blocks([section]) == blocks


# --- OpenAPI ------------------------------------------------------------------------------------


def test_openapi_documents_the_topology_api(client: TestClient) -> None:
    spec = client.get("/openapi.json").json()
    paths = spec["paths"]
    expected = {
        ("get", "/api/v1/topology/graph"): {"200", "401", "403", "404", "422", "503"},
        ("get", "/api/v1/topology/links"): {"200", "401", "403", "404", "422", "503"},
        ("get", "/api/v1/topology/links/{link_id}"): {"200", "401", "403", "404", "422", "503"},
        ("patch", "/api/v1/topology/links/{link_id}/review"): {
            "200",
            "401",
            "403",
            "404",
            "409",
            "422",
            "503",
        },
        ("get", "/api/v1/topology/nodes/{node_id}"): {"200", "401", "403", "404", "422", "503"},
        ("post", "/api/v1/topology/rebuild"): {"200", "401", "403", "404", "409", "422", "503"},
        ("get", "/api/v1/topology/status"): {"200", "401", "403", "404", "422", "503"},
    }
    for (method, path), statuses in expected.items():
        operation = paths[path][method]
        assert set(operation["responses"]) == statuses, (method, path)
        assert operation["tags"] == ["topology"]
    schemas = spec["components"]["schemas"]
    for name in (
        "TopologyGraph",
        "TopologyNode",
        "TopologyLink",
        "TopologyLinkDetail",
        "TopologyLinkList",
        "TopologyNodeDetail",
        "TopologyBuild",
        "TopologyStatus",
        "TopologyReviewUpdate",
    ):
        assert name in schemas, name
    review = schemas["TopologyReviewUpdate"]["properties"]
    assert review["note"]["anyOf"][0]["maxLength"] == 500
