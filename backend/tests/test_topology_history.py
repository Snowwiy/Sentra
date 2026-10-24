"""Fase 6E.1: historial de topología y cambios de red (docs/topology-history.md).

Primero las reglas puras del diff (sin base de datos) y después el registro dentro de la
reconstrucción, la conclusión de enlaces eliminados, la API, la revisión, el enfriamiento y
la retención con PostgreSQL. Los datos de red se crean con los ayudantes de test_topology.
"""

import hashlib
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select, text, update
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.models.asset import Asset
from app.models.audit import AuditEvent
from app.models.network import NetworkDevice
from app.models.topology import TopologyBuild, TopologyLink
from app.models.topology_history import NetworkChange, TopologySnapshot
from app.topology.history import DiffContext, canonical_hash, diff_snapshots, pair_key, vlan_of
from app.topology.history_service import purge_topology_history, rebuild_cooldown_remaining
from app.topology.service import TopologyService
from tests.conftest import authenticate
from tests.test_topology import (
    add_asset,
    add_device,
    add_interface,
    add_mac,
    add_neighbor,
    default_site,
)

API = "/api/v1/topology"


def now() -> datetime:
    return datetime.now(UTC)


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session
    with engine.begin() as connection:
        connection.execute(
            text(
                "TRUNCATE network_changes, topology_snapshots, topology_links, topology_builds"
                " RESTART IDENTITY"
            )
        )


def _ok(response: Any, status: int = 200) -> Any:
    assert response.status_code == status, response.text
    return response.json()


# --- reglas puras -------------------------------------------------------------------------------


def _node(**fields: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "kind": "asset",
        "label": "pc",
        "ip": "10.0.0.5",
        "mac": "aa:aa:aa:aa:aa:01",
        "vendor": None,
        "device_type": None,
        "role": "endpoint",
        "status": "online",
        "managed": False,
        "identity": "low",
        "gateways": [],
        "wifi": None,
    }
    base.update(fields)
    return base


def _link(s: str, t: str, **fields: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "s": s,
        "t": t,
        "k": "observed",
        "rel": "fdb_edge",
        "c": "medium",
        "med": "wired",
        "sp": "Gi0/3",
        "tp": None,
        "vlan": 10,
        "id": "x",
    }
    base.update(fields)
    return base


def test_hash_depends_only_on_content() -> None:
    nodes = {"asset:a": _node()}
    assert canonical_hash(nodes, {}) == canonical_hash(dict(nodes), {})
    assert canonical_hash(nodes, {}) != canonical_hash({"asset:a": _node(ip="10.0.0.6")}, {})


def test_missing_node_is_not_observed_unless_retired() -> None:
    old = {"asset:a": _node(), "asset:b": _node(label="b")}
    changes = diff_snapshots(old, {}, {"asset:a": _node()}, {}, DiffContext())
    assert [(c.change_type, c.subject_key) for c in changes] == [("device_not_observed", "asset:b")]
    retired = diff_snapshots(
        old, {}, {"asset:a": _node()}, {}, DiffContext(retired_nodes=frozenset({"asset:b"}))
    )
    assert retired[0].change_type == "device_retired"


def test_offline_without_agent_is_disappeared_but_agent_offline_is_connectivity() -> None:
    old = {"asset:a": _node(), "asset:m": _node(managed=True)}
    new = {"asset:a": _node(status="offline"), "asset:m": _node(managed=True, status="offline")}
    types = {c.subject_key: c.change_type for c in diff_snapshots(old, {}, new, {}, DiffContext())}
    assert types == {"asset:a": "device_disappeared", "asset:m": "connectivity_changed"}


def test_identity_field_changes_and_blank_values() -> None:
    old = {"asset:a": _node(vendor="TP-Link")}
    new = {"asset:a": _node(ip="10.0.0.9", label="pixel-7", vendor=None)}
    types = sorted(c.change_type for c in diff_snapshots(old, {}, new, {}, DiffContext()))
    # El fabricante que deja de informarse no es un cambio del dispositivo.
    assert types == ["ip_changed", "name_changed"]


def test_port_change_is_recognised_instead_of_add_and_remove() -> None:
    nodes = {"network_device:s": _node(kind="network_device"), "asset:a": _node()}
    old = {"k1": _link("network_device:s", "asset:a", sp="Gi0/3")}
    new = {"k2": _link("network_device:s", "asset:a", sp="Gi0/5")}
    changes = diff_snapshots(nodes, old, nodes, new, DiffContext())
    assert [c.change_type for c in changes] == ["link_port_changed"]
    assert changes[0].before == {"source_port": "Gi0/3", "target_port": None}
    assert pair_key(old["k1"]) == pair_key(new["k2"])


def test_link_vlan_kind_confidence_and_absence() -> None:
    nodes = {"network_device:s": _node(kind="network_device"), "asset:a": _node()}
    old = {
        "k1": _link("network_device:s", "asset:a"),
        "k2": _link("network_device:s", "asset:b", rel="lldp"),
    }
    new = {"k1": _link("network_device:s", "asset:a", vlan=20, c="low")}
    types = sorted(c.change_type for c in diff_snapshots(nodes, old, nodes, new, DiffContext()))
    # Un enlace que falta en un snapshot nunca es "eliminado" en el diff.
    assert types == ["link_confidence_changed", "link_not_observed", "link_vlan_changed"]


def test_wifi_ap_change() -> None:
    old = {"asset:a": _node(wifi={"ap": "wlan_ap:1", "ssid": "Casa"})}
    new = {"asset:a": _node(wifi={"ap": "wlan_ap:2", "ssid": "Casa"})}
    changes = diff_snapshots(old, {}, new, {}, DiffContext())
    assert [c.change_type for c in changes] == ["wifi_ap_changed"]


def test_vlan_is_read_from_fdb_evidence() -> None:
    assert vlan_of([{"detail": "MAC aa learned on port Gi0/3 vlan 30; 1 MAC(s)"}]) == 30
    assert vlan_of([{"detail": "no vlan here"}]) is None


# --- registro en la reconstrucción --------------------------------------------------------------


def _lab(db: Session) -> dict[str, Any]:
    """Dos switches con LLDP recíproco y un PC visto en un puerto de acceso."""
    site = default_site(db)
    pc = add_asset(db, site, "192.168.50.20", "00:10:00:00:00:20", hostname="pc-1")
    core = add_device(db, site, "192.168.50.2", name="core")
    access = add_device(db, site, "192.168.50.3", name="access")
    core_up = add_interface(db, core, "Gi1/0/1", 1)
    access_up = add_interface(db, access, "Gi0/24", 24)
    access_pc = add_interface(db, access, "Gi0/3", 3)
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
    mac = add_mac(db, access, "00:10:00:00:00:20", "edge_candidate", access_pc)
    return {"site": site, "pc": pc, "core": core, "access": access, "mac": mac}


def _rebuild(db: Session) -> TopologyBuild:
    service = TopologyService(db, get_settings())
    build = service.rebuild(default_site(db), "scheduled")
    row = db.scalars(select(TopologyBuild).where(TopologyBuild.public_id == build.id)).one()
    db.expire_all()
    return row


def _changes(db: Session) -> list[NetworkChange]:
    db.expire_all()
    return list(db.scalars(select(NetworkChange).order_by(NetworkChange.id)))


def test_first_rebuild_is_a_baseline_and_identical_rebuilds_only_confirm(db: Session) -> None:
    _lab(db)
    first = _rebuild(db)
    assert first.counts is not None and first.counts["snapshot_created"] == 1
    assert first.counts["changes_detected"] == 0
    second = _rebuild(db)
    assert second.counts is not None and second.counts["snapshot_created"] == 0
    snapshots = list(db.scalars(select(TopologySnapshot)))
    assert len(snapshots) == 1
    assert snapshots[0].confirmations == 2 and snapshots[0].quality == "complete"
    assert snapshots[0].node_count >= 3 and snapshots[0].link_count >= 2
    assert _changes(db) == []


def test_ip_change_creates_snapshot_and_change_with_asset(db: Session) -> None:
    lab = _lab(db)
    _rebuild(db)
    db.execute(update(Asset).where(Asset.id == lab["pc"].id).values(primary_ip="192.168.50.21"))
    db.commit()
    build = _rebuild(db)
    assert build.counts is not None and build.counts["snapshot_created"] == 1
    changes = _changes(db)
    assert [c.change_type for c in changes] == ["ip_changed"]
    assert changes[0].asset_id == lab["pc"].id
    assert changes[0].before == {"ip": "192.168.50.20"}
    assert changes[0].after == {"ip": "192.168.50.21"}
    sequences = sorted(db.scalars(select(TopologySnapshot.sequence)))
    assert sequences == [1, 2]
    assert changes[0].from_snapshot_id is not None and changes[0].to_snapshot_id is not None


def test_link_removed_only_after_confirmations_with_healthy_source(db: Session) -> None:
    lab = _lab(db)
    _rebuild(db)
    db.delete(db.get(type(lab["mac"]), lab["mac"].id))
    db.commit()
    _rebuild(db)
    assert [c.change_type for c in _changes(db)] == ["link_not_observed"]
    # Ausencias 2 y 3 (TOPOLOGY_LINK_REMOVAL_CONFIRMATIONS=3 en conftest).
    _rebuild(db)
    assert [c.change_type for c in _changes(db)] == ["link_not_observed"]
    _rebuild(db)
    assert [c.change_type for c in _changes(db)] == ["link_not_observed", "link_removed"]
    # Se concluye una sola vez.
    _rebuild(db)
    assert [c.change_type for c in _changes(db)] == ["link_not_observed", "link_removed"]


def test_degraded_source_never_concludes_removal(db: Session) -> None:
    lab = _lab(db)
    _rebuild(db)
    db.execute(
        update(NetworkDevice)
        .where(NetworkDevice.id == lab["access"].id)
        .values(snmp_status="no_response")
    )
    db.delete(db.get(type(lab["mac"]), lab["mac"].id))
    db.commit()
    for _ in range(5):
        _rebuild(db)
    types = [c.change_type for c in _changes(db)]
    assert "link_removed" not in types and "link_not_observed" in types
    latest = db.scalars(
        select(TopologySnapshot).order_by(TopologySnapshot.sequence.desc()).limit(1)
    ).one()
    assert latest.quality == "degraded"
    link = db.scalars(select(TopologyLink).where(TopologyLink.relation == "fdb_edge")).one()
    assert link.absent_builds >= 3 and link.removed_at is None


def test_archived_asset_is_retired(db: Session) -> None:
    lab = _lab(db)
    _rebuild(db)
    db.execute(update(Asset).where(Asset.id == lab["pc"].id).values(archived_at=now()))
    db.commit()
    _rebuild(db)
    types = {c.change_type for c in _changes(db)}
    assert "device_retired" in types


# --- API ----------------------------------------------------------------------------------------


def test_snapshots_diff_export_and_history_api(client: TestClient, db: Session) -> None:
    lab = _lab(db)
    _rebuild(db)
    db.execute(update(Asset).where(Asset.id == lab["pc"].id).values(device_name="pc-renamed"))
    db.commit()
    _rebuild(db)

    page = _ok(client.get(f"{API}/snapshots?limit=1"))
    assert len(page["items"]) == 1 and page["items"][0]["sequence"] == 2
    assert page["next_before_sequence"] == 2
    older = _ok(client.get(f"{API}/snapshots?before_sequence=2"))
    assert [s["sequence"] for s in older["items"]] == [1]
    first, second = older["items"][0]["id"], page["items"][0]["id"]

    detail = _ok(client.get(f"{API}/snapshots/{first}"))
    assert f"asset:{lab['pc'].public_id}" in detail["nodes"]

    diff = _ok(client.get(f"{API}/diff?from_snapshot={first}&to_snapshot={second}"))
    assert diff["summary"]["by_type"] == {"name_changed": 1}
    # Sin destino: el estado actual. Filtro por subred que no contiene el activo: nada.
    assert _ok(client.get(f"{API}/diff?from_snapshot={first}"))["summary"]["total"] == 1
    empty = _ok(client.get(f"{API}/diff?from_snapshot={first}&subnet=10.9.0.0/16"))
    assert empty["summary"]["total"] == 0
    missing = client.get(f"{API}/diff")
    assert missing.status_code == 422
    assert missing.json()["error"]["code"] == "topology_diff_missing_from"

    exported = client.get(f"{API}/diff/export?from_snapshot={first}&format=csv")
    assert exported.status_code == 200
    assert exported.headers["x-sentra-sha256"] == hashlib.sha256(exported.content).hexdigest()
    assert exported.text.splitlines()[0].startswith("change_type,")

    node = f"asset:{lab['pc'].public_id}"
    history = _ok(client.get(f"{API}/history/nodes/{node}"))
    assert [e["sequence"] for e in history["entries"]] == [1, 2]
    assert history["entries"][1]["value"]["label"] == "pc-renamed"
    assert client.get(f"{API}/history/nodes/asset:not-a-uuid").status_code == 404

    link = db.scalars(select(TopologyLink).where(TopologyLink.relation == "lldp")).first()
    assert link is not None
    link_history = _ok(client.get(f"{API}/history/links/{link.public_id}"))
    assert link_history["entries"][0]["present"] is True
    assert client.get(f"{API}/snapshots/{lab['pc'].public_id}").status_code == 404


def test_changes_list_and_review(client: TestClient, db: Session, engine: Engine) -> None:
    lab = _lab(db)
    _rebuild(db)
    db.execute(update(Asset).where(Asset.id == lab["pc"].id).values(primary_ip="192.168.50.99"))
    db.commit()
    _rebuild(db)
    listing = _ok(client.get(f"{API}/changes?change_type=ip_changed"))
    assert listing["total"] == 1
    change = listing["items"][0]
    assert change["asset_id"] == str(lab["pc"].public_id)
    assert _ok(client.get(f"{API}/changes?subnet=192.168.50.0/24"))["total"] == 1
    assert _ok(client.get(f"{API}/changes?subnet=10.0.0.0/8"))["total"] == 0
    bad = client.get(f"{API}/changes?subnet=nonsense")
    assert bad.status_code == 422 and bad.json()["error"]["code"] == "topology_invalid_subnet"

    url = f"{API}/changes/{change['id']}/review"
    reviewed = _ok(client.patch(url, json={"status": "confirmed", "note": "DHCP", "version": 1}))
    assert reviewed["status"] == "confirmed" and reviewed["version"] == 2
    conflict = client.patch(url, json={"status": "dismissed", "version": 1})
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "network_change_conflict"
    db.expire_all()
    assert db.scalars(
        select(AuditEvent).where(AuditEvent.action == "network_change_reviewed")
    ).first()

    authenticate(client, engine, "viewer")
    assert client.get(f"{API}/changes").status_code == 200
    denied = client.patch(url, json={"status": "dismissed", "version": 2})
    assert denied.status_code == 403


def test_manual_rebuild_cooldown(client: TestClient, db: Session) -> None:
    _lab(db)
    settings = get_settings().model_copy(update={"topology_manual_rebuild_cooldown_seconds": 60})
    site = default_site(db)
    assert rebuild_cooldown_remaining(db, settings, site.id) == 0
    _ok(client.post(f"{API}/rebuild", json={}))
    remaining = rebuild_cooldown_remaining(db, settings, site.id)
    assert 0 < remaining <= 60
    # La programada no cuenta para el enfriamiento manual.
    db.execute(update(TopologyBuild).values(trigger="scheduled"))
    db.commit()
    assert rebuild_cooldown_remaining(db, settings, site.id) == 0


def test_retention_keeps_latest_and_preserved(db: Session) -> None:
    lab = _lab(db)
    _rebuild(db)
    db.execute(update(Asset).where(Asset.id == lab["pc"].id).values(primary_ip="192.168.50.77"))
    db.commit()
    _rebuild(db)
    old = now() - timedelta(days=400)
    db.execute(update(TopologySnapshot).values(confirmed_at=old, taken_at=old))
    db.execute(update(NetworkChange).values(detected_at=old))
    db.execute(update(TopologyBuild).values(started_at=old))
    db.commit()
    first = db.scalars(select(TopologySnapshot).where(TopologySnapshot.sequence == 1)).one()
    result = purge_topology_history(db, get_settings())
    assert result["topology_snapshots"] == 1 and result["network_changes"] == 1
    assert result["topology_builds"] == 1
    remaining = list(db.scalars(select(TopologySnapshot.sequence)))
    assert remaining == [2]
    assert db.get(TopologySnapshot, first.id) is None
    # Un snapshot preservado sobrevive aunque sea antiguo.
    db.execute(update(TopologySnapshot).values(preserved=True))
    db.commit()
    assert purge_topology_history(db, get_settings())["topology_snapshots"] == 0
