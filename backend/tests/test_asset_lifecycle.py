"""Fase 5C.1: ciclo de vida de activos (archivar, restaurar, borrar, duplicados, reconciliar).

Escenarios de la especificación:
A. agente antiguo revocado + agente nuevo del mismo equipo (caso real Ravenslg);
B. archivar un activo gestionado: oculto, fuera del resumen, restaurable, historial intacto;
C. borrar un activo descubierto sin historial (y rechazar el borrado con historial);
D. permisos por rol y concurrencia optimista.
"""

from collections.abc import Iterator
from datetime import UTC, datetime
from itertools import count
from typing import Any

import pytest
from alembic import command
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select, text
from sqlalchemy.orm import Session, sessionmaker

from app.models.asset import Asset, AssetStatus, MonitoringMethod
from app.models.audit import AuditEvent
from app.models.detection import DetectionSeverity
from app.services.reconciliation import _network_gear
from tests.conftest import agent_payload, authenticate
from tests.test_risk import _detection
from tests.test_telemetry import telemetry_payload

API = "/api/v1"
ASSETS = f"{API}/assets"
REGISTER = f"{API}/agents/register"
MACHINE = "a" * 64
_ips = count(10)


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


def _register(client: TestClient, **host: Any) -> dict[str, Any]:
    payload = agent_payload(**host)
    response = client.post(REGISTER, json=payload)
    assert response.status_code == 201, response.text
    return {"agent_id": payload["agent_id"], "asset_id": response.json()["asset_id"]}


def _revoke(client: TestClient, asset_id: str) -> None:
    response = client.post(f"{API}/console/agents/{asset_id}/revoke")
    assert response.status_code == 200, response.text


def _asset(client: TestClient, asset_id: str) -> dict[str, Any]:
    response = client.get(f"{ASSETS}/{asset_id}")
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def _archive(client: TestClient, asset_id: str, reason: str = "Equipo retirado") -> Any:
    version = _asset(client, asset_id)["lifecycle_version"]
    return client.post(f"{ASSETS}/{asset_id}/archive", json={"reason": reason, "version": version})


def _ids(client: TestClient, **params: Any) -> set[str]:
    response = client.get(ASSETS, params={"limit": 200, **params})
    assert response.status_code == 200, response.text
    return {a["asset_id"] for a in response.json()["items"]}


def _discovered(db: Session, **fields: Any) -> Asset:
    now = datetime.now(UTC)
    values: dict[str, Any] = {
        "monitoring_method": MonitoringMethod.DISCOVERED,
        "primary_ip": f"10.77.0.{next(_ips)}",
        "status": AssetStatus.UNKNOWN,
        "network_status": AssetStatus.ONLINE,
        "last_network_seen_at": now,
        "first_seen_at": now,
        "mac_address": "aa:bb:cc:00:11:22",
        **fields,
    }
    asset = Asset(**values)
    db.add(asset)
    db.commit()
    return asset


def _audits(db: Session, action: str) -> list[AuditEvent]:
    db.expire_all()
    return list(db.scalars(select(AuditEvent).where(AuditEvent.action == action)))


def _error(response: Any) -> str:
    code: str = response.json()["error"]["code"]
    return code


# --- A. Reinstalación: agente revocado + agente nuevo ----------------------------------------


def _ravenslg(client: TestClient) -> tuple[dict[str, Any], dict[str, Any]]:
    host = {"hostname": "Ravenslg", "primary_ip": "192.168.50.66", "os_name": "Windows"}
    old = _register(client, agent_version="0.1.0", **host)
    sample = client.post(f"{API}/telemetry", json=telemetry_payload(old["agent_id"]))
    assert sample.status_code == 201, sample.text
    _revoke(client, old["asset_id"])
    new = _register(client, agent_version="0.2.0", **host)
    return old, new


def test_reinstalled_agent_is_suggested_as_duplicate_of_the_revoked_asset(
    client: TestClient, db: Session
) -> None:
    old, new = _ravenslg(client)
    assert old["asset_id"] != new["asset_id"]

    response = client.get(f"{ASSETS}/{new['asset_id']}/duplicate-candidates")
    assert response.status_code == 200, response.text
    items = response.json()["items"]
    assert [c["asset"]["asset_id"] for c in items] == [old["asset_id"]]
    candidate = items[0]
    assert candidate["confidence"] == "medium"
    assert set(candidate["reasons"]) == {"same_hostname", "same_ip"}
    assert candidate["reconcilable"] is True
    assert candidate["asset"]["credential_status"] == "revoked"

    pairs = client.get(f"{ASSETS}/duplicates").json()["items"]
    assert len(pairs) == 1 and pairs[0]["asset"]["asset_id"] == new["asset_id"]
    # El enrolamiento dejó constancia (solo IDs y razones, sin telemetría).
    detected = _audits(db, "asset_duplicate_detected")
    assert len(detected) == 1 and detected[0].actor == "system"


def test_reconcile_moves_the_new_agent_to_the_historical_asset(
    client: TestClient, db: Session
) -> None:
    old, new = _ravenslg(client)
    versions = {k: _asset(client, v["asset_id"])["lifecycle_version"] for k, v in
                (("old", old), ("new", new))}  # fmt: skip

    response = client.post(
        f"{ASSETS}/{new['asset_id']}/reconcile",
        json={
            "target_asset_id": old["asset_id"],
            "version": versions["new"],
            "target_version": versions["old"],
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["asset"]["asset_id"] == old["asset_id"]
    assert body["archived_duplicate_id"] == new["asset_id"]
    assert body["asset"]["agent_version"] == "0.2.0"

    # El agente nuevo sigue informando sin re-enrolarse, ahora en el activo histórico.
    beat = client.post(f"{API}/agents/heartbeat", json={"agent_id": new["agent_id"]})
    assert beat.status_code == 200 and beat.json()["asset_id"] == old["asset_id"]
    duplicate = _asset(client, new["asset_id"])
    assert duplicate["archived_at"] is not None and duplicate["archived_by"] == "system"
    assert new["asset_id"] not in _ids(client) and old["asset_id"] in _ids(client)
    audit = _audits(db, "agent_asset_reconciled")
    assert len(audit) == 1 and audit[0].target_id == old["asset_id"]
    assert audit[0].details is not None and audit[0].details["confidence"] == "medium"


def test_reconcile_needs_evidence_and_never_trusts_ip_only(client: TestClient, db: Session) -> None:
    old = _register(client, hostname="PC-A", primary_ip="192.168.1.50")
    _revoke(client, old["asset_id"])
    new = _register(client, hostname="PC-B", primary_ip="192.168.1.50")
    candidates = client.get(f"{ASSETS}/{new['asset_id']}/duplicate-candidates").json()["items"]
    assert candidates[0]["confidence"] == "low"
    assert "insufficient_evidence" in candidates[0]["reconcile_blockers"]

    response = client.post(
        f"{ASSETS}/{new['asset_id']}/reconcile",
        json={
            "target_asset_id": old["asset_id"],
            "version": _asset(client, new["asset_id"])["lifecycle_version"],
            "target_version": _asset(client, old["asset_id"])["lifecycle_version"],
        },
    )
    assert response.status_code == 409 and _error(response) == "asset_reconcile_refused"
    assert _audits(db, "agent_asset_reconciled")[0].result == "failure"


def test_reconcile_refuses_a_target_whose_agent_is_alive(client: TestClient) -> None:
    host = {"hostname": "CLON", "primary_ip": "10.0.0.9"}
    alive = _register(client, **host)
    assert client.post(f"{API}/agents/heartbeat", json={"agent_id": alive["agent_id"]}).is_success
    new = _register(client, **host)
    target = _asset(client, alive["asset_id"])
    response = client.post(
        f"{ASSETS}/{new['asset_id']}/reconcile",
        json={
            "target_asset_id": alive["asset_id"],
            "version": _asset(client, new["asset_id"])["lifecycle_version"],
            "target_version": target["lifecycle_version"],
        },
    )
    assert response.status_code == 409
    assert "target_agent_online" in response.json()["error"]["details"][0]["blockers"]


def test_machine_identity_gives_high_confidence_and_mismatch_excludes(
    client: TestClient,
) -> None:
    old = _register(client, hostname="NUEVO-NOMBRE", primary_ip="10.1.1.1", machine_id_hash=MACHINE)
    _revoke(client, old["asset_id"])
    new = _register(client, hostname="OTRO", primary_ip="10.1.1.2", machine_id_hash=MACHINE)
    items = client.get(f"{ASSETS}/{new['asset_id']}/duplicate-candidates").json()["items"]
    assert items[0]["confidence"] == "high" and items[0]["reasons"] == ["same_machine_id"]

    twin = _register(client, hostname="OTRO", primary_ip="10.1.1.2", machine_id_hash="b" * 64)
    twins = client.get(f"{ASSETS}/{twin['asset_id']}/duplicate-candidates").json()["items"]
    # Mismo nombre e IP pero otra máquina: no se sugiere como duplicado de `new`.
    assert new["asset_id"] not in {c["asset"]["asset_id"] for c in twins}


def test_machine_id_is_never_exposed_raw(client: TestClient) -> None:
    agent = _register(client, machine_id_hash=MACHINE)
    assert MACHINE not in client.get(f"{ASSETS}/{agent['asset_id']}").text
    assert MACHINE not in client.get(f"{API}/agents").text
    bad = client.post(REGISTER, json=agent_payload(machine_id_hash="raw-machine-id"))
    assert bad.status_code == 422


# --- B. Archivar y restaurar ---------------------------------------------------------------


def test_archive_requires_revoking_the_agent_first(client: TestClient) -> None:
    agent = _register(client)
    response = _archive(client, agent["asset_id"])
    assert response.status_code == 409 and _error(response) == "asset_state_conflict"
    # Revocar no archiva.
    _revoke(client, agent["asset_id"])
    assert _asset(client, agent["asset_id"])["archived_at"] is None


def test_archived_asset_is_hidden_kept_and_restorable(client: TestClient, db: Session) -> None:
    agent = _register(client, hostname="RETIRADO")
    assert client.post(f"{API}/telemetry", json=telemetry_payload(agent["agent_id"])).is_success
    _revoke(client, agent["asset_id"])
    before = client.get(f"{API}/dashboard/summary").json()["assets"]["total"]

    response = _archive(client, agent["asset_id"], "Sustituido por otro equipo")
    assert response.status_code == 200, response.text
    archived = response.json()
    assert archived["archive_reason"] == "Sustituido por otro equipo"
    assert archived["archived_by"] == "admin" and archived["managed_history"] is True

    assert agent["asset_id"] not in _ids(client)
    assert agent["asset_id"] in _ids(client, archived="include")
    assert _ids(client, archived="only") == {agent["asset_id"]}
    assert client.get(f"{API}/dashboard/summary").json()["assets"]["total"] == before - 1
    agents = client.get(f"{API}/agents").json()
    row = next(a for a in agents["items"] if a["asset_id"] == agent["asset_id"])
    assert row["asset_state"] == "archived" and row["credential_status"] == "revoked"
    assert agents["summary"]["archived"] == 1
    # El historial sigue ahí.
    telemetry = client.get(f"{ASSETS}/{agent['asset_id']}/telemetry")
    assert telemetry.status_code == 200 and telemetry.json()["items"]

    restored = client.post(
        f"{ASSETS}/{agent['asset_id']}/restore", json={"version": archived["lifecycle_version"]}
    )
    assert restored.status_code == 200, restored.text
    assert restored.json()["archived_at"] is None
    # Restaurar no reactiva la credencial.
    row = next(a for a in client.get(f"{API}/agents").json()["items"]
               if a["asset_id"] == agent["asset_id"])  # fmt: skip
    assert row["credential_status"] == "revoked"
    assert len(_audits(db, "asset_archived")) == 1 and len(_audits(db, "asset_restored")) == 1


def test_archived_agent_cannot_enroll_again(client: TestClient) -> None:
    agent = _register(client)
    _revoke(client, agent["asset_id"])
    client.post(f"{API}/console/agents/{agent['asset_id']}/reinstate")
    asset = _asset(client, agent["asset_id"])
    assert asset["archived_at"] is None
    assert _archive(client, agent["asset_id"]).status_code == 200
    again = client.post(REGISTER, json=agent_payload(agent_id=agent["agent_id"]))
    assert again.status_code == 403 and _error(again) == "asset_archived"


def test_stale_version_is_a_conflict(client: TestClient) -> None:
    agent = _register(client)
    _revoke(client, agent["asset_id"])
    version = _asset(client, agent["asset_id"])["lifecycle_version"]
    first = client.post(
        f"{ASSETS}/{agent['asset_id']}/archive", json={"reason": "uno", "version": version}
    )
    assert first.status_code == 200
    second = client.post(f"{ASSETS}/{agent['asset_id']}/restore", json={"version": version})
    assert second.status_code == 409 and _error(second) == "asset_lifecycle_conflict"


def test_archive_reason_is_required(client: TestClient) -> None:
    agent = _register(client)
    _revoke(client, agent["asset_id"])
    response = client.post(
        f"{ASSETS}/{agent['asset_id']}/archive", json={"reason": " ", "version": 0}
    )
    assert response.status_code == 422


# --- C. Borrado ----------------------------------------------------------------------------


def test_discovered_asset_without_history_can_be_deleted(client: TestClient, db: Session) -> None:
    ghost = _discovered(db, device_name="Fantasma")
    ip = ghost.primary_ip
    check = client.get(f"{ASSETS}/{ghost.public_id}/delete-check")
    assert check.status_code == 200, check.text
    body = check.json()
    assert body["deletable"] is True and body["blocking_reasons"] == []
    assert body["primary_ip"] == ghost.primary_ip and body["mac_address"] == ghost.mac_address

    response = client.delete(f"{ASSETS}/{ghost.public_id}", params={"version": body["version"]})
    assert response.status_code == 204, response.text
    assert client.get(f"{ASSETS}/{ghost.public_id}").status_code == 404
    deleted = _audits(db, "asset_deleted")
    assert len(deleted) == 1 and deleted[0].details is not None
    assert deleted[0].details["primary_ip"] == ip


def test_managed_asset_is_never_deleted(client: TestClient, db: Session) -> None:
    agent = _register(client)
    _revoke(client, agent["asset_id"])
    check = client.get(f"{ASSETS}/{agent['asset_id']}/delete-check").json()
    assert check["deletable"] is False and "managed_history" in check["blocking_reasons"]
    assert check["can_archive"] is True

    response = client.delete(f"{ASSETS}/{agent['asset_id']}", params={"version": check["version"]})
    assert response.status_code == 409 and _error(response) == "asset_not_deletable"
    assert _asset(client, agent["asset_id"])["asset_id"] == agent["asset_id"]
    rejected = _audits(db, "asset_delete_rejected")
    assert len(rejected) == 1 and rejected[0].result == "failure"


def test_discovered_asset_with_relevant_detection_is_kept(client: TestClient, db: Session) -> None:
    asset = _discovered(db)
    _detection(db, asset, severity=DetectionSeverity.HIGH)
    check = client.get(f"{ASSETS}/{asset.public_id}/delete-check").json()
    assert check["blocking_reasons"] == ["detections"]
    response = client.delete(f"{ASSETS}/{asset.public_id}", params={"version": 0})
    assert response.status_code == 409


def test_delete_rechecks_dependencies_inside_the_transaction(
    client: TestClient, db: Session
) -> None:
    """TOCTOU: la UI vio "borrable", pero algo apareció antes de confirmar."""
    asset = _discovered(db)
    assert client.get(f"{ASSETS}/{asset.public_id}/delete-check").json()["deletable"] is True
    _detection(db, asset, severity=DetectionSeverity.MEDIUM)
    response = client.delete(f"{ASSETS}/{asset.public_id}", params={"version": 0})
    assert response.status_code == 409
    details = response.json()["error"]["details"][0]
    assert details["blocking_reasons"] == ["detections"]


def test_low_impact_detections_go_with_the_ghost_but_are_shown(
    client: TestClient, db: Session
) -> None:
    asset = _discovered(db)
    _detection(db, asset, rule_id="NET-003", severity=DetectionSeverity.LOW)
    check = client.get(f"{ASSETS}/{asset.public_id}/delete-check").json()
    assert check["deletable"] is True and check["removes"]["detections"] == 1


# --- D. Permisos ---------------------------------------------------------------------------


@pytest.mark.parametrize("role", ["viewer", "analyst"])
def test_only_admins_archive_restore_delete_and_reconcile(
    client: TestClient, engine: Engine, db: Session, role: str
) -> None:
    ghost = _discovered(db)
    agent = _register(client)
    with TestClient(client.app) as other:
        authenticate(other, engine, role)
        target = f"{ASSETS}/{ghost.public_id}"
        assert other.get(f"{target}/delete-check").status_code == 403
        assert other.delete(target, params={"version": 0}).status_code == 403
        assert (
            other.post(f"{target}/archive", json={"reason": "x y z", "version": 0}).status_code
            == 403
        )
        assert other.post(f"{target}/restore", json={"version": 0}).status_code == 403
        reconcile = other.post(
            f"{ASSETS}/{agent['asset_id']}/reconcile",
            json={"target_asset_id": str(ghost.public_id), "version": 0, "target_version": 0},
        )
        assert reconcile.status_code == 403
        duplicates = other.get(f"{ASSETS}/{agent['asset_id']}/duplicate-candidates")
        # Analyst lee sugerencias de duplicado; viewer no.
        assert duplicates.status_code == (200 if role == "analyst" else 403)
        assert other.get(ASSETS, params={"archived": "include"}).status_code == 200
    assert client.get(f"{ASSETS}/{ghost.public_id}").status_code == 200


# --- Discovery ----------------------------------------------------------------------------


def test_network_gear_is_never_merged_by_ip() -> None:
    router = Asset(primary_ip="192.168.1.1", device_type="router")
    gateway = Asset(primary_ip="192.168.1.1", identity_observations={"gateway": True})
    pc = Asset(primary_ip="192.168.1.20", device_type="computer")
    assert _network_gear(router) and _network_gear(gateway)
    assert not _network_gear(pc)


# --- Migración 0027 <-> 0028 --------------------------------------------------------------


def test_migration_0028_roundtrip_keeps_data(client: TestClient, engine: Engine) -> None:
    from tests.conftest import _alembic_config

    agent = _register(client, machine_id_hash=MACHINE)
    _revoke(client, agent["asset_id"])
    assert _archive(client, agent["asset_id"]).status_code == 200
    linux = _register(client, os_name="Linux", hostname="mint")
    event = {
        "source": "linux_journal",
        "channel": "journal",
        "record_id": 1,
        "event_type": "auth_failure",
        "provider": "sshd",
        "level": "warning",
        "message": "Failed password",
        "occurred_at": datetime.now(UTC).isoformat(),
    }
    assert client.post(
        f"{API}/events", json={"agent_id": linux["agent_id"], "events": [event]}
    ).is_success
    config = _alembic_config(str(engine.url.render_as_string(hide_password=False)))
    try:
        command.downgrade(config, "0027")
        with engine.connect() as connection:
            columns = {
                row[0]
                for row in connection.execute(
                    text(
                        "SELECT column_name FROM information_schema.columns"
                        " WHERE table_name = 'assets'"
                    )
                )
            }
            assert "archived_at" not in columns and "machine_id_hash" not in columns
            # Los eventos Linux se conservan (event_code 0: el esquema anterior lo exigía).
            code = connection.execute(text("SELECT event_code FROM system_events")).scalar()
            assert code == 0
            assert connection.execute(text("SELECT count(*) FROM assets")).scalar() == 2
        command.upgrade(config, "0028")
        command.downgrade(config, "0027")
    finally:
        command.upgrade(config, "head")
    with engine.connect() as connection:
        managed = connection.execute(
            text("SELECT count(*) FROM assets WHERE ever_managed AND archived_at IS NULL")
        ).scalar()
    # Backfill: ever_managed = tenía agente. El archivado se pierde al bajar (documentado).
    assert managed == 2
