"""Fase 5C.2: stale source-aware, limpieza segura, duplicados con evidencia y reconciliación.

Los casos A-T de la especificación están marcados en el nombre o docstring de cada test.
Todo usa datos de prueba: ningún test toca activos reales (DESKTOP-03IJGBE / ravenslg solo
aparecen como nombres de fixtures del caso conceptual M).
"""

import threading
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest
from alembic import command
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select, update
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.core.exceptions import AssetLifecycleConflictError, ConflictError
from app.discovery.scanner import ScanConfig
from app.discovery.targets import DiscoveryScope
from app.models.asset import Asset, AssetStatus, MonitoringMethod
from app.models.asset_lineage import AssetAgentLineage
from app.models.audit import AuditEvent
from app.models.detection import DetectionSeverity
from app.models.telemetry import TelemetrySample
from app.schemas.agent import HeartbeatRequest
from app.services import asset_lifecycle_service as lifecycle_module
from app.services.agent_service import AgentService
from app.services.alert_service import AlertThresholds
from app.services.asset_lifecycle_policy import (
    LifecyclePolicy,
    LifecycleState,
    evaluate,
    stale_condition,
)
from app.services.asset_lifecycle_service import AssetLifecycleService
from app.services.audit_service import Actor
from app.services.discovery_service import DiscoveryConfig, DiscoveryService
from tests.conftest import TEST_ENROLLMENT_KEY, agent_payload, authenticate
from tests.test_discovery_service import NETWORK, PORTS, Host, Lab
from tests.test_risk import _detection
from tests.test_telemetry import telemetry_payload

API = "/api/v1"
ASSETS = f"{API}/assets"
PREVIEW = f"{ASSETS}/lifecycle/cleanup-preview"
CLEANUP = f"{ASSETS}/lifecycle/cleanup"
REGISTER = f"{API}/agents/register"
HEARTBEAT = f"{API}/agents/heartbeat"
TIMEOUT = timedelta(seconds=90)
POLICY = LifecyclePolicy()


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    # `client` por su limpieza (TRUNCATE ... CASCADE al terminar cada test).
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


def _service(session: Session) -> AssetLifecycleService:
    return AssetLifecycleService(session, TIMEOUT, POLICY)


def _discovered(db: Session, *, days_ago: float = 0, misses: int = 0, **fields: Any) -> Asset:
    seen = datetime.now(UTC) - timedelta(days=days_ago)
    values: dict[str, Any] = {
        "monitoring_method": MonitoringMethod.DISCOVERED,
        "primary_ip": "10.99.0.10",
        "status": AssetStatus.UNKNOWN,
        "network_status": AssetStatus.OFFLINE if misses else AssetStatus.ONLINE,
        "network_misses": misses,
        "last_network_seen_at": seen,
        "first_seen_at": seen,
        "discovered_at": seen,
        "discovery_network": NETWORK,
        **fields,
    }
    asset = Asset(**values)
    db.add(asset)
    db.commit()
    return asset


def _register(client: TestClient, **host: Any) -> dict[str, Any]:
    payload = agent_payload(**host)
    response = client.post(REGISTER, json=payload)
    assert response.status_code == 201, response.text
    return {"agent_id": payload["agent_id"], "asset_id": response.json()["asset_id"]}


def _asset(client: TestClient, asset_id: Any) -> dict[str, Any]:
    response = client.get(f"{ASSETS}/{asset_id}")
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def _preview(client: TestClient, **params: Any) -> dict[str, Any]:
    response = client.get(PREVIEW, params=params)
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def _row(preview: dict[str, Any], asset: Asset) -> dict[str, Any] | None:
    return next((i for i in preview["items"] if i["asset_id"] == str(asset.public_id)), None)


def _cleanup(client: TestClient, action: str, *assets: Asset, **extra: Any) -> dict[str, Any]:
    items = [{"asset_id": str(a.public_id), "version": a.lifecycle_version} for a in assets]
    response = client.post(CLEANUP, json={"action": action, "items": items, **extra})
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def _audits(db: Session, action: str) -> list[AuditEvent]:
    db.expire_all()
    return list(db.scalars(select(AuditEvent).where(AuditEvent.action == action)))


def _make_offline(db: Session, asset_id: str, days: float) -> None:
    db.execute(
        update(Asset)
        .where(Asset.public_id == UUID(asset_id))
        .values(last_seen_at=datetime.now(UTC) - timedelta(days=days))
    )
    db.commit()


def _discovery(engine: Engine, lab: Lab, *, excluded: str = "") -> DiscoveryService:
    config = DiscoveryConfig(
        scope=DiscoveryScope.parse(NETWORK, excluded),
        scan=ScanConfig(ports=PORTS, timeout=0.5, concurrency=16, max_rate=5000, icmp=False),
        offline_after_misses=2,
        heartbeat_timeout=TIMEOUT,
    )
    thresholds = AlertThresholds(
        cpu_percent=90, ram_percent=90, disk_percent=90, sustained_samples=3,
        offline_after=TIMEOUT,
    )  # fmt: skip
    return DiscoveryService(
        sessionmaker(bind=engine, expire_on_commit=False),
        config,
        thresholds,
        prober_factory=lambda: lab,
        gateways=set,
    )


def _by_ip(db: Session, ip: str) -> Asset:
    db.expire_all()
    asset = db.scalar(select(Asset).where(Asset.primary_ip == ip))
    assert asset is not None
    return asset


def _backdate(db: Session, asset: Asset, days: float) -> None:
    seen = datetime.now(UTC) - timedelta(days=days)
    db.execute(
        update(Asset)
        .where(Asset.id == asset.id)
        .values(last_network_seen_at=seen, discovered_at=seen, first_seen_at=seen)
    )
    db.commit()


# --- Discovery: solo scans completos y exitosos cuentan como ausencia --------------------


def lab_net() -> dict[str, Host]:
    return {
        "10.20.0.1": Host({80}, mac="00:11:22:00:00:01"),
        "10.20.0.7": Host({9100}, mac="00:11:22:00:00:07"),
    }


def test_a_one_missed_scan_never_deletes(engine: Engine, db: Session, client: TestClient) -> None:
    """A. Un descubierto falta en UN scan exitoso: offline como mucho, nunca borrable."""
    lab = Lab(lab_net())
    service = _discovery(engine, lab)
    service.run()
    lab.hosts["10.20.0.7"].up = False
    service.run()
    printer = _by_ip(db, "10.20.0.7")
    assert printer.network_misses == 1
    _backdate(db, printer, 30)
    body = _asset(client, printer.public_id)
    # Un scan perdido no es ni siquiera "offline" para discovery (DISCOVERY_OFFLINE_AFTER_MISSES).
    assert body["lifecycle_state"] == "active" and body["missed_discovery_scans"] == 1
    check = client.get(f"{ASSETS}/{printer.public_id}/delete-check").json()
    assert check["deletable"] is False and check["blocking_reasons"] == ["not_stale"]
    response = client.delete(f"{ASSETS}/{printer.public_id}", params={"version": 0})
    assert response.status_code == 409


def test_b_many_complete_missed_scans_make_a_cleanup_candidate(
    engine: Engine, db: Session, client: TestClient
) -> None:
    """B. Falta en varios scans completos y supera el umbral de tiempo: candidato."""
    lab = Lab(lab_net())
    service = _discovery(engine, lab)
    service.run()
    lab.hosts["10.20.0.7"].up = False
    for _ in range(3):
        service.run()
    printer = _by_ip(db, "10.20.0.7")
    assert printer.network_misses == 3
    # Recién desaparecido: los scans no bastan sin el tiempo mínimo.
    assert _asset(client, printer.public_id)["lifecycle_state"] == "offline"

    _backdate(db, printer, 5)  # > 72 h pero < 14 días: stale, aún sin purga
    assert _asset(client, printer.public_id)["lifecycle_state"] == "stale"
    row = _row(_preview(client), printer)
    assert row is not None and row["action"] == "mark_stale"
    assert row["blocking_reasons"] == ["purge_window_not_reached"]

    _backdate(db, printer, 20)
    assert _asset(client, printer.public_id)["lifecycle_state"] == "cleanup_candidate"
    row = _row(_preview(client), printer)
    assert row is not None and row["action"] == "hard_delete_eligible"
    assert row["hard_delete_eligible"] is True and row["missed_successful_scans"] == 3
    assert row["stale_for_hours"] >= 20 * 24
    # El otro host sigue presente: no es candidato.
    assert _row(_preview(client), _by_ip(db, "10.20.0.1")) is None
    stale = client.get(ASSETS, params={"lifecycle": "cleanup_candidate"}).json()["items"]
    assert [a["asset_id"] for a in stale] == [str(printer.public_id)]


def test_c_failed_run_and_errored_probes_do_not_count(engine: Engine, db: Session) -> None:
    """C. Un discovery fallido (o una sonda que falla con error) no suma scans perdidos."""
    lab = Lab(lab_net())
    service = _discovery(engine, lab)
    service.run()
    lab.hosts["10.20.0.7"].up = False

    def broken() -> Lab:
        raise RuntimeError("scanner unavailable")

    failing = _discovery(engine, lab)
    failing._prober_factory = broken
    with pytest.raises(RuntimeError):
        failing.run()
    assert _by_ip(db, "10.20.0.7").network_misses == 0

    class Flaky(Lab):
        async def tcp(self, address: Any, port: int, timeout: float) -> Any:
            if str(address) == "10.20.0.7":
                raise OSError("network unreachable")
            return await super().tcp(address, port, timeout)

    _discovery(engine, Flaky(lab.hosts)).run()
    # Scan completo, pero esa dirección no se sondeó de verdad: no es prueba de ausencia.
    assert _by_ip(db, "10.20.0.7").network_misses == 0
    service.run()
    assert _by_ip(db, "10.20.0.7").network_misses == 1


def test_d_partial_or_out_of_scope_runs_do_not_count(engine: Engine, db: Session) -> None:
    """D. Un scan parcial (cancelado) o que no cubre la dirección no suma scans perdidos."""
    lab = Lab(lab_net())
    service = _discovery(engine, lab)
    service.run()
    lab.hosts["10.20.0.7"].up = False

    cancelled = _discovery(engine, lab)
    stop = threading.Event()
    stop.set()
    cancelled._cancel = stop
    cancelled.run_network(cancelled._config.scope.resolve(None)[0], cancelled_trigger())
    assert _by_ip(db, "10.20.0.7").network_misses == 0

    _discovery(engine, lab, excluded="10.20.0.7").run()
    assert _by_ip(db, "10.20.0.7").network_misses == 0


def cancelled_trigger() -> Any:
    from app.models.discovery import DiscoveryTrigger

    return DiscoveryTrigger.MANUAL


# --- Gates de borrado y limpieza -----------------------------------------------------------


def test_e_stale_discovered_with_detection_is_blocked(client: TestClient, db: Session) -> None:
    """E. Stale con una detección relevante: no se borra; se propone archivar."""
    ghost = _discovered(db, days_ago=20, misses=3)
    _detection(db, ghost, severity=DetectionSeverity.HIGH)
    row = _row(_preview(client), ghost)
    assert row is not None and row["action"] == "archive_candidate"
    assert row["blocking_reasons"] == ["detections"] and row["dependencies"] == {"detections": 1}
    result = _cleanup(client, "hard_delete", ghost)
    assert result["succeeded"] == 0 and result["results"][0]["outcome"] == "skipped"
    assert result["results"][0]["reasons"] == ["detections"]
    assert client.get(f"{ASSETS}/{ghost.public_id}").status_code == 200

    archived = _cleanup(client, "archive", ghost, reason="Dispositivo retirado")
    assert archived["results"][0]["outcome"] == "archived"
    assert _asset(client, ghost.public_id)["lifecycle_state"] == "archived"


def test_f_stale_never_managed_without_dependencies_is_deleted(
    client: TestClient, db: Session
) -> None:
    """F. Stale, nunca gestionado y sin dependencias: borrado permitido y auditado."""
    ghost = _discovered(db, days_ago=20, misses=3, device_name="Fantasma")
    check = client.get(f"{ASSETS}/{ghost.public_id}/delete-check").json()
    assert check["deletable"] is True and check["lifecycle_state"] == "cleanup_candidate"
    result = _cleanup(client, "hard_delete", ghost)
    assert result == {
        "action": "hard_delete",
        "requested": 1,
        "succeeded": 1,
        "skipped": 0,
        "results": [
            {
                "asset_id": str(ghost.public_id),
                "outcome": "deleted",
                "reasons": [],
                "display_name": "Fantasma",
            }
        ],
    }
    assert client.get(f"{ASSETS}/{ghost.public_id}").status_code == 404
    deleted = _audits(db, "asset_deleted")
    assert len(deleted) == 1 and deleted[0].details is not None
    assert deleted[0].details["cleanup"] is True
    summary = _audits(db, "asset_cleanup_executed")
    assert len(summary) == 1 and summary[0].details is not None
    assert summary[0].details["succeeded"] == 1


def test_g_managed_offline_for_a_year_is_never_hard_deleted(
    client: TestClient, db: Session
) -> None:
    """G. Gestionado offline un año: candidato a archivar, nunca a borrar (ni automático)."""
    agent = _register(client)
    _make_offline(db, agent["asset_id"], 365)
    asset = db.scalar(select(Asset).where(Asset.public_id == UUID(agent["asset_id"])))
    assert asset is not None
    assert _asset(client, agent["asset_id"])["lifecycle_state"] == "stale"
    row = _row(_preview(client), asset)
    # Credencial activa: ni siquiera archivable hasta revocar.
    assert row is not None and row["action"] == "blocked"
    assert (
        "managed_history" in row["blocking_reasons"] and "agent_active" in row["blocking_reasons"]
    )
    result = _cleanup(client, "hard_delete", asset)
    assert result["results"][0]["outcome"] == "skipped"
    assert "managed_history" in result["results"][0]["reasons"]

    assert client.post(f"{API}/console/agents/{agent['asset_id']}/revoke").status_code == 200
    db.expire_all()
    row = _row(_preview(client), asset)
    assert row is not None and row["action"] == "archive_candidate"
    with sessionmaker(bind=db.get_bind(), expire_on_commit=False)() as session:
        assert _service(session).auto_cleanup(50) is None
    assert client.get(f"{ASSETS}/{agent['asset_id']}").status_code == 200


def test_auto_cleanup_only_deletes_eligible_discovered(engine: Engine, db: Session) -> None:
    ghost = _discovered(db, days_ago=20, misses=3)
    recent = _discovered(db, primary_ip="10.99.0.11", days_ago=1, misses=3)
    kept = _discovered(db, primary_ip="10.99.0.12", days_ago=20, misses=3)
    _detection(db, kept, severity=DetectionSeverity.MEDIUM)
    ghost_id, keep_ids = ghost.public_id, {recent.public_id, kept.public_id}
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        result = _service(session).auto_cleanup(50)
        session.commit()
    assert result is not None and result.succeeded == 1
    db.expire_all()
    left = set(db.scalars(select(Asset.public_id)))
    assert ghost_id not in left and keep_ids <= left
    [summary] = _audits(db, "asset_cleanup_executed")
    assert summary.actor == "system" and summary.details is not None
    assert summary.details["automatic"] is True


def test_cleanup_batch_is_bounded_and_archive_needs_reason(client: TestClient, db: Session) -> None:
    ghost = _discovered(db, days_ago=20, misses=3)
    items = [{"asset_id": str(ghost.public_id), "version": 0}] * 51
    assert client.post(CLEANUP, json={"action": "hard_delete", "items": items}).status_code == 422
    response = client.post(CLEANUP, json={"action": "archive", "items": items[:1]})
    assert response.status_code == 422


def test_s_stale_preview_then_discovery_sees_it_cancels_the_delete(
    client: TestClient, db: Session
) -> None:
    """S. Preview viejo + discovery/heartbeat/detección nuevos: el ejecutor revalida."""
    seen_again = _discovered(db, days_ago=20, misses=3)
    detected = _discovered(db, primary_ip="10.99.0.11", days_ago=20, misses=3)
    changed = _discovered(db, primary_ip="10.99.0.12", days_ago=20, misses=3)
    preview = _preview(client)
    assert {r["action"] for r in preview["items"]} == {"hard_delete_eligible"}

    # Discovery lo vuelve a ver (lo que hace _update_presence) antes de confirmar.
    db.execute(
        update(Asset)
        .where(Asset.id == seen_again.id)
        .values(network_misses=0, last_network_seen_at=datetime.now(UTC))
    )
    db.commit()
    _detection(db, detected, severity=DetectionSeverity.CRITICAL)
    # Otro admin lo archivó y restauró: la versión que vio el preview ya no vale.
    db.execute(update(Asset).where(Asset.id == changed.id).values(lifecycle_version=2))
    db.commit()

    items = [{"asset_id": r["asset_id"], "version": r["version"]} for r in preview["items"]]
    result = client.post(CLEANUP, json={"action": "hard_delete", "items": items}).json()
    outcome = {r["asset_id"]: r for r in result["results"]}
    assert outcome[str(seen_again.public_id)]["reasons"] == ["not_stale"]
    assert outcome[str(detected.public_id)]["reasons"] == ["detections"]
    assert outcome[str(changed.public_id)]["reasons"] == ["version_conflict"]
    assert result["succeeded"] == 0 and len(set(db.scalars(select(Asset.id)))) == 3


def test_preview_and_sql_filter_use_the_same_rule(db: Session) -> None:
    """La condición SQL (listado/preview) coincide con evaluate() (detalle/ejecutor)."""
    now = datetime.now(UTC)
    cases = [
        _discovered(db, primary_ip="10.99.1.1", days_ago=0, misses=0),
        _discovered(db, primary_ip="10.99.1.2", days_ago=2, misses=3),
        _discovered(db, primary_ip="10.99.1.3", days_ago=4, misses=2),
        _discovered(db, primary_ip="10.99.1.4", days_ago=4, misses=3),
        _discovered(db, primary_ip="10.99.1.5", days_ago=15, misses=3),
        _discovered(
            db, primary_ip="10.99.1.6", days_ago=40, misses=9, monitoring_method="agentless"
        ),
        _discovered(
            db,
            primary_ip="10.99.1.7",
            days_ago=40,
            misses=0,
            ever_managed=True,
            monitoring_method=MonitoringMethod.AGENT,
        ),
    ]
    stale_sql = set(db.scalars(select(Asset.id).where(stale_condition(POLICY, now))))
    purge_sql = set(
        db.scalars(select(Asset.id).where(stale_condition(POLICY, now, purgeable_only=True)))
    )
    for asset in cases:
        state = evaluate(asset, now, POLICY, online=False).state
        assert (asset.id in stale_sql) == (
            state in (LifecycleState.STALE, LifecycleState.CLEANUP_CANDIDATE)
        ), asset.primary_ip
        assert (asset.id in purge_sql) == (state is LifecycleState.CLEANUP_CANDIDATE)


# --- Duplicados y reconciliación -----------------------------------------------------------


def _reconcile(
    client: TestClient, source: str, target: str, ack: bool = False
) -> Any:  # respuesta httpx
    return client.post(
        f"{ASSETS}/{source}/reconcile",
        json={
            "target_asset_id": target,
            "version": _asset(client, source)["lifecycle_version"],
            "target_version": _asset(client, target)["lifecycle_version"],
            "acknowledge_weak_evidence": ack,
        },
    )


def _candidate(client: TestClient, source: str, target: str) -> dict[str, Any]:
    items = client.get(f"{ASSETS}/{source}/duplicate-candidates").json()["items"]
    found: dict[str, Any] = next(c for c in items if c["asset"]["asset_id"] == target)
    return found


@pytest.mark.parametrize(
    ("old_host", "new_host", "reasons"),
    [
        # H. Misma IP, otro nombre.
        (
            {"hostname": "PC-A", "primary_ip": "10.5.0.9"},
            {"hostname": "PC-B", "primary_ip": "10.5.0.9"},
            {"same_ip", "same_os"},
        ),
        # I. Mismo nombre, otra IP.
        (
            {"hostname": "PC-A", "primary_ip": "10.5.0.9"},
            {"hostname": "PC-A", "primary_ip": "10.5.0.10"},
            {"same_hostname", "same_os"},
        ),
        # J. Mismo nombre y misma IP.
        (
            {"hostname": "PC-A", "primary_ip": "10.5.0.9"},
            {"hostname": "PC-A", "primary_ip": "10.5.0.9"},
            {"same_hostname", "same_ip", "same_os"},
        ),
    ],
)
def test_hij_ip_and_hostname_never_merge_by_themselves(
    client: TestClient, db: Session, old_host: Any, new_host: Any, reasons: set[str]
) -> None:
    """H/I/J. IP, hostname o ambos: confianza baja, nada se fusiona solo y reconciliar
    exige la confirmación explícita de un admin."""
    old = _register(client, **old_host)
    assert client.post(f"{API}/console/agents/{old['asset_id']}/revoke").status_code == 200
    new = _register(client, **new_host)
    # Dos activos distintos: el enrolamiento no fusionó nada.
    assert old["asset_id"] != new["asset_id"]
    assert _asset(client, old["asset_id"])["archived_at"] is None
    candidate = _candidate(client, new["asset_id"], old["asset_id"])
    assert candidate["confidence"] == "low" and set(candidate["reasons"]) == reasons
    assert candidate["requires_acknowledgement"] is True
    refused = _reconcile(client, new["asset_id"], old["asset_id"])
    assert refused.status_code == 409
    assert refused.json()["error"]["details"][0]["requires_acknowledgement"] is True
    # Nada cambió tras el rechazo.
    assert _asset(client, new["asset_id"])["archived_at"] is None


def test_k_same_machine_identity_is_strong_evidence(client: TestClient) -> None:
    """K. Identidad de máquina exacta: confianza alta, evidencia fuerte, sin confirmación."""
    old = _register(client, hostname="A", primary_ip="10.6.0.1", machine_id_hash="c" * 64)
    client.post(f"{API}/console/agents/{old['asset_id']}/revoke")
    new = _register(client, hostname="B", primary_ip="10.6.0.2", machine_id_hash="c" * 64)
    candidate = _candidate(client, new["asset_id"], old["asset_id"])
    assert candidate["confidence"] == "high" and candidate["requires_acknowledgement"] is False
    assert {"code": "same_machine_id", "strength": "strong"} in candidate["evidence"]
    response = _reconcile(client, new["asset_id"], old["asset_id"])
    assert response.status_code == 200, response.text
    assert response.json()["acknowledged_warnings"] == []


def test_mac_strength_universal_vs_random(client: TestClient, db: Session) -> None:
    old = _register(client, hostname="X1", primary_ip="10.7.0.1")
    client.post(f"{API}/console/agents/{old['asset_id']}/revoke")
    new = _register(client, hostname="X2", primary_ip="10.7.0.2")
    for public_id, mac in ((old["asset_id"], "00:1a:2b:3c:4d:5e"), (new["asset_id"], None)):
        db.execute(update(Asset).where(Asset.public_id == UUID(public_id)).values(mac_address=mac))
    db.execute(
        update(Asset)
        .where(Asset.public_id == UUID(new["asset_id"]))
        .values(mac_address="00:1a:2b:3c:4d:5e")
    )
    db.commit()
    candidate = _candidate(client, new["asset_id"], old["asset_id"])
    assert candidate["confidence"] == "medium"
    assert {"code": "same_mac", "strength": "medium"} in candidate["evidence"]

    # MAC administrada localmente (aleatoria): solo señal débil.
    db.execute(update(Asset).where(Asset.agent_id.is_not(None)).values(mac_address=None))
    db.execute(
        update(Asset)
        .where(Asset.public_id.in_([UUID(old["asset_id"]), UUID(new["asset_id"])]))
        .values(mac_address="02:1a:2b:3c:4d:5e")
    )
    db.commit()
    candidate = _candidate(client, new["asset_id"], old["asset_id"])
    assert candidate["confidence"] == "low"
    assert {"code": "same_random_mac", "strength": "weak"} in candidate["evidence"]


def _desktop_case(client: TestClient, db: Session) -> tuple[dict[str, Any], dict[str, Any]]:
    """Caso conceptual M (datos de prueba): histórico DESKTOP-03IJGBE con historial y offline,
    y un agente nuevo "ravenslg" tras reinstalar Windows (MachineGuid nuevo, misma IP)."""
    ip = "192.168.50.201"
    historical = _register(
        client, hostname="DESKTOP-03IJGBE", primary_ip=ip, machine_id_hash="d" * 64
    )
    sample = client.post(f"{API}/telemetry", json=telemetry_payload(historical["agent_id"]))
    assert sample.status_code == 201, sample.text
    target = db.scalar(select(Asset).where(Asset.public_id == UUID(historical["asset_id"])))
    assert target is not None
    _detection(db, target, severity=DetectionSeverity.HIGH)
    # Offline desde hace días (el agente viejo desapareció con la reinstalación). Su
    # credencial sigue "activa": nadie la revocó, pero no está en línea.
    _make_offline(db, historical["asset_id"], 3)
    current = _register(client, hostname="ravenslg", primary_ip=ip, machine_id_hash="e" * 64)
    assert client.post(HEARTBEAT, json={"agent_id": current["agent_id"]}).status_code == 200
    return historical, current


def test_l_reinstall_with_new_identity_needs_manual_confirmation(
    client: TestClient, db: Session
) -> None:
    """L. Reinstalación (identidad nueva, misma IP): sin auto-merge; reconciliación manual
    posible solo aceptando el conflicto de identidad."""
    historical, current = _desktop_case(client, db)
    candidate = _candidate(client, current["asset_id"], historical["asset_id"])
    assert candidate["confidence"] == "low" and candidate["conflicts"] == ["machine_id_mismatch"]
    assert set(candidate["reconcile_warnings"]) == {"machine_id_mismatch", "insufficient_evidence"}
    assert candidate["reconcilable"] is True and candidate["reconcile_blockers"] == []
    assert candidate["requires_acknowledgement"] is True
    refused = _reconcile(client, current["asset_id"], historical["asset_id"])
    assert refused.status_code == 409
    # Ambos activos siguen intactos.
    assert _asset(client, current["asset_id"])["agent_status"] == "online"


def test_m_real_case_reconciles_into_the_historical_asset(client: TestClient, db: Session) -> None:
    """M + T. El admin elige el histórico como destino: el agente actual pasa a él, el
    historial se conserva, el agente viejo queda histórico y el actual sigue autenticando."""
    historical, current = _desktop_case(client, db)
    old_token = client.tokens[historical["agent_id"]]  # type: ignore[attr-defined]

    preview = client.get(
        f"{ASSETS}/{current['asset_id']}/reconcile-preview",
        params={"target_asset_id": historical["asset_id"]},
    )
    assert preview.status_code == 200, preview.text
    impact = preview.json()
    assert impact["requires_acknowledgement"] is True
    assert impact["target_history"]["telemetry_samples"] == 1
    assert impact["target_history"]["detections"] == 1
    assert impact["target_has_previous_agent"] is True
    assert impact["source_disposition"] == "source_archived"
    assert "managed_history" in impact["source_disposition_reasons"]

    response = _reconcile(client, current["asset_id"], historical["asset_id"], ack=True)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["target_asset_id"] == historical["asset_id"]
    assert body["source_asset_id"] == current["asset_id"]
    assert body["agent_id"] == current["agent_id"]
    assert body["previous_target_agent_id"] == historical["agent_id"]
    assert body["source_disposition"] == "source_archived"
    assert set(body["acknowledged_warnings"]) == {"machine_id_mismatch", "insufficient_evidence"}
    assert body["asset"]["hostname"] == "ravenslg"

    # T. El agente actual sigue con SU credencial: heartbeat y telemetría van al histórico.
    beat = client.post(HEARTBEAT, json={"agent_id": current["agent_id"]})
    assert beat.status_code == 200 and beat.json()["asset_id"] == historical["asset_id"]
    sample = client.post(f"{API}/telemetry", json=telemetry_payload(current["agent_id"]))
    assert sample.status_code == 201
    # El agente viejo ya no autentica (su credencial se descartó, nunca se reutiliza).
    stale = client.post(
        HEARTBEAT,
        json={"agent_id": historical["agent_id"]},
        headers={"Authorization": f"Bearer {old_token}"},
    )
    assert stale.status_code == 401

    db.expire_all()
    target = db.scalar(select(Asset).where(Asset.public_id == UUID(historical["asset_id"])))
    source = db.scalar(select(Asset).where(Asset.public_id == UUID(current["asset_id"])))
    assert target is not None and source is not None
    # Historial previo intacto en el histórico (+ la muestra nueva).
    samples = db.scalars(select(TelemetrySample).where(TelemetrySample.asset_id == target.id))
    assert len(list(samples)) == 2
    assert source.archived_at is not None and source.agent_id is None
    assert source.agent_token_hash is None
    lineage = {
        (row.asset_id, str(row.agent_id), row.end_reason)
        for row in db.scalars(select(AssetAgentLineage))
    }
    assert lineage == {
        (source.id, current["agent_id"], "reassigned"),
        (target.id, historical["agent_id"], "replaced"),
    }
    # El duplicado archivado no se puede borrar (Managed) y conserva lo que envió.
    check = client.get(f"{ASSETS}/{current['asset_id']}/delete-check").json()
    assert check["deletable"] is False and "agent_history" in check["blocking_reasons"]

    # Auditoría completa, sin tokens ni identidad de máquina.
    [reconciled] = _audits(db, "agent_asset_reconciled")
    [reassigned] = _audits(db, "agent_reassigned")
    archived = [a for a in _audits(db, "asset_archived") if a.target_id == current["asset_id"]]
    assert reconciled.details is not None and reassigned.details is not None
    assert reconciled.details["source_disposition"] == "source_archived"
    assert reconciled.details["previous_target_agent_id"] == historical["agent_id"]
    assert reassigned.details["to_asset"] == historical["asset_id"]
    assert len(archived) == 1
    for event in (reconciled, reassigned, archived[0]):
        text = str(event.details)
        assert "d" * 64 not in text and "e" * 64 not in text and old_token not in text

    # El agente viejo, si volviera a enrolarse, sería un duplicado de linaje (fuerte).
    back = client.post(
        REGISTER,
        json=agent_payload(agent_id=historical["agent_id"], hostname="OTRO", primary_ip="10.0.9.9"),
        headers={"X-Enrollment-Key": TEST_ENROLLMENT_KEY},
    )
    assert back.status_code == 201, back.text
    lineage_candidate = _candidate(client, back.json()["asset_id"], historical["asset_id"])
    assert lineage_candidate["confidence"] == "high"
    assert "same_agent_lineage" in lineage_candidate["reasons"]


def test_n_two_concurrent_reconciliations_only_one_wins(
    client: TestClient, engine: Engine, db: Session
) -> None:
    """N. Dos admins a la vez: el segundo espera el bloqueo y recibe conflicto."""
    historical, current = _desktop_case(client, db)
    source = _asset(client, current["asset_id"])
    target = _asset(client, historical["asset_id"])
    args = (
        UUID(current["asset_id"]),
        UUID(historical["asset_id"]),
        source["lifecycle_version"],
        target["lifecycle_version"],
    )
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    errors: list[BaseException] = []
    first = factory()
    _service(first).reconcile(*args, acknowledge_weak_evidence=True, actor=Actor("admin-1"))

    def second() -> None:
        with factory() as session:
            try:
                _service(session).reconcile(
                    *args, acknowledge_weak_evidence=True, actor=Actor("admin-2")
                )
                session.commit()
            except BaseException as exc:
                errors.append(exc)
                session.rollback()

    worker = threading.Thread(target=second)
    worker.start()
    time.sleep(0.5)
    assert worker.is_alive()  # bloqueado en FOR UPDATE
    first.commit()
    first.close()
    worker.join(timeout=10)
    assert len(errors) == 1 and isinstance(errors[0], AssetLifecycleConflictError)
    db.expire_all()
    assert len(list(db.scalars(select(AssetAgentLineage)))) == 2


def test_heartbeat_racing_a_reconciliation_is_retried_not_misfiled(
    client: TestClient, engine: Engine, db: Session
) -> None:
    """Un heartbeat que espera mientras se reconcilia no escribe en el duplicado: 409 y el
    agente reintenta (contra el activo histórico)."""
    historical, current = _desktop_case(client, db)
    token = client.tokens[current["agent_id"]]  # type: ignore[attr-defined]
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    lock = factory()
    _service(lock).reconcile(
        UUID(current["asset_id"]),
        UUID(historical["asset_id"]),
        _asset(client, current["asset_id"])["lifecycle_version"],
        _asset(client, historical["asset_id"])["lifecycle_version"],
        acknowledge_weak_evidence=True,
    )
    outcome: list[Any] = []

    def beat() -> None:
        with factory() as session:
            try:
                AgentService(session, None).heartbeat(
                    HeartbeatRequest(agent_id=UUID(current["agent_id"])), token
                )
                outcome.append("ok")
            except ConflictError as exc:
                outcome.append(exc)
                session.rollback()

    worker = threading.Thread(target=beat)
    worker.start()
    time.sleep(0.5)
    lock.commit()
    lock.close()
    worker.join(timeout=10)
    assert len(outcome) == 1 and isinstance(outcome[0], ConflictError)
    retry = client.post(HEARTBEAT, json={"agent_id": current["agent_id"]})
    assert retry.status_code == 200 and retry.json()["asset_id"] == historical["asset_id"]


def test_o_failure_mid_reconciliation_rolls_back_everything(
    client: TestClient, engine: Engine, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """O. Un error a mitad (después de mover el agente) deshace toda la operación."""
    historical, current = _desktop_case(client, db)

    def boom(*_: Any, **__: Any) -> None:
        raise RuntimeError("fallo simulado")

    monkeypatch.setattr(lifecycle_module, "mark_dirty", boom)
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        with pytest.raises(RuntimeError):
            _service(session).reconcile(
                UUID(current["asset_id"]),
                UUID(historical["asset_id"]),
                _asset(client, current["asset_id"])["lifecycle_version"],
                _asset(client, historical["asset_id"])["lifecycle_version"],
                acknowledge_weak_evidence=True,
            )
        session.rollback()
    db.expire_all()
    source = db.scalar(select(Asset).where(Asset.public_id == UUID(current["asset_id"])))
    target = db.scalar(select(Asset).where(Asset.public_id == UUID(historical["asset_id"])))
    assert source is not None and target is not None
    assert str(source.agent_id) == current["agent_id"] and source.archived_at is None
    assert str(target.agent_id) == historical["agent_id"]
    assert list(db.scalars(select(AssetAgentLineage))) == []
    beat = client.post(HEARTBEAT, json={"agent_id": current["agent_id"]})
    assert beat.json()["asset_id"] == current["asset_id"]


def test_source_equal_target_is_refused(client: TestClient) -> None:
    agent = _register(client)
    response = _reconcile(client, agent["asset_id"], agent["asset_id"], ack=True)
    assert response.status_code == 409
    assert response.json()["error"]["details"][0]["blockers"] == ["same_asset"]


# --- Permisos y archivados -----------------------------------------------------------------


@pytest.mark.parametrize("role", ["viewer", "analyst"])
def test_pq_only_admins_clean_up_or_reconcile(
    client: TestClient, engine: Engine, db: Session, role: str
) -> None:
    """P/Q. Viewer y analyst: 403 en limpieza, borrado, preview y reconciliación."""
    ghost = _discovered(db, days_ago=20, misses=3)
    agent = _register(client)
    item = {"asset_id": str(ghost.public_id), "version": 0}
    with TestClient(client.app) as other:
        authenticate(other, engine, role)
        assert other.get(PREVIEW).status_code == 403
        assert (
            other.post(CLEANUP, json={"action": "hard_delete", "items": [item]}).status_code == 403
        )
        assert other.delete(f"{ASSETS}/{ghost.public_id}", params={"version": 0}).status_code == 403
        preview = other.get(
            f"{ASSETS}/{agent['asset_id']}/reconcile-preview",
            params={"target_asset_id": str(ghost.public_id)},
        )
        assert preview.status_code == 403
        reconcile = other.post(
            f"{ASSETS}/{agent['asset_id']}/reconcile",
            json={
                "target_asset_id": str(ghost.public_id),
                "version": 0,
                "target_version": 0,
                "acknowledge_weak_evidence": True,
            },
        )
        assert reconcile.status_code == 403
        # Todos leen el estado de ciclo de vida.
        assert other.get(f"{ASSETS}/{ghost.public_id}").json()["lifecycle_state"] == (
            "cleanup_candidate"
        )
    assert client.get(f"{ASSETS}/{ghost.public_id}").status_code == 200


def test_r_archived_assets_stay_out_of_default_views(client: TestClient, db: Session) -> None:
    """R. Archivado: fuera del listado por defecto, de los filtros de ciclo de vida y del
    preview; visible con archived=include y con su estado "archived"."""
    ghost = _discovered(db, days_ago=20, misses=3)
    _cleanup(client, "archive", ghost, reason="Retirado")
    assert str(ghost.public_id) not in {a["asset_id"] for a in client.get(ASSETS).json()["items"]}
    assert client.get(ASSETS, params={"lifecycle": "stale"}).json()["items"] == []
    assert _row(_preview(client), ghost) is None
    listed = client.get(ASSETS, params={"archived": "only"}).json()["items"]
    assert [a["lifecycle_state"] for a in listed] == ["archived"]
    # Archivado, sin historial y pasada la purga: sigue siendo borrable a mano.
    check = client.get(f"{ASSETS}/{ghost.public_id}/delete-check").json()
    assert check["deletable"] is True


# --- Configuración y migración -------------------------------------------------------------


def test_purge_window_cannot_be_shorter_than_stale(monkeypatch: pytest.MonkeyPatch) -> None:
    # Settings(_env_file=None): sin depender del .env real (DATABASE_URL se fija aquí).
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@127.0.0.1:1/x")
    monkeypatch.setenv("DISCOVERED_STALE_AFTER_HOURS", "480")
    monkeypatch.setenv("DISCOVERED_PURGE_AFTER_DAYS", "14")
    with pytest.raises(ValueError, match="DISCOVERED_PURGE_AFTER_DAYS"):
        Settings(_env_file=None)
    monkeypatch.setenv("DISCOVERED_STALE_AFTER_HOURS", "72")
    settings = Settings(_env_file=None)
    assert settings.asset_auto_cleanup is False
    assert LifecyclePolicy.from_settings(settings) == LifecyclePolicy()


def test_migration_0029_roundtrip(client: TestClient, engine: Engine, db: Session) -> None:
    from tests.conftest import _alembic_config

    historical, current = _desktop_case(client, db)
    _reconcile(client, current["asset_id"], historical["asset_id"], ack=True)
    config = _alembic_config(engine.url.render_as_string(hide_password=False))
    command.downgrade(config, "0028")
    command.upgrade(config, "head")
    db.expire_all()
    # Bajar pierde solo el linaje; activos, historial y auditoría siguen.
    assert list(db.scalars(select(AssetAgentLineage))) == []
    assert _asset(client, historical["asset_id"])["agent_version"] is not None
    assert _audits(db, "agent_reassigned")
