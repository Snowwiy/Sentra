"""Fase 4D: descubrimiento de red desde el dashboard.

Cubre el flujo completo por HTTP (iniciar, cola, progreso, cancelar, detalle), la guarda de
consola local (403 desde la LAN) y la regla crítica: un scan cancelado, fallido o
incompleto nunca genera asset_disappeared ni port_closed.

El runner real (hilo de trabajo, latido, cancelación por base de datos) se ejecuta contra
la base de pruebas; solo las sondas son simuladas (Lab), y GatedLab permite congelar un scan
a mitad para observar los estados intermedios sin depender de tiempos.
"""

import asyncio
import threading
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select, update
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings, get_settings
from app.discovery.probes import PortState
from app.discovery.scanner import ScanConfig
from app.discovery.targets import DiscoveryScope
from app.models.alert import Alert, AlertRule
from app.models.asset import Asset, AssetStatus
from app.models.audit import AuditEvent
from app.models.discovery import DiscoveryJob, DiscoveryJobStatus, DiscoveryTrigger
from app.models.exposure import AssetPort, PortStateValue
from app.services.alert_service import AlertThresholds
from app.services.discovery_runner import DiscoveryRunner, get_discovery_runner
from app.services.discovery_service import DiscoveryConfig, DiscoveryService
from tests.conftest import authenticate
from tests.test_discovery_service import NETWORK, PORTS, Host, Lab, office

OTHER = "10.20.1.0/28"
JOBS = "/api/v1/discovery/jobs"
START = "/api/v1/console/discovery/jobs"
DASHBOARD_ORIGIN = "http://localhost:5173"
# Fase 4G: el dashboard (sesión de analyst) envía su Origin; ya no hay cabecera de consola.
LOCAL = {"Origin": DASHBOARD_ORIGIN}
FINISHED = {"completed", "failed", "cancelled"}


class GatedLab(Lab):
    """Lab cuyas sondas a direcciones "bloqueadas" esperan a que se abra la puerta.

    Así un scan queda en curso de forma determinista: los hosts libres se evalúan (hay
    progreso real) y el resto espera hasta que el test abre `gate`.
    """

    def __init__(self, hosts: dict[str, Host], blocked_from: int = 8) -> None:
        super().__init__(hosts)
        self.gate = threading.Event()
        self.blocked_from = blocked_from

    async def tcp(self, address: Any, port: int, timeout: float) -> PortState:
        if int(str(address).rsplit(".", 1)[1]) >= self.blocked_from:
            while not self.gate.is_set():
                await asyncio.sleep(0.01)
        return await super().tcp(address, port, timeout)


class Broken(Lab):
    def neighbours(self) -> dict[str, str]:
        return {}

    async def tcp(self, address: Any, port: int, timeout: float) -> PortState:
        return PortState.FILTERED


class Web:
    """Dashboard con sesión de analyst + runner real sobre la base de pruebas."""

    def __init__(self, client: TestClient, engine: Engine) -> None:
        self.client = client
        self.engine = engine
        self.lab: Lab = Lab(office())
        self.allowed = f"{NETWORK},{OTHER}"
        self.misses = 1
        self.prober_factory: Callable[[], Any] | None = None
        self.runner: DiscoveryRunner | None = None
        self.local: TestClient | None = None

    def service(self, cancel: threading.Event | None = None) -> DiscoveryService:
        config = DiscoveryConfig(
            scope=DiscoveryScope.parse(self.allowed) if self.allowed else DiscoveryScope.parse(""),
            scan=ScanConfig(ports=PORTS, timeout=0.5, concurrency=16, max_rate=5000, icmp=False),
            offline_after_misses=self.misses,
            heartbeat_timeout=timedelta(seconds=90),
            progress_interval=0.05,
        )
        thresholds = AlertThresholds(
            cpu_percent=90, ram_percent=90, disk_percent=90, sustained_samples=3,
            offline_after=timedelta(seconds=90),
        )  # fmt: skip
        return DiscoveryService(
            sessionmaker(bind=self.engine, expire_on_commit=False),
            config,
            thresholds,
            prober_factory=self.prober_factory or (lambda: self.lab),
            gateways=set,
            cancel=cancel,
        )

    def start_runner(self) -> DiscoveryRunner:
        self.runner = DiscoveryRunner(self.service)
        runner = self.runner
        self.client.app.dependency_overrides[get_discovery_runner] = lambda: runner  # type: ignore[attr-defined]
        return runner

    def start(self, target: str = NETWORK, headers: dict[str, str] | None = None) -> Any:
        assert self.local is not None
        return self.local.post(START, json={"target": target}, headers=headers or LOCAL)

    def cancel(self, job_id: str) -> Any:
        assert self.local is not None
        return self.local.post(f"{START}/{job_id}/cancel", headers=LOCAL)

    def job(self, job_id: str) -> dict[str, Any]:
        response = self.client.get(f"{JOBS}/{job_id}")
        assert response.status_code == 200, response.text
        body: dict[str, Any] = response.json()
        return body

    def wait(
        self, job_id: str, until: Callable[[dict[str, Any]], bool], timeout: float = 10
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while True:
            job = self.job(job_id)
            if until(job):
                return job
            assert time.monotonic() < deadline, f"job never reached the expected state: {job}"
            time.sleep(0.02)

    def finished(self, job_id: str) -> dict[str, Any]:
        return self.wait(job_id, lambda j: j["status"] in FINISHED)

    def run_now(self) -> None:
        """Scan completo síncrono (como la CLI) para preparar el estado previo."""
        self.service().run(NETWORK)


def _settings(**changes: Any) -> Settings:
    base = {
        "cors_origins": DASHBOARD_ORIGIN,
        "discovery_allowed_networks": f"{NETWORK},{OTHER}",
    }
    return get_settings().model_copy(update={**base, **changes})


def _console_settings() -> Settings:
    return _settings()


@pytest.fixture
def web(client: TestClient, engine: Engine) -> Iterator[Web]:
    helper = Web(client, engine)
    client.app.dependency_overrides[get_settings] = _console_settings  # type: ignore[attr-defined]
    helper.start_runner()
    # Desde otra PC de la LAN y con rol analyst: la Fase 4G permite iniciar/cancelar
    # discovery a admin y analyst, sin depender de estar en el propio servidor.
    with TestClient(
        client.app, base_url="http://192.168.50.201:8000", client=("192.168.50.20", 50123)
    ) as local:
        authenticate(local, engine, "analyst")
        helper.local = local
        yield helper
    # Antes del TRUNCATE de `client`: ningún hilo del runner puede seguir usando la base.
    if isinstance(helper.lab, GatedLab):
        helper.lab.gate.set()
    if helper.runner is not None:
        helper.runner.stop(timeout=10)


@pytest.fixture
def db(engine: Engine, web: Web) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


def _alerts(db: Session, rule: AlertRule) -> list[Alert]:
    db.expire_all()
    return list(db.scalars(select(Alert).where(Alert.rule == rule)))


def _assets(db: Session) -> dict[str, Asset]:
    db.expire_all()
    return {a.primary_ip: a for a in db.scalars(select(Asset))}


def _active_jobs(db: Session) -> list[DiscoveryJob]:
    db.expire_all()
    return list(
        db.scalars(
            select(DiscoveryJob).where(
                DiscoveryJob.status.in_([DiscoveryJobStatus.QUEUED, DiscoveryJobStatus.RUNNING])
            )
        )
    )


# --- iniciar ------------------------------------------------------------------------------


def test_start_authorized_discovery_completes_as_baseline(web: Web, db: Session) -> None:
    response = web.start()
    assert response.status_code == 202, response.text
    created = response.json()
    assert created["status"] in ("queued", "running")
    assert created["target"] == NETWORK and created["requested_via"] == "dashboard"
    assert created["trigger"] == "manual" and created["hosts_total"] == 14

    job = web.finished(created["job_id"])
    assert job["status"] == "completed" and job["stop_reason"] is None
    # Primer scan completo: establece la línea base sin ruido de alertas.
    assert job["baseline"] is True
    assert job["hosts_scanned"] == 14 and job["hosts_alive"] == 4 and job["hosts_new"] == 4
    assert job["hosts_updated"] == 0 and job["ports_opened"] == 0 and job["ports_closed"] == 0
    assert job["progress"] is None and job["duration_seconds"] is not None
    assert job["parameters"]["ports"] == list(PORTS)
    assert len(job["new_assets"]) == 4 and job["changes"] == []
    assert _alerts(db, AlertRule.ASSET_DISCOVERED) == []
    assert _alerts(db, AlertRule.UNKNOWN_DEVICE) == []
    assert _alerts(db, AlertRule.PORT_EXPOSED) == []
    # Los activos aparecen en la tabla Red (la web los recoge con polling).
    assert len(web.client.get("/api/v1/assets").json()["items"]) == 4


def test_second_scan_reports_new_devices_and_changes(web: Web, db: Session) -> None:
    web.run_now()
    web.lab.hosts["10.20.0.11"] = Host({22}, mac="02:00:00:00:00:11")
    web.lab.hosts["10.20.0.7"].ports.add(8080)

    job = web.finished(web.start().json()["job_id"])

    assert job["status"] == "completed" and job["baseline"] is False
    assert job["hosts_new"] == 1 and job["hosts_updated"] == 4 and job["ports_opened"] == 1
    assert [a["primary_ip"] for a in job["new_assets"]] == ["10.20.0.11"]
    assert [(c["primary_ip"], c["kind"]) for c in job["changes"]] == [("10.20.0.7", "port_opened")]
    assert len(_alerts(db, AlertRule.PORT_EXPOSED)) == 1


@pytest.mark.parametrize(
    "target",
    [
        "10.30.0.0/28",  # privada pero fuera de la allowlist
        "10.0.0.0/8",  # contiene la red autorizada: más amplia, no permitida
        "0.0.0.0/0",
        "8.8.8.0/28",  # Internet
        "224.0.0.0/28",  # multicast
        "255.255.255.255",  # broadcast
        "240.0.0.0/28",  # reservada
        "10.20.0.1/24",  # bits de host: ambiguo
        "bogus",
    ],
)
def test_targets_outside_the_allowlist_are_refused(web: Web, db: Session, target: str) -> None:
    response = web.start(target)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "discovery_target_refused"
    db.expire_all()
    assert list(db.scalars(select(DiscoveryJob))) == []


def test_malformed_request_is_rejected(web: Web) -> None:
    assert web.local is not None
    for body in ({}, {"target": ""}, {"target": "x" * 65}, {"target": NETWORK, "extra": 1}):
        response = web.local.post(START, json=body, headers=LOCAL)
        assert response.status_code == 422, body


def test_subnet_inside_an_allowed_network_is_accepted(web: Web) -> None:
    response = web.start("10.20.0.4/30")
    assert response.status_code == 202
    job = web.finished(response.json()["job_id"])
    assert job["target"] == "10.20.0.4/30" and job["hosts_scanned"] == 2


def test_discovery_disabled_without_allowed_networks(web: Web) -> None:
    web.allowed = ""
    web.start_runner()
    response = web.start()
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "discovery_disabled"


# --- estados, progreso y concurrencia -----------------------------------------------------


def test_queued_running_progress_and_completed(web: Web, db: Session) -> None:
    lab = GatedLab(office())
    web.lab = lab
    first = web.start(NETWORK).json()
    running = web.wait(
        first["job_id"], lambda j: j["status"] == "running" and j["hosts_scanned"] > 0
    )
    # Progreso real: evaluados .1-.7 de 14; el total es exacto en la fase de liveness.
    assert running["hosts_total"] == 14
    assert 0 < running["hosts_scanned"] < 14
    assert running["progress"]["phase"] == "liveness"
    assert running["hosts_updated"] is None and running["duration_seconds"] is None

    # El runner ejecuta los jobs de uno en uno: el segundo espera en cola.
    second = web.start(OTHER)
    assert second.status_code == 202
    assert second.json()["status"] == "queued"
    listed = {j["job_id"]: j["status"] for j in web.client.get(JOBS).json()["items"]}
    assert listed == {first["job_id"]: "running", second.json()["job_id"]: "queued"}

    lab.gate.set()
    assert web.finished(first["job_id"])["status"] == "completed"
    assert web.finished(second.json()["job_id"])["status"] == "completed"
    assert _active_jobs(db) == []


def test_same_network_twice_is_refused_while_active(web: Web, db: Session) -> None:
    lab = GatedLab(office())
    web.lab = lab
    first = web.start().json()
    again = web.start()
    assert again.status_code == 409
    assert again.json()["error"]["code"] == "discovery_busy"
    # El scheduler y la CLI respetan la misma reserva: no escanean la red dos veces.
    assert web.service().run(NETWORK) == []
    lab.gate.set()
    web.finished(first["job_id"])
    # Terminado el primero, se puede volver a lanzar.
    assert web.start().status_code == 202


def test_failed_job(web: Web, db: Session) -> None:
    def broken() -> Any:
        raise RuntimeError("prober unavailable")

    web.prober_factory = broken
    web.start_runner()
    job = web.finished(web.start().json()["job_id"])
    assert job["status"] == "failed" and job["stop_reason"] == "error"
    assert "prober unavailable" in job["errors"][0]
    assert _active_jobs(db) == []
    # El runner sigue vivo tras un fallo.
    web.prober_factory = None
    web.start_runner()
    assert web.finished(web.start().json()["job_id"])["status"] == "completed"


# --- cancelación ---------------------------------------------------------------------------


def test_cancel_running_job_draws_no_negative_conclusions(web: Web, db: Session) -> None:
    web.run_now()  # baseline completo: 4 hosts con sus puertos
    lab = GatedLab(office())
    # Tras la línea base, un host se apaga y otro cierra un puerto. Con misses=1, un scan
    # COMPLETO concluiría asset_disappeared y (al segundo) port_closed; uno cancelado no.
    lab.hosts["10.20.0.9"].up = False
    lab.hosts["10.20.0.5"].ports.discard(3389)
    web.lab = lab

    job_id = web.start().json()["job_id"]
    web.wait(job_id, lambda j: j["status"] == "running" and j["hosts_scanned"] > 0)
    response = web.cancel(job_id)
    assert response.status_code == 200
    assert response.json()["cancel_requested"] is True
    # Margen para que el latido (cada 0,05 s) recoja la petición antes de abrir la puerta.
    time.sleep(0.5)
    lab.gate.set()

    job = web.finished(job_id)
    assert job["status"] == "cancelled" and job["stop_reason"] == "operator"
    assert job["hosts_scanned"] < 14
    assets = _assets(db)
    assert assets["10.20.0.9"].network_status == AssetStatus.ONLINE
    assert assets["10.20.0.9"].network_misses == 0
    assert _alerts(db, AlertRule.ASSET_DISAPPEARED) == []
    assert _alerts(db, AlertRule.PORT_CLOSED) == []
    db.expire_all()
    rdp = db.scalar(
        select(AssetPort).where(
            AssetPort.asset_id == assets["10.20.0.5"].id, AssetPort.port == 3389
        )
    )
    assert rdp is not None and rdp.state == PortStateValue.OPEN and rdp.misses == 0
    assert _active_jobs(db) == []


def test_cancel_queued_job_never_runs(web: Web, db: Session) -> None:
    lab = GatedLab(office())
    web.lab = lab
    first = web.start(NETWORK).json()
    web.wait(first["job_id"], lambda j: j["status"] == "running")
    second = web.start(OTHER).json()
    assert second["status"] == "queued"

    cancelled = web.cancel(second["job_id"]).json()
    assert cancelled["status"] == "cancelled" and cancelled["stop_reason"] == "operator"

    lab.gate.set()
    web.finished(first["job_id"])
    assert web.runner is not None and web.runner.wait_idle(10)
    job = web.job(second["job_id"])
    assert job["status"] == "cancelled" and job["hosts_scanned"] == 0
    assert _active_jobs(db) == []


def test_cancel_finished_or_unknown_job(web: Web) -> None:
    job = web.finished(web.start().json()["job_id"])
    response = web.cancel(job["job_id"])
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "discovery_job_finished"
    assert web.cancel("00000000-0000-0000-0000-000000000000").status_code == 404
    assert web.client.get(f"{JOBS}/00000000-0000-0000-0000-000000000000").status_code == 404


def test_shutdown_leaves_no_orphan_jobs(web: Web, db: Session) -> None:
    lab = GatedLab(office())
    web.lab = lab
    first = web.start(NETWORK).json()
    web.wait(first["job_id"], lambda j: j["status"] == "running")
    second = web.start(OTHER).json()

    assert web.runner is not None
    stopper = threading.Thread(target=web.runner.stop)
    stopper.start()
    time.sleep(0.3)
    lab.gate.set()  # libera las sondas ya en vuelo; las nuevas ya no se lanzan
    stopper.join(timeout=15)

    assert _active_jobs(db) == []
    assert web.job(first["job_id"])["stop_reason"] == "shutdown"
    second_job = web.job(second["job_id"])
    assert second_job["status"] == "cancelled" and second_job["stop_reason"] == "shutdown"


def test_orphaned_jobs_expire_and_free_the_network(web: Web, db: Session) -> None:
    # Un job que quedó en cola o en curso en un proceso que murió (sin latido).
    old = datetime.now(UTC) - timedelta(hours=1)
    for status in (DiscoveryJobStatus.QUEUED, DiscoveryJobStatus.RUNNING):
        db.add(
            DiscoveryJob(
                target=NETWORK if status == DiscoveryJobStatus.QUEUED else OTHER,
                trigger=DiscoveryTrigger.MANUAL, status=status, baseline=False,
                started_at=old, heartbeat_at=old, hosts_scanned=0, hosts_alive=0, hosts_new=0,
                open_ports=0, probes=0, error_count=0, hosts_total=14,
            )
        )  # fmt: skip
    db.commit()

    response = web.start()
    assert response.status_code == 202
    web.finished(response.json()["job_id"])
    db.expire_all()
    stopped = db.scalars(select(DiscoveryJob).where(DiscoveryJob.started_at == old)).all()
    assert {(j.status, j.stop_reason) for j in stopped} == {
        (DiscoveryJobStatus.FAILED, "interrupted")
    }


def test_alive_queued_job_is_not_expired(web: Web, db: Session) -> None:
    # Con latido reciente sigue reservando su red aunque lleve rato en cola.
    db.add(
        DiscoveryJob(
            target=NETWORK, trigger=DiscoveryTrigger.MANUAL, status=DiscoveryJobStatus.QUEUED,
            baseline=False, started_at=datetime.now(UTC) - timedelta(hours=1),
            heartbeat_at=datetime.now(UTC), hosts_scanned=0, hosts_alive=0, hosts_new=0,
            open_ports=0, probes=0, error_count=0, hosts_total=14,
        )
    )  # fmt: skip
    db.commit()
    assert web.start().json()["error"]["code"] == "discovery_busy"


# --- baseline ------------------------------------------------------------------------------


def test_cancelled_first_scan_is_not_the_baseline(web: Web, db: Session) -> None:
    lab = GatedLab(office())
    web.lab = lab
    first = web.start().json()
    web.wait(first["job_id"], lambda j: j["status"] == "running" and j["hosts_scanned"] > 0)
    web.cancel(first["job_id"])
    time.sleep(0.5)
    lab.gate.set()
    cancelled = web.finished(first["job_id"])
    assert cancelled["status"] == "cancelled" and cancelled["baseline"] is False

    # El primer scan completo posterior sigue siendo la línea base: sin alertas de
    # "nuevo activo" por los hosts que el parcial no llegó a ver.
    job = web.finished(web.start().json()["job_id"])
    assert job["baseline"] is True
    assert _alerts(db, AlertRule.ASSET_DISCOVERED) == []
    assert _alerts(db, AlertRule.UNKNOWN_DEVICE) == []
    assert _alerts(db, AlertRule.PORT_EXPOSED) == []


# --- RBAC y CSRF (Fase 4G) -----------------------------------------------------------------


def test_viewer_can_read_but_not_start_or_cancel(web: Web, engine: Engine, db: Session) -> None:
    job = web.finished(web.start().json()["job_id"])
    with TestClient(web.client.app) as viewer:
        authenticate(viewer, engine, "viewer")
        for path in (START, f"{START}/{job['job_id']}/cancel"):
            response = viewer.post(path, json={"target": NETWORK})
            assert response.status_code == 403, path
            assert response.json()["error"]["code"] == "permission_denied"
        for path in (
            JOBS,
            f"{JOBS}/{job['job_id']}",
            "/api/v1/discovery/scope",
            "/api/v1/discovery/schedule",
        ):
            assert viewer.get(path).status_code == 200, path
    db.expire_all()
    assert len(list(db.scalars(select(DiscoveryJob)))) == 1
    denied = db.scalars(select(AuditEvent).where(AuditEvent.action == "permission_denied")).all()
    assert len(denied) == 2 and {d.result for d in denied} == {"denied"}


def test_discovery_needs_session_and_csrf(web: Web, db: Session) -> None:
    assert web.local is not None
    with TestClient(web.client.app) as anonymous:
        response = anonymous.post(START, json={"target": NETWORK})
        assert response.status_code == 401
        assert anonymous.get(JOBS).status_code == 401
    # Sin token CSRF (formulario HTML, petición simple cross-site con la cookie).
    response = web.local.post(
        START, json={"target": NETWORK}, headers={"X-CSRF-Token": "", **LOCAL}
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "csrf_failed"
    # Otro sitio abierto en el navegador del operador, aunque tuviera el token.
    response = web.local.post(
        START, json={"target": NETWORK}, headers={"Origin": "http://evil.example"}
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "csrf_failed"
    db.expire_all()
    assert list(db.scalars(select(DiscoveryJob))) == []


def test_discovery_start_and_cancel_are_audited(web: Web, db: Session) -> None:
    job_id = web.finished(web.start().json()["job_id"])["job_id"]
    assert web.cancel(job_id).status_code == 409  # ya terminó
    assert web.start("8.8.8.0/24").status_code == 422
    db.expire_all()
    rows = [
        (r.action, r.result, r.target_id)
        for r in db.scalars(select(AuditEvent).order_by(AuditEvent.id))
    ]
    assert ("discovery_started", "success", job_id) in rows
    assert ("discovery_cancelled", "failure", job_id) in rows
    assert ("discovery_started", "failure", "8.8.8.0/24") in rows


# --- lectura: alcance y scheduler -------------------------------------------------------------


def test_scope_lists_networks_with_their_size(web: Web) -> None:
    scope = web.client.get("/api/v1/discovery/scope").json()
    assert scope["enabled"] is True
    assert scope["allowed_networks"] == [NETWORK, OTHER]
    assert scope["networks"] == [{"network": NETWORK, "hosts": 14}, {"network": OTHER, "hosts": 14}]
    assert scope["max_hosts_per_network"] == get_settings().discovery_max_hosts_per_network


def test_schedule_state(web: Web, db: Session) -> None:
    schedule = web.client.get("/api/v1/discovery/schedule").json()
    assert schedule["enabled"] is False and schedule["disabled_reason"] == "no_interval"
    assert schedule["next_run_at"] is None and schedule["last_run_at"] is None

    web.service().run(NETWORK, DiscoveryTrigger.SCHEDULED, via="scheduler")

    class FakeSchedule:
        next_run_at = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)
        running = False

    app = web.client.app
    app.dependency_overrides[get_settings] = lambda: _settings(  # type: ignore[attr-defined]
        discovery_interval_minutes=60, background_jobs_enabled=True
    )
    app.state.discovery_schedule = FakeSchedule()  # type: ignore[attr-defined]
    try:
        schedule = web.client.get("/api/v1/discovery/schedule").json()
    finally:
        del app.state.discovery_schedule  # type: ignore[attr-defined]
    assert schedule["enabled"] is True and schedule["interval_minutes"] == 60
    assert schedule["last_run_status"] == "completed" and schedule["last_run_at"] is not None
    assert schedule["next_run_at"].startswith("2026-10-04T12:00:00")
    jobs = web.client.get(JOBS).json()["items"]
    assert jobs[0]["trigger"] == "scheduled" and jobs[0]["requested_via"] == "scheduler"


def test_cli_and_dashboard_share_the_same_history(web: Web, db: Session) -> None:
    web.service().run(NETWORK, DiscoveryTrigger.MANUAL, via="cli")
    web.finished(web.start().json()["job_id"])
    vias = [j["requested_via"] for j in web.client.get(JOBS).json()["items"]]
    assert vias == ["dashboard", "cli"]


def test_scan_never_touches_hosts_outside_the_target(web: Web, db: Session) -> None:
    # Defensa en profundidad: aunque una fila en cola se manipulase para apuntar fuera de
    # la allowlist, el runner revalida antes de escanear y la marca como fallida.
    db.execute(update(DiscoveryJob).values(target="10.99.0.0/28"))
    db.commit()
    seen: list[str] = []

    class Recording(Lab):
        async def tcp(self, address: Any, port: int, timeout: float) -> PortState:
            seen.append(str(address))
            return await super().tcp(address, port, timeout)

    web.lab = Recording(office())
    assert web.runner is not None
    job_id, _ = web.runner.service.enqueue(NETWORK, "dashboard")
    db.execute(update(DiscoveryJob).where(DiscoveryJob.id == job_id).values(target="10.99.0.0/28"))
    db.commit()
    assert web.runner.service.run_job(job_id) is None
    db.expire_all()
    job = db.get(DiscoveryJob, job_id)
    assert job is not None and job.status == DiscoveryJobStatus.FAILED
    assert seen == []
