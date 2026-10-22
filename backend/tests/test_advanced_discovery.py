"""Fase 6A: Advanced Network Discovery (perfiles, discovery_advanced, observaciones).

Nada sale a la red: el discovery local usa el Lab falso de test_discovery_service y el
sensor se simula con el protocolo HTTP real (SensorSim de test_sites_sensors).
"""

import asyncio
import ipaddress
import threading
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, func, select, update
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.discovery import profiles as profile_mod
from app.discovery.probes import PortState
from app.discovery.scanner import NetworkScanner, ScanConfig
from app.models.alert import Alert, AlertRule
from app.models.asset import Asset
from app.models.audit import AuditEvent
from app.models.discovery import DiscoveryJob, DiscoveryObservation
from app.models.site import SensorJob, Site
from app.schemas.site import ObservationIn
from app.services.retention_service import RetentionPolicy, RetentionService
from app.services.sensor_service import _payload_sha256
from tests.conftest import authenticate
from tests.test_discovery_service import NETWORK, Host, Lab
from tests.test_discovery_web import LOCAL, Web, _console_settings
from tests.test_sites_sensors import (
    CAPS,
    NET,
    TARGET,
    SensorSim,
    _error,
    _ok,
    create_site,
    enroll,
    new_token,
    obs,
)

API = "/api/v1"
START = f"{API}/console/discovery/jobs"
OBS = f"{API}/discovery/observations"
ADV_CAPS = [*CAPS, "network.discovery.advanced", "network.dns"]


# --- utilidades -------------------------------------------------------------------------------


class AdvancedSensor(SensorSim):
    """Sensor 0.2.0 que declara discovery_advanced."""

    def __init__(self, client: TestClient, site_id: str, name: str = "adv") -> None:
        self.client = client
        body = _ok(enroll(client, new_token(client, site_id, name), ADV_CAPS, "0.2.0"), 201)
        self.credential = body["credential"]
        self.sensor_id = body["sensor_id"]
        self.site_id = site_id
        self.config = body["config"]


def start_advanced(
    client: TestClient,
    sensor: SensorSim,
    profile: str = "quick",
    target: str = TARGET,
    **extra: Any,
) -> Any:
    return client.post(
        START,
        json={
            "target": target,
            "site_id": sensor.site_id,
            "execution_target": "sensor",
            "sensor_id": sensor.sensor_id,
            "profile": profile,
            **extra,
        },
    )


def run_advanced(
    client: TestClient,
    sensor: SensorSim,
    observations: list[dict[str, Any]],
    profile: str = "quick",
    **complete: Any,
) -> dict[str, Any]:
    discovery = _ok(start_advanced(client, sensor, profile), 202)
    [job] = sensor.poll()
    assert job["job_type"] == "discovery_advanced"
    _ok(sensor.start(job))
    if observations:
        _ok(sensor.results(job, observations))
    complete.setdefault("batches_sent", 1 if observations else 0)
    _ok(sensor.complete(job, **complete))
    detail: dict[str, Any] = _ok(client.get(f"{API}/discovery/jobs/{discovery['job_id']}"))
    return detail


def observations(client: TestClient, **params: Any) -> dict[str, Any]:
    body: dict[str, Any] = _ok(client.get(OBS, params=params))
    return body


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


@pytest.fixture
def web(client: TestClient, engine: Engine) -> Iterator[Web]:
    helper = Web(client, engine)
    client.app.dependency_overrides[get_settings] = _console_settings  # type: ignore[attr-defined]
    helper.start_runner()
    with TestClient(
        client.app, base_url="http://192.168.50.201:8000", client=("192.168.50.20", 50123)
    ) as local:
        authenticate(local, engine, "analyst")
        helper.local = local
        yield helper
    # Como en test_discovery_web: un test que falle con la puerta cerrada no deja el hilo del
    # runner bloqueado ni usando la base durante el TRUNCATE de `client`.
    from tests.test_discovery_web import GatedLab

    if isinstance(helper.lab, GatedLab):
        helper.lab.gate.set()
    if helper.runner is not None:
        helper.runner.stop(timeout=10)


# --- perfiles ---------------------------------------------------------------------------------


def test_profiles_are_bounded_by_server_caps() -> None:
    settings = get_settings().model_copy(
        update={"discovery_concurrency": 10, "discovery_max_probes_per_second": 50}
    )
    catalog = profile_mod.profiles(settings)
    assert set(catalog) == {"quick", "standard", "deep"}
    for profile in catalog.values():
        assert profile.limits.concurrency <= 10
        assert profile.limits.max_probes_per_second <= 50
        assert profile.limits.deadline_minutes <= settings.discovery_job_timeout_minutes
        assert len(profile.ports) <= profile.limits.max_ports <= profile_mod.HARD_MAX_PORTS
    # Deep es más amplio pero acotado, y ninguno trae fingerprinting ni UDP genérico.
    assert set(catalog["quick"].ports) < set(catalog["standard"].ports) < set(catalog["deep"].ports)
    assert not catalog["quick"].reverse_dns and catalog["standard"].forward_dns


def test_profiles_endpoint_and_can_tune(client: TestClient, engine: Engine) -> None:
    body = _ok(client.get(f"{API}/discovery/profiles"))
    assert body["can_tune"] is True and body["default_profile"] == "standard"
    assert [p["name"] for p in body["profiles"]] == ["quick", "standard", "deep"]
    with TestClient(client.app) as viewer:
        authenticate(viewer, engine, "analyst")
        assert _ok(viewer.get(f"{API}/discovery/profiles"))["can_tune"] is False


def test_resolve_validates_ports_and_limits() -> None:
    settings = get_settings()
    resolved = profile_mod.resolve(settings, "quick", [22, 80], can_tune=False)
    assert resolved.ports == (22, 80)
    with pytest.raises(PermissionError):
        profile_mod.resolve(settings, "quick", [22, 6000], can_tune=False)
    with pytest.raises(PermissionError):
        profile_mod.resolve(settings, "quick", None, {"concurrency": 2}, can_tune=False)
    with pytest.raises(profile_mod.ProfileError) as info:
        profile_mod.resolve(settings, "quick", None, {"concurrency": 100_000}, can_tune=True)
    assert info.value.code == "discovery_limit_exceeded"
    with pytest.raises(profile_mod.ProfileError) as info:
        profile_mod.resolve(settings, "quick", [22, 22], can_tune=True)
    assert info.value.code == "discovery_ports_invalid"
    with pytest.raises(profile_mod.ProfileError) as info:
        profile_mod.resolve(settings, "quick", list(range(1, 300)), can_tune=True)
    assert info.value.code == "discovery_limit_exceeded"
    tuned = profile_mod.resolve(
        settings, "deep", [22, 6000], {"timeout_ms": 300, "tcp_retries": 0}, can_tune=True
    )
    params = tuned.parameters("10.0.0.0/24", for_sensor=True)
    assert params["schema_version"] == 1 and params["timeout_ms"] == 300
    assert "identify" not in params  # el sensor no tiene sondas de nombre


# --- discovery local avanzado -----------------------------------------------------------------


def test_local_advanced_job_records_evidence(web: Web, db: Session) -> None:
    from tests.test_discovery_web import GatedLab

    # Contrato (Fase 4D, test_start_authorized_discovery_completes_as_baseline): el 202 es una
    # foto tomada DESPUÉS de entregar el job al runner, así que su estado puede ser "queued" o
    # ya "running" según el planificador del SO (en Windows suele ganar el hilo del runner).
    # La puerta hace el resto determinista: el primer scan no puede terminar hasta abrirla y el
    # runner ejecuta de uno en uno, así que el segundo job sigue en cola con certeza.
    lab = GatedLab(
        {
            "10.20.0.1": Host({80, 443}, mac="02:00:00:00:00:01", name="router.corp"),
            "10.20.0.5": Host({445, 3389}, mac="02:00:00:00:00:05"),
        },
        blocked_from=6,
    )
    web.lab = lab
    job = _ok(web.start(), 202)
    assert job["status"] in {"queued", "running"}
    assert job["profile"] is None and job["job_type"] == "discovery_basic"
    created = _ok(
        web.local.post(START, json={"target": "10.20.1.0/28", "profile": "quick"}, headers=LOCAL),  # type: ignore[union-attr]
        202,
    )
    assert created["status"] == "queued"
    assert created["job_id"] != job["job_id"]
    assert created["profile"] == "quick" and created["job_type"] == "discovery_advanced"
    assert created["parameters"]["schema_version"] == 1
    # Identificador persistente: el job existe en la base con su perfil y parámetros.
    db.expire_all()
    stored = db.scalar(select(DiscoveryJob).where(DiscoveryJob.public_id == created["job_id"]))
    assert stored is not None and stored.profile == "quick"
    assert stored.parameters is not None and stored.parameters["profile"] == "quick"
    # Transición observada de verdad: en curso con progreso, sin terminar y sin evidencia
    # de un scan incompleto.
    running = web.wait(job["job_id"], lambda j: j["status"] == "running" and j["hosts_scanned"] > 0)
    assert running["completed_at"] is None
    assert web.job(created["job_id"])["status"] == "queued"
    lab.gate.set()
    done = web.finished(job["job_id"])
    assert done["status"] == "completed"
    adv = web.finished(created["job_id"])
    assert adv["status"] == "completed" and adv["observations_total"] == 0
    # Basic también deja evidencia con el mismo formato, ligada a su job y al site Local.
    default_site = db.scalar(select(Site).where(Site.is_default))
    assert default_site is not None
    basic_obs = observations(web.client, job_id=done["job_id"])
    assert basic_obs["total"] == 2 and done["observations_total"] == 2
    assert {i["job_id"] for i in basic_obs["items"]} == {done["job_id"]}
    assert {i["site_id"] for i in basic_obs["items"]} == {str(default_site.public_id)}
    item = next(i for i in basic_obs["items"] if i["address"] == "10.20.0.1")
    assert item["executor"] == "local" and item["sensor_id"] is None
    assert item["reachability"] == "responded" and item["mac"] == "02:00:00:00:00:01"
    assert set(item["methods"]) >= {"tcp", "arp", "dns"}
    assert item["confidence"] == "high"
    assert {h["hint"] for h in item["port_hints"]} == {"http", "https"}
    assert all(h["state"] == "inferred" for h in item["port_hints"])
    assert item["rtt_ms"] is not None and item["rtt_ms"] >= 0
    assert any(e["field"] == "mac" and e["state"] == "observed" for e in item["evidence"])
    # El job avanzado sondeó una red vacía: ninguna fila inventada, tampoco de otro job.
    assert observations(web.client, job_id=adv["job_id"])["total"] == 0
    db.expire_all()
    basic_id = db.scalar(select(DiscoveryJob.id).where(DiscoveryJob.public_id == done["job_id"]))
    rows = db.scalars(select(DiscoveryObservation)).all()
    assert len(rows) == 2 and {r.job_id for r in rows} == {basic_id}
    assert {r.site_id for r in rows} == {default_site.id}


def test_local_advanced_cancel_keeps_partial_results(web: Web, db: Session) -> None:
    from tests.test_discovery_web import GatedLab

    lab = GatedLab({f"10.20.0.{i}": Host({22}) for i in range(1, 14)}, blocked_from=4)
    web.lab = lab
    job = _ok(
        web.local.post(START, json={"target": NETWORK, "profile": "quick"}, headers=LOCAL),  # type: ignore[union-attr]
        202,
    )
    web.wait(job["job_id"], lambda j: j["status"] == "running" and j["hosts_alive"] >= 1)
    _ok(web.cancel(job["job_id"]))
    lab.gate.set()
    done = web.finished(job["job_id"])
    assert done["status"] == "cancelled" and done["stop_reason"] == "operator"
    # Parcial: sin filas "no_response" ni ausencias contadas.
    assert done["hosts_unresponsive"] == 0
    db.expire_all()
    assert db.scalar(select(func.count()).select_from(Asset).where(Asset.network_misses > 0)) == 0


def test_local_profile_respects_server_switches() -> None:
    server = ScanConfig(ports=(22,), icmp=False, reverse_dns=False, identify=False)
    resolved = profile_mod.resolve(get_settings(), "deep", can_tune=False)
    scan = profile_mod.scan_config(resolved.parameters("10.0.0.0/28"), server)
    # DISCOVERY_ICMP/REVERSE_DNS/IDENTIFY=false ganan a cualquier perfil.
    assert not scan.icmp and not scan.reverse_dns and not scan.forward_dns and not scan.identify
    assert scan.tcp_retries == resolved.limits.tcp_retries


# --- motor: reintentos, DNS, timeouts, concurrencia -----------------------------------------


class CountingLab(Lab):
    def __init__(self, hosts: dict[str, Host], flaky: set[tuple[str, int]]) -> None:
        super().__init__(hosts)
        self.calls: list[tuple[str, int]] = []
        self.flaky = set(flaky)
        self.inflight = 0
        self.peak = 0
        self.forward: dict[str, set[str] | None] = {}

    async def tcp(self, address: Any, port: int, timeout: float) -> PortState:
        key = (str(address), port)
        self.calls.append(key)
        self.inflight += 1
        self.peak = max(self.peak, self.inflight)
        await asyncio.sleep(0.001)
        self.inflight -= 1
        if key in self.flaky:
            self.flaky.discard(key)
            return PortState.FILTERED
        return await super().tcp(address, port, timeout)

    async def forward_dns(self, name: str, timeout: float) -> set[str] | None:
        return self.forward.get(name)


def _scan(lab: Lab, **config: Any) -> Any:
    values: dict[str, Any] = {"ports": (22, 80, 443), "timeout": 0.2, "icmp": False}
    values.update(config)
    hosts = [ipaddress.ip_address(f"10.20.0.{i}") for i in range(1, 9)]
    return NetworkScanner(ScanConfig(**values), lab).run(hosts)


def test_retries_only_for_live_hosts_in_details_phase() -> None:
    lab = CountingLab({"10.20.0.1": Host({22, 443})}, flaky={("10.20.0.1", 443)})
    result = _scan(lab, tcp_retries=2)
    [host] = result.observations
    assert host.open_ports == [22, 443]
    dead = [c for c in lab.calls if c[0] != "10.20.0.1"]
    assert len(dead) == 7 * 3  # liveness sin reintentos en direcciones vacías


def test_forward_dns_and_budget() -> None:
    hosts = {f"10.20.0.{i}": Host({22}, name=f"h{i}.corp") for i in range(1, 4)}
    lab = CountingLab(hosts, set())
    lab.forward = {"h1.corp": {"10.20.0.1"}, "h2.corp": {"198.51.100.7"}}
    result = _scan(lab, reverse_dns=True, forward_dns=True, dns_timeout=0.5)
    by_ip = {o.address: o for o in result.observations}
    assert by_ip["10.20.0.1"].forward_dns_match is True
    assert by_ip["10.20.0.2"].forward_dns_match is False
    assert by_ip["10.20.0.3"].forward_dns_match is None  # sin respuesta: sin conclusión
    # Lo que devuelve el DNS directo nunca se sondea.
    assert all(c[0].startswith("10.20.0.") for c in lab.calls)
    limited = _scan(CountingLab(hosts, set()), reverse_dns=True, max_dns_queries=1)
    assert sum(1 for o in limited.observations if o.reverse_dns) == 1
    assert any("budget" in e for e in limited.errors)


def test_concurrency_rate_and_deadline_are_enforced() -> None:
    lab = CountingLab({f"10.20.0.{i}": Host({22}) for i in range(1, 9)}, set())
    _scan(lab, concurrency=2, tcp_retries=1)
    assert lab.peak <= 2

    class Slow(Lab):
        async def tcp(self, address: Any, port: int, timeout: float) -> PortState:
            await asyncio.sleep(0.2)
            return PortState.FILTERED

    started = datetime.now(UTC)
    result = _scan(Slow({}), deadline=0.3, max_rate=5, concurrency=1)
    assert result.timed_out and not result.complete
    assert datetime.now(UTC) - started < timedelta(seconds=5)


# --- sensor: protocolo avanzado ---------------------------------------------------------------


def test_advanced_sensor_job_flow_and_evidence(client: TestClient, db: Session) -> None:
    site = create_site(client, "Adv", (NET,))
    sensor = AdvancedSensor(client, site["site_id"])
    assert sensor.config["max_tcp_retries"] == 2 and sensor.config["advanced_max_ports"] == 256
    first = run_advanced(
        client,
        sensor,
        [
            obs(
                "10.60.0.2",
                {22: "open", 80: "closed"},
                mac="02:00:00:00:00:02",
                rtt_ms=4,
                reverse_dns="srv.branch.lan",
                forward_dns_match=True,
            ),
            obs("10.60.0.3", {443: "open"}),
        ],
    )
    assert first["status"] == "completed" and first["profile"] == "quick"
    assert first["job_type"] == "discovery_advanced" and first["observations_total"] == 2
    assert first["sensor_name"] == "adv"
    page = observations(client, job_id=first["job_id"])
    item = next(i for i in page["items"] if i["address"] == "10.60.0.2")
    assert item["executor"] == "sensor" and item["sensor_id"] == sensor.sensor_id
    assert item["site_id"] == site["site_id"] and item["rtt_ms"] == 4
    assert item["forward_dns_match"] is True and item["open_ports"] == [22]
    assert item["changes"] == [
        {"kind": "new_host", "previous": None, "current": "10.60.0.2", "state": "observed"}
    ]
    # Segundo scan del mismo site: sin duplicados, con evidencia de cambio observada.
    second = run_advanced(
        client,
        sensor,
        [
            obs(
                "10.60.0.9",
                {22: "open", 443: "open"},
                mac="02:00:00:00:00:02",
                reverse_dns="srv2.branch.lan",
            )
        ],
    )
    assert second["hosts_new"] == 0
    db.expire_all()
    assert db.scalar(select(func.count()).select_from(Asset).where(Asset.site_id != 1)) == 2
    [moved] = observations(client, job_id=second["job_id"], reachability="responded")["items"]
    kinds = {c["kind"]: c for c in moved["changes"]}
    assert kinds["address_changed"]["previous"] == "10.60.0.2"
    assert kinds["hostname_changed"]["current"] == "srv2.branch.lan"
    assert kinds["port_new"]["current"] == "443"
    # El activo que no respondió en un scan COMPLETO queda como evidencia, no desaparece.
    assert second["hosts_unresponsive"] == 1
    [gone] = observations(client, job_id=second["job_id"], reachability="no_response")["items"]
    assert gone["address"] == "10.60.0.3" and gone["confidence"] == "low"
    assert gone["changes"][0]["kind"] == "host_unresponsive"


def test_basic_sensor_cannot_receive_advanced_jobs(client: TestClient) -> None:
    site = create_site(client, "Old", (NET,))
    old = SensorSim(client, site["site_id"])  # 0.1.0, solo discovery_basic
    body = _error(start_advanced(client, old), 409, "sensor_not_available")
    assert body["details"] == [{"required_capability": "network.discovery.advanced"}]
    # El básico sigue igual.
    discovery = _ok(
        client.post(
            START,
            json={
                "target": TARGET,
                "site_id": site["site_id"],
                "execution_target": "sensor",
                "sensor_id": old.sensor_id,
            },
        ),
        202,
    )
    assert discovery["job_type"] == "discovery_basic" and discovery["profile"] is None
    [job] = old.poll()
    assert job["job_type"] == "discovery_basic" and "schema_version" not in job["parameters"]


def test_advanced_job_scope_is_enforced(client: TestClient) -> None:
    a = create_site(client, "ScopeA", (NET,))
    b = create_site(client, "ScopeB", ("10.61.0.0/24",))
    sensor_b = AdvancedSensor(client, b["site_id"])
    # Red de otro site, red fuera de cualquier site, /0, pública y red demasiado grande.
    for target in (TARGET, "10.62.0.0/28", "0.0.0.0/0", "8.8.8.0/24"):
        _error(start_advanced(client, sensor_b, target=target), 422, "discovery_target_refused")
    # Un job no cambia de site manipulando site_id: el sensor pertenece a B.
    response = client.post(
        START,
        json={
            "target": TARGET,
            "site_id": a["site_id"],
            "execution_target": "sensor",
            "sensor_id": sensor_b.sensor_id,
            "profile": "quick",
        },
    )
    _error(response, 409, "sensor_not_available")
    _error(
        start_advanced(client, sensor_b, target="10.61.0.0/24", limits={"max_hosts": 16}),
        422,
        "discovery_scope_too_large",
    )
    _error(
        start_advanced(client, sensor_b, target="10.61.0.0/28", limits={"concurrency": 4000}),
        422,
        "discovery_limit_exceeded",
    )
    _error(
        client.post(START, json={"target": TARGET, "ports": [22]}),
        422,
        "discovery_options_require_profile",
    )
    _error(start_advanced(client, sensor_b, profile="pentest"), 422, "validation_error")


def test_rbac_tune_and_viewer(client: TestClient, engine: Engine, db: Session) -> None:
    site = create_site(client, "Rbac6a", (NET,))
    sensor = AdvancedSensor(client, site["site_id"])
    with TestClient(client.app) as analyst:
        authenticate(analyst, engine, "analyst")
        _error(
            start_advanced(analyst, sensor, limits={"timeout_ms": 300}),
            403,
            "discovery_tune_forbidden",
        )
        _error(start_advanced(analyst, sensor, ports=[22, 6000]), 403, "discovery_tune_forbidden")
        # Un subconjunto de puertos del perfil sí está permitido.
        created = _ok(start_advanced(analyst, sensor, ports=[22, 443]), 202)
        assert created["parameters"]["ports"] == [22, 443]
        _ok(analyst.post(f"{START}/{created['job_id']}/cancel"))
    with TestClient(client.app) as viewer:
        authenticate(viewer, engine, "viewer")
        _error(start_advanced(viewer, sensor), 403, "permission_denied")
        assert observations(viewer)["total"] >= 0
    # Admin: límites propios, guardados y auditados.
    tuned = _ok(
        start_advanced(
            client, sensor, ports=[22, 6000], limits={"timeout_ms": 300, "tcp_retries": 0}
        ),
        202,
    )
    assert tuned["parameters"]["ports"] == [22, 6000]
    assert tuned["parameters"]["timeout_ms"] == 300
    db.expire_all()
    [event] = db.scalars(
        select(AuditEvent).where(
            AuditEvent.action == "discovery_started", AuditEvent.target_id == tuned["job_id"]
        )
    ).all()
    assert event.details is not None and event.details["profile"] == "quick"
    denied = db.scalars(
        select(AuditEvent).where(
            AuditEvent.action == "discovery_started", AuditEvent.result != "success"
        )
    ).all()
    assert any((e.details or {}).get("error") == "discovery_tune_forbidden" for e in denied)


def test_partial_and_failed_runs_never_delete_or_conclude(client: TestClient, db: Session) -> None:
    site = create_site(client, "Partial", (NET,))
    sensor = AdvancedSensor(client, site["site_id"])
    run_advanced(client, sensor, [obs("10.60.0.2"), obs("10.60.0.3")])
    before = db.scalar(select(func.count()).select_from(Asset)) or 0
    timed = run_advanced(client, sensor, [obs("10.60.0.2")], outcome="timed_out")
    assert timed["status"] == "cancelled" and timed["hosts_unresponsive"] == 0
    incomplete = run_advanced(client, sensor, [obs("10.60.0.2")], batches_sent=3)
    assert incomplete["stop_reason"] == "incomplete" and incomplete["hosts_unresponsive"] == 0
    failed = run_advanced(client, sensor, [], outcome="failed", errors=["boom"])
    assert failed["status"] == "failed" and failed["observations_total"] == 0
    # Un scan completo vacío: evidencia "no_response", un fallo contado, nada borrado.
    empty = run_advanced(client, sensor, [])
    assert empty["status"] == "completed" and empty["hosts_unresponsive"] == 2
    db.expire_all()
    assert (db.scalar(select(func.count()).select_from(Asset)) or 0) == before
    assert not db.scalars(select(Alert).where(Alert.rule == AlertRule.ASSET_DISAPPEARED)).all()


def test_duplicate_batches_and_merged_observations(client: TestClient, db: Session) -> None:
    site = create_site(client, "Dup", (NET,))
    sensor = AdvancedSensor(client, site["site_id"])
    _ok(start_advanced(client, sensor), 202)
    [job] = sensor.poll()
    _ok(sensor.start(job))
    batch = str(uuid.uuid4())
    first = [obs("10.60.0.2", {22: "open"}, rtt_ms=9)]
    _ok(sensor.results(job, first, batch))
    again = _ok(sensor.results(job, first, batch))
    assert again["duplicate"] is True
    _error(
        sensor.results(job, [obs("10.60.0.2", {80: "open"})], batch), 409, "sensor_batch_conflict"
    )
    # Misma dirección en otro lote: se fusiona (puertos por unión, RTT mínimo).
    _ok(sensor.results(job, [obs("10.60.0.2", {443: "open"}, rtt_ms=3, forward_dns_match=False)]))
    _ok(sensor.complete(job, batches_sent=2))
    done = sensor.admin()["last_job"]
    assert done["observations_received"] == 1
    [item] = observations(client, site_id=site["site_id"])["items"]
    assert item["open_ports"] == [22, 443] and item["rtt_ms"] == 3
    assert item["forward_dns_match"] is False
    # El complete repetido devuelve lo mismo sin volver a aplicar.
    assert _ok(sensor.complete(job, batches_sent=2))["duplicate"] is True
    assert observations(client, site_id=site["site_id"])["total"] == 1


def test_cross_site_isolation_and_filters(client: TestClient) -> None:
    a = create_site(client, "IsoA", (NET,))
    b = create_site(client, "IsoB", (NET,))
    sa, sb = AdvancedSensor(client, a["site_id"], "sa"), AdvancedSensor(client, b["site_id"], "sb")
    run_advanced(client, sa, [obs("10.60.0.2", mac="02:00:00:00:00:aa", sources=["tcp", "arp"])])
    run_advanced(client, sb, [obs("10.60.0.2", mac="02:00:00:00:00:aa")])
    latest = observations(client, latest="true", q="10.60.0.2")
    assert latest["total"] == 2
    assert len({i["asset_id"] for i in latest["items"]}) == 2  # dos activos, sin fusión
    assert observations(client, site_id=a["site_id"])["total"] == 1
    assert observations(client, sensor_id=sb.sensor_id)["items"][0]["site_name"] == "IsoB"
    assert observations(client, method="arp")["total"] == 1
    assert observations(client, network="10.60.0.0/30", executor="sensor")["total"] == 2
    assert observations(client, network="10.99.0.0/24")["total"] == 0
    assert observations(client, q="02:00:00:00:00:AA")["total"] == 2
    assert observations(client, q="%")["total"] == 0  # comodines escapados
    page = observations(client, limit=1, offset=1)
    assert len(page["items"]) == 1 and page["total"] == 2
    for bad in ({"network": "nope"}, {"method": "snmp"}, {"reachability": "x"}, {"executor": "y"}):
        _error(client.get(OBS, params=bad), 422, "discovery_filter_invalid")


def test_basic_batch_digest_is_unchanged() -> None:
    """Un lote de un sensor 0.1.x reenviado tras actualizar el servidor sigue siendo duplicado."""
    import hashlib
    import json

    item = ObservationIn.model_validate(obs("10.60.0.2"))
    legacy = item.model_dump(mode="json")
    legacy.pop("rtt_ms")
    legacy.pop("forward_dns_match")
    legacy.pop("identity")  # Corrección 6C: campo opcional, fuera del digest si falta
    raw = json.dumps([legacy], sort_keys=True, separators=(",", ":")).encode()
    assert _payload_sha256([item]) == hashlib.sha256(raw).hexdigest()


def test_observation_retention(client: TestClient, db: Session) -> None:
    site = create_site(client, "Ret", (NET,))
    run_advanced(client, AdvancedSensor(client, site["site_id"]), [obs("10.60.0.2")])
    db.execute(
        update(DiscoveryObservation).values(observed_at=datetime.now(UTC) - timedelta(days=40))
    )
    db.commit()
    policy = RetentionPolicy(None, None, discovery_observation_days=30)
    assert policy.enabled
    result = RetentionService(db, policy).purge()
    assert result.discovery_observations == 1
    assert db.scalar(select(func.count()).select_from(DiscoveryJob)) == 1  # el job se conserva


def test_job_parameters_from_tampered_row_are_rejected_by_poll(
    client: TestClient, db: Session
) -> None:
    site = create_site(client, "Tamper", (NET,))
    sensor = AdvancedSensor(client, site["site_id"])
    _ok(start_advanced(client, sensor), 202)
    # Alguien con acceso a la base cambia el target del job a una red fuera del site.
    job = db.scalars(select(SensorJob)).one()
    db.execute(
        update(SensorJob)
        .where(SensorJob.id == job.id)
        .values(parameters={**job.parameters, "target": "10.99.0.0/28"})
    )
    db.commit()
    assert sensor.poll() == []
    db.expire_all()
    assert db.get(SensorJob, job.id).error_code == "network_not_authorized"  # type: ignore[union-attr]


def test_concurrent_cancel_and_complete_do_not_corrupt(client: TestClient, engine: Engine) -> None:
    site = create_site(client, "Race6a", (NET,))
    sensor = AdvancedSensor(client, site["site_id"])
    discovery = _ok(start_advanced(client, sensor), 202)
    [job] = sensor.poll()
    _ok(sensor.start(job))
    _ok(sensor.results(job, [obs("10.60.0.2")]))
    errors: list[BaseException] = []

    def cancel() -> None:
        try:
            client.post(f"{START}/{discovery['job_id']}/cancel")
        except BaseException as exc:  # pragma: no cover - solo para el informe
            errors.append(exc)

    thread = threading.Thread(target=cancel)
    thread.start()
    sensor.complete(job, batches_sent=1)
    thread.join(10)
    assert not errors
    final = _ok(client.get(f"{API}/discovery/jobs/{discovery['job_id']}"))
    assert final["status"] in {"completed", "cancelled"}
    with sessionmaker(bind=engine)() as session:
        rows = session.scalars(select(DiscoveryObservation)).all()
        assert len(rows) <= 1
