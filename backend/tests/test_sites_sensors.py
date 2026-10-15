"""Fase 5F: sites, redes autorizadas, sensores distribuidos y discovery remoto.

Cada test lleva la letra del caso obligatorio que cubre (A-AE, ver el plan de la fase). El
sensor se simula con llamadas HTTP al protocolo real (/api/v1/sensor/*): nada de red real.
"""

import json
import logging
import threading
import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

import pytest
from alembic import command
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select, text, update
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.core.exceptions import SentraError
from app.models.asset import Asset, MonitoringMethod
from app.models.audit import AuditEvent
from app.models.discovery import DiscoveryJob
from app.models.site import Sensor, SensorEnrollmentToken, SensorJob, SensorJobBatch, Site
from app.schemas.site import SensorEnrollRequest, SensorPollRequest, SensorResultsRequest
from app.services.sensor_service import SensorProtocol
from tests.conftest import _alembic_config, agent_payload, authenticate

API = "/api/v1"
SITES = f"{API}/sites"
SENSORS = f"{API}/sensors"
TOKENS = f"{API}/sensors/enrollment-tokens"
PROTO = f"{API}/sensor"
START = f"{API}/console/discovery/jobs"
CAPS = ["network.discovery.basic", "network.icmp", "network.tcp", "network.arp"]
NET = "10.60.0.0/24"
TARGET = "10.60.0.0/28"


# --- utilidades -------------------------------------------------------------------------------


def _ok(response: Any, status: int = 200) -> Any:
    assert response.status_code == status, response.text
    return response.json() if response.content else None


def _error(response: Any, status: int, code: str) -> dict[str, Any]:
    assert response.status_code == status, response.text
    body: dict[str, Any] = response.json()["error"]
    assert body["code"] == code, body
    return body


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


def create_site(client: TestClient, name: str, cidrs: tuple[str, ...] = ()) -> dict[str, Any]:
    site: dict[str, Any] = _ok(client.post(SITES, json={"name": name}), 201)
    for cidr in cidrs:
        _ok(client.post(f"{SITES}/{site['site_id']}/networks", json={"cidr": cidr}), 201)
    return site


def default_site(client: TestClient) -> dict[str, Any]:
    sites = _ok(client.get(SITES))["items"]
    return next(s for s in sites if s["is_default"])


def new_token(client: TestClient, site_id: str, name: str = "sensor") -> str:
    created = _ok(client.post(TOKENS, json={"site_id": site_id, "name": name}), 201)
    token: str = created["token"]
    return token


def enroll(
    client: TestClient, token: str, caps: list[str] | None = None, version: str = "0.1.0"
) -> Any:
    return client.post(
        f"{PROTO}/enroll",
        json={
            "hostname": "sensor-host",
            "platform": "linux",
            "sensor_version": version,
            "capabilities": CAPS if caps is None else caps,
        },
        headers={"X-Sensor-Enrollment-Token": token},
    )


class SensorSim:
    """Un sensor de pruebas: habla el protocolo real con su credencial."""

    def __init__(self, client: TestClient, site_id: str, name: str = "sensor") -> None:
        self.client = client
        body = _ok(enroll(client, new_token(client, site_id, name)), 201)
        self.credential: str = body["credential"]
        self.sensor_id: str = body["sensor_id"]
        self.site_id = site_id
        self.config = body["config"]

    def call(self, path: str, body: Any = None) -> Any:
        return self.client.post(
            f"{PROTO}{path}",
            json=body if body is not None else {},
            headers={"Authorization": f"Bearer {self.credential}"},
        )

    def heartbeat(self, **body: Any) -> Any:
        return self.call("/heartbeat", body)

    def poll(self, max_jobs: int = 1) -> list[dict[str, Any]]:
        jobs: list[dict[str, Any]] = _ok(self.call("/jobs/poll", {"max_jobs": max_jobs}))["jobs"]
        return jobs

    def start(self, job: dict[str, Any]) -> Any:
        return self.call(f"/jobs/{job['job_id']}/start", {"attempt": job["attempt"]})

    def results(
        self, job: dict[str, Any], observations: list[dict[str, Any]], batch: str | None = None
    ) -> Any:
        return self.call(
            f"/jobs/{job['job_id']}/results",
            {
                "batch_id": batch or str(uuid.uuid4()),
                "attempt": job["attempt"],
                "observations": observations,
            },
        )

    def complete(self, job: dict[str, Any], outcome: str = "completed", **extra: Any) -> Any:
        body = {"attempt": job["attempt"], "outcome": outcome, "hosts_scanned": 14}
        body.update(extra)
        return self.call(f"/jobs/{job['job_id']}/complete", body)

    def admin(self) -> dict[str, Any]:
        sensor: dict[str, Any] = _ok(self.client.get(f"{SENSORS}/{self.sensor_id}"))
        return sensor


def obs(address: str, ports: dict[int, str] | None = None, **extra: Any) -> dict[str, Any]:
    return {
        "address": address,
        "ports": [{"port": p, "state": s} for p, s in (ports or {22: "open"}).items()],
        "sources": ["tcp"],
        "observed_at": datetime.now(UTC).isoformat(),
        **extra,
    }


def start_remote(client: TestClient, sensor: SensorSim, target: str = TARGET) -> Any:
    return client.post(
        START,
        json={
            "target": target,
            "site_id": sensor.site_id,
            "execution_target": "sensor",
            "sensor_id": sensor.sensor_id,
        },
    )


def run_remote(
    client: TestClient, sensor: SensorSim, observations: list[dict[str, Any]], **complete: Any
) -> dict[str, Any]:
    """Discovery remoto completo: pedirlo, recogerlo, empezar, enviar y cerrar."""
    discovery = _ok(start_remote(client, sensor), 202)
    [job] = sensor.poll()
    _ok(sensor.start(job))
    if observations:
        _ok(sensor.results(job, observations))
    complete.setdefault("batches_sent", 1 if observations else 0)
    _ok(sensor.complete(job, **complete))
    return _ok(client.get(f"{API}/discovery/jobs/{discovery['job_id']}"))  # type: ignore[no-any-return]


def audit(db: Session, action: str) -> list[AuditEvent]:
    db.expire_all()
    return list(db.scalars(select(AuditEvent).where(AuditEvent.action == action)))


# --- A-F: sites y redes -------------------------------------------------------------------------


def test_a_create_site(client: TestClient, db: Session) -> None:
    site = create_site(client, "Sede Madrid")
    assert site["slug"] == "sede-madrid" and site["status"] == "active"
    assert site["is_default"] is False and site["version"] == 1
    _error(client.post(SITES, json={"name": "Otra", "slug": "sede-madrid"}), 409, "site_slug_taken")
    _error(
        client.post(SITES, json={"name": "X", "timezone": "Mars/Base"}),
        422,
        "site_timezone_invalid",
    )
    assert [e.target_id for e in audit(db, "site_created")] == [site["site_id"]]
    # Siempre existe el site por defecto con los datos históricos.
    assert default_site(client)["slug"] == "local"


def test_b_edit_site_with_optimistic_concurrency(client: TestClient) -> None:
    site = create_site(client, "Lab")
    edited = _ok(
        client.patch(f"{SITES}/{site['site_id']}", json={"version": 1, "location_label": "P2"})
    )
    assert edited["location_label"] == "P2" and edited["version"] == 2
    _error(
        client.patch(f"{SITES}/{site['site_id']}", json={"version": 1, "name": "Y"}),
        409,
        "site_conflict",
    )
    disabled = _ok(
        client.patch(f"{SITES}/{site['site_id']}", json={"version": 2, "status": "disabled"})
    )
    assert disabled["status"] == "disabled"


def test_c_archive_and_restore_site(client: TestClient) -> None:
    site = create_site(client, "Antigua")
    archived = _ok(
        client.post(f"{SITES}/{site['site_id']}/archive", json={"version": 1, "reason": "cierre"})
    )
    assert archived["status"] == "archived" and archived["archived_at"]
    _error(
        client.patch(f"{SITES}/{site['site_id']}", json={"version": 2, "name": "Z"}),
        409,
        "site_archived",
    )
    restored = _ok(client.post(f"{SITES}/{site['site_id']}/restore", json={"version": 2}))
    assert restored["status"] == "active"
    local = default_site(client)
    _error(
        client.post(f"{SITES}/{local['site_id']}/archive", json={"version": 1, "reason": "x"}),
        409,
        "site_default_protected",
    )


def test_d_site_with_data_is_never_hard_deleted(client: TestClient) -> None:
    empty = create_site(client, "Vacia")
    _ok(client.delete(f"{SITES}/{empty['site_id']}", params={"version": 1}), 204)
    _error(client.get(f"{SITES}/{empty['site_id']}"), 404, "site_not_found")

    busy = create_site(client, "Con datos")
    new_token(client, busy["site_id"])
    body = _error(
        client.delete(f"{SITES}/{busy['site_id']}", params={"version": 1}), 409, "site_has_data"
    )
    assert body["details"]
    local = default_site(client)
    _error(
        client.delete(f"{SITES}/{local['site_id']}", params={"version": 1}),
        409,
        "site_default_protected",
    )


@pytest.mark.parametrize(
    "cidr",
    ["10.0.0.0/33", "0.0.0.0/0", "8.8.8.0/24", "224.0.0.0/24", "10.0.0.0/8", "no-es-una-red"],
)
def test_e_network_cidr_is_validated(client: TestClient, cidr: str) -> None:
    site = create_site(client, "Validacion")
    _error(
        client.post(f"{SITES}/{site['site_id']}/networks", json={"cidr": cidr}),
        422,
        "site_network_invalid",
    )


def test_e_overlap_inside_one_site_is_refused(client: TestClient) -> None:
    site = create_site(client, "Solape", (NET,))
    _error(
        client.post(f"{SITES}/{site['site_id']}/networks", json={"cidr": "10.60.0.128/25"}),
        409,
        "site_network_overlap",
    )


def test_f_same_cidr_in_two_sites_is_allowed(client: TestClient) -> None:
    a = create_site(client, "A", (NET,))
    b = create_site(client, "B", (NET,))
    for site in (a, b):
        [network] = _ok(client.get(f"{SITES}/{site['site_id']}/networks"))["items"]
        assert network["cidr"] == NET and network["host_count"] == 254
    other = _ok(client.get(f"{SITES}/{b['site_id']}/networks"))["items"][0]
    # La red de otro site responde como inexistente (sin IDOR).
    _error(
        client.patch(
            f"{SITES}/{a['site_id']}/networks/{other['network_id']}", json={"enabled": False}
        ),
        404,
        "site_network_not_found",
    )


# --- G-K: enrolamiento e identidad --------------------------------------------------------------


def test_g_i_enrollment_token_is_single_use(client: TestClient, db: Session) -> None:
    site = create_site(client, "Enrol", (NET,))
    token = new_token(client, site["site_id"])
    first = _ok(enroll(client, token), 201)
    assert first["credential"].startswith("sentra_sc_") and first["site_id"] == site["site_id"]
    assert first["config"]["allowed_networks"] == [NET]
    _error(enroll(client, token), 401, "sensor_enrollment_invalid")  # I: reutilizado
    [row] = _ok(client.get(TOKENS))["items"]
    assert row["state"] == "consumed" and row["sensor_id"] == first["sensor_id"]
    # Solo hashes en la base de datos.
    sensor = db.scalar(select(Sensor))
    assert sensor is not None and first["credential"] not in sensor.credential_hash
    stored = db.scalar(select(SensorEnrollmentToken))
    assert stored is not None and token not in stored.token_hash


def test_h_expired_and_revoked_tokens_are_refused(client: TestClient, db: Session) -> None:
    site = create_site(client, "Caducado")
    expired = new_token(client, site["site_id"])
    db.execute(
        update(SensorEnrollmentToken).values(expires_at=datetime.now(UTC) - timedelta(minutes=1))
    )
    db.commit()
    _error(enroll(client, expired), 401, "sensor_enrollment_invalid")
    revoked = _ok(client.post(TOKENS, json={"site_id": site["site_id"], "name": "r"}), 201)
    _ok(client.post(f"{TOKENS}/{revoked['enrollment_id']}/revoke"))
    _error(enroll(client, revoked["token"]), 401, "sensor_enrollment_invalid")
    _error(enroll(client, "sentra_se_inventado"), 401, "sensor_enrollment_invalid")
    _error(enroll(client, "otra-cosa"), 401, "sensor_enrollment_invalid")
    # Un site archivado no emite tokens.
    _ok(client.post(f"{SITES}/{site['site_id']}/archive", json={"version": 1, "reason": "x"}))
    _error(
        client.post(TOKENS, json={"site_id": site["site_id"], "name": "n"}), 409, "site_not_active"
    )


def test_j_heartbeat_requires_the_sensor_credential(client: TestClient) -> None:
    site = create_site(client, "HB", (NET,))
    sensor = SensorSim(client, site["site_id"])
    _error(client.post(f"{PROTO}/heartbeat", json={}), 401, "sensor_unauthorized")
    _error(
        client.post(f"{PROTO}/heartbeat", json={}, headers={"Authorization": "Bearer sentra_sc_x"}),
        401,
        "sensor_unauthorized",
    )
    # Una sesión del dashboard no sirve como credencial de sensor.
    _error(client.post(f"{PROTO}/jobs/poll", json={}), 401, "sensor_unauthorized")
    beat = _ok(
        sensor.heartbeat(
            sensor_version="0.1.0",
            capabilities=[*CAPS, "snmp.walk"],
            queue_depth=2,
            spool_items=3,
            uptime_seconds=60,
            sent_at=datetime.now(UTC).isoformat(),
        )
    )
    assert beat["status"] == "active" and beat["config"]["jobs_enabled"] is True
    assert beat["version_status"] == "current" and beat["rotate_credential"] is False
    admin = sensor.admin()
    assert admin["status"] == "online" and admin["spool_items"] == 3
    # Capacidades fuera de la allowlist del servidor se descartan.
    assert "snmp.walk" not in admin["capabilities"]


def test_k_revoked_sensor_is_refused_and_its_jobs_cancelled(
    client: TestClient, db: Session
) -> None:
    site = create_site(client, "Rev", (NET,))
    sensor = SensorSim(client, site["site_id"])
    discovery = _ok(start_remote(client, sensor), 202)
    _ok(
        client.post(f"{SENSORS}/{sensor.sensor_id}/revoke", json={"version": 1, "reason": "robado"})
    )
    _error(sensor.heartbeat(), 403, "sensor_revoked")
    _error(sensor.call("/jobs/poll", {}), 403, "sensor_revoked")
    job = _ok(client.get(f"{API}/discovery/jobs/{discovery['job_id']}"))
    assert job["status"] == "cancelled"
    assert sensor.admin()["status"] == "revoked"
    _error(
        client.post(f"{SENSORS}/{sensor.sensor_id}/enable", json={"version": 2}),
        409,
        "sensor_revoked",
    )
    assert audit(db, "sensor_revoked")


# --- L-R: jobs, leases, idempotencia y límites -------------------------------------------------


def test_l_m_sensor_only_gets_its_own_jobs(client: TestClient) -> None:
    a = create_site(client, "A", (NET,))
    b = create_site(client, "B", (NET,))
    first = SensorSim(client, a["site_id"], "a1")
    second = SensorSim(client, a["site_id"], "a2")
    remote = SensorSim(client, b["site_id"], "b1")
    _ok(start_remote(client, first), 202)
    assert second.poll() == [] and remote.poll() == []  # L y M
    [job] = first.poll()
    assert job["site_id"] == a["site_id"] and job["job_type"] == "discovery_basic"
    assert job["parameters"]["target"] == TARGET
    # El job de otro sensor responde como inexistente.
    _error(second.start(job), 404, "sensor_job_not_found")
    _error(remote.results(job, [obs("10.60.0.2")]), 404, "sensor_job_not_found")
    # M: un sensor de otro site no puede ejecutar un discovery de este site.
    body = {"target": TARGET, "site_id": a["site_id"], "execution_target": "sensor"}
    _error(
        client.post(START, json={**body, "sensor_id": remote.sensor_id}),
        409,
        "sensor_not_available",
    )
    # Dos sensores en un mismo site: el segundo también trabaja (otra red libre).
    other = {**body, "target": "10.60.0.16/28", "sensor_id": second.sensor_id}
    _ok(client.post(START, json=other), 202)
    assert [j["parameters"]["target"] for j in second.poll()] == ["10.60.0.16/28"]


def test_n_expired_job_is_never_delivered(client: TestClient, db: Session) -> None:
    site = create_site(client, "Exp", (NET,))
    sensor = SensorSim(client, site["site_id"])
    discovery = _ok(start_remote(client, sensor), 202)
    db.execute(update(SensorJob).values(expires_at=datetime.now(UTC) - timedelta(seconds=1)))
    db.commit()
    assert sensor.poll() == []
    db.expire_all()
    assert db.scalar(select(SensorJob.status)) == "expired"
    job = _ok(client.get(f"{API}/discovery/jobs/{discovery['job_id']}"))
    assert job["status"] == "failed" and job["stop_reason"] == "expired"
    # La red queda libre para otro discovery.
    _ok(start_remote(client, sensor), 202)


def test_o_unconfirmed_lease_returns_to_the_queue(client: TestClient, db: Session) -> None:
    site = create_site(client, "Lease", (NET,))
    sensor = SensorSim(client, site["site_id"])
    _ok(start_remote(client, sensor), 202)
    [job] = sensor.poll()
    assert job["attempt"] == 1 and sensor.poll() == []  # leased: no se re-entrega
    db.execute(update(SensorJob).values(lease_expires_at=datetime.now(UTC) - timedelta(seconds=1)))
    db.commit()
    [again] = sensor.poll()
    assert again["job_id"] == job["job_id"] and again["attempt"] == 2
    assert again["idempotency_key"] != job["idempotency_key"]
    _error(sensor.start(job), 409, "sensor_job_not_leased")  # intento viejo
    started = _ok(sensor.start(again))
    assert started["status"] == "running"
    assert _ok(sensor.start(again)) == started  # start repetido: misma respuesta
    # Sin más intentos el lease vencido falla el job.
    db.execute(
        update(SensorJob).values(
            status="leased", lease_expires_at=datetime.now(UTC) - timedelta(seconds=1)
        )
    )
    db.commit()
    assert sensor.poll() == []
    db.expire_all()
    assert db.scalar(select(SensorJob.error_code)) == "lease_expired"


def test_p_duplicate_results_are_idempotent(client: TestClient) -> None:
    site = create_site(client, "Idem", (NET,))
    sensor = SensorSim(client, site["site_id"])
    _ok(start_remote(client, sensor), 202)
    [job] = sensor.poll()
    _ok(sensor.start(job))
    batch = str(uuid.uuid4())
    payload = [obs("10.60.0.2", {22: "open"}), obs("10.60.0.3", {80: "closed"})]
    first = _ok(sensor.results(job, payload, batch))
    assert first["accepted"] == 2 and first["duplicate"] is False
    repeat = _ok(sensor.results(job, payload, batch))
    assert repeat["duplicate"] is True and repeat["observations_total"] == 2
    _error(sensor.results(job, payload[:1], batch), 409, "sensor_batch_conflict")
    # Otro lote con el mismo host se fusiona (puertos por unión; "open" nunca se pierde).
    _ok(sensor.results(job, [obs("10.60.0.2", {22: "closed", 443: "open"})]))
    done = _ok(sensor.complete(job, batches_sent=2))
    assert done["status"] == "succeeded" and done["hosts_alive"] == 2
    assert done["open_ports"] == 2  # 22 y 443 en .2
    again = _ok(sensor.complete(job, batches_sent=2))
    assert again["duplicate"] is True and again["hosts_alive"] == 2
    _error(sensor.results(job, [obs("10.60.0.4")]), 409, "sensor_job_finished")


def test_q_oversized_batches_are_refused(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    site = create_site(client, "Grande", (NET,))
    sensor = SensorSim(client, site["site_id"])
    _ok(start_remote(client, sensor), 202)
    [job] = sensor.poll()
    _ok(sensor.start(job))
    monkeypatch.setattr(get_settings(), "sensor_max_observations_per_batch", 2)
    many = [obs(f"10.60.0.{i}") for i in range(2, 5)]
    _error(sensor.results(job, many), 422, "sensor_batch_too_large")
    ports = {p: "closed" for p in range(1, 300)}
    _error(sensor.results(job, [obs("10.60.0.2", ports)]), 422, "sensor_batch_too_large")
    # Por encima de SENSOR_MAX_REQUEST_KB el cuerpo ni se lee (413 antes de autenticar).
    huge = b'{"x":"' + b"a" * (1024 * 1024 + 10) + b'"}'
    response = client.post(
        f"{PROTO}/jobs/{job['job_id']}/results",
        content=huge,
        headers={
            "Authorization": f"Bearer {sensor.credential}",
            "Content-Type": "application/json",
        },
    )
    _error(response, 413, "payload_too_large")


def test_r_site_spoofing_is_refused(client: TestClient, db: Session) -> None:
    a = create_site(client, "A", (NET,))
    b = create_site(client, "B", (NET,))
    sensor = SensorSim(client, a["site_id"])
    _ok(start_remote(client, sensor), 202)
    [job] = sensor.poll()
    _ok(sensor.start(job))
    # Campos de site en el cuerpo no existen en el protocolo (extra=forbid).
    spoof = {
        "batch_id": str(uuid.uuid4()),
        "attempt": 1,
        "observations": [],
        "site_id": b["site_id"],
    }
    assert sensor.call(f"/jobs/{job['job_id']}/results", spoof).status_code == 422
    bad = obs("10.60.0.2", site_id=b["site_id"])
    assert sensor.results(job, [bad]).status_code == 422
    # Fuera del target del job (aunque dentro de la red del site): rechazado.
    _error(sensor.results(job, [obs("10.60.0.200")]), 422, "sensor_observation_out_of_scope")
    _error(sensor.results(job, [obs("192.168.50.2")]), 422, "sensor_observation_out_of_scope")
    _ok(sensor.results(job, [obs("10.60.0.2")]))
    _ok(sensor.complete(job, batches_sent=1))
    db.expire_all()
    [asset] = db.scalars(select(Asset).where(Asset.primary_ip == "10.60.0.2")).all()
    site_a = db.scalar(select(Site.id).where(Site.public_id == uuid.UUID(a["site_id"])))
    assert asset.site_id == site_a


# --- S-V: identidad de activos y discovery ------------------------------------------------------


def test_s_same_ip_in_two_sites_are_two_assets(client: TestClient, db: Session) -> None:
    a = create_site(client, "A", (NET,))
    b = create_site(client, "B", (NET,))
    for site in (a, b):
        sensor = SensorSim(client, site["site_id"])
        job = run_remote(client, sensor, [obs("10.60.0.5", mac="02:00:00:00:00:05")])
        assert job["status"] == "completed" and job["hosts_new"] == 1
        assert job["execution_target"] == "sensor" and job["site_id"] == site["site_id"]
        assert job["sensor_name"] == "sensor"
    db.expire_all()
    assets = db.scalars(select(Asset).where(Asset.primary_ip == "10.60.0.5")).all()
    # Misma IP y misma MAC en dos sites: dos activos, nunca fusionados automáticamente.
    assert len(assets) == 2 and len({x.site_id for x in assets}) == 2
    listed = _ok(client.get(f"{API}/assets", params={"site_id": a["site_id"]}))["items"]
    assert [x["primary_ip"] for x in listed] == ["10.60.0.5"]
    assert listed[0]["site_name"] == "A"


def test_t_no_cross_site_auto_reconciliation(client: TestClient, db: Session) -> None:
    remote = create_site(client, "Remota", (NET,))
    sensor = SensorSim(client, remote["site_id"])
    run_remote(client, sensor, [obs("10.60.0.7")])
    # Un agente del site por defecto con la misma IP NO adopta el descubierto de otro site.
    _ok(client.post(f"{API}/agents/register", json=agent_payload(primary_ip="10.60.0.7")), 201)
    db.expire_all()
    assets = db.scalars(select(Asset).where(Asset.primary_ip == "10.60.0.7")).all()
    assert len(assets) == 2
    agent = next(x for x in assets if x.agent_id is not None)
    discovered = next(x for x in assets if x.agent_id is None)
    assert agent.site_id != discovered.site_id
    # Tampoco se sugiere ni se permite reconciliar a mano entre sites.
    preview = client.get(f"{API}/assets/{discovered.public_id}/duplicates")
    if preview.status_code == 200:
        ids = {c["asset"]["asset_id"] for c in preview.json()["items"]}
        assert str(agent.public_id) not in ids


def test_t_agent_token_site_places_the_agent_in_that_site(client: TestClient, db: Session) -> None:
    remote = create_site(client, "Sucursal", (NET,))
    sensor = SensorSim(client, remote["site_id"])
    run_remote(client, sensor, [obs("10.60.0.8")])
    token = _ok(
        client.post(f"{API}/console/enrollment-tokens", json={"site_id": remote["site_id"]}), 201
    )
    assert token["site_name"] == "Sucursal"
    payload = agent_payload(primary_ip="10.60.0.8")
    response = client.post(
        f"{API}/agents/register", json=payload, headers={"X-Enrollment-Token": token["token"]}
    )
    _ok(response, 201)
    db.expire_all()
    # Mismo site: el descubierto se fusiona en el activo del agente (comportamiento 4E).
    [asset] = db.scalars(select(Asset).where(Asset.primary_ip == "10.60.0.8")).all()
    assert asset.agent_id is not None
    agents = _ok(client.get(f"{API}/agents", params={"site_id": remote["site_id"]}))["items"]
    assert [a["site_name"] for a in agents] == ["Sucursal"]


def test_u_local_discovery_still_works(client: TestClient, engine: Engine, db: Session) -> None:
    from tests.test_discovery_service import NETWORK
    from tests.test_discovery_web import Web

    [summary] = Web(client, engine).service().run(NETWORK)
    assert summary.hosts_new > 0
    db.expire_all()
    local = db.scalar(select(Site.id).where(Site.is_default))
    sites = set(db.scalars(select(Asset.site_id)).all())
    assert sites == {local}
    [job] = _ok(client.get(f"{API}/discovery/jobs"))["items"]
    assert job["execution_target"] == "local" and job["site_name"] == "Local"
    assert job["sensor_id"] is None
    other = create_site(client, "Otra")
    _error(
        client.post(START, json={"target": NETWORK, "site_id": other["site_id"]}),
        422,
        "discovery_local_default_site_only",
    )


def test_v_remote_discovery_ingestion(client: TestClient, db: Session) -> None:
    site = create_site(client, "Remota", (NET,))
    sensor = SensorSim(client, site["site_id"])
    first = run_remote(
        client,
        sensor,
        [
            obs("10.60.0.2", {22: "open", 80: "closed"}, mac="02:00:00:00:00:02"),
            obs("10.60.0.3", {443: "open"}, reverse_dns="nas.example.lan"),
        ],
    )
    assert first["status"] == "completed" and first["hosts_new"] == 2 and first["baseline"]
    assert first["open_ports"] == 2
    db.expire_all()
    nas = db.scalar(select(Asset).where(Asset.primary_ip == "10.60.0.3"))
    assert nas is not None and nas.reverse_dns == "nas.example.lan"
    assert nas.monitoring_method == MonitoringMethod.DISCOVERED
    assert nas.discovery_network == TARGET
    # Un scan parcial (timeout) no cuenta ausencias; uno completo sí.
    run_remote(client, sensor, [obs("10.60.0.2")], outcome="timed_out")
    db.expire_all()
    db.refresh(nas)
    assert nas.network_misses == 0
    second = run_remote(client, sensor, [obs("10.60.0.2")])
    assert second["status"] == "completed" and second["hosts_new"] == 0
    db.refresh(nas)
    assert nas.network_misses == 1
    # Lotes perdidos: el cierre se acepta como parcial (sin conclusiones negativas).
    third = run_remote(client, sensor, [obs("10.60.0.2")], batches_sent=3)
    assert third["status"] == "cancelled" and third["stop_reason"] == "incomplete"
    db.refresh(nas)
    assert nas.network_misses == 1
    last = sensor.admin()["last_job"]
    assert last["status"] == "succeeded" and last["observations_received"] == 1


def test_v_operator_cancel_of_a_running_remote_job(client: TestClient) -> None:
    site = create_site(client, "Cancel", (NET,))
    sensor = SensorSim(client, site["site_id"])
    discovery = _ok(start_remote(client, sensor), 202)
    [job] = sensor.poll()
    _ok(sensor.start(job))
    _ok(client.post(f"{START}/{discovery['job_id']}/cancel"))
    beat = _ok(sensor.heartbeat())
    assert beat["cancel_job_ids"] == [job["job_id"]]
    assert _ok(sensor.results(job, [obs("10.60.0.2")]))["cancel_requested"] is True
    _ok(sensor.complete(job, outcome="cancelled", batches_sent=1))
    done = _ok(client.get(f"{API}/discovery/jobs/{discovery['job_id']}"))
    assert done["status"] == "cancelled" and done["stop_reason"] == "operator"
    assert done["hosts_alive"] == 1


def test_v_cancel_before_start_is_immediate(client: TestClient, db: Session) -> None:
    site = create_site(client, "Cancel2", (NET,))
    sensor = SensorSim(client, site["site_id"])
    discovery = _ok(start_remote(client, sensor), 202)
    _ok(client.post(f"{START}/{discovery['job_id']}/cancel"))
    assert sensor.poll() == []
    assert audit(db, "sensor_job_cancelled")


# --- W-X: filtros por site ---------------------------------------------------------------------


def test_w_site_filters_on_dashboard_and_listings(client: TestClient) -> None:
    a = create_site(client, "A", (NET,))
    b = create_site(client, "B", (NET,))
    run_remote(client, SensorSim(client, a["site_id"]), [obs("10.60.0.2"), obs("10.60.0.3")])
    run_remote(client, SensorSim(client, b["site_id"]), [obs("10.60.0.2")])
    total = _ok(client.get(f"{API}/dashboard/summary"))
    only_a = _ok(client.get(f"{API}/dashboard/summary", params={"site_id": a["site_id"]}))
    only_b = _ok(client.get(f"{API}/dashboard/summary", params={"site_id": b["site_id"]}))
    assert total["assets"]["total"] == 3 and total["site_id"] is None
    assert only_a["assets"]["total"] == 2 and only_a["site_id"] == a["site_id"]
    assert only_b["assets"]["total"] == 1
    for path in (
        "/assets",
        "/agents",
        "/alerts",
        "/detections",
        "/incidents",
        "/vulnerabilities/findings",
        "/risk/assets",
        "/response/executions",
        "/discovery/jobs",
        "/sensors",
    ):
        response = client.get(f"{API}{path}", params={"site_id": b["site_id"]})
        assert response.status_code == 200, (path, response.text)
        _error(
            client.get(f"{API}{path}", params={"site_id": str(uuid.uuid4())}), 404, "site_not_found"
        )
    jobs = _ok(client.get(f"{API}/discovery/jobs", params={"site_id": b["site_id"]}))["items"]
    assert [j["site_name"] for j in jobs] == ["B"]
    sensors = _ok(client.get(SENSORS, params={"site_id": a["site_id"]}))
    assert sensors["summary"]["total"] == 1
    counts = {s["name"]: s for s in _ok(client.get(SITES))["items"]}
    assert counts["A"]["asset_count"] == 2 and counts["A"]["sensor_count"] == 1


def test_x_reports_site_filter(client: TestClient) -> None:
    a = create_site(client, "A", (NET,))
    preview = _ok(
        client.post(
            f"{API}/reports/preview",
            json={"report_type": "risk", "format": "html", "filters": {"site_id": a["site_id"]}},
        )
    )
    assert preview["filters"]["site_id"] == a["site_id"]
    assert preview["scope"]["site"] == {"id": a["site_id"], "name": "A"}
    _error(
        client.post(
            f"{API}/reports/preview",
            json={
                "report_type": "risk",
                "format": "html",
                "filters": {"site_id": str(uuid.uuid4())},
            },
        ),
        422,
        "report_target_not_found",
    )


def test_x_report_builders_only_see_the_site(client: TestClient, engine: Engine) -> None:
    from app.reports.builders import asset_conditions

    a = create_site(client, "A", (NET,))
    run_remote(client, SensorSim(client, a["site_id"]), [obs("10.60.0.2")])
    _ok(client.post(f"{API}/agents/register", json=agent_payload(primary_ip="10.60.0.2")), 201)

    class Ctx:
        filters: ClassVar[dict[str, Any]] = {"site_id": a["site_id"]}
        cutoff = datetime.now(UTC) + timedelta(minutes=1)

        class scope:  # noqa: N801  (imita DataScope)
            @staticmethod
            def asset_condition() -> Any:
                return text("true")

    with sessionmaker(bind=engine)() as session:
        rows = session.scalars(select(Asset.primary_ip).where(*asset_conditions(Ctx()))).all()  # type: ignore[arg-type]
    assert rows == ["10.60.0.2"]


# --- Y-AE --------------------------------------------------------------------------------------


def test_y_audit_and_logs_never_contain_secrets(
    client: TestClient, db: Session, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    site = create_site(client, "Secretos", (NET,))
    created = _ok(client.post(TOKENS, json={"site_id": site["site_id"], "name": "s"}), 201)
    token = created["token"]
    assert created["command_example"].endswith(token)
    enrolled = _ok(enroll(client, token), 201)
    credential = enrolled["credential"]
    sensor = enrolled["sensor_id"]
    _ok(client.post(f"{SENSORS}/{sensor}/rotate-credential", json={"version": 1}))
    beat = client.post(
        f"{PROTO}/heartbeat", json={}, headers={"Authorization": f"Bearer {credential}"}
    ).json()
    assert beat["rotate_credential"] is True
    rotated = client.post(
        f"{PROTO}/credential/rotate", json={}, headers={"Authorization": f"Bearer {credential}"}
    ).json()["credential"]
    # La credencial nueva funciona; al usarla, la anterior deja de valer.
    new = {"Authorization": f"Bearer {rotated}"}
    assert (
        client.post(f"{PROTO}/heartbeat", json={}, headers=new).json()["rotate_credential"] is False
    )
    old = client.post(
        f"{PROTO}/heartbeat", json={}, headers={"Authorization": f"Bearer {credential}"}
    )
    _error(old, 401, "sensor_unauthorized")
    db.expire_all()
    rows = db.scalars(select(AuditEvent)).all()
    actions = {row.action for row in rows}
    assert {
        "site_created",
        "site_network_created",
        "sensor_enrollment_token_created",
        "sensor_enrolled",
        "sensor_credential_rotation_requested",
        "sensor_credential_rotated",
    } <= actions
    dumped = json.dumps([row.details for row in rows], default=str)
    for secret in (token, credential, rotated):
        assert secret not in dumped
        assert secret not in caplog.text
    # Ni la API de lectura devuelve hashes o credenciales.
    listing = json.dumps(_ok(client.get(SENSORS)))
    assert "hash" not in listing and credential not in listing


def test_z_sensor_status_transitions(client: TestClient, db: Session) -> None:
    site = create_site(client, "Estados", (NET,))
    sensor = SensorSim(client, site["site_id"])
    assert sensor.admin()["status"] == "pending"
    _ok(sensor.heartbeat())
    assert sensor.admin()["status"] == "online"
    db.execute(update(Sensor).values(last_seen_at=datetime.now(UTC) - timedelta(minutes=10)))
    db.commit()
    assert sensor.admin()["status"] == "offline"
    db.execute(update(Sensor).values(last_seen_at=datetime.now(UTC) - timedelta(days=2)))
    db.commit()
    listed = _ok(client.get(SENSORS))
    assert listed["items"][0]["status"] == "stale" and listed["summary"]["stale"] == 1
    # Un sensor offline/stale nunca se borra ni se marca comprometido: vuelve al hablar.
    _ok(sensor.heartbeat())
    assert sensor.admin()["status"] == "online"


def test_aa_disabled_sensor_gets_no_jobs(client: TestClient, db: Session) -> None:
    site = create_site(client, "Off", (NET,))
    sensor = SensorSim(client, site["site_id"])
    discovery = _ok(start_remote(client, sensor), 202)
    _ok(client.post(f"{SENSORS}/{sensor.sensor_id}/disable", json={"version": 1}))
    assert _ok(client.get(f"{API}/discovery/jobs/{discovery['job_id']}"))["status"] == "cancelled"
    beat = _ok(sensor.heartbeat())
    assert beat["status"] == "disabled" and beat["config"]["jobs_enabled"] is False
    assert beat["config"]["allowed_networks"] == []
    assert sensor.poll() == []
    _error(start_remote(client, sensor), 409, "sensor_not_available")
    _error(sensor.call("/credential/rotate", {}), 403, "sensor_disabled")
    _ok(client.post(f"{SENSORS}/{sensor.sensor_id}/enable", json={"version": 2}))
    _ok(start_remote(client, sensor), 202)
    assert len(sensor.poll()) == 1
    # Un site deshabilitado también corta el trabajo de sus sensores.
    _ok(client.patch(f"{SITES}/{site['site_id']}", json={"version": 1, "status": "disabled"}))
    assert _ok(sensor.heartbeat())["config"]["jobs_enabled"] is False
    db.expire_all()
    assert db.scalar(select(SensorJob.status).order_by(SensorJob.id.desc())) == "cancelled"


def test_ab_unknown_job_type_is_never_delivered(client: TestClient, db: Session) -> None:
    site = create_site(client, "Tipos", (NET,))
    sensor = SensorSim(client, site["site_id"])
    row = db.scalar(select(Sensor))
    assert row is not None
    now = datetime.now(UTC)
    db.add(
        SensorJob(
            site_id=row.site_id,
            sensor_id=row.id,
            job_type="shell",
            parameters={"target": TARGET, "command": "id"},
            status="pending",
            created_by="tampered",
            created_at=now,
            expires_at=now + timedelta(minutes=5),
        )
    )
    db.commit()
    assert sensor.poll() == []
    db.expire_all()
    job = db.scalar(select(SensorJob))
    assert job is not None and job.status == "failed" and job.error_code == "job_type_unknown"
    # La API no tiene forma de pedir otro tipo de ejecución.
    body = {"target": TARGET, "site_id": site["site_id"], "execution_target": "shell"}
    assert client.post(START, json=body).status_code == 422
    # Un sensor sin la capacidad de discovery no recibe trabajos de discovery.
    lame = SensorSim.__new__(SensorSim)
    lame.client = client
    lame.site_id = site["site_id"]
    enrolled = _ok(
        enroll(client, new_token(client, site["site_id"], "lame"), caps=["network.icmp"]), 201
    )
    lame.credential, lame.sensor_id = enrolled["credential"], enrolled["sensor_id"]
    _error(start_remote(client, lame), 409, "sensor_not_available")


def test_ac_target_outside_the_site_networks_is_refused(client: TestClient) -> None:
    site = create_site(client, "Redes", (NET,))
    sensor = SensorSim(client, site["site_id"])
    _error(start_remote(client, sensor, "10.99.0.0/28"), 422, "discovery_target_refused")
    _error(start_remote(client, sensor, "10.60.0.0/16"), 422, "discovery_target_refused")
    _error(start_remote(client, sensor, "8.8.8.0/28"), 422, "discovery_target_refused")
    [network] = _ok(client.get(f"{SITES}/{site['site_id']}/networks"))["items"]
    _ok(
        client.patch(
            f"{SITES}/{site['site_id']}/networks/{network['network_id']}", json={"enabled": False}
        )
    )
    _error(start_remote(client, sensor), 422, "discovery_target_refused")
    # Una red deshabilitada después de crear el job tampoco se entrega.
    _ok(
        client.patch(
            f"{SITES}/{site['site_id']}/networks/{network['network_id']}", json={"enabled": True}
        )
    )
    discovery = _ok(start_remote(client, sensor), 202)
    _ok(
        client.patch(
            f"{SITES}/{site['site_id']}/networks/{network['network_id']}", json={"enabled": False}
        )
    )
    assert sensor.poll() == []
    assert _ok(client.get(f"{API}/discovery/jobs/{discovery['job_id']}"))["status"] == "failed"


def test_ad_observation_timestamps_are_validated(client: TestClient) -> None:
    site = create_site(client, "Reloj", (NET,))
    sensor = SensorSim(client, site["site_id"])
    _ok(start_remote(client, sensor), 202)
    [job] = sensor.poll()
    _ok(sensor.start(job))
    future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    past = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    _error(
        sensor.results(job, [obs("10.60.0.2", observed_at=future)]), 422, "sensor_timestamp_invalid"
    )
    _error(
        sensor.results(job, [obs("10.60.0.2", observed_at=past)]), 422, "sensor_timestamp_invalid"
    )
    naive = datetime.now(UTC).replace(tzinfo=None).isoformat()
    assert sensor.results(job, [obs("10.60.0.2", observed_at=naive)]).status_code == 422
    skewed = (datetime.now(UTC) + timedelta(seconds=60)).isoformat()
    _ok(sensor.results(job, [obs("10.60.0.2", observed_at=skewed)]))


def test_ae_migration_preserves_existing_assets(client: TestClient, engine: Engine) -> None:
    _ok(client.post(f"{API}/agents/register", json=agent_payload(primary_ip="10.70.0.9")), 201)
    config = _alembic_config(get_settings().test_database_url or "")
    command.downgrade(config, "0031")
    try:
        with engine.connect() as connection:
            count = connection.execute(
                text("SELECT count(*) FROM assets WHERE primary_ip = '10.70.0.9'")
            ).scalar()
        assert count == 1
    finally:
        command.upgrade(config, "head")
    with engine.connect() as connection:
        row = connection.execute(
            text(
                "SELECT s.slug, s.is_default FROM assets a JOIN sites s ON s.id = a.site_id"
                " WHERE a.primary_ip = '10.70.0.9'"
            )
        ).one()
    assert tuple(row) == ("local", True)
    [asset] = _ok(client.get(f"{API}/assets"))["items"]
    assert asset["site_name"] == "Local"


# --- concurrencia y RBAC ---------------------------------------------------------------------


def test_two_polls_never_share_a_job(client: TestClient) -> None:
    site = create_site(client, "Carrera", (NET,))
    sensor = SensorSim(client, site["site_id"])
    _ok(start_remote(client, sensor), 202)
    first = sensor.poll(max_jobs=5)
    second = sensor.poll(max_jobs=5)
    assert len(first) == 1 and second == []
    # Un discovery de la misma red en el mismo site está ocupado; en otro site, no.
    _error(start_remote(client, sensor), 409, "discovery_busy")
    other = create_site(client, "Otro", (NET,))
    _ok(start_remote(client, SensorSim(client, other["site_id"])), 202)


def _race(
    engine: Engine, work: Callable[[SensorProtocol], Any], n: int = 4
) -> tuple[list[Any], list[BaseException]]:
    """Ejecuta `work` en n hilos a la vez, cada uno con su sesión (como n peticiones reales)."""
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    barrier = threading.Barrier(n)
    results: list[Any] = []
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            with factory() as session:
                protocol = SensorProtocol(session, get_settings())
                barrier.wait()
                results.append(work(protocol))
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return results, errors


def test_concurrent_enrollments_with_one_token_create_one_sensor(
    client: TestClient, engine: Engine, db: Session
) -> None:
    site = create_site(client, "Carrera", (NET,))
    token = new_token(client, site["site_id"])
    body = SensorEnrollRequest(
        hostname="h", platform="linux", sensor_version="0.1.0", capabilities=CAPS
    )
    results, errors = _race(engine, lambda p: p.enroll(token, body, "127.0.0.1"))
    assert len(results) == 1
    assert all(
        isinstance(e, SentraError) and e.code == "sensor_enrollment_invalid" for e in errors
    ), errors
    db.expire_all()
    assert len(db.scalars(select(Sensor)).all()) == 1


def test_concurrent_polls_lease_a_job_once(client: TestClient, engine: Engine) -> None:
    site = create_site(client, "Carrera", (NET,))
    sensor = SensorSim(client, site["site_id"])
    _ok(start_remote(client, sensor), 202)

    def poll(protocol: SensorProtocol) -> int:
        me = protocol.authenticate(sensor.credential)
        return len(protocol.poll(me, SensorPollRequest(max_jobs=5)).jobs)

    results, errors = _race(engine, poll)
    assert errors == [] and sorted(results) == [0, 0, 0, 1]


def test_concurrent_duplicate_batches_are_stored_once(
    client: TestClient, engine: Engine, db: Session
) -> None:
    site = create_site(client, "Carrera", (NET,))
    sensor = SensorSim(client, site["site_id"])
    _ok(start_remote(client, sensor), 202)
    [job] = sensor.poll()
    _ok(sensor.start(job))
    body = SensorResultsRequest.model_validate(
        {
            "batch_id": str(uuid.uuid4()),
            "attempt": job["attempt"],
            "observations": [obs("10.60.0.2")],
        }
    )

    def send(protocol: SensorProtocol) -> bool:
        me = protocol.authenticate(sensor.credential, allow_disabled=False)
        return protocol.results(me, uuid.UUID(job["job_id"]), body).duplicate

    results, errors = _race(engine, send)
    assert errors == [] and sorted(results) == [False, True, True, True]
    db.expire_all()
    assert len(db.scalars(select(SensorJobBatch)).all()) == 1


def test_rbac_viewer_and_analyst_cannot_manage_sites_or_sensors(
    client: TestClient, engine: Engine
) -> None:
    site = create_site(client, "RBAC", (NET,))
    sensor = SensorSim(client, site["site_id"])
    for role in ("viewer", "analyst"):
        with TestClient(client.app) as browser:
            authenticate(browser, engine, role)
            assert browser.get(SITES).status_code == 200
            assert browser.get(SENSORS).status_code == 200
            _error(browser.post(SITES, json={"name": "x"}), 403, "permission_denied")
            _error(
                browser.post(TOKENS, json={"site_id": site["site_id"], "name": "x"}),
                403,
                "permission_denied",
            )
            _error(browser.get(TOKENS), 403, "permission_denied")
            _error(
                browser.post(
                    f"{SENSORS}/{sensor.sensor_id}/revoke", json={"version": 1, "reason": "x"}
                ),
                403,
                "permission_denied",
            )
    with TestClient(client.app) as analyst:
        authenticate(analyst, engine, "analyst")
        # discovery:run alcanza para pedir un discovery remoto dentro de las redes del site.
        _ok(start_remote(analyst, sensor), 202)
        moved = analyst.post(
            f"{API}/assets/{uuid.uuid4()}/site",
            json={"site_id": site["site_id"], "reason": "x", "version": 0},
        )
        _error(moved, 403, "permission_denied")


def test_admin_moves_an_asset_between_sites(client: TestClient, db: Session) -> None:
    _ok(client.post(f"{API}/agents/register", json=agent_payload(primary_ip="10.70.0.10")), 201)
    [asset] = _ok(client.get(f"{API}/assets"))["items"]
    target = create_site(client, "Destino")
    path = f"{API}/assets/{asset['asset_id']}/site"
    body = {
        "site_id": target["site_id"],
        "reason": "traslado",
        "version": asset["lifecycle_version"],
    }
    moved = _ok(client.post(path, json=body))
    assert moved["site_name"] == "Destino"
    _error(client.post(path, json=body), 409, "asset_lifecycle_conflict")
    [event] = audit(db, "asset_site_changed")
    assert event.details and event.details["to_site_id"] == target["site_id"]
    _ok(client.post(f"{SITES}/{target['site_id']}/archive", json={"version": 1, "reason": "x"}))
    back = {
        "site_id": default_site(client)["site_id"],
        "reason": "x",
        "version": moved["lifecycle_version"],
    }
    _ok(client.post(path, json=back))
    archived = {
        "site_id": target["site_id"],
        "reason": "x",
        "version": moved["lifecycle_version"] + 1,
    }
    _error(client.post(path, json=archived), 409, "site_not_active")


def test_sensor_rate_limits(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.core.rate_limit import RateLimiter

    site = create_site(client, "Limites", (NET,))
    sensor = SensorSim(client, site["site_id"])
    client.app.state.sensor_heartbeat_limiter = RateLimiter(2, 60)  # type: ignore[attr-defined]
    _ok(sensor.heartbeat())
    _ok(sensor.heartbeat())
    limited = sensor.heartbeat()
    _error(limited, 429, "rate_limited")
    assert int(limited.headers["Retry-After"]) >= 1
    client.app.state.sensor_enroll_limiter = RateLimiter(1, 60)  # type: ignore[attr-defined]
    enroll(client, "sentra_se_x")
    _error(enroll(client, "sentra_se_x"), 429, "rate_limited")


def test_sensor_maintenance_sweep_marks_lost_sensors(client: TestClient, db: Session) -> None:
    from app.services.sensor_service import run_sensor_maintenance

    site = create_site(client, "Perdido", (NET,))
    sensor = SensorSim(client, site["site_id"])
    discovery = _ok(start_remote(client, sensor), 202)
    [job] = sensor.poll()
    _ok(sensor.start(job))
    _ok(sensor.results(job, [obs("10.60.0.2")]))
    db.execute(update(SensorJob).values(lease_expires_at=datetime.now(UTC) - timedelta(seconds=1)))
    db.commit()
    counts = run_sensor_maintenance(db)
    assert counts["lost"] == 1
    finished = _ok(client.get(f"{API}/discovery/jobs/{discovery['job_id']}"))
    assert finished["status"] == "failed" and finished["stop_reason"] == "interrupted"
    # Lo recibido no se aplica: sin activos creados por un scan que no terminó.
    db.expire_all()
    assert db.scalar(select(Asset.id).where(Asset.primary_ip == "10.60.0.2")) is None
    assert db.scalar(select(DiscoveryJob.id)) is not None
    _error(sensor.complete(job, batches_sent=1), 409, "sensor_job_finished")
