"""Servidor Sentra falso (transporte inyectado) y utilidades comunes. Sin red real."""

import json
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from sentra_sensor.client import HttpResponse, TransportError
from sentra_sensor.config import LocalConfig
from sentra_sensor.credentials import CredentialStore, SensorIdentity
from sentra_sensor.runner import ProberSet, SensorRunner

SENSOR_ID = "11111111-1111-4111-8111-111111111111"
SITE_ID = "22222222-2222-4222-8222-222222222222"
OTHER_ID = "33333333-3333-4333-8333-333333333333"
ENROLL_TOKEN = "enroll-token-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
CREDENTIAL = "sensor-credential-0123456789abcdefghijklmnopqrstuvwxyz"
SERVER = "http://127.0.0.1:8000"


def server_config(**overrides: Any) -> dict[str, Any]:
    config: dict[str, Any] = {
        "site_id": SITE_ID,
        "site_name": "Branch Office",
        "allowed_networks": ["10.0.0.0/24", "192.168.50.0/24"],
        "jobs_enabled": True,
        "heartbeat_interval_seconds": 30,
        "poll_interval_seconds": 60,
        "max_observations_per_batch": 100,
        "max_batch_bytes": 262_144,
        "max_ports_per_observation": 32,
        "max_hosts_per_job": 1024,
        "max_concurrency": 64,
        "max_probes_per_second": 1000,
        "max_timeout_ms": 5000,
    }
    config.update(overrides)
    return config


def make_job(now: datetime | None = None, **overrides: Any) -> dict[str, Any]:
    now = now or datetime.now(UTC)
    params = {
        "target": "10.0.0.0/29",
        "ports": [22, 80, 443],
        "timeout_ms": 500,
        "concurrency": 16,
        "max_probes_per_second": 1000,
        "icmp": False,
        "reverse_dns": False,
        "arp": False,
        "deadline_seconds": 60,
    }
    params.update(overrides.pop("parameters", {}))
    job: dict[str, Any] = {
        "job_id": str(uuid.uuid4()),
        "site_id": SITE_ID,
        "sensor_id": SENSOR_ID,
        "job_type": "discovery_basic",
        "parameters": params,
        "created_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "lease_expires_at": (now + timedelta(minutes=10)).isoformat(),
        "attempt": 1,
        "idempotency_key": "idem-1",
    }
    job.update(overrides)
    return job


def _json(status: int, body: Any, headers: dict[str, str] | None = None) -> HttpResponse:
    return HttpResponse(status, headers or {}, json.dumps(body).encode())


def _error(status: int, code: str, headers: dict[str, str] | None = None) -> HttpResponse:
    return _json(status, {"error": {"code": code, "message": code}}, headers)


class FakeServer:
    """Implementa el protocolo del sensor en memoria, con idempotencia por batch_id."""

    def __init__(self) -> None:
        self.down = False
        self.requests: list[tuple[str, dict[str, str], dict[str, Any]]] = []
        self.valid_credentials = {CREDENTIAL}
        self.enroll_token = ENROLL_TOKEN
        self.config = server_config()
        self.jobs: list[dict[str, Any]] = []
        self.batches: dict[str, dict[str, Any]] = {}
        self.batch_jobs: dict[str, str] = {}
        self.completes: dict[str, dict[str, Any]] = {}
        self.started: list[str] = []
        self.status = "active"
        self.revoked = False
        self.rotate = False
        self.cancel_ids: list[str] = []
        self.cancel_requested: set[str] = set()
        self.finished_jobs: set[str] = set()
        # (sufijo de ruta, status, code) consumidos en orden por la siguiente petición que encaje.
        self.fail_next: list[tuple[str, int, str]] = []
        # Procesa la petición y luego "pierde" la respuesta (fallo de red tras el commit).
        self.lose_response_for: set[str] = set()
        self.rotations = 0
        self.max_body_seen = 0

    # --- utilidades de test ---------------------------------------------------------
    def paths(self) -> list[str]:
        return [p for p, _h, _b in self.requests]

    def bearer_tokens(self) -> list[str]:
        return [h.get("Authorization", "") for _p, h, _b in self.requests]

    # --- transporte -----------------------------------------------------------------
    def request(
        self, method: str, url: str, headers: Mapping[str, str], body: bytes, timeout: float
    ) -> HttpResponse:
        assert method == "POST"
        path = url.split("/api/v1", 1)[1]
        payload = json.loads(body or b"{}")
        self.requests.append((path, dict(headers), payload))
        self.max_body_seen = max(self.max_body_seen, len(body))
        if self.down:
            raise TransportError("connection refused")
        for index, (suffix, status, code) in enumerate(self.fail_next):
            if path.endswith(suffix):
                del self.fail_next[index]
                return _error(status, code, {"Retry-After": "1"} if status == 429 else None)
        response = self._route(path, headers, payload)
        for suffix in list(self.lose_response_for):
            if path.endswith(suffix):
                self.lose_response_for.discard(suffix)
                raise TransportError("connection reset after commit")
        return response

    def _route(
        self, path: str, headers: Mapping[str, str], payload: dict[str, Any]
    ) -> HttpResponse:
        if path == "/sensor/enroll":
            if headers.get("X-Sensor-Enrollment-Token") != self.enroll_token:
                return _error(401, "sensor_enrollment_invalid")
            return _json(
                201,
                {
                    "sensor_id": SENSOR_ID,
                    "site_id": SITE_ID,
                    "site_name": "Branch Office",
                    "credential": CREDENTIAL,
                    "credential_issued_at": datetime.now(UTC).isoformat(),
                    "config": self.config,
                },
            )
        auth = headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or auth[7:] not in self.valid_credentials:
            return _error(401, "sensor_unauthorized")
        if self.revoked:
            return _error(403, "sensor_revoked")
        if path == "/sensor/heartbeat":
            return _json(
                200,
                {
                    "sensor_id": SENSOR_ID,
                    "site_id": SITE_ID,
                    "status": self.status,
                    "server_time": datetime.now(UTC).isoformat(),
                    "version_status": "current",
                    "rotate_credential": self.rotate,
                    "pending_jobs": len(self.jobs),
                    "cancel_job_ids": list(self.cancel_ids),
                    "config": self.config,
                },
            )
        if self.status == "disabled":
            return _error(403, "sensor_disabled")
        if path == "/sensor/credential/rotate":
            new = f"rotated-credential-{self.rotations}-{uuid.uuid4().hex}"
            self.rotations += 1
            # Dos fases: la antigua vale hasta que se usa la nueva.
            self.valid_credentials = {auth[7:], new}
            self.rotate = False
            return _json(
                200, {"credential": new, "credential_issued_at": datetime.now(UTC).isoformat()}
            )
        # Primer uso de la nueva credencial: la antigua deja de valer.
        if len(self.valid_credentials) > 1 and auth[7:].startswith("rotated-"):
            self.valid_credentials = {auth[7:]}
        if path == "/sensor/jobs/poll":
            jobs, self.jobs = self.jobs[: payload["max_jobs"]], self.jobs[payload["max_jobs"] :]
            return _json(200, {"jobs": jobs, "config": self.config})
        parts = path.split("/")
        job_id, action = parts[3], parts[4]
        if action == "start":
            self.started.append(job_id)
            return _json(200, {"job_id": job_id, "status": "running", "lease_expires_at": None})
        if job_id in self.finished_jobs:
            return _error(409, "sensor_job_finished")
        if action == "results":
            batch_id = payload["batch_id"]
            duplicate = batch_id in self.batches
            if not duplicate:
                self.batches[batch_id] = payload
                self.batch_jobs[batch_id] = job_id
            total = sum(
                len(b["observations"])
                for bid, b in self.batches.items()
                if self.batch_jobs[bid] == job_id
            )
            return _json(
                200,
                {
                    "job_id": job_id,
                    "batch_id": batch_id,
                    "accepted": len(payload["observations"]),
                    "duplicate": duplicate,
                    "observations_total": total,
                    "cancel_requested": job_id in self.cancel_requested,
                },
            )
        if action == "complete":
            duplicate = job_id in self.completes
            self.completes.setdefault(job_id, payload)
            return _json(
                200,
                {
                    "job_id": job_id,
                    "status": "succeeded",
                    "duplicate": duplicate,
                    "discovery_job_id": None,
                    "hosts_alive": 0,
                    "hosts_new": 0,
                    "open_ports": 0,
                },
            )
        return _error(404, "not_found")

    def observations_for(self, job_id: str) -> list[dict[str, Any]]:
        return [
            o
            for bid, b in self.batches.items()
            if self.batch_jobs[bid] == job_id
            for o in b["observations"]
        ]


class FakeClock:
    def __init__(self, start: float = 1_800_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class FakeTcp:
    def __init__(self, states: dict[tuple[str, int], str] | None = None) -> None:
        self.states = states or {}
        self.calls: list[tuple[str, int]] = []

    async def probe(self, address: str, port: int, timeout: float) -> str:
        self.calls.append((address, port))
        return self.states.get((address, port), "filtered")


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    path = tmp_path / "data"
    path.mkdir(mode=0o700)
    return path


@pytest.fixture
def config(data_dir: Path) -> LocalConfig:
    return LocalConfig(server_url=SERVER, data_dir=data_dir).validate()


@pytest.fixture
def server() -> FakeServer:
    return FakeServer()


def enroll_identity(config: LocalConfig, credential: str = CREDENTIAL) -> CredentialStore:
    store = CredentialStore(config.credential_file())
    store.save(
        SensorIdentity(
            sensor_id=SENSOR_ID,
            site_id=SITE_ID,
            site_name="Branch Office",
            server_url=SERVER,
            credential_issued_at=None,
            enrolled_at=datetime.now(UTC).isoformat(),
            credential=credential,
        )
    )
    return store


def make_runner(
    config: LocalConfig,
    server: FakeServer,
    clock: FakeClock | None = None,
    tcp: FakeTcp | None = None,
    threaded: bool = False,
    **prober_kwargs: Any,
) -> SensorRunner:
    enroll_identity(config)
    tcp = tcp or FakeTcp({("10.0.0.1", 22): "open", ("10.0.0.2", 80): "closed"})
    clock = clock or FakeClock()
    return SensorRunner(
        config,
        server,
        probers=lambda: ProberSet(tcp=tcp, **prober_kwargs),
        clock=clock,
        threaded_jobs=threaded,
    )
