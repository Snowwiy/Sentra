"""Fase 7D.2 (H06): cuotas de ingesta por identidad de agente autenticada.

Cubren los dos almacenes (memoria y PostgreSQL de sentra_test), la puerta HTTP de las rutas
legacy y los requisitos del informe: un agente ruidoso recibe 429 con Retry-After mientras
otro sano sigue transmitiendo, un 429 no escribe nada, un reenvío posterior se procesa sin
duplicados, sin credencial no se gasta el cupo de nadie y varios workers comparten el cupo.
"""

import threading
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings, get_settings
from app.core.ingest_quota import (
    BucketSpec,
    Charge,
    ConcurrencyGate,
    DatabaseBucketStore,
    IngestQuota,
    MemoryBucketStore,
    QuotaPolicy,
)
from app.core.metrics import REGISTRY
from app.db.session import get_db
from app.main import create_app
from tests.conftest import TEST_ENROLLMENT_KEY, AgentClient, agent_payload, authenticate

API = "/api/v1"


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def policy(**overrides: Any) -> QuotaPolicy:
    """Política de prueba: todo sin límite salvo lo que pida cada test."""
    base: dict[str, Any] = {
        "enabled": True,
        "agent_requests": None,
        "agent_events": None,
        "agent_bytes": None,
        "global_requests": None,
        "global_events": None,
        "global_bytes": None,
        "agent_max_concurrent": 100,
        "global_max_concurrent": 100,
    }
    base.update(overrides)
    return QuotaPolicy(**base)


def spec(per_minute: float, capacity: float) -> BucketSpec:
    return BucketSpec(rate=per_minute / 60.0, capacity=capacity)


AppFactory = Callable[..., AgentClient]


@pytest.fixture
def make_client(client: TestClient, engine: Engine) -> Iterator[AppFactory]:
    """Clientes de agente sobre apps propias (ajustes o cuotas de prueba).

    Depende de `client` solo para heredar su limpieza (TRUNCATE al terminar el test).
    """
    opened: list[AgentClient] = []
    factory = sessionmaker(bind=engine, expire_on_commit=False)

    def build(quota: IngestQuota | None = None, **settings: Any) -> AgentClient:
        app = create_app(get_settings().model_copy(update=settings))
        if quota is not None:
            app.state.ingest_quota = quota

        def override_get_db() -> Iterator[Session]:
            with factory() as session:
                yield session

        app.dependency_overrides[get_db] = override_get_db
        test_client = AgentClient(app)
        test_client.__enter__()
        test_client.tokens = {}
        opened.append(test_client)
        return test_client

    yield build
    for test_client in opened:
        test_client.__exit__(None, None, None)


def register(test_client: TestClient) -> str:
    payload = agent_payload()
    response = test_client.post(f"{API}/agents/register", json=payload)
    assert response.status_code == 201, response.text
    return str(payload["agent_id"])


def telemetry(agent_id: str) -> dict[str, Any]:
    return {
        "agent_id": agent_id,
        "sample_id": str(uuid4()),
        "timestamp": datetime.now(UTC).isoformat(),
        "cpu_percent": 10.0,
        "ram_percent": 20.0,
        "disk_percent": 30.0,
        "uptime_seconds": 100,
    }


def event(record_id: int) -> dict[str, Any]:
    return {
        "source": "windows_eventlog",
        "channel": "System",
        "record_id": record_id,
        "event_code": 7034,
        "provider": "Service Control Manager",
        "level": "error",
        "message": f"Service terminated unexpectedly ({record_id})",
        "occurred_at": (datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
    }


def stored_events(engine: Engine) -> int:
    with engine.connect() as conn:
        return int(conn.execute(text("SELECT count(*) FROM system_events")).scalar_one())


# --- Almacén en memoria -----------------------------------------------------------------


def test_memory_bucket_allows_burst_then_rejects_with_wait_and_refills() -> None:
    clock = FakeClock()
    store = MemoryBucketStore(clock)
    charge = Charge("agent:x:telemetry", spec(60, 3), 1, "agent_requests")

    assert [store.consume([charge]).allowed for _ in range(3)] == [True, True, True]
    rejected = store.consume([charge])
    assert rejected.reason == "agent_requests"
    # Tasa 1/s: falta un token entero.
    assert rejected.wait == pytest.approx(1.0)

    clock.now += 1.0
    assert store.consume([charge]).allowed
    assert not store.consume([charge]).allowed


def test_memory_rejection_spends_nothing_from_any_bucket() -> None:
    store = MemoryBucketStore(FakeClock())
    requests = Charge("agent:x:events", spec(60, 10), 1, "agent_requests")
    events = Charge("agent:x:events-items", spec(60, 5), 4, "agent_events")

    assert store.consume([requests, events]).allowed
    # Quedan 1 evento y 9 peticiones: el segundo lote no cabe y no gasta peticiones.
    assert store.consume([requests, events]).reason == "agent_events"
    small = Charge("agent:x:events-items", spec(60, 5), 1, "agent_events")
    assert store.consume([requests, small]).allowed


def test_a_request_bigger_than_the_burst_is_charged_the_full_capacity() -> None:
    clock = FakeClock()
    store = MemoryBucketStore(clock)
    huge = Charge("agent:x:bytes", spec(60, 100), 1_000, "agent_bytes")

    # Con el cubo lleno pasa (si no, nunca pasaría) y lo deja vacío.
    assert store.consume([huge]).allowed
    rejected = store.consume([huge])
    assert rejected.reason == "agent_bytes"
    assert rejected.wait == pytest.approx(100.0)


def test_concurrency_gate_limits_per_agent_and_total() -> None:
    gate = ConcurrencyGate(per_agent=1, total=2)
    a, b, c = uuid4(), uuid4(), uuid4()

    assert gate.enter_agent(a)
    assert not gate.enter_agent(a)
    assert gate.enter_agent(b)
    gate.leave_agent(a)
    assert gate.enter_agent(a)
    assert gate.enter_global() and gate.enter_global()
    assert not gate.enter_global()
    gate.leave_global()
    assert gate.enter_global()
    assert gate.enter_agent(c)


def test_control_routes_skip_data_and_global_buckets() -> None:
    quota_policy = policy(
        agent_requests=spec(60, 10),
        agent_events=spec(60, 10),
        agent_bytes=spec(60, 10_000),
        global_requests=spec(60, 10),
        global_events=spec(60, 10),
        global_bytes=spec(60, 10_000),
    )
    agent = uuid4()

    control = quota_policy.charges(agent, "control", events=0, body_bytes=500)
    data = quota_policy.charges(agent, "events", events=3, body_bytes=500)

    assert [c.key for c in control] == [f"agent:{agent}:control"]
    assert sorted(c.reason for c in data) == [
        "agent_bytes",
        "agent_events",
        "agent_requests",
        "global_bytes",
        "global_events",
        "global_requests",
    ]
    # Sin eventos no se consulta el cubo de eventos.
    assert "agent_events" not in {
        c.reason for c in quota_policy.charges(agent, "telemetry", events=0, body_bytes=10)
    }


# --- Almacén en PostgreSQL (sentra_test) ------------------------------------------------


@pytest.fixture
def db_store(engine: Engine) -> Iterator[DatabaseBucketStore]:
    with engine.begin() as conn:
        conn.execute(text("TRUNCATE ingest_quota_buckets"))
    yield DatabaseBucketStore(lambda: engine)
    with engine.begin() as conn:
        conn.execute(text("TRUNCATE ingest_quota_buckets"))


def test_database_bucket_allows_burst_then_rejects_and_records_the_rejection(
    db_store: DatabaseBucketStore,
) -> None:
    agent = uuid4()
    charge = Charge(f"agent:{agent}:telemetry", spec(1, 3), 1, "agent_requests")

    assert [db_store.consume([charge]).allowed for _ in range(3)] == [True, True, True]
    rejected = db_store.consume([charge])

    assert rejected.reason == "agent_requests"
    # Tasa 1/min: hasta el próximo token faltan casi 60 s.
    assert 50 < rejected.wait <= 60
    state = db_store.throttled([agent])[agent]
    assert state.rejected_total == 1
    assert state.last_rejected_at is not None


def test_database_rejection_is_atomic_across_buckets(db_store: DatabaseBucketStore) -> None:
    requests = Charge("agent:a:events", spec(1, 10), 1, "agent_requests")
    events = Charge("global:events", spec(1, 5), 4, "global_events")

    assert db_store.consume([requests, events]).allowed
    assert db_store.consume([requests, events]).reason == "global_events"
    with db_store._engine().connect() as conn:
        tokens = {
            row[0]: row[1]
            for row in conn.execute(text("SELECT bucket_key, tokens FROM ingest_quota_buckets"))
        }
    # El rechazo no gastó la petición del agente.
    assert tokens["agent:a:events"] == pytest.approx(9.0, abs=0.01)
    assert tokens["global:events"] == pytest.approx(1.0, abs=0.01)


def test_database_buckets_never_overspend_under_concurrency(
    db_store: DatabaseBucketStore,
) -> None:
    """Varios hilos (como varios workers) gastando del mismo cubo a la vez: nunca más que su
    capacidad. El bloqueo FOR UPDATE serializa el cálculo de cada gasto."""
    charge = Charge("global:requests", spec(1, 10), 1, "global_requests")
    results: list[bool] = []
    lock = threading.Lock()
    barrier = threading.Barrier(20)

    def worker() -> None:
        barrier.wait()
        allowed = db_store.consume([charge]).allowed
        with lock:
            results.append(allowed)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert results.count(True) == 10
    assert results.count(False) == 10


def test_database_purge_drops_only_idle_buckets(db_store: DatabaseBucketStore) -> None:
    fresh = Charge("agent:fresh:telemetry", spec(1, 3), 1, "agent_requests")
    db_store.consume([fresh])
    with db_store._engine().begin() as conn:
        conn.execute(
            text(
                "INSERT INTO ingest_quota_buckets (bucket_key, tokens, updated_at)"
                " VALUES ('agent:old:telemetry', 3, now() - interval '2 days')"
            )
        )
    db_store._last_purge = None
    db_store._maybe_purge()

    with db_store._engine().connect() as conn:
        keys = set(conn.execute(text("SELECT bucket_key FROM ingest_quota_buckets")).scalars())
    assert keys == {"agent:fresh:telemetry"}


# --- Rutas HTTP ---------------------------------------------------------------------------


def test_noisy_agent_gets_429_while_a_healthy_agent_keeps_sending(
    make_client: AppFactory,
) -> None:
    api = make_client(agent_quota_requests_per_minute=5, agent_quota_burst_minutes=1.0)
    noisy, healthy = register(api), register(api)

    statuses = [api.post(f"{API}/telemetry", json=telemetry(noisy)).status_code for _ in range(6)]

    assert statuses == [201] * 5 + [429]
    limited = api.post(f"{API}/telemetry", json=telemetry(noisy))
    assert limited.status_code == 429
    assert int(limited.headers["Retry-After"]) >= 1
    assert limited.json()["error"]["code"] == "rate_limited"
    assert limited.json()["error"]["details"] == [{"reason": "agent_requests"}]
    for _ in range(3):
        assert api.post(f"{API}/telemetry", json=telemetry(healthy)).status_code == 201
    # Clase de ruta propia: el heartbeat del agente limitado sigue entrando (no queda offline).
    beat = api.post(f"{API}/agents/heartbeat", json={"agent_id": noisy})
    assert beat.status_code == 200


def test_rejected_batch_writes_nothing_and_its_resend_is_stored_once(
    make_client: AppFactory, engine: Engine
) -> None:
    clock = FakeClock()
    quota = IngestQuota(policy(agent_events=spec(60, 10)), MemoryBucketStore(clock))
    api = make_client(quota)
    agent = register(api)
    first = [event(i) for i in range(1, 9)]
    second = [event(i) for i in range(9, 13)]

    assert api.post(f"{API}/events", json={"agent_id": agent, "events": first}).status_code == 201
    refused = api.post(f"{API}/events", json={"agent_id": agent, "events": second})

    assert refused.status_code == 429
    assert refused.json()["error"]["details"] == [{"reason": "agent_events"}]
    # Faltan 2 eventos a 1/s: Retry-After cubre la espera completa.
    assert int(refused.headers["Retry-After"]) >= 2
    assert stored_events(engine) == 8

    # El agente reintenta pasado el Retry-After: entra y no hay duplicados.
    clock.now += 60
    accepted = api.post(f"{API}/events", json={"agent_id": agent, "events": second})
    assert accepted.status_code == 201
    assert stored_events(engine) == 12
    clock.now += 60
    again = api.post(f"{API}/events", json={"agent_id": agent, "events": second})
    assert again.status_code == 201
    assert stored_events(engine) == 12


def test_requests_without_valid_credential_spend_nobody_quota(make_client: AppFactory) -> None:
    api = make_client(agent_quota_requests_per_minute=2, agent_quota_burst_minutes=1.0)
    victim = register(api)

    for _ in range(10):
        forged = api.post(
            f"{API}/telemetry",
            json=telemetry(victim),
            headers={"Authorization": "Bearer not-the-real-token"},
        )
        assert forged.status_code == 401

    assert api.post(f"{API}/telemetry", json=telemetry(victim)).status_code == 201
    assert api.post(f"{API}/telemetry", json=telemetry(victim)).status_code == 201


def test_global_limit_protects_the_backend_across_agents(make_client: AppFactory) -> None:
    quota = IngestQuota(policy(global_requests=spec(1, 3)), MemoryBucketStore(FakeClock()))
    api = make_client(quota)
    a, b = register(api), register(api)

    assert api.post(f"{API}/telemetry", json=telemetry(a)).status_code == 201
    assert api.post(f"{API}/telemetry", json=telemetry(a)).status_code == 201
    assert api.post(f"{API}/telemetry", json=telemetry(b)).status_code == 201
    refused = api.post(f"{API}/telemetry", json=telemetry(b))

    assert refused.status_code == 429
    assert refused.json()["error"]["details"] == [{"reason": "global_requests"}]
    # El heartbeat no cuenta contra el global.
    assert api.post(f"{API}/agents/heartbeat", json={"agent_id": b}).status_code == 200


def test_byte_budget_counts_the_received_body(make_client: AppFactory) -> None:
    body = telemetry(str(uuid4()))
    size = len(TestClient(create_app()).build_request("POST", "/", json=body).content)
    quota = IngestQuota(policy(agent_bytes=spec(1, size * 1.5)), MemoryBucketStore(FakeClock()))
    api = make_client(quota)
    agent = register(api)

    # El cubo cabe un cuerpo y medio: el primero entra, el segundo ya no.
    assert api.post(f"{API}/telemetry", json=telemetry(agent)).status_code == 201
    refused = api.post(f"{API}/telemetry", json=telemetry(agent))
    assert refused.status_code == 429
    assert refused.json()["error"]["details"] == [{"reason": "agent_bytes"}]


def test_quota_disabled_never_limits(make_client: AppFactory) -> None:
    api = make_client(
        agent_quota_enabled=False,
        agent_quota_requests_per_minute=1,
        agent_quota_burst_minutes=1.0,
    )
    agent = register(api)

    statuses = {api.post(f"{API}/telemetry", json=telemetry(agent)).status_code for _ in range(5)}
    assert statuses == {201}


def test_agent_list_and_metrics_show_throttling_without_secrets(
    make_client: AppFactory, engine: Engine
) -> None:
    api = make_client(agent_quota_requests_per_minute=1, agent_quota_burst_minutes=1.0)
    noisy, healthy = register(api), register(api)
    api.post(f"{API}/telemetry", json=telemetry(noisy))
    api.post(f"{API}/telemetry", json=telemetry(healthy))
    before = REGISTRY.render()
    assert api.post(f"{API}/telemetry", json=telemetry(noisy)).status_code == 429

    authenticate(api, engine, "viewer")
    listing = api.get(f"{API}/agents").json()
    by_agent = {item["agent_id"]: item for item in listing["items"]}

    assert by_agent[noisy]["ingest_rejections"] == 1
    assert by_agent[noisy]["ingest_throttled_at"] is not None
    assert by_agent[healthy]["ingest_rejections"] == 0
    assert by_agent[healthy]["ingest_throttled_at"] is None
    assert listing["summary"]["throttled"] == 1
    after = "\n".join(REGISTRY.render())
    assert (
        'sentra_ingest_quota_rejections_total{route="telemetry",reason="agent_requests"}' in after
    )
    assert after != "\n".join(before)
    # Ni tokens ni hashes en la métrica ni en el listado.
    assert api.tokens[noisy] not in after
    assert api.tokens[noisy] not in str(listing)


def test_429_does_not_revoke_or_rotate_the_agent_credential(make_client: AppFactory) -> None:
    api = make_client(agent_quota_requests_per_minute=1, agent_quota_burst_minutes=1.0)
    agent = register(api)
    token = api.tokens[agent]
    api.post(f"{API}/telemetry", json=telemetry(agent))
    assert api.post(f"{API}/telemetry", json=telemetry(agent)).status_code == 429

    # La misma credencial sigue valiendo y no hay rotación pendiente.
    beat = api.post(
        f"{API}/agents/heartbeat",
        json={"agent_id": agent},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert beat.status_code == 200


def test_two_workers_share_the_database_quota(make_client: AppFactory, engine: Engine) -> None:
    """Dos apps con su propio almacén PostgreSQL = dos workers: el cupo es uno solo.

    Equivale a RATE_LIMIT_BACKEND=database, pero sobre sentra_test (el resto de limitadores de
    la app de prueba siguen en memoria y no tocan la base de desarrollo).
    """
    with engine.begin() as conn:
        conn.execute(text("TRUNCATE ingest_quota_buckets"))
    settings = get_settings().model_copy(
        update={"agent_quota_requests_per_minute": 4, "agent_quota_burst_minutes": 1.0}
    )

    def worker() -> AgentClient:
        quota = IngestQuota(
            QuotaPolicy.from_settings(settings), DatabaseBucketStore(lambda: engine)
        )
        return make_client(quota)

    worker_a, worker_b = worker(), worker()
    agent = register(worker_a)
    worker_b.tokens = worker_a.tokens

    statuses = [
        (worker_a if i % 2 else worker_b)
        .post(f"{API}/telemetry", json=telemetry(agent))
        .status_code
        for i in range(6)
    ]

    assert statuses == [201] * 4 + [429, 429]


def test_activity_route_spends_the_shared_event_budget(make_client: AppFactory) -> None:
    quota = IngestQuota(policy(agent_events=spec(1, 3)), MemoryBucketStore(FakeClock()))
    api = make_client(quota)
    agent = register(api)
    batch = {
        "agent_id": agent,
        "batch_id": str(uuid4()),
        "boot_id": "boot-1",
        "events": [{"kind": "process_start"} for _ in range(2)],
    }

    # Un lote de 2 eventos cabe en el cubo de 3; el segundo ya no.
    assert api.post(f"{API}/agents/activity", json=batch).status_code == 200
    refused = api.post(f"{API}/agents/activity", json={**batch, "batch_id": str(uuid4())})

    assert refused.status_code == 429
    assert refused.json()["error"]["details"] == [{"reason": "agent_events"}]


# --- Configuración ------------------------------------------------------------------------


def _settings(**values: Any) -> Settings:
    return Settings(_env_file=None, database_url="postgresql+psycopg://u:p@h/db", **values)


def test_settings_require_an_event_burst_that_covers_an_agent_backlog() -> None:
    with pytest.raises(ValidationError, match="2500 events"):
        _settings(agent_quota_events_per_minute=600, agent_quota_burst_minutes=3)
    assert _settings(agent_quota_events_per_minute=0).agent_quota_events_per_minute == 0


def test_settings_reject_a_byte_budget_below_the_request_size() -> None:
    with pytest.raises(ValidationError, match="AGENT_QUOTA_BYTES_PER_MINUTE"):
        _settings(agent_quota_bytes_per_minute=1024)


def test_default_policy_leaves_ample_room_for_a_healthy_agent() -> None:
    """Los valores por defecto frente al tráfico de un agente sano (intervalos por defecto):
    heartbeat y telemetría cada 30 s, eventos y procesos cada 60 s, inventario cada 15 min."""
    defaults = QuotaPolicy.from_settings(_settings())
    assert defaults.enabled
    assert defaults.agent_requests is not None and defaults.agent_events is not None
    # 2 peticiones por minuto y clase frente a 120.
    assert defaults.agent_requests.rate * 60 >= 50 * 2
    # El mayor atraso de un ciclo (8 canales x 200 eventos) cabe en la ráfaga.
    assert defaults.agent_events.capacity >= 1_600
    _ = TEST_ENROLLMENT_KEY  # la app de prueba usa la clave de conftest
