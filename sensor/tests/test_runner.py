"""Runner contra el servidor falso: heartbeat, poll, jobs, spool, offline, revocación..."""

import asyncio
import ipaddress
import json
import logging
import sqlite3
import threading
import time
from typing import Any

import pytest

from sentra_sensor import snmp
from sentra_sensor.config import LocalConfig
from sentra_sensor.state import MODE_ACTIVE, MODE_DISABLED, MODE_REVOKED, load_state
from tests.conftest import (
    CREDENTIAL,
    OTHER_ID,
    FakeClock,
    FakeServer,
    FakeTcp,
    make_job,
    make_runner,
    server_config,
)
from tests.privacy import assert_private

SECRET_KEYS = ("credential", "token", "authorization", "env", "password", "key")


def test_heartbeat_payload_is_safe(config: LocalConfig, server: FakeServer) -> None:
    runner = make_runner(config, server)
    runner.tick()
    path, headers, body = server.requests[0]
    assert path == "/sensor/heartbeat"
    assert headers["Authorization"] == f"Bearer {CREDENTIAL}"
    assert set(body) == {
        "hostname",
        "platform",
        "sensor_version",
        "capabilities",
        "queue_depth",
        "spool_items",
        "spool_bytes",
        "uptime_seconds",
        "sent_at",
    }
    assert body["capabilities"] == [
        "network.discovery.basic",
        "network.discovery.advanced",
        "network.discovery.names",
        "network.dns",
        "network.tcp",
        "network.icmp",
        "network.arp",
        # Fase 6B: solo si el extra snmp está instalado en esta máquina.
        *snmp.capabilities(),
    ]
    dumped = json.dumps(body).lower()
    assert CREDENTIAL.lower() not in dumped
    assert not any(k in key.lower() for key in body for k in SECRET_KEYS)
    # La config del servidor queda persistida (status sin red).
    state = load_state(config.state_file())
    assert state.server_config is not None
    assert state.server_config["allowed_networks"] == ["10.0.0.0/24", "192.168.50.0/24"]


def test_no_busy_loop_when_idle(config: LocalConfig, server: FakeServer) -> None:
    clock = FakeClock()
    runner = make_runner(config, server, clock)
    wait = runner.tick()
    assert wait >= 29  # heartbeat cada 30 s, poll cada 60 s, nada en el spool
    count = len(server.requests)
    clock.advance(1)
    runner.tick()
    assert len(server.requests) == count  # nada vencido: ninguna petición


def test_poll_only_when_pending_or_interval(config: LocalConfig, server: FakeServer) -> None:
    clock = FakeClock()
    runner = make_runner(config, server, clock)
    runner.tick()
    assert server.paths() == ["/sensor/heartbeat", "/sensor/jobs/poll"]  # primer poll
    clock.advance(31)
    runner.tick()
    assert server.paths()[-1] == "/sensor/heartbeat"  # sin pending_jobs ni intervalo
    server.jobs.append(make_job())
    clock.advance(30)
    runner.tick()
    assert "/sensor/jobs/poll" in server.paths()[-6:]


def test_jobs_disabled_no_poll(config: LocalConfig, server: FakeServer) -> None:
    server.config = server_config(jobs_enabled=False)
    server.jobs.append(make_job())
    runner = make_runner(config, server)
    runner.tick()
    assert server.paths() == ["/sensor/heartbeat"]


def test_full_job_flow(config: LocalConfig, server: FakeServer) -> None:
    job = make_job()
    server.jobs.append(job)
    runner = make_runner(config, server)
    runner.tick()
    job_id = job["job_id"]
    assert server.started == [job_id]
    observed = {o["address"] for o in server.observations_for(job_id)}
    assert observed == {"10.0.0.1", "10.0.0.2"}
    complete = server.completes[job_id]
    assert complete["outcome"] == "completed"
    assert complete["hosts_scanned"] == 6 and complete["hosts_checked"] == 6
    assert complete["batches_sent"] == 1 and complete["attempt"] == 1
    assert runner.spool.stats().items == 0
    # complete después de los lotes (FIFO por job).
    paths = server.paths()
    assert paths.index(f"/sensor/jobs/{job_id}/complete") > paths.index(
        f"/sensor/jobs/{job_id}/results"
    )
    assert runner.state.last_successful_job_at is not None


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"job_type": "run_script"}, "unknown_job_type"),
        ({"parameters": {"target": "8.8.8.0/24"}}, "target_out_of_scope"),
        ({"site_id": OTHER_ID}, "wrong_site"),
        ({"parameters": {"target": "0.0.0.0/0"}}, "target_invalid"),
    ],
)
def test_rejected_job_is_not_executed_and_reported_failed(
    config: LocalConfig, server: FakeServer, overrides: dict[str, Any], reason: str
) -> None:
    job = make_job(**overrides)
    server.jobs.append(job)
    tcp = FakeTcp()
    runner = make_runner(config, server, tcp=tcp)
    runner.tick()
    assert tcp.calls == []  # nada sondeado
    assert server.started == []  # ni siquiera se marcó como iniciado
    complete = server.completes[job["job_id"]]
    assert complete["outcome"] == "failed"
    assert complete["errors"] == [f"job_rejected:{reason}"]


def test_payload_limits_respected(config: LocalConfig, server: FakeServer) -> None:
    server.config = server_config(max_observations_per_batch=7, max_batch_bytes=2048)
    states = {(f"10.0.0.{i}", 22): "open" for i in range(1, 255)}
    job = make_job(parameters={"target": "10.0.0.0/24", "ports": [22]})
    server.jobs.append(job)
    runner = make_runner(config, server, tcp=FakeTcp(states))
    runner.tick()
    batches = [b for b in server.batches.values()]
    assert len(server.observations_for(job["job_id"])) == 254
    assert all(len(b["observations"]) <= 7 for b in batches)
    for path, _headers, body in server.requests:
        if path.endswith("/results"):
            assert len(json.dumps(body, separators=(",", ":")).encode()) <= 2048
    assert server.max_body_seen <= 2048 or not any(p.endswith("/results") for p in server.paths())
    assert server.completes[job["job_id"]]["batches_sent"] == len(batches)


def test_offline_accumulates_and_delivers_once(config: LocalConfig, server: FakeServer) -> None:
    clock = FakeClock()
    jobs = [make_job(), make_job()]
    server.jobs.append(jobs[0])
    runner = make_runner(config, server, clock)
    # El servidor empieza a fallar justo después de entregar el job: start OK, envíos no.
    server.fail_next.append(("/results", 503, "unavailable"))
    runner.tick()
    assert runner.spool.stats().items == 2  # lote + complete esperando
    server.down = True
    for _ in range(50):  # horas de caída simuladas
        clock.advance(600)
        runner.tick()
    assert runner.spool.stats().items == 2
    assert server.completes == {}
    server.down = False
    server.jobs.append(jobs[1])
    clock.advance(600)
    runner.tick()
    clock.advance(1)
    runner.tick()
    assert runner.spool.stats().items == 0
    for job in jobs:
        assert server.completes[job["job_id"]]["outcome"] == "completed"
        assert len(server.observations_for(job["job_id"])) == 2  # sin duplicados


def test_retry_reuses_same_batch_id(config: LocalConfig, server: FakeServer) -> None:
    clock = FakeClock()
    job = make_job()
    server.jobs.append(job)
    # El servidor guarda el lote pero la respuesta se pierde: el sensor reintenta.
    server.lose_response_for.add("/results")
    runner = make_runner(config, server, clock)
    runner.tick()
    sent = [b["batch_id"] for p, _h, b in server.requests if p.endswith("/results")]
    assert len(sent) == 1
    for _ in range(5):
        clock.advance(400)
        runner.tick()
    sent = [b["batch_id"] for p, _h, b in server.requests if p.endswith("/results")]
    assert len(sent) == 2 and sent[0] == sent[1]  # mismo batch_id: idempotente
    assert len(server.batches) == 1
    assert len(server.observations_for(job["job_id"])) == 2
    assert job["job_id"] in server.completes


def test_retry_backoff_and_rate_limit(config: LocalConfig, server: FakeServer) -> None:
    clock = FakeClock()
    job = make_job()
    server.jobs.append(job)
    server.fail_next.append(("/results", 429, "rate_limited"))
    runner = make_runner(config, server, clock)
    runner.tick()
    item = runner.spool.heads()[0]
    assert item.attempts == 1 and item.next_attempt_at >= clock.now + 1  # Retry-After
    count = len(server.requests)
    runner.tick()  # todavía no vence: no reintenta
    assert len(server.requests) == count
    clock.advance(10)
    runner.tick()
    assert runner.spool.stats().items == 0


def test_finished_job_items_are_discarded(
    config: LocalConfig, server: FakeServer, caplog: pytest.LogCaptureFixture
) -> None:
    job = make_job()
    server.jobs.append(job)
    server.finished_jobs.add(job["job_id"])
    runner = make_runner(config, server)
    with caplog.at_level(logging.WARNING):
        runner.tick()
    assert runner.spool.stats().items == 0
    assert runner.spool.stats().dropped_total == 2
    reasons = [getattr(r, "reason", None) for r in caplog.records]
    assert reasons.count("sensor_job_finished") == 2


def test_revoked_stops_work_and_keeps_spool(
    config: LocalConfig, server: FakeServer, caplog: pytest.LogCaptureFixture
) -> None:
    clock = FakeClock()
    runner = make_runner(config, server, clock)
    runner.spool.enqueue(
        make_job()["job_id"], "results", {"batch_id": "x", "attempt": 1, "observations": []}, "x"
    )
    server.revoked = True
    server.jobs.append(make_job())
    with caplog.at_level(logging.ERROR):
        runner.tick()
    assert runner.mode == MODE_REVOKED
    assert "REVOKED" in caplog.text and "enroll" in caplog.text
    assert CREDENTIAL not in caplog.text
    for _ in range(3):
        clock.advance(10_000)
        runner.tick()
    assert all(p == "/sensor/heartbeat" for p in server.paths())
    assert runner.spool.stats().items == 1  # nada descartado
    assert load_state(config.state_file()).mode == MODE_REVOKED


def test_unauthorized_does_not_discard(config: LocalConfig, server: FakeServer) -> None:
    clock = FakeClock()
    runner = make_runner(config, server, clock)
    runner.tick()
    runner.spool.enqueue(make_job()["job_id"], "complete", {"attempt": 1})
    server.valid_credentials = {"something-else"}
    clock.advance(31)
    runner.tick()
    assert runner.spool.stats().items == 1


def test_disabled_only_heartbeats(config: LocalConfig, server: FakeServer) -> None:
    clock = FakeClock()
    server.status = "disabled"
    server.jobs.append(make_job())
    runner = make_runner(config, server, clock)
    runner.spool.enqueue(make_job()["job_id"], "complete", {"attempt": 1})
    for _ in range(3):
        runner.tick()
        clock.advance(61)
    assert runner.mode == MODE_DISABLED
    assert set(server.paths()) == {"/sensor/heartbeat"}
    server.status = "active"
    runner.tick()
    assert runner.mode == MODE_ACTIVE
    assert "/sensor/jobs/poll" in server.paths()


def test_credential_rotation(config: LocalConfig, server: FakeServer) -> None:
    clock = FakeClock()
    runner = make_runner(config, server, clock)
    server.rotate = True
    runner.tick()
    assert server.rotations == 1
    stored = runner.store.load().credential
    assert stored.startswith("rotated-credential-0")
    assert_private(runner.store.path)  # la credencial rotada también es privada
    clock.advance(31)
    runner.tick()
    assert server.bearer_tokens()[-1] == f"Bearer {stored}"
    assert server.valid_credentials == {stored}  # la antigua ya no vale
    assert CREDENTIAL not in runner.store.path.read_text()


def test_rotation_save_failure_keeps_old_credential(
    config: LocalConfig, server: FakeServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = make_runner(config, server)
    server.rotate = True

    def fail(_identity: object) -> None:
        raise OSError("read-only filesystem")

    monkeypatch.setattr(runner.store, "save", fail)
    runner.tick()
    assert runner.identity.credential == CREDENTIAL


def test_cancel_via_heartbeat(config: LocalConfig, server: FakeServer) -> None:
    clock = FakeClock()

    class HangingTcp:
        def __init__(self) -> None:
            self.started = threading.Event()

        async def probe(self, address: str, port: int, timeout: float) -> str:
            if address == "10.0.0.1":
                return "open"
            self.started.set()
            await asyncio.sleep(30)
            return "filtered"

    tcp = HangingTcp()
    job = make_job()
    server.jobs.append(job)
    runner = make_runner(config, server, clock, tcp=tcp, threaded=True)  # type: ignore[arg-type]
    runner.tick()
    assert tcp.started.wait(5)
    time.sleep(0.05)
    server.cancel_ids = [job["job_id"]]
    clock.advance(31)
    runner.tick()
    deadline = time.monotonic() + 5
    while job["job_id"] not in server.completes and time.monotonic() < deadline:
        time.sleep(0.02)
        runner.tick()
    complete = server.completes[job["job_id"]]
    assert complete["outcome"] == "cancelled"
    assert [o["address"] for o in server.observations_for(job["job_id"])] == ["10.0.0.1"]


def test_cancel_via_upload_response(config: LocalConfig, server: FakeServer) -> None:
    clock = FakeClock()

    class SecondChunkHangs:
        async def probe(self, address: str, port: int, timeout: float) -> str:
            if int(ipaddress.ip_address(address)) - int(ipaddress.ip_address("10.0.0.0")) > 64:
                await asyncio.sleep(30)
            return "open" if address == "10.0.0.3" else "filtered"

    job = make_job(parameters={"target": "10.0.0.0/25", "ports": [22]})
    server.jobs.append(job)
    server.cancel_requested.add(job["job_id"])
    runner = make_runner(config, server, clock, tcp=SecondChunkHangs(), threaded=True)  # type: ignore[arg-type]
    runner.tick()
    deadline = time.monotonic() + 5
    while not server.batches and time.monotonic() < deadline:
        time.sleep(0.02)
        runner.tick()
    while job["job_id"] not in server.completes and time.monotonic() < deadline + 5:
        time.sleep(0.02)
        runner.tick()
    assert server.completes[job["job_id"]]["outcome"] == "cancelled"
    assert server.completes[job["job_id"]]["hosts_checked"] < 126


def test_reenroll_while_revoked_is_picked_up(config: LocalConfig, server: FakeServer) -> None:
    clock = FakeClock()
    runner = make_runner(config, server, clock)
    server.revoked = True
    runner.tick()
    assert runner.mode == MODE_REVOKED
    server.revoked = False
    server.valid_credentials = {"brand-new-credential-after-reenroll"}
    from tests.conftest import enroll_identity

    time.sleep(0.01)
    enroll_identity(config, "brand-new-credential-after-reenroll")
    import os

    os.utime(runner.store.path, (time.time() + 5, time.time() + 5))
    runner.tick()
    assert runner.mode == MODE_ACTIVE


def test_run_and_stop_thread(config: LocalConfig, server: FakeServer) -> None:
    runner = make_runner(config, server, clock=None)
    runner._clock = time.time  # reloj real para el bucle
    thread = threading.Thread(target=runner.run)
    thread.start()
    time.sleep(0.2)
    runner.stop()
    thread.join(5)
    assert not thread.is_alive()
    assert "/sensor/heartbeat" in server.paths()


def test_runner_closes_its_spool_if_startup_fails(
    config: LocalConfig, server: FakeServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Fix 2: si el arranque falla después de abrir el spool, la conexión SQLite se cierra
    # en el acto (antes quedaba viva hasta el GC).
    from sentra_sensor.spool import Spool

    opened: list[Any] = []
    real_spool = Spool

    def recording_spool(*args: Any, **kwargs: Any) -> Any:
        spool = real_spool(*args, **kwargs)
        opened.append(spool)
        return spool

    def broken_state(path: Any) -> Any:
        raise OSError("state unreadable")

    monkeypatch.setattr("sentra_sensor.runner.Spool", recording_spool)
    monkeypatch.setattr("sentra_sensor.runner.load_state", broken_state)
    with pytest.raises(OSError, match="state unreadable"):
        make_runner(config, server)
    (spool,) = opened
    with pytest.raises(sqlite3.ProgrammingError):
        spool._db.execute("SELECT 1")


def test_shutdown_closes_the_spool_even_if_the_last_flush_fails(
    config: LocalConfig, server: FakeServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = make_runner(config, server)
    runner._server_reachable = True

    def failing_flush() -> int:
        raise RuntimeError("network down")

    monkeypatch.setattr(runner, "flush", failing_flush)
    with pytest.raises(RuntimeError, match="network down"):
        runner._shutdown()
    with pytest.raises(sqlite3.ProgrammingError):
        runner.spool._db.execute("SELECT 1")
    runner.close()  # idempotente: el teardown del test vuelve a cerrarlo
