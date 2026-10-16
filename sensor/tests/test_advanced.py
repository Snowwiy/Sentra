"""Fase 6A: jobs discovery_advanced (esquema, topes, gating, DNS, reintentos, RTT, runner).

Nada sale a la red: probers falsos y servidor falso en memoria.
"""

import ipaddress
import threading
from datetime import UTC, datetime
from typing import Any

import pytest

from sentra_sensor import CAPABILITIES, __version__, snmp
from sentra_sensor.config import LocalConfig
from sentra_sensor.jobs import (
    JOB_TYPE_DISCOVERY_ADVANCED,
    DiscoveryParameters,
    JobRejectedError,
    validate_job,
)
from sentra_sensor.protocol import ServerConfig
from sentra_sensor.scanner import Observation, Scanner
from tests.conftest import (
    SENSOR_ID,
    SITE_ID,
    FakeServer,
    FakeTcp,
    make_job,
    make_runner,
    server_config,
)

NOW = datetime.now(UTC)
# Topes avanzados tal como los envía un servidor 6A.
ADVANCED_CAPS = {
    "advanced_max_timeout_ms": 5000,
    "max_dns_timeout_ms": 5000,
    "max_tcp_retries": 2,
    "max_dns_queries": 4096,
    "advanced_max_ports": 256,
    "max_deadline_seconds": 1800,
}
CONFIG = ServerConfig.parse(server_config(**ADVANCED_CAPS))


def advanced_params(**overrides: Any) -> dict[str, Any]:
    params: dict[str, Any] = {
        "schema_version": 1,
        "profile": "standard",
        "target": "10.0.0.0/29",
        "ports": [22, 80, 443],
        "timeout_ms": 800,
        "dns_timeout_ms": 1500,
        "concurrency": 16,
        "max_probes_per_second": 500,
        "tcp_retries": 1,
        "icmp": False,
        "arp": False,
        "reverse_dns": False,
        "forward_dns": False,
        "max_dns_queries": 100,
        "deadline_seconds": 600,
        "max_hosts": 256,
    }
    params.update(overrides)
    return params


def advanced_job(**overrides: Any) -> dict[str, Any]:
    job = make_job(NOW, job_type=JOB_TYPE_DISCOVERY_ADVANCED)
    job["parameters"] = advanced_params(**overrides)
    return job


def validate(job: dict[str, Any], config: ServerConfig = CONFIG) -> Any:
    return validate_job(job, sensor_id=SENSOR_ID, site_id=SITE_ID, config=config, now=NOW)


def rejected(job: dict[str, Any], config: ServerConfig = CONFIG) -> str:
    with pytest.raises(JobRejectedError) as info:
        validate(job, config)
    return info.value.code


# --- esquema y capability ------------------------------------------------------------------


def test_capability_and_version_declared() -> None:
    assert "network.discovery.advanced" in CAPABILITIES
    assert "network.discovery.basic" in CAPABILITIES  # compatibilidad con 5F
    assert __version__ == "0.3.0"
    # Nada que el sensor no implemente: las snmp.* solo con el extra snmp instalado (6B).
    assert not any(c.startswith(("network.snmp", "network.lldp")) for c in CAPABILITIES)
    assert set(c for c in CAPABILITIES if c.startswith("snmp.")) == set(snmp.capabilities())


def test_valid_advanced_job() -> None:
    job = validate(advanced_job(reverse_dns=True, forward_dns=True))
    assert job.job_type == "discovery_advanced"
    p = job.parameters
    assert p.profile == "standard" and p.tcp_retries == 1 and p.forward_dns
    assert p.dns_timeout_ms == 1500 and p.max_dns_queries == 100


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"schema_version": 2}, "schema_unsupported"),
        ({"schema_version": True}, "schema_unsupported"),
        ({"profile": "pentest"}, "invalid_schema"),
        ({"timeout_ms": 6000}, "invalid_schema"),
        ({"dns_timeout_ms": 9000}, "invalid_schema"),
        ({"tcp_retries": 3}, "invalid_schema"),
        ({"max_dns_queries": 5000}, "invalid_schema"),
        ({"deadline_seconds": 3600}, "invalid_schema"),
        ({"concurrency": 65}, "invalid_schema"),
        ({"max_hosts": 4}, "target_too_large"),
        ({"forward_dns": True, "reverse_dns": False}, "invalid_schema"),
        ({"target": "8.8.8.0/24"}, "target_out_of_scope"),
        ({"target": "10.0.0.0/8"}, "target_out_of_scope"),
        ({"target": "0.0.0.0/0"}, "target_invalid"),
        ({"target": "10.0.0.1/24"}, "target_invalid"),
        ({"ports": list(range(1, 300))}, "ports_invalid"),
    ],
)
def test_advanced_limits_and_scope(overrides: dict[str, Any], code: str) -> None:
    assert rejected(advanced_job(**overrides)) == code


def test_unknown_or_missing_parameter_keys_are_rejected() -> None:
    job = advanced_job()
    job["parameters"]["script"] = "id"
    assert rejected(job) == "invalid_schema"
    job = advanced_job()
    del job["parameters"]["max_hosts"]
    assert rejected(job) == "invalid_schema"


def test_basic_parameters_do_not_pass_as_advanced() -> None:
    # Un job básico con job_type avanzado (o al revés) nunca se interpreta a medias.
    job = make_job(NOW, job_type=JOB_TYPE_DISCOVERY_ADVANCED)
    assert rejected(job) == "invalid_schema"
    job = make_job(NOW)
    job["parameters"] = advanced_params()
    assert rejected(job) == "invalid_schema"


def test_pre_6a_server_config_never_allows_advanced() -> None:
    old = ServerConfig.parse(server_config())  # sin claves avanzadas: servidor 5F
    assert old.max_tcp_retries == 0 and old.advanced_max_timeout_ms == 0
    assert rejected(advanced_job(), old) == "advanced_not_configured"
    # El básico sigue igual con el servidor viejo.
    assert validate(make_job(NOW), old).job_type == "discovery_basic"


def test_server_config_roundtrip_keeps_advanced_caps() -> None:
    again = ServerConfig.parse(CONFIG.to_json())
    assert again == CONFIG


# --- scanner -----------------------------------------------------------------------------


def scan_params(**overrides: object) -> DiscoveryParameters:
    values: dict[str, object] = {
        "target": ipaddress.ip_network("10.0.0.0/29"),
        "ports": (22, 80),
        "timeout_ms": 200,
        "concurrency": 8,
        "max_probes_per_second": 10_000,
        "icmp": False,
        "reverse_dns": False,
        "arp": False,
        "deadline_seconds": 30,
        "profile": "standard",
    }
    values.update(overrides)
    return DiscoveryParameters(**values)  # type: ignore[arg-type]


class Resolver:
    def __init__(self, forward: dict[str, set[str] | None]) -> None:
        self.forward_map = forward
        self.reverse_calls = 0
        self.forward_calls = 0

    async def resolve(self, address: str, timeout: float) -> str | None:
        self.reverse_calls += 1
        return f"host-{address.split('.')[-1]}.lan"

    async def forward(self, name: str, timeout: float) -> set[str] | None:
        self.forward_calls += 1
        return self.forward_map.get(name)


def collect(p: DiscoveryParameters, **probers: object) -> tuple[Any, list[dict[str, Any]]]:
    seen: list[dict[str, Any]] = []
    scanner = Scanner(p, lambda obs: seen.extend(o.to_json() for o in obs), **probers)  # type: ignore[arg-type]
    return scanner.run(), seen


def test_forward_dns_confirms_only_matching_names() -> None:
    tcp = FakeTcp({("10.0.0.1", 22): "open", ("10.0.0.2", 22): "open", ("10.0.0.3", 22): "open"})
    resolver = Resolver(
        {"host-1.lan": {"10.0.0.1"}, "host-2.lan": {"192.0.2.50"}, "host-3.lan": None}
    )
    _report, seen = collect(
        scan_params(reverse_dns=True, forward_dns=True, dns_timeout_ms=500),
        tcp=tcp,
        resolver=resolver,
    )
    by_ip = {o["address"]: o for o in seen}
    assert by_ip["10.0.0.1"]["forward_dns_match"] is True
    assert by_ip["10.0.0.2"]["forward_dns_match"] is False
    # Sin respuesta directa no se concluye nada (no aparece la clave).
    assert "forward_dns_match" not in by_ip["10.0.0.3"]
    # Lo que devuelve el DNS directo nunca se sondea (sin rebinding hacia fuera del target).
    assert all(addr.startswith("10.0.0.") for addr, _port in tcp.calls)


def test_dns_budget_is_enforced_and_reported() -> None:
    states = {(f"10.0.0.{i}", 22): "open" for i in range(1, 7)}
    resolver = Resolver({})
    report, seen = collect(
        scan_params(reverse_dns=True, forward_dns=True, max_dns_queries=2),
        tcp=FakeTcp(states),
        resolver=resolver,
    )
    assert resolver.reverse_calls + resolver.forward_calls <= 2
    assert any("dns query budget exhausted" in e for e in report.errors)
    assert len(seen) == 6  # los hosts siguen observados, solo sin DNS


class FlakyTcp(FakeTcp):
    """El primer intento a un puerto da timeout; el segundo responde."""

    def __init__(self, states: dict[tuple[str, int], str]) -> None:
        super().__init__(states)
        self.seen: set[tuple[str, int]] = set()

    async def probe(self, address: str, port: int, timeout: float) -> str:
        self.calls.append((address, port))
        key = (address, port)
        if key in self.states and key not in self.seen:
            self.seen.add(key)
            return "filtered"
        return self.states.get(key, "filtered")


def test_retries_only_on_live_hosts() -> None:
    # 10.0.0.1 está vivo (22 abierto) y su 80 se pierde una vez; el resto no existe.
    tcp = FlakyTcp({("10.0.0.1", 80): "open"})
    tcp.states[("10.0.0.1", 22)] = "open"
    tcp.seen.add(("10.0.0.1", 22))
    _report, seen = collect(scan_params(tcp_retries=1), tcp=tcp)
    assert seen[0]["ports"] == [{"port": 22, "state": "open"}, {"port": 80, "state": "open"}]
    # Direcciones muertas: un intento por puerto, sin reintentos.
    dead = [c for c in tcp.calls if c[0] != "10.0.0.1"]
    assert len(dead) == 5 * 2


def test_rtt_is_measured_and_absent_without_tcp_answer() -> None:
    tcp = FakeTcp({("10.0.0.1", 22): "closed"})

    class Icmp:
        async def ping(self, address: str, timeout: float) -> bool:
            return address == "10.0.0.2"

    _report, seen = collect(scan_params(icmp=True), tcp=tcp, icmp=Icmp())
    by_ip = {o["address"]: o for o in seen}
    assert isinstance(by_ip["10.0.0.1"]["rtt_ms"], int)
    # Solo ICMP: no hay medida TCP y no se inventa una.
    assert "rtt_ms" not in by_ip["10.0.0.2"]


def test_basic_observation_json_is_unchanged() -> None:
    obs = Observation("10.0.0.1", {22: "open"}, {"tcp"}, observed_at="2026-10-15T00:00:00+00:00")
    assert set(obs.to_json()) == {"address", "ports", "sources", "observed_at"}


class GateTcp:
    def __init__(self) -> None:
        self.inflight = 0
        self.peak = 0
        self.lock = threading.Lock()

    async def probe(self, address: str, port: int, timeout: float) -> str:
        import asyncio

        with self.lock:
            self.inflight += 1
            self.peak = max(self.peak, self.inflight)
        await asyncio.sleep(0.005)
        with self.lock:
            self.inflight -= 1
        return "filtered"


def test_max_concurrency_holds_with_retries() -> None:
    tcp = GateTcp()
    collect(
        scan_params(target=ipaddress.ip_network("10.0.0.0/27"), concurrency=3, tcp_retries=2),
        tcp=tcp,
    )
    assert tcp.peak <= 3


def test_cancel_stops_advanced_scan() -> None:
    import asyncio

    started = threading.Event()

    class Slow:
        async def probe(self, address: str, port: int, timeout: float) -> str:
            started.set()
            await asyncio.sleep(5)
            return "filtered"

    seen: list[Observation] = []
    scanner = Scanner(scan_params(tcp_retries=2), seen.extend, tcp=Slow())
    thread = threading.Thread(target=lambda: setattr(thread, "report", scanner.run()))
    thread.start()
    assert started.wait(2)
    scanner.request_cancel()
    thread.join(5)
    assert not thread.is_alive()
    assert thread.report.cancelled  # type: ignore[attr-defined]


# --- runner + servidor falso ---------------------------------------------------------------


def test_runner_executes_advanced_job_end_to_end(config: LocalConfig, server: FakeServer) -> None:
    server.config = server_config(**ADVANCED_CAPS)
    job = advanced_job()
    server.jobs.append(job)
    tcp = FakeTcp({("10.0.0.1", 22): "open", ("10.0.0.2", 80): "closed"})
    runner = make_runner(config, server, tcp=tcp)
    runner.tick()
    job_id = job["job_id"]
    assert server.started == [job_id]
    observed = {o["address"]: o for o in server.observations_for(job_id)}
    assert set(observed) == {"10.0.0.1", "10.0.0.2"}
    assert "rtt_ms" in observed["10.0.0.1"]
    assert server.completes[job_id]["outcome"] == "completed"


def test_runner_rejects_advanced_job_from_old_server(
    config: LocalConfig, server: FakeServer
) -> None:
    job = advanced_job()
    server.jobs.append(job)  # server.config sin topes avanzados (servidor 5F)
    tcp = FakeTcp()
    runner = make_runner(config, server, tcp=tcp)
    runner.tick()
    assert tcp.calls == [] and server.started == []
    assert server.completes[job["job_id"]]["errors"] == ["job_rejected:advanced_not_configured"]


def test_runner_rejects_out_of_scope_advanced_job(config: LocalConfig, server: FakeServer) -> None:
    server.config = server_config(**ADVANCED_CAPS)
    job = advanced_job(target="172.16.0.0/29")
    server.jobs.append(job)
    tcp = FakeTcp()
    runner = make_runner(config, server, tcp=tcp)
    runner.tick()
    assert tcp.calls == []
    assert server.completes[job["job_id"]]["errors"] == ["job_rejected:target_out_of_scope"]


def test_advanced_job_survives_offline_and_is_not_duplicated(
    config: LocalConfig, server: FakeServer
) -> None:
    from tests.conftest import FakeClock

    server.config = server_config(**ADVANCED_CAPS)
    clock = FakeClock()
    job = advanced_job()
    server.jobs.append(job)
    runner = make_runner(config, server, clock, tcp=FakeTcp({("10.0.0.1", 22): "open"}))
    server.fail_next.append(("/results", 503, "unavailable"))
    runner.tick()
    server.down = True
    for _ in range(10):
        clock.advance(600)
        runner.tick()
    server.down = False
    # El servidor pierde la respuesta del primer reenvío: el sensor repite el MISMO batch_id.
    server.lose_response_for.add("/results")
    for _ in range(6):
        clock.advance(600)
        runner.tick()
    assert runner.spool.stats().items == 0
    assert len(server.observations_for(job["job_id"])) == 1
    sent = {b["batch_id"] for p, _h, b in server.requests if p.endswith("/results")}
    assert len(sent) == 1
