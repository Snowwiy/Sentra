"""Fase 6B: colector SNMP de solo lectura (catálogo, MIBs, límites, errores, jobs y runner).

Nada sale a la red: un agente SNMP simulado en memoria (tests/snmp_fixtures.py) sustituye al
transporte real y el servidor es el FakeServer de conftest.
"""

import logging
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from sentra_sensor import snmp
from sentra_sensor.config import LocalConfig
from sentra_sensor.jobs import (
    JOB_TYPE_SNMP_INVENTORY,
    SNMP_MODULES,
    JobRejectedError,
    SnmpParameters,
    validate_job,
)
from sentra_sensor.protocol import ServerConfig
from sentra_sensor.snmp import catalog, values
from sentra_sensor.snmp.collector import SnmpCollector, SnmpCredentials, SnmpReport
from sentra_sensor.snmp.mibs import Record
from sentra_sensor.snmp.transport import (
    SnmpAuthError,
    SnmpMalformedError,
    SnmpTimeoutError,
    SnmpTransport,
    SnmpUnreachableError,
)
from tests.conftest import SENSOR_ID, SITE_ID, FakeServer, make_job, make_runner, server_config
from tests.snmp_fixtures import FakeAgent, minimal_mib, switch_mib

PROFILE_ID = str(uuid.uuid4())
AUTH_SECRET = "auth-Secret-6b-XYZ"  # valor ficticio de test
PRIV_SECRET = "priv-Secret-6b-QRS"  # valor ficticio de test
CONFIG = ServerConfig.parse(server_config())


def collect(
    agent: FakeAgent,
    modules: tuple[str, ...] = SNMP_MODULES,
    *,
    max_varbinds: int = 100_000,
    max_rows: int = 10_000,
    max_repetitions: int = 10,
    deadline_seconds: int = 600,
    clock: Callable[[], float] | None = None,
) -> tuple[SnmpReport, list[Record]]:
    emitted: list[Record] = []
    kwargs: dict[str, Any] = {} if clock is None else {"clock": clock}
    collector = SnmpCollector(
        modules,
        lambda: agent,
        emitted.extend,
        max_varbinds=max_varbinds,
        max_rows=max_rows,
        max_repetitions=max_repetitions,
        deadline_seconds=deadline_seconds,
        **kwargs,
    )
    return collector.run(), emitted


def by_kind(records: list[Record], kind: str) -> list[Record]:
    return [r for r in records if r["kind"] == kind]


# --- colección completa -----------------------------------------------------------------------


def test_full_collection_normalizes_every_module() -> None:
    agent = FakeAgent(switch_mib())
    report, records = collect(agent)
    assert report.outcome == "completed"
    assert report.error_code is None
    # Fase 6C.3: un switch sin MIBs Wi-Fi informa wlan como unsupported, no como error.
    assert report.modules == {**dict.fromkeys(SNMP_MODULES[:-1], "complete"), "wlan": "unsupported"}
    assert report.records == len(records)
    assert agent.closed

    (system,) = by_kind(records, "system")
    assert system["sys_name"] == "sw-core-01"
    assert system["sys_descr"] == "Example Switch OS 1.2"
    assert system["sys_location"] == "Rack  A"  # control saneado, nunca crudo
    assert system["sys_object_id"] == "1.3.6.1.4.1.11.2.3.7.11.1"
    assert system["ip_forwarding"] == 2

    # Solo el chassis; el módulo (clase 9) no describe el equipo.
    (entity,) = by_kind(records, "entity")
    assert entity == {
        "kind": "entity",
        "index": 1,
        "phys_class": 3,
        "descr": "Chassis",
        "serial": "SN-0001",
        "mfg_name": "Example Corp",
        "model_name": "EX-2400",
        "software_rev": "1.2.3",
    }

    interfaces = {r["if_index"]: r for r in by_kind(records, "interface")}
    assert set(interfaces) == {1, 2, 3, 4, 100}
    assert interfaces[1]["name"] == "Gi1/0/1"
    assert interfaces[1]["counters_hc"] is True
    assert interfaces[1]["in_octets"] == 2**40 + 1  # contador de 64 bits preferido
    assert interfaces[3]["oper_status"] == 2
    assert interfaces[100]["if_type"] == 161
    stack = {(r["higher"], r["lower"]) for r in by_kind(records, "if_stack")}
    assert stack == {(100, 3), (100, 4)}  # la fila con 0 no es relación

    (local,) = by_kind(records, "lldp_local")
    assert local["chassis_id"] == "00:11:22:33:44:aa"
    assert local["capabilities"] == ["bridge"]
    assert {r["port_num"] for r in by_kind(records, "lldp_local_port")} == {1, 2}
    (remote,) = by_kind(records, "lldp_remote")
    assert remote["local_port_num"] == 1
    assert remote["rem_index"] == 7
    assert remote["chassis_id"] == "00:aa:bb:cc:dd:01"
    assert remote["port_id"] == "Gi0/24"
    assert remote["sys_name"] == "sw-access-02"
    assert remote["mgmt_addresses"] == ["10.0.0.2"]
    assert set(remote["capabilities"]) == {"bridge", "router"}

    (cdp,) = by_kind(records, "cdp_neighbor")
    assert cdp["if_index"] == 2
    assert cdp["address"] == "10.0.0.3"
    assert cdp["device_id"] == "ap-hall.example"
    assert cdp["native_vlan"] == 10

    (base,) = by_kind(records, "bridge_base")
    assert base == {"kind": "bridge_base", "bridge_address": "00:11:22:33:44:aa", "num_ports": 4}
    assert {(r["port"], r["if_index"]) for r in by_kind(records, "bridge_port")} == {
        (1, 1),
        (2, 2),
        (3, 3),
        (4, 4),
    }
    macs = {r["mac"]: r for r in by_kind(records, "mac_entry")}
    # La multicast se descarta; la propia del switch llega con status self (4).
    assert set(macs) == {"00:16:3e:00:00:01", "00:16:3e:00:00:02", "00:11:22:33:44:aa"}
    assert macs["00:16:3e:00:00:01"] == {
        "kind": "mac_entry",
        "mac": "00:16:3e:00:00:01",
        "port": 1,
        "fdb_id": 10,
        "status": 3,
        "source": "dot1q",
    }
    assert macs["00:11:22:33:44:aa"]["status"] == 4

    vlans = by_kind(records, "vlan")
    static = {r["vlan_id"]: r for r in vlans if r["source"] == "static"}
    assert static[1]["name"] == "default"
    assert static[1]["egress_ports"] == [1, 2, 3, 4]
    assert static[10]["untagged_ports"] == [1]
    current = [r for r in vlans if r["source"] == "current"]
    assert current == [
        {
            "kind": "vlan",
            "vlan_id": 10,
            "source": "current",
            "fdb_id": 10,
            "egress_ports": [1, 3],
            "untagged_ports": [1],
        }
    ]
    pvids = {r["port"]: r["vlan_id"] for r in by_kind(records, "pvid")}
    assert pvids == {1: 10, 2: 1, 3: 1, 4: 1}


def test_unsupported_mibs_are_not_errors() -> None:
    report, records = collect(FakeAgent(minimal_mib()))
    assert report.outcome == "completed"
    assert report.error_code is None
    assert report.modules["system"] == "complete"
    assert report.modules["interfaces"] == "complete"
    for name in ("entity", "lldp", "cdp", "bridge", "vlan"):
        assert report.modules[name] == "unsupported"
    assert {r["kind"] for r in records} == {"system", "interface"}


def test_only_requested_modules_are_queried() -> None:
    agent = FakeAgent(switch_mib())
    report, records = collect(agent, ("system",))
    assert report.modules == {"system": "complete"}
    assert {r["kind"] for r in records} == {"system"}
    assert len(agent.requests) == 1


def test_records_never_contain_raw_bytes() -> None:
    _report, records = collect(FakeAgent(switch_mib()))
    for record in records:
        for value in record.values():
            assert not isinstance(value, bytes)


# --- errores ----------------------------------------------------------------------------------


def test_device_without_system_group_fails() -> None:
    report, records = collect(FakeAgent({catalog.IP_FORWARDING: 1}))
    assert report.outcome == "failed"
    assert report.error_code == "oid_unavailable"
    assert records == []


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (SnmpTimeoutError, "timeout"),
        (SnmpAuthError, "auth_failed"),
        (SnmpUnreachableError, "host_unreachable"),
    ],
)
def test_error_in_system_fails_the_job(error: type[Exception], code: str) -> None:
    report, records = collect(FakeAgent(switch_mib(), fail_after=0, error=error))  # type: ignore[arg-type]
    assert report.outcome == "failed"
    assert report.error_code == code
    assert report.modules["system"] == "failed"
    assert report.modules["interfaces"] == "skipped"
    assert records == []


def test_timeout_after_system_is_partial_and_skips_the_rest() -> None:
    agent = FakeAgent(switch_mib(), fail_prefix=catalog.IF_ENTRY)
    report, records = collect(agent)
    assert report.outcome == "completed"
    assert report.error_code == "timeout"
    assert report.modules["system"] == "complete"
    assert report.modules["entity"] == "complete"
    assert report.modules["interfaces"] == "failed"
    for name in ("lldp", "cdp", "bridge", "vlan"):
        assert report.modules[name] == "skipped"  # fatal: no se acumulan más esperas
    assert {r["kind"] for r in records} == {"system", "entity"}


def test_looping_agent_is_cut_as_malformed() -> None:
    # Un agente que repite siempre el mismo OID no hace girar al sensor para siempre.
    agent = FakeAgent(switch_mib(), loop_at=catalog.CDP_CACHE)
    report, _records = collect(agent)
    assert report.modules["cdp"] == "partial"
    assert report.error_code == "partial"
    assert len(agent.requests) < 200


def test_malformed_module_does_not_stop_the_others() -> None:
    agent = FakeAgent(switch_mib(), fail_prefix=catalog.CDP_CACHE, error=SnmpMalformedError)
    report, records = collect(agent)
    assert report.modules["cdp"] == "failed"
    assert report.modules["bridge"] == "complete"
    assert report.modules["vlan"] == "complete"
    assert report.error_code == "malformed_response"
    assert by_kind(records, "mac_entry")


# --- límites, plazo y cancelación ---------------------------------------------------------------


def test_varbind_budget_stops_the_job() -> None:
    report, records = collect(FakeAgent(switch_mib()), max_varbinds=120)
    assert report.error_code == "limit_exceeded"
    assert report.truncated
    assert "partial" in report.modules.values()
    assert "skipped" in report.modules.values()
    assert by_kind(records, "system")


def test_row_limit_truncates_tables() -> None:
    report, records = collect(FakeAgent(switch_mib()), max_rows=2)
    assert report.truncated
    assert report.error_code == "limit_exceeded"
    assert report.modules["interfaces"] == "partial"
    assert len({r["if_index"] for r in by_kind(records, "interface")}) <= 2


def test_cancel_before_any_request() -> None:
    agent = FakeAgent(switch_mib())
    emitted: list[Record] = []
    collector = SnmpCollector(
        SNMP_MODULES,
        lambda: agent,
        emitted.extend,
        max_varbinds=1000,
        max_rows=100,
        max_repetitions=10,
        deadline_seconds=60,
    )
    collector.request_cancel()
    report = collector.run()
    assert report.outcome == "cancelled"
    assert report.error_code == "cancelled"
    assert agent.requests == []
    assert agent.closed


def test_deadline_stops_the_job() -> None:
    ticks = iter(range(0, 10_000, 5))
    report, _records = collect(
        FakeAgent(switch_mib()), deadline_seconds=30, clock=lambda: float(next(ticks))
    )
    assert report.outcome == "timed_out"
    assert report.error_code == "timeout"


def test_transport_factory_error_fails_cleanly() -> None:
    def factory() -> SnmpTransport:
        raise SnmpUnreachableError("no route")

    collector = SnmpCollector(
        ("system",),
        factory,
        lambda _r: None,
        max_varbinds=1000,
        max_rows=100,
        max_repetitions=10,
        deadline_seconds=60,
    )
    report = collector.run()
    assert report.outcome == "failed"
    assert report.error_code == "host_unreachable"


# --- catálogo cerrado -------------------------------------------------------------------------


def test_catalog_allows_only_read_only_roots() -> None:
    assert catalog.allowed(catalog.SYS_DESCR)
    assert catalog.allowed((*catalog.IF_COLUMNS["descr"], 7))
    assert catalog.allowed((*catalog.LLDP_REM, 9, 0, 1, 1))
    assert catalog.allowed((*catalog.CDP_CACHE, 6, 1, 1))
    assert not catalog.allowed(catalog.oid("1.3.6.1.6.3.15"))  # usmUser (SNMP-USER-BASED-SM)
    assert not catalog.allowed(catalog.oid("1.3.6.1.4.1.9.9.96"))  # ciscoConfigCopy
    assert not catalog.allowed(catalog.oid("1.3.6.1.2.1.25"))  # HOST-RESOURCES
    assert not catalog.allowed(catalog.oid("1.3.6.1.2.1"))  # demasiado amplio


def test_walker_refuses_oids_outside_the_catalog() -> None:
    from threading import Event

    from sentra_sensor.snmp.walker import Budget, Walker

    agent = FakeAgent(switch_mib())
    walker = Walker(agent, Budget(1000, 100, float("inf"), Event()), 10)
    with pytest.raises(SnmpMalformedError):
        walker.column(catalog.oid("1.3.6.1.6.3.15.1.2"))
    with pytest.raises(SnmpMalformedError):
        walker.get([catalog.oid("1.3.6.1.4.1.9.2.1.55.0")])
    assert agent.requests == []


def test_snmp_package_has_no_write_operations() -> None:
    package = Path(snmp.__file__).parent
    forbidden = ("set_cmd", "setCmd", "SetRequest", "SetRequestPdu", "CommandResponder")
    for source in package.glob("*.py"):
        text = source.read_text(encoding="utf-8")
        for word in forbidden:
            assert word not in text, f"{word} en {source.name}"


# --- valores -----------------------------------------------------------------------------------


def test_value_helpers() -> None:
    assert values.text(b"  hola\x00\x1b ", 10) == "hola"
    assert values.text(b"", 10) is None
    assert values.text(b"x" * 50, 5) == "xxxxx"
    assert values.integer(5, 1, 3) is None
    assert values.integer(b"5", 1, 9) is None
    assert values.mac(b"\x00\x11\x22\x33\x44\x55") == "00:11:22:33:44:55"
    assert values.mac(b"\x00\x11") is None
    assert values.ip_address(bytes([10, 0, 0, 1])) == "10.0.0.1"
    assert values.port_list(bytes([0b10100000, 0b00000001])) == [1, 3, 16]
    assert values.cdp_capabilities(bytes([0, 0, 0, 0x01])) == ["router"]
    assert values.lldp_capabilities(bytes([0x08, 0x00])) == ["router"]


# --- validación de jobs -------------------------------------------------------------------------


NOW = datetime.now(UTC)


def snmp_params(**overrides: Any) -> dict[str, Any]:
    params: dict[str, Any] = {
        "schema_version": 1,
        "target": "10.0.0.5",
        "port": 161,
        "snmp_version": "v3",
        "profile_id": PROFILE_ID,
        "secret_revision": 1,
        "auth_protocol": "sha256",
        "priv_protocol": "aes128",
        "modules": list(SNMP_MODULES),
        "timeout_ms": 1000,
        "retries": 1,
        "max_repetitions": 10,
        "max_varbinds": 50_000,
        "max_rows_per_table": 10_000,
        "deadline_seconds": 120,
    }
    params.update(overrides)
    return params


def snmp_job(**overrides: Any) -> dict[str, Any]:
    job = make_job(NOW, job_type=JOB_TYPE_SNMP_INVENTORY)
    job["parameters"] = snmp_params(**overrides)
    return job


def rejected(job: dict[str, Any]) -> str:
    with pytest.raises(JobRejectedError) as info:
        validate_job(job, sensor_id=SENSOR_ID, site_id=SITE_ID, config=CONFIG, now=NOW)
    return info.value.code


def test_valid_snmp_job() -> None:
    job = validate_job(snmp_job(), sensor_id=SENSOR_ID, site_id=SITE_ID, config=CONFIG, now=NOW)
    assert isinstance(job.parameters, SnmpParameters)
    assert job.parameters.address == "10.0.0.5"
    assert job.parameters.modules == SNMP_MODULES


def test_modules_are_put_in_catalog_order() -> None:
    job = validate_job(
        snmp_job(modules=["bridge", "system"]),
        sensor_id=SENSOR_ID,
        site_id=SITE_ID,
        config=CONFIG,
        now=NOW,
    )
    assert isinstance(job.parameters, SnmpParameters)
    assert job.parameters.modules == ("system", "bridge")


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"schema_version": 2}, "schema_unsupported"),
        ({"target": "10.0.0.0/30"}, "target_invalid"),
        ({"target": "172.16.0.5"}, "target_out_of_scope"),
        ({"snmp_version": "v1"}, "invalid_schema"),
        ({"snmp_version": "v3", "auth_protocol": "md5"}, "invalid_schema"),
        ({"snmp_version": "v3", "priv_protocol": "des"}, "invalid_schema"),
        ({"snmp_version": "v3", "priv_protocol": None}, "invalid_schema"),
        ({"snmp_version": "v2c"}, "invalid_schema"),  # v2c con protocolos v3
        ({"modules": []}, "invalid_schema"),
        ({"modules": ["system", "routes"]}, "invalid_schema"),
        ({"modules": ["system", "system"]}, "invalid_schema"),
        ({"modules": ["interfaces"]}, "invalid_schema"),
        ({"modules": ["system", "vlan"]}, "invalid_schema"),
        ({"port": 0}, "invalid_schema"),
        ({"timeout_ms": 50}, "invalid_schema"),
        ({"retries": 9}, "invalid_schema"),
        ({"max_repetitions": 500}, "invalid_schema"),
        ({"max_varbinds": 10_000_000}, "invalid_schema"),
        ({"deadline_seconds": 86_400}, "invalid_schema"),
    ],
)
def test_snmp_job_validation(overrides: dict[str, Any], code: str) -> None:
    assert rejected(snmp_job(**overrides)) == code


def test_v2c_without_protocols_is_valid() -> None:
    job = validate_job(
        snmp_job(snmp_version="v2c", auth_protocol=None, priv_protocol=None),
        sensor_id=SENSOR_ID,
        site_id=SITE_ID,
        config=CONFIG,
        now=NOW,
    )
    assert isinstance(job.parameters, SnmpParameters)
    assert job.parameters.snmp_version == "v2c"


def test_unknown_or_extra_snmp_keys_are_rejected() -> None:
    job = snmp_job()
    job["parameters"]["oids"] = ["1.3.6.1.6.3.15"]
    assert rejected(job) == "invalid_schema"
    job = snmp_job()
    del job["parameters"]["modules"]
    assert rejected(job) == "invalid_schema"


def test_snmp_job_rejected_when_library_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(snmp, "snmp_available", lambda: False)
    assert rejected(snmp_job()) == "snmp_unavailable"


def test_v3_rejected_without_crypto(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(snmp, "v3_available", lambda: False)
    assert rejected(snmp_job()) == "snmp_unavailable"


# --- runner extremo a extremo -----------------------------------------------------------------


def credentials(**overrides: Any) -> dict[str, Any]:
    raw: dict[str, Any] = {
        "profile_id": PROFILE_ID,
        "secret_revision": 1,
        "snmp_version": "v3",
        "username": "sentra-ro",
        "auth_password": AUTH_SECRET,
        "priv_password": PRIV_SECRET,
    }
    raw.update(overrides)
    return raw


class AgentFactory:
    def __init__(self, agent: FakeAgent) -> None:
        self.agent = agent
        self.calls: list[tuple[SnmpParameters, SnmpCredentials]] = []

    def __call__(self, params: SnmpParameters, creds: SnmpCredentials) -> SnmpTransport:
        self.calls.append((params, creds))
        return self.agent


def files_text(root: Path) -> str:
    return "\n".join(
        p.read_bytes().decode("utf-8", errors="replace") for p in root.rglob("*") if p.is_file()
    )


def test_runner_executes_snmp_job_end_to_end(
    config: LocalConfig, server: FakeServer, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    job = snmp_job()
    server.jobs.append(job)
    server.start_credentials = credentials()
    factory = AgentFactory(FakeAgent(switch_mib()))
    runner = make_runner(config, server, snmp_transport=factory)
    runner.tick()
    runner.tick()
    job_id = job["job_id"]
    assert server.started == [job_id]
    (params, creds), *_ = factory.calls
    assert params.address == "10.0.0.5"
    assert creds.auth_password == AUTH_SECRET and creds.priv_password == PRIV_SECRET
    assert AUTH_SECRET not in repr(creds) and PRIV_SECRET not in repr(creds)
    records = server.records_for(job_id)
    assert {r["kind"] for r in records} >= {"system", "interface", "lldp_remote", "mac_entry"}
    complete = server.completes[job_id]
    assert complete["outcome"] == "completed"
    assert complete["snmp"]["modules"] == {
        **dict.fromkeys(SNMP_MODULES[:-1], "complete"),
        "wlan": "unsupported",
    }
    assert "observations" not in complete
    # Los secretos no llegan al disco (spool, estado) ni a los logs ni a lo enviado al servidor.
    stored = files_text(Path(config.data_dir))
    sent = "\n".join(str(b) for p, _h, b in server.requests if not p.endswith("/start"))
    for secret in (AUTH_SECRET, PRIV_SECRET):
        assert secret not in stored
        assert secret not in caplog.text
        assert secret not in sent


@pytest.mark.parametrize(
    "start_credentials",
    [
        None,
        credentials(profile_id=str(uuid.uuid4())),
        credentials(secret_revision=2),
        credentials(snmp_version="v2c"),
    ],
)
def test_runner_refuses_snmp_job_without_matching_credentials(
    config: LocalConfig, server: FakeServer, start_credentials: dict[str, Any] | None
) -> None:
    job = snmp_job()
    server.jobs.append(job)
    server.start_credentials = start_credentials
    factory = AgentFactory(FakeAgent(switch_mib()))
    runner = make_runner(config, server, snmp_transport=factory)
    runner.tick()
    runner.tick()
    assert factory.calls == []
    complete = server.completes[job["job_id"]]
    assert complete["outcome"] == "failed"
    assert complete["errors"] == ["job_rejected:credentials_missing"]
    assert complete["snmp"] == {"modules": {}, "error_code": "internal"}


def test_runner_reports_snmp_failure_summary(config: LocalConfig, server: FakeServer) -> None:
    job = snmp_job()
    server.jobs.append(job)
    server.start_credentials = credentials()
    factory = AgentFactory(FakeAgent(switch_mib(), fail_after=0, error=SnmpAuthError))
    runner = make_runner(config, server, snmp_transport=factory)
    runner.tick()
    runner.tick()
    complete = server.completes[job["job_id"]]
    assert complete["outcome"] == "failed"
    assert complete["snmp"]["error_code"] == "auth_failed"
    assert server.records_for(job["job_id"]) == []


def test_runner_rejects_out_of_scope_snmp_job_before_start(
    config: LocalConfig, server: FakeServer
) -> None:
    job = snmp_job(target="172.16.0.5")
    server.jobs.append(job)
    server.start_credentials = credentials()
    factory = AgentFactory(FakeAgent(switch_mib()))
    runner = make_runner(config, server, snmp_transport=factory)
    runner.tick()
    assert server.started == [] and factory.calls == []
    assert server.completes[job["job_id"]]["errors"] == ["job_rejected:target_out_of_scope"]
