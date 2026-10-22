"""Fase 6D.4: diagnóstico del "snmp error: KeyError" y fallos internos del colector.

Causa reproducida: cuando un lector de módulo lanzaba una excepción que no era SnmpError, el
manejador registraba el fallo con `extra={"module": ...}`. "module" es un atributo reservado
de logging.LogRecord, así que el propio log lanzaba KeyError, que escapaba de
SnmpCollector.run() y sustituía al fallo real: el job terminaba como "snmp error: KeyError".
"""

import ast
import logging
from collections.abc import Sequence
from pathlib import Path

import pytest

from sentra_sensor.config import LocalConfig
from sentra_sensor.snmp import catalog
from sentra_sensor.snmp.collector import SnmpCollector
from sentra_sensor.snmp.transport import Oid, SnmpTransport, VarBind
from tests.conftest import FakeServer, make_runner
from tests.snmp_fixtures import FakeAgent, switch_mib
from tests.test_snmp import AgentFactory, credentials, snmp_job

PACKAGE = Path(__file__).resolve().parents[1] / "sentra_sensor"
# Grupo system de SNMPv2-MIB: lo pide siempre el primer módulo.
SYSTEM_GROUP: Oid = (1, 3, 6, 1, 2, 1, 1)


class CrashingAgent:
    """Agente simulado que lanza un error que NO es SnmpError dentro de un módulo (lo que
    haría un fallo inesperado de la biblioteca SNMP o de un lector con datos raros)."""

    def __init__(self, crash_prefix: Oid, exc: Exception) -> None:
        self._inner = FakeAgent(switch_mib())
        self._prefix = crash_prefix
        self._exc = exc

    def get(self, oids: Sequence[Oid]) -> list[VarBind]:
        if oids[0][: len(self._prefix)] == self._prefix:
            raise self._exc
        return self._inner.get(oids)

    def get_bulk(self, start: Oid, max_repetitions: int) -> list[VarBind]:
        if start[: len(self._prefix)] == self._prefix:
            raise self._exc
        return self._inner.get_bulk(start, max_repetitions)

    def close(self) -> None:
        self._inner.close()


def _collector(factory: object) -> SnmpCollector:
    return SnmpCollector(
        ("system", "interfaces", "cdp", "bridge"),
        factory,  # type: ignore[arg-type]
        lambda _r: None,
        max_varbinds=100_000,
        max_rows=10_000,
        max_repetitions=10,
        deadline_seconds=600,
    )


def test_module_crash_is_reported_not_raised(caplog: pytest.LogCaptureFixture) -> None:
    # Con el nivel WARNING activo el registro se crea de verdad: antes de 6D lanzaba KeyError.
    caplog.set_level(logging.WARNING, logger="sentra_sensor.snmp")
    agent = CrashingAgent(catalog.CDP_CACHE, ValueError("weird value"))
    report = _collector(lambda: agent).run()
    assert report.outcome == "completed"
    assert report.modules["cdp"] == "failed"
    assert report.modules["bridge"] == "complete"
    assert report.error_code == "internal"
    assert "cdp: internal" in report.errors
    # El tipo de la excepción solo va al log local, nunca al resumen que ve el servidor.
    assert not any("ValueError" in e or "KeyError" in e for e in report.errors)
    record = next(r for r in caplog.records if r.getMessage() == "snmp module crashed")
    assert record.snmp_module == "cdp"  # type: ignore[attr-defined]
    assert record.error == "ValueError"  # type: ignore[attr-defined]


def test_crash_in_system_module_is_internal(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger="sentra_sensor.snmp")
    agent = CrashingAgent(SYSTEM_GROUP, KeyError("engine"))
    report = _collector(lambda: agent).run()
    assert report.outcome == "failed"
    assert report.modules["system"] == "failed"
    assert report.modules["interfaces"] == "skipped"
    assert report.error_code == "internal"


def test_unexpected_transport_setup_error_is_internal(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger="sentra_sensor.snmp")

    def factory() -> SnmpTransport:
        raise KeyError("dispatcher")

    report = _collector(factory).run()
    assert report.outcome == "failed"
    assert report.error_code == "internal"
    assert report.errors == ["transport: internal"]


def test_runner_never_reports_exception_names(config: LocalConfig, server: FakeServer) -> None:
    job = snmp_job()
    server.jobs.append(job)
    server.start_credentials = credentials()
    agent = CrashingAgent(SYSTEM_GROUP, KeyError("x"))
    runner = make_runner(config, server, snmp_transport=AgentFactory(agent))  # type: ignore[arg-type]
    runner.tick()
    runner.tick()
    complete = server.completes[job["job_id"]]
    assert complete["outcome"] == "failed"
    assert complete["snmp"]["error_code"] == "internal"
    assert all("KeyError" not in e for e in complete.get("errors", []))


def _reserved_log_attributes() -> set[str]:
    sample = logging.LogRecord("n", logging.INFO, "p", 1, "m", None, None)
    return set(sample.__dict__) | {"message", "asctime"}


def test_no_log_call_uses_reserved_extra_keys() -> None:
    """Ninguna llamada de log del sensor usa en `extra` un nombre reservado de LogRecord."""
    reserved = _reserved_log_attributes()
    offenders: list[str] = []
    for path in sorted(PACKAGE.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for keyword in node.keywords:
                if keyword.arg != "extra" or not isinstance(keyword.value, ast.Dict):
                    continue
                for key in keyword.value.keys:
                    if isinstance(key, ast.Constant) and key.value in reserved:
                        offenders.append(f"{path.name}:{node.lineno}:{key.value}")
    assert offenders == []
