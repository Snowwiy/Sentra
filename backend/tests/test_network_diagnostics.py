"""Fase 6D.4: diagnóstico SNMP por equipo, pausa automática y verificación de compatibilidad.

Caso real que motiva la fase: un Archer GX90 sin servicio SNMP utilizable devolvía
"snmp error: KeyError" (fallo interno del colector, ver sensor/tests/test_snmp_diagnostics.py)
y se seguía consultando en cada intervalo. Aquí se comprueba que el servidor:
- clasifica cada fallo en una taxonomía propia (snmp_status) y nunca muestra el nombre de
  una excepción como diagnóstico del equipo;
- deja de consultar periódicamente tras fallos repetidos sin SNMP utilizable;
- permite verificar la compatibilidad con una consulta mínima (solo system).
"""

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select, update
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.models.network import NetworkDevice, NetworkDevicePoll
from app.services.network_jobs import diagnose, safe_error_message, schedule_due_polls
from tests.conftest import authenticate
from tests.test_network import DEVICES, full_summary, run_poll, sensor_records, setup_device
from tests.test_sites_sensors import _error, _ok, audit


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


@pytest.fixture
def scheduled(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("SNMP_POLL_INTERVAL_MINUTES", "15")
    get_settings.cache_clear()
    yield
    monkeypatch.setenv("SNMP_POLL_INTERVAL_MINUTES", "")
    get_settings.cache_clear()


def _fail(client: TestClient, sensor: Any, device: dict[str, Any], code: str) -> dict[str, Any]:
    return run_poll(
        client,
        sensor,
        device,
        [],
        {"modules": {"system": "failed"}, "error_code": code},
        outcome="failed",
    )


def _detail(client: TestClient, device: dict[str, Any]) -> dict[str, Any]:
    return _ok(client.get(f"{DEVICES}/{device['device_id']}"))  # type: ignore[no-any-return]


@pytest.mark.parametrize(
    ("code", "ever_ok", "expected"),
    [
        ("timeout", False, "no_response"),
        ("timeout", True, "timeout"),
        ("host_unreachable", False, "unreachable"),
        ("auth_failed", False, "auth_failed"),
        ("unsupported_version", False, "unsupported_version"),
        ("malformed_response", False, "malformed_response"),
        ("internal", False, "collector_error"),
        ("partial", False, "compatible"),
        (None, False, "compatible"),
        # Lo que no dice nada del equipo no cambia el diagnóstico.
        ("sensor_offline", False, None),
        ("job_expired", False, None),
        ("cancelled", False, None),
        ("credentials_unavailable", False, None),
    ],
)
def test_diagnosis_taxonomy(code: str | None, ever_ok: bool, expected: str | None) -> None:
    from datetime import UTC, datetime

    device = NetworkDevice(last_success_at=datetime.now(UTC) if ever_ok else None)
    assert diagnose(code, device) == expected


def test_internal_errors_never_expose_exception_names() -> None:
    # Historial guardado por sensores <= 0.5.0 con el nombre de la excepción.
    assert "KeyError" not in (safe_error_message("internal", "snmp error: KeyError") or "")
    assert "KeyError" not in (safe_error_message(None, "snmp error: KeyError") or "")
    assert safe_error_message("auth_failed", "system: auth_failed") == "system: auth_failed"


def test_old_sensor_crash_is_a_collector_error_not_a_device_diagnosis(
    client: TestClient, db: Session
) -> None:
    _site, sensor, _profile, device = setup_device(client, "Archer")
    poll = run_poll(
        client,
        sensor,
        device,
        [],
        {"modules": {}, "error_code": "internal"},
        outcome="failed",
    )
    # Lo que envía un sensor 0.5.0 al fallar el colector.
    db.execute(
        update(NetworkDevicePoll)
        .where(NetworkDevicePoll.public_id == poll["poll_id"])
        .values(error_message="snmp error: KeyError")
    )
    db.commit()
    polls = _ok(client.get(f"{DEVICES}/{device['device_id']}/polls"))["items"]
    assert polls[0]["error_code"] == "internal"
    assert "KeyError" not in (polls[0]["error_message"] or "")
    detail = _detail(client, device)
    assert detail["snmp_status"] == "collector_error"
    assert "KeyError" not in str(detail)


def test_no_response_without_previous_success(client: TestClient) -> None:
    _site, sensor, _profile, device = setup_device(client, "Sin SNMP")
    assert _detail(client, device)["snmp_status"] == "unverified"
    _fail(client, sensor, device, "timeout")
    assert _detail(client, device)["snmp_status"] == "no_response"


def test_success_marks_compatible_and_later_timeout_is_timeout(client: TestClient) -> None:
    _site, sensor, _profile, device = setup_device(client, "Compatible")
    records, report = sensor_records()
    run_poll(client, sensor, device, records, report.summary())
    assert _detail(client, device)["snmp_status"] == "compatible"
    _fail(client, sensor, device, "timeout")
    assert _detail(client, device)["snmp_status"] == "timeout"


def test_repeated_failures_pause_periodic_polls(
    client: TestClient, db: Session, scheduled: None
) -> None:
    _site, sensor, _profile, device = setup_device(client, "Pausa")
    for _ in range(3):
        _fail(client, sensor, device, "timeout")
    detail = _detail(client, device)
    assert detail["monitoring_paused_at"] is not None
    assert detail["monitoring_pause_reason"] == "no_response"
    assert detail["monitoring_status"] == "paused"
    assert audit(db, "network_monitoring_paused")
    # El programador ya no lo encola aunque su intervalo haya vencido.
    db.execute(update(NetworkDevice).values(last_poll_at=None))
    db.commit()
    before = len(list(db.scalars(select(NetworkDevicePoll))))
    result = schedule_due_polls(db, get_settings())
    assert result["queued"] == 0
    assert len(list(db.scalars(select(NetworkDevicePoll)))) == before
    # La consulta manual sigue disponible y un éxito levanta la pausa.
    records, report = sensor_records()
    run_poll(client, sensor, device, records, report.summary())
    detail = _detail(client, device)
    assert detail["monitoring_paused_at"] is None
    assert detail["snmp_status"] == "compatible"
    assert audit(db, "network_monitoring_resumed")


def test_failures_unrelated_to_the_device_never_pause(client: TestClient) -> None:
    _site, sensor, _profile, device = setup_device(client, "Colector")
    for _ in range(4):
        _fail(client, sensor, device, "internal")
    detail = _detail(client, device)
    # Un fallo del colector no demuestra que el equipo no tenga SNMP: no se pausa.
    assert detail["monitoring_paused_at"] is None
    assert detail["snmp_status"] == "collector_error"


def test_resume_requires_admin_and_version(client: TestClient, engine: Engine, db: Session) -> None:
    _site, sensor, _profile, device = setup_device(client, "Reanudar")
    for _ in range(3):
        _fail(client, sensor, device, "auth_failed")
    detail = _detail(client, device)
    assert detail["monitoring_pause_reason"] == "auth_failed"
    url = f"{DEVICES}/{device['device_id']}/monitoring/resume"
    _error(
        client.post(url, json={"version": detail["version"] - 1}), 409, "network_device_conflict"
    )
    resumed = _ok(client.post(url, json={"version": detail["version"]}))
    assert resumed["monitoring_paused_at"] is None
    assert resumed["consecutive_failures"] == 0
    authenticate(client, engine, role="analyst")
    _error(client.post(url, json={"version": resumed["version"]}), 403, "permission_denied")


def test_reenabling_monitoring_clears_the_pause(client: TestClient) -> None:
    _site, sensor, _profile, device = setup_device(client, "Reactivar")
    for _ in range(3):
        _fail(client, sensor, device, "host_unreachable")
    detail = _detail(client, device)
    assert detail["monitoring_pause_reason"] == "unreachable"
    off = _ok(
        client.patch(
            f"{DEVICES}/{device['device_id']}",
            json={"version": detail["version"], "monitoring_enabled": False},
        )
    )
    on = _ok(
        client.patch(
            f"{DEVICES}/{device['device_id']}",
            json={"version": off["version"], "monitoring_enabled": True},
        )
    )
    assert on["monitoring_paused_at"] is None


def test_compatibility_check_polls_only_system(client: TestClient, engine: Engine) -> None:
    _site, sensor, _profile, device = setup_device(client, "Verificar")
    check = _ok(client.post(f"{DEVICES}/{device['device_id']}/compatibility-check"), 202)
    assert check["trigger"] == "check"
    assert check["modules_requested"] == ["system"]
    [job] = sensor.poll()
    assert job["parameters"]["modules"] == ["system"]
    _ok(sensor.start(job))
    records, _report = sensor_records()
    system = [r for r in records if r["kind"] == "system"]
    _ok(sensor.snmp_results(job, system))
    _ok(sensor.snmp_complete(job, full_summary(), batches_sent=1))
    assert _detail(client, device)["snmp_status"] == "compatible"
    authenticate(client, engine, role="viewer")
    _error(
        client.post(f"{DEVICES}/{device['device_id']}/compatibility-check"),
        403,
        "permission_denied",
    )


def test_compatibility_check_keeps_the_last_full_poll_state(client: TestClient) -> None:
    _site, sensor, _profile, device = setup_device(client, "Verificar tras consulta")
    records, report = sensor_records()
    run_poll(client, sensor, device, records, report.summary())
    full = _detail(client, device)
    assert len(full["last_modules"]) > 1
    _ok(client.post(f"{DEVICES}/{device['device_id']}/compatibility-check"), 202)
    [job] = sensor.poll()
    _ok(sensor.start(job))
    system = [r for r in records if r["kind"] == "system"]
    _ok(sensor.snmp_results(job, system))
    _ok(sensor.snmp_complete(job, full_summary(), batches_sent=1))
    after = _detail(client, device)
    # La verificación (solo system) no se hace pasar por una consulta completa: ni frescura,
    # ni módulos, ni el plazo de la siguiente consulta periódica cambian.
    assert after["last_modules"] == full["last_modules"]
    assert after["last_success_at"] == full["last_success_at"]
    assert after["last_poll_at"] == full["last_poll_at"]
    assert after["snmp_status"] == "compatible"


def test_timeout_after_a_successful_check_is_timeout(client: TestClient) -> None:
    _site, sensor, _profile, device = setup_device(client, "Verificado")
    _ok(client.post(f"{DEVICES}/{device['device_id']}/compatibility-check"), 202)
    [job] = sensor.poll()
    _ok(sensor.start(job))
    records, _report = sensor_records()
    _ok(sensor.snmp_results(job, [r for r in records if r["kind"] == "system"]))
    _ok(sensor.snmp_complete(job, full_summary(), batches_sent=1))
    assert _detail(client, device)["last_success_at"] is None
    _fail(client, sensor, device, "timeout")
    assert _detail(client, device)["snmp_status"] == "timeout"
