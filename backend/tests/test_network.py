"""Fase 6B: perfiles SNMP, equipos de red, jobs snmp_inventory e inventario de switches.

El sensor se simula con el protocolo real (/api/v1/sensor/*). Los registros SNMP no se
escriben a mano: los genera el colector real del sensor (sensor/sentra_sensor/snmp) contra el
agente simulado de sensor/tests/snmp_fixtures.py, así el test es también el contrato
backend ↔ sensor. Nada sale a la red.
"""

import importlib
import importlib.util
import logging
import sys
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import TypeAdapter
from sqlalchemy import Engine, select, text, update
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.core.secret_box import (
    SecretBox,
    SecretDecryptError,
    SecretStoreError,
    add_key,
    load_keyring,
    write_new_keyring,
)
from app.models.audit import AuditEvent
from app.models.network import NetworkDevicePoll, SnmpCredentialProfile
from app.models.site import SensorJob
from app.network import classify
from app.schemas.network_protocol import SnmpRecord
from tests.conftest import authenticate
from tests.test_sites_sensors import (
    API,
    CAPS,
    PROTO,
    SensorSim,
    _error,
    _ok,
    audit,
    create_site,
    new_token,
)

NETWORK = f"{API}/network"
PROFILES = f"{NETWORK}/snmp-profiles"
DEVICES = f"{NETWORK}/devices"
NET = "10.70.0.0/24"
DEVICE_IP = "10.70.0.5"
SNMP_CAPS = [
    "snmp.v3",
    "snmp.system",
    "snmp.entity",
    "snmp.interfaces",
    "snmp.lldp",
    "snmp.cdp",
    "snmp.bridge",
    "snmp.vlan",
]
AUTH = "auth-Passphrase-6B"  # valores ficticios de test
PRIV = "priv-Passphrase-6B"
COMMUNITY = "comm-6B-test"

_SENSOR_ROOT = Path(__file__).resolve().parents[2] / "sensor"


def _sensor_modules() -> tuple[ModuleType, ModuleType]:
    """Colector real del sensor y su agente simulado (solo biblioteca estándar)."""
    if str(_SENSOR_ROOT) not in sys.path:
        sys.path.insert(0, str(_SENSOR_ROOT))
    collector = importlib.import_module("sentra_sensor.snmp.collector")
    spec = importlib.util.spec_from_file_location(
        "sentra_sensor_snmp_fixtures", _SENSOR_ROOT / "tests" / "snmp_fixtures.py"
    )
    assert spec is not None and spec.loader is not None
    fixtures = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixtures)
    return collector, fixtures


def sensor_records(mib: str = "switch_mib", **agent: Any) -> tuple[list[dict[str, Any]], Any]:
    collector, fixtures = _sensor_modules()
    emitted: list[dict[str, Any]] = []
    fake = fixtures.FakeAgent(getattr(fixtures, mib)(), **agent)
    report = collector.SnmpCollector(
        ("system", "entity", "interfaces", "lldp", "cdp", "bridge", "vlan"),
        lambda: fake,
        emitted.extend,
        max_varbinds=50_000,
        max_rows=10_000,
        max_repetitions=10,
        deadline_seconds=60,
    ).run()
    return emitted, report


# --- utilidades -------------------------------------------------------------------------------


class SnmpSensor(SensorSim):
    """Sensor 0.3.0 con capacidades SNMP, ya online."""

    def __init__(
        self,
        client: TestClient,
        site_id: str,
        caps: list[str] | None = None,
        version: str = "0.3.0",
    ) -> None:
        self.client = client
        body = _ok(
            client.post(
                f"{PROTO}/enroll",
                json={
                    "hostname": "sensor-snmp",
                    "platform": "linux",
                    "sensor_version": version,
                    "capabilities": [*CAPS, *SNMP_CAPS] if caps is None else caps,
                },
                headers={"X-Sensor-Enrollment-Token": new_token(client, site_id, "snmp")},
            ),
            201,
        )
        self.credential = body["credential"]
        self.sensor_id = body["sensor_id"]
        self.site_id = site_id
        self.config = body["config"]
        _ok(self.heartbeat())

    def snmp_results(
        self, job: dict[str, Any], records: list[dict[str, Any]], batch: str | None = None
    ) -> Any:
        return self.call(
            f"/jobs/{job['job_id']}/results",
            {"batch_id": batch or str(uuid.uuid4()), "attempt": job["attempt"], "records": records},
        )

    def snmp_complete(
        self, job: dict[str, Any], summary: dict[str, Any], outcome: str = "completed", **extra: Any
    ) -> Any:
        body = {"attempt": job["attempt"], "outcome": outcome, "snmp": summary, **extra}
        return self.call(f"/jobs/{job['job_id']}/complete", body)


def v3_profile(site_id: str, name: str = "core-ro", **extra: Any) -> dict[str, Any]:
    body = {
        "site_id": site_id,
        "name": name,
        "snmp_version": "v3",
        "username": "sentra-ro",
        "auth_protocol": "sha256",
        "priv_protocol": "aes128",
        "auth_password": AUTH,
        "priv_password": PRIV,
    }
    body.update(extra)
    return body


def setup_device(
    client: TestClient, site_name: str = "Campus", address: str = DEVICE_IP
) -> tuple[dict[str, Any], SnmpSensor, dict[str, Any], dict[str, Any]]:
    site = create_site(client, site_name, (NET,))
    sensor = SnmpSensor(client, site["site_id"])
    profile = _ok(client.post(PROFILES, json=v3_profile(site["site_id"])), 201)
    device = _ok(
        client.post(
            DEVICES,
            json={
                "site_id": site["site_id"],
                "management_address": address,
                "profile_id": profile["profile_id"],
                "sensor_id": sensor.sensor_id,
                "monitoring_enabled": True,
            },
        ),
        201,
    )
    return site, sensor, profile, device


def run_poll(
    client: TestClient,
    sensor: SnmpSensor,
    device: dict[str, Any],
    records: list[dict[str, Any]],
    summary: dict[str, Any],
    outcome: str = "completed",
) -> dict[str, Any]:
    poll = _ok(client.post(f"{DEVICES}/{device['device_id']}/polls"), 202)
    [job] = sensor.poll()
    _ok(sensor.start(job))
    if records:
        _ok(sensor.snmp_results(job, records))
    _ok(sensor.snmp_complete(job, summary, outcome, batches_sent=1 if records else 0))
    polls = _ok(client.get(f"{DEVICES}/{device['device_id']}/polls"))["items"]
    return next(p for p in polls if p["poll_id"] == poll["poll_id"])


def full_summary(**extra: Any) -> dict[str, Any]:
    modules = dict.fromkeys(
        ("system", "entity", "interfaces", "lldp", "cdp", "bridge", "vlan"), "complete"
    )
    return {"modules": modules, **extra}


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


@pytest.fixture
def allow_v2c(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("SNMP_ALLOW_V2C", "true")
    get_settings.cache_clear()
    yield
    monkeypatch.setenv("SNMP_ALLOW_V2C", "false")
    get_settings.cache_clear()


# --- cifrado de secretos ----------------------------------------------------------------------


def test_secret_box_roundtrip_binding_and_rotation(tmp_path: Path) -> None:
    keyfile = tmp_path / "snmp.keys"
    write_new_keyring(keyfile, "k1")
    box = SecretBox(load_keyring(keyfile))
    blob, kid = box.encrypt({"auth_password": AUTH}, "profile-a|site-a")
    assert kid == "k1" and AUTH not in blob
    assert box.decrypt(blob, "profile-a|site-a") == {"auth_password": AUTH}
    # El AAD ata el blob a su perfil y site: copiarlo a otro perfil no lo descifra.
    with pytest.raises(SecretDecryptError):
        box.decrypt(blob, "profile-b|site-a")
    tampered = blob[:-4] + ("AAAA" if not blob.endswith("AAAA") else "BBBB")
    with pytest.raises(SecretDecryptError):
        box.decrypt(tampered, "profile-a|site-a")
    # Rotación de la clave maestra: la nueva va primero y la vieja sigue descifrando.
    add_key(keyfile, "k2")
    rotated = SecretBox(load_keyring(keyfile))
    assert rotated.active_kid == "k2"
    assert rotated.decrypt(blob, "profile-a|site-a") == {"auth_password": AUTH}
    assert rotated.encrypt({"x": "y"}, "c")[1] == "k2"
    with pytest.raises(ValueError):
        add_key(keyfile, "k2")
    if sys.platform != "win32":
        assert keyfile.stat().st_mode & 0o077 == 0
        keyfile.chmod(0o644)
        with pytest.raises(SecretStoreError):
            load_keyring(keyfile)


def test_secret_store_refuses_bad_key_files(tmp_path: Path) -> None:
    keyfile = tmp_path / "bad.keys"
    keyfile.write_text("k1:" + "QQ==" + "\n")
    keyfile.chmod(0o600)
    with pytest.raises(SecretStoreError):
        load_keyring(keyfile)
    with pytest.raises(SecretStoreError):
        load_keyring(tmp_path / "missing.keys")
    with pytest.raises(FileExistsError):
        write_new_keyring(tmp_path / "bad.keys", "k9")


# --- perfiles ---------------------------------------------------------------------------------


def test_profile_secrets_are_write_only(
    client: TestClient,
    db: Session,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    site = create_site(client, "Perfiles", (NET,))
    created = client.post(PROFILES, json=v3_profile(site["site_id"]))
    profile = _ok(created, 201)
    assert profile["secret_configured"] is True
    assert profile["security_level"] == "authPriv"
    assert profile["secret_revision"] == 1
    listed = client.get(PROFILES)
    single = client.get(f"{PROFILES}/{profile['profile_id']}")
    for response in (created, listed, single):
        assert AUTH not in response.text and PRIV not in response.text
    row = db.scalar(select(SnmpCredentialProfile))
    assert row is not None and row.secret_blob
    stored = str(row.secret_blob)
    assert AUTH not in stored and PRIV not in stored
    details = " ".join(str(e.details) for e in db.scalars(select(AuditEvent)))
    assert AUTH not in details and PRIV not in details
    assert AUTH not in caplog.text and PRIV not in caplog.text
    assert audit(db, "snmp_profile_created")


@pytest.mark.parametrize(
    "overrides",
    [
        {"priv_password": None},
        {"auth_protocol": "md5"},
        {"priv_protocol": "des"},
        {"auth_password": "short"},
        {"priv_password": AUTH},  # misma passphrase en auth y priv
        {"community": COMMUNITY},
        {"snmp_version": "v1"},
    ],
)
def test_invalid_v3_profiles_are_refused(client: TestClient, overrides: dict[str, Any]) -> None:
    site = create_site(client, "Invalidos", (NET,))
    body = v3_profile(site["site_id"], **overrides)
    body = {k: v for k, v in body.items() if v is not None}
    response = client.post(PROFILES, json=body)
    assert response.status_code == 422, response.text
    assert AUTH not in response.text and PRIV not in response.text


def test_v2c_is_opt_in(client: TestClient, allow_v2c: None) -> None:
    site = create_site(client, "V2c", (NET,))
    body = {"site_id": site["site_id"], "name": "legacy", "snmp_version": "v2c"}
    _ok(client.post(PROFILES, json={**body, "community": COMMUNITY}), 201)
    assert (
        client.post(PROFILES, json={**body, "name": "p", "community": "public"}).status_code == 422
    )


def test_v2c_refused_by_default(client: TestClient) -> None:
    site = create_site(client, "SinV2c", (NET,))
    body = {"site_id": site["site_id"], "name": "x", "snmp_version": "v2c", "community": COMMUNITY}
    _error(client.post(PROFILES, json=body), 409, "snmp_v2c_disabled")


def test_rotate_and_revoke(client: TestClient, db: Session) -> None:
    _site, sensor, profile, device = setup_device(client, "Rotar")
    url = f"{PROFILES}/{profile['profile_id']}"
    # Una consulta encolada lleva la revisión del momento: rotar la cancela (el sensor
    # rechazaría la credencial nueva) y la siguiente lleva la revisión 2.
    _ok(client.post(f"{DEVICES}/{device['device_id']}/polls"), 202)
    rotated = _ok(
        client.post(
            f"{url}/rotate",
            json={"version": profile["version"], "auth_password": "new-Auth-6B-pass"},
        )
    )
    assert rotated["secret_revision"] == 2
    assert "new-Auth-6B-pass" not in str(rotated)
    assert audit(db, "snmp_profile_rotated")
    assert sensor.poll() == []
    db.expire_all()
    assert db.scalar(select(NetworkDevicePoll.status)) == "cancelled"
    _ok(client.post(f"{DEVICES}/{device['device_id']}/polls"), 202)
    [job] = sensor.poll()
    assert job["parameters"]["secret_revision"] == 2
    started = _ok(sensor.start(job))
    assert started["credentials"]["auth_password"] == "new-Auth-6B-pass"
    assert started["credentials"]["secret_revision"] == 2
    # Tras revocar, la consulta en curso se cancela y no se puede pedir otra.
    revoked = _ok(
        client.post(f"{url}/revoke", json={"version": rotated["version"], "reason": "fuga"})
    )
    assert revoked["status"] == "revoked" and revoked["secret_configured"] is False
    assert sensor.poll() == []
    db.expire_all()
    statuses = list(db.scalars(select(NetworkDevicePoll.status)))
    assert statuses == ["cancelled", "cancelled"]
    assert audit(db, "snmp_profile_revoked")
    detail = _ok(client.get(f"{DEVICES}/{device['device_id']}"))
    assert detail["monitoring_status"] == "credentials_pending"
    assert "profile_revoked" in detail["poll_blockers"]
    _error(client.post(f"{DEVICES}/{device['device_id']}/polls"), 409, "network_poll_unavailable")


def test_rbac_on_profiles_devices_and_polls(client: TestClient, engine: Engine) -> None:
    site, _sensor, profile, device = setup_device(client, "Rbac")
    device_url = f"{DEVICES}/{device['device_id']}"
    authenticate(client, engine, role="viewer")
    _error(client.get(PROFILES), 403, "permission_denied")
    _ok(client.get(DEVICES))
    _ok(client.get(f"{device_url}/interfaces"))
    _error(client.post(f"{device_url}/polls"), 403, "permission_denied")
    _error(
        client.post(PROFILES, json=v3_profile(site["site_id"], name="v")), 403, "permission_denied"
    )
    authenticate(client, engine, role="analyst")
    _error(client.get(f"{PROFILES}/{profile['profile_id']}"), 403, "permission_denied")
    _error(
        client.post(DEVICES, json={"site_id": site["site_id"], "management_address": "10.70.0.9"}),
        403,
        "permission_denied",
    )
    _ok(client.post(f"{device_url}/polls"), 202)  # network:poll


# --- equipos y aislamiento de sites ------------------------------------------------------------


def test_device_without_credentials_is_pending_configuration(client: TestClient) -> None:
    site = create_site(client, "Pendiente", (NET,))
    device = _ok(
        client.post(DEVICES, json={"site_id": site["site_id"], "management_address": DEVICE_IP}),
        201,
    )
    assert device["monitoring_status"] in ("disabled", "credentials_pending")
    assert device["freshness"] == "none"
    assert device["last_error_code"] is None
    assert {"profile_missing", "sensor_missing"} <= set(device["poll_blockers"])
    assert device["classification"] == "unclassified"
    assert device["vendor"] is None and device["model"] is None


def test_device_address_scope_and_duplicates(client: TestClient) -> None:
    site = create_site(client, "Alcance", (NET,))
    body = {"site_id": site["site_id"], "management_address": "172.20.0.5"}
    _error(client.post(DEVICES, json=body), 422, "network_address_out_of_scope")
    _error(
        client.post(DEVICES, json={**body, "management_address": "8.8.8.8"}),
        422,
        "network_address_public",
    )
    _ok(client.post(DEVICES, json={**body, "management_address": DEVICE_IP}), 201)
    _error(
        client.post(DEVICES, json={**body, "management_address": DEVICE_IP}),
        409,
        "network_device_exists",
    )


def test_same_private_address_in_two_sites(client: TestClient) -> None:
    _a, _sa, _pa, device_a = setup_device(client, "Sede A")
    _b, _sb, _pb, device_b = setup_device(client, "Sede B")
    assert device_a["management_address"] == device_b["management_address"]
    assert device_a["device_id"] != device_b["device_id"]


def test_cross_site_profile_and_sensor_are_refused(client: TestClient) -> None:
    _site_a, sensor_a, profile_a, _device = setup_device(client, "Origen")
    site_b = create_site(client, "Destino", (NET,))
    body = {"site_id": site_b["site_id"], "management_address": "10.70.0.20"}
    _error(
        client.post(DEVICES, json={**body, "profile_id": profile_a["profile_id"]}),
        422,
        "snmp_profile_invalid",
    )
    _error(
        client.post(DEVICES, json={**body, "sensor_id": sensor_a.sensor_id}),
        422,
        "sensor_invalid",
    )


def test_old_sensors_never_receive_snmp_jobs(client: TestClient) -> None:
    site = create_site(client, "Antiguo", (NET,))
    old = SnmpSensor(client, site["site_id"], caps=CAPS, version="0.2.0")
    profile = _ok(client.post(PROFILES, json=v3_profile(site["site_id"])), 201)
    device = _ok(
        client.post(
            DEVICES,
            json={
                "site_id": site["site_id"],
                "management_address": DEVICE_IP,
                "profile_id": profile["profile_id"],
                "sensor_id": old.sensor_id,
            },
        ),
        201,
    )
    assert "sensor_without_snmp" in device["poll_blockers"]
    _error(client.post(f"{DEVICES}/{device['device_id']}/polls"), 409, "network_poll_unavailable")
    assert old.poll() == []


def test_sensor_without_module_capability_skips_the_job(
    client: TestClient,
    db: Session,
) -> None:
    _site, sensor, _profile, device = setup_device(client, "Gating")
    _ok(client.post(f"{DEVICES}/{device['device_id']}/polls"), 202)
    # El sensor se degrada (p. ej. se reinstaló sin pysnmp): deja de declarar snmp.*.
    _ok(sensor.heartbeat(capabilities=CAPS))
    assert sensor.poll() == []


# --- protocolo del sensor ---------------------------------------------------------------------


def test_snmp_poll_end_to_end(
    client: TestClient,
    db: Session,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    _site, sensor, profile, device = setup_device(client, "Extremo")
    records, report = sensor_records()
    assert report.outcome == "completed"
    poll = _ok(client.post(f"{DEVICES}/{device['device_id']}/polls"), 202)
    assert poll["status"] == "queued"
    [job] = sensor.poll()
    assert job["job_type"] == "snmp_inventory"
    params = job["parameters"]
    assert params["target"] == DEVICE_IP and params["snmp_version"] == "v3"
    assert params["profile_id"] == profile["profile_id"]
    # Los parámetros del job nunca llevan secretos ni OIDs.
    assert AUTH not in str(job) and PRIV not in str(job)
    assert not any("oid" in key for key in params)
    started = _ok(sensor.start(job))
    creds = started["credentials"]
    assert creds["auth_password"] == AUTH and creds["priv_password"] == PRIV
    assert creds["profile_id"] == profile["profile_id"] and creds["secret_revision"] == 1
    _ok(sensor.snmp_results(job, records))
    completed = _ok(sensor.snmp_complete(job, report.summary(), batches_sent=1))
    assert completed is not None

    detail = _ok(client.get(f"{DEVICES}/{device['device_id']}"))
    assert detail["sys_name"] == "sw-core-01"
    assert detail["monitoring_status"] == "ok"
    assert detail["freshness"] == "recent"
    assert detail["classification"] == "managed_switch"
    assert detail["classification_confidence"] in ("high", "medium")
    assert detail["classification_evidence"]
    assert detail["model"] == "EX-2400" and detail["serial_number"] == "SN-0001"
    assert detail["interfaces_total"] == 5

    interfaces = _ok(client.get(f"{DEVICES}/{device['device_id']}/interfaces"))["items"]
    by_index = {i["if_index"]: i for i in interfaces}
    assert by_index[100]["port_kind"] == "lag"
    assert by_index[3]["lag_parent"]["name"] in ("Po1", "Port-channel1")
    assert by_index[1]["pvid"] == 10
    assert all(i["evidence_source"].startswith("snmp:") for i in interfaces)

    neighbors = _ok(client.get(f"{DEVICES}/{device['device_id']}/neighbors"))["items"]
    protocols = {n["protocol"]: n for n in neighbors}
    assert set(protocols) == {"lldp", "cdp"}
    assert protocols["lldp"]["remote_sys_name"] == "sw-access-02"
    assert protocols["lldp"]["assessment"] == "reported_by_device"
    assert protocols["cdp"]["remote_mgmt_address"] == "10.0.0.3"
    assert all(n["sensor_id"] == sensor.sensor_id for n in neighbors)

    vlans = _ok(client.get(f"{DEVICES}/{device['device_id']}/vlans"))["items"]
    assert {v["vlan_id"] for v in vlans} == {1, 10}

    macs = _ok(client.get(f"{DEVICES}/{device['device_id']}/mac-entries"))
    entries = {m["mac"]: m for m in macs["items"]}
    assert "01:00:5e:00:00:01" not in entries  # multicast nunca
    learned = entries["00:16:3e:00:00:01"]
    # El puerto 1 tiene un vecino LLDP: una MAC ahí no es la ubicación de un endpoint.
    assert learned["location"] == "uplink_or_shared"
    assert all(m["location"] != "confirmed" for m in macs["items"])

    polls = _ok(client.get(f"{DEVICES}/{device['device_id']}/polls"))["items"]
    assert polls[0]["status"] == "succeeded"
    assert polls[0]["counts"]["interfaces"] == 5
    db.expire_all()
    assert db.scalar(select(SensorJob.status).where(SensorJob.job_type == "snmp_inventory")) in (
        "completed",
        "succeeded",
    )
    # Ni la API de inventario ni el historial ni el audit ni los logs llevan secretos.
    details = " ".join(str(e.details) for e in db.scalars(select(AuditEvent)))
    for secret in (AUTH, PRIV):
        assert secret not in details
        assert secret not in caplog.text
        assert secret not in str(polls)
    assert audit(db, "network_poll_requested")


def test_records_are_refused_on_discovery_jobs_and_vice_versa(client: TestClient) -> None:
    _site, sensor, _profile, device = setup_device(client, "Tipos")
    records, _report = sensor_records()
    _ok(client.post(f"{DEVICES}/{device['device_id']}/polls"), 202)
    [job] = sensor.poll()
    _ok(sensor.start(job))
    observation = {
        "address": DEVICE_IP,
        "ports": [{"port": 161, "state": "open"}],
        "sources": ["tcp"],
        "observed_at": datetime.now(UTC).isoformat(),
    }
    _error(sensor.results(job, [observation]), 422, "sensor_batch_invalid")
    _ok(sensor.snmp_results(job, records[:5]))


def test_duplicate_batches_are_idempotent(client: TestClient) -> None:
    _site, sensor, _profile, device = setup_device(client, "Idem")
    records, report = sensor_records()
    _ok(client.post(f"{DEVICES}/{device['device_id']}/polls"), 202)
    [job] = sensor.poll()
    _ok(sensor.start(job))
    batch = str(uuid.uuid4())
    first = _ok(sensor.snmp_results(job, records, batch))
    again = _ok(sensor.snmp_results(job, records, batch))
    assert again["duplicate"] is True and first["duplicate"] is False
    # Mismo batch_id con contenido distinto: conflicto, nunca se mezcla.
    response = sensor.snmp_results(job, records[:3], batch)
    assert response.status_code == 409, response.text
    _ok(sensor.snmp_complete(job, report.summary(), batches_sent=1))
    interfaces = _ok(client.get(f"{DEVICES}/{device['device_id']}/interfaces"))
    assert interfaces["total"] == 5


def test_auth_failure_is_reported_and_audited(client: TestClient, db: Session) -> None:
    _site, sensor, _profile, device = setup_device(client, "Clave")
    poll = run_poll(
        client,
        sensor,
        device,
        [],
        {"modules": {"system": "failed"}, "error_code": "auth_failed"},
        outcome="failed",
    )
    assert poll["status"] == "failed" and poll["error_code"] == "auth_failed"
    detail = _ok(client.get(f"{DEVICES}/{device['device_id']}"))
    assert detail["last_error_code"] == "auth_failed"
    assert detail["monitoring_status"] == "failing"
    assert detail["freshness"] == "none"  # nunca hubo una consulta correcta
    assert audit(db, "snmp_authentication_failed")


def test_partial_poll_keeps_previous_data_and_is_partial(client: TestClient) -> None:
    _site, sensor, _profile, device = setup_device(client, "Parcial")
    records, report = sensor_records()
    run_poll(client, sensor, device, records, report.summary())
    partial, partial_report = sensor_records(fail_prefix=(1, 3, 6, 1, 2, 1, 2, 2, 1))
    assert partial_report.error_code == "timeout"
    poll = run_poll(client, sensor, device, partial, partial_report.summary())
    assert poll["status"] == "partial"
    detail = _ok(client.get(f"{DEVICES}/{device['device_id']}"))
    assert detail["monitoring_status"] == "partial"
    # Un módulo que no se leyó no borra lo que ya se sabía de él.
    assert _ok(client.get(f"{DEVICES}/{device['device_id']}/interfaces"))["total"] == 5


def test_cancel_queued_poll(client: TestClient, db: Session) -> None:
    _site, sensor, _profile, device = setup_device(client, "Cancelar")
    poll = _ok(client.post(f"{DEVICES}/{device['device_id']}/polls"), 202)
    _error(client.post(f"{DEVICES}/{device['device_id']}/polls"), 409, "network_poll_busy")
    cancelled = _ok(client.post(f"{NETWORK}/polls/{poll['poll_id']}/cancel"))
    assert cancelled["status"] == "cancelled"
    assert sensor.poll() == []
    _error(client.post(f"{NETWORK}/polls/{uuid.uuid4()}/cancel"), 404, "network_poll_not_found")


def test_expired_job_closes_the_poll(client: TestClient, db: Session) -> None:
    from app.services.sensor_service import sweep

    _site, _sensor, _profile, device = setup_device(client, "Caduca")
    _ok(client.post(f"{DEVICES}/{device['device_id']}/polls"), 202)
    db.execute(update(SensorJob).values(expires_at=datetime.now(UTC) - timedelta(minutes=1)))
    db.commit()
    sweep(db, datetime.now(UTC))
    db.commit()
    db.expire_all()
    status = db.scalar(select(NetworkDevicePoll.status))
    assert status in ("expired", "failed")
    polls = _ok(client.get(f"{DEVICES}/{device['device_id']}/polls"))["items"]
    assert polls[0]["error_code"] in ("job_expired", "sensor_lost")


def test_reassigning_the_sensor_cancels_open_polls(client: TestClient, db: Session) -> None:
    site, sensor, _profile, device = setup_device(client, "Reasignar")
    _ok(client.post(f"{DEVICES}/{device['device_id']}/polls"), 202)
    other = SnmpSensor(client, site["site_id"])
    _ok(
        client.patch(
            f"{DEVICES}/{device['device_id']}",
            json={"version": device["version"], "sensor_id": other.sensor_id},
        )
    )
    assert sensor.poll() == []
    db.expire_all()
    assert db.scalar(select(NetworkDevicePoll.status)) == "cancelled"


def test_cross_site_spoofed_records_cannot_land_in_another_site(client: TestClient) -> None:
    # El sensor de la sede B intenta enviar resultados al job de la sede A.
    _a, sensor_a, _pa, device_a = setup_device(client, "Victima")
    _b, sensor_b, _pb, _device_b = setup_device(client, "Atacante")
    records, _report = sensor_records()
    _ok(client.post(f"{DEVICES}/{device_a['device_id']}/polls"), 202)
    [job] = sensor_a.poll()
    assert sensor_b.poll() == []
    assert sensor_b.start(job).status_code in (403, 404, 409)
    assert sensor_b.snmp_results(job, records).status_code in (403, 404, 409)


def test_mac_locations_never_merge_sites(client: TestClient) -> None:
    _a, sensor_a, _pa, device_a = setup_device(client, "Mac A")
    _b, sensor_b, _pb, device_b = setup_device(client, "Mac B")
    records, report = sensor_records()
    run_poll(client, sensor_a, device_a, records, report.summary())
    run_poll(client, sensor_b, device_b, records, report.summary())
    found = _ok(client.get(f"{NETWORK}/mac-locations", params={"mac": "00-16-3E-00-00-02"}))
    assert found["mac"] == "00:16:3e:00:00:02"
    sites = {item["site_name"] for item in found["items"]}
    assert sites == {"Mac A", "Mac B"}
    assert len({item["device"]["device_id"] for item in found["items"]}) == 2
    _error(client.get(f"{NETWORK}/mac-locations", params={"mac": "zz"}), 422, "validation_error")


def test_historical_evidence_is_never_shown_as_online(
    client: TestClient,
    db: Session,
) -> None:
    _site, sensor, _profile, device = setup_device(client, "Historico")
    records, report = sensor_records()
    run_poll(client, sensor, device, records, report.summary())
    db.execute(
        text(
            "UPDATE network_devices SET last_success_at = now() - interval '3 days', "
            "last_poll_at = now() - interval '3 days'"
        )
    )
    db.commit()
    detail = _ok(client.get(f"{DEVICES}/{device['device_id']}"))
    assert detail["freshness"] == "historical"


def test_scheduler_skips_devices_pending_configuration(
    client: TestClient,
    db: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.services.network_jobs import schedule_due_polls

    site = create_site(client, "Agenda", (NET,))
    _ok(
        client.post(
            DEVICES,
            json={
                "site_id": site["site_id"],
                "management_address": DEVICE_IP,
                "monitoring_enabled": True,
            },
        ),
        201,
    )
    _s2, _sensor, _profile, _device = setup_device(client, "Agenda2", address="10.70.0.6")
    monkeypatch.setenv("SNMP_POLL_INTERVAL_MINUTES", "15")
    get_settings.cache_clear()
    try:
        result = schedule_due_polls(db, get_settings())
    finally:
        monkeypatch.setenv("SNMP_POLL_INTERVAL_MINUTES", "")
        get_settings.cache_clear()
    db.expire_all()
    polls = list(db.scalars(select(NetworkDevicePoll)))
    assert len(polls) == 1 and polls[0].trigger == "scheduled"
    assert result


# --- unidades ---------------------------------------------------------------------------------


def test_sensor_records_match_the_backend_contract() -> None:
    adapter: TypeAdapter[Any] = TypeAdapter(SnmpRecord)
    for mib in ("switch_mib", "minimal_mib"):
        records, _report = sensor_records(mib)
        assert records
        for record in records:
            adapter.validate_python(record)


def test_classifier_uses_only_snmp_evidence_and_never_invents() -> None:
    import dataclasses

    names = {f.name for f in dataclasses.fields(classify.DeviceEvidence)}
    # Ni puertos TCP abiertos ni texto libre de sysDescr: solo evidencia SNMP estructurada.
    assert not any("port" in n and "tcp" in n for n in names)
    assert "open_ports" not in names and "sys_descr" not in names
    empty = classify.classify(classify.DeviceEvidence())
    assert empty.classification == "unclassified" and empty.confidence == "none"
    assert empty.vendor is None and empty.model is None
    switch = classify.classify(
        classify.DeviceEvidence(
            sys_services=2,
            ip_forwarding=False,
            lldp_capabilities=["bridge"],
            bridge_ports=24,
            physical_ports=24,
        )
    )
    assert switch.classification == "managed_switch"
    assert switch.evidence and all(e["source"] for e in switch.evidence)
    # Un número de empresa desconocido no se convierte en un fabricante inventado.
    unknown = classify.classify(classify.DeviceEvidence(sys_object_id="1.3.6.1.4.1.999999.1"))
    assert unknown.vendor is None
    assert unknown.enterprise_number == 999999
