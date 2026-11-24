"""Fase 7E.1: aprobación de captura NDR, heartbeat e ingesta de lotes del sensor.

El lote de ejemplo (fixtures/ndr_batch_sample.json) lo generó el pipeline real del sensor
0.8.0 (`ndr-replay`) a partir de tramas SINTÉTICAS construidas en sensor/tests/ndr_packets.py:
no hay tráfico real. Así el contrato sensor -> servidor se prueba con la salida verdadera
del sensor y no con un JSON escrito a mano.
"""

import copy
import json
import re
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, func, select, update
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.models.audit import AuditEvent
from app.models.ndr import NdrBatch, NdrFlow, NdrProtocolObservation
from app.models.site import Sensor
from app.ndr.retention import purge_ndr
from tests.conftest import authenticate
from tests.test_sites_sensors import CAPS, SensorSim, _error, _ok, default_site

API = "/api/v1"
NDR = f"{API}/ndr"
NDR_CAP = "network.ndr.passive"
SAMPLE = Path(__file__).parent / "fixtures" / "ndr_batch_sample.json"
_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}T")


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


def _shift(value: Any, delta: timedelta) -> Any:
    if isinstance(value, dict):
        return {k: _shift(v, delta) for k, v in value.items()}
    if isinstance(value, list):
        return [_shift(v, delta) for v in value]
    if isinstance(value, str) and _ISO.match(value):
        return (datetime.fromisoformat(value) + delta).isoformat()
    return value


def sample_batch(interface: str = "lan", minutes_ago: int = 5) -> dict[str, Any]:
    """Lote de ejemplo con las marcas movidas a "hace unos minutos" (calculado en el test)."""
    raw = json.loads(SAMPLE.read_text(encoding="utf-8"))
    anchor = datetime.fromisoformat(raw["window_end"])
    target = datetime.now(UTC) - timedelta(minutes=minutes_ago)
    batch: dict[str, Any] = _shift(raw, target - anchor)
    batch["interface"] = interface
    batch["batch_id"] = str(uuid.uuid4())
    return batch


def ndr_sensor(client: TestClient, name: str = "ndr-sensor") -> SensorSim:
    site = default_site(client)
    sensor = SensorSim.__new__(SensorSim)
    sensor.client = client
    token = _ok(
        client.post(
            f"{API}/sensors/enrollment-tokens", json={"site_id": site["site_id"], "name": name}
        ),
        201,
    )["token"]
    body = _ok(
        client.post(
            f"{API}/sensor/enroll",
            json={
                "hostname": "sensor-host",
                "platform": "linux",
                "sensor_version": "0.8.0",
                "capabilities": [*CAPS, NDR_CAP],
            },
            headers={"X-Sensor-Enrollment-Token": token},
        ),
        201,
    )
    sensor.credential = body["credential"]
    sensor.sensor_id = body["sensor_id"]
    sensor.site_id = site["site_id"]
    sensor.config = body["config"]
    return sensor


def approve(
    client: TestClient, sensor: SensorSim, revision: int = 0, **overrides: Any
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "enabled": True,
        "interfaces": ["lan"],
        "observation_point": "SPAN del switch core, puerto 24",
        "confirm_passive_authorized": True,
        "dns_metadata": True,
        "tls_metadata": True,
        "expected_revision": revision,
        **overrides,
    }
    result: dict[str, Any] = _ok(client.put(f"{NDR}/sensors/{sensor.sensor_id}/config", json=body))
    return result


def send(sensor: SensorSim, batch: dict[str, Any]) -> Any:
    return sensor.call("/ndr/batches", batch)


# --- configuración y heartbeat -----------------------------------------------------------------


def test_heartbeat_ndr_block_only_for_capable_sensors(client: TestClient) -> None:
    legacy = SensorSim(client, default_site(client)["site_id"], "legacy")
    config = _ok(legacy.heartbeat())["config"]
    assert config["ndr"] is None
    sensor = ndr_sensor(client)
    block = _ok(sensor.heartbeat())["config"]["ndr"]
    assert block["enabled"] is False and block["revision"] == 0 and block["interfaces"] == []
    # Lo privado va apagado por defecto y el lote cabe en el límite de cuerpo del servidor.
    assert block["dns_metadata"] is False and block["tls_metadata"] is False
    assert block["max_batch_bytes"] == get_settings().sensor_max_request_kb * 1024


def test_approval_requires_point_confirmation_and_admin(
    client: TestClient, engine: Engine, db: Session
) -> None:
    sensor = ndr_sensor(client)
    url = f"{NDR}/sensors/{sensor.sensor_id}/config"
    base = {"enabled": True, "interfaces": ["lan"], "expected_revision": 0}
    _error(client.put(url, json=base), 422, "ndr_observation_point_required")
    _error(
        client.put(url, json={**base, "observation_point": "TAP planta 1"}),
        422,
        "ndr_confirmation_required",
    )
    _error(
        client.put(url, json={**base, "interfaces": [], "observation_point": "TAP"}),
        422,
        "ndr_interfaces_required",
    )
    # Un alias con forma de dispositivo o ruta no se acepta: el servidor nunca envía nombres.
    bad = client.put(url, json={**base, "interfaces": ["\\Device\\NPF_{x}"]})
    assert bad.status_code == 422
    approved = approve(client, sensor)
    assert approved["revision"] == 1 and approved["interfaces"] == ["lan"]
    _error(client.put(url, json={**base, "enabled": False}), 409, "ndr_config_changed")
    events = db.scalars(
        select(AuditEvent).where(AuditEvent.action == "ndr_capture_config_changed")
    ).all()
    assert len(events) == 1 and events[0].details is not None
    assert events[0].details["to"]["interfaces"] == ["lan"]
    authenticate(client, engine, "analyst")
    _error(client.put(url, json={**base, "expected_revision": 1}), 403, "permission_denied")


def test_heartbeat_applies_approval_and_stores_health(client: TestClient) -> None:
    sensor = ndr_sensor(client)
    approve(client, sensor)
    health = {
        "state": "running",
        "config_revision": 1,
        "interfaces": [
            {
                "name": "lan",
                "state": "running",
                "backend": "af_packet",
                "packets_seen": 100,
                "packets_processed": 100,
                "budget_dropped": 0,
                "malformed": 0,
                "cpu_percent": 3.5,
                "pps_budget": 20000,
                "degraded_reasons": [],
            }
        ],
        "spool_items": 0,
        "spool_bytes": 0,
        "spool_dropped": 0,
    }
    block = _ok(sensor.heartbeat(ndr=health))["config"]["ndr"]
    assert block["enabled"] is True and block["interfaces"] == ["lan"]
    assert block["dns_metadata"] is True and block["revision"] == 1
    listed = _ok(client.get(f"{NDR}/sensors"))["items"]
    item = next(i for i in listed if i["sensor_id"] == sensor.sensor_id)
    assert item["capable"] and item["capture_state"] == "running"
    assert item["interfaces"][0]["backend"] == "af_packet"
    # Un estado con claves desconocidas (o un dispositivo) se rechaza entero.
    bad = dict(health, interfaces=[{"name": "lan", "state": "running", "device": "eth0"}])
    assert sensor.heartbeat(ndr=bad).status_code == 422


def test_disabled_sensor_gets_capture_disabled(client: TestClient, db: Session) -> None:
    sensor = ndr_sensor(client)
    approve(client, sensor)
    db.execute(
        update(Sensor)
        .where(Sensor.public_id == uuid.UUID(sensor.sensor_id))
        .values(status="disabled")
    )
    db.commit()
    block = _ok(sensor.heartbeat())["config"]["ndr"]
    assert block["enabled"] is False and block["interfaces"] == []
    _error(send(sensor, sample_batch()), 403, "sensor_disabled")


# --- ingesta -----------------------------------------------------------------------------------


def test_batch_requires_approved_interface(client: TestClient) -> None:
    sensor = ndr_sensor(client)
    _error(send(sensor, sample_batch()), 403, "ndr_not_authorized")
    approve(client, sensor)
    _error(send(sensor, sample_batch(interface="dmz")), 403, "ndr_not_authorized")
    assert send(sensor, sample_batch()).status_code == 200


def test_ingest_stores_flows_and_metadata_and_dedups(client: TestClient, db: Session) -> None:
    sensor = ndr_sensor(client)
    approve(client, sensor)
    batch = sample_batch()
    first = _ok(send(sensor, batch))
    assert first == {
        "batch_id": batch["batch_id"],
        "duplicate": False,
        "flows": 3,
        "observations": 5,
    }
    again = _ok(send(sensor, batch))
    assert again["duplicate"] is True
    assert db.scalar(select(func.count()).select_from(NdrFlow)) == 3
    assert db.scalar(select(func.count()).select_from(NdrBatch)) == 1
    flows = _ok(client.get(f"{NDR}/flows", params={"port": 443}))
    assert flows["total"] == 1
    tcp = flows["items"][0]
    assert tcp["src_ip"] == "10.50.0.5" and tcp["dst_ip"] == "10.50.0.9"
    assert tcp["state"] == "closed" and "tls" in tcp["app_hints"]
    dns = _ok(client.get(f"{NDR}/observations", params={"kind": "dns"}))["items"]
    assert dns[0]["name"] == "files.example" and dns[0]["data"]["answers"] == ["10.50.0.20"]
    tls = _ok(client.get(f"{NDR}/observations", params={"kind": "tls"}))["items"]
    assert tls[0]["name"] == "intranet.example"
    dhcp = _ok(client.get(f"{NDR}/observations", params={"kind": "dhcp"}))["items"]
    assert dhcp[0]["data"]["routers"] == ["10.50.0.1"]
    overview = _ok(client.get(f"{NDR}/overview"))
    assert overview["flows"] == 3 and overview["packets_seen"] == 10
    assert overview["observations"]["arp"] == 2 and overview["sensors_enabled"] == 1


def test_segments_merge_with_maximum_and_metadata_accumulates(
    client: TestClient, db: Session
) -> None:
    sensor = ndr_sensor(client)
    approve(client, sensor)
    batch = sample_batch()
    _ok(send(sensor, batch))
    later = copy.deepcopy(batch)
    later["batch_id"] = str(uuid.uuid4())
    later["stats"] = None
    tcp = next(f for f in later["flows"] if f["dst_port"] == 443)
    tcp["segment"] = 1
    tcp["bytes_out"] += 1000
    tcp["flags"] = ["retransmissions"]
    # Un segmento antiguo reenviado (contadores menores) no resta nada.
    stale = copy.deepcopy(next(f for f in batch["flows"] if f["dst_port"] == 443))
    stale["bytes_out"] = 1
    later["flows"] = [tcp, stale]
    _ok(send(sensor, later))
    row = db.scalar(select(NdrFlow).where(NdrFlow.dst_port == 443))
    assert row is not None
    original = next(f for f in batch["flows"] if f["dst_port"] == 443)
    assert row.bytes_out == original["bytes_out"] + 1000
    assert row.segments == 2 and "retransmissions" in row.flags
    dns = db.scalar(select(NdrProtocolObservation).where(NdrProtocolObservation.kind == "dns"))
    assert dns is not None and dns.count == 4 and dns.data["queries"] == 2


def test_future_timestamps_are_clamped(client: TestClient, db: Session) -> None:
    sensor = ndr_sensor(client)
    approve(client, sensor)
    batch = sample_batch(minutes_ago=-600)  # reloj del sensor 10 h adelantado
    _ok(send(sensor, batch))
    limit = datetime.now(UTC) + timedelta(seconds=get_settings().sensor_max_clock_skew_seconds)
    newest = db.scalar(select(func.max(NdrFlow.last_seen)))
    assert newest is not None and newest <= limit


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b["dns"][0].update(qname="<script>alert(1)</script>"),
        lambda b: b["flows"][0].update(payload="AAAA"),
        lambda b: b["flows"][0].update(src_ip="not-an-ip"),
        lambda b: b["flows"][0].update(bytes_out=-1),
        lambda b: b["tls"][0].update(sni="a" * 300),
        lambda b: b.update(interface="eth0 && reboot"),
    ],
)
def test_malformed_batches_are_rejected(client: TestClient, mutate: Any) -> None:
    sensor = ndr_sensor(client)
    approve(client, sensor)
    batch = sample_batch()
    mutate(batch)
    assert send(sensor, batch).status_code == 422


def test_evidence_needs_ndr_evidence_permission(client: TestClient, engine: Engine) -> None:
    authenticate(client, engine, "viewer")
    assert client.get(f"{NDR}/overview").status_code == 200
    assert client.get(f"{NDR}/sensors").status_code == 200
    _error(client.get(f"{NDR}/flows"), 403, "permission_denied")
    _error(client.get(f"{NDR}/observations"), 403, "permission_denied")
    authenticate(client, engine, "analyst")
    assert client.get(f"{NDR}/flows").status_code == 200


def test_retention_purges_old_ndr_rows(client: TestClient, db: Session) -> None:
    sensor = ndr_sensor(client)
    approve(client, sensor)
    _ok(send(sensor, sample_batch()))
    settings = get_settings()
    future = datetime.now(UTC) + timedelta(days=(settings.ndr_observation_retention_days or 0) + 1)
    counts = purge_ndr(db, settings, future)
    db.commit()
    # Desde 7E.2 la purga también informa de anomalías cerradas y asociaciones IP-MAC.
    assert {k: counts[k] for k in ("ndr_flows", "ndr_protocol_observations", "ndr_batches")} == {
        "ndr_flows": 3,
        "ndr_protocol_observations": 5,
        "ndr_batches": 1,
    }
