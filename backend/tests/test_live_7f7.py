"""Fase 7F.7: stream SSE del Live SOC.

Datos SINTÉTICOS creados en la base de pruebas. Cada stream se cierra solo al cumplir
LIVE_MAX_STREAM_SECONDS (reducido aquí a 1-3 s) con un evento `reconnect`.
"""

import json
import threading
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select, update
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.core.permissions import Role, permissions_for
from app.live.stream import Cursor, StreamSlots, allowed_channels, sse
from app.models.alert import Alert, AlertRule, AlertSeverity, AlertStatus
from app.models.detection import (
    Detection,
    DetectionConfidence,
    DetectionSeverity,
    DetectionStatus,
)
from app.models.user import UserSession
from tests.conftest import authenticate
from tests.test_ndr_7e4 import _asset
from tests.test_siem_7f3_suricata import _site, eve_alert, import_eve, suricata_source
from tests.test_siem_7f3_suricata import ts as eve_ts

STREAM = "/api/v1/live/stream"


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


def _fast(client: TestClient, **overrides: Any) -> None:
    values: dict[str, Any] = {
        "live_poll_interval_ms": 100,
        "live_max_stream_seconds": 1,
        "live_heartbeat_seconds": 1,
        **overrides,
    }
    settings = get_settings().model_copy(update=values)
    app: Any = client.app
    app.dependency_overrides[get_settings] = lambda: settings


def read(
    client: TestClient, headers: dict[str, str] | None = None, **params: Any
) -> list[dict[str, Any]]:
    """Mensajes SSE (event, id, data) hasta que el servidor cierra el stream."""
    messages: list[dict[str, Any]] = []
    with client.stream("GET", STREAM, headers=headers or {}, params=params) as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        current: dict[str, Any] = {}
        for line in response.iter_lines():
            if line == "":
                # El bloque "retry:" inicial no es un evento.
                if "event" in current:
                    messages.append(current)
                current = {}
            elif line.startswith(":"):
                messages.append({"event": "comment", "data": line})
            else:
                key, _, value = line.partition(": ")
                current[key] = json.loads(value) if key == "data" else value
    return messages


def _detection(db: Session, asset_id: int, title: str = "Fuerza bruta") -> Detection:
    now = datetime.now(UTC)
    detection = Detection(
        asset_id=asset_id,
        rule_id="AUTH-001",
        rule_version=1,
        rule_category="authentication",
        kind="threshold",
        dedup_key=uuid.uuid4().hex,
        severity=DetectionSeverity.HIGH,
        confidence=DetectionConfidence.MEDIUM,
        status=DetectionStatus.OPEN,
        title=title,
        summary="Sintética de test",
        details={"secret_detail": "no debe salir en el stream"},
        first_seen_at=now - timedelta(minutes=1),
        last_seen_at=now,
        created_at=now,
        updated_at=now,
    )
    db.add(detection)
    db.commit()
    return detection


def _alert(db: Session, asset_id: int, message: str) -> Alert:
    alert = Alert(
        asset_id=asset_id,
        rule=AlertRule.HIGH_CPU,
        severity=AlertSeverity.WARNING,
        status=AlertStatus.OPEN,
        message=message,
        opened_at=datetime.now(UTC),
    )
    db.add(alert)
    db.commit()
    return alert


def test_resume_delivers_real_rows_with_cursors(client: TestClient, db: Session) -> None:
    _fast(client)
    asset = _asset(db, _site(db, client), "10.70.0.20")
    detection = _detection(db, asset.id)
    import_eve(client, suricata_source(client), eve_alert())
    messages = read(client, headers={"Last-Event-ID": "d0-a0-i0-s0"})
    events = [m["event"] for m in messages]
    assert events[0] == "status" and messages[0]["data"]["state"] == "catching_up"
    assert set(messages[0]["data"]["channels"]) == {"detection", "alert", "incident", "siem"}
    [det] = [m for m in messages if m["event"] == "detection"]
    assert det["data"]["id"] == str(detection.public_id) and det["data"]["severity"] == "high"
    # Solo campos de catálogo: los detalles de la detección no viajan por el stream.
    assert "secret_detail" not in json.dumps(det)
    [siem] = [m for m in messages if m["event"] == "siem"]
    assert siem["data"]["source_type"] == "suricata_eve"
    assert Cursor.decode(siem["id"]) is not None
    assert any(m["event"] == "status" and m["data"]["state"] == "live" for m in messages)
    assert events[-1] == "reconnect"
    # Reanudar desde el último id no repite nada.
    again = read(client, headers={"Last-Event-ID": messages[-1]["id"]})
    assert [m for m in again if m["event"] in ("detection", "siem")] == []


def test_new_rows_arrive_while_connected(client: TestClient, engine: Engine, db: Session) -> None:
    _fast(client, live_max_stream_seconds=2)
    asset = _asset(db, _site(db, client), "10.70.0.21")

    def later() -> None:
        with sessionmaker(bind=engine)() as other:
            threading.Event().wait(0.5)
            _alert(other, asset.id, "CPU alta")

    worker = threading.Thread(target=later)
    worker.start()
    messages = read(client)
    worker.join()
    assert messages[0]["data"]["state"] == "live"
    [alert] = [m for m in messages if m["event"] == "alert"]
    assert alert["data"]["message"] == "CPU alta" and alert["data"]["asset_name"]
    assert any(m["event"] == "comment" for m in messages)


def test_viewer_gets_no_siem_channel(client: TestClient, engine: Engine) -> None:
    _fast(client)
    import_eve(client, suricata_source(client), eve_alert())
    authenticate(client, engine, "viewer")
    messages = read(client, headers={"Last-Event-ID": "d0-a0-i0-s0"})
    assert "siem" not in messages[0]["data"]["channels"]
    assert [m for m in messages if m["event"] == "siem"] == []
    assert allowed_channels(permissions_for(Role.VIEWER)) == ("detection", "alert", "incident")


def test_hostile_text_cannot_inject_sse_fields(client: TestClient, db: Session) -> None:
    _fast(client)
    asset = _asset(db, _site(db, client), "10.70.0.22")
    _alert(db, asset.id, "x\n\nevent: session_ended\ndata: {}")
    messages = read(client, headers={"Last-Event-ID": "d0-a0-i0-s0"})
    assert [m["event"] for m in messages].count("session_ended") == 0
    [alert] = [m for m in messages if m["event"] == "alert"]
    assert alert["data"]["message"].startswith("x\n\nevent:")
    assert "\n" not in sse("alert", {"m": "a\nb"}).strip().split("\n")[-1][6:].replace("\\n", "")


def test_bad_last_event_id_starts_at_present(client: TestClient, db: Session) -> None:
    _fast(client)
    asset = _asset(db, _site(db, client), "10.70.0.23")
    _detection(db, asset.id)
    for value in ("d-1-a0-i0-s0", "' OR 1=1 --", "d1-a2-i3", "x" * 99):
        messages = read(client, headers={"Last-Event-ID": value})
        assert messages[0]["data"]["state"] == "live"
        assert [m for m in messages if m["event"] == "detection"] == []


def test_large_backlog_is_skipped_not_buffered(client: TestClient, db: Session) -> None:
    _fast(client, live_backlog_limit=10)
    import_eve(
        client,
        suricata_source(client),
        *[eve_alert(flow_id=i, timestamp=eve_ts(200 + i)) for i in range(12)],
    )
    messages = read(client, headers={"Last-Event-ID": "d0-a0-i0-s0"})
    assert messages[0]["data"] == {"state": "degraded", "reason": "backlog_skipped"}
    assert [m for m in messages if m["event"] == "siem"] == []


def test_site_filter_and_unknown_site(client: TestClient, db: Session) -> None:
    _fast(client)
    asset = _asset(db, _site(db, client), "10.70.0.24")
    _detection(db, asset.id)
    from app.models.site import Site

    site = db.get(Site, _site(db, client))
    assert site is not None
    messages = read(client, headers={"Last-Event-ID": "d0-a0-i0-s0"}, site_id=str(site.public_id))
    assert len([m for m in messages if m["event"] == "detection"]) == 1
    assert client.get(STREAM, params={"site_id": str(uuid.uuid4())}).status_code == 404


def test_stream_limits_per_user(client: TestClient) -> None:
    _fast(client, live_max_streams_per_user=1, live_max_stream_seconds=2)
    with client.stream("GET", STREAM) as first:
        assert first.status_code == 200
        second = client.get(STREAM)
        assert second.status_code == 429 and second.json()["error"]["code"] == "live_stream_limit"
        for _ in first.iter_lines():
            pass
    # Liberado al cerrar: se puede volver a abrir.
    assert read(client)[-1]["event"] == "reconnect"


def test_slots_are_bounded() -> None:
    slots = StreamSlots()
    assert slots.acquire(1, 2, 3) and slots.acquire(1, 2, 3)
    assert not slots.acquire(1, 2, 3)
    assert slots.acquire(2, 2, 3) and not slots.acquire(3, 2, 3)
    slots.release(1)
    assert slots.acquire(3, 2, 3) and slots.total == 3


def test_revoked_session_ends_the_stream(client: TestClient, engine: Engine) -> None:
    _fast(client, live_max_stream_seconds=10, live_revalidate_seconds=1)
    user = authenticate(client, engine, "analyst")
    seen: list[str] = []
    with client.stream("GET", STREAM) as response:
        assert response.status_code == 200
        for line in response.iter_lines():
            if line.startswith("event: "):
                seen.append(line[7:])
                if line == "event: status":
                    # Ya conectado: se revoca la sesión (logout en otra pestaña, admin...).
                    with sessionmaker(bind=engine)() as other:
                        other.execute(
                            update(UserSession)
                            .where(UserSession.user_id == user.id)
                            .values(revoked_at=datetime.now(UTC), revoked_reason="test")
                        )
                        other.commit()
    assert seen[-1] == "session_ended"


def test_stream_does_not_extend_idle_session(client: TestClient, engine: Engine) -> None:
    _fast(client, live_max_stream_seconds=2, live_revalidate_seconds=1)
    user = authenticate(client, engine, "analyst")
    with sessionmaker(bind=engine)() as other:
        before = other.scalar(
            select(UserSession.last_seen_at).where(UserSession.user_id == user.id)
        )
    read(client)
    with sessionmaker(bind=engine)() as other:
        after = other.scalar(select(UserSession.last_seen_at).where(UserSession.user_id == user.id))
    assert before == after


def test_anonymous_is_rejected(client: TestClient) -> None:
    client.cookies.clear()
    assert client.get(STREAM).status_code == 401
