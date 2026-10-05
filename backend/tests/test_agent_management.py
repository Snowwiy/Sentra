"""Agent management from the dashboard: listing, console guard, tokens, revoke, reinstate."""

import hashlib
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings, get_settings
from app.models.asset import Asset, MonitoringMethod
from app.models.audit import AuditEvent
from app.services import agent_management_service
from app.services.agent_management_service import suggested_server_urls
from tests.conftest import TEST_ADMIN_KEY, agent_payload, authenticate
from tests.test_alert_rules import _event
from tests.test_inventory import inventory_payload
from tests.test_telemetry import telemetry_payload

CONSOLE = "/api/v1/console"
AGENTS = "/api/v1/agents"
REGISTER = "/api/v1/agents/register"
# Fase 4G: las cabeceras de la antigua consola local ya no hacen falta (ni dan acceso); se
# mantienen vacías para no reescribir cada llamada.
LOCAL: dict[str, str] = {}


def _settings(**changes: Any) -> Settings:
    return get_settings().model_copy(update=changes)


@pytest.fixture
def console(client: TestClient) -> TestClient:
    """El dashboard con sesión de admin (el `client` del conftest ya la tiene)."""
    return client


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


def _create_token(console: TestClient, **body: Any) -> dict[str, Any]:
    response = console.post(f"{CONSOLE}/enrollment-tokens", json=body, headers=LOCAL)
    assert response.status_code == 201, response.text
    created: dict[str, Any] = response.json()
    return created


def _enroll(client: TestClient, token: str, **host: Any) -> tuple[Any, dict[str, Any]]:
    payload = agent_payload(**host)
    response = client.post(REGISTER, json=payload, headers={"X-Enrollment-Token": token})
    return response, payload


def _agent(client: TestClient, asset_id: str) -> dict[str, Any]:
    found: dict[str, Any] = next(
        a for a in client.get(AGENTS).json()["items"] if a["asset_id"] == asset_id
    )
    return found


# --- Acceso a la gestión de agentes (Fase 4G: sesión + permisos) ---------------------------


@pytest.mark.parametrize("role", ["analyst", "viewer"])
def test_only_admins_manage_agents_and_tokens(
    client: TestClient, engine: Engine, role: str
) -> None:
    response, _ = _enroll(client, _create_token(client)["token"])
    asset_id = response.json()["asset_id"]
    with TestClient(client.app) as other:
        authenticate(other, engine, role)
        for method, path in (
            ("GET", CONSOLE),
            ("POST", f"{CONSOLE}/enrollment-tokens"),
            ("GET", f"{CONSOLE}/enrollment-tokens"),
            ("POST", f"{CONSOLE}/agents/{asset_id}/revoke"),
            ("POST", f"{CONSOLE}/agents/{asset_id}/reinstate"),
        ):
            refused = other.request(method, path, json={})
            assert refused.status_code == 403, (method, path)
            assert refused.json()["error"]["code"] == "permission_denied"
        # Lectura sí: la lista de agentes y su estado (sin secretos).
        assert other.get(AGENTS).status_code == 200
    assert _agent(client, asset_id)["credential_status"] == "active"


def test_console_requires_a_session_whatever_the_origin(client: TestClient) -> None:
    # La guarda local (loopback, X-Sentra-Console) ya no da acceso: sin sesión es 401 también
    # desde el propio servidor, y la clave de administración no sirve de cookie.
    with TestClient(client.app, base_url="http://localhost:8000", client=("127.0.0.1", 1)) as local:
        for headers in (
            {"X-Sentra-Console": "1", "Origin": "http://localhost:5173"},
            {"X-Admin-Key": TEST_ADMIN_KEY},
        ):
            response = local.get(CONSOLE, headers=headers)
            assert response.status_code == 401
            assert response.json()["error"]["code"] == "not_authenticated"


def test_console_answers_an_admin_from_another_lan_machine(
    client: TestClient, engine: Engine
) -> None:
    with TestClient(
        client.app, base_url="http://192.168.50.201:8000", client=("192.168.50.20", 1)
    ) as lan:
        authenticate(lan, engine, "admin")
        response = lan.get(CONSOLE, headers={"Origin": "http://192.168.50.201:8000"})
        created = lan.post(
            f"{CONSOLE}/enrollment-tokens",
            json={},
            headers={"Origin": "http://192.168.50.201:8000"},
        )
    assert response.status_code == 200, response.text
    assert response.json()["enrollment_token_ttl_minutes"] == 15
    assert created.status_code == 201, created.text


def test_console_suggests_the_configured_server_url(client: TestClient) -> None:
    client.app.dependency_overrides[get_settings] = lambda: _settings(  # type: ignore[attr-defined]
        agent_server_url="http://192.168.50.201:8000"
    )
    info = client.get(CONSOLE).json()
    assert info["suggested_server_urls"] == ["http://192.168.50.201:8000"]
    assert info["server_url_configured"] is True


def test_suggested_urls_use_lan_addresses_never_localhost(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert suggested_server_urls(None, 8000, lambda: ["192.168.50.201", "10.0.0.5"]) == [
        "http://192.168.50.201:8000",
        "http://10.0.0.5:8000",
    ]
    assert suggested_server_urls(None, 80, lambda: ["192.168.1.2"]) == ["http://192.168.1.2"]
    for address in agent_management_service.local_ipv4_addresses():
        assert not address.startswith("127.") and address != "0.0.0.0"  # noqa: S104


def test_agent_server_url_setting_is_validated() -> None:
    assert Settings(database_url="postgresql://x", agent_server_url=" ").agent_server_url is None
    url = Settings(
        database_url="postgresql://x", agent_server_url="https://sentra.lan/"
    ).agent_server_url
    assert url == "https://sentra.lan"
    with pytest.raises(ValueError, match="agent_server_url"):
        Settings(database_url="postgresql://x", agent_server_url="ftp://x; rm -rf /")


# --- Enrollment tokens through the console ------------------------------------------------


def test_token_is_shown_once_and_never_listed(console: TestClient, client: TestClient) -> None:
    created = _create_token(console, expected_platform="linux", expected_hostname="pc-ana")
    token = created["token"]
    assert token.startswith("sentra_et_")
    assert created["created_via"] == "dashboard" and created["max_uses"] == 1
    assert created["state"] == "active" and created["expected_hostname"] == "pc-ana"

    listing = console.get(f"{CONSOLE}/enrollment-tokens", headers=LOCAL)
    assert listing.status_code == 200
    assert listing.headers["Cache-Control"] == "no-store"
    text = listing.text
    assert token not in text and hashlib.sha256(token.encode()).hexdigest() not in text
    [item] = listing.json()["items"]
    assert "token" not in item and "token_hash" not in item
    assert item["token_id"] == created["token_id"] and item["state"] == "active"


def test_console_token_enrolls_once_then_is_consumed(
    console: TestClient, client: TestClient
) -> None:
    created = _create_token(console, expected_platform="linux")
    response, _ = _enroll(client, created["token"], os_name="Linux", hostname="pc-linux")
    assert response.status_code == 201
    asset_id = response.json()["asset_id"]

    again, _ = _enroll(client, created["token"], os_name="Linux")
    assert again.status_code == 401  # a consumed token cannot be reused

    [item] = console.get(f"{CONSOLE}/enrollment-tokens", headers=LOCAL).json()["items"]
    assert item["state"] == "consumed" and item["last_asset_id"] == asset_id
    revoke = console.post(f"{CONSOLE}/enrollment-tokens/{item['token_id']}/revoke", headers=LOCAL)
    assert revoke.status_code == 409  # consumed: revoke the agent instead
    agent = _agent(client, asset_id)
    assert agent["platform"] == "linux" and agent["credential_status"] == "active"


def test_revoked_token_cannot_be_used(console: TestClient, client: TestClient) -> None:
    created = _create_token(console)
    revoked = console.post(
        f"{CONSOLE}/enrollment-tokens/{created['token_id']}/revoke", headers=LOCAL
    )
    assert revoked.status_code == 200 and revoked.json()["state"] == "revoked"
    assert "token" not in revoked.json()

    response, _ = _enroll(client, created["token"])
    assert response.status_code == 401


def test_token_input_is_validated(console: TestClient) -> None:
    for body in ({"max_uses": 0}, {"ttl_minutes": 5000}, {"expected_platform": "macos"}, {"x": 1}):
        response = console.post(f"{CONSOLE}/enrollment-tokens", json=body, headers=LOCAL)
        assert response.status_code == 422, body


# --- Agents listing -----------------------------------------------------------------------


def test_agents_listing_states_and_no_secrets(
    console: TestClient, client: TestClient, db: Session
) -> None:
    tokens = [_create_token(console)["token"] for _ in range(3)]
    online, online_payload = _enroll(client, tokens[0], hostname="online-pc")
    pending, _ = _enroll(client, tokens[1], hostname="pending-pc", os_name="Linux")
    revoked, _ = _enroll(client, tokens[2], hostname="revoked-pc")
    agent_tokens = [r.json()["agent_token"] for r in (online, pending, revoked)]
    beat = client.post(
        "/api/v1/agents/heartbeat",
        json={"agent_id": online_payload["agent_id"]},
        headers={"Authorization": f"Bearer {agent_tokens[0]}"},
    )
    assert beat.status_code == 200
    console.post(f"{CONSOLE}/agents/{revoked.json()['asset_id']}/revoke", headers=LOCAL)
    db.add(  # a host only seen on the network is not an agent
        Asset(
            monitoring_method=MonitoringMethod.DISCOVERED,
            primary_ip="192.168.50.99",
            first_seen_at=datetime.now(UTC),
        )
    )
    db.commit()

    response = client.get(AGENTS)  # read-only, like /assets

    assert response.status_code == 200
    body = response.json()
    assert body["summary"] == {"total": 3, "online": 1, "offline": 0, "pending": 1, "revoked": 1}
    by_name = {a["hostname"]: a for a in body["items"]}
    assert by_name["online-pc"]["status"] == "online"
    assert by_name["online-pc"]["credential_status"] == "active"
    assert by_name["pending-pc"]["status"] == "unknown"
    assert by_name["pending-pc"]["platform"] == "linux"
    assert by_name["revoked-pc"]["credential_status"] == "revoked"
    assert by_name["revoked-pc"]["revoked_at"] is not None
    assert by_name["online-pc"]["agent_id"] == online_payload["agent_id"]
    for agent in body["items"]:
        assert not {k for k in agent if "token" in k or "hash" in k or "secret" in k}
    hashes = db.scalars(select(Asset.agent_token_hash).where(Asset.agent_token_hash.is_not(None)))
    for secret in [*agent_tokens, *tokens, *hashes]:
        assert secret not in response.text


def test_asset_agent_detail(console: TestClient, client: TestClient, db: Session) -> None:
    response, payload = _enroll(client, _create_token(console)["token"])
    asset_id = response.json()["asset_id"]

    detail = client.get(f"/api/v1/assets/{asset_id}/agent")

    assert detail.status_code == 200
    agent = detail.json()
    assert agent["agent_id"] == payload["agent_id"] and agent["platform"] == "windows"
    assert agent["credential_issued_at"] is not None and agent["enrolled_at"] is not None
    assert response.json()["agent_token"] not in detail.text
    discovered = Asset(
        monitoring_method=MonitoringMethod.DISCOVERED,
        primary_ip="192.168.50.98",
        first_seen_at=datetime.now(UTC),
    )
    db.add(discovered)
    db.commit()
    assert client.get(f"/api/v1/assets/{discovered.public_id}/agent").status_code == 404


# --- Revoke / reinstate -------------------------------------------------------------------


def test_revoked_agent_stops_authenticating_and_its_history_stays(
    console: TestClient, client: TestClient
) -> None:
    response, payload = _enroll(client, _create_token(console)["token"])
    asset_id = response.json()["asset_id"]
    bearer = {"Authorization": f"Bearer {response.json()['agent_token']}"}
    sample = telemetry_payload(payload["agent_id"], disk_percent=97.0)  # opens a disk alert
    assert client.post("/api/v1/telemetry", json=sample, headers=bearer).status_code == 201
    alerts_before = client.get(f"/api/v1/alerts?asset_id={asset_id}").json()["total"]
    assert alerts_before >= 1

    revoked = console.post(f"{CONSOLE}/agents/{asset_id}/revoke", headers=LOCAL)

    assert revoked.status_code == 200
    assert revoked.json()["credential_status"] == "revoked"
    for path, body in (
        ("/api/v1/agents/heartbeat", {"agent_id": payload["agent_id"]}),
        ("/api/v1/telemetry", telemetry_payload(payload["agent_id"])),
        ("/api/v1/inventory", inventory_payload(payload["agent_id"])),
        ("/api/v1/events", {"agent_id": payload["agent_id"], "events": [_event(1)]}),
    ):
        assert client.post(path, json=body, headers=bearer).status_code == 401, path
    # Enrolling again is refused, even with a fresh valid one-time token.
    again = client.post(
        REGISTER, json=payload, headers={"X-Enrollment-Token": _create_token(console)["token"]}
    )
    assert again.status_code == 403 and again.json()["error"]["code"] == "agent_revoked"
    # Nothing was deleted: asset, telemetry and alerts are still there for audit.
    assert client.get(f"/api/v1/assets/{asset_id}").status_code == 200
    assert len(client.get(f"/api/v1/assets/{asset_id}/telemetry").json()["items"]) == 1
    assert client.get(f"/api/v1/alerts?asset_id={asset_id}").json()["total"] == alerts_before
    # Revoking twice is harmless.
    assert console.post(f"{CONSOLE}/agents/{asset_id}/revoke", headers=LOCAL).status_code == 200


def test_reinstated_agent_needs_a_new_token_and_keeps_its_asset(
    console: TestClient, client: TestClient
) -> None:
    response, payload = _enroll(client, _create_token(console)["token"])
    asset_id = response.json()["asset_id"]
    assert console.post(f"{CONSOLE}/agents/{asset_id}/reinstate", headers=LOCAL).status_code == 409
    console.post(f"{CONSOLE}/agents/{asset_id}/revoke", headers=LOCAL)

    reinstated = console.post(f"{CONSOLE}/agents/{asset_id}/reinstate", headers=LOCAL)

    assert reinstated.status_code == 200
    assert reinstated.json()["credential_status"] == "re_enrollment_required"
    old = {"Authorization": f"Bearer {response.json()['agent_token']}"}
    beat = client.post(
        "/api/v1/agents/heartbeat", json={"agent_id": payload["agent_id"]}, headers=old
    )
    assert beat.status_code == 401  # the old token never comes back
    new = client.post(
        REGISTER, json=payload, headers={"X-Enrollment-Token": _create_token(console)["token"]}
    )
    assert new.status_code == 200  # re-enrolled, not a new asset
    assert new.json()["asset_id"] == asset_id
    assert _agent(client, asset_id)["credential_status"] == "active"


def test_revoke_needs_an_agent(console: TestClient, db: Session) -> None:
    discovered = Asset(
        monitoring_method=MonitoringMethod.DISCOVERED,
        primary_ip="192.168.50.97",
        first_seen_at=datetime.now(UTC),
    )
    db.add(discovered)
    db.commit()
    for asset_id in (discovered.public_id, "00000000-0000-0000-0000-000000000000"):
        response = console.post(f"{CONSOLE}/agents/{asset_id}/revoke", headers=LOCAL)
        assert response.status_code == 404
    db.refresh(discovered)
    assert discovered.agent_token_revoked_at is None


def test_agent_actions_are_audited_without_secrets(
    console: TestClient, client: TestClient, db: Session
) -> None:
    created = _create_token(console)
    response, _ = _enroll(client, created["token"])
    asset_id = response.json()["asset_id"]
    console.post(f"{CONSOLE}/agents/{asset_id}/revoke")
    console.post(f"{CONSOLE}/agents/{asset_id}/reinstate")
    rows = db.scalars(select(AuditEvent).order_by(AuditEvent.id)).all()
    actions = [(r.action, r.result, r.target_id) for r in rows]
    assert ("enrollment_token_created", "success", created["token_id"]) in actions
    assert ("agent_revoked", "success", asset_id) in actions
    assert ("agent_reactivated", "success", asset_id) in actions
    dump = repr([(r.actor, r.target_id, r.details) for r in rows])
    assert created["token"] not in dump
    assert client.tokens[response.json()["agent_id"]] not in dump  # type: ignore[attr-defined]


# --- Fase 4F: método de instalación y re-enrolamiento de un servicio Windows ---------------


def test_installation_method_is_reported_and_follows_the_running_agent(
    console: TestClient, client: TestClient
) -> None:
    # Un agente antiguo (sin el campo) queda "No reportado" (null), sin romper nada.
    old_response, _ = _enroll(client, _create_token(console)["token"])
    assert _agent(client, old_response.json()["asset_id"])["installation_method"] is None

    token = _create_token(console, expected_platform="windows")["token"]
    response, payload = _enroll(client, token, installation_method="windows_service")
    assert response.status_code == 201, response.text
    asset_id = response.json()["asset_id"]
    assert _agent(client, asset_id)["installation_method"] == "windows_service"

    # Cada heartbeat lo actualiza: el mismo equipo ejecutado a mano deja de mostrarlo.
    bearer = {"Authorization": f"Bearer {response.json()['agent_token']}"}
    host = {k: v for k, v in payload.items() if k not in ("agent_id", "installation_method")}
    beat = client.post(
        "/api/v1/agents/heartbeat",
        json={"agent_id": payload["agent_id"], "host": host},
        headers=bearer,
    )
    assert beat.status_code == 200
    assert _agent(client, asset_id)["installation_method"] is None


@pytest.mark.parametrize("value", ["Windows Service", "x" * 40, "1abc", "a;b"])
def test_installation_method_is_validated(
    console: TestClient, client: TestClient, value: str
) -> None:
    response, _ = _enroll(client, _create_token(console)["token"], installation_method=value)
    assert response.status_code == 422


def test_revoked_windows_service_reenrolls_as_the_same_asset_keeping_history(
    console: TestClient, client: TestClient
) -> None:
    # Flujo del criterio de éxito 15: revocar -> reactivar -> token nuevo -> -Reenroll con el
    # mismo agent_id (la identidad se conserva en ProgramData) -> mismo activo, con historial.
    host = {"installation_method": "windows_service"}
    response, payload = _enroll(client, _create_token(console)["token"], **host)
    asset_id = response.json()["asset_id"]
    bearer = {"Authorization": f"Bearer {response.json()['agent_token']}"}
    sample = telemetry_payload(payload["agent_id"])
    assert client.post("/api/v1/telemetry", json=sample, headers=bearer).status_code == 201
    console.post(f"{CONSOLE}/agents/{asset_id}/revoke", headers=LOCAL)
    console.post(f"{CONSOLE}/agents/{asset_id}/reinstate", headers=LOCAL)

    token = _create_token(console, expected_platform="windows", expected_hostname="PC-ADMIN-01")
    again = client.post(REGISTER, json=payload, headers={"X-Enrollment-Token": token["token"]})

    assert again.status_code == 200
    assert again.json()["asset_id"] == asset_id
    assert client.get(AGENTS).json()["summary"]["total"] == 1
    assert len(client.get(f"/api/v1/assets/{asset_id}/telemetry").json()["items"]) == 1
    agent = _agent(client, asset_id)
    assert agent["credential_status"] == "active"
    assert agent["installation_method"] == "windows_service"
