"""Fase 7D.1 (H01, H04 servidor): identidad de agentes, recuperación, rotación y transporte.

Reproducciones controladas con datos sintéticos contra PostgreSQL (sentra_test): primero
cómo se explotaba cada hallazgo y después que ya no se puede. El TestClient habla por
http://testserver (equivale a "HTTP fuera de loopback"); las URL https://testserver simulan
la llegada por HTTPS (TLS terminado en el proxy de confianza).
"""

import threading
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select, update
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings, get_settings
from app.core.exceptions import AgentRecoveryRequiredError, ConflictError
from app.models.asset import Asset
from app.models.audit import AuditEvent
from app.models.enrollment import AgentRecoveryToken
from app.models.site import Site
from app.schemas.agent import AgentRegisterRequest
from app.services.agent_service import AgentService
from tests.conftest import (
    HTTPS_API,
    TEST_ENROLLMENT_KEY,
    agent_payload,
    authenticate,
    authorize_recovery,
)

API = "/api/v1"
CONSOLE = f"{API}/console"
REGISTER = f"{API}/agents/register"


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


def _register(client: TestClient, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = payload or agent_payload()
    response = client.post(f"{HTTPS_API}/agents/register", json=payload)
    assert response.status_code == 201, response.text
    return {"payload": payload, **response.json()}


def _beat(client: TestClient, agent_id: str, token: str, base: str = API) -> Any:
    return client.post(
        f"{base}/agents/heartbeat",
        json={"agent_id": agent_id},
        headers={"Authorization": f"Bearer {token}"},
    )


def _rotate(client: TestClient, agent_id: str, token: str | None, base: str = HTTPS_API) -> Any:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return client.post(
        f"{base}/agents/credentials/rotate", json={"agent_id": agent_id}, headers=headers
    )


def _audit(db: Session, action: str) -> list[AuditEvent]:
    db.expire_all()
    return list(
        db.scalars(select(AuditEvent).where(AuditEvent.action == action).order_by(AuditEvent.id))
    )


def _token(console: TestClient, **body: Any) -> dict[str, Any]:
    response = console.post(f"{CONSOLE}/enrollment-tokens", json=body)
    assert response.status_code == 201, response.text
    created: dict[str, Any] = response.json()
    return created


def _as(client: TestClient, engine: Engine, role: str) -> TestClient:
    other = TestClient(client.app)
    authenticate(other, engine, role)
    return other


# --- H01: suplantación con un token o la clave de instalación --------------------------------


@pytest.mark.parametrize("method", ["legacy_key", "enrollment_token"])
def test_h01_existing_agent_id_cannot_be_taken_over(
    client: TestClient, db: Session, method: str
) -> None:
    """Reproducción H01: antes, un segundo registro con el mismo agent_id ROTABA la credencial
    del agente legítimo (200) y el atacante pasaba a ser ese activo. Ahora: 403, el legítimo
    sigue funcionando, el token no se consume y el intento queda auditado."""
    victim = _register(client)
    agent_id = victim["payload"]["agent_id"]
    attacker = {**victim["payload"], "hostname": "ATTACKER", "primary_ip": "10.66.6.6"}
    headers: dict[str, str]
    token: dict[str, Any] | None = None
    if method == "legacy_key":
        headers = {"X-Enrollment-Key": TEST_ENROLLMENT_KEY}
    else:
        token = _token(client)
        headers = {"X-Enrollment-Token": token["token"]}

    response = client.post(f"{HTTPS_API}/agents/register", json=attacker, headers=headers)

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "agent_recovery_required"
    assert "agent_token" not in response.text
    assert _beat(client, agent_id, victim["agent_token"]).status_code == 200
    asset = db.scalar(select(Asset).where(Asset.agent_id == UUID(agent_id)))
    assert asset is not None and asset.hostname == "PC-ADMIN-01"
    if token is not None:
        listed = client.get(f"{CONSOLE}/enrollment-tokens").json()["items"]
        assert next(t for t in listed if t["token_id"] == token["token_id"])["use_count"] == 0
    refused = _audit(db, "agent_enrollment_refused")
    assert len(refused) == 1
    assert refused[0].result == "denied"
    assert (refused[0].details or {})["method"] == method
    assert victim["agent_token"] not in str(refused[0].details)


def test_h01_new_identities_still_enroll_with_both_methods(client: TestClient) -> None:
    legacy = client.post(f"{HTTPS_API}/agents/register", json=agent_payload())
    assert legacy.status_code == 201
    token = _token(client)
    fresh = client.post(
        f"{HTTPS_API}/agents/register",
        json=agent_payload(),
        headers={"X-Enrollment-Token": token["token"]},
    )
    assert fresh.status_code == 201
    agents = client.get(f"{API}/agents").json()
    assert agents["summary"]["legacy_key"] == 1


def test_h01_concurrent_registration_of_a_new_agent_id_creates_one_identity(
    engine: Engine, client: TestClient
) -> None:
    data = AgentRegisterRequest.model_validate(agent_payload())
    barrier = threading.Barrier(4)
    outcomes: list[str] = []
    lock = threading.Lock()

    def attempt() -> None:
        with sessionmaker(bind=engine, expire_on_commit=False)() as session:
            barrier.wait()
            try:
                AgentService(session, TEST_ENROLLMENT_KEY).register(data, TEST_ENROLLMENT_KEY)
                result = "created"
            except ConflictError:
                result = "conflict"
            except AgentRecoveryRequiredError:
                result = "recovery_required"
        with lock:
            outcomes.append(result)

    threads = [threading.Thread(target=attempt) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)

    assert sorted(outcomes).count("created") == 1
    assert len(outcomes) == 4
    with sessionmaker(bind=engine)() as session:
        count = session.scalars(select(Asset).where(Asset.agent_id == data.agent_id)).all()
    assert len(count) == 1


def test_h01_legacy_key_can_be_retired_without_cutting_enrolled_agents(
    client: TestClient,
) -> None:
    enrolled = _register(client)
    expired = get_settings().model_copy(
        update={"agent_enrollment_key_expires_at": datetime.now(UTC) - timedelta(minutes=1)}
    )
    client.app.dependency_overrides[get_settings] = lambda: expired  # type: ignore[attr-defined]

    refused = client.post(f"{HTTPS_API}/agents/register", json=agent_payload())

    assert refused.status_code == 403
    assert "AGENT_ENROLLMENT_KEY_EXPIRES_AT" in refused.json()["error"]["message"]
    # Un agente ya enrolado sigue con su credencial propia: retirar la clave no lo corta.
    beat = _beat(client, enrolled["payload"]["agent_id"], enrolled["agent_token"], HTTPS_API)
    assert beat.status_code == 200
    # Y los tokens de un solo uso siguen funcionando.
    token = _token(client)
    ok = client.post(
        f"{HTTPS_API}/agents/register",
        json=agent_payload(),
        headers={"X-Enrollment-Token": token["token"]},
    )
    assert ok.status_code == 201


def test_h01_expiry_setting_must_be_timezone_aware() -> None:
    with pytest.raises(ValueError, match="time zone"):
        Settings(
            _env_file=None,
            database_url=get_settings().database_url,
            agent_enrollment_key_expires_at="2027-01-01T00:00:00",
        )


# --- H01: recuperación autorizada por un admin -----------------------------------------------


def test_h01_recovery_is_admin_only_and_needs_reason_and_confirmation(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent = _register(client)
    url = f"{CONSOLE}/agents/{agent['asset_id']}/recovery-tokens"
    body = {"reason": "Reinstalación tras cambio de disco", "confirm": True}
    for role in ("viewer", "analyst"):
        assert _as(client, engine, role).post(url, json=body).status_code == 403
    assert client.post(url, json={"reason": "corto", "confirm": True}).status_code == 422
    assert client.post(url, json={"reason": body["reason"]}).status_code == 422
    assert client.post(url, json={**body, "confirm": False}).status_code == 422
    assert client.post(url, json={**body, "ttl_minutes": 61}).status_code == 422

    created = client.post(url, json=body)

    assert created.status_code == 201
    value = created.json()["token"]
    assert value.startswith("sentra_et_rec_")
    listed = client.get(url).json()["items"]
    assert [r["state"] for r in listed] == ["active"]
    assert "token" not in listed[0]
    audit = _audit(db, "agent_recovery_authorized")
    assert len(audit) == 1 and (audit[0].details or {})["reason"] == body["reason"]
    assert value not in str(audit[0].details)
    row = db.scalar(select(AgentRecoveryToken))
    assert row is not None and row.token_hash != value  # solo el SHA-256
    assert row.expires_at - row.created_at == timedelta(minutes=15)


def test_h01_recovery_is_single_use_short_lived_and_bound_to_its_agent(
    client: TestClient, db: Session
) -> None:
    agent = _register(client)
    other = _register(client)
    payload = agent["payload"]
    first = authorize_recovery(client, agent["asset_id"])
    headers = {"X-Enrollment-Token": first["token"]}

    # Otro agent_id con la autorización de este: rechazado y la autorización no se gasta.
    wrong = client.post(f"{HTTPS_API}/agents/register", json=other["payload"], headers=headers)
    assert wrong.status_code == 401
    # Por HTTP fuera de loopback: rechazado (la credencial nueva viajaría en claro).
    plain = client.post(REGISTER, json=payload, headers=headers)
    assert plain.status_code == 403
    assert plain.json()["error"]["code"] == "https_required"

    ok = client.post(f"{HTTPS_API}/agents/register", json=payload, headers=headers)
    assert ok.status_code == 200
    assert ok.json()["asset_id"] == agent["asset_id"]
    again = client.post(f"{HTTPS_API}/agents/register", json=payload, headers=headers)
    assert again.status_code == 401  # un solo uso
    assert _beat(client, payload["agent_id"], agent["agent_token"]).status_code == 401
    assert _beat(client, payload["agent_id"], ok.json()["agent_token"]).status_code == 200
    assert len(_audit(db, "agent_recovered")) == 1
    rejected = _audit(db, "agent_recovery_rejected")
    assert len(rejected) == 3
    assert all(first["token"] not in str(e.details) for e in rejected)

    # Caducada: no vale aunque nunca se usara.
    late = authorize_recovery(client, agent["asset_id"])
    db.execute(
        update(AgentRecoveryToken)
        .where(AgentRecoveryToken.public_id == UUID(late["recovery_id"]))
        .values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
    )
    db.commit()
    expired = client.post(
        f"{HTTPS_API}/agents/register", json=payload, headers={"X-Enrollment-Token": late["token"]}
    )
    assert expired.status_code == 401


def test_h01_recovery_checks_site_hostname_and_replaces_previous_authorizations(
    client: TestClient, db: Session
) -> None:
    agent = _register(client)
    payload = agent["payload"]
    pinned = authorize_recovery(client, agent["asset_id"], expected_hostname="OTRO-PC")
    mismatch = client.post(
        f"{HTTPS_API}/agents/register",
        json=payload,
        headers={"X-Enrollment-Token": pinned["token"]},
    )
    assert mismatch.status_code == 401

    moved = authorize_recovery(client, agent["asset_id"])
    # Emitir una nueva revoca la anterior: nunca hay dos autorizaciones vivas.
    states = {
        r["recovery_id"]: r["state"]
        for r in client.get(f"{CONSOLE}/agents/{agent['asset_id']}/recovery-tokens").json()["items"]
    }
    assert states[pinned["recovery_id"]] == "revoked"
    assert states[moved["recovery_id"]] == "active"
    site = Site(name="Sede B", slug=f"sede-b-{uuid4().hex[:6]}", status="active", timezone="UTC")
    db.add(site)
    db.flush()
    db.execute(
        update(Asset).where(Asset.public_id == UUID(agent["asset_id"])).values(site_id=site.id)
    )
    db.commit()
    out_of_site = client.post(
        f"{HTTPS_API}/agents/register",
        json=payload,
        headers={"X-Enrollment-Token": moved["token"]},
    )
    assert out_of_site.status_code == 401

    revoked = authorize_recovery(client, agent["asset_id"])
    cancel = client.post(f"{CONSOLE}/agents/recovery-tokens/{revoked['recovery_id']}/revoke")
    assert cancel.status_code == 200 and cancel.json()["state"] == "revoked"
    after = client.post(
        f"{HTTPS_API}/agents/register",
        json=payload,
        headers={"X-Enrollment-Token": revoked["token"]},
    )
    assert after.status_code == 401


def test_h01_revoked_agent_needs_reinstate_before_recovery(client: TestClient) -> None:
    agent = _register(client)
    client.post(f"{CONSOLE}/agents/{agent['asset_id']}/revoke")
    url = f"{CONSOLE}/agents/{agent['asset_id']}/recovery-tokens"
    blocked = client.post(url, json={"reason": "Reinstalación autorizada", "confirm": True})
    assert blocked.status_code == 409
    client.post(f"{CONSOLE}/agents/{agent['asset_id']}/reinstate")
    assert authorize_recovery(client, agent["asset_id"])["state"] == "active"


# --- H01: rotación con la credencial vigente ------------------------------------------------


def test_h01_rotation_requires_the_current_credential_and_https(client: TestClient) -> None:
    agent = _register(client)
    agent_id = agent["payload"]["agent_id"]
    assert _rotate(client, agent_id, None).status_code == 401
    assert _rotate(client, agent_id, "sentra_at_" + "x" * 40).status_code == 401
    # Nunca con la clave de instalación ni con un token de enrolamiento.
    with_key = client.post(
        f"{HTTPS_API}/agents/credentials/rotate",
        json={"agent_id": agent_id},
        headers={"X-Enrollment-Key": TEST_ENROLLMENT_KEY},
    )
    assert with_key.status_code == 401
    # Con la credencial de OTRO agente tampoco.
    other = _register(client)
    assert _rotate(client, agent_id, other["agent_token"]).status_code == 401
    plain = _rotate(client, agent_id, agent["agent_token"], API)
    assert plain.status_code == 403
    assert plain.json()["error"]["code"] == "https_required"


def test_h01_rotation_keeps_identity_and_never_locks_the_agent_out(
    client: TestClient, db: Session
) -> None:
    agent = _register(client)
    agent_id = agent["payload"]["agent_id"]
    old = agent["agent_token"]

    rotated = _rotate(client, agent_id, old)

    assert rotated.status_code == 200
    new = rotated.json()["agent_token"]
    assert rotated.json()["asset_id"] == agent["asset_id"]
    # La anterior sigue valiendo hasta el primer uso de la nueva (respuesta perdida = sin
    # corte); en cuanto la nueva se usa, la anterior deja de valer.
    assert _beat(client, agent_id, old, HTTPS_API).status_code == 200
    assert _beat(client, agent_id, new, HTTPS_API).status_code == 200
    assert _beat(client, agent_id, old, HTTPS_API).status_code == 401
    assert len(_audit(db, "agent_credential_rotated")) == 1
    assert len(_audit(db, "agent_credential_rotation_completed")) == 1
    assert new not in str([e.details for e in _audit(db, "agent_credential_rotated")])


def test_h01_concurrent_rotations_leave_a_single_new_credential(
    client: TestClient, engine: Engine
) -> None:
    agent = _register(client)
    agent_id = agent["payload"]["agent_id"]
    barrier = threading.Barrier(3)
    issued: list[str] = []
    lock = threading.Lock()

    def attempt() -> None:
        with sessionmaker(bind=engine, expire_on_commit=False)() as session:
            barrier.wait()
            out = AgentService(session, None).rotate(
                UUID(agent_id), agent["agent_token"], "https", None
            )
        with lock:
            issued.append(out.agent_token)

    threads = [threading.Thread(target=attempt) for _ in range(3)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)

    assert len(issued) == 3
    working = [t for t in issued if _beat(client, agent_id, t, HTTPS_API).status_code == 200]
    assert len(working) == 1


def test_h01_rotation_requests_reach_the_agent_only_over_a_secure_transport(
    client: TestClient,
) -> None:
    agent = _register(client)
    agent_id = agent["payload"]["agent_id"]
    beat = _beat(client, agent_id, agent["agent_token"], HTTPS_API).json()
    assert beat["rotate_credential"] is False
    requested = client.post(
        f"{CONSOLE}/agents/{agent['asset_id']}/rotate-credential", json={"reason": None}
    )
    assert requested.status_code == 200
    assert requested.json()["rotation_requested_at"] is not None
    assert requested.json()["rotation_reason"] == "operator_request"
    assert _beat(client, agent_id, agent["agent_token"], HTTPS_API).json()["rotate_credential"]
    plain = _beat(client, agent_id, agent["agent_token"]).json()
    assert plain["rotate_credential"] is False
    new = _rotate(client, agent_id, agent["agent_token"]).json()["agent_token"]
    assert _beat(client, agent_id, new, HTTPS_API).json()["rotate_credential"] is False


# --- H04 (servidor): inventario de transporte ------------------------------------------------


def test_h04_http_outside_loopback_is_flagged_but_not_cut_off(client: TestClient) -> None:
    agent = _register(client)
    agent_id = agent["payload"]["agent_id"]

    beat = _beat(client, agent_id, agent["agent_token"])  # http://testserver

    assert beat.status_code == 200  # nunca se corta a un agente en silencio
    listed = next(
        a for a in client.get(f"{API}/agents").json()["items"] if a["asset_id"] == agent["asset_id"]
    )
    assert listed["transport"] == "http_remote"
    assert listed["insecure_transport_at"] is not None
    assert listed["rotation_reason"] == "insecure_transport"
    assert client.get(f"{API}/agents").json()["summary"]["insecure_transport"] == 1

    # El agente pasa a HTTPS: el transporte se actualiza y se le pide rotar la credencial
    # expuesta, que deja de estar pendiente al usar la nueva.
    https_beat = _beat(client, agent_id, agent["agent_token"], HTTPS_API).json()
    assert https_beat["rotate_credential"] is True
    new = _rotate(client, agent_id, agent["agent_token"]).json()["agent_token"]
    _beat(client, agent_id, new, HTTPS_API)
    listed = next(
        a for a in client.get(f"{API}/agents").json()["items"] if a["asset_id"] == agent["asset_id"]
    )
    assert listed["transport"] == "https"
    assert listed["rotation_pending"] is False
    assert listed["rotation_requested_at"] is None


def test_h04_loopback_http_is_accepted_as_secure(client: TestClient) -> None:
    with TestClient(client.app, client=("127.0.0.1", 50000)) as local:
        registered = local.post(
            REGISTER, json=agent_payload(), headers={"X-Enrollment-Key": TEST_ENROLLMENT_KEY}
        )
        assert registered.status_code == 201
        body = registered.json()
        rotated = local.post(
            f"{API}/agents/credentials/rotate",
            json={"agent_id": body["agent_id"]},
            headers={"Authorization": f"Bearer {body['agent_token']}"},
        )
        assert rotated.status_code == 200
    agents = client.get(f"{API}/agents").json()
    assert agents["items"][0]["transport"] == "http_loopback"
    assert agents["summary"]["insecure_transport"] == 0
