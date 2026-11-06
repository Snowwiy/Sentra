"""7C-Security-Fix1: política de privacidad estricta del asistente de la consola.

Decisión de Jesus (2026-10-29): proveedor local solo por loopback, sin fallback externo,
activación administrativa explícita, minimización de datos, revisión del contexto antes de
enviarlo, RBAC y auditoría. El proveedor es FakeAIProvider (sin red), salvo en las pruebas
de la comprobación de la IP conectada, que usan el proveedor real sin abrir conexiones.
"""

import json
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, update
from sqlalchemy.orm import Session, sessionmaker

from app.ai.config import AIConfig
from app.ai.openai_compat import OpenAICompatibleProvider
from app.ai.provider import AIDestinationBlockedError
from app.core.config import get_settings
from app.models.audit import AuditEvent
from app.models.tool import ToolExecution
from tests.conftest import authenticate
from tests.test_ai import _audit, _enable
from tests.test_console_ai_7c import _assist, _console, _error, _ok, _profile, _review

API = "/api/v1"
SECRETS = {
    "password": "S3cr3t-Passw0rd",
    "cmd": "curl -H 'Authorization: Bearer abcdefghijklmnop' http://svc:hunter22@intranet/x",
    "api_token": "tok_live_123456789",
}


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


@pytest.fixture
def analyst(client: TestClient, engine: Engine) -> Iterator[TestClient]:
    with TestClient(client.app) as other:
        authenticate(other, engine, "analyst")
        yield other


def _d(event: AuditEvent) -> dict[str, Any]:
    assert event.details is not None
    return event.details


def _settings(**values: Any) -> AIConfig:
    base = {"ai_enabled": True, "ai_model": "m", "ai_console_assist_enabled": True, **values}
    return AIConfig.from_settings(get_settings().model_copy(update=base))


# --- Activación administrativa explícita ---------------------------------------------------


def test_console_assist_is_off_by_default_even_with_ai_enabled(
    client: TestClient, analyst: TestClient, db: Session
) -> None:
    assert get_settings().ai_console_assist_enabled is False
    fake, _ = _enable(client)  # IA activa, asistente sin activar
    _, execution_id = _profile(analyst, db)
    status = _ok(analyst.get(f"{API}/ai/status"))
    assert status["available"] is True
    assert status["console_assist_available"] is False
    assert "AI_CONSOLE_ASSIST_ENABLED" in status["console_assist_reason"]
    _error(_review(analyst, execution_ids=[execution_id]), 409, "ai_console_disabled")
    assert fake.requests == []


# --- Solo loopback, sin fallback -----------------------------------------------------------


@pytest.mark.parametrize(
    ("base_url", "allowed"),
    [
        ("http://127.0.0.1:8080/v1", True),
        ("http://127.5.6.7:8080/v1", True),
        ("http://[::1]:8080/v1", True),
        ("http://localhost:11434/v1", True),
        ("http://192.168.10.5:8080/v1", False),
        ("http://ia-servidor:8080/v1", False),
        ("https://api.example.com/v1", False),
    ],
)
def test_console_destination_must_be_loopback(base_url: str, allowed: bool) -> None:
    config = _settings(
        ai_base_url=base_url,
        ai_local_networks="192.168.10.0/24",
        ai_local_hosts="ia-servidor",
        ai_allow_external=True,
    )
    assert (config.console_destination_blocked_reason() is None) is allowed


def test_lan_model_serves_insights_but_never_the_console(
    client: TestClient, analyst: TestClient, db: Session
) -> None:
    fake, _ = _console(
        client, ai_base_url="http://192.168.10.5:8080/v1", ai_local_networks="192.168.10.0/24"
    )
    _, execution_id = _profile(analyst, db)
    status = _ok(analyst.get(f"{API}/ai/status"))
    assert status["available"] is True and status["location"] == "local"
    assert status["console_assist_available"] is False
    assert "loopback" in status["console_assist_reason"]
    _error(_review(analyst, execution_ids=[execution_id]), 409, "ai_console_loopback_required")
    body = {"execution_ids": [execution_id], "context_sha256": "0" * 64, "confirm_send": True}
    _error(analyst.post(f"{API}/ai/console/assist", json=body), 409, "ai_console_loopback_required")
    assert fake.requests == []
    blocked = _audit(db, "ai_console_blocked")
    assert blocked and _d(blocked[-1])["reason"] == "ai_console_loopback_required"


class _Sock:
    def __init__(self, peer: str) -> None:
        self._peer = peer

    def getpeername(self) -> tuple[str, int]:
        return (self._peer, 8080)


class _Conn:
    def __init__(self, peer: str) -> None:
        self.sock = _Sock(peer)


def test_console_provider_only_accepts_a_loopback_peer() -> None:
    # "localhost" que resolviera a la LAN (DNS o hosts manipulados): la IP conectada manda.
    config = _settings(ai_base_url="http://localhost:8080/v1", ai_local_networks="192.168.10.0/24")
    console = OpenAICompatibleProvider(config.console_provider_config())
    console._check_peer(_Conn("127.0.0.1"))  # type: ignore[arg-type]
    with pytest.raises(AIDestinationBlockedError):
        console._check_peer(_Conn("192.168.10.5"))  # type: ignore[arg-type]
    # AI Insights sigue aceptando su LAN autorizada (4J.1 no cambia).
    insights = OpenAICompatibleProvider(config)
    insights._check_peer(_Conn("192.168.10.5"))  # type: ignore[arg-type]
    assert config.console_provider_config().allow_external is False


def test_console_uses_the_loopback_provider_config(
    client: TestClient, analyst: TestClient, db: Session
) -> None:
    fake, _ = _console(client, ai_local_networks="192.168.10.0/24", ai_allow_external=True)
    seen: list[AIConfig] = []
    app: Any = client.app

    def factory(config: AIConfig) -> Any:
        seen.append(config)
        return fake

    app.state.ai_provider_factory = factory
    _, execution_id = _profile(analyst, db)
    _ok(_assist(analyst, execution_ids=[execution_id]))
    assert seen and seen[-1].local_networks == () and seen[-1].allow_external is False


# --- Revisión del contexto compartido ------------------------------------------------------


def test_nothing_is_sent_without_review_and_confirmation(
    client: TestClient, analyst: TestClient, db: Session
) -> None:
    fake, _ = _console(client)
    _, execution_id = _profile(analyst, db)
    url = f"{API}/ai/console/assist"
    _error(
        analyst.post(url, json={"execution_ids": [execution_id]}),
        422,
        "console_context_review_required",
    )
    digest = _ok(_review(analyst, execution_ids=[execution_id]))["context_sha256"]
    _error(
        analyst.post(url, json={"execution_ids": [execution_id], "context_sha256": digest}),
        422,
        "console_context_review_required",
    )
    wrong = {"execution_ids": [execution_id], "context_sha256": "a" * 64, "confirm_send": True}
    _error(analyst.post(url, json=wrong), 409, "console_context_changed")
    # Otra tarea con la misma huella tampoco vale: la huella cubre tarea, prompt y pregunta.
    other = {
        "task": "hypotheses",
        "execution_ids": [execution_id],
        "context_sha256": digest,
        "confirm_send": True,
    }
    _error(analyst.post(url, json=other), 409, "console_context_changed")
    assert fake.requests == []
    mismatch = _audit(db, "ai_console_context_mismatch")
    assert len(mismatch) == 2 and _d(mismatch[0])["reviewed_sha256"] == "a" * 64


def test_the_model_receives_exactly_what_was_reviewed(
    client: TestClient, analyst: TestClient, db: Session
) -> None:
    fake, _ = _console(client)
    asset_id, execution_id = _profile(analyst, db)
    preview = _ok(
        _review(analyst, execution_ids=[execution_id], asset_id=asset_id, question="¿Es normal?")
    )
    assert preview["destination"] == "loopback" and preview["model"] == "fake-model"
    assert {i["ref"] for i in preview["items"]} >= {"R1"}
    assert preview["question"] == "¿Es normal?"
    body = {
        "execution_ids": [execution_id],
        "asset_id": asset_id,
        "question": "¿Es normal?",
        "context_sha256": preview["context_sha256"],
        "confirm_send": True,
    }
    _ok(analyst.post(f"{API}/ai/console/assist", json=body))
    sent = json.loads(fake.requests[-1].user)
    data = {k: v for k, v in sent["sentra_data"].items() if k != "now"}
    assert json.loads(json.dumps(data, default=str)) == preview["document"]


def test_changed_data_after_review_is_not_sent(
    client: TestClient, analyst: TestClient, db: Session
) -> None:
    fake, _ = _console(client)
    _, execution_id = _profile(analyst, db)
    digest = _ok(_review(analyst, execution_ids=[execution_id]))["context_sha256"]
    db.execute(
        update(ToolExecution)
        .where(ToolExecution.public_id == execution_id)
        .values(summary="Resumen cambiado después de la revisión")
    )
    db.commit()
    body = {"execution_ids": [execution_id], "context_sha256": digest, "confirm_send": True}
    _error(analyst.post(f"{API}/ai/console/assist", json=body), 409, "console_context_changed")
    assert fake.requests == []


# --- Minimización ---------------------------------------------------------------------------


def test_secrets_never_reach_the_model(
    client: TestClient, analyst: TestClient, db: Session
) -> None:
    fake, _ = _console(client)
    _, execution_id = _profile(analyst, db)
    db.execute(
        update(ToolExecution)
        .where(ToolExecution.public_id == execution_id)
        .values(output={"service": "backup", **SECRETS})
    )
    db.commit()
    preview = _ok(_review(analyst, execution_ids=[execution_id]))
    assert preview["redacted_values"] >= 3
    shown = json.dumps(preview["document"])
    _ok(_assist(analyst, execution_ids=[execution_id]))
    sent = fake.requests[-1].user
    for text in (shown, sent):
        assert "S3cr3t-Passw0rd" not in text
        assert "abcdefghijklmnop" not in text
        assert "hunter22" not in text
        assert "tok_live_123456789" not in text
        assert "backup" in text  # lo que no es secreto se conserva


# --- RBAC y auditoría -----------------------------------------------------------------------


def test_viewer_cannot_share_console_data_with_the_model(
    client: TestClient, engine: Engine, analyst: TestClient, db: Session
) -> None:
    fake, _ = _console(client)
    _, execution_id = _profile(analyst, db)
    with TestClient(client.app) as viewer:
        authenticate(viewer, engine, "viewer")
        _error(_review(viewer, execution_ids=[execution_id]), 403, "permission_denied")
        body = {"execution_ids": [execution_id], "context_sha256": "0" * 64, "confirm_send": True}
        _error(viewer.post(f"{API}/ai/console/assist", json=body), 403, "permission_denied")
    assert fake.requests == []


def test_review_and_send_are_audited_without_content(
    client: TestClient, analyst: TestClient, db: Session
) -> None:
    _console(client)
    _, execution_id = _profile(analyst, db)
    db.execute(
        update(ToolExecution)
        .where(ToolExecution.public_id == execution_id)
        .values(output={"service": "backup", **SECRETS})
    )
    db.commit()
    _ok(_assist(analyst, execution_ids=[execution_id], question="¿Qué reviso?"))
    (reviewed,) = _audit(db, "ai_console_context_reviewed")
    digest = _d(reviewed)["context_sha256"]
    assert _d(reviewed)["execution_ids"] == [execution_id]
    assert _d(reviewed)["destination"] == "loopback"
    assert _d(reviewed)["redacted_values"] >= 3
    requested = _audit(db, "ai_analysis_requested")[-1]
    assert _d(requested)["context_sha256"] == digest
    assert _d(requested)["reviewed"] is True
    completed = _audit(db, "ai_analysis_completed")[-1]
    assert _d(completed)["context_sha256"] == digest
    for event in (reviewed, requested, completed):
        text = json.dumps(event.details)
        assert "backup" not in text and "S3cr3t" not in text and "Qué reviso" not in text
