"""Fase 7C.1-7C.2: modelo open-weight opcional y asistente de la Analyst Console.

- salida de modelos open-weight: razonamiento <think>, prosa alrededor del JSON, bloques de
  código en cualquier posición (sin evaluar nada: solo json.loads);
- AI_SYSTEM_PROMPT_MODE=user_prefix para plantillas sin rol system;
- asistente de la consola: solo con IA activada, sobre ejecuciones que el analista puede ver,
  con grounding (refs R<n> de las ejecuciones), hipótesis siempre "possible", borrador con
  encabezado fijo, presupuesto de contexto y resultados privados de quien los pidió.

El proveedor es FakeAIProvider: nunca hay red ni modelo real.
"""

import json
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select, update
from sqlalchemy.orm import Session, sessionmaker

from app.ai.config import AIConfig
from app.ai.openai_compat import OpenAICompatibleProvider
from app.ai.output import DRAFT_HEADER, extract_json_text, parse_console_json
from app.ai.provider import AIRequest
from app.core.config import get_settings
from app.models.ai import AIInsight
from app.models.tool import ToolExecution
from tests.ai_fakes import FakeAIProvider, answer, context_refs
from tests.conftest import authenticate
from tests.test_ai import _enable
from tests.test_risk import _detection, _discovered

API = "/api/v1"


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


@pytest.fixture
def analyst(client: TestClient, engine: Engine) -> Iterator[TestClient]:
    with TestClient(client.app) as other:
        authenticate(other, engine, "analyst")
        yield other


def _ok(response: Any) -> dict[str, Any]:
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def _error(response: Any, status: int, code: str) -> None:
    assert response.status_code == status, response.text
    assert response.json()["error"]["code"] == code, response.text


def _profile(analyst: TestClient, db: Session, name: str = "pc-finanzas-14") -> tuple[str, str]:
    """Ejecuta asset.profile como analista y devuelve (asset_id, execution_id)."""
    asset = _discovered(db, name=name)
    _detection(db, asset)
    body = _ok(
        analyst.post(
            f"{API}/tools/asset.profile/execute",
            json={"input": {"asset_id": str(asset.public_id)}},
        )
    )
    assert body["status"] == "succeeded"
    return str(asset.public_id), body["execution_id"]


def _console(client: TestClient, **overrides: Any) -> tuple[FakeAIProvider, Any]:
    """IA activada y, de forma explícita, el asistente de la consola (apagado por defecto)."""
    return _enable(client, **{"ai_console_assist_enabled": True, **overrides})


def _review(client: TestClient, **body: Any) -> Any:
    body.pop("refresh", None)
    return client.post(f"{API}/ai/console/context", json=body)


def _assist(client: TestClient, **body: Any) -> Any:
    """Flujo de la UI (7C-Security-Fix1): revisar el documento y enviarlo con su huella."""
    reviewed = _review(client, **dict(body))
    if reviewed.status_code != 200:
        return reviewed
    digest = reviewed.json()["context_sha256"]
    return client.post(
        f"{API}/ai/console/assist",
        json={**body, "context_sha256": digest, "confirm_send": True},
    )


# --- 7C.1: salida de modelos open-weight ------------------------------------------------------


@pytest.mark.parametrize(
    "content",
    [
        '{"summary": "ok"}',
        '<think>Primero miro R1 {no es json}</think>\n{"summary": "ok"}',
        '<THINKING>razono</THINKING>```json\n{"summary": "ok"}\n```',
        'Aquí tienes el análisis:\n```json\n{"summary": "ok"}\n```\nEspero que ayude.',
        'Resultado: {"summary": "ok"} fin',
        '<reasoning>a</reasoning> texto {"summary": "ok"}',
    ],
)
def test_extract_json_from_open_weight_answers(content: str) -> None:
    assert json.loads(extract_json_text(content)) == {"summary": "ok"}


def test_extract_json_respects_strings_and_nesting() -> None:
    content = 'Nota {previa} sin json. {"summary": "llave } en texto", "a": {"b": [1, {"c": 2}]}}'
    # "{previa}" no es JSON: el extractor lo salta y sigue con el siguiente objeto.
    data = json.loads(extract_json_text(content))
    assert data["summary"] == "llave } en texto" and data["a"]["b"][1] == {"c": 2}
    raw = parse_console_json('<think>…</think>{"summary": "s", "draft": null, "hypotheses": null}')
    assert raw.draft == "" and raw.hypotheses == []


def test_unclosed_reasoning_block_is_invalid_not_guessed() -> None:
    # El modelo agotó los tokens pensando: no hay respuesta y no se inventa ninguna.
    assert extract_json_text('<think>{"summary": "a medias"') == ""


def test_user_prefix_mode_sends_a_single_user_message() -> None:
    settings = get_settings().model_copy(
        update={
            "ai_enabled": True,
            "ai_base_url": "http://127.0.0.1:9/v1",
            "ai_model": "gemma-local",
            "ai_system_prompt_mode": "user_prefix",
        }
    )
    provider = OpenAICompatibleProvider(AIConfig.from_settings(settings))
    payload = json.loads(provider._payload(AIRequest("REGLAS", '{"sentra_data": {}}', 100)))
    assert [m["role"] for m in payload["messages"]] == ["user"]
    content = payload["messages"][0]["content"]
    assert content.startswith("REGLAS") and content.endswith('{"sentra_data": {}}')
    default = OpenAICompatibleProvider(
        AIConfig.from_settings(settings.model_copy(update={"ai_system_prompt_mode": "system"}))
    )
    roles = [m["role"] for m in json.loads(default._payload(AIRequest("R", "{}", 10)))["messages"]]
    assert roles == ["system", "user"]


# --- 7C.2: asistente de la consola -------------------------------------------------------------


def test_console_assist_off_by_default(analyst: TestClient, db: Session) -> None:
    _asset_id, execution_id = _profile(analyst, db)
    status = _ok(analyst.get(f"{API}/ai/status"))
    assert status["enabled"] is False and status["console_assist_available"] is False
    _error(_assist(analyst, execution_ids=[execution_id]), 409, "ai_not_configured")


def test_console_summary_is_grounded_on_tool_results(
    client: TestClient, analyst: TestClient, db: Session
) -> None:
    fake, _ = _console(client)
    asset_id, execution_id = _profile(analyst, db)
    status = _ok(analyst.get(f"{API}/ai/status"))
    assert status["console_assist_available"] is True
    assert status["system_prompt_mode"] == "system" and status["model_source"] == "settings"

    body = _ok(_assist(analyst, execution_ids=[execution_id], asset_id=asset_id))
    assert body["kind"] == "console_summary" and body["scope"] == "console"
    assert body["tool_execution_ids"] == [execution_id]
    assert body["asset_id"] == asset_id
    assert body["result"]["origin"] == "model"
    refs = {r["ref"]: r for r in body["result"]["evidence_refs"]}
    assert refs["R1"]["type"] == "tool_execution" and refs["R1"]["id"] == execution_id

    sent = json.loads(fake.requests[-1].user)["sentra_data"]
    (result,) = sent["tool_results"]
    row = db.scalar(select(ToolExecution).where(ToolExecution.public_id == execution_id))
    assert row is not None
    assert result["ref"] == "R1" and result["output_sha256"] == row.output_sha256
    assert result["truncated_for_model"] is False
    assert sent["asset"]["ref"].startswith("A")
    assert "REGLAS DE LA CONSOLA" in fake.requests[-1].system

    # Misma petición: sale de la caché (no se vuelve a llamar al modelo).
    calls = len(fake.requests)
    again = _ok(_assist(analyst, execution_ids=[execution_id], asset_id=asset_id))
    assert again["cached"] is True and len(fake.requests) == calls

    stored = db.scalar(select(AIInsight).where(AIInsight.public_id == body["insight_id"]))
    assert stored is not None
    (tool_ref,) = [r for r in stored.input_refs or [] if r["type"] == "tool_execution"]
    assert tool_ref["sha256"] == row.output_sha256


def test_hypotheses_are_always_possible_and_need_evidence(
    client: TestClient, analyst: TestClient, db: Session
) -> None:
    fake, _ = _console(client)
    _, execution_id = _profile(analyst, db)

    def responder(request: AIRequest) -> str:
        refs = context_refs(request)
        base = json.loads(answer(refs[:1]))
        base["hypotheses"] = [
            {"text": "Mantenimiento legítimo.", "evidence": ["R1"], "validate_with": "Ticket"},
            {"text": "Inventada.", "evidence": ["R99", "Z1"]},
        ]
        base["key_findings"][0]["certainty"] = "observed"
        return json.dumps(base)

    fake.responder = responder
    body = _ok(_assist(analyst, task="hypotheses", execution_ids=[execution_id]))
    result = body["result"]
    assert body["kind"] == "console_hypotheses"
    assert result["hypotheses"] == [
        {
            "text": "Mantenimiento legítimo.",
            "certainty": "possible",
            "evidence": ["R1"],
            "validate_with": "Ticket",
        }
    ]
    assert any("hipótesis sin evidencia" in w for w in result["warnings"])
    assert result["draft"] is None


def test_draft_note_carries_a_fixed_ai_header(
    client: TestClient, analyst: TestClient, db: Session
) -> None:
    fake, _ = _console(client)
    _, execution_id = _profile(analyst, db)

    def responder(request: AIRequest) -> str:
        base = json.loads(answer(context_refs(request)[:1]))
        base["draft"] = "Contexto\n\n\n\nSe observó [R1].\nHipótesis abierta."
        return json.dumps(base)

    fake.responder = responder
    body = _ok(_assist(analyst, task="draft_note", execution_ids=[execution_id]))
    draft = body["result"]["draft"]
    assert draft.startswith(DRAFT_HEADER)
    assert "Contexto\n\nSe observó [R1].\nHipótesis abierta." in draft


def test_executions_of_other_users_and_unusable_ones(
    client: TestClient, analyst: TestClient, engine: Engine, db: Session
) -> None:
    _console(client)
    _, execution_id = _profile(analyst, db)
    with TestClient(client.app) as second:
        authenticate(second, engine, "analyst", username="analyst2")
        # Sin tools:manage una ejecución ajena no existe (404, como en /tools/executions).
        _error(_assist(second, execution_ids=[execution_id]), 404, "not_found")
    # El admin (tools:manage) sí puede analizarla.
    assert _ok(_assist(client, execution_ids=[execution_id]))["kind"] == "console_summary"

    db.execute(
        update(ToolExecution)
        .where(ToolExecution.public_id == execution_id)
        .values(status="failed", output=None)
    )
    db.commit()
    _error(_assist(analyst, execution_ids=[execution_id]), 422, "console_execution_not_usable")
    _error(_assist(analyst), 422, "console_assist_invalid")


def test_console_insights_are_private(
    client: TestClient, analyst: TestClient, engine: Engine, db: Session
) -> None:
    _console(client)
    _, execution_id = _profile(analyst, db)
    body = _ok(_assist(analyst, execution_ids=[execution_id]))
    assert _ok(analyst.get(f"{API}/ai/insights", params={"kind": "console_summary"}))["total"] == 1
    with TestClient(client.app) as second:
        authenticate(second, engine, "analyst", username="analyst2")
        listed = _ok(second.get(f"{API}/ai/insights", params={"kind": "console_summary"}))
        assert listed["total"] == 0
        assert second.get(f"{API}/ai/insights/{body['insight_id']}").status_code == 404


def test_large_outputs_are_trimmed_to_the_prompt_budget(
    client: TestClient, analyst: TestClient, db: Session
) -> None:
    fake, _ = _console(client, ai_max_prompt_chars=6000)
    _, execution_id = _profile(analyst, db)
    big = {"rows": [{"line": "x" * 190, "n": i, "more": ["y" * 150] * 8} for i in range(10)]}
    db.execute(
        update(ToolExecution).where(ToolExecution.public_id == execution_id).values(output=big)
    )
    db.commit()
    _ok(_assist(analyst, execution_ids=[execution_id]))
    request = fake.requests[-1]
    (result,) = json.loads(request.user)["sentra_data"]["tool_results"]
    assert result["truncated_for_model"] is True
    assert len(request.user) <= 6000


def test_console_assist_can_be_switched_off(
    client: TestClient, analyst: TestClient, db: Session
) -> None:
    _enable(client, ai_console_assist_enabled=False)
    _, execution_id = _profile(analyst, db)
    status = _ok(analyst.get(f"{API}/ai/status"))
    assert status["available"] is True and status["console_assist_available"] is False
    _error(_assist(analyst, execution_ids=[execution_id]), 409, "ai_console_disabled")


def test_too_many_executions_and_asset_with_detection(
    client: TestClient, analyst: TestClient, db: Session
) -> None:
    _console(client, ai_console_max_executions=1)
    asset_id, first = _profile(analyst, db)
    _, second = _profile(analyst, db, name="pc-ventas-02")
    _error(_assist(analyst, execution_ids=[first, second]), 422, "console_assist_invalid")
    fake_detection = "00000000-0000-0000-0000-000000000001"
    _error(
        _assist(analyst, asset_id=asset_id, detection_id=fake_detection),
        422,
        "console_assist_invalid",
    )


def test_unused_provider_when_nothing_to_analyse(client: TestClient, analyst: TestClient) -> None:
    fake: FakeAIProvider
    fake, _ = _console(client)
    _error(_assist(analyst, asset_id="00000000-0000-0000-0000-000000000002"), 404, "not_found")
    assert fake.requests == []
