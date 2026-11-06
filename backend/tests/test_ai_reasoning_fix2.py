"""7C-Fix2: modelos con razonamiento (llama.cpp) y respuestas de IA inutilizables.

Caso real de Jesus (llama.cpp en 127.0.0.1 con un modelo Qwen "thinking"): sin
`reasoning_effort=none` el modelo gasta el presupuesto de salida pensando, devuelve `content`
vacío y AI Security Insights mostraba "respuesta no válida" sin más. Aquí se prueba:
- el parámetro opcional AI_REASONING_EFFORT (solo se envía si se fija);
- la clasificación interna del fallo (truncado, solo razonamiento, vacío, JSON, schema);
- que un JSON genérico no pasa por análisis;
- AI Security Insights y la consola de punta a punta con el proveedor HTTP real contra un
  servidor local que imita a llama.cpp (127.0.0.1, sin red externa).
"""

import json
import logging
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.ai.config import AIConfig
from app.ai.openai_compat import OpenAICompatibleProvider
from app.ai.output import answer_content, parse_console_json, parse_json
from app.ai.provider import (
    INVALID_REASONS,
    AIInvalidResponseError,
    AIProviderUnavailableError,
    AIRequest,
    AIResponse,
)
from app.core.config import get_settings
from app.models.audit import AuditEvent
from app.services.ai_service import default_provider_factory
from tests.ai_fakes import answer, grounded
from tests.conftest import authenticate
from tests.test_ai import _audit, _enable, _scenario
from tests.test_console_ai_7c import _assist, _console, _profile

API = "/api/v1"
THOUGHT = "El usuario pide un análisis de detecciones recurrentes de Windows. " * 40
REQUEST = AIRequest(system="sistema", user='{"task":"ask"}', max_output_tokens=1200)


def _response(content: str | None = "", **kw: Any) -> AIResponse:
    return AIResponse(content=content or "", model="m", latency_ms=1, **kw)


def _reason(exc: pytest.ExceptionInfo[AIInvalidResponseError]) -> str:
    assert exc.value.details == [{"reason": exc.value.reason}]
    return exc.value.reason


# --- Servidor local que imita a llama.cpp ---------------------------------------------------


class LlamaCpp:
    """Imita /v1/chat/completions de llama.cpp con un modelo "thinking".

    Sin reasoning_effort="none" piensa hasta agotar max_tokens: `reasoning_content` lleno,
    `content` vacío y finish_reason="length". Con "none" responde el análisis citando las
    referencias del documento de datos. `strict` rechaza parámetros desconocidos (400), como
    algunos proveedores compatibles.
    """

    def __init__(self) -> None:
        self.bodies: list[dict[str, Any]] = []
        self.strict = False
        self.answer = grounded

    def reply(self, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        self.bodies.append(body)
        if self.strict and "reasoning_effort" in body:
            return 400, {"error": {"message": "Unrecognized request argument: reasoning_effort"}}
        if body.get("reasoning_effort") != "none":
            message = {"role": "assistant", "content": "", "reasoning_content": THOUGHT}
            return 200, {
                "model": body["model"],
                "choices": [{"message": message, "finish_reason": "length"}],
                "usage": {"prompt_tokens": 900, "completion_tokens": body["max_tokens"]},
            }
        messages = body["messages"]
        request = AIRequest(
            system=messages[0]["content"], user=messages[-1]["content"], max_output_tokens=1
        )
        return 200, {
            "model": body["model"],
            "choices": [
                {
                    "message": {"role": "assistant", "content": self.answer(request)},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 900, "completion_tokens": 180},
        }


@pytest.fixture
def llama() -> Iterator[tuple[str, LlamaCpp]]:
    model = LlamaCpp()

    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", 0))
            status, payload = model.reply(json.loads(self.rfile.read(length)))
            data = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:  # health check de /v1/models
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *args: Any) -> None:
            return

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}/v1", model
    httpd.shutdown()
    httpd.server_close()


def _config(url: str, **values: Any) -> AIConfig:
    base = {"ai_enabled": True, "ai_base_url": url, "ai_model": "qwen-local", **values}
    return AIConfig.from_settings(get_settings().model_copy(update=base))


# --- Proveedor: reasoning_effort opcional ---------------------------------------------------


def test_reasoning_effort_is_not_sent_by_default(llama: tuple[str, LlamaCpp]) -> None:
    url, model = llama
    assert get_settings().ai_reasoning_effort == ""
    response = OpenAICompatibleProvider(_config(url)).complete(REQUEST)
    sent = model.bodies[-1]
    assert "reasoning_effort" not in sent
    assert sent["response_format"] == {"type": "json_object"} and sent["max_tokens"] == 1200
    # Lo que ve Sentra con el modelo pensando: contenido vacío, cortado por max_tokens.
    assert response.content == "" and response.finish_reason == "length"
    assert response.reasoning_chars == len(THOUGHT)


def test_reasoning_effort_none_reaches_llama_cpp_and_keeps_json_mode(
    llama: tuple[str, LlamaCpp],
) -> None:
    url, model = llama
    config = _config(url, ai_reasoning_effort="none")
    response = OpenAICompatibleProvider(config).complete(
        AIRequest(
            system="s", user=json.dumps({"sentra_data": {"a": {"ref": "A1"}}}), max_output_tokens=1
        )
    )
    sent = model.bodies[-1]
    assert sent["reasoning_effort"] == "none"
    assert sent["response_format"] == {"type": "json_object"}
    assert sent["model"] == "qwen-local"  # AI_MODEL sigue mandando; no se fuerza ninguno
    assert response.finish_reason == "stop" and response.reasoning_chars == 0
    assert parse_json(answer_content(response)).summary
    # Sin modo JSON (servidores que no lo aceptan) tampoco se añade response_format.
    OpenAICompatibleProvider(_config(url, ai_json_mode=False, ai_reasoning_effort="low")).complete(
        REQUEST
    )
    assert "response_format" not in model.bodies[-1]
    assert model.bodies[-1]["reasoning_effort"] == "low"


def test_strict_provider_keeps_working_unless_the_admin_sets_the_parameter(
    llama: tuple[str, LlamaCpp],
) -> None:
    url, model = llama
    model.strict = True
    model.answer = lambda request: answer(["A1"])
    # Por defecto el parámetro no viaja: un proveedor estricto se comporta como antes.
    OpenAICompatibleProvider(_config(url)).complete(REQUEST)
    assert "reasoning_effort" not in model.bodies[-1]
    with pytest.raises(AIProviderUnavailableError) as info:
        OpenAICompatibleProvider(_config(url, ai_reasoning_effort="none")).complete(REQUEST)
    assert "reasoning_effort" not in info.value.message  # sin eco del cuerpo del proveedor


def test_reasoning_effort_values_are_validated() -> None:
    from pydantic import ValidationError

    from app.core.config import Settings

    with pytest.raises(ValidationError):
        Settings(ai_reasoning_effort="off")
    assert _config("http://127.0.0.1:1/v1", ai_reasoning_effort="none").reasoning_effort == "none"
    # La consola usa la misma configuración (solo cambia el destino a loopback).
    console = _config("http://127.0.0.1:1/v1", ai_reasoning_effort="none").console_provider_config()
    assert console.reasoning_effort == "none"


def test_null_content_with_reasoning_is_classified_not_rejected_as_body() -> None:
    provider = OpenAICompatibleProvider(_config("http://127.0.0.1:1/v1"))
    body = {
        "choices": [
            {"message": {"content": None, "reasoning": "pensando"}, "finish_reason": "length"}
        ]
    }
    response = provider._parse(200, json.dumps(body).encode(), 5)
    assert response.content == "" and response.reasoning_chars == len("pensando")
    with pytest.raises(AIInvalidResponseError) as info:
        provider._parse(200, b'{"choices": [{"message": {"content": 5}}]}', 5)
    assert _reason(info) == "unexpected_body"
    with pytest.raises(AIInvalidResponseError) as info:
        provider._parse(200, b"<html>", 5)
    assert _reason(info) == "unexpected_body"


# --- Clasificación del fallo ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("response", "reason"),
    [
        (_response("", finish_reason="length", reasoning_chars=4000), "truncated_reasoning"),
        (_response("<think>pensando sin cerrar", finish_reason="length"), "truncated_reasoning"),
        (_response("", finish_reason="length"), "truncated"),
        (_response("", finish_reason="stop", reasoning_chars=900), "reasoning_only"),
        (_response("<think>todo</think>  ", finish_reason="stop"), "reasoning_only"),
        (_response("", finish_reason="stop"), "empty_answer"),
        (_response("   "), "empty_answer"),
    ],
)
def test_unusable_answers_are_told_apart(response: AIResponse, reason: str) -> None:
    with pytest.raises(AIInvalidResponseError) as info:
        answer_content(response)
    assert _reason(info) == reason
    assert reason in INVALID_REASONS


def test_json_and_schema_failures_are_told_apart() -> None:
    with pytest.raises(AIInvalidResponseError) as info:
        parse_json("Claro, aquí tienes el análisis")
    assert _reason(info) == "invalid_json"
    # JSON cortado por max_tokens: truncado, no "el modelo no sabe JSON".
    cut = answer(["D1"])[:120]
    with pytest.raises(AIInvalidResponseError) as info:
        parse_json(cut, truncated=True)
    assert _reason(info) == "truncated"
    with pytest.raises(AIInvalidResponseError) as info:
        parse_json(cut)
    assert _reason(info) == "invalid_json"
    # El JSON genérico de la prueba de Jesus es JSON válido, pero no es un análisis.
    generic = '{"status": "ok", "message": "SENTRA_LOCAL_OK"}'
    for parse in (parse_json, parse_console_json):
        with pytest.raises(AIInvalidResponseError) as info:
            parse(generic)
        assert _reason(info) == "schema_mismatch"
    with pytest.raises(AIInvalidResponseError) as info:
        parse_json('["summary"]')
    assert _reason(info) == "invalid_json"
    # Un RawInsight válido, con razonamiento cerrado delante, sí pasa.
    ok = _response("<think>breve</think>" + answer(["D1"]), finish_reason="stop")
    assert parse_json(answer_content(ok)).summary


# --- AI Security Insights de punta a punta -------------------------------------------------


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


def _details(event: AuditEvent) -> dict[str, Any]:
    assert event.details is not None
    return event.details


def test_insights_with_a_thinking_model_fails_with_a_precise_reason(
    client: TestClient, engine: Engine, db: Session, caplog: pytest.LogCaptureFixture
) -> None:
    fake, _ = _enable(client)
    ids = _scenario(client, engine)
    fake.responder = lambda request: _response(
        "", finish_reason="length", reasoning_chars=len(THOUGHT), usage_output=1200
    )
    with caplog.at_level(logging.WARNING, logger="app.services.ai_service"):
        response = client.post(f"{API}/ai/assets/{ids['asset']}/analyze")
    assert response.status_code == 502
    error = response.json()["error"]
    assert error["code"] == "ai_invalid_response"
    assert error["details"] == [{"reason": "truncated_reasoning"}]
    # Cortado por max_tokens: no se reintenta (mismo presupuesto, misma respuesta).
    assert len(fake.requests) == 1
    (failed,) = _audit(db, "ai_analysis_failed")
    details = _details(failed)
    assert details["error"] == "ai_invalid_response"
    assert details["reason"] == "truncated_reasoning"
    assert details["finish_reason"] == "length"
    assert details["reasoning_chars"] == len(THOUGHT) and details["output_chars"] == 0
    assert details["usage_output"] == 1200 and details["attempts"] == 1
    record = next(r for r in caplog.records if r.getMessage() == "ai analysis failed")
    assert record.__dict__["ai_reason"] == "truncated_reasoning"
    # Ni el razonamiento ni el contexto llegan a la auditoría ni al log.
    assert "Windows" not in json.dumps(details)
    assert not any("detecciones recurrentes" in r.getMessage() for r in caplog.records)


def test_insights_retries_bad_json_once_and_reports_schema_mismatch(
    client: TestClient, engine: Engine, db: Session
) -> None:
    fake, _ = _enable(client)
    ids = _scenario(client, engine)
    fake.responder = lambda request: "no es JSON"
    response = client.post(f"{API}/ai/assets/{ids['asset']}/analyze")
    assert response.json()["error"]["details"] == [{"reason": "invalid_json"}]
    assert len(fake.requests) == 2  # AI_MAX_RETRIES=1, sin cambios
    fake.requests.clear()
    fake.responder = lambda request: '{"status": "ok", "message": "SENTRA_LOCAL_OK"}'
    response = client.post(f"{API}/ai/assets/{ids['asset']}/analyze", json={"refresh": True})
    assert response.status_code == 502
    assert response.json()["error"]["details"] == [{"reason": "schema_mismatch"}]
    assert len(fake.requests) == 2
    assert _details(_audit(db, "ai_analysis_failed")[-1])["reason"] == "schema_mismatch"


def test_insights_with_llama_cpp_and_reasoning_off_returns_a_valid_insight(
    client: TestClient, engine: Engine, llama: tuple[str, LlamaCpp]
) -> None:
    url, model = llama
    _enable(client, ai_base_url=url, ai_model="qwen-local")
    app: Any = client.app
    app.state.ai_provider_factory = default_provider_factory  # proveedor HTTP real
    ids = _scenario(client, engine)
    # Sin reasoning_effort: el fallo real de Jesus, ahora con su motivo.
    failed = client.post(f"{API}/ai/assets/{ids['asset']}/analyze")
    assert failed.json()["error"]["details"] == [{"reason": "truncated_reasoning"}]
    assert len(model.bodies) == 1
    _enable(client, ai_base_url=url, ai_model="qwen-local", ai_reasoning_effort="none")
    app.state.ai_provider_factory = default_provider_factory
    body = client.post(f"{API}/ai/assets/{ids['asset']}/analyze", json={"refresh": True})
    assert body.status_code == 200, body.text
    insight = body.json()
    assert insight["model"] == "qwen-local" and insight["result"]["origin"] == "model"
    assert insight["result"]["evidence_refs"], "el análisis cita evidencia real de Sentra"
    assert model.bodies[-1]["reasoning_effort"] == "none"


# --- Analyst Console: misma corrección sin tocar la privacidad de Security-Fix1 ------------


def test_console_with_llama_cpp_keeps_review_and_loopback(
    client: TestClient, engine: Engine, db: Session, llama: tuple[str, LlamaCpp]
) -> None:
    url, model = llama
    _console(client, ai_base_url=url, ai_model="qwen-local", ai_reasoning_effort="none")
    app: Any = client.app
    app.state.ai_provider_factory = default_provider_factory
    with TestClient(client.app) as analyst:
        authenticate(analyst, engine, "analyst")
        _, execution_id = _profile(analyst, db)
        # Sin revisión no sale nada hacia el modelo.
        refused = analyst.post(f"{API}/ai/console/assist", json={"execution_ids": [execution_id]})
        assert refused.status_code == 422 and model.bodies == []
        result = analyst.post(f"{API}/ai/console/assist", json={})  # cuerpo inválido
        assert result.status_code == 422 and model.bodies == []
        response = _assist(analyst, execution_ids=[execution_id])
        assert response.status_code == 200, response.text
    assert len(model.bodies) == 1
    assert model.bodies[0]["reasoning_effort"] == "none"
    assert response.json()["result"]["origin"] == "model"
    reviewed = _audit(db, "ai_console_context_reviewed")
    assert reviewed and _details(reviewed[-1])["destination"] == "loopback"


def test_console_reports_the_same_reasons(client: TestClient, engine: Engine, db: Session) -> None:
    fake, _ = _console(client)
    fake.responder = lambda request: _response(
        "<think>" + THOUGHT, finish_reason="length", usage_output=1200
    )
    with TestClient(client.app) as analyst:
        authenticate(analyst, engine, "analyst")
        _, execution_id = _profile(analyst, db)
        response = _assist(analyst, execution_ids=[execution_id])
    assert response.status_code == 502
    assert response.json()["error"]["details"] == [{"reason": "truncated_reasoning"}]
    assert len(fake.requests) == 1
    assert "Windows" not in json.dumps(_details(_audit(db, "ai_analysis_failed")[-1]))


def test_unexpected_provider_body_is_audited_with_its_reason(
    client: TestClient, engine: Engine, db: Session
) -> None:
    fake, _ = _enable(client)
    ids = _scenario(client, engine)
    fake.responder = lambda request: AIInvalidResponseError(
        "The AI provider returned an unexpected body", "unexpected_body"
    )
    response = client.post(f"{API}/ai/assets/{ids['asset']}/analyze")
    assert response.json()["error"]["details"] == [{"reason": "unexpected_body"}]
    assert len(fake.requests) == 1  # un error del proveedor no se reintenta (como antes)
    assert _details(_audit(db, "ai_analysis_failed")[-1])["reason"] == "unexpected_body"
