"""Piezas de la Fase 4J sin base de datos: proveedor HTTP, local/externo, redacción, salida.

El proveedor OpenAI-compatible se prueba contra un servidor HTTP local de pruebas en
127.0.0.1 (nunca Internet): éxito, errores HTTP, redirecciones y timeouts.
"""

import json
import threading
import time
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from app.ai.config import AIConfig, classify_location
from app.ai.context import AIContext, EvidenceRef
from app.ai.openai_compat import OpenAICompatibleProvider
from app.ai.output import ground, parse_json
from app.ai.provider import (
    AIInvalidResponseError,
    AIProviderAuthError,
    AIProviderRateLimitedError,
    AIProviderUnavailableError,
    AIRequest,
    AITimeoutError,
    AIUngroundedResponseError,
)
from app.ai.redaction import Redactor
from app.core.config import Settings, get_settings, parse_ai_local_networks

KEY = "sk-unit-test-secret-value"
Handler = Callable[[BaseHTTPRequestHandler, dict[str, Any]], None]


@pytest.fixture
def server() -> Iterator[tuple[str, list[dict[str, Any]], list[Handler]]]:
    """Servidor local que delega en `handlers[0]` y guarda lo recibido."""
    received: list[dict[str, Any]] = []
    handlers: list[Handler] = []

    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length))
            received.append({"path": self.path, "headers": dict(self.headers), "body": body})
            handlers[0](self, body)

        def log_message(self, *args: Any) -> None:
            return

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}/v1", received, handlers
    httpd.shutdown()
    httpd.server_close()


def _reply(status: int, payload: Any) -> Handler:
    def handler(h: BaseHTTPRequestHandler, _: dict[str, Any]) -> None:
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        h.send_response(status)
        h.send_header("Content-Type", "application/json")
        h.send_header("Content-Length", str(len(data)))
        h.end_headers()
        h.wfile.write(data)

    return handler


def _config(base_url: str, **overrides: Any) -> AIConfig:
    values: dict[str, Any] = {
        "ai_enabled": True,
        "ai_base_url": base_url,
        "ai_model": "local-model",
        "ai_api_key": None,
        **overrides,
    }
    return AIConfig.from_settings(get_settings().model_copy(update=values))


REQUEST = AIRequest(system="sistema", user='{"task":"ask"}', max_output_tokens=300)


def test_provider_sends_separated_messages_and_parses_the_answer(server: Any) -> None:
    url, received, handlers = server
    handlers.append(
        _reply(
            200,
            {
                "model": "local-model-q4",
                "choices": [{"message": {"content": '{"summary": "ok"}'}}],
                "usage": {"prompt_tokens": 12, "completion_tokens": 3},
            },
        )
    )
    from pydantic import SecretStr

    provider = OpenAICompatibleProvider(_config(url, ai_api_key=SecretStr(KEY)))
    response = provider.complete(REQUEST)
    assert response.content == '{"summary": "ok"}' and response.model == "local-model-q4"
    assert (response.usage_input, response.usage_output) == (12, 3)
    sent = received[0]
    assert sent["path"] == "/v1/chat/completions"
    assert sent["headers"]["Authorization"] == f"Bearer {KEY}"
    assert [m["role"] for m in sent["body"]["messages"]] == ["system", "user"]
    assert sent["body"]["temperature"] == 0 and sent["body"]["stream"] is False
    assert sent["body"]["response_format"] == {"type": "json_object"}
    # Sin clave configurada no se envía Authorization (modelo local sin autenticación).
    OpenAICompatibleProvider(_config(url, ai_json_mode=False)).complete(REQUEST)
    assert "Authorization" not in received[1]["headers"]
    assert "response_format" not in received[1]["body"]


@pytest.mark.parametrize(
    ("status", "error"),
    [
        (401, AIProviderAuthError),
        (403, AIProviderAuthError),
        (429, AIProviderRateLimitedError),
        (500, AIProviderUnavailableError),
        (400, AIProviderUnavailableError),
    ],
)
def test_provider_http_errors_are_mapped(server: Any, status: int, error: type) -> None:
    url, _, handlers = server
    handlers.append(_reply(status, {"error": {"message": f"bad key {KEY}"}}))
    with pytest.raises(error) as info:
        OpenAICompatibleProvider(_config(url)).complete(REQUEST)
    # El cuerpo del proveedor nunca llega al mensaje (podría contener eco de secretos).
    assert KEY not in str(info.value)


def test_provider_rejects_bad_bodies_and_never_follows_redirects(server: Any) -> None:
    url, received, handlers = server
    handlers.append(_reply(200, b"<html>not json</html>"))
    with pytest.raises(AIInvalidResponseError):
        OpenAICompatibleProvider(_config(url)).complete(REQUEST)

    def redirect(h: BaseHTTPRequestHandler, _: dict[str, Any]) -> None:
        h.send_response(307)
        h.send_header("Location", "http://198.51.100.1/steal")
        h.send_header("Content-Length", "0")
        h.end_headers()

    handlers[0] = redirect
    with pytest.raises(AIInvalidResponseError):
        OpenAICompatibleProvider(_config(url)).complete(REQUEST)
    assert len(received) == 2  # la redirección no se siguió


def test_provider_overall_timeout_bounds_a_slow_model(server: Any) -> None:
    url, _, handlers = server

    def slow(h: BaseHTTPRequestHandler, _: dict[str, Any]) -> None:
        time.sleep(1.5)
        _reply(200, {"choices": [{"message": {"content": "{}"}}]})(h, {})

    handlers.append(slow)
    config = _config(url)
    object.__setattr__(config, "timeout_seconds", 0.5)
    started = time.monotonic()
    with pytest.raises(AITimeoutError):
        OpenAICompatibleProvider(config).complete(REQUEST)
    assert time.monotonic() - started < 1.4


def test_provider_unreachable_is_unavailable() -> None:
    # Puerto 9 (discard) cerrado en loopback: conexión rechazada al instante.
    with pytest.raises(AIProviderUnavailableError):
        OpenAICompatibleProvider(_config("http://127.0.0.1:9/v1")).complete(REQUEST)


def test_local_or_external_by_configured_url() -> None:
    local_hosts = frozenset({"servidor-ia"})
    # 4J.1: una IP privada solo es local si su red está en AI_LOCAL_NETWORKS.
    networks = parse_ai_local_networks("192.168.50.0/24,10.0.0.0/8")
    for url in (
        "http://127.0.0.1:11434/v1",
        "http://localhost:8080/v1",
        "http://192.168.50.10:8000/v1",
        "http://10.0.0.5/v1",
        "http://[::1]:8000/v1",
        "http://servidor-ia:9000/v1",
    ):
        assert classify_location(url, local_hosts, networks) == "local", url
    for url in (
        "https://api.openai.com/v1",
        "http://8.8.8.8/v1",
        "http://192.168.51.10/v1",
        "http://172.16.0.5/v1",
        # Un nombre no listado es externo aunque resuelva a una IP privada (fail closed).
        "http://ia.empresa.lan/v1",
    ):
        assert classify_location(url, local_hosts, networks) == "external", url


def test_settings_validation_and_config_never_prints_the_key() -> None:
    with pytest.raises(ValueError, match="AI_REDACT"):
        Settings(database_url="postgresql+psycopg://x/y", ai_redact="emails")
    from pydantic import SecretStr

    config = _config("http://127.0.0.1:1/v1", ai_api_key=SecretStr(KEY))
    assert KEY not in repr(config) and KEY not in str(config)
    assert _config("http://127.0.0.1:1/v1", ai_enabled=False).unavailable_reason()
    assert "AI_BASE_URL" in (_config(None).unavailable_reason() or "")  # type: ignore[arg-type]


def test_redactor_keeps_correlation_and_restores() -> None:
    r = Redactor({"usernames", "hostnames", "ips", "paths"})
    assert r.value("usernames", "Administrator") == "[user-1]"
    assert r.value("usernames", "administrator") == "[user-1]"  # misma cuenta, mismo alias
    assert r.value("hostnames", "PC-01") == "[host-2]"
    text = r.text(r"Administrator inició sesión en PC-01 desde 10.1.2.3 con C:\Temp\x.exe")
    assert text == "[user-1] inició sesión en [host-2] desde [ip-3] con [path-4]"
    assert r.restore("Revise [host-2] y [user-1]; [user-99] no existe") == (
        "Revise PC-01 y Administrator; [user-99] no existe"
    )
    # Sin redacción configurada, nada cambia.
    assert Redactor(()).text("PC-01 10.1.2.3") == "PC-01 10.1.2.3"


def _ctx() -> AIContext:
    refs = {
        "A1": EvidenceRef("asset", "a-uuid", "PC-01", "a-uuid"),
        "D1": EvidenceRef("detection", "d-uuid", "AUTH-001", "a-uuid"),
    }
    return AIContext(
        scope="asset",
        data={"active_detections": [{"confidence": "low", "severity": "high"}]},
        refs=refs,
        redactor=Redactor(()),
    )


def test_output_schema_and_grounding() -> None:
    with pytest.raises(AIInvalidResponseError):
        parse_json("[1, 2]")
    with pytest.raises(AIInvalidResponseError):
        parse_json('{"assessment": "sin summary"}')
    raw = parse_json(
        json.dumps(
            {
                "summary": "s",
                "key_findings": [
                    {"text": "con evidencia", "certainty": "CONFIRMED", "evidence": ["d1", "D7"]},
                    {"text": "sin evidencia", "certainty": "observed", "evidence": []},
                ],
                "recommended_actions": [{"text": "validar", "evidence": ["A1"]}],
                "evidence_refs": ["A1"],
                "extra_field": "ignorado",
            }
        )
    )
    result = ground(raw, _ctx())
    # La certeza fuera de vocabulario se degrada; la referencia válida se normaliza.
    assert result["key_findings"] == [
        {"text": "con evidencia", "certainty": "requires_validation", "evidence": ["D1"]}
    ]
    assert result["dropped_refs"] == 1
    assert [r["id"] for r in result["evidence_refs"]] == ["a-uuid", "d-uuid"]
    assert len(result["warnings"]) == 2  # ref descartada + hallazgo sin evidencia

    ungrounded = parse_json(
        json.dumps({"summary": "s", "key_findings": [{"text": "x", "evidence": ["D9"]}]})
    )
    with pytest.raises(AIUngroundedResponseError):
        ground(ungrounded, _ctx())

    # Sin hallazgos ni referencias: se marca como datos insuficientes (no es un error).
    empty = ground(parse_json('{"summary": "No hay datos suficientes."}'), _ctx())
    assert empty["insufficient_data"] is True
