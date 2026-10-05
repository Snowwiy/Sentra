"""Fase 4J.1: IA local-first, fail closed y sin fallback cloud.

Todo corre contra servidores HTTP de prueba en 127.0.0.1 o con conexiones simuladas: ningún
test necesita Internet ni DNS. Las conexiones salientes se registran parcheando
`socket.create_connection` (lo que usa http.client) para demostrar qué destinos se tocan.
"""

import json
import socket
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy.engine import Engine

from app.ai.config import AIConfig, classify_location, is_authorized_local_ip
from app.ai.openai_compat import OpenAICompatibleProvider
from app.ai.provider import (
    AIDestinationBlockedError,
    AIProviderUnavailableError,
    AIRequest,
)
from app.core.config import Settings, get_settings, parse_ai_local_networks
from app.services.ai_service import AIRuntime, default_provider_factory
from tests.ai_fakes import FakeAIProvider, grounded
from tests.test_ai import _enable, _scenario

API = "/api/v1"
KEY = "sk-local-NEVER-LEAK-42"
REQUEST = AIRequest(system="sistema", user='{"task":"ask"}', max_output_tokens=300)
OK_BODY = {"model": "qwen-local", "choices": [{"message": {"content": '{"summary": "ok"}'}}]}


class _LocalModel(BaseHTTPRequestHandler):
    """Servidor OpenAI-compatible mínimo (como Ollama, llama.cpp o vLLM en /v1)."""

    received: list[dict[str, Any]]
    models_status = 200

    def _send(self, status: int, payload: Any) -> None:
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        self.received.append(
            {"path": self.path, "headers": dict(self.headers), "body": self.rfile.read(length)}
        )
        self._send(200, OK_BODY)

    def do_GET(self) -> None:
        self.received.append({"path": self.path, "headers": dict(self.headers), "body": b""})
        self._send(self.models_status, {"data": [{"id": "qwen-local"}]})

    def log_message(self, *args: Any) -> None:
        return


@pytest.fixture
def local_model() -> Iterator[tuple[int, list[dict[str, Any]], type[_LocalModel]]]:
    received: list[dict[str, Any]] = []
    handler = type("Handler", (_LocalModel,), {"received": received})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd.server_address[1], received, handler
    httpd.shutdown()
    httpd.server_close()


@pytest.fixture
def connections(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, int]]:
    """Registra cada conexión TCP que abre http.client (destino host, puerto)."""
    seen: list[tuple[str, int]] = []
    real = socket.create_connection

    def recording(address: tuple[str, int], *args: Any, **kwargs: Any) -> socket.socket:
        seen.append((address[0], address[1]))
        return real(address, *args, **kwargs)

    monkeypatch.setattr(socket, "create_connection", recording)
    return seen


@pytest.fixture
def no_dns(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Sin DNS: cualquier resolución de un nombre falla (solo IPs literales funcionan)."""
    asked: list[str] = []
    real = socket.getaddrinfo

    def offline(host: Any, *args: Any, **kwargs: Any) -> Any:
        try:
            socket.inet_pton(socket.AF_INET6 if ":" in str(host) else socket.AF_INET, str(host))
        except OSError:
            asked.append(str(host))
            raise socket.gaierror("no DNS in this test") from None
        return real(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", offline)
    return asked


def _config(base_url: str, **overrides: Any) -> AIConfig:
    values: dict[str, Any] = {
        "ai_enabled": True,
        "ai_base_url": base_url,
        "ai_model": "qwen-local",
        "ai_api_key": None,
        **overrides,
    }
    return AIConfig.from_settings(get_settings().model_copy(update=values))


class _FakeConn:
    """Conexión ya establecida cuyo par remoto es `peer` (para probar el check de IP real)."""

    def __init__(self, peer: str) -> None:
        self.sock = self
        self._peer = peer

    def getpeername(self) -> tuple[str, int]:
        return (self._peer, 8000)


# --- Destinos permitidos -------------------------------------------------------------------


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost"])
def test_loopback_local_model_works_without_api_key(
    local_model: Any, connections: list[tuple[str, int]], host: str
) -> None:
    port, received, _ = local_model
    config = _config(f"http://{host}:{port}/v1")
    assert config.location == "local" and config.unavailable_reason() is None
    response = OpenAICompatibleProvider(config).complete(REQUEST)
    assert response.content == '{"summary": "ok"}'
    # Sin AI_API_KEY no se exige clave dummy ni se envía Authorization.
    assert "Authorization" not in received[0]["headers"]
    assert {target for target in connections} == {(host, port)}


def test_ipv6_loopback_is_local() -> None:
    config = _config("http://[::1]:11434/v1")
    assert config.location == "local" and config.unavailable_reason() is None
    assert is_authorized_local_ip("::1", ())
    # El contenedor de CI puede no tener IPv6: se comprueba la IP real con un par simulado.
    OpenAICompatibleProvider(config)._check_peer(_FakeConn("::1"))  # type: ignore[arg-type]


def test_private_lan_is_local_only_when_its_network_is_authorized() -> None:
    url = "http://192.168.50.10:8000/v1"
    blocked = _config(url)
    assert blocked.location == "external"
    reason = blocked.unavailable_reason()
    assert reason is not None and "AI_LOCAL_NETWORKS" in reason
    with pytest.raises(AIDestinationBlockedError):
        OpenAICompatibleProvider(blocked)

    allowed = _config(url, ai_local_networks="192.168.50.0/24")
    assert allowed.location == "local" and allowed.unavailable_reason() is None
    provider = OpenAICompatibleProvider(allowed)
    provider._check_peer(_FakeConn("192.168.50.10"))  # type: ignore[arg-type]
    # Otra red privada no autorizada sigue siendo externa.
    assert _config("http://192.168.60.10/v1", ai_local_networks="192.168.50.0/24").location == (
        "external"
    )


def test_local_hostname_must_connect_to_an_authorized_address() -> None:
    # "servidor-ia" está en AI_LOCAL_HOSTS, pero si el DNS (o /etc/hosts) lo resuelve fuera de
    # loopback/AI_LOCAL_NETWORKS no se envía nada: se verifica la IP real antes del POST.
    config = _config("http://servidor-ia:8000/v1", ai_local_hosts="servidor-ia")
    provider = OpenAICompatibleProvider(config)
    with pytest.raises(AIDestinationBlockedError):
        provider._check_peer(_FakeConn("203.0.113.7"))  # type: ignore[arg-type]
    with pytest.raises(AIDestinationBlockedError):
        provider._check_peer(_FakeConn("192.168.1.20"))  # type: ignore[arg-type]
    provider._check_peer(_FakeConn("127.0.0.1"))  # type: ignore[arg-type]
    provider._check_peer(_FakeConn("::ffff:127.0.0.1"))  # type: ignore[arg-type]


def test_local_networks_setting_only_accepts_private_lans() -> None:
    assert len(parse_ai_local_networks("192.168.1.0/24, 10.20.0.0/16,fd12:3456::/48")) == 3
    for bad in (
        "0.0.0.0/0",
        "8.8.8.0/24",
        "169.254.0.0/16",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "::/0",
        "fe80::/10",
        "no-es-una-red",
    ):
        with pytest.raises(ValueError, match="AI_LOCAL_NETWORKS"):
            parse_ai_local_networks(bad)
        with pytest.raises(ValueError):
            Settings(database_url="postgresql+psycopg://x/y", ai_local_networks=bad)


# --- Destinos bloqueados (fail closed) -----------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://api.openai.com/v1",
        "https://api.anthropic.com/v1",
        "https://generativelanguage.googleapis.com/v1beta/openai",
        "https://empresa.openai.azure.com/openai/v1",
        "http://8.8.8.8/v1",
    ],
)
def test_public_endpoint_is_blocked_by_default_without_connecting(
    url: str, connections: list[tuple[str, int]], no_dns: list[str]
) -> None:
    config = _config(url, ai_api_key=SecretStr(KEY))
    assert config.location == "external"
    reason = config.unavailable_reason()
    assert reason is not None and "AI_ALLOW_EXTERNAL=false" in reason
    with pytest.raises(AIDestinationBlockedError) as info:
        OpenAICompatibleProvider(config)
    assert KEY not in str(info.value)
    # Ni conexión ni consulta DNS: la decisión solo usa la URL configurada.
    assert connections == [] and no_dns == []


def test_external_needs_explicit_opt_in_https_and_never_metadata_addresses() -> None:
    assert _config("https://api.openai.com/v1", ai_allow_external=True).unavailable_reason() is None
    plain = _config("http://api.example.com/v1", ai_allow_external=True).unavailable_reason()
    assert plain is not None and "https" in plain
    # Link-local (metadatos de nube) nunca es un servidor de IA, ni con AI_ALLOW_EXTERNAL.
    for url in ("http://169.254.169.254/v1", "http://0.0.0.0:11434/v1"):
        reason = _config(url, ai_allow_external=True).unavailable_reason()
        assert reason is not None and "no válida" in reason


# --- Caídas, sin fallback y sin red --------------------------------------------------------


def test_local_server_down_is_a_controlled_error_with_no_fallback(
    connections: list[tuple[str, int]],
) -> None:
    # Puerto 9 cerrado en loopback. Aunque AI_ALLOW_EXTERNAL=true, no se prueba otro destino.
    config = _config("http://127.0.0.1:9/v1", ai_allow_external=True, ai_api_key=SecretStr(KEY))
    with pytest.raises(AIProviderUnavailableError) as info:
        OpenAICompatibleProvider(config).complete(REQUEST)
    assert KEY not in str(info.value) and "127.0.0.1" not in str(info.value)
    assert connections == [("127.0.0.1", 9)]


def test_local_model_works_without_dns_and_ignores_proxy_env(
    local_model: Any,
    no_dns: list[str],
    connections: list[tuple[str, int]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Un proxy del entorno nunca debe desviar los datos (ni necesitar Internet para un local).
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy"):
        monkeypatch.setenv(name, "http://proxy.invalid:3128")
    port, received, _ = local_model
    config = _config(f"http://127.0.0.1:{port}/v1")
    assert OpenAICompatibleProvider(config).complete(REQUEST).model == "qwen-local"
    assert OpenAICompatibleProvider(config).check().reachable is True
    assert no_dns == [] and connections == [("127.0.0.1", port), ("127.0.0.1", port)]
    assert [r["path"] for r in received] == ["/v1/chat/completions", "/v1/models"]


def test_health_check_sends_no_sentra_data(local_model: Any) -> None:
    port, received, handler = local_model
    provider = OpenAICompatibleProvider(_config(f"http://127.0.0.1:{port}/v1"))
    assert provider.check().reachable is True
    assert received[-1]["body"] == b"" and "Authorization" not in received[-1]["headers"]
    # Servidores sin /models (404) siguen contando como disponibles; un 5xx no.
    handler.models_status = 404
    assert provider.check().reachable is True
    handler.models_status = 503
    assert provider.check().reachable is False
    handler.models_status = 401
    assert provider.check().reachable is False
    down = OpenAICompatibleProvider(_config("http://127.0.0.1:9/v1")).check()
    assert down.reachable is False and down.detail and "127.0.0.1" not in down.detail


# --- API: estado del proveedor y Sentra sin IA ---------------------------------------------


def test_status_reports_provider_state_without_secrets(client: TestClient) -> None:
    status = client.get(f"{API}/ai/status").json()
    assert (status["state"], status["mode_label"], status["reachable"]) == (
        "disabled",
        None,
        None,
    )

    fake, _ = _enable(client, ai_api_key=SecretStr(KEY))
    status = client.get(f"{API}/ai/status").json()
    assert status["state"] == "local_available" and status["mode_label"] == "Local AI"
    assert status["model"] == "fake-model" and status["reachable"] is True
    # El protocolo OpenAI-compatible no convierte un modelo local en "OpenAI".
    assert "openai" not in status["mode_label"].lower()
    raw = client.get(f"{API}/ai/status").text
    assert KEY not in raw and "127.0.0.1" not in raw and "base_url" not in raw
    assert fake.checks == 1  # health check cacheado entre llamadas

    fake, _ = _enable(client)
    fake.healthy = False
    status = client.get(f"{API}/ai/status").json()
    assert status["state"] == "local_unavailable" and status["available"] is True
    assert status["reachable"] is False and status["health_detail"]

    fake, _ = _enable(client, ai_base_url="https://api.openai.com/v1")
    status = client.get(f"{API}/ai/status").json()
    assert status["state"] == "external_blocked" and status["available"] is False
    assert fake.checks == 0  # destino bloqueado: ni siquiera se sondea

    fake, _ = _enable(client, ai_base_url="https://api.openai.com/v1", ai_allow_external=True)
    status = client.get(f"{API}/ai/status").json()
    assert status["state"] == "external_available" and status["mode_label"] == "External AI"

    _enable(client, ai_model=None)
    assert client.get(f"{API}/ai/status").json()["state"] == "not_configured"


def test_ai_disabled_opens_zero_connections(
    client: TestClient, engine: Engine, connections: list[tuple[str, int]]
) -> None:
    ids = _scenario(client, engine)
    app: Any = client.app
    calls: list[AIConfig] = []

    def factory(config: AIConfig) -> FakeAIProvider:
        calls.append(config)
        return FakeAIProvider()

    app.state.ai_provider_factory = factory
    assert client.get(f"{API}/ai/status").json()["state"] == "disabled"
    assert client.post(f"{API}/ai/assets/{ids['asset']}/analyze").status_code == 409
    assert client.post(f"{API}/ai/ask", json={"question": "¿Qué pasa?"}).status_code == 409
    assert calls == [] and connections == []


def test_local_model_down_keeps_sentra_working_and_never_falls_back(
    client: TestClient, engine: Engine, connections: list[tuple[str, int]]
) -> None:
    ids = _scenario(client, engine)
    settings = get_settings().model_copy(
        update={
            "ai_enabled": True,
            "ai_base_url": "http://127.0.0.1:9/v1",
            "ai_model": "qwen-local",
            # Aunque el admin permitiera externos, un local caído no se sustituye por otro.
            "ai_allow_external": True,
        }
    )
    app: Any = client.app
    app.dependency_overrides[get_settings] = lambda: settings
    factories: list[AIConfig] = []

    def factory(config: AIConfig) -> Any:
        factories.append(config)
        return default_provider_factory(config)

    app.state.ai_provider_factory = factory
    app.state.ai_runtime = AIRuntime(AIConfig.from_settings(settings))

    status = client.get(f"{API}/ai/status").json()
    assert status["state"] == "local_unavailable" and status["reachable"] is False

    response = client.post(f"{API}/ai/assets/{ids['asset']}/analyze")
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "ai_provider_unavailable"
    # Un único destino (el local configurado), sin reintentos hacia otro proveedor.
    assert {target for target in connections} == {("127.0.0.1", 9)}
    assert {c.base_url for c in factories} == {"http://127.0.0.1:9/v1"}

    # Ingesta, detecciones y riesgo siguen funcionando sin el modelo.
    assert client.get(f"{API}/risk/assets/{ids['asset']}").json()["evaluated"] is True
    assert client.get(f"{API}/detections/{ids['detection']}").status_code == 200
    assert client.get(f"{API}/assets").status_code == 200


def test_local_model_recovers_without_restart(client: TestClient, engine: Engine) -> None:
    ids = _scenario(client, engine)
    fake, _ = _enable(client)
    fake.responder = lambda _: AIProviderUnavailableError("The AI provider is unavailable")
    first = client.post(f"{API}/ai/assets/{ids['asset']}/analyze")
    assert first.status_code == 502
    fake.responder = grounded
    assert client.post(f"{API}/ai/assets/{ids['asset']}/analyze").status_code == 200


def test_classification_never_resolves_names(no_dns: list[str]) -> None:
    for url in ("http://servidor-ia:8000/v1", "https://api.openai.com/v1", "http://localhost/v1"):
        classify_location(url, frozenset({"servidor-ia"}))
        _config(url, ai_local_hosts="servidor-ia").unavailable_reason()
    assert no_dns == []


def test_end_to_end_with_a_local_model_and_no_internet(
    client: TestClient,
    engine: Engine,
    no_dns: list[str],
    connections: list[tuple[str, int]],
) -> None:
    """Criterio de éxito de la 4J.1: análisis completo con un modelo local, sin DNS ni Internet."""
    ids = _scenario(client, engine)

    class _GroundedModel(_LocalModel):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length))
            self.received.append({"path": self.path, "headers": dict(self.headers), "body": b""})
            request = AIRequest(
                system=body["messages"][0]["content"],
                user=body["messages"][1]["content"],
                max_output_tokens=body["max_tokens"],
            )
            self._send(
                200,
                {"model": "qwen-local", "choices": [{"message": {"content": grounded(request)}}]},
            )

    received: list[dict[str, Any]] = []
    httpd = ThreadingHTTPServer(
        ("127.0.0.1", 0), type("Handler", (_GroundedModel,), {"received": received})
    )
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        port = httpd.server_address[1]
        settings = get_settings().model_copy(
            update={
                "ai_enabled": True,
                "ai_base_url": f"http://127.0.0.1:{port}/v1",
                "ai_model": "qwen-local",
                "ai_api_key": None,
            }
        )
        app: Any = client.app
        app.dependency_overrides[get_settings] = lambda: settings
        app.state.ai_provider_factory = default_provider_factory
        app.state.ai_runtime = AIRuntime(AIConfig.from_settings(settings))

        status = client.get(f"{API}/ai/status").json()
        assert (status["state"], status["mode_label"], status["model"]) == (
            "local_available",
            "Local AI",
            "qwen-local",
        )
        response = client.post(f"{API}/ai/assets/{ids['asset']}/analyze")
        assert response.status_code == 200, response.text
        assert response.json()["result"]["evidence_refs"]
    finally:
        httpd.shutdown()
        httpd.server_close()
    assert no_dns == []
    assert {target for target in connections} == {("127.0.0.1", port)}
    assert all("Authorization" not in r["headers"] for r in received)
