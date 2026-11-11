"""Fase 7D.1 (H04, H05): transporte del agente 0.7.0 con servidores locales sintéticos.

Reproducción H05: antes, urllib seguía las redirecciones 301/302/303/307/308 y reenviaba la
petición (con la cabecera Authorization o la credencial de enrolamiento) a la URL que dijera
el servidor, incluso a otro host o a http:// en claro. Ahora la redirección es un error
controlado, el segundo servidor no recibe nada y el agente reintenta con backoff.

Todo con datos sintéticos y servidores en 127.0.0.1; el certificado TLS se genera para el
test con openssl (se omite el bloque TLS si no está disponible).
"""

import json
import shutil
import ssl
import subprocess
import threading
import time
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from sentra_agent.client import (
    ApiError,
    RedirectError,
    ResponseTooLargeError,
    SentraClient,
    TlsError,
    TransportError,
)
from sentra_agent.config import AgentConfig, insecure_url_reason

TOKEN = "sentra_at_" + "S" * 43


class Recorder:
    def __init__(self) -> None:
        self.requests: list[tuple[str, dict[str, str]]] = []


Behaviour = Callable[[BaseHTTPRequestHandler], None]


def _serve(behaviour: Behaviour, recorder: Recorder, tls: ssl.SSLContext | None = None) -> Any:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_: Any) -> None:
            pass

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            recorder.requests.append((self.path, dict(self.headers.items())))
            behaviour(self)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    if tls is not None:
        server.socket = tls.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture
def servers() -> Iterator[Callable[..., tuple[str, Recorder]]]:
    started: list[Any] = []

    def start(behaviour: Behaviour, tls: ssl.SSLContext | None = None) -> tuple[str, Recorder]:
        recorder = Recorder()
        server = _serve(behaviour, recorder, tls)
        started.append(server)
        scheme = "https" if tls else "http"
        return f"{scheme}://127.0.0.1:{server.server_address[1]}", recorder

    yield start
    for server in started:
        server.shutdown()
        server.server_close()


def _json(handler: BaseHTTPRequestHandler, status: int, body: Any) -> None:
    data = json.dumps(body).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


# --- H05: redirecciones ----------------------------------------------------------------------


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_h05_redirects_are_refused_and_credentials_never_forwarded(
    servers: Callable[..., tuple[str, Recorder]], status: int
) -> None:
    # Segundo servidor: otro origen (otro puerto) que recogería la credencial.
    attacker_url, attacker = servers(lambda h: _json(h, 200, {"asset_id": "x"}))

    def redirect(handler: BaseHTTPRequestHandler) -> None:
        handler.send_response(status)
        handler.send_header("Location", f"{attacker_url}/api/v1/agents/heartbeat")
        handler.send_header("Content-Length", "0")
        handler.end_headers()

    url, origin = servers(redirect)
    client = SentraClient(url, timeout=2)

    with pytest.raises(RedirectError) as raised:
        client.heartbeat(uuid4(), TOKEN)
    with pytest.raises(RedirectError):
        client.register(uuid4(), {"hostname": "PC"}, enrollment_token="sentra_et_" + "E" * 43)

    assert raised.value.status == status
    assert attacker_url in str(raised.value)
    # Es un fallo de transporte (el bucle reintenta con backoff), no un rechazo definitivo.
    assert isinstance(raised.value, TransportError)
    assert len(origin.requests) == 2
    assert attacker.requests == []  # nada llegó al otro origen: ni token ni cuerpo


def test_h05_redirect_from_https_to_http_is_refused(
    servers: Callable[..., tuple[str, Recorder]], tls_material: dict[str, Any]
) -> None:
    plain_url, plain = servers(lambda h: _json(h, 200, {}))

    def downgrade(handler: BaseHTTPRequestHandler) -> None:
        handler.send_response(302)
        handler.send_header("Location", plain_url + "/api/v1/agents/heartbeat")
        handler.send_header("Content-Length", "0")
        handler.end_headers()

    url, _ = servers(downgrade, tls_material["server"])
    client = SentraClient(url, timeout=2, ca_bundle=tls_material["ca"])
    with pytest.raises(RedirectError):
        client.heartbeat(uuid4(), TOKEN)
    assert plain.requests == []


# --- Endurecimiento: tamaño, JSON, plazo total -----------------------------------------------


def test_response_size_is_bounded_and_read_incrementally(
    servers: Callable[..., tuple[str, Recorder]],
) -> None:
    def huge(handler: BaseHTTPRequestHandler) -> None:
        handler.send_response(200)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(8 * 1024 * 1024))
        handler.end_headers()
        try:
            for _ in range(128):
                handler.wfile.write(b" " * 65536)
        except OSError:
            pass  # el cliente corta la lectura: es lo esperado

    url, _ = servers(huge)
    client = SentraClient(url, timeout=2, max_response_bytes=128 * 1024)
    with pytest.raises(ResponseTooLargeError):
        client.heartbeat(uuid4(), TOKEN)


@pytest.mark.parametrize("body", [b"[1, 2]", b'"text"', b"<html>portal</html>", b"null"])
def test_response_must_be_a_json_object(
    servers: Callable[..., tuple[str, Recorder]], body: bytes
) -> None:
    def answer(handler: BaseHTTPRequestHandler) -> None:
        handler.send_response(200)
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)

    url, _ = servers(answer)
    with pytest.raises(TransportError, match="unexpected"):
        SentraClient(url, timeout=2).heartbeat(uuid4(), TOKEN)


def test_total_deadline_stops_a_server_that_dribbles_the_response(
    servers: Callable[..., tuple[str, Recorder]],
) -> None:
    def dribble(handler: BaseHTTPRequestHandler) -> None:
        handler.send_response(200)
        handler.send_header("Content-Length", "200")
        handler.end_headers()
        try:
            for _ in range(200):
                handler.wfile.write(b" ")
                handler.wfile.flush()
                time.sleep(0.05)
        except OSError:
            pass

    url, _ = servers(dribble)
    client = SentraClient(url, timeout=1, deadline=1)
    started = time.monotonic()
    with pytest.raises(TransportError, match="deadline"):
        client.heartbeat(uuid4(), TOKEN)
    assert time.monotonic() - started < 5  # sin plazo total tardaría ~10 s


def test_client_errors_and_retryable_errors_are_still_distinguished(
    servers: Callable[..., tuple[str, Recorder]],
) -> None:
    url, _ = servers(lambda h: _json(h, 403, {"error": {"code": "agent_recovery_required"}}))
    with pytest.raises(ApiError) as raised:
        SentraClient(url, timeout=2).heartbeat(uuid4(), TOKEN)
    assert raised.value.code == "agent_recovery_required"

    def busy(handler: BaseHTTPRequestHandler) -> None:
        data = b'{"error": {"code": "rate_limited"}}'
        handler.send_response(429)
        handler.send_header("Retry-After", "7")
        handler.send_header("Content-Length", str(len(data)))
        handler.end_headers()
        handler.wfile.write(data)

    url, _ = servers(busy)
    with pytest.raises(TransportError) as retry:
        SentraClient(url, timeout=2).heartbeat(uuid4(), TOKEN)
    assert retry.value.retry_after == 7


# --- H04: URL y TLS ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "ok"),
    [
        ("https://sentra.lan", True),
        ("https://10.0.0.5:8443/sentra", True),
        ("http://127.0.0.1:8000", True),
        ("http://127.5.0.1:8000", True),
        ("http://localhost:8000", True),
        ("http://[::1]:8000", True),
        ("http://192.168.50.201:8000", False),
        ("http://sentra.lan", False),
        ("http://127.evil.example", False),
        ("http://localhost.evil.example", False),
        ("https://user:pass@sentra.lan", False),
        ("https://sentra.lan/?x=1", False),
        ("ftp://sentra.lan", False),
    ],
)
def test_h04_only_https_or_loopback_http(url: str, ok: bool) -> None:
    assert (insecure_url_reason(url) is None) is ok
    if ok:
        AgentConfig(api_url=url).validate()
        SentraClient(url, timeout=1)
    else:
        with pytest.raises(ValueError):
            AgentConfig(api_url=url).validate()
        with pytest.raises(ValueError):
            SentraClient(url, timeout=1)


def test_h04_legacy_http_config_gets_a_migration_diagnostic(tmp_path: Path) -> None:
    from sentra_agent.config import load_config

    config = tmp_path / "agent.toml"
    config.write_text('api_url = "http://192.168.50.201:8000"\n')
    with pytest.raises(ValueError) as raised:
        load_config(config)
    message = str(raised.value)
    assert "192.168.50.201" in message and "https://" in message
    assert "agent-https-migration.md" in message


@pytest.fixture(scope="module")
def tls_material(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """CA de pruebas y certificado de servidor para 127.0.0.1 (y otro para un nombre ajeno)."""
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("openssl not available")
    base = tmp_path_factory.mktemp("tls")

    def run(*args: str) -> None:
        subprocess.run([openssl, *args], check=True, capture_output=True)  # noqa: S603

    run(
        "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
        "-subj", "/CN=Sentra Test CA",
        "-keyout", str(base / "ca.key"), "-out", str(base / "ca.pem"),
        "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign",
    )  # fmt: skip
    for name, san in (("good", "IP:127.0.0.1"), ("wrong", "DNS:other.example")):
        run(
            "req", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={name}",
            "-keyout", str(base / f"{name}.key"), "-out", str(base / f"{name}.csr"),
        )  # fmt: skip
        ext = base / f"{name}.ext"
        ext.write_text(f"subjectAltName={san}\nextendedKeyUsage=serverAuth\n")
        run(
            "x509", "-req", "-in", str(base / f"{name}.csr"), "-CA", str(base / "ca.pem"),
            "-CAkey", str(base / "ca.key"), "-CAcreateserial", "-days", "2",
            "-out", str(base / f"{name}.pem"), "-extfile", str(ext),
        )  # fmt: skip

    def context(name: str) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(base / f"{name}.pem"), str(base / f"{name}.key"))
        return ctx

    return {"ca": base / "ca.pem", "server": context("good"), "wrong": context("wrong")}


def test_h04_https_with_a_trusted_private_ca_works(
    servers: Callable[..., tuple[str, Recorder]], tls_material: dict[str, Any]
) -> None:
    url, recorder = servers(lambda h: _json(h, 200, {"asset_id": "a"}), tls_material["server"])
    response = SentraClient(url, timeout=2, ca_bundle=tls_material["ca"]).heartbeat(uuid4(), TOKEN)
    assert response == {"asset_id": "a"}
    assert recorder.requests[0][1]["Authorization"] == f"Bearer {TOKEN}"


def test_h04_untrusted_or_mismatched_certificates_are_rejected(
    servers: Callable[..., tuple[str, Recorder]], tls_material: dict[str, Any]
) -> None:
    url, recorder = servers(lambda h: _json(h, 200, {}), tls_material["server"])
    # Sin la CA privada: la verificación normal falla (nunca se desactiva).
    with pytest.raises(TlsError):
        SentraClient(url, timeout=2).heartbeat(uuid4(), TOKEN)
    wrong_url, wrong = servers(lambda h: _json(h, 200, {}), tls_material["wrong"])
    # Certificado válido de la CA pero para otro nombre: también se rechaza.
    with pytest.raises(TlsError):
        SentraClient(wrong_url, timeout=2, ca_bundle=tls_material["ca"]).heartbeat(uuid4(), TOKEN)
    assert recorder.requests == [] and wrong.requests == []  # el token nunca se envió
