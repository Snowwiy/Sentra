"""Fase 4M: el agente siempre verifica el certificado del servidor.

Un servidor HTTPS con un certificado autofirmado (como uno de una CA interna no instalada)
debe rechazarse: el token del agente nunca se envía a un servidor no verificado. Para
confiar en una CA interna se instala en el almacén del sistema (docs/network-security.md);
no existe ninguna opción para desactivar la verificación.
"""

import http.server
import shutil
import ssl
import subprocess
import threading
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import ClassVar

import pytest

from sentra_agent import client as client_module
from sentra_agent.client import SentraClient, TransportError


class _Handler(http.server.BaseHTTPRequestHandler):
    received: ClassVar[list[str]] = []

    def do_POST(self) -> None:
        # Si la verificación fallara en abierto, aquí llegaría el token.
        _Handler.received.append(self.headers.get("Authorization", ""))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *args: object) -> None:
        return


@pytest.fixture
def untrusted_https(tmp_path: Path) -> Iterator[str]:
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("openssl no disponible para crear el certificado de prueba")
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(  # noqa: S603  (binario local, argumentos fijos)
        [
            openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
            "-keyout", str(key), "-out", str(cert),
        ],
        check=True,
        capture_output=True,
    )  # fmt: skip
    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _Handler.received = []
    try:
        yield f"https://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def test_untrusted_certificate_is_rejected_and_the_token_never_sent(untrusted_https: str) -> None:
    api = SentraClient(untrusted_https, timeout=5)
    with pytest.raises(TransportError, match=r"CERTIFICATE_VERIFY_FAILED|certificate verify"):
        api.heartbeat(uuid.uuid4(), "sentra_at_secret-token")
    assert _Handler.received == []


def test_the_client_never_builds_an_unverified_tls_context() -> None:
    source = Path(client_module.__file__).read_text(encoding="utf-8")
    for insecure in (
        "_create_unverified_context",
        "CERT_NONE",
        "check_hostname = False",
        "verify=False",
    ):
        assert insecure not in source
