"""CLI: enroll (sin imprimir secretos), status, diagnostics; HTTP real solo en 127.0.0.1."""

import io
import json
import logging
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from sentra_sensor.cli import main
from sentra_sensor.client import (
    ApiError,
    SensorClient,
    TlsError,
    UrllibTransport,
    build_ssl_context,
    parse_retry_after,
)
from sentra_sensor.config import LocalConfig
from sentra_sensor.credentials import CredentialStore
from tests.conftest import CREDENTIAL, ENROLL_TOKEN, SITE_ID, FakeServer
from tests.privacy import assert_private


def run_cli(args: list[str], server: FakeServer, stdin: str = "") -> tuple[int, str]:
    out = io.StringIO()
    code = main(args, transport_factory=lambda _c: server, out=out, stdin=io.StringIO(stdin))
    return code, out.getvalue()


def test_enroll_stores_0600_and_never_prints_secrets(
    data_dir: Path,
    server: FakeServer,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.DEBUG):
        code, out = run_cli(
            [
                "--data-dir",
                str(data_dir),
                "enroll",
                "--server",
                "http://127.0.0.1:8000",
                "--token",
                ENROLL_TOKEN,
            ],
            server,
        )
    assert code == 0
    captured = capsys.readouterr()
    everything = out + captured.out + captured.err + caplog.text
    assert ENROLL_TOKEN not in everything and CREDENTIAL not in everything
    assert SITE_ID in out
    cred = data_dir / "credential.json"
    assert_private(cred)  # 0600 en POSIX; DACL privada en Windows (st_mode no la refleja)
    assert ENROLL_TOKEN not in cred.read_text()  # el token de enrollment no se guarda
    _path, headers, body = server.requests[0]
    assert headers["X-Sensor-Enrollment-Token"] == ENROLL_TOKEN
    assert "Authorization" not in headers
    assert set(body) == {"hostname", "platform", "sensor_version", "capabilities"}


def test_enroll_token_from_stdin_and_file(
    data_dir: Path, server: FakeServer, tmp_path: Path
) -> None:
    code, _ = run_cli(
        [
            "--data-dir",
            str(data_dir),
            "enroll",
            "--server",
            "http://127.0.0.1:8000",
            "--token-stdin",
        ],
        server,
        stdin=ENROLL_TOKEN + "\n",
    )
    assert code == 0
    token_file = tmp_path / "token.txt"
    token_file.write_text(ENROLL_TOKEN)
    # Ya enrolado: sin --force no se sobrescribe la credencial.
    code, _ = run_cli(
        [
            "--data-dir",
            str(data_dir),
            "enroll",
            "--server",
            "http://127.0.0.1:8000",
            "--token-file",
            str(token_file),
        ],
        server,
    )
    assert code == 2
    code, _ = run_cli(
        [
            "--data-dir",
            str(data_dir),
            "enroll",
            "--server",
            "http://127.0.0.1:8000",
            "--token-file",
            str(token_file),
            "--force",
        ],
        server,
    )
    assert code == 0


def test_enroll_rejections(
    data_dir: Path, server: FakeServer, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = "wrong-token-0000000000000000000000"
    code, _ = run_cli(
        [
            "--data-dir",
            str(data_dir),
            "enroll",
            "--server",
            "http://127.0.0.1:8000",
            "--token",
            bad,
        ],
        server,
    )
    err = capsys.readouterr().err
    assert code == 2 and "rejected" in err and bad not in err
    code, _ = run_cli(
        [
            "--data-dir",
            str(data_dir),
            "enroll",
            "--server",
            "http://10.0.0.9",
            "--token",
            ENROLL_TOKEN,
        ],
        server,
    )
    assert code == 2  # http fuera de loopback
    code, _ = run_cli(
        [
            "--data-dir",
            str(data_dir),
            "enroll",
            "--server",
            "http://127.0.0.1:8000",
            "--token",
            "abc\r\nX-Evil: 1",
        ],
        server,
    )
    assert code == 2
    assert not (data_dir / "credential.json").exists()


def test_status_and_diagnostics(data_dir: Path, server: FakeServer) -> None:
    code, out = run_cli(["--data-dir", str(data_dir), "status"], server)
    assert code == 0 and "Enrolled:       no" in out
    run_cli(
        [
            "--data-dir",
            str(data_dir),
            "enroll",
            "--server",
            "http://127.0.0.1:8000",
            "--token",
            ENROLL_TOKEN,
        ],
        server,
    )
    code, out = run_cli(["--data-dir", str(data_dir), "status", "--json"], server)
    status = json.loads(out)
    assert status["enrolled"] and status["site_id"] == SITE_ID
    assert status["spool"]["items"] == 0
    assert CREDENTIAL not in out
    code, out = run_cli(["--data-dir", str(data_dir), "diagnostics"], server)
    assert code == 0, out
    assert "[OK] credential" in out and "[OK] site" in out and CREDENTIAL not in out
    server.down = True
    code, out = run_cli(["--data-dir", str(data_dir), "diagnostics"], server)
    assert code == 1 and "[FAIL] server_reachable" in out


# --- HTTP real sobre loopback (sin red externa) ---------------------------------------


class _Handler(BaseHTTPRequestHandler):
    fake: FakeServer

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        response = self.fake.request(
            "POST", "http://127.0.0.1" + self.path, dict(self.headers.items()), body, 5
        )
        self.send_response(response.status)
        for key, value in response.headers.items():
            self.send_header(key, value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response.body)))
        self.end_headers()
        self.wfile.write(response.body)

    def log_message(self, *args: Any) -> None:
        return


@pytest.fixture
def http_server(server: FakeServer) -> Iterator[str]:
    handler = type("Handler", (_Handler,), {"fake": server})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def test_enroll_and_run_over_real_loopback_http(
    data_dir: Path, server: FakeServer, http_server: str
) -> None:
    out = io.StringIO()
    code = main(
        ["--data-dir", str(data_dir), "enroll", "--server", http_server, "--token", ENROLL_TOKEN],
        out=out,
    )
    assert code == 0
    config = LocalConfig(server_url=http_server, data_dir=data_dir).validate()
    identity = CredentialStore(config.credential_file()).load()
    client = SensorClient(http_server, UrllibTransport(), credential=identity.credential)
    response = client.heartbeat({"sent_at": "2026-01-01T00:00:00+00:00"})
    assert response["status"] == "active"
    server.fail_next.append(("/sensor/jobs/poll", 429, "rate_limited"))
    with pytest.raises(ApiError) as info:
        client.poll()
    assert info.value.status == 429 and info.value.retryable and info.value.retry_after == 1
    server.revoked = True
    with pytest.raises(ApiError) as info:
        client.heartbeat({})
    assert (info.value.status, info.value.code) == (403, "sensor_revoked")


def test_tls_context_always_verifies(tmp_path: Path) -> None:
    import ssl

    context = build_ssl_context(None)
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
    bad = tmp_path / "ca.pem"
    bad.write_text("not a certificate")
    with pytest.raises(ssl.SSLError):
        build_ssl_context(bad)


def test_tls_failure_is_reported_as_tls_error(http_server: str) -> None:
    # Un servidor HTTP plano contestando a un cliente HTTPS: el handshake falla.
    url = http_server.replace("http://", "https://")
    with pytest.raises(TlsError):
        UrllibTransport().request("POST", url + "/api/v1/sensor/heartbeat", {}, b"{}", 5)


def test_retry_after_parsing() -> None:
    assert parse_retry_after("5") == 5
    assert parse_retry_after("999999") == 3600
    assert parse_retry_after("garbage") is None
    assert parse_retry_after(None) is None


def test_enroll_on_first_run_deletes_token_file(data_dir: Path, server: FakeServer) -> None:
    from sentra_sensor.cli import enroll_on_first_run

    config = LocalConfig(server_url="http://127.0.0.1:8000", data_dir=data_dir).validate()
    token_file = data_dir / "enroll.token"
    token_file.write_text(ENROLL_TOKEN)
    enroll_on_first_run(config, token_file, lambda _c: server)
    assert not token_file.exists()
    assert CredentialStore(config.credential_file()).load().site_id == SITE_ID
    # Ya enrolado: un token nuevo no se usa ni se consume.
    token_file.write_text(ENROLL_TOKEN)
    enroll_on_first_run(config, token_file, lambda _c: server)
    assert token_file.exists()
    assert [p for p in server.paths() if p == "/sensor/enroll"] == ["/sensor/enroll"]
