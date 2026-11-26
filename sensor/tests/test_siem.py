"""Receptores SIEM del sensor (Fase 7F.2): configuración, enmarcado Syslog, receptores reales en
loopback (UDP, TCP y TLS), gestor de lotes y su integración con el runner."""

import contextlib
import datetime as dt
import errno
import json
import socket
import ssl
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from sentra_sensor.config import ConfigError, LocalConfig, load_config
from sentra_sensor.runner import SensorRunner
from sentra_sensor.siem import SIEM_CAPABILITY
from sentra_sensor.siem import config as siem_config
from sentra_sensor.siem.config import (
    SiemConfigError,
    SiemLocalConfig,
    SiemServerConfig,
    SyslogInput,
    parse_local_siem,
)
from sentra_sensor.siem.manager import SiemManager
from sentra_sensor.siem.syslog import (
    InputCounters,
    RateLimiter,
    SyslogFramer,
    SyslogReceiver,
    decode_message,
)
from tests.conftest import FakeClock, FakeServer, enroll_identity, server_config, track_resource

SOURCE_A = "5f000000-0000-4000-8000-0000000000a1"
SOURCE_B = "5f000000-0000-4000-8000-0000000000b2"


def only_syslog(config: SiemLocalConfig, index: int = 0) -> SyslogInput:
    spec = config.inputs[index]
    assert isinstance(spec, SyslogInput)
    return spec


def syslog_input(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "name": "fw",
        "type": "syslog",
        "protocol": "tcp",
        "bind": "127.0.0.1",
        "port": 6514,
        "allowed_peers": ["127.0.0.0/8"],
    }
    base.update(overrides)
    return base


def server_siem(*sources: tuple[str, str], revision: int = 1, **extra: Any) -> dict[str, Any]:
    return {
        "enabled": True,
        "revision": revision,
        "sources": [
            {"source_id": sid, "input": alias, "source_type": "syslog", "revision": 1}
            for sid, alias in sources
        ],
        **extra,
    }


# --- configuración local -----------------------------------------------------------------


def test_siem_disabled_by_default() -> None:
    config = parse_local_siem(None)
    assert config.enabled is False and config.inputs == ()


def test_udp_requires_explicit_opt_in() -> None:
    with pytest.raises(SiemConfigError, match="allow_udp"):
        parse_local_siem({"enabled": True, "inputs": [syslog_input(protocol="udp")]})
    config = parse_local_siem(
        {"enabled": True, "inputs": [syslog_input(protocol="udp", allow_udp=True)]}
    )
    assert only_syslog(config).protocol == "udp"


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"allowed_peers": ["0.0.0.0/0"]}, "/0"),
        ({"allowed_peers": []}, "allowed_peers"),
        ({"allowed_peers": ["203.0.113.0/24"]}, "need protocol = tls"),
        ({"protocol": "tls"}, "tls_cert"),
        ({"protocol": "tls", "tls_cert": "cert.pem", "tls_key": "/k.pem"}, "absolute"),
        ({"tls_cert": "/c.pem"}, "only apply"),
        ({"port": 0}, "port"),
        ({"bind": "eth0"}, "bind"),
        ({"max_message_bytes": 100}, "max_message_bytes"),
        ({"command": "rm -rf /"}, "unknown keys"),
        ({"name": "FW Syslog"}, "name"),
        ({"type": "exec"}, "type"),
    ],
)
def test_invalid_inputs_are_rejected(overrides: dict[str, Any], message: str) -> None:
    with pytest.raises(SiemConfigError, match=message):
        parse_local_siem({"enabled": True, "inputs": [syslog_input(**overrides)]})


def local_abs(*parts: str) -> str:
    """Ruta absoluta local de la plataforma que ejecuta el test (/etc/... o C:\\etc\\...)."""
    return str(Path(Path.cwd().anchor, *parts))


def test_public_peers_are_allowed_with_tls() -> None:
    config = parse_local_siem(
        {
            "enabled": True,
            "inputs": [
                syslog_input(
                    protocol="tls",
                    allowed_peers=["203.0.113.0/24"],
                    tls_cert=local_abs("etc", "sentra", "syslog.crt"),
                    tls_key=local_abs("etc", "sentra", "syslog.key"),
                )
            ],
        }
    )
    assert only_syslog(config).peer_allowed("203.0.113.7")
    assert not only_syslog(config).peer_allowed("198.51.100.1")


def test_duplicate_listener_and_alias_rejected() -> None:
    with pytest.raises(SiemConfigError, match="duplicated"):
        parse_local_siem({"inputs": [syslog_input(), syslog_input(port=7000)]})
    with pytest.raises(SiemConfigError, match="reuses"):
        parse_local_siem({"inputs": [syslog_input(), syslog_input(name="other")]})
    # UDP y TCP en el mismo número de puerto son receptores distintos.
    config = parse_local_siem(
        {"inputs": [syslog_input(), syslog_input(name="u", protocol="udp", allow_udp=True)]}
    )
    assert len(config.inputs) == 2


def test_enabled_without_inputs_rejected() -> None:
    with pytest.raises(SiemConfigError, match="at least one"):
        parse_local_siem({"enabled": True})


def test_peer_allowed_handles_mapped_ipv6_and_garbage() -> None:
    spec = only_syslog(parse_local_siem({"inputs": [syslog_input(allowed_peers=["10.0.0.0/8"])]}))
    assert spec.peer_allowed("::ffff:10.1.2.3")
    assert not spec.peer_allowed("not-an-ip")
    assert not spec.peer_allowed("11.0.0.1")


def test_toml_siem_section(tmp_path: Path) -> None:
    toml = tmp_path / "sensor.toml"
    toml.write_text(
        '[sensor]\nserver_url = "https://sentra.example"\n'
        f'data_dir = "{(tmp_path / "data").as_posix()}"\n\n'
        "[siem]\nenabled = true\n\n[[siem.inputs]]\n"
        'name = "fw"\ntype = "syslog"\nprotocol = "tcp"\nport = 6601\n'
        'allowed_peers = ["192.168.0.0/16"]\n'
    )
    config = load_config(toml)
    assert config.siem.enabled and only_syslog(config.siem).port == 6601
    bad = tmp_path / "bad.toml"
    bad.write_text("[siem]\nenabled = true\n")
    with pytest.raises(ConfigError):
        load_config(bad)


# --- configuración del servidor ------------------------------------------------------------


def test_server_config_parse_is_defensive() -> None:
    parsed = SiemServerConfig.parse(
        {
            "enabled": True,
            "revision": 3,
            "sources": [
                {"source_id": SOURCE_A, "input": "fw", "source_type": "syslog", "revision": 1},
                {"source_id": "../../etc", "input": "x", "source_type": "syslog", "revision": 1},
                {"source_id": SOURCE_B, "input": "FW!", "source_type": "syslog", "revision": 1},
                {"source_id": SOURCE_B, "input": "fw", "source_type": "syslog", "revision": 1},
            ],
            "max_records_per_batch": 10**9,
            "flush_interval_seconds": 0,
        }
    )
    assert parsed is not None
    assert [s.source_id for s in parsed.sources] == [SOURCE_A]
    assert parsed.max_records_per_batch == 5000 and parsed.flush_interval_seconds == 1
    assert SiemServerConfig.parse(None) is None
    assert SiemServerConfig.parse({"revision": "1", "sources": []}) is None
    empty = SiemServerConfig.parse({"enabled": True, "revision": 0, "sources": []})
    assert empty is not None and empty.enabled is False


# --- enmarcado -------------------------------------------------------------------------------


# --- 7F-Windows-Fix1: rutas TLS y de logs según la plataforma ------------------------------
#
# `_windows()` se sustituye para comprobar las reglas de las dos plataformas en cualquier
# sistema. La confirmación en un Windows físico queda pendiente (docs/fase-7f-windows-qa.md).

WINDOWS_OK = [
    "C:/ProgramData/SentraSensor/syslog.crt",
    "C:\\ProgramData\\SentraSensor\\syslog.crt",
    "d:/certs/syslog.crt",
]
WINDOWS_BAD = [
    ("/etc/sentra/syslog.crt", "drive letter"),
    ("\\etc\\sentra\\syslog.crt", "drive letter"),
    ("C:syslog.crt", "drive letter"),
    ("syslog.crt", "drive letter"),
    ("\\\\fileserver\\certs\\syslog.crt", "UNC"),
    ("//fileserver/certs/syslog.crt", "UNC"),
    ("\\\\?\\C:\\certs\\syslog.crt", "UNC"),
    ("\\\\.\\C:\\certs\\syslog.crt", "UNC"),
    ("C:/ProgramData/../Windows/syslog.crt", "'..'"),
]
POSIX_OK = ["/etc/sentra/syslog.crt", "/opt/sentra sensor/syslog.crt"]
POSIX_BAD = [
    ("C:/ProgramData/SentraSensor/syslog.crt", "absolute"),
    ("etc/sentra/syslog.crt", "absolute"),
    ("./syslog.crt", "absolute"),
    ("/etc/sentra/../shadow", "'..'"),
]


def _tls(cert: str, key: str | None = None) -> dict[str, Any]:
    return syslog_input(protocol="tls", tls_cert=cert, tls_key=key or cert + ".key")


@pytest.mark.parametrize("path", WINDOWS_OK)
def test_windows_tls_paths_need_a_local_drive(monkeypatch: pytest.MonkeyPatch, path: str) -> None:
    monkeypatch.setattr(siem_config, "_windows", lambda: True)
    spec = only_syslog(parse_local_siem({"inputs": [_tls(path)]}))
    assert spec.tls_cert == Path(path) and spec.tls_key == Path(path + ".key")


@pytest.mark.parametrize(("path", "message"), WINDOWS_BAD)
def test_windows_rejects_linux_relative_unc_and_traversal_paths(
    monkeypatch: pytest.MonkeyPatch, path: str, message: str
) -> None:
    monkeypatch.setattr(siem_config, "_windows", lambda: True)
    with pytest.raises(SiemConfigError, match=message):
        parse_local_siem({"inputs": [_tls(path)]})
    # La clave se valida igual que el certificado.
    with pytest.raises(SiemConfigError, match=message):
        parse_local_siem({"inputs": [_tls("C:/certs/syslog.crt", path)]})


@pytest.mark.parametrize("path", POSIX_OK)
def test_posix_tls_paths_stay_valid(monkeypatch: pytest.MonkeyPatch, path: str) -> None:
    monkeypatch.setattr(siem_config, "_windows", lambda: False)
    assert only_syslog(parse_local_siem({"inputs": [_tls(path)]})).tls_cert == Path(path)


@pytest.mark.parametrize(("path", "message"), POSIX_BAD)
def test_posix_rejects_windows_relative_and_traversal_paths(
    monkeypatch: pytest.MonkeyPatch, path: str, message: str
) -> None:
    monkeypatch.setattr(siem_config, "_windows", lambda: False)
    with pytest.raises(SiemConfigError, match=message):
        parse_local_siem({"inputs": [_tls(path)]})


@pytest.mark.parametrize("windows", [True, False])
def test_tls_paths_reject_malformed_values(monkeypatch: pytest.MonkeyPatch, windows: bool) -> None:
    monkeypatch.setattr(siem_config, "_windows", lambda: windows)
    for value in ("", "C:/a\x00b.crt", 42, None):
        item = syslog_input(protocol="tls", tls_cert=value, tls_key="C:/k.pem")
        with pytest.raises(SiemConfigError, match="tls_cert"):
            parse_local_siem({"inputs": [item]})
    # TLS sigue exigiendo las dos rutas.
    with pytest.raises(SiemConfigError, match="tls_key"):
        parse_local_siem({"inputs": [syslog_input(protocol="tls", tls_cert="C:/c.pem")]})


@pytest.mark.parametrize(
    ("windows", "good", "bad"),
    [
        (True, "C:/Program Files/Suricata/log", "/var/log/suricata"),
        (True, "C:/Program Files/Suricata/log", "\\\\nas\\logs"),
        (False, "/var/log/suricata", "C:/Program Files/Suricata/log"),
    ],
)
def test_file_allowed_dir_follows_platform_rules(
    monkeypatch: pytest.MonkeyPatch, windows: bool, good: str, bad: str
) -> None:
    monkeypatch.setattr(siem_config, "_windows", lambda: windows)
    item = {"name": "ids", "type": "file", "format": "suricata_eve", "paths": ["eve.json"]}
    parsed = parse_local_siem({"inputs": [{**item, "allowed_dir": good}]}).inputs[0]
    assert parsed.type == "file"
    with pytest.raises(SiemConfigError, match="allowed_dir"):
        parse_local_siem({"inputs": [{**item, "allowed_dir": bad}]})


def test_framer_octet_counting_and_lf_mixed_and_split() -> None:
    framer = SyslogFramer(1024)
    first = b"<34>1 2026-11-24T08:00:00Z h app - - - uno"
    stream = f"{len(first)} ".encode() + first + b"<13>dos\n<13>tres\r\n"
    # Se trocea byte a byte: el resultado tiene que ser el mismo que de una vez.
    out: list[bytes] = []
    for index in range(len(stream)):
        out.extend(framer.feed(stream[index : index + 1]))
    assert out == [first, b"<13>dos", b"<13>tres\r"]
    assert decode_message(out[2]) == "<13>tres"


def test_framer_drops_oversize_without_breaking_stream() -> None:
    framer = SyslogFramer(500)
    big = b"x" * 600
    stream = b"600 " + big + b"5 <13>a" + b"y" * 700 + b"\n<13>ok\n"
    out = framer.feed(stream)
    assert out == [b"<13>a", b"<13>ok"]
    assert framer.oversize == 2


def test_framer_long_line_without_newline_is_bounded() -> None:
    framer = SyslogFramer(500)
    assert framer.feed(b"<13>" + b"z" * 2000) == []
    assert framer.oversize == 1
    assert framer.feed(b"z" * 5000 + b"\n<13>next\n") == [b"<13>next"]


def test_decode_replaces_nul_and_invalid_utf8() -> None:
    text = decode_message(b"<13>a\x00b\xff\n")
    assert "\x00" not in text and text.startswith("<13>a") and "�" in text


def test_rate_limiter_wait_and_take() -> None:
    clock = FakeClock(0)
    limiter = RateLimiter(2, clock=clock)
    assert limiter.take() and limiter.take() and not limiter.take()
    clock.advance(0.5)
    assert limiter.take()


# --- receptores reales en loopback -----------------------------------------------------------


class Collector:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []
        self.event = threading.Event()

    def __call__(self, name: str, record: dict[str, Any]) -> None:
        self.records.append(record)
        self.event.set()

    def wait_for(self, count: int, timeout: float = 5.0) -> None:
        deadline = time.monotonic() + timeout
        while len(self.records) < count and time.monotonic() < deadline:
            time.sleep(0.01)
        assert len(self.records) >= count, self.records


def _spec(**overrides: Any) -> SyslogInput:
    data = syslog_input(port=1, **overrides)
    spec = only_syslog(parse_local_siem({"inputs": [data]}))
    # Puerto 0: el sistema asigna uno libre (los tests no dependen de puertos fijos).
    return SyslogInput(**{**spec.__dict__, "port": 0})


def _receiver(spec: SyslogInput, sink: Collector) -> SyslogReceiver:
    receiver = SyslogReceiver(spec, sink)
    receiver.start()
    assert receiver.state == "running", receiver.error_code
    return receiver


def test_tcp_receiver_end_to_end() -> None:
    sink = Collector()
    receiver = _receiver(_spec(), sink)
    try:
        with socket.create_connection(("127.0.0.1", receiver.bound_port or 0), timeout=5) as conn:
            message = b"<38>1 2026-11-24T08:00:00Z host sshd 77 - - Failed password"
            conn.sendall(f"{len(message)} ".encode() + message + b"<13>Nov 24 08:00:00 h a: b\n")
            sink.wait_for(2)
        first = sink.records[0]
        assert first["raw"].endswith("Failed password") and first["transport"] == "tcp"
        assert (
            first["peer_ip"] == "127.0.0.1" and first["record_id"] != sink.records[1]["record_id"]
        )
        assert receiver.counters.snapshot()["received"] == 2
    finally:
        receiver.stop()
    assert receiver.state == "stopped"


def test_tcp_receiver_rejects_peer_outside_allowlist() -> None:
    sink = Collector()
    receiver = _receiver(_spec(allowed_peers=["10.0.0.0/8"]), sink)
    try:
        with socket.create_connection(("127.0.0.1", receiver.bound_port or 0), timeout=5) as conn:
            conn.sendall(b"<13>no deberia llegar\n")
            conn.settimeout(2)
            # El receptor cierra sin leer: recv devuelve b"" (o la conexión se resetea).
            with contextlib.suppress(ConnectionResetError):
                assert conn.recv(10) == b""
        time.sleep(0.1)
        assert sink.records == []
        snapshot = receiver.counters.snapshot()
        assert snapshot["connections_rejected"] == 1 and snapshot["dropped_peer"] == 1
    finally:
        receiver.stop()


def test_tcp_receiver_limits_connections() -> None:
    sink = Collector()
    receiver = _receiver(_spec(max_connections=1), sink)
    port = receiver.bound_port or 0
    try:
        first = socket.create_connection(("127.0.0.1", port), timeout=5)
        first.sendall(b"<13>uno\n")
        sink.wait_for(1)
        second = socket.create_connection(("127.0.0.1", port), timeout=5)
        second.settimeout(2)
        with contextlib.suppress(ConnectionResetError):
            assert second.recv(10) == b""
        assert receiver.counters.snapshot()["connections_rejected"] == 1
        first.close()
        second.close()
    finally:
        receiver.stop()


def test_udp_receiver_end_to_end_and_oversize() -> None:
    sink = Collector()
    receiver = _receiver(_spec(protocol="udp", allow_udp=True, max_message_bytes=480), sink)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(b"<13>datagrama", ("127.0.0.1", receiver.bound_port or 0))
            sock.sendto(b"<13>" + b"x" * 600, ("127.0.0.1", receiver.bound_port or 0))
            sock.sendto(b"<13>otro", ("127.0.0.1", receiver.bound_port or 0))
            sink.wait_for(2)
        assert [r["raw"] for r in sink.records] == ["<13>datagrama", "<13>otro"]
        assert sink.records[0]["transport"] == "udp"
        deadline = time.monotonic() + 2
        while receiver.counters.snapshot()["dropped_oversize"] < 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert receiver.counters.snapshot()["dropped_oversize"] == 1
    finally:
        receiver.stop()


def _datagram(size: int, tag: str = "x") -> bytes:
    """Mensaje Syslog de exactamente `size` bytes."""
    head = f"<13>{tag}:".encode()
    return head + b"y" * (size - len(head))


def test_udp_oversize_boundaries_and_recovery() -> None:
    """Límites exactos con sockets reales: < max, = max, max + 1, muy grande, varios
    rechazados seguidos y mensajes válidos después."""
    limit = 480
    sink = Collector()
    receiver = _receiver(_spec(protocol="udp", allow_udp=True, max_message_bytes=limit), sink)
    sizes = [limit - 1, limit, limit + 1, 16_000, limit + 1, limit + 2, 100, limit]
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            for index, size in enumerate(sizes):
                sock.sendto(_datagram(size, f"m{index}"), ("127.0.0.1", receiver.bound_port or 0))
            sink.wait_for(4)
        # Un solo hilo procesa en orden: al llegar el último válido, los anteriores ya están.
        accepted = [r["raw"] for r in sink.records]
        assert [len(raw.encode()) for raw in accepted] == [limit - 1, limit, 100, limit]
        assert [raw.split(":", 1)[0] for raw in accepted] == [
            "<13>m0",
            "<13>m1",
            "<13>m6",
            "<13>m7",
        ]
        counters = receiver.counters.snapshot()
        assert counters["dropped_oversize"] == 4 and counters["received"] == 4
        assert receiver.counters.receive_errors == 0
    finally:
        receiver.stop()


class _ScriptedSocket:
    """Socket UDP de prueba: devuelve o lanza lo indicado y después para el receptor."""

    def __init__(self, receiver: SyslogReceiver, script: list[Any]) -> None:
        self.receiver = receiver
        self.script = list(script)
        self.sizes: list[int] = []

    def recvfrom(self, size: int) -> tuple[bytes, tuple[str, int]]:
        self.sizes.append(size)
        if not self.script:
            self.receiver._stop.set()
            raise TimeoutError
        step = self.script.pop(0)
        if isinstance(step, BaseException):
            raise step
        assert isinstance(step, bytes)
        return step, ("127.0.0.1", 5140)


def _windows_error(code: int) -> OSError:
    """OSError como lo construye Python en Windows para un error de Winsock."""
    exc = OSError(code, "winsock error")
    setattr(exc, "winerror", code)  # noqa: B010 (en Linux OSError no declara winerror)
    return exc


def test_udp_windows_msgsize_counts_as_oversize_and_network_errors_apart() -> None:
    """Semántica de Windows simulada: WSAEMSGSIZE (10040) es un datagrama sobredimensionado
    ya descartado por el sistema; WSAECONNRESET (10054) es un error de red y se cuenta aparte.
    Ninguno corta el bucle ni se reenvía nada parcial."""
    sink = Collector()
    receiver = SyslogReceiver(_spec(protocol="udp", allow_udp=True, max_message_bytes=480), sink)
    script: list[Any] = [
        b"<13>antes",
        _windows_error(10040),
        OSError(errno.EMSGSIZE, "Message too long"),
        _windows_error(10054),
        _datagram(481),
        b"<13>despues",
    ]
    fake = _ScriptedSocket(receiver, script)
    receiver._socket = fake  # type: ignore[assignment]
    receiver._serve_udp()
    assert [r["raw"] for r in sink.records] == ["<13>antes", "<13>despues"]
    counters = receiver.counters.snapshot()
    assert counters["dropped_oversize"] == 3 and counters["received"] == 2
    assert receiver.counters.receive_errors == 1
    # El búfer de lectura es mayor que cualquier datagrama UDP: nunca se trunca al leer.
    assert min(fake.sizes) > 65_535
    # El contrato de estadísticas del servidor no cambia (receive_errors es solo local).
    assert "receive_errors" not in counters


def test_bind_failure_is_reported_not_raised() -> None:
    sink = Collector()
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)
    try:
        spec = SyslogInput(**{**_spec().__dict__, "port": blocker.getsockname()[1]})
        receiver = SyslogReceiver(spec, sink)
        receiver.start()
        assert receiver.state == "error" and receiver.error_code == "bind_failed"
        receiver.stop()
    finally:
        blocker.close()


def _self_signed(tmp_path: Path) -> tuple[Path, Path]:
    pytest.importorskip("cryptography")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "syslog.crt", tmp_path / "syslog.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def test_tls_receiver_end_to_end(tmp_path: Path) -> None:
    cert, key = _self_signed(tmp_path)
    sink = Collector()
    receiver = _receiver(_spec(protocol="tls", tls_cert=str(cert), tls_key=str(key)), sink)
    try:
        context = ssl.create_default_context(cafile=str(cert))
        with (
            socket.create_connection(("127.0.0.1", receiver.bound_port or 0), timeout=5) as raw,
            context.wrap_socket(raw, server_hostname="localhost") as conn,
        ):
            message = b"<86>1 2026-11-24T08:00:00Z h sudo - - - cifrado"
            conn.sendall(f"{len(message)} ".encode() + message)
            sink.wait_for(1)
        assert sink.records[0]["transport"] == "tls"
        assert sink.records[0]["raw"].endswith("cifrado")
    finally:
        receiver.stop()


def test_tls_receiver_rejects_plaintext_client(tmp_path: Path) -> None:
    cert, key = _self_signed(tmp_path)
    sink = Collector()
    receiver = _receiver(_spec(protocol="tls", tls_cert=str(cert), tls_key=str(key)), sink)
    try:
        with socket.create_connection(("127.0.0.1", receiver.bound_port or 0), timeout=5) as conn:
            conn.sendall(b"<13>en claro\n")
            conn.settimeout(3)
            with contextlib.suppress(ConnectionResetError, TimeoutError):
                conn.recv(100)
        time.sleep(0.2)
        assert sink.records == []
    finally:
        receiver.stop()


def test_tls_invalid_certificate_reports_error(tmp_path: Path) -> None:
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    cert.write_text("not a cert")
    key.write_text("not a key")
    receiver = SyslogReceiver(
        _spec(protocol="tls", tls_cert=str(cert), tls_key=str(key)), Collector()
    )
    receiver.start()
    assert receiver.state == "error" and receiver.error_code == "tls_config_invalid"


# --- gestor ----------------------------------------------------------------------------------


class FakeReceiver:
    def __init__(self, spec: Any, sink: Any) -> None:
        self.spec = spec
        self.sink = sink
        self.counters = InputCounters()
        self.state = "starting"
        self.error_code: str | None = None
        self.stopped = False

    def start(self) -> None:
        self.state = "running"

    def stop(self, timeout: float = 5.0) -> None:
        self.stopped = True
        self.state = "stopped"


def _local(*names: str) -> SiemLocalConfig:
    return parse_local_siem(
        {
            "enabled": True,
            "inputs": [syslog_input(name=n, port=6000 + i) for i, n in enumerate(names)],
        }
    )


def _record(text: str = "<13>hola", index: int = 0) -> dict[str, Any]:
    return {
        "raw": text,
        "record_id": f"r:{index}",
        "collected_at": "2026-11-24T08:00:00+00:00",
        "transport": "tcp",
        "peer_ip": "127.0.0.1",
        "peer_port": 5000,
    }


Batches = list[tuple[str, dict[str, Any]]]


def _manager(local: SiemLocalConfig, clock: FakeClock | None = None) -> tuple[SiemManager, Batches]:
    batches: Batches = []
    manager = SiemManager(
        local,
        lambda name, batch: batches.append((name, batch)),
        receiver_factory=FakeReceiver,
        clock=clock or FakeClock(),
    )
    return manager, batches


def test_manager_only_listens_on_declared_and_approved_inputs() -> None:
    manager, _ = _manager(_local("fw", "core"))
    manager.apply(SiemServerConfig.parse(server_siem((SOURCE_A, "fw"), (SOURCE_B, "ghost"))))
    assert sorted(manager.receivers) == ["fw"]
    health = manager.health()
    assert health["state"] == "degraded"
    ghost = next(i for i in health["inputs"] if i["name"] == "ghost")
    assert ghost["state"] == "not_declared"
    # El estado nunca lleva puertos ni pares.
    assert "6000" not in json.dumps(health) and "127.0.0" not in json.dumps(health)


def test_manager_batches_by_count_and_interval() -> None:
    clock = FakeClock()
    manager, batches = _manager(_local("fw"), clock)
    manager.apply(SiemServerConfig.parse(server_siem((SOURCE_A, "fw"), max_records_per_batch=10)))
    for index in range(25):
        manager.submit("fw", _record(index=index))
    assert [len(b["records"]) for _n, b in batches] == [10, 10]
    assert manager.flush_due() == 0
    clock.advance(6)
    assert manager.flush_due() == 1
    assert [len(b["records"]) for _n, b in batches] == [10, 10, 5]
    batch = batches[0][1]
    assert batch["source_id"] == SOURCE_A and batch["input"] == "fw"
    assert batch["config_revision"] == 1 and len({b["batch_id"] for _n, b in batches}) == 3


def test_manager_respects_byte_limits() -> None:
    manager, batches = _manager(_local("fw"))
    manager.apply(
        SiemServerConfig.parse(
            server_siem((SOURCE_A, "fw"), max_record_bytes=1024, max_batch_bytes=64 * 1024)
        )
    )
    manager.submit("fw", _record("<13>" + "x" * 2000))
    assert manager.dropped_oversize == 1
    for index in range(100):
        manager.submit("fw", _record("<13>" + "y" * 900, index))
    assert batches and all(len(json.dumps(b).encode()) <= 64 * 1024 for _n, b in batches)


def test_manager_drops_unapproved_and_flushes_on_revoke() -> None:
    manager, batches = _manager(_local("fw"))
    manager.submit("fw", _record())
    assert manager.dropped_unapproved == 1
    manager.apply(SiemServerConfig.parse(server_siem((SOURCE_A, "fw"))))
    manager.submit("fw", _record())
    receiver = manager.receivers["fw"]
    manager.apply(SiemServerConfig.parse({"enabled": False, "revision": 2, "sources": []}))
    assert isinstance(receiver, FakeReceiver) and receiver.stopped
    assert len(batches) == 1 and manager.receivers == {}
    assert manager.health()["state"] == "not_configured"


def test_manager_reassigned_input_flushes_with_previous_source() -> None:
    manager, batches = _manager(_local("fw"))
    manager.apply(SiemServerConfig.parse(server_siem((SOURCE_A, "fw"))))
    manager.submit("fw", _record())
    manager.apply(SiemServerConfig.parse(server_siem((SOURCE_B, "fw"), revision=2)))
    manager.submit("fw", _record(index=1))
    manager.stop()
    assert [b["source_id"] for _n, b in batches] == [SOURCE_A, SOURCE_B]


def test_manager_reports_stat_deltas() -> None:
    manager, batches = _manager(_local("fw"))
    manager.apply(SiemServerConfig.parse(server_siem((SOURCE_A, "fw"))))
    receiver = manager.receivers["fw"]
    receiver.counters.add(received=3, dropped_rate=2)
    manager.submit("fw", _record())
    manager.stop()
    receiver.counters.add(received=1)
    assert batches[0][1]["stats"]["received"] == 3
    assert batches[0][1]["stats"]["dropped_rate"] == 2


def test_manager_rate_limited_input_is_degraded() -> None:
    manager, _ = _manager(_local("fw"))
    manager.apply(SiemServerConfig.parse(server_siem((SOURCE_A, "fw"))))
    manager.receivers["fw"].counters.add(dropped_rate=1)
    item = manager.health()["inputs"][0]
    assert item["state"] == "degraded" and item["degraded_reasons"] == ["rate_limited"]


# --- runner ----------------------------------------------------------------------------------


def _siem_config(data_dir: Path) -> LocalConfig:
    return LocalConfig(
        server_url="http://127.0.0.1:8000", data_dir=data_dir, siem=_local("fw")
    ).validate()


def _siem_runner(config: LocalConfig, server: FakeServer) -> SensorRunner:
    store = enroll_identity(config)
    runner = track_resource(SensorRunner(config, server, store=store, threaded_jobs=False))
    # Receptores falsos: los tests del runner no abren puertos.
    runner.siem = SiemManager(config.siem, runner._enqueue_siem, receiver_factory=FakeReceiver)
    return runner


def test_runner_declares_capability_and_reports_only_with_server_block(data_dir: Path) -> None:
    config = _siem_config(data_dir)
    server = FakeServer()
    runner = _siem_runner(config, server)
    runner.tick()
    first = server.requests[0][2]
    assert SIEM_CAPABILITY in first["capabilities"] and "siem" not in first
    server.config = server_config(siem=server_siem((SOURCE_A, "fw")))
    for _ in range(2):
        runner.next_heartbeat_at = 0
        runner.tick()
    last = [b for p, _h, b in server.requests if p == "/sensor/heartbeat"][-1]
    assert last["siem"]["state"] == "running" and last["siem"]["config_revision"] == 1
    assert last["siem"]["inputs"][0]["name"] == "fw"


def test_runner_without_siem_creates_nothing(data_dir: Path) -> None:
    config = LocalConfig(server_url="http://127.0.0.1:8000", data_dir=data_dir).validate()
    runner = track_resource(
        SensorRunner(config, FakeServer(), store=enroll_identity(config), threaded_jobs=False)
    )
    runner.tick()
    assert runner.siem_spool is None and not config.siem_spool_file().exists()
    assert SIEM_CAPABILITY not in runner.heartbeat_body()["capabilities"]


def test_runner_forwards_batches_and_discards_unauthorized(data_dir: Path) -> None:
    config = _siem_config(data_dir)
    server = FakeServer()
    server.config = server_config(siem=server_siem((SOURCE_A, "fw")))
    runner = _siem_runner(config, server)
    runner.tick()
    runner.siem.submit("fw", _record())
    runner.siem.stop()
    runner.flush()
    assert len(server.siem_batches) == 1
    sent = next(iter(server.siem_batches.values()))
    assert sent["records"][0]["raw"] == "<13>hola" and sent["source_id"] == SOURCE_A
    runner.siem.apply(runner.server_config.siem if runner.server_config else None)
    runner.siem.submit("fw", _record(index=2))
    runner.siem.stop()
    server.fail_next.append(("/sensor/siem/batches", 403, "siem_not_authorized"))
    runner.flush()
    assert runner.siem_spool is not None and runner.siem_spool.stats().items == 0
    assert len(server.siem_batches) == 1


def test_runner_keeps_batches_while_server_is_down(data_dir: Path) -> None:
    config = _siem_config(data_dir)
    server = FakeServer()
    server.config = server_config(siem=server_siem((SOURCE_A, "fw")))
    runner = _siem_runner(config, server)
    runner.tick()
    runner.siem.submit("fw", _record())
    runner.siem.stop()
    server.fail_next.append(("/sensor/siem/batches", 503, "unavailable"))
    runner.flush()
    assert runner.siem_spool is not None and runner.siem_spool.stats().items == 1
    runner._flush_not_before = 0
    runner.siem_spool.reset_backoff()
    runner.flush()
    assert runner.siem_spool.stats().items == 0 and len(server.siem_batches) == 1


def test_disabled_sensor_stops_receivers(data_dir: Path) -> None:
    config = _siem_config(data_dir)
    server = FakeServer()
    server.config = server_config(siem=server_siem((SOURCE_A, "fw")))
    runner = _siem_runner(config, server)
    runner.tick()
    assert runner.siem.receivers
    server.status = "disabled"
    runner.next_heartbeat_at = 0
    runner.tick()
    assert runner.siem.receivers == {}


def test_siem_spool_is_separate(data_dir: Path) -> None:
    config = _siem_config(data_dir)
    runner = _siem_runner(config, FakeServer())
    assert runner.siem_spool is not None
    assert runner.siem_spool.path not in (runner.spool.path, config.ndr_spool_file())
