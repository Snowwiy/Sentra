"""Receptor Syslog del sensor (Fase 7F.2): enmarcado, límites y pares permitidos.

* TCP y TLS usan el enmarcado de RFC 6587 en sus dos variantes, detectadas por mensaje:
  recuento de octetos (`LEN SP MSG`, también el de RFC 5425 para TLS) y la no transparente
  con LF final. Un mensaje que supera `max_message_bytes` se descarta entero (se cuenta como
  `dropped_oversize`) sin cortar el flujo: el resto de mensajes de la conexión sigue llegando.
* UDP (solo con `allow_udp = true`): un datagrama es un mensaje. La dirección de origen NO
  autentica: el filtro de pares en UDP reduce ruido, no es una defensa (se documenta).
  Cada datagrama se lee con un búfer mayor que cualquier datagrama UDP posible, así que se
  conoce su tamaño real en todas las plataformas: uno mayor que `max_message_bytes` se
  descarta entero (`dropped_oversize`), nunca se reenvía un trozo. Con un búfer pequeño,
  Linux trunca el datagrama en silencio y Windows lanza WSAEMSGSIZE y lo descarta; ese error
  también se cuenta como `dropped_oversize`, no como un fallo de red.
* El par se comprueba ANTES del handshake TLS y antes de leer nada: una conexión de fuera de
  `allowed_peers` se cierra sin consumir CPU de TLS.
* Límite de ritmo por entrada: en TCP/TLS se aplica contrapresión (se deja de leer y el
  emisor espera por el control de flujo de TCP); en UDP no hay contrapresión posible y el
  exceso se descarta (`dropped_rate`).
* Nada del contenido se interpreta en el sensor: el texto se decodifica como UTF-8 (los bytes
  inválidos se sustituyen), los NUL se sustituyen y se reenvía tal cual. El análisis de la
  cabecera es del servidor (backend/app/siem/normalizers/syslog.py).
"""

import contextlib
import errno
import logging
import secrets
import socket
import ssl
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sentra_sensor.siem.config import SyslogInput

logger = logging.getLogger("sentra_sensor.siem")

Sink = Callable[[str, dict[str, Any]], None]
READ_CHUNK = 16 * 1024
# Cabecera de recuento de octetos: como mucho 6 dígitos (65536 cabe) y un espacio.
_MAX_LEN_DIGITS = 6
_ACCEPT_TIMEOUT = 0.5
# Mayor que la carga útil máxima de un datagrama UDP (65 507 en IPv4, 65 527 en IPv6 sin
# jumbogramas) y que `max_message_bytes` + 1 (su tope es 65 536): ningún datagrama se trunca
# al leerlo. Es memoria temporal de una sola lectura, no crece con el tráfico.
_UDP_READ_BYTES = 65_537
# Windows: WSAEMSGSIZE (el datagrama no cabía en el búfer y el sistema lo ha descartado).
_WSAEMSGSIZE = 10_040
_MSGSIZE_ERRNOS = frozenset({errno.EMSGSIZE, _WSAEMSGSIZE})
_ERROR_LOG_INTERVAL = 60.0


class OversizeError(Exception):
    """Marca interna: el mensaje superaba el máximo y se ha descartado."""


@dataclass
class InputCounters:
    received: int = 0
    dropped_oversize: int = 0
    dropped_peer: int = 0
    dropped_rate: int = 0
    malformed: int = 0
    connections_rejected: int = 0
    # Lectores de ficheros (7F.3): ficheros truncados y rotaciones detectadas.
    truncations: int = 0
    rotations: int = 0
    # Errores de red al recibir (no de tamaño). Solo local: el contrato de estadísticas del
    # servidor no tiene este campo y no se envía en los lotes.
    receive_errors: int = 0
    connections: int = 0
    last_record_at: float | None = None
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def add(self, **deltas: int) -> None:
        with self.lock:
            for key, value in deltas.items():
                setattr(self, key, getattr(self, key) + value)

    def snapshot(self) -> dict[str, int]:
        with self.lock:
            return {
                "received": self.received,
                "dropped_oversize": self.dropped_oversize,
                "dropped_peer": self.dropped_peer,
                "dropped_rate": self.dropped_rate,
                "malformed": self.malformed,
                "connections_rejected": self.connections_rejected,
                "truncations": self.truncations,
                "rotations": self.rotations,
            }


class RateLimiter:
    """Cubo de fichas compartido por las conexiones de una entrada (thread-safe)."""

    def __init__(self, rate: int, clock: Callable[[], float] = time.monotonic) -> None:
        self.rate = float(rate)
        self._clock = clock
        self._tokens = float(rate)
        self._last = clock()
        self._lock = threading.Lock()

    def take(self) -> bool:
        with self._lock:
            now = self._clock()
            self._tokens = min(self.rate, self._tokens + (now - self._last) * self.rate)
            self._last = now
            if self._tokens >= 1:
                self._tokens -= 1
                return True
            return False

    def wait(self, stop: threading.Event, max_wait: float = 5.0) -> bool:
        """Contrapresión: espera una ficha (hasta `max_wait`). False si no llegó o se para."""
        deadline = self._clock() + max_wait
        while not stop.is_set():
            if self.take():
                return True
            if self._clock() >= deadline:
                return False
            stop.wait(min(0.05, 1.0 / self.rate))
        return False


class SyslogFramer:
    """Enmarcado RFC 6587 incremental y acotado. `feed` devuelve los mensajes completos."""

    def __init__(self, max_message_bytes: int) -> None:
        self.max = max_message_bytes
        self._buffer = bytearray()
        # Bytes que quedan por descartar de un mensaje con recuento demasiado grande.
        self._skip = 0
        # Descartando hasta el siguiente LF (mensaje no transparente demasiado largo).
        self._skip_line = False
        self.oversize = 0
        self.malformed = 0

    def feed(self, data: bytes) -> list[bytes]:
        self._buffer += data
        out: list[bytes] = []
        while self._buffer:
            if self._skip:
                taken = min(self._skip, len(self._buffer))
                del self._buffer[:taken]
                self._skip -= taken
                continue
            if self._skip_line:
                newline = self._buffer.find(b"\n")
                if newline < 0:
                    self._buffer.clear()
                    break
                del self._buffer[: newline + 1]
                self._skip_line = False
                continue
            first = self._buffer[0]
            if first in b"\r\n\x00 ":
                # Separadores sobrantes entre mensajes (CRLF de algunos emisores).
                del self._buffer[:1]
                continue
            if 0x31 <= first <= 0x39:  # '1'..'9': recuento de octetos
                space = self._buffer.find(b" ", 0, _MAX_LEN_DIGITS + 1)
                if space < 0:
                    if len(self._buffer) <= _MAX_LEN_DIGITS:
                        break  # cabecera incompleta: esperar más datos
                    # Ni cabecera válida ni '<': se trata como texto con LF.
                    if not self._take_line(out):
                        break
                    continue
                digits = bytes(self._buffer[:space])
                if not digits.isdigit():
                    self.malformed += 1
                    if not self._take_line(out):
                        break
                    continue
                length = int(digits)
                del self._buffer[: space + 1]
                if length > self.max:
                    self.oversize += 1
                    self._skip = length
                    continue
                if len(self._buffer) < length:
                    # Se reinserta la cabecera para reintentar cuando llegue el resto.
                    self._buffer[:0] = digits + b" "
                    break
                message = bytes(self._buffer[:length])
                del self._buffer[:length]
                out.append(message)
                continue
            if not self._take_line(out):
                break
        return out

    def _take_line(self, out: list[bytes]) -> bool:
        newline = self._buffer.find(b"\n")
        if newline < 0:
            if len(self._buffer) > self.max:
                self.oversize += 1
                self._buffer.clear()
                self._skip_line = True
            return False
        line = bytes(self._buffer[:newline])
        del self._buffer[: newline + 1]
        if len(line) > self.max:
            self.oversize += 1
        else:
            out.append(line)
        return True


def decode_message(data: bytes) -> str:
    """Bytes de un mensaje → texto reenviable: UTF-8 con sustitución, sin NUL ni CR/LF final."""
    text = data.decode("utf-8", errors="replace").replace("\x00", "�")
    return text.rstrip("\r\n")


def _now_iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, UTC).isoformat()


class SyslogReceiver:
    """Una entrada `type = "syslog"`: un socket de escucha y sus conexiones."""

    def __init__(
        self,
        spec: SyslogInput,
        sink: Sink,
        clock: Callable[[], float] = time.time,
        ssl_context_factory: Callable[[SyslogInput], ssl.SSLContext] | None = None,
    ) -> None:
        self.spec = spec
        self._sink = sink
        self._clock = clock
        self._ssl_factory = ssl_context_factory or server_ssl_context
        self.counters = InputCounters()
        self.limiter = RateLimiter(spec.max_records_per_second)
        self.state = "starting"
        self.error_code: str | None = None
        self.bound_port: int | None = None
        self._stop = threading.Event()
        self._socket: socket.socket | None = None
        self._threads: list[threading.Thread] = []
        self._connections: set[socket.socket] = set()
        self._lock = threading.Lock()
        # Prefijo aleatorio por arranque: record_id es único aunque el contador se reinicie.
        self._boot = secrets.token_hex(4)
        self._seq = 0

    # --- ciclo de vida ---------------------------------------------------------------

    def start(self) -> None:
        try:
            self._socket = self._open()
        except (OSError, ssl.SSLError, ValueError) as exc:
            self.state = "error"
            self.error_code = (
                "tls_config_invalid" if isinstance(exc, ssl.SSLError) else "bind_failed"
            )
            logger.error(
                "siem syslog input could not start",
                extra={"input": self.spec.name, "code": self.error_code, "error": str(exc)},
            )
            return
        target = self._serve_udp if self.spec.protocol == "udp" else self._serve_tcp
        thread = threading.Thread(target=target, name=f"siem-syslog-{self.spec.name}", daemon=True)
        self._threads.append(thread)
        self.state = "running"
        thread.start()

    def _open(self) -> socket.socket:
        family = socket.AF_INET6 if ":" in self.spec.bind else socket.AF_INET
        kind = socket.SOCK_DGRAM if self.spec.protocol == "udp" else socket.SOCK_STREAM
        sock = socket.socket(family, kind)
        try:
            if kind == socket.SOCK_STREAM:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if self.spec.protocol == "tls":
                # Se valida el certificado al arrancar: un error de configuración se ve ya.
                self._tls = self._ssl_factory(self.spec)
            sock.bind((self.spec.bind, self.spec.port))
            if kind == socket.SOCK_STREAM:
                sock.listen(min(128, self.spec.max_connections * 2))
            sock.settimeout(_ACCEPT_TIMEOUT)
            self.bound_port = sock.getsockname()[1]
        except BaseException:
            sock.close()
            raise
        return sock

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        with self._lock:
            for conn in list(self._connections):
                _close_quietly(conn)
        if self._socket is not None:
            _close_quietly(self._socket)
        for thread in list(self._threads):
            thread.join(timeout=timeout)
        if self.state != "error":
            self.state = "stopped"

    # --- registros -------------------------------------------------------------------

    def _emit(self, data: bytes, transport: str, peer: tuple[str, int]) -> None:
        text = decode_message(data)
        if not text.strip():
            self.counters.add(malformed=1)
            return
        now = self._clock()
        with self._lock:
            self._seq += 1
            record_id = f"{self._boot}:{self._seq}"
        record = {
            "raw": text,
            "record_id": record_id,
            "collected_at": _now_iso(now),
            "transport": transport,
            "peer_ip": peer[0].split("%", 1)[0][:45],
            "peer_port": peer[1],
        }
        self.counters.add(received=1)
        with self.counters.lock:
            self.counters.last_record_at = now
        self._sink(self.spec.name, record)

    # --- UDP -------------------------------------------------------------------------

    def _serve_udp(self) -> None:
        sock = self._socket
        if sock is None:
            return
        last_error_log = 0.0
        while not self._stop.is_set():
            try:
                data, address = sock.recvfrom(_UDP_READ_BYTES)
            except TimeoutError:
                continue
            except OSError as exc:
                if self._stop.is_set():
                    return
                if _is_msgsize(exc):
                    # No debería ocurrir con _UDP_READ_BYTES, pero si un sistema lo hace, el
                    # datagrama ya está descartado entero: es un sobredimensionado.
                    self.counters.add(dropped_oversize=1)
                    continue
                # Windows informa así de un ICMP "port unreachable" de un envío anterior
                # (WSAECONNRESET) y de otros fallos transitorios: se cuentan aparte.
                self.counters.add(receive_errors=1)
                now = time.monotonic()
                if now - last_error_log >= _ERROR_LOG_INTERVAL:
                    last_error_log = now
                    logger.warning(
                        "siem udp receive error",
                        extra={"input": self.spec.name, "errno": exc.errno},
                    )
                continue
            if not self.spec.peer_allowed(address[0]):
                self.counters.add(dropped_peer=1)
                continue
            if len(data) > self.spec.max_message_bytes:
                self.counters.add(dropped_oversize=1)
                continue
            if not self.limiter.take():
                self.counters.add(dropped_rate=1)
                continue
            try:
                self._emit(data, "udp", (address[0], address[1]))
            except Exception:
                logger.exception("siem syslog sink failed", extra={"input": self.spec.name})

    # --- TCP / TLS -------------------------------------------------------------------

    def _serve_tcp(self) -> None:
        sock = self._socket
        if sock is None:
            return
        while not self._stop.is_set():
            try:
                conn, address = sock.accept()
            except TimeoutError:
                continue
            except OSError:
                if self._stop.is_set():
                    return
                continue
            if not self.spec.peer_allowed(address[0]):
                self.counters.add(connections_rejected=1, dropped_peer=1)
                _close_quietly(conn)
                continue
            with self._lock:
                if len(self._connections) >= self.spec.max_connections:
                    self.counters.add(connections_rejected=1)
                    _close_quietly(conn)
                    continue
                self._connections.add(conn)
            thread = threading.Thread(
                target=self._serve_connection,
                args=(conn, (address[0], address[1])),
                name=f"siem-syslog-{self.spec.name}-conn",
                daemon=True,
            )
            self._threads = [t for t in self._threads if t.is_alive()]
            self._threads.append(thread)
            thread.start()

    def _serve_connection(self, conn: socket.socket, peer: tuple[str, int]) -> None:
        stream: socket.socket = conn
        with self.counters.lock:
            self.counters.connections += 1
        try:
            conn.settimeout(self.spec.idle_timeout_seconds)
            if self.spec.protocol == "tls":
                try:
                    stream = self._tls.wrap_socket(conn, server_side=True)
                except (ssl.SSLError, OSError):
                    self.counters.add(connections_rejected=1)
                    return
                with self._lock:
                    self._connections.discard(conn)
                    self._connections.add(stream)
            framer = SyslogFramer(self.spec.max_message_bytes)
            transport = "tls" if self.spec.protocol == "tls" else "tcp"
            while not self._stop.is_set():
                try:
                    data = stream.recv(READ_CHUNK)
                except (TimeoutError, OSError, ssl.SSLError):
                    return
                if not data:
                    return
                messages = framer.feed(data)
                if framer.oversize or framer.malformed:
                    self.counters.add(dropped_oversize=framer.oversize, malformed=framer.malformed)
                    framer.oversize = framer.malformed = 0
                for message in messages:
                    if not self.limiter.wait(self._stop):
                        # Sin ficha tras la espera máxima: se descarta y se cuenta.
                        self.counters.add(dropped_rate=1)
                        continue
                    try:
                        self._emit(message, transport, peer)
                    except Exception:
                        logger.exception("siem syslog sink failed", extra={"input": self.spec.name})
        finally:
            with self._lock:
                self._connections.discard(stream)
                self._connections.discard(conn)
            with self.counters.lock:
                self.counters.connections -= 1
            _close_quietly(stream)

    _tls: ssl.SSLContext


def server_ssl_context(spec: SyslogInput) -> ssl.SSLContext:
    """Contexto TLS de servidor: TLS 1.2 como mínimo, certificado y clave del host."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if spec.tls_cert is None or spec.tls_key is None:
        raise ValueError("tls input without certificate")
    context.load_cert_chain(str(spec.tls_cert), str(spec.tls_key))
    return context


def _is_msgsize(exc: OSError) -> bool:
    return exc.errno in _MSGSIZE_ERRNOS or getattr(exc, "winerror", None) == _WSAEMSGSIZE


def _close_quietly(sock: socket.socket) -> None:
    with contextlib.suppress(OSError):
        sock.close()
