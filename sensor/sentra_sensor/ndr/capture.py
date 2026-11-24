"""Backends de captura pasiva (Fase 7E.1): AF_PACKET (Linux), libpcap/Npcap (ctypes) y pcap.

Ninguno es una dependencia obligatoria:
* Linux: `af_packet` usa solo `socket` de la biblioteca estándar y necesita CAP_NET_RAW (no
  root): ver packaging/linux/sentra-sensor-ndr.conf.
* Windows: Npcap (instalado por el operador, nunca por Sentra) a través de ctypes sobre
  `%SystemRoot%\\System32\\Npcap\\wpcap.dll`. No se usa WinPcap (abandonado) ni se cargan DLL
  desde el directorio de trabajo.
* macOS: la libpcap del sistema. Leer /dev/bpf* necesita permisos (grupo `access_bpf` de
  Wireshark/ChmodBPF o root); sin ellos el backend informa `permission_denied`.
* `pcap_file`: lectura de un fichero .pcap clásico para pruebas y para `ndr-replay`; nunca se
  usa en producción ni envía nada.

Captura estrictamente pasiva: ningún backend abre un socket de envío ni llama a funciones de
inyección (pcap_inject/pcap_sendpacket). El modo promiscuo solo se activa si el servidor lo
aprueba y nunca se modifica la configuración del adaptador más allá de esa membresía, que el
sistema operativo retira al cerrar el socket.
"""

import ctypes
import ctypes.util
import errno
import os
import socket
import struct
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from sentra_sensor.ndr.decode import DLT_EN10MB

# Códigos de error estables que el sensor informa al servidor (heartbeat y diagnóstico).
ERR_BACKEND_UNAVAILABLE = "backend_unavailable"
ERR_NPCAP_MISSING = "npcap_missing"
ERR_LIBPCAP_MISSING = "libpcap_missing"
ERR_PERMISSION = "permission_denied"
ERR_NO_INTERFACE = "interface_not_found"
ERR_INTERFACE_DOWN = "interface_down"
ERR_CAPTURE_FAILED = "capture_failed"
ERR_UNSUPPORTED_LINK = "unsupported_link_type"

ETH_P_ALL = 0x0003
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1
PACKET_STATISTICS = 6
MAX_BATCH_PACKETS = 512


class CaptureError(Exception):
    """Fallo de apertura o lectura con un código estable (ERR_*) y un detalle acotado."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail[:300]


@dataclass(frozen=True)
class RawFrame:
    timestamp: float
    data: bytes
    wire_length: int


@dataclass(frozen=True)
class DropCounters:
    """Pérdidas informadas por el sistema (acumuladas desde la apertura)."""

    kernel: int = 0
    interface: int = 0


class CaptureBackend(Protocol):
    name: str
    linktype: int

    def open(self) -> None: ...

    def read(self, timeout: float) -> list[RawFrame]: ...

    def drops(self) -> DropCounters: ...

    def close(self) -> None: ...


@dataclass(frozen=True)
class InterfaceInfo:
    device: str
    description: str | None
    up: bool | None
    addresses: tuple[str, ...] = ()


# --- Linux: AF_PACKET ----------------------------------------------------------------------


class AfPacketBackend:
    """Socket AF_PACKET de solo recepción enlazado a un dispositivo concreto."""

    name = "af_packet"
    linktype = DLT_EN10MB

    def __init__(self, device: str, snaplen: int, promiscuous: bool, buffer_kb: int = 4096):
        self.device = device
        self.snaplen = snaplen
        self.promiscuous = promiscuous
        self.buffer_kb = buffer_kb
        self._sock: socket.socket | None = None
        self._buffer = bytearray(max(snaplen, 64))
        self._drops = DropCounters()

    def open(self) -> None:
        if not hasattr(socket, "AF_PACKET"):
            raise CaptureError(ERR_BACKEND_UNAVAILABLE, "AF_PACKET is only available on Linux")
        try:
            index = socket.if_nametoindex(self.device)
        except OSError as exc:
            raise CaptureError(ERR_NO_INTERFACE, f"interface {self.device!r} not found") from exc
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        except PermissionError as exc:
            raise CaptureError(
                ERR_PERMISSION, "AF_PACKET needs CAP_NET_RAW (see sentra-sensor-ndr.conf)"
            ) from exc
        except OSError as exc:
            raise CaptureError(ERR_CAPTURE_FAILED, f"socket: {exc}") from exc
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.buffer_kb * 1024)
            sock.bind((self.device, 0))
            if self.promiscuous:
                # packet_mreq: ifindex, tipo, longitud de dirección, dirección (8 bytes).
                mreq = struct.pack("iHH8s", index, PACKET_MR_PROMISC, 0, b"")
                sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)
        except OSError as exc:
            sock.close()
            if exc.errno == errno.ENETDOWN:
                raise CaptureError(
                    ERR_INTERFACE_DOWN, f"interface {self.device!r} is down"
                ) from exc
            raise CaptureError(ERR_CAPTURE_FAILED, f"bind: {exc}") from exc
        self._sock = sock

    def read(self, timeout: float) -> list[RawFrame]:
        sock = self._sock
        if sock is None:
            raise CaptureError(ERR_CAPTURE_FAILED, "capture is not open")
        frames: list[RawFrame] = []
        sock.settimeout(timeout)
        try:
            while len(frames) < MAX_BATCH_PACKETS:
                # MSG_TRUNC devuelve la longitud real aunque solo se copien `snaplen` bytes.
                length = sock.recv_into(self._buffer, self.snaplen, socket.MSG_TRUNC)
                frames.append(
                    RawFrame(time.time(), bytes(self._buffer[: min(length, self.snaplen)]), length)
                )
                sock.settimeout(0)
        except (TimeoutError, BlockingIOError):
            pass
        except OSError as exc:
            if exc.errno == errno.ENETDOWN:
                raise CaptureError(ERR_INTERFACE_DOWN, "interface went down") from exc
            raise CaptureError(ERR_CAPTURE_FAILED, f"recv: {exc}") from exc
        return frames

    def drops(self) -> DropCounters:
        sock = self._sock
        if sock is not None:
            try:
                raw = sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8)
                _packets, dropped = struct.unpack("II", raw)
                # El kernel pone a cero el contador en cada lectura: se acumula aquí.
                self._drops = DropCounters(self._drops.kernel + dropped, 0)
            except OSError:
                pass
        return self._drops

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None


# --- libpcap / Npcap por ctypes -------------------------------------------------------------


PCAP_ERRBUF_SIZE = 256
PCAP_ERROR_NO_SUCH_DEVICE = -5
PCAP_ERROR_PERM_DENIED = -8
PCAP_ERROR_IFACE_NOT_UP = -9
PCAP_ERROR_PROMISC_PERM_DENIED = -11


class _TimevalUnix(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]


class _TimevalDarwin(ctypes.Structure):
    # macOS: tv_usec es un int de 32 bits (con relleno), no un long.
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_int32)]


class _TimevalWindows(ctypes.Structure):
    # Windows (LLP64): long es de 32 bits incluso en 64 bits.
    _fields_ = [("tv_sec", ctypes.c_int32), ("tv_usec", ctypes.c_int32)]


def _pkthdr_type(platform: str) -> type[ctypes.Structure]:
    timeval: type[ctypes.Structure]
    if platform == "win32":
        timeval = _TimevalWindows
    elif platform == "darwin":
        timeval = _TimevalDarwin
    else:
        timeval = _TimevalUnix

    class PcapPkthdr(ctypes.Structure):
        _fields_ = [("ts", timeval), ("caplen", ctypes.c_uint32), ("len", ctypes.c_uint32)]

    return PcapPkthdr


class _PcapStat(ctypes.Structure):
    _fields_ = [
        ("ps_recv", ctypes.c_uint),
        ("ps_drop", ctypes.c_uint),
        ("ps_ifdrop", ctypes.c_uint),
    ]


class _PcapAddr(ctypes.Structure):
    pass


class _SockAddr(ctypes.Structure):
    _fields_ = [("sa_family", ctypes.c_ushort), ("sa_data", ctypes.c_char * 14)]


_PcapAddr._fields_ = [
    ("next", ctypes.POINTER(_PcapAddr)),
    ("addr", ctypes.POINTER(_SockAddr)),
    ("netmask", ctypes.POINTER(_SockAddr)),
    ("broadaddr", ctypes.POINTER(_SockAddr)),
    ("dstaddr", ctypes.POINTER(_SockAddr)),
]


class _PcapIf(ctypes.Structure):
    pass


_PcapIf._fields_ = [
    ("next", ctypes.POINTER(_PcapIf)),
    ("name", ctypes.c_char_p),
    ("description", ctypes.c_char_p),
    ("addresses", ctypes.POINTER(_PcapAddr)),
    ("flags", ctypes.c_uint),
]
PCAP_IF_UP = 0x00000002


def npcap_directory(env: dict[str, str] | None = None) -> Path:
    env = env if env is not None else dict(os.environ)
    root = env.get("SYSTEMROOT") or env.get("SystemRoot") or "C:\\Windows"
    return Path(root) / "System32" / "Npcap"


def load_libpcap(platform: str | None = None) -> Any:
    """Carga libpcap/Npcap o lanza CaptureError(npcap_missing | libpcap_missing).

    En Windows solo se acepta la DLL de la carpeta de Npcap del sistema (ruta absoluta), nunca
    una búsqueda por PATH: una wpcap.dll plantada junto al servicio no debe cargarse.
    """
    platform = platform or sys.platform
    if platform == "win32":
        directory = npcap_directory()
        dll = directory / "wpcap.dll"
        if not dll.is_file():
            raise CaptureError(ERR_NPCAP_MISSING, f"Npcap is not installed ({dll} not found)")
        add_dll_directory = getattr(os, "add_dll_directory", None)
        handle = add_dll_directory(str(directory)) if add_dll_directory is not None else None
        try:
            return ctypes.CDLL(str(dll))
        except OSError as exc:
            raise CaptureError(ERR_NPCAP_MISSING, f"cannot load Npcap: {exc}") from exc
        finally:
            if handle is not None:
                handle.close()
    name = ctypes.util.find_library("pcap")
    candidates = [name] if name else []
    candidates += (
        ["/usr/lib/libpcap.A.dylib"]
        if platform == "darwin"
        else ["libpcap.so.1", "libpcap.so.0.8", "libpcap.so"]
    )
    for candidate in candidates:
        try:
            return ctypes.CDLL(candidate)
        except OSError:
            continue
    raise CaptureError(ERR_LIBPCAP_MISSING, "libpcap is not installed")


class LibpcapBackend:
    """Captura con libpcap (Linux/macOS) o Npcap (Windows) por ctypes, solo lectura."""

    name = "libpcap"

    def __init__(
        self,
        device: str,
        snaplen: int,
        promiscuous: bool,
        buffer_kb: int = 4096,
        platform: str | None = None,
    ) -> None:
        self.device = device
        self.snaplen = snaplen
        self.promiscuous = promiscuous
        self.buffer_kb = buffer_kb
        self.platform = platform or sys.platform
        if self.platform == "win32":
            self.name = "npcap"
        self.linktype = DLT_EN10MB
        self._lib: Any = None
        self._handle: Any = None
        self._hdr_type = _pkthdr_type(self.platform)

    def _bind(self, lib: Any) -> None:
        lib.pcap_create.restype = ctypes.c_void_p
        lib.pcap_create.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        for fn in ("pcap_set_snaplen", "pcap_set_promisc", "pcap_set_timeout"):
            getattr(lib, fn).argtypes = [ctypes.c_void_p, ctypes.c_int]
            getattr(lib, fn).restype = ctypes.c_int
        lib.pcap_set_buffer_size.argtypes = [ctypes.c_void_p, ctypes.c_int]
        lib.pcap_activate.argtypes = [ctypes.c_void_p]
        lib.pcap_activate.restype = ctypes.c_int
        lib.pcap_datalink.argtypes = [ctypes.c_void_p]
        lib.pcap_datalink.restype = ctypes.c_int
        lib.pcap_geterr.argtypes = [ctypes.c_void_p]
        lib.pcap_geterr.restype = ctypes.c_char_p
        lib.pcap_next_ex.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.POINTER(self._hdr_type)),
            ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)),
        ]
        lib.pcap_next_ex.restype = ctypes.c_int
        lib.pcap_stats.argtypes = [ctypes.c_void_p, ctypes.POINTER(_PcapStat)]
        lib.pcap_stats.restype = ctypes.c_int
        lib.pcap_close.argtypes = [ctypes.c_void_p]

    def open(self) -> None:
        lib = load_libpcap(self.platform)
        self._bind(lib)
        errbuf = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
        handle = lib.pcap_create(self.device.encode(), errbuf)
        if not handle:
            raise CaptureError(ERR_NO_INTERFACE, errbuf.value.decode(errors="replace"))
        lib.pcap_set_snaplen(handle, self.snaplen)
        lib.pcap_set_promisc(handle, 1 if self.promiscuous else 0)
        # Timeout de lectura corto: el bucle debe poder parar y exportar aunque no haya tráfico.
        lib.pcap_set_timeout(handle, 250)
        lib.pcap_set_buffer_size(handle, self.buffer_kb * 1024)
        status = lib.pcap_activate(handle)
        if status < 0:
            message = (lib.pcap_geterr(handle) or b"").decode(errors="replace")
            lib.pcap_close(handle)
            code = {
                PCAP_ERROR_NO_SUCH_DEVICE: ERR_NO_INTERFACE,
                PCAP_ERROR_PERM_DENIED: ERR_PERMISSION,
                PCAP_ERROR_PROMISC_PERM_DENIED: ERR_PERMISSION,
                PCAP_ERROR_IFACE_NOT_UP: ERR_INTERFACE_DOWN,
            }.get(status, ERR_CAPTURE_FAILED)
            raise CaptureError(code, message or f"pcap_activate returned {status}")
        self.linktype = int(lib.pcap_datalink(handle))
        self._lib = lib
        self._handle = handle

    def read(self, timeout: float) -> list[RawFrame]:
        lib, handle = self._lib, self._handle
        if lib is None or handle is None:
            raise CaptureError(ERR_CAPTURE_FAILED, "capture is not open")
        frames: list[RawFrame] = []
        header = ctypes.POINTER(self._hdr_type)()
        data = ctypes.POINTER(ctypes.c_ubyte)()
        deadline = time.monotonic() + timeout
        while len(frames) < MAX_BATCH_PACKETS:
            status = lib.pcap_next_ex(handle, ctypes.byref(header), ctypes.byref(data))
            if status == 1:
                hdr = header.contents
                caplen = min(int(hdr.caplen), self.snaplen)
                frames.append(
                    RawFrame(
                        hdr.ts.tv_sec + hdr.ts.tv_usec / 1_000_000,
                        ctypes.string_at(data, caplen),
                        int(hdr.len),
                    )
                )
                continue
            if status == 0:
                # Timeout del buffer sin paquetes: se vuelve al bucle si ya pasó el plazo.
                if frames or time.monotonic() >= deadline:
                    break
                continue
            message = (lib.pcap_geterr(handle) or b"").decode(errors="replace")
            raise CaptureError(ERR_CAPTURE_FAILED, message or f"pcap_next_ex returned {status}")
        return frames

    def drops(self) -> DropCounters:
        if self._lib is None or self._handle is None:
            return DropCounters()
        stat = _PcapStat()
        if self._lib.pcap_stats(self._handle, ctypes.byref(stat)) != 0:
            return DropCounters()
        return DropCounters(int(stat.ps_drop), int(stat.ps_ifdrop))

    def close(self) -> None:
        if self._lib is not None and self._handle is not None:
            self._lib.pcap_close(self._handle)
        self._handle = None


def list_pcap_interfaces(platform: str | None = None) -> list[InterfaceInfo]:
    """Interfaces que ve libpcap/Npcap (nombre de dispositivo y descripción). Puede lanzar
    CaptureError si la biblioteca no está instalada."""
    lib = load_libpcap(platform)
    lib.pcap_findalldevs.argtypes = [
        ctypes.POINTER(ctypes.POINTER(_PcapIf)),
        ctypes.c_char_p,
    ]
    lib.pcap_findalldevs.restype = ctypes.c_int
    lib.pcap_freealldevs.argtypes = [ctypes.POINTER(_PcapIf)]
    errbuf = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
    first = ctypes.POINTER(_PcapIf)()
    if lib.pcap_findalldevs(ctypes.byref(first), errbuf) != 0:
        raise CaptureError(ERR_CAPTURE_FAILED, errbuf.value.decode(errors="replace"))
    result: list[InterfaceInfo] = []
    try:
        node = first
        while node and len(result) < 128:
            item = node.contents
            result.append(
                InterfaceInfo(
                    device=(item.name or b"").decode(errors="replace"),
                    description=(item.description or b"").decode(errors="replace") or None,
                    up=bool(item.flags & PCAP_IF_UP),
                )
            )
            node = item.next
    finally:
        if first:
            lib.pcap_freealldevs(first)
    return result


def list_os_interfaces() -> list[InterfaceInfo]:
    """Interfaces del sistema sin dependencias (nombres). En Linux añade si están UP."""
    result: list[InterfaceInfo] = []
    try:
        names = [name for _, name in socket.if_nameindex()]
    except OSError:
        names = []
    for name in names[:128]:
        up: bool | None = None
        operstate = Path("/sys/class/net") / name / "operstate"
        if operstate.is_file():
            try:
                up = operstate.read_text().strip() in ("up", "unknown")
            except OSError:
                up = None
        result.append(InterfaceInfo(device=name, description=None, up=up))
    return result


# --- Fichero pcap (pruebas y replay) --------------------------------------------------------

_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
MAX_PCAP_RECORD = 262_144


def read_pcap(path: Path) -> tuple[int, Iterator[RawFrame]]:
    """(linktype, frames) de un .pcap clásico. pcapng no está soportado (se rechaza)."""
    handle = path.open("rb")
    header = handle.read(24)
    if len(header) < 24 or header[:4] not in _PCAP_MAGICS:
        handle.close()
        raise CaptureError(
            ERR_UNSUPPORTED_LINK, "not a classic pcap file (pcapng is not supported)"
        )
    order, divisor = _PCAP_MAGICS[header[:4]]
    linktype = struct.unpack(order + "I", header[20:24])[0] & 0x0FFFFFFF

    def frames() -> Iterator[RawFrame]:
        with handle:
            while True:
                record = handle.read(16)
                if len(record) < 16:
                    return
                seconds, fraction, caplen, length = struct.unpack(order + "IIII", record)
                if caplen > MAX_PCAP_RECORD:
                    raise CaptureError(ERR_CAPTURE_FAILED, "pcap record larger than allowed")
                data = handle.read(caplen)
                if len(data) < caplen:
                    return
                yield RawFrame(seconds + fraction / divisor, data, length)

    return linktype, frames()


class PcapFileBackend:
    """Reproduce un .pcap como si fuese una captura (pruebas y `ndr-replay`)."""

    name = "pcap_file"

    def __init__(self, path: Path, snaplen: int = 65_535) -> None:
        self.path = path
        self.snaplen = snaplen
        self.linktype = DLT_EN10MB
        self._frames: Iterator[RawFrame] | None = None
        self.exhausted = False

    def open(self) -> None:
        self.linktype, self._frames = read_pcap(self.path)

    def read(self, timeout: float) -> list[RawFrame]:
        if self._frames is None:
            raise CaptureError(ERR_CAPTURE_FAILED, "capture is not open")
        frames: list[RawFrame] = []
        for frame in self._frames:
            frames.append(RawFrame(frame.timestamp, frame.data[: self.snaplen], frame.wire_length))
            if len(frames) >= MAX_BATCH_PACKETS:
                return frames
        self.exhausted = True
        return frames

    def drops(self) -> DropCounters:
        return DropCounters()

    def close(self) -> None:
        self._frames = None


def write_pcap(path: Path, frames: list[tuple[float, bytes]], linktype: int = DLT_EN10MB) -> None:
    """Escribe un .pcap clásico (pruebas sintéticas; nunca tráfico real del usuario)."""
    with path.open("wb") as handle:
        handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_535, linktype))
        for timestamp, data in frames:
            seconds = int(timestamp)
            micros = round((timestamp - seconds) * 1_000_000)
            handle.write(struct.pack("<IIII", seconds, micros, len(data), len(data)))
            handle.write(data)


def make_backend(
    kind: str, device: str, snaplen: int, promiscuous: bool, platform: str | None = None
) -> CaptureBackend:
    """Backend según la configuración local (`auto` elige el nativo de cada sistema)."""
    platform = platform or sys.platform
    if kind == "auto":
        kind = "af_packet" if platform.startswith("linux") else "libpcap"
    if kind == "af_packet":
        return AfPacketBackend(device, snaplen, promiscuous)
    if kind == "libpcap":
        return LibpcapBackend(device, snaplen, promiscuous, platform=platform)
    raise CaptureError(ERR_BACKEND_UNAVAILABLE, f"unknown capture backend {kind!r}")
