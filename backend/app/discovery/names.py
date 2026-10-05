"""Sondas de nombre e identidad: mDNS, NetBIOS y SSDP/UPnP.

Todas son consultas estándar que cualquier equipo de la LAN hace a diario (el explorador de
archivos de Windows, AirPlay, el "Enviar a dispositivo" de un móvil):

- mDNS (RFC 6762 §6.7, "legacy unicast"): una pregunta PTR del nombre inverso de la IP,
  enviada directamente al host en el puerto 5353. Sin multicast ni anuncios propios.
- NetBIOS (RFC 1002, NBSTAT): la consulta de `nbtstat -A <ip>`; solo se lee el nombre del
  equipo, no los recursos compartidos ni los usuarios.
- SSDP (UPnP): un único M-SEARCH multicast por scan con TTL 1 (no sale del segmento), y la
  lectura del documento de descripción XML que el propio dispositivo anuncia. Es lo que
  hace cualquier "control point" UPnP (Windows, una Smart TV) al ver la red.

No se envía nada más, no se prueban credenciales ni se explota nada. Cada sonda tiene
timeout estricto y tamaño de respuesta acotado; una respuesta mal formada se descarta
(None), nunca rompe el scan.

🪟 VALIDACIÓN LOCAL EN WINDOWS: UDP sobre el ProactorEventLoop y la recepción multicast
de SSDP con el firewall de Windows activo están probados solo con dobles de prueba.
"""

import asyncio
import contextlib
import ipaddress
import os
import re
import socket
import struct
import time

# Sin DTD ni entidades: ver parse_description.
import xml.etree.ElementTree as ET
from collections.abc import Collection
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit

MDNS_PORT = 5353
NETBIOS_PORT = 137
SSDP_ADDRESS = ("239.255.255.250", 1900)
# Ventana de escucha de respuestas al M-SEARCH. MX=1 pide a los dispositivos responder en
# menos de 1 s; el margen cubre equipos lentos sin alargar el scan.
SSDP_WINDOW = 2.0
MAX_SSDP_RESPONSES = 1024
MAX_DATAGRAM = 4096
# Un documento de descripción UPnP real ocupa pocos KB: el límite corta respuestas
# anómalas o maliciosas antes de parsearlas.
MAX_DESCRIPTION_BYTES = 64 * 1024
DESCRIPTION_TIMEOUT = 2.0
MAX_TEXT = 128

_HOSTNAME = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_.-]{0,252})$")


@dataclass(frozen=True)
class SsdpResponse:
    address: str
    server: str | None = None
    location: str | None = None


@dataclass(frozen=True)
class UpnpDescription:
    friendly_name: str | None = None
    manufacturer: str | None = None
    model_name: str | None = None
    model_number: str | None = None
    device_type: str | None = None


class IdentityProber(Protocol):
    async def mdns_name(self, address: str, timeout: float) -> str | None: ...

    async def netbios_name(self, address: str, timeout: float) -> str | None: ...

    async def ssdp_search(
        self, addresses: Collection[str], window: float
    ) -> dict[str, SsdpResponse]: ...

    async def upnp_description(
        self, response: SsdpResponse, timeout: float
    ) -> UpnpDescription | None: ...


# --- DNS (mDNS) -------------------------------------------------------------------------------


def reverse_pointer(address: str) -> str:
    return ipaddress.ip_address(address).reverse_pointer


def build_ptr_query(name: str, query_id: int) -> bytes:
    header = struct.pack("!HHHHHH", query_id, 0, 1, 0, 0, 0)
    question = b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in name.split(".") if label
    )
    return header + question + b"\x00" + struct.pack("!HH", 12, 1)  # PTR, IN


class DnsFormatError(ValueError):
    pass


def _read_name(message: bytes, offset: int) -> tuple[str, int]:
    """Nombre DNS en `offset`, siguiendo punteros de compresión con límites estrictos.

    Devuelve (nombre, offset tras el nombre en su posición original). Los punteros se
    limitan a 32 saltos y siempre hacia atrás, así un paquete hostil no provoca bucles.
    """
    labels: list[str] = []
    end: int | None = None
    jumps = 0
    position = offset
    while True:
        if position >= len(message):
            raise DnsFormatError("name out of bounds")
        length = message[position]
        if length & 0xC0 == 0xC0:
            if position + 1 >= len(message):
                raise DnsFormatError("truncated pointer")
            target = ((length & 0x3F) << 8) | message[position + 1]
            if end is None:
                end = position + 2
            jumps += 1
            if jumps > 32 or target >= position:
                raise DnsFormatError("bad compression pointer")
            position = target
            continue
        if length & 0xC0:
            raise DnsFormatError("unsupported label type")
        position += 1
        if length == 0:
            break
        label = message[position : position + length]
        if len(label) != length:
            raise DnsFormatError("truncated label")
        labels.append(label.decode("utf-8", "replace"))
        position += length
        if sum(len(part) + 1 for part in labels) > 255:
            raise DnsFormatError("name too long")
    return ".".join(labels), (end if end is not None else position)


def parse_ptr_response(message: bytes, query_id: int) -> str | None:
    """Primer PTR de la respuesta, o None si no es una respuesta válida a esa pregunta."""
    try:
        if len(message) < 12:
            return None
        rid, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", message[:12])
        # mDNS legacy unicast debe devolver el mismo id; QR=1 (respuesta) y RCODE=0.
        if rid != query_id or not flags & 0x8000 or flags & 0x000F:
            return None
        offset = 12
        for _ in range(qdcount):
            _, offset = _read_name(message, offset)
            offset += 4
        for _ in range(min(ancount, 32)):
            _, offset = _read_name(message, offset)
            if offset + 10 > len(message):
                return None
            rtype, _, _, rdlength = struct.unpack("!HHIH", message[offset : offset + 10])
            offset += 10
            if rtype == 12:
                name, _ = _read_name(message, offset)
                return clean_name(name)
            offset += rdlength
    except (DnsFormatError, struct.error):
        return None
    return None


# --- NetBIOS -----------------------------------------------------------------------------------


def build_nbstat_query(query_id: int) -> bytes:
    # Nombre "*" relleno con NUL hasta 16 bytes, en codificación de primer nivel (RFC 1001
    # §14.1): cada nibble se suma a 'A'.
    raw = b"*" + b"\x00" * 15
    encoded = bytes(c for byte in raw for c in (0x41 + (byte >> 4), 0x41 + (byte & 0x0F)))
    header = struct.pack("!HHHHHH", query_id, 0, 1, 0, 0, 0)
    return header + b"\x20" + encoded + b"\x00" + struct.pack("!HH", 0x21, 1)  # NBSTAT, IN


def parse_nbstat_response(message: bytes, query_id: int) -> str | None:
    """Nombre del equipo (entrada única con sufijo 0x00) de una respuesta NBSTAT."""
    try:
        if len(message) < 12:
            return None
        rid, flags, _, ancount, _, _ = struct.unpack("!HHHHHH", message[:12])
        if rid != query_id or not flags & 0x8000 or ancount < 1:
            return None
        _, offset = _read_name(message, 12)
        if offset + 11 > len(message):
            return None
        rtype, _, _, rdlength = struct.unpack("!HHIH", message[offset : offset + 10])
        offset += 10
        if rtype != 0x21:
            return None
        rdata = message[offset : offset + rdlength]
        if not rdata:
            return None
        count = rdata[0]
        for index in range(min(count, 64)):
            entry = rdata[1 + index * 18 : 1 + (index + 1) * 18]
            if len(entry) < 18:
                break
            name, suffix, name_flags = entry[:15], entry[15], (entry[16] << 8) | entry[17]
            # Bit de grupo (0x8000) = grupo de trabajo/dominio, no el equipo.
            if suffix == 0x00 and not name_flags & 0x8000:
                return clean_name(name.decode("ascii", "replace").strip())
    except (DnsFormatError, struct.error, IndexError):
        return None
    return None


# --- SSDP / UPnP -------------------------------------------------------------------------------

M_SEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 1\r\n"
    "ST: upnp:rootdevice\r\n"
    "\r\n"
).encode("ascii")


def parse_ssdp_response(address: str, data: bytes) -> SsdpResponse | None:
    try:
        text = data[:MAX_DATAGRAM].decode("utf-8", "replace")
    except UnicodeError:
        return None
    lines = text.split("\r\n")
    if not lines or not lines[0].upper().startswith("HTTP/1.1 200"):
        return None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        key, sep, value = line.partition(":")
        if sep:
            headers.setdefault(key.strip().lower(), value.strip())
    return SsdpResponse(
        address=address,
        server=clean_text(headers.get("server")),
        location=safe_location(address, headers.get("location")),
    )


def safe_location(address: str, location: str | None) -> str | None:
    """LOCATION solo si apunta por HTTP a la misma IP que respondió.

    Sin esta regla un dispositivo (o un paquete falsificado) podría hacer que el servidor
    Sentra pidiera URLs arbitrarias (SSRF): otra máquina, Internet o un servicio local.
    """
    if not location or len(location) > 512:
        return None
    try:
        parts = urlsplit(location)
        port = parts.port
    except ValueError:
        return None
    if parts.scheme != "http" or parts.hostname != address or parts.username or parts.password:
        return None
    if port is not None and not 1 <= port <= 65535:
        return None
    return location


def _local_text(element: ET.Element, tag: str) -> str | None:
    for child in element:
        if child.tag.rsplit("}", 1)[-1] == tag:
            return clean_text(child.text)
    return None


def parse_description(body: bytes) -> UpnpDescription | None:
    # ElementTree no resuelve entidades externas, pero una DTD con entidades anidadas
    # ("billion laughs") podría consumir memoria: un documento UPnP no necesita DTD, así que
    # cualquier DOCTYPE/ENTITY se rechaza antes de parsear.
    head = body[:MAX_DESCRIPTION_BYTES]
    if b"<!DOCTYPE" in head.upper() or b"<!ENTITY" in head.upper():
        return None
    try:
        root = ET.fromstring(head)  # noqa: S314  (sin DTD, ver arriba)
    except ET.ParseError:
        return None
    device = next((e for e in root.iter() if e.tag.rsplit("}", 1)[-1] == "device"), None)
    if device is None:
        return None
    description = UpnpDescription(
        friendly_name=_local_text(device, "friendlyName"),
        manufacturer=_local_text(device, "manufacturer"),
        model_name=_local_text(device, "modelName"),
        model_number=_local_text(device, "modelNumber"),
        device_type=_local_text(device, "deviceType"),
    )
    return description if any(vars(description).values()) else None


# --- Limpieza --------------------------------------------------------------------------------


def clean_text(value: str | None) -> str | None:
    """Texto de un dispositivo ajeno: imprimible, sin espacios repetidos y acotado."""
    if not value:
        return None
    text = re.sub(r"\s+", " ", "".join(ch for ch in value if ch.isprintable())).strip()
    return text[:MAX_TEXT] or None


def clean_name(value: str | None) -> str | None:
    if not value:
        return None
    name = value.strip().rstrip(".")
    if name.lower().endswith(".local"):
        name = name[: -len(".local")]
    return name if _HOSTNAME.match(name) else None


# --- Implementación real ----------------------------------------------------------------------


class _OneShot(asyncio.DatagramProtocol):
    def __init__(self, future: asyncio.Future[bytes | None]) -> None:
        self._future = future

    def datagram_received(self, data: bytes, addr: tuple[str | int, ...]) -> None:
        if not self._future.done():
            self._future.set_result(data)

    def error_received(self, exc: Exception) -> None:
        # Windows notifica el "port unreachable" ICMP como WSAECONNRESET en el socket UDP:
        # el host no tiene ese servicio. Es una respuesta normal, no un error del scan.
        if not self._future.done():
            self._future.set_result(None)

    def connection_lost(self, exc: Exception | None) -> None:
        if not self._future.done():
            self._future.set_result(None)


async def udp_query(address: str, port: int, payload: bytes, timeout: float) -> bytes | None:
    loop = asyncio.get_running_loop()
    future: asyncio.Future[bytes | None] = loop.create_future()
    try:
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _OneShot(future), remote_addr=(address, port)
        )
    except OSError:
        return None
    try:
        transport.sendto(payload)
        return await asyncio.wait_for(future, timeout)
    except (TimeoutError, OSError):
        return None
    finally:
        transport.close()


def _query_id() -> int:
    return int.from_bytes(os.urandom(2), "big")


class SystemIdentityProber:
    """Las sondas reales; los tests usan dobles que implementan IdentityProber."""

    async def mdns_name(self, address: str, timeout: float) -> str | None:
        query_id = _query_id()
        query = build_ptr_query(reverse_pointer(address), query_id)
        response = await udp_query(address, MDNS_PORT, query, timeout)
        return parse_ptr_response(response, query_id) if response else None

    async def netbios_name(self, address: str, timeout: float) -> str | None:
        query_id = _query_id()
        response = await udp_query(address, NETBIOS_PORT, build_nbstat_query(query_id), timeout)
        return parse_nbstat_response(response, query_id) if response else None

    async def ssdp_search(
        self, addresses: Collection[str], window: float
    ) -> dict[str, SsdpResponse]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, ssdp_search_blocking, set(addresses), window)

    async def upnp_description(
        self, response: SsdpResponse, timeout: float
    ) -> UpnpDescription | None:
        if response.location is None:
            return None
        body = await http_get(response.location, timeout)
        return parse_description(body) if body else None


def ssdp_search_blocking(addresses: set[str], window: float) -> dict[str, SsdpResponse]:
    """Un M-SEARCH y las respuestas de los hosts del scan durante `window` segundos.

    Respuestas de direcciones fuera del scan se ignoran: el alcance lo decide la allowlist,
    no quién conteste al multicast.
    """
    found: dict[str, SsdpResponse] = {}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        # TTL 1: el M-SEARCH no atraviesa routers.
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        sock.bind(("", 0))
        sock.sendto(M_SEARCH, SSDP_ADDRESS)
        deadline = time.monotonic() + window
        received = 0
        while received < MAX_SSDP_RESPONSES:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                data, (host, _) = sock.recvfrom(MAX_DATAGRAM)
            except TimeoutError:
                break
            except OSError:
                # Windows: un ICMP previo puede aflorar como error en recvfrom; se sigue.
                continue
            received += 1
            if host in addresses and host not in found:
                parsed = parse_ssdp_response(host, data)
                if parsed is not None:
                    found[host] = parsed
    return found


async def http_get(url: str, timeout: float) -> bytes | None:
    """GET HTTP/1.0 mínimo, acotado en tiempo y tamaño (sin seguir redirecciones)."""
    parts = urlsplit(url)
    host = parts.hostname
    if host is None:
        return None
    port = parts.port or 80
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except (OSError, TimeoutError):
        return None
    try:
        request = f"GET {path} HTTP/1.0\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n"
        writer.write(request.encode("latin-1", "replace"))
        await asyncio.wait_for(writer.drain(), timeout)
        raw = await asyncio.wait_for(_read_limited(reader, MAX_DESCRIPTION_BYTES + 8192), timeout)
    except (OSError, TimeoutError):
        return None
    finally:
        writer.close()
        with contextlib.suppress(OSError, TimeoutError):
            await asyncio.wait_for(writer.wait_closed(), timeout)
    head, sep, body = raw.partition(b"\r\n\r\n")
    status = head.split(b"\r\n", 1)[0].split()
    if not sep or len(status) < 2 or status[1] != b"200":
        return None
    return body


async def _read_limited(reader: asyncio.StreamReader, limit: int) -> bytes:
    # read(n) puede devolver menos de n aunque falten datos: se lee hasta EOF o el límite.
    chunks: list[bytes] = []
    size = 0
    while size < limit:
        chunk = await reader.read(limit - size)
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
    return b"".join(chunks)
