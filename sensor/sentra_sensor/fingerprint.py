"""Huellas de servicio del sensor (Fase 7A.4): mismo código que app/discovery/fingerprint.py
del servidor, para que un sensor y el discovery local observen exactamente lo mismo.

Tres sondas acotadas que leen lo que el propio dispositivo publica de sí mismo:

- mDNS DNS-SD (RFC 6763): qué tipos de servicio anuncia (`_ipp._tcp`, `_googlecast._tcp`,
  `_hap._tcp`...) y, si lo publica, su modelo (`_device-info._tcp`, TXT `model=`). Consultas
  unicast al puerto 5353 del host, igual que el nombre mDNS de la Fase 4E.
- HTTP: la cabecera `Server` y el `<title>` de `GET /` en el primer puerto web abierto.
- TLS: sujeto (CN y O) y emisor del certificado en el primer puerto TLS abierto.

Límites de seguridad (no es un escáner de vulnerabilidades ni un crawler):
- Solo hosts del target del job (que el servidor ya validó contra las redes del site) y solo
  puertos que el propio scan encontró abiertos; un puerto web y uno TLS por host como mucho.
- Una petición por puerto, sin credenciales, sin seguir redirecciones, sin cuerpo enviado y
  leyendo como mucho MAX_HTTP_BYTES.
- El certificado se lee del saludo TLS 1.2, que viaja en claro: se envía un ClientHello y se
  corta la conexión al recibir el certificado, antes del intercambio de claves. No se negocia
  ninguna sesión TLS, así que no hay validación que desactivar (un certificado autofirmado es
  justo lo habitual en cámaras e impresoras). Un servidor solo TLS 1.3 cifra su certificado y
  no aporta esta huella.
- Todo el texto recibido se limpia (imprimible, acotado) antes de guardarse.
"""

import asyncio
import contextlib
import html
import re
import secrets
import struct
from collections.abc import Collection, Iterable
from dataclasses import dataclass
from typing import Protocol

from sentra_sensor.names import (
    MDNS_PORT,
    DnsFormatError,
    _query_id,
    _read_name,
    clean_text,
    udp_query,
)

# Puertos web habituales de interfaces de gestión (routers, cámaras, NAS, impresoras).
HTTP_PORTS = (80, 8080, 8000, 8081, 8008, 8888, 9000, 9090, 10000, 5000, 7080)
TLS_PORTS = (443, 8443, 9443, 5001, 10443, 4443)
MAX_HTTP_BYTES = 32 * 1024
MAX_SERVICES = 24
MAX_RECORDS = 64
USER_AGENT = "Sentra-Discovery"

_SERVICE_TYPE = re.compile(r"^_[a-z0-9][a-z0-9-]{0,62}\._(tcp|udp)$")
_TITLE = re.compile(rb"<title[^>]*>(.*?)</title\s*>", re.IGNORECASE | re.DOTALL)
_DNS_PTR = 12
_DNS_TXT = 16


@dataclass(frozen=True)
class WebFingerprint:
    """Lo que un puerto web o TLS dice de sí mismo. Nada se interpreta aquí."""

    port: int
    tls: bool
    server: str | None = None
    title: str | None = None
    cert_cn: str | None = None
    cert_org: str | None = None
    # Emisor igual al sujeto: certificado autofirmado (típico de firmware embebido).
    self_signed: bool | None = None

    def as_dict(self) -> dict[str, object]:
        return {k: v for k, v in vars(self).items() if v is not None}


@dataclass(frozen=True)
class MdnsServices:
    services: tuple[str, ...] = ()
    model: str | None = None


class FingerprintProber(Protocol):
    async def mdns_services(self, address: str, timeout: float) -> MdnsServices | None: ...

    async def web(
        self, address: str, port: int, tls: bool, timeout: float
    ) -> WebFingerprint | None: ...


def pick_ports(open_ports: Collection[int]) -> list[tuple[int, bool]]:
    """Primer puerto web y primer puerto TLS abiertos, en orden de preferencia."""
    chosen: list[tuple[int, bool]] = []
    web = next((p for p in HTTP_PORTS if p in open_ports), None)
    if web is not None:
        chosen.append((web, False))
    secure = next((p for p in TLS_PORTS if p in open_ports), None)
    if secure is not None:
        chosen.append((secure, True))
    return chosen


# --- DNS-SD -------------------------------------------------------------------------------


def build_query(name: str, qtype: int, query_id: int) -> bytes:
    header = struct.pack("!HHHHHH", query_id, 0, 1, 0, 0, 0)
    labels = [label for label in name.split(".") if label]
    if any(len(label.encode()) > 63 for label in labels):
        raise ValueError("label too long")
    question = b"".join(bytes([len(label.encode())]) + label.encode() for label in labels)
    return header + question + b"\x00" + struct.pack("!HH", qtype, 1)


@dataclass(frozen=True)
class _Record:
    name: str
    rtype: int
    offset: int
    length: int


def parse_records(message: bytes, query_id: int) -> list[_Record]:
    """Registros de respuesta (answer + authority + additional) de una respuesta válida."""
    if len(message) < 12:
        return []
    rid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", message[:12])
    if rid != query_id or not flags & 0x8000 or flags & 0x000F:
        return []
    records: list[_Record] = []
    try:
        offset = 12
        for _ in range(min(qdcount, 4)):
            _, offset = _read_name(message, offset)
            offset += 4
        for _ in range(min(ancount + nscount + arcount, MAX_RECORDS)):
            name, offset = _read_name(message, offset)
            if offset + 10 > len(message):
                break
            rtype, _, _, rdlength = struct.unpack("!HHIH", message[offset : offset + 10])
            offset += 10
            if offset + rdlength > len(message):
                break
            records.append(_Record(name.lower(), rtype, offset, rdlength))
            offset += rdlength
    except (DnsFormatError, struct.error):
        return records
    return records


def _ptr_target(message: bytes, record: _Record) -> str | None:
    try:
        target, _ = _read_name(message, record.offset)
    except DnsFormatError:
        return None
    return target


def _txt_values(message: bytes, record: _Record) -> list[str]:
    values: list[str] = []
    position, end = record.offset, record.offset + record.length
    while position < end and len(values) < 32:
        size = message[position]
        position += 1
        chunk = message[position : min(position + size, end)]
        position += size
        values.append(chunk.decode("utf-8", "replace"))
    return values


def parse_service_types(message: bytes, query_id: int) -> tuple[str, ...]:
    """Tipos de servicio de una respuesta a `_services._dns-sd._udp.local` PTR."""
    found: list[str] = []
    for record in parse_records(message, query_id):
        if record.rtype != _DNS_PTR or record.name != "_services._dns-sd._udp.local":
            continue
        target = _ptr_target(message, record)
        if not target:
            continue
        service = target.lower().removesuffix(".local").rstrip(".")
        if _SERVICE_TYPE.match(service) and service not in found:
            found.append(service)
        if len(found) >= MAX_SERVICES:
            break
    return tuple(sorted(found))


def parse_device_info(message: bytes, query_id: int) -> tuple[str | None, str | None]:
    """(instancia, modelo) de una respuesta a `_device-info._tcp.local` PTR o TXT."""
    instance: str | None = None
    model: str | None = None
    for record in parse_records(message, query_id):
        if record.rtype == _DNS_PTR and record.name == "_device-info._tcp.local":
            instance = instance or _ptr_target(message, record)
        elif record.rtype == _DNS_TXT and record.name.endswith("._device-info._tcp.local"):
            for value in _txt_values(message, record):
                key, _, raw = value.partition("=")
                if key.lower() == "model" and raw:
                    model = clean_text(raw)
    return instance, model


# --- HTTP y TLS ---------------------------------------------------------------------------


def parse_http_response(raw: bytes) -> tuple[int | None, str | None, str | None]:
    """(estado, cabecera Server, título) de una respuesta HTTP/1.x acotada."""
    head, sep, body = raw.partition(b"\r\n\r\n")
    if not sep:
        head, sep, body = raw.partition(b"\n\n")
    lines = head.decode("latin-1", "replace").splitlines()
    if not lines or not lines[0].startswith("HTTP/"):
        return None, None, None
    parts = lines[0].split()
    status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
    server: str | None = None
    content_type = ""
    for line in lines[1:64]:
        name, _, value = line.partition(":")
        key = name.strip().lower()
        if key == "server":
            server = clean_text(value)
        elif key == "content-type":
            content_type = value.lower()
    title: str | None = None
    if status == 200 and ("html" in content_type or not content_type):
        match = _TITLE.search(body[:MAX_HTTP_BYTES])
        if match:
            text = match.group(1).decode("utf-8", "replace")
            title = clean_text(html.unescape(text))
    return status, server, title


def _der_item(data: bytes, offset: int) -> tuple[int, int, int]:
    """(etiqueta, inicio del contenido, fin del contenido) del elemento DER en `offset`."""
    if offset + 2 > len(data):
        raise ValueError("truncated")
    tag = data[offset]
    length = data[offset + 1]
    start = offset + 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or start + count > len(data):
            raise ValueError("bad length")
        length = int.from_bytes(data[start : start + count], "big")
        start += count
    end = start + length
    if end > len(data):
        raise ValueError("truncated")
    return tag, start, end


def _der_children(data: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    children: list[tuple[int, int, int]] = []
    position = start
    while position < end and len(children) < 64:
        tag, child_start, child_end = _der_item(data, position)
        children.append((tag, child_start, child_end))
        position = child_end
    return children


_OID_CN = bytes([0x55, 0x04, 0x03])
_OID_O = bytes([0x55, 0x04, 0x0A])


def _der_name(data: bytes, start: int, end: int) -> dict[str, str]:
    """CN y O de un Name X.509 (SEQUENCE de SET de SEQUENCE {OID, valor})."""
    found: dict[str, str] = {}
    for _, set_start, set_end in _der_children(data, start, end):
        for _, attr_start, attr_end in _der_children(data, set_start, set_end):
            parts = _der_children(data, attr_start, attr_end)
            if len(parts) != 2 or parts[0][0] != 0x06:
                continue
            oid = data[parts[0][1] : parts[0][2]]
            value = data[parts[1][1] : parts[1][2]].decode("utf-8", "replace")
            if oid == _OID_CN:
                found.setdefault("cn", value)
            elif oid == _OID_O:
                found.setdefault("o", value)
    return found


def certificate_names(der: bytes) -> tuple[dict[str, str], dict[str, str]]:
    """(sujeto, emisor) de un certificado DER. Vacíos si no se puede leer.

    Lector DER mínimo y acotado (solo SEQUENCE/SET y longitudes de hasta 4 bytes): no se
    añade una dependencia para leer dos campos, y un certificado malformado solo produce
    "sin datos", nunca una excepción hacia el scan.
    """
    try:
        _, cert_start, _ = _der_item(der, 0)
        _, tbs_start, tbs_end = _der_item(der, cert_start)
        fields = _der_children(der, tbs_start, tbs_end)
        # [0] version es opcional: con ella, el emisor es el 4.º elemento; sin ella, el 3.º.
        index = 1 if fields and fields[0][0] == 0xA0 else 0
        issuer = fields[index + 2]
        subject = fields[index + 4]
        return _der_name(der, subject[1], subject[2]), _der_name(der, issuer[1], issuer[2])
    except (ValueError, IndexError):
        return {}, {}


# --- Certificado TLS en claro -------------------------------------------------------------

_TLS_HANDSHAKE = 22
_HS_CLIENT_HELLO = 1
_HS_SERVER_HELLO_DONE = 14
_HS_CERTIFICATE = 11
MAX_TLS_BYTES = 64 * 1024
# Un registro TLS no supera 2^14 bytes más la expansión permitida.
_MAX_TLS_RECORD = 16384 + 2048
# Suites habituales en firmware embebido y en servidores actuales (ECDHE y RSA, también las
# antiguas que aún usan cámaras y NVR). Nunca se llega a cifrar nada con ellas: solo sirven
# para que el servidor elija una y envíe su certificado.
_CIPHER_SUITES = (
    0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC009, 0xC013, 0xC00A, 0xC014,
    0x009C, 0x009D, 0x002F, 0x0035, 0x000A, 0x00FF,
)  # fmt: skip
_GROUPS = (0x001D, 0x0017, 0x0018)
_SIGNATURE_ALGORITHMS = (
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201, 0x0203,
)  # fmt: skip


def _extension(kind: int, body: bytes) -> bytes:
    return struct.pack("!HH", kind, len(body)) + body


def _u16_list(values: Iterable[int]) -> bytes:
    data = b"".join(struct.pack("!H", value) for value in values)
    return struct.pack("!H", len(data)) + data


def build_client_hello(random: bytes) -> bytes:
    """ClientHello TLS 1.2 sin SNI (el destino es una IP) y sin `supported_versions`.

    Sin `supported_versions` un servidor no puede elegir TLS 1.3, en el que el certificado
    viaja cifrado; con TLS 1.2 o anterior lo envía en claro justo después del ServerHello.
    """
    if len(random) != 32:
        raise ValueError("random must be 32 bytes")
    extensions = (
        _extension(0x000A, _u16_list(_GROUPS))
        + _extension(0x000B, b"\x01\x00")
        + _extension(0x000D, _u16_list(_SIGNATURE_ALGORITHMS))
    )
    body = (
        b"\x03\x03"
        + random
        + b"\x00"
        + _u16_list(_CIPHER_SUITES)
        + b"\x01\x00"
        + struct.pack("!H", len(extensions))
        + extensions
    )
    handshake = bytes([_HS_CLIENT_HELLO]) + len(body).to_bytes(3, "big") + body
    return bytes([_TLS_HANDSHAKE, 3, 1]) + struct.pack("!H", len(handshake)) + handshake


def certificate_from_handshake(data: bytes) -> tuple[bool, bytes | None]:
    """Primer certificado (DER) de los registros TLS recibidos del servidor.

    Devuelve (terminado, certificado). Terminado significa que no hace falta leer más: llegó
    el certificado, una alerta, el final del saludo sin certificado o algo que no es TLS.
    Los mensajes de saludo pueden repartirse entre registros, por eso se reensamblan.
    """
    handshake = bytearray()
    position = 0
    while position + 5 <= len(data):
        content_type, major = data[position], data[position + 1]
        length = struct.unpack_from("!H", data, position + 3)[0]
        if content_type != _TLS_HANDSHAKE or major != 3 or length > _MAX_TLS_RECORD:
            # Una alerta (21), un servicio que no es TLS o un registro imposible.
            return True, None
        end = position + 5 + length
        if end > len(data):
            break
        handshake += data[position + 5 : end]
        position = end
    offset = 0
    while offset + 4 <= len(handshake):
        kind = handshake[offset]
        size = int.from_bytes(handshake[offset + 1 : offset + 4], "big")
        body_end = offset + 4 + size
        if body_end > len(handshake):
            return False, None
        if kind == _HS_CERTIFICATE:
            body = handshake[offset + 4 : body_end]
            if len(body) < 6:
                return True, None
            first = int.from_bytes(body[3:6], "big")
            if first == 0 or 6 + first > len(body):
                return True, None
            return True, bytes(body[6 : 6 + first])
        if kind == _HS_SERVER_HELLO_DONE:
            return True, None
        offset = body_end
    return False, None


async def tls_certificate(address: str, port: int, timeout: float) -> bytes | None:
    """Certificado que el servidor envía en su saludo TLS 1.2; None si no lo envía en claro."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout)
    except (OSError, TimeoutError):
        return None
    try:
        writer.write(build_client_hello(secrets.token_bytes(32)))
        await asyncio.wait_for(writer.drain(), timeout)
        data = b""
        while len(data) < MAX_TLS_BYTES:
            remaining = deadline - loop.time()
            if remaining <= 0:
                return None
            chunk = await asyncio.wait_for(reader.read(MAX_TLS_BYTES - len(data)), remaining)
            if not chunk:
                return None
            data += chunk
            done, der = certificate_from_handshake(data)
            if done:
                return der
        return None
    except (OSError, TimeoutError):
        return None
    finally:
        # Se corta aquí, antes del intercambio de claves: nunca queda una sesión TLS abierta.
        writer.close()
        with contextlib.suppress(OSError, TimeoutError):
            await asyncio.wait_for(writer.wait_closed(), timeout)


async def web_fingerprint(
    address: str, port: int, tls: bool, timeout: float
) -> WebFingerprint | None:
    """Huella de un puerto: cabecera Server y título por HTTP, o el certificado si es TLS."""
    if tls:
        der = await tls_certificate(address, port, timeout)
        subject, issuer = certificate_names(der) if der else ({}, {})
        found = WebFingerprint(
            port=port,
            tls=True,
            cert_cn=clean_text(subject.get("cn")),
            cert_org=clean_text(subject.get("o")),
            self_signed=(subject == issuer) if subject else None,
        )
        return found if (found.cert_cn or found.cert_org) else None
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout)
    except (OSError, TimeoutError):
        return None
    try:
        request = (
            f"GET / HTTP/1.0\r\nHost: {address}\r\nUser-Agent: {USER_AGENT}\r\n"
            "Accept: text/html\r\nConnection: close\r\n\r\n"
        )
        writer.write(request.encode("ascii"))
        await asyncio.wait_for(writer.drain(), timeout)
        raw = await asyncio.wait_for(_read_limited(reader, MAX_HTTP_BYTES), timeout)
    except (OSError, TimeoutError):
        raw = b""
    finally:
        writer.close()
        with contextlib.suppress(OSError, TimeoutError):
            await asyncio.wait_for(writer.wait_closed(), timeout)
    _, server, title = parse_http_response(raw) if raw else (None, None, None)
    if not (server or title):
        return None
    return WebFingerprint(port=port, tls=False, server=server, title=title)


async def _read_limited(reader: asyncio.StreamReader, limit: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while size < limit:
        chunk = await reader.read(limit - size)
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
    return b"".join(chunks)


async def mdns_services(address: str, timeout: float) -> MdnsServices | None:
    query_id = _query_id()
    response = await udp_query(
        address, MDNS_PORT, build_query("_services._dns-sd._udp.local", _DNS_PTR, query_id), timeout
    )
    services = parse_service_types(response, query_id) if response else ()
    model: str | None = None
    if "_device-info._tcp" in services or not services:
        query_id = _query_id()
        response = await udp_query(
            address, MDNS_PORT, build_query("_device-info._tcp.local", _DNS_PTR, query_id), timeout
        )
        instance, model = parse_device_info(response, query_id) if response else (None, None)
        if model is None and instance:
            # Algunos respondedores no adjuntan el TXT: se pide directamente a la instancia.
            query_id = _query_id()
            with contextlib.suppress(ValueError):
                response = await udp_query(
                    address, MDNS_PORT, build_query(instance, _DNS_TXT, query_id), timeout
                )
                _, model = parse_device_info(response, query_id) if response else (None, None)
    if not services and model is None:
        return None
    return MdnsServices(services=services, model=model)


class SystemFingerprintProber:
    """Las sondas reales; los tests usan dobles que implementan FingerprintProber."""

    async def mdns_services(self, address: str, timeout: float) -> MdnsServices | None:
        return await mdns_services(address, timeout)

    async def web(
        self, address: str, port: int, tls: bool, timeout: float
    ) -> WebFingerprint | None:
        return await web_fingerprint(address, port, tls, timeout)


def web_dicts(items: Iterable[WebFingerprint]) -> list[dict[str, object]]:
    return [item.as_dict() for item in items]
