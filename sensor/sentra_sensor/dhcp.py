"""Leases DHCP de ficheros locales (Fase 6E, sensor 0.6.0): lectura acotada y parsers puros.

El sensor solo lee los ficheros que el operador del host declaró en `[[dhcp_lease_files]]`;
el servidor nombra la fuente y nunca envía una ruta, así que no puede usar este job para leer
otra cosa del disco. Por eso:

* La lectura está acotada por `dhcp_max_file_kb` (se comprueba el tamaño antes y durante la
  lectura, porque el fichero puede crecer entre el `stat` y el `read`) y no se siguen FIFOs ni
  dispositivos: un `open` bloqueante sobre una FIFO colgaría el hilo del job.
* Los parsers son funciones puras (texto + hora de referencia → leases normalizados): se
  prueban sin disco y una línea rara nunca rompe el job, solo cuenta como `skipped`.
* Nada del contenido del fichero va a los logs; al servidor solo llegan los campos
  normalizados (el `client_id` opaco va resumido con sha256, no en claro).
"""

import csv
import hashlib
import ipaddress
import os
import re
import stat
import threading
import time
import unicodedata
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sentra_sensor.config import DHCP_FORMATS, LocalConfig

ERROR_SOURCE_UNKNOWN = "dhcp_source_unknown"
ERROR_FILE_MISSING = "dhcp_file_missing"
ERROR_FILE_UNREADABLE = "dhcp_file_unreadable"
ERROR_FILE_TOO_LARGE = "dhcp_file_too_large"
ERROR_FORMAT_INVALID = "dhcp_format_invalid"

STATE_ACTIVE = "active"
STATE_EXPIRED = "expired"
STATE_RELEASED = "released"
STATE_UNKNOWN = "unknown"

# Contrato: máximo 5000 leases por lote de resultados.
MAX_LEASES_PER_BATCH = 5000
# Topes de trabajo independientes del tamaño en bytes: un fichero de 64 MiB con líneas
# vacías o un servidor DHCP enorme no deben convertir el job en un consumo sin límite.
MAX_LINES = 200_000
MAX_LEASES = 100_000
MAX_LINE_CHARS = 8192
HOSTNAME_MAX_CHARS = 255
# Hexadecimales del resumen sha256 de un client_id opaco: suficiente para correlacionar el
# mismo cliente entre importaciones sin publicar el identificador original.
CLIENT_ID_HASH_CHARS = 16
# Kea usa 0xFFFFFFFF como valid_lifetime "infinito".
KEA_INFINITE_LIFETIME = 0xFFFFFFFF


class DhcpFormatError(ValueError):
    """El fichero no tiene la forma del formato declarado (cabecera ausente, nada legible)."""


class DhcpReadError(Exception):
    """No se pudo leer el fichero; `code` es uno de los códigos de error del contrato."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Lease:
    ip: str
    mac: str
    hostname: str | None
    client_id: str | None
    starts_at: datetime | None
    ends_at: datetime | None
    state: str

    def to_json(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "client_id": self.client_id,
            "starts_at": _iso(self.starts_at),
            "ends_at": _iso(self.ends_at),
            "state": self.state,
        }


@dataclass
class ParseResult:
    """Leases únicos por IP (la última aparición gana) y contadores para el resumen.

    `lines` cuenta los registros examinados (líneas de datos, filas CSV sin la cabecera o
    bloques/sentencias de dhcpd.leases); `skipped`, los mal formados. Las apariciones
    repetidas de una IP no cuentan como `skipped`: son historial normal de ISC y Kea.
    """

    leases: list[Lease] = field(default_factory=list)
    lines: int = 0
    skipped: int = 0
    truncated: bool = False

    @property
    def parsed(self) -> int:
        return len(self.leases)


def _iso(value: datetime | None) -> str | None:
    return None if value is None else value.astimezone(UTC).isoformat()


# --- normalización ------------------------------------------------------------------------

_MAC_SEPARATED = re.compile(r"[0-9a-f]{2}([:-])[0-9a-f]{2}(?:\1[0-9a-f]{2}){4}")
_MAC_DOTTED = re.compile(r"[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}")
_MAC_BARE = re.compile(r"[0-9a-f]{12}")


def normalize_mac(value: str | None) -> str | None:
    """MAC Ethernet como aa:bb:cc:dd:ee:ff, o None si no es una MAC de cliente válida.

    Se rechazan la MAC nula, la de difusión y las multicast (bit 0 del primer octeto): un
    cliente DHCP real nunca las tiene, y aceptarlas uniría identidades distintas.
    """
    if value is None:
        return None
    raw = value.strip().lower()
    if not (
        _MAC_SEPARATED.fullmatch(raw) or _MAC_DOTTED.fullmatch(raw) or _MAC_BARE.fullmatch(raw)
    ):
        return None
    digits = re.sub(r"[^0-9a-f]", "", raw)
    octets = bytes.fromhex(digits)
    if octets == b"\x00" * 6 or octets[0] & 0x01:
        return None
    return ":".join(f"{b:02x}" for b in octets)


def normalize_ip(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if address.is_unspecified or address.is_multicast or address.is_loopback:
        return None
    return str(address)


def sanitize_hostname(value: str | None) -> str | None:
    """Quita caracteres de control y de formato, recorta a 255 y trata '*' o vacío como None.

    El hostname lo elige el propio cliente DHCP: puede traer secuencias de escape de terminal
    o caracteres invisibles pensados para engañar a quien lo lea en la consola.
    """
    if value is None:
        return None
    cleaned = "".join(ch for ch in value if unicodedata.category(ch) not in ("Cc", "Cf"))
    cleaned = cleaned.strip()[:HOSTNAME_MAX_CHARS].strip()
    if cleaned in ("", "*"):
        return None
    return cleaned


def client_id_value(raw: bytes | None, mac: str) -> str | None:
    """client_id para el servidor: None si es la MAC con tipo 01; si no, un sha256 corto.

    El client_id puede ser un DUID u otro identificador estable del equipo: se envía como
    huella (`sha256:<16 hex>`) para poder correlacionar sin exponer el valor original.
    """
    if not raw:
        return None
    if raw == b"\x01" + bytes.fromhex(mac.replace(":", "")):
        return None
    return "sha256:" + hashlib.sha256(raw).hexdigest()[:CLIENT_ID_HASH_CHARS]


_HEX_ID = re.compile(r"[0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2})+")


def parse_hex_id(value: str | None) -> bytes | None:
    """client_id escrito como octetos hex separados por ':' (dnsmasq, Kea, ISC sin comillas).

    Si no tiene esa forma se toma el texto tal cual como identificador opaco.
    """
    if value is None:
        return None
    text = value.strip()
    if text in ("", "*"):
        return None
    if _HEX_ID.fullmatch(text):
        return bytes(int(part, 16) for part in text.split(":"))
    return text.encode("utf-8", errors="replace")


def _from_epoch(value: str) -> datetime | None:
    """Epoch en segundos; ValueError si no es un entero razonable (fila mal formada)."""
    seconds = int(value.strip())
    if seconds < 0:
        raise ValueError("negative epoch")
    try:
        return datetime.fromtimestamp(seconds, UTC)
    except (OverflowError, OSError) as exc:
        raise ValueError("epoch out of range") from exc


def _from_iso(value: str) -> datetime:
    """ISO 8601. Sin zona horaria se interpreta como hora local del host del sensor, que es
    donde corre (o desde donde se exporta) el servidor DHCP que escribió el fichero."""
    parsed = datetime.fromisoformat(value.strip())
    if parsed.tzinfo is None:
        parsed = parsed.astimezone()
    return parsed.astimezone(UTC)


def state_by_time(ends_at: datetime | None, now: datetime) -> str:
    return STATE_ACTIVE if ends_at is None or ends_at > now else STATE_EXPIRED


def decode_text(data: bytes) -> str:
    """Bytes del fichero a texto. Export-Csv de Windows puede escribir UTF-16 con BOM."""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    return data.decode("utf-8-sig", errors="replace")


class _Accumulator:
    """Leases únicos por IP con los topes del job; la última aparición de una IP gana."""

    def __init__(self) -> None:
        self.result = ParseResult()
        self._by_ip: dict[str, Lease] = {}

    def record(self) -> None:
        self.result.lines += 1

    def skip(self) -> None:
        self.result.skipped += 1

    def add(self, lease: Lease) -> None:
        if lease.ip not in self._by_ip and len(self._by_ip) >= MAX_LEASES:
            self.result.truncated = True
            return
        # pop + asignación: la IP queda en la posición de su última aparición.
        self._by_ip.pop(lease.ip, None)
        self._by_ip[lease.ip] = lease

    def finish(self, truncated: bool) -> ParseResult:
        self.result.leases = list(self._by_ip.values())
        self.result.truncated = self.result.truncated or truncated
        return self.result


def _limited_lines(text: str) -> tuple[list[str], bool]:
    lines = text.splitlines()
    if len(lines) > MAX_LINES:
        return lines[:MAX_LINES], True
    return lines, False


def _make_lease(
    ip: str | None,
    mac: str | None,
    hostname: str | None,
    client_id: bytes | None,
    starts_at: datetime | None,
    ends_at: datetime | None,
    state: str,
) -> Lease | None:
    norm_ip, norm_mac = normalize_ip(ip), normalize_mac(mac)
    if norm_ip is None or norm_mac is None:
        return None
    return Lease(
        ip=norm_ip,
        mac=norm_mac,
        hostname=sanitize_hostname(hostname),
        client_id=client_id_value(client_id, norm_mac),
        starts_at=starts_at,
        ends_at=ends_at,
        state=state,
    )


# --- dnsmasq ------------------------------------------------------------------------------


def parse_dnsmasq(text: str, now: datetime) -> ParseResult:
    """`<expiry epoch> <mac> <ip> <hostname> <client_id>`; expiry 0 = lease infinito.

    La línea `duid ...` (DUID del servidor para DHCPv6) no es un lease y se ignora. Los
    leases DHCPv6 (IAID en lugar de MAC) no tienen MAC y cuentan como `skipped`.
    """
    lines, truncated = _limited_lines(text)
    acc = _Accumulator()
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("duid "):
            continue
        acc.record()
        parts = stripped.split()
        if len(stripped) > MAX_LINE_CHARS or not 4 <= len(parts) <= 5:
            acc.skip()
            continue
        try:
            expiry = int(parts[0])
            ends_at = None if expiry == 0 else _from_epoch(parts[0])
        except ValueError:
            acc.skip()
            continue
        lease = _make_lease(
            parts[2],
            parts[1],
            parts[3],
            parse_hex_id(parts[4]) if len(parts) == 5 else None,
            None,
            ends_at,
            state_by_time(ends_at, now),
        )
        if lease is None:
            acc.skip()
        else:
            acc.add(lease)
    return acc.finish(truncated)


# --- ISC dhcpd.leases ---------------------------------------------------------------------

_ISC_TOKEN = re.compile(r'\s+|#[^\n]*|"(?:[^"\\\n]|\\.)*"|[{};]|[^\s{};"#]+|.', re.S)
# Sentencias y bloques de nivel superior que dhcpd escribe y que no son leases.
_ISC_TOP_LEVEL = frozenset(
    {
        "authoring-byte-order",
        "server-duid",
        "db-time-format",
        "failover",
        "host",
        "class",
        "subclass",
        "group",
        "lease6",
        "ia-na",
        "ia-ta",
        "ia-pd",
    }
)
_ISC_STATES = {
    "active": None,  # según la hora de fin
    "bootp": None,
    "free": STATE_EXPIRED,
    "expired": STATE_EXPIRED,
    "reset": STATE_EXPIRED,
    "released": STATE_RELEASED,
}


@dataclass(frozen=True)
class _Token:
    text: str
    quoted: bool = False

    def is_(self, symbol: str) -> bool:
        return not self.quoted and self.text == symbol


def _isc_tokens(text: str) -> list[_Token]:
    tokens: list[_Token] = []
    for match in _ISC_TOKEN.finditer(text):
        value = match.group(0)
        if value.isspace() or value.startswith("#"):
            continue
        if value.startswith('"') and len(value) >= 2 and value.endswith('"'):
            tokens.append(_Token(value[1:-1], quoted=True))
        else:
            tokens.append(_Token(value))
    return tokens


_ESCAPES = {"n": 0x0A, "r": 0x0D, "t": 0x09, '"': 0x22, "\\": 0x5C}


def _isc_unescape(value: str) -> bytes:
    """Cadena entre comillas de dhcpd: escapes octales (\\001) y los habituales de C."""
    out = bytearray()
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\" and index + 1 < len(value):
            nxt = value[index + 1]
            octal = re.match(r"[0-7]{1,3}", value[index + 1 : index + 4])
            if octal:
                out.append(int(octal.group(0), 8) & 0xFF)
                index += 1 + len(octal.group(0))
                continue
            hexa = re.match(r"x([0-9a-fA-F]{1,2})", value[index + 1 : index + 4])
            if hexa:
                out.append(int(hexa.group(1), 16))
                index += 1 + len(hexa.group(0))
                continue
            out.append(_ESCAPES.get(nxt, ord(nxt) & 0xFF if ord(nxt) < 256 else 0x3F))
            index += 2
            continue
        out.extend(char.encode("utf-8", errors="replace"))
        index += 1
    return bytes(out)


def _isc_time(words: list[_Token]) -> datetime | None:
    """`<día> YYYY/MM/DD HH:MM:SS` (UTC), `never` o `epoch <n>`. ValueError si no encaja."""
    texts = [w.text for w in words]
    if texts == ["never"]:
        return None
    if len(texts) == 2 and texts[0] == "epoch":
        return _from_epoch(texts[1])
    if len(texts) == 3 and texts[0].isdigit():
        parsed = datetime.strptime(f"{texts[1]} {texts[2]}", "%Y/%m/%d %H:%M:%S")
        return parsed.replace(tzinfo=UTC)
    raise ValueError("unrecognised dhcpd time")


def _isc_lease(ip: str, body: list[list[_Token]], now: datetime) -> Lease | None:
    starts_at: datetime | None = None
    ends_at: datetime | None = None
    binding: str | None = None
    mac: str | None = None
    uid: bytes | None = None
    hostname: str | None = None
    for statement in body:
        keyword = statement[0].text if not statement[0].quoted else ""
        args = statement[1:]
        if keyword in ("starts", "ends"):
            try:
                value = _isc_time(args)
            except ValueError:
                return None
            if keyword == "starts":
                starts_at = value
            else:
                ends_at = value
        elif keyword == "binding" and len(args) == 2 and args[0].is_("state"):
            binding = args[1].text
        elif keyword == "hardware" and len(args) == 2 and args[0].is_("ethernet"):
            mac = args[1].text
        elif keyword == "uid" and len(args) == 1:
            uid = _isc_unescape(args[0].text) if args[0].quoted else parse_hex_id(args[0].text)
        elif keyword == "client-hostname" and len(args) == 1 and args[0].quoted:
            hostname = _isc_unescape(args[0].text).decode("utf-8", errors="replace")
    if binding is None or binding in ("active", "bootp"):
        state = state_by_time(ends_at, now)
    else:
        state = _ISC_STATES.get(binding) or STATE_UNKNOWN
    return _make_lease(ip, mac, hostname, uid, starts_at, ends_at, state)


def parse_isc_dhcpd(text: str, now: datetime) -> ParseResult:
    """dhcpd.leases: bloques `lease <ip> { ... }`; la última aparición de una IP gana.

    dhcpd añade un bloque nuevo cada vez que cambia un lease y reescribe el fichero de vez
    en cuando, así que las apariciones antiguas de una IP son historial, no errores.
    Sentencias de nivel superior desconocidas y bloques sin cerrar cuentan como `skipped`:
    así un fichero de otro formato no pasa por un dhcpd.leases vacío.
    """
    lines, truncated = _limited_lines(text)
    tokens = _isc_tokens("\n".join(lines))
    acc = _Accumulator()
    index, total = 0, len(tokens)
    while index < total:
        header: list[_Token] = []
        while index < total and not any(tokens[index].is_(s) for s in "{};"):
            header.append(tokens[index])
            index += 1
        if index >= total:
            if header:  # sentencia sin terminar al final del fichero
                acc.record()
                acc.skip()
            break
        delimiter = tokens[index]
        index += 1
        if delimiter.is_(";"):
            if header and header[0].text not in _ISC_TOP_LEVEL:
                acc.record()
                acc.skip()
            continue
        if delimiter.is_("}"):
            acc.record()
            acc.skip()
            continue
        # Bloque `{`: se recogen las sentencias de primer nivel; lo anidado se ignora.
        body: list[list[_Token]] = []
        statement: list[_Token] = []
        depth = 1
        while index < total and depth > 0:
            token = tokens[index]
            index += 1
            if token.is_("{"):
                depth += 1
                statement = []
            elif token.is_("}"):
                depth -= 1
                statement = []
            elif token.is_(";"):
                if depth == 1 and statement:
                    body.append(statement)
                statement = []
            elif depth == 1:
                statement.append(token)
        is_lease = len(header) == 2 and header[0].is_("lease") and not header[1].quoted
        if not is_lease:
            if not header or header[0].text not in _ISC_TOP_LEVEL or depth > 0:
                acc.record()
                acc.skip()
            continue
        acc.record()
        lease = _isc_lease(header[1].text, body, now) if depth == 0 else None
        if lease is None:
            acc.skip()
        else:
            acc.add(lease)
    return acc.finish(truncated)


# --- CSV (Kea, Windows, genérico) ---------------------------------------------------------


def _csv_rows(text: str) -> tuple[list[str] | None, Iterable[list[str] | None], bool]:
    """(cabecera en minúsculas, filas, truncado). Una fila ilegible llega como None.

    Cada línea se parsea por separado: ninguno de estos formatos usa campos multilínea, y
    así una comilla sin cerrar estropea solo su línea y no el resto del fichero.
    """
    lines, truncated = _limited_lines(text)
    header: list[str] | None = None
    rows: list[list[str] | None] = []
    for line in lines:
        if not line.strip():
            continue
        if header is None:
            # Export-Csv de Windows PowerShell 5.1 antepone "#TYPE ..." si no se usa
            # -NoTypeInformation; Kea no escribe comentarios.
            if line.startswith("#"):
                continue
            header = [h.strip().lower() for h in _csv_line(line) or []]
            continue
        rows.append(None if len(line) > MAX_LINE_CHARS else _csv_line(line))
    return header, rows, truncated


def _csv_line(line: str) -> list[str] | None:
    try:
        return next(csv.reader([line], strict=True))
    except (csv.Error, StopIteration):
        return None


def _columns(header: list[str] | None, required: Iterable[str]) -> dict[str, int]:
    if header is None:
        raise DhcpFormatError("missing CSV header")
    index = {name: position for position, name in enumerate(header)}
    missing = [name for name in required if name not in index]
    if missing:
        raise DhcpFormatError(f"CSV header lacks {missing}")
    return index


def _cell(row: list[str], index: dict[str, int], name: str) -> str | None:
    # Una fila con menos columnas que la cabecera no se descarta entera: las columnas que
    # faltan valen None y solo es mal formada si falta una obligatoria (IP, MAC, tiempos).
    position = index.get(name)
    if position is None or position >= len(row):
        return None
    return row[position].strip()


def _kea_hostname(value: str | None) -> str | None:
    if value is None:
        return None
    # Kea escapa las comas de los valores como "&#x2c" para no romper su CSV sin comillas.
    return value.replace("&#x2c", ",").rstrip(".")


def parse_kea_csv(text: str, now: datetime) -> ParseResult:
    """Kea memfile lease4. Es un fichero de solo-añadir: la última fila de una IP gana.

    `state`: 0 = asignado (activo o caducado según `expire`), 1 = declinado (unknown),
    2 = caducado y recuperado (expired). `valid_lifetime` 0xFFFFFFFF = infinito.
    """
    header, rows, truncated = _csv_rows(text)
    index = _columns(header, ("address", "hwaddr", "valid_lifetime", "expire"))
    acc = _Accumulator()
    for row in rows:
        acc.record()
        if row is None:
            acc.skip()
            continue
        try:
            lifetime = int(_cell(row, index, "valid_lifetime") or "")
            expire = int(_cell(row, index, "expire") or "")
            if lifetime < 0 or expire < 0:
                raise ValueError("negative lease times")
            if lifetime == KEA_INFINITE_LIFETIME:
                starts_at, ends_at = None, None
            else:
                ends_at = _from_epoch(str(expire))
                starts_at = _from_epoch(str(expire - lifetime)) if expire >= lifetime else None
        except ValueError:
            acc.skip()
            continue
        raw_state = _cell(row, index, "state")
        if raw_state in (None, "", "0"):
            state = state_by_time(ends_at, now)
        elif raw_state == "2":
            state = STATE_EXPIRED
        else:
            state = STATE_UNKNOWN
        lease = _make_lease(
            _cell(row, index, "address"),
            _cell(row, index, "hwaddr"),
            _kea_hostname(_cell(row, index, "hostname")),
            parse_hex_id(_cell(row, index, "client_id")),
            starts_at,
            ends_at,
            state,
        )
        if lease is None:
            acc.skip()
        else:
            acc.add(lease)
    return acc.finish(truncated)


_WINDOWS_STATES = {
    "active": STATE_ACTIVE,
    "activereservation": STATE_ACTIVE,
    "expired": STATE_EXPIRED,
    # Reserva sin cliente o concesión liberada: igual que el parser del servidor
    # (backend/app/dhcp/parsers.py). Nunca debe dar nombre a un activo.
    "inactive": STATE_RELEASED,
    "inactivereservation": STATE_RELEASED,
    "declined": STATE_UNKNOWN,
}


def _windows_time(value: str | None) -> datetime | None:
    """LeaseExpiryTime: ISO 8601 (recomendado en la exportación) o el formato en-US por
    defecto de PowerShell (M/d/yyyy h:mm:ss AM/PM, hora local). Cualquier otro formato
    regional es ambiguo (¿10/11 es octubre o noviembre?) y se deja en None antes que
    adivinar mal."""
    if not value:
        return None
    try:
        return _from_iso(value)
    except ValueError:
        pass
    try:
        parsed = datetime.strptime(value.strip(), "%m/%d/%Y %I:%M:%S %p")
    except ValueError:
        return None
    return parsed.astimezone().astimezone(UTC)


def parse_windows_dhcp_csv(text: str, now: datetime) -> ParseResult:
    """`Get-DhcpServerv4Lease | Export-Csv`: IPAddress, ClientId (MAC con guiones), HostName,
    AddressState y LeaseExpiryTime. El ClientId de un cliente Ethernet ES su MAC, por eso
    aquí `client_id` siempre sale None."""
    header, rows, truncated = _csv_rows(text)
    index = _columns(header, ("ipaddress", "clientid"))
    acc = _Accumulator()
    for row in rows:
        acc.record()
        if row is None:
            acc.skip()
            continue
        ends_at = _windows_time(_cell(row, index, "leaseexpirytime"))
        raw_state = (_cell(row, index, "addressstate") or "").lower()
        state = _WINDOWS_STATES.get(raw_state, STATE_UNKNOWN)
        if raw_state == "active":
            state = state_by_time(ends_at, now)
        hostname = _cell(row, index, "hostname")
        lease = _make_lease(
            _cell(row, index, "ipaddress"),
            _cell(row, index, "clientid"),
            hostname.rstrip(".") if hostname else None,
            None,
            None,
            ends_at,
            state,
        )
        if lease is None:
            acc.skip()
        else:
            acc.add(lease)
    return acc.finish(truncated)


def parse_generic_csv(text: str, now: datetime) -> ParseResult:
    """CSV propio con cabecera `ip,mac,hostname[,expires]`. `expires` vacío = sin fin; si
    no, epoch en segundos o ISO 8601 (sin zona = hora local)."""
    header, rows, truncated = _csv_rows(text)
    index = _columns(header, ("ip", "mac", "hostname"))
    acc = _Accumulator()
    for row in rows:
        acc.record()
        if row is None or len(row) < 3:
            acc.skip()
            continue
        expires = _cell(row, index, "expires")
        try:
            if not expires:
                ends_at = None
            elif expires.isdigit():
                ends_at = _from_epoch(expires)
            else:
                ends_at = _from_iso(expires)
        except ValueError:
            acc.skip()
            continue
        lease = _make_lease(
            _cell(row, index, "ip"),
            _cell(row, index, "mac"),
            _cell(row, index, "hostname"),
            None,
            None,
            ends_at,
            state_by_time(ends_at, now),
        )
        if lease is None:
            acc.skip()
        else:
            acc.add(lease)
    return acc.finish(truncated)


PARSERS: dict[str, Callable[[str, datetime], ParseResult]] = {
    "dnsmasq": parse_dnsmasq,
    "isc_dhcpd": parse_isc_dhcpd,
    "kea_csv": parse_kea_csv,
    "windows_dhcp_csv": parse_windows_dhcp_csv,
    "generic_csv": parse_generic_csv,
}
assert set(PARSERS) == set(DHCP_FORMATS)  # noqa: S101  (catálogo y config sincronizados)


def parse_leases(fmt: str, text: str, now: datetime) -> ParseResult:
    """Parsea con el formato declarado. DhcpFormatError si el fichero no tiene esa forma:
    sin cabecera válida, o con registros pero ninguno legible (formato equivocado)."""
    parser = PARSERS.get(fmt)
    if parser is None:
        raise DhcpFormatError(f"unknown format {fmt}")
    result = parser(text, now)
    if result.lines > 0 and result.parsed == 0 and result.skipped == result.lines:
        raise DhcpFormatError("no record could be parsed")
    return result


# --- lectura del fichero ------------------------------------------------------------------


def _open_flags() -> int:
    # O_NONBLOCK: abrir una FIFO para leer no se queda esperando a un escritor (el tipo se
    # comprueba justo después con fstat). En un fichero regular no cambia nada.
    return os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)


def read_lease_file(path: Path, max_bytes: int) -> tuple[bytes, datetime | None]:
    """Contenido (≤ max_bytes) y mtime del fichero. DhcpReadError con el código del contrato."""
    try:
        fd = os.open(path, _open_flags())
    except (FileNotFoundError, NotADirectoryError) as exc:
        raise DhcpReadError(ERROR_FILE_MISSING) from exc
    except OSError as exc:
        raise DhcpReadError(ERROR_FILE_UNREADABLE) from exc
    try:
        # El tipo se comprueba sobre el descriptor ya abierto (no hay carrera con un cambio
        # de fichero) y antes de fdopen, que rechaza directorios con su propio error.
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise DhcpReadError(ERROR_FILE_UNREADABLE)
        if info.st_size > max_bytes:
            raise DhcpReadError(ERROR_FILE_TOO_LARGE)
        with os.fdopen(fd, "rb") as handle:
            fd = -1  # el objeto fichero es ahora el dueño del descriptor
            # +1: si el fichero creció tras el fstat se detecta sin leerlo entero.
            data = handle.read(max_bytes + 1)
    except OSError as exc:
        raise DhcpReadError(ERROR_FILE_UNREADABLE) from exc
    finally:
        if fd >= 0:
            os.close(fd)
    if len(data) > max_bytes:
        raise DhcpReadError(ERROR_FILE_TOO_LARGE)
    return data, datetime.fromtimestamp(info.st_mtime, UTC)


def describe_sources(config: LocalConfig) -> list[dict[str, Any]]:
    """Estado de cada fuente para status/diagnostics: nunca lee ni muestra el contenido."""
    described: list[dict[str, Any]] = []
    max_bytes = config.dhcp_max_file_kb * 1024
    for source in config.dhcp_lease_files:
        entry: dict[str, Any] = {
            "name": source.name,
            "format": source.format,
            "path": str(source.path),
            "exists": False,
            "readable": False,
            "size_bytes": None,
            "too_large": False,
        }
        try:
            info = source.path.stat()
        except OSError:
            described.append(entry)
            continue
        entry["exists"] = True
        if stat.S_ISREG(info.st_mode):
            entry["size_bytes"] = info.st_size
            entry["too_large"] = info.st_size > max_bytes
            try:
                # Abrir y cerrar sin leer: os.access no refleja las ACL de Windows.
                os.close(os.open(source.path, _open_flags()))
            except OSError:
                pass
            else:
                entry["readable"] = True
        described.append(entry)
    return described


# --- job ----------------------------------------------------------------------------------


@dataclass
class DhcpReport:
    outcome: str
    summary: dict[str, Any]
    errors: list[str]
    leases: int


class DhcpCollector:
    """Ejecuta un job `dhcp_leases`: busca la fuente por nombre, lee, parsea y emite lotes.

    Misma interfaz que Scanner/SnmpCollector (`run`, `request_cancel`) para que el runner la
    trate igual: cancelable desde el servidor entre lotes y sin hilos propios.
    """

    def __init__(
        self,
        source_name: str,
        config: LocalConfig,
        emit: Callable[[list[dict[str, Any]]], None],
        clock: Callable[[], float] = time.time,
        batch_size: int = MAX_LEASES_PER_BATCH,
    ) -> None:
        self._source_name = source_name
        self._config = config
        self._emit = emit
        self._clock = clock
        self._batch_size = max(1, min(batch_size, MAX_LEASES_PER_BATCH))
        self._cancel = threading.Event()

    def request_cancel(self) -> None:
        self._cancel.set()

    def _summary(
        self,
        fmt: str | None,
        result: ParseResult | None = None,
        mtime: datetime | None = None,
        error_code: str | None = None,
    ) -> dict[str, Any]:
        return {
            "format": fmt,
            "lines": result.lines if result else 0,
            "parsed": result.parsed if result else 0,
            "skipped": result.skipped if result else 0,
            "truncated": result.truncated if result else False,
            "file_mtime": _iso(mtime),
            "error_code": error_code,
        }

    def _failed(self, fmt: str | None, code: str, mtime: datetime | None = None) -> DhcpReport:
        return DhcpReport("failed", self._summary(fmt, None, mtime, code), [code], 0)

    def run(self) -> DhcpReport:
        source = self._config.dhcp_source(self._source_name)
        if source is None:
            return self._failed(None, ERROR_SOURCE_UNKNOWN)
        fmt = source.format
        if self._cancel.is_set():
            return DhcpReport("cancelled", self._summary(fmt), [], 0)
        try:
            data, mtime = read_lease_file(source.path, self._config.dhcp_max_file_kb * 1024)
        except DhcpReadError as exc:
            return self._failed(fmt, exc.code)
        now = datetime.fromtimestamp(self._clock(), UTC)
        try:
            result = parse_leases(fmt, decode_text(data), now)
        except DhcpFormatError:
            return self._failed(fmt, ERROR_FORMAT_INVALID, mtime)
        sent = 0
        for start in range(0, result.parsed, self._batch_size):
            if self._cancel.is_set():
                return DhcpReport("cancelled", self._summary(fmt, result, mtime), [], sent)
            chunk = result.leases[start : start + self._batch_size]
            self._emit([lease.to_json() for lease in chunk])
            sent += len(chunk)
        return DhcpReport("completed", self._summary(fmt, result, mtime), [], sent)
