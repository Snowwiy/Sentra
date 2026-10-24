"""Parsers de ficheros de leases DHCP (Fase 6E.2).

Mismos formatos y criterios que el sensor (sensor/sentra_sensor/dhcp.py): el sensor es un
paquete aparte que solo usa la biblioteca estándar y no puede importar el servidor, así que
se replica aquí para la importación manual. Si cambia un criterio en un lado, debe cambiar en
el otro.

Reglas comunes:
- solo se extraen IP, MAC, hostname, client id, inicio, fin y estado; nada más del fichero;
- una línea o bloque mal formado se cuenta como `skipped` y nunca rompe la importación;
- el hostname se sanea (sin caracteres de control, máx. 255) y '*' o vacío es "sin nombre";
- un client id que es la propia MAC (tipo 01) no aporta nada y se descarta; uno opaco se
  guarda como huella sha256 corta para correlacionar sin conservar el valor original;
- tope de líneas: un fichero gigante se corta (truncated=true) en vez de agotar memoria.
"""

import csv
import hashlib
import io
import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.discovery.probes import normalize_mac

FORMATS = ("dnsmasq", "isc_dhcpd", "kea_csv", "windows_dhcp_csv", "generic_csv")
MAX_LINES = 200_000
MAX_HOSTNAME = 255
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


@dataclass(frozen=True)
class LeaseRecord:
    ip: str
    mac: str
    hostname: str | None = None
    client_id: str | None = None
    starts_at: datetime | None = None
    ends_at: datetime | None = None
    state: str = "unknown"


@dataclass
class ParseResult:
    leases: list[LeaseRecord] = field(default_factory=list)
    lines: int = 0
    skipped: int = 0
    truncated: bool = False

    @property
    def parsed(self) -> int:
        return len(self.leases)


class LeaseFormatError(ValueError):
    """El fichero no tiene la forma del formato declarado (cabecera CSV ausente, etc.)."""


def clean_hostname(value: str | None) -> str | None:
    if value is None:
        return None
    text = _CONTROL.sub("", value).strip().strip('"').strip()
    if not text or text == "*":
        return None
    return text[:MAX_HOSTNAME]


def clean_ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


_HEX_ID = re.compile(r"[0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2})+")


def clean_client_id(value: str | None, mac: str) -> str | None:
    """Huella `sha256:<16 hex>` de un client id opaco; None si falta o es la MAC con tipo 01.

    Mismo cálculo que el sensor (sentra_sensor/dhcp.py: parse_hex_id + client_id_value): el
    mismo equipo debe dar la misma huella tanto si el lease llega importado como por sensor.
    """
    if not value:
        return None
    text = value.strip().strip('"').strip()
    if not text or text == "*":
        return None
    if _HEX_ID.fullmatch(text):
        raw = bytes(int(part, 16) for part in text.split(":"))
    else:
        raw = text.encode("utf-8", errors="replace")
    if raw == b"\x01" + bytes.fromhex(mac.replace(":", "")):
        return None
    return "sha256:" + hashlib.sha256(raw).hexdigest()[:16]


def _epoch(value: str) -> datetime | None:
    try:
        number = int(value)
    except ValueError:
        return None
    if number <= 0:
        return None
    try:
        return datetime.fromtimestamp(number, UTC)
    except (OverflowError, OSError, ValueError):
        return None


def _iso(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip().strip('"')
    for candidate in (text, text.replace(" ", "T", 1)):
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            continue
        return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)
    for fmt in ("%m/%d/%Y %I:%M:%S %p", "%d/%m/%Y %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def _state_by_time(ends_at: datetime | None, now: datetime) -> str:
    if ends_at is None:
        return "active"
    return "active" if ends_at > now else "expired"


def _lines(text: str, result: ParseResult) -> Iterable[str]:
    for count, line in enumerate(text.splitlines(), start=1):
        if count > MAX_LINES:
            result.truncated = True
            return
        result.lines = count
        yield line


def parse_dnsmasq(text: str, now: datetime) -> ParseResult:
    """`<expiry epoch> <mac> <ip> <hostname> <client-id>` (expiry 0 = sin caducidad)."""
    result = ParseResult()
    for line in _lines(text, result):
        parts = line.split()
        if not parts or line.startswith("duid "):
            continue
        if len(parts) < 4:
            result.skipped += 1
            continue
        mac, ip = normalize_mac(parts[1]), clean_ip(parts[2])
        if mac is None or ip is None:
            result.skipped += 1
            continue
        ends = _epoch(parts[0])
        result.leases.append(
            LeaseRecord(
                ip=ip,
                mac=mac,
                hostname=clean_hostname(parts[3]),
                client_id=clean_client_id(parts[4] if len(parts) > 4 else None, mac),
                ends_at=ends,
                state=_state_by_time(ends, now),
            )
        )
    return result


_ISC_BLOCK = re.compile(r"lease\s+([0-9a-fA-F.:]+)\s*\{(.*?)\}", re.S)
_ISC_STATE = {
    "active": "active",
    # Igual que el sensor 0.6.0: en ISC "free" es una concesión que ya no está en uso.
    "free": "expired",
    "released": "released",
    "expired": "expired",
    "abandoned": "expired",
    "backup": "unknown",
}


def parse_isc_dhcpd(text: str, now: datetime) -> ParseResult:
    """dhcpd.leases: bloques `lease <ip> { ... }`; la última aparición de una IP gana."""
    result = ParseResult()
    lines = text.splitlines()
    if len(lines) > MAX_LINES:
        result.truncated = True
        text = "\n".join(lines[:MAX_LINES])
    result.lines = min(len(lines), MAX_LINES)
    latest: dict[str, LeaseRecord] = {}
    for match in _ISC_BLOCK.finditer(text):
        ip = clean_ip(match.group(1))
        body = match.group(2)
        fields: dict[str, str] = {}
        for raw in body.split(";"):
            statement = raw.strip()
            if not statement:
                continue
            if statement.startswith("hardware ethernet"):
                fields["mac"] = statement.split()[-1]
            elif statement.startswith("starts"):
                fields["starts"] = " ".join(statement.split()[2:4])
            elif statement.startswith("ends"):
                fields["ends"] = " ".join(statement.split()[2:4])
            elif statement.startswith("binding state"):
                fields["state"] = statement.split()[-1]
            elif statement.startswith("client-hostname"):
                fields["hostname"] = statement.split(None, 1)[1]
            elif statement.startswith("uid"):
                fields["uid"] = statement.split(None, 1)[1]
        mac = normalize_mac(fields.get("mac"))
        if ip is None or mac is None:
            result.skipped += 1
            continue
        ends = _iso(fields.get("ends"))
        state = _ISC_STATE.get(fields.get("state", "")) or _state_by_time(ends, now)
        if state == "active" and ends is not None and ends <= now:
            state = "expired"
        latest[ip] = LeaseRecord(
            ip=ip,
            mac=mac,
            hostname=clean_hostname(fields.get("hostname")),
            client_id=clean_client_id(fields.get("uid"), mac),
            starts_at=_iso(fields.get("starts")),
            ends_at=ends,
            state=state,
        )
    result.leases = list(latest.values())
    return result


def _csv_rows(text: str, result: ParseResult, required: set[str]) -> Iterable[dict[str, str]]:
    body = text.lstrip("﻿")
    lines = body.splitlines()
    # Export-Csv de Windows PowerShell 5 añade una línea "#TYPE ..." antes de la cabecera.
    while lines and lines[0].startswith("#"):
        lines.pop(0)
    if len(lines) > MAX_LINES:
        result.truncated = True
        lines = lines[:MAX_LINES]
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    header = {(h or "").strip().lower() for h in (reader.fieldnames or [])}
    if not required <= header:
        raise LeaseFormatError("missing CSV columns: " + ",".join(sorted(required - header)))
    for row in reader:
        result.lines += 1
        yield {(k or "").strip().lower(): (v or "").strip() for k, v in row.items() if k}


_KEA_STATE = {"0": "active", "1": "unknown", "2": "expired"}


def parse_kea_csv(text: str, now: datetime) -> ParseResult:
    result = ParseResult()
    for row in _csv_rows(text, result, {"address", "hwaddr"}):
        ip, mac = clean_ip(row.get("address")), normalize_mac(row.get("hwaddr"))
        if ip is None or mac is None:
            result.skipped += 1
            continue
        ends = _epoch(row.get("expire", ""))
        state = _KEA_STATE.get(row.get("state", "0"), "unknown")
        if state == "active" and ends is not None and ends <= now:
            state = "expired"
        lifetime = row.get("valid_lifetime", "")
        starts = None
        if ends is not None and lifetime.isdigit():
            starts = datetime.fromtimestamp(ends.timestamp() - int(lifetime), UTC)
        result.leases.append(
            LeaseRecord(
                ip=ip,
                mac=mac,
                hostname=clean_hostname(row.get("hostname", "").rstrip(".")),
                client_id=clean_client_id(row.get("client_id"), mac),
                starts_at=starts,
                ends_at=ends,
                state=state,
            )
        )
    return result


_WINDOWS_STATE = {
    "active": "active",
    "activereservation": "active",
    "inactivereservation": "released",
    "inactive": "released",
    "declined": "unknown",
    "expired": "expired",
}


def parse_windows_dhcp_csv(text: str, now: datetime) -> ParseResult:
    """`Get-DhcpServerv4Lease | Export-Csv`: IPAddress, ClientId (MAC con guiones), HostName,
    AddressState, LeaseExpiryTime."""
    result = ParseResult()
    for row in _csv_rows(text, result, {"ipaddress", "clientid"}):
        ip, mac = clean_ip(row.get("ipaddress")), normalize_mac(row.get("clientid"))
        if ip is None or mac is None:
            result.skipped += 1
            continue
        ends = _iso(row.get("leaseexpirytime"))
        state = _WINDOWS_STATE.get(row.get("addressstate", "").lower(), "unknown")
        if state == "active" and ends is not None and ends <= now:
            state = "expired"
        result.leases.append(
            LeaseRecord(
                ip=ip,
                mac=mac,
                hostname=clean_hostname(row.get("hostname")),
                ends_at=ends,
                state=state,
            )
        )
    return result


def parse_generic_csv(text: str, now: datetime) -> ParseResult:
    """Cabecera `ip,mac,hostname[,expires]` (expires en ISO 8601 o epoch)."""
    result = ParseResult()
    for row in _csv_rows(text, result, {"ip", "mac"}):
        ip, mac = clean_ip(row.get("ip")), normalize_mac(row.get("mac"))
        if ip is None or mac is None:
            result.skipped += 1
            continue
        raw = row.get("expires", "")
        ends = _epoch(raw) if raw.isdigit() else _iso(raw)
        result.leases.append(
            LeaseRecord(
                ip=ip,
                mac=mac,
                hostname=clean_hostname(row.get("hostname")),
                ends_at=ends,
                state=_state_by_time(ends, now),
            )
        )
    return result


def parse(fmt: str, text: str, now: datetime | None = None) -> ParseResult:
    now = now or datetime.now(UTC)
    parsers = {
        "dnsmasq": parse_dnsmasq,
        "isc_dhcpd": parse_isc_dhcpd,
        "kea_csv": parse_kea_csv,
        "windows_dhcp_csv": parse_windows_dhcp_csv,
        "generic_csv": parse_generic_csv,
    }
    if fmt not in parsers:
        raise LeaseFormatError(f"unknown format {fmt}")
    result = parsers[fmt](text, now)
    # Una entrada por IP y la última aparición gana, igual que el sensor 0.6.0: los ficheros
    # de leases son registros que se añaden, y la línea más reciente es la vigente.
    latest: dict[str, LeaseRecord] = {}
    for lease in result.leases:
        latest.pop(lease.ip, None)
        latest[lease.ip] = lease
    result.leases = list(latest.values())
    return result
