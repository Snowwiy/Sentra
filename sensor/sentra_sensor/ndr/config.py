"""Configuración de NDR: lo que decide el operador del host y lo que aprueba el servidor.

Doble control deliberado (Fase 7E.1):
* El operador del host declara en sensor.toml qué dispositivos de red PUEDEN observarse y les
  da un alias (`[[ndr.interfaces]] name = "lan-span", device = "eth1"`). Sin `[ndr] enabled =
  true` el sensor no declara la capacidad NDR ni abre ningún dispositivo de captura.
* El servidor (un admin, con la confirmación del punto de observación) aprueba qué alias se
  capturan y con qué límites. El servidor solo envía alias: nunca rutas, nombres de
  dispositivo, filtros BPF ni comandos. Un alias que el host no declaró se ignora.

Los límites del servidor se validan y acotan aquí igual que el resto de su configuración
(protocol.py): un proxy roto o un servidor comprometido no puede pedir 10^9 flujos en memoria.
"""

import re
from dataclasses import dataclass
from typing import Any

NDR_ALIAS_RE = re.compile(r"^[a-z0-9_-]{1,32}$")
# Nombre de dispositivo local: en Windows `\Device\NPF_{GUID}`, en Linux `eth0`, en macOS
# `en0`. Se exige texto imprimible sin separadores de ruta peligrosos fuera de ese formato.
_DEVICE_RE = re.compile(r"^[A-Za-z0-9_.:{}\\@-]{1,128}$")
BACKENDS = ("auto", "af_packet", "libpcap")
MAX_INTERFACES = 4


class NdrConfigError(ValueError):
    """La sección [ndr] de sensor.toml no es válida."""


@dataclass(frozen=True)
class NdrInterface:
    name: str
    device: str


@dataclass(frozen=True)
class NdrLocalConfig:
    enabled: bool = False
    backend: str = "auto"
    interfaces: tuple[NdrInterface, ...] = ()
    # Disco que el operador del host concede al spool de NDR (separado del de jobs: una
    # avalancha de flujos no puede desplazar los resultados de un discovery).
    spool_max_mb: int = 256
    buffer_kb: int = 4096

    def interface(self, name: str) -> NdrInterface | None:
        for item in self.interfaces:
            if item.name == name:
                return item
        return None


def parse_local_ndr(raw: object) -> NdrLocalConfig:
    if raw is None:
        return NdrLocalConfig()
    if not isinstance(raw, dict):
        raise NdrConfigError("[ndr] must be a table")
    allowed = {"enabled", "backend", "interfaces", "spool_max_mb", "buffer_kb"}
    unknown = set(raw) - allowed
    if unknown:
        raise NdrConfigError(f"[ndr] has unknown keys: {sorted(unknown)}")
    enabled = raw.get("enabled", False)
    if not isinstance(enabled, bool):
        raise NdrConfigError("ndr.enabled must be a boolean")
    backend = raw.get("backend", "auto")
    if backend not in BACKENDS:
        raise NdrConfigError(f"ndr.backend must be one of {list(BACKENDS)}")
    spool_max_mb = raw.get("spool_max_mb", 256)
    buffer_kb = raw.get("buffer_kb", 4096)
    for key, value, low, high in (
        ("spool_max_mb", spool_max_mb, 1, 10_240),
        ("buffer_kb", buffer_kb, 256, 262_144),
    ):
        if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
            raise NdrConfigError(f"ndr.{key} must be an integer between {low} and {high}")
    items = raw.get("interfaces", [])
    if not isinstance(items, list):
        raise NdrConfigError("ndr.interfaces must be an array of tables ([[ndr.interfaces]])")
    if len(items) > MAX_INTERFACES:
        raise NdrConfigError(f"at most {MAX_INTERFACES} ndr.interfaces")
    interfaces: list[NdrInterface] = []
    seen: set[str] = set()
    for index, item in enumerate(items):
        where = f"ndr.interfaces[{index}]"
        if not isinstance(item, dict) or set(item) != {"name", "device"}:
            raise NdrConfigError(f"{where} must have exactly the keys name and device")
        name, device = item["name"], item["device"]
        if not isinstance(name, str) or not NDR_ALIAS_RE.fullmatch(name):
            raise NdrConfigError(f"{where}.name must match ^[a-z0-9_-]{{1,32}}$")
        if name in seen:
            raise NdrConfigError(f"{where}.name {name!r} is duplicated")
        if not isinstance(device, str) or not _DEVICE_RE.fullmatch(device):
            raise NdrConfigError(f"{where}.device is not a valid interface name")
        seen.add(name)
        interfaces.append(NdrInterface(name, device))
    if enabled and not interfaces:
        raise NdrConfigError("ndr.enabled = true needs at least one [[ndr.interfaces]]")
    return NdrLocalConfig(enabled, backend, tuple(interfaces), spool_max_mb, buffer_kb)


def _bounded(data: dict[str, Any], key: str, low: int, high: int, default: int) -> int:
    value = data.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool):
        return default
    return max(low, min(high, value))


def _flag(data: dict[str, Any], key: str) -> bool:
    return data.get(key) is True


@dataclass(frozen=True)
class NdrServerConfig:
    """Bloque `config.ndr` del heartbeat: captura aprobada por un admin para ESTE sensor."""

    enabled: bool
    revision: int
    interfaces: tuple[str, ...]
    promiscuous: bool = False
    snaplen: int = 512
    max_flows: int = 20_000
    max_packets_per_second: int = 20_000
    max_cpu_percent: int = 40
    export_interval_seconds: int = 60
    flow_idle_timeout_seconds: int = 120
    flow_active_timeout_seconds: int = 300
    max_records_per_batch: int = 2000
    max_batch_bytes: int = 1024 * 1024
    spool_max_mb: int = 256
    spool_max_age_hours: int = 24
    arp_metadata: bool = True
    dns_metadata: bool = False
    dhcp_metadata: bool = True
    tls_metadata: bool = False

    @classmethod
    def parse(cls, raw: object) -> "NdrServerConfig | None":
        """None si el servidor no envía NDR (servidor anterior a 7E) o el bloque es inválido."""
        if not isinstance(raw, dict):
            return None
        names = raw.get("interfaces")
        revision = raw.get("revision")
        if not isinstance(names, list) or not isinstance(revision, int):
            return None
        interfaces = tuple(
            name
            for name in names[:MAX_INTERFACES]
            if isinstance(name, str) and NDR_ALIAS_RE.fullmatch(name)
        )
        return cls(
            enabled=_flag(raw, "enabled") and bool(interfaces),
            revision=max(0, revision),
            interfaces=interfaces,
            promiscuous=_flag(raw, "promiscuous"),
            snaplen=_bounded(raw, "snaplen", 96, 2048, 512),
            max_flows=_bounded(raw, "max_flows", 1000, 500_000, 20_000),
            max_packets_per_second=_bounded(raw, "max_packets_per_second", 100, 500_000, 20_000),
            max_cpu_percent=_bounded(raw, "max_cpu_percent", 5, 90, 40),
            export_interval_seconds=_bounded(raw, "export_interval_seconds", 10, 600, 60),
            flow_idle_timeout_seconds=_bounded(raw, "flow_idle_timeout_seconds", 10, 3600, 120),
            flow_active_timeout_seconds=_bounded(raw, "flow_active_timeout_seconds", 30, 7200, 300),
            max_records_per_batch=_bounded(raw, "max_records_per_batch", 50, 10_000, 2000),
            max_batch_bytes=_bounded(raw, "max_batch_bytes", 16 * 1024, 16 * 1024 * 1024, 1 << 20),
            spool_max_mb=_bounded(raw, "spool_max_mb", 1, 10_240, 256),
            spool_max_age_hours=_bounded(raw, "spool_max_age_hours", 1, 168, 24),
            arp_metadata=_flag(raw, "arp_metadata"),
            dns_metadata=_flag(raw, "dns_metadata"),
            dhcp_metadata=_flag(raw, "dhcp_metadata"),
            tls_metadata=_flag(raw, "tls_metadata"),
        )
