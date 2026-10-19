"""Contrato sensor ↔ servidor de los jobs snmp_inventory (Fase 6B).

Lo que envía el sensor es evidencia NORMALIZADA (texto saneado, MAC e IP canónicas, subtipos
y estados como enteros de la MIB, bitmaps decodificados a nombres del catálogo) y se valida
aquí con límites estrictos: un sensor autenticado sigue siendo una fuente no confiable. La
interpretación (tipo de puerto, interfaz resuelta, VLAN, clasificación) la hace el servidor.

Cada registro tiene un `kind` del catálogo cerrado; un tipo desconocido o un campo extra
rechaza el lote entero (422), igual que una observación de discovery fuera de alcance.
"""

import ipaddress
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import Field, field_validator

from app.discovery.probes import normalize_mac
from app.network.catalog import CDP_CAPABILITIES, LLDP_CAPABILITIES
from app.schemas.common import RequestModel, ResponseModel

_INDEX = Field(ge=1, le=2**31 - 1)
_COUNTER = Field(default=None, ge=0, le=2**64 - 1)
_OID = r"^[0-2](\.\d{1,10}){1,127}$"
# Texto ya saneado por el sensor: sin caracteres de control (se muestra en la UI e informes).
_PRINTABLE = r"^[^\x00-\x1f\x7f]*$"


def _text(limit: int) -> Any:
    return Field(default=None, max_length=limit, pattern=_PRINTABLE)


def _strict_mac(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = normalize_mac(value)
    if normalized is None:
        raise ValueError("invalid or non-unicast MAC address")
    return normalized


def _lenient_mac(value: str | None) -> str | None:
    # ifPhysAddress de loopbacks, túneles o VLANs suele ser vacío o 00:00:...: no es un error
    # del equipo ni del sensor, simplemente no hay MAC útil.
    return normalize_mac(value) if value else None


def _capabilities(value: list[str], allowed: frozenset[str]) -> list[str]:
    unknown = set(value) - allowed
    if unknown:
        raise ValueError("unknown capability name")
    return sorted(set(value))


class SystemRecord(RequestModel):
    kind: Literal["system"]
    sys_descr: str | None = _text(1024)
    sys_object_id: str | None = Field(default=None, max_length=255, pattern=_OID)
    sys_name: str | None = _text(255)
    sys_location: str | None = _text(255)
    sys_uptime_ticks: int | None = Field(default=None, ge=0, le=2**32 - 1)
    sys_services: int | None = Field(default=None, ge=0, le=127)
    # IP-MIB ipForwarding: 1 = forwarding (router), 2 = notForwarding.
    ip_forwarding: Literal[1, 2] | None = None


class EntityRecord(RequestModel):
    kind: Literal["entity"]
    index: int = _INDEX
    # PhysicalClass: 3 = chassis, 11 = stack (el sensor solo envía esos dos).
    phys_class: int = Field(ge=1, le=12)
    descr: str | None = _text(255)
    name: str | None = _text(255)
    hardware_rev: str | None = _text(128)
    firmware_rev: str | None = _text(128)
    software_rev: str | None = _text(128)
    serial: str | None = _text(128)
    mfg_name: str | None = _text(128)
    model_name: str | None = _text(128)


class InterfaceRecord(RequestModel):
    kind: Literal["interface"]
    if_index: int = _INDEX
    descr: str | None = _text(255)
    name: str | None = _text(255)
    alias: str | None = _text(255)
    if_type: int | None = Field(default=None, ge=1, le=65535)
    mtu: int | None = Field(default=None, ge=0, le=2**31 - 1)
    # ifSpeed (bps, satura en 4294967295) e ifHighSpeed (Mbps): el servidor elige.
    speed: int | None = Field(default=None, ge=0, le=2**32 - 1)
    high_speed: int | None = Field(default=None, ge=0, le=2**32 - 1)
    mac: str | None = Field(default=None, max_length=17)
    admin_status: int | None = Field(default=None, ge=1, le=3)
    oper_status: int | None = Field(default=None, ge=1, le=7)
    in_octets: int | None = _COUNTER
    out_octets: int | None = _COUNTER
    counters_hc: bool = False
    in_errors: int | None = _COUNTER
    out_errors: int | None = _COUNTER
    in_discards: int | None = _COUNTER
    out_discards: int | None = _COUNTER

    @field_validator("mac")
    @classmethod
    def _mac(cls, value: str | None) -> str | None:
        return _lenient_mac(value)


class IfStackRecord(RequestModel):
    """ifStackTable: `higher` está apilada sobre `lower` (p. ej. un LAG sobre sus miembros)."""

    kind: Literal["if_stack"]
    higher: int = _INDEX
    lower: int = _INDEX


class LldpLocalRecord(RequestModel):
    kind: Literal["lldp_local"]
    chassis_id_subtype: int | None = Field(default=None, ge=1, le=7)
    chassis_id: str | None = _text(255)
    sys_name: str | None = _text(255)
    capabilities: list[str] = Field(default_factory=list, max_length=16)

    @field_validator("capabilities")
    @classmethod
    def _caps(cls, value: list[str]) -> list[str]:
        return _capabilities(value, LLDP_CAPABILITIES)


class LldpLocalPortRecord(RequestModel):
    kind: Literal["lldp_local_port"]
    port_num: int = _INDEX
    port_id_subtype: int | None = Field(default=None, ge=1, le=7)
    port_id: str | None = _text(255)
    port_desc: str | None = _text(255)


class LldpRemoteRecord(RequestModel):
    kind: Literal["lldp_remote"]
    local_port_num: int = _INDEX
    rem_index: int = _INDEX
    chassis_id_subtype: int | None = Field(default=None, ge=1, le=7)
    chassis_id: str | None = _text(255)
    port_id_subtype: int | None = Field(default=None, ge=1, le=7)
    port_id: str | None = _text(255)
    port_desc: str | None = _text(255)
    sys_name: str | None = _text(255)
    sys_desc: str | None = _text(1024)
    capabilities: list[str] = Field(default_factory=list, max_length=16)
    mgmt_addresses: list[str] = Field(default_factory=list, max_length=4)

    @field_validator("capabilities")
    @classmethod
    def _caps(cls, value: list[str]) -> list[str]:
        return _capabilities(value, LLDP_CAPABILITIES)

    @field_validator("mgmt_addresses")
    @classmethod
    def _addresses(cls, value: list[str]) -> list[str]:
        return [str(ipaddress.ip_address(item)) for item in value]


class CdpNeighborRecord(RequestModel):
    kind: Literal["cdp_neighbor"]
    if_index: int = _INDEX
    device_index: int = _INDEX
    device_id: str | None = _text(255)
    device_port: str | None = _text(255)
    platform: str | None = _text(255)
    software: str | None = _text(512)
    address: str | None = Field(default=None, max_length=45)
    capabilities: list[str] = Field(default_factory=list, max_length=16)
    native_vlan: int | None = Field(default=None, ge=1, le=4094)

    @field_validator("capabilities")
    @classmethod
    def _caps(cls, value: list[str]) -> list[str]:
        return _capabilities(value, CDP_CAPABILITIES)

    @field_validator("address")
    @classmethod
    def _address(cls, value: str | None) -> str | None:
        return None if value is None else str(ipaddress.ip_address(value))


class BridgeBaseRecord(RequestModel):
    kind: Literal["bridge_base"]
    bridge_address: str | None = Field(default=None, max_length=17)
    num_ports: int | None = Field(default=None, ge=0, le=65535)

    @field_validator("bridge_address")
    @classmethod
    def _mac(cls, value: str | None) -> str | None:
        return _lenient_mac(value)


class BridgePortRecord(RequestModel):
    """dot1dBasePortIfIndex: puerto de bridge → ifIndex (necesario para ubicar una MAC)."""

    kind: Literal["bridge_port"]
    port: int = Field(ge=1, le=65535)
    if_index: int = _INDEX


class MacEntryRecord(RequestModel):
    kind: Literal["mac_entry"]
    mac: str = Field(max_length=17)
    # 0 = el equipo no informa puerto (p. ej. dirección propia).
    port: int = Field(ge=0, le=65535)
    # Q-BRIDGE dot1qFdbId; 0 en BRIDGE-MIB (tabla sin VLAN).
    fdb_id: int = Field(ge=0, le=2**31 - 1)
    # dot1dTpFdbStatus / dot1qTpFdbStatus: other(1) invalid(2) learned(3) self(4) mgmt(5).
    status: int = Field(ge=1, le=5)
    source: Literal["dot1q", "dot1d"]

    @field_validator("mac")
    @classmethod
    def _mac(cls, value: str) -> str:
        return _strict_mac(value) or value


class VlanRecord(RequestModel):
    kind: Literal["vlan"]
    vlan_id: int = Field(ge=1, le=4094)
    name: str | None = _text(64)
    source: Literal["static", "current"]
    fdb_id: int | None = Field(default=None, ge=0, le=2**31 - 1)
    # Puertos de bridge decodificados del PortList (bitmap) por el sensor.
    egress_ports: list[Annotated[int, Field(ge=1, le=65535)]] = Field(
        default_factory=list, max_length=4096
    )
    untagged_ports: list[Annotated[int, Field(ge=1, le=65535)]] = Field(
        default_factory=list, max_length=4096
    )


class PvidRecord(RequestModel):
    kind: Literal["pvid"]
    port: int = Field(ge=1, le=65535)
    vlan_id: int = Field(ge=1, le=4094)


# --- Fase 6C.3: módulo wlan ----------------------------------------------------------------
# Lo que informa el sensor tal cual (enteros de la MIB, MAC/IP canónicas, texto saneado). El
# significado de cada valor lo decide el servidor (app/network/wlan_catalog.py).


def _ip(value: str | None) -> str | None:
    return None if value is None else str(ipaddress.ip_address(value))


class WlanSourceRecord(RequestModel):
    """Un adaptador del sensor encontró su MIB y la leyó completa o parcialmente."""

    kind: Literal["wlan_source"]
    source: Literal["ieee802dot11", "airespace", "unifi"]
    status: Literal["complete", "partial"]


class WlanDot11RadioRecord(RequestModel):
    """IEEE802dot11-MIB: una radio (ifIndex) de un AP autónomo."""

    kind: Literal["wlan_dot11_radio"]
    if_index: int = _INDEX
    station_id: str | None = Field(default=None, max_length=17)
    mac_address: str | None = Field(default=None, max_length=17)
    ssid: str | None = _text(64)
    bss_type: int | None = Field(default=None, ge=1, le=3)
    # TruthValue: 1 = true, 2 = false.
    privacy_invoked: Literal[1, 2] | None = None
    exclude_unencrypted: Literal[1, 2] | None = None
    rsna_enabled: Literal[1, 2] | None = None
    phy_type: int | None = Field(default=None, ge=1, le=255)
    dsss_channel: int | None = Field(default=None, ge=1, le=14)
    ofdm_channel: int | None = Field(default=None, ge=1, le=255)

    @field_validator("station_id", "mac_address")
    @classmethod
    def _mac(cls, value: str | None) -> str | None:
        return _lenient_mac(value)


class WlanControllerApRecord(RequestModel):
    """AIRESPACE-WIRELESS-MIB bsnAPEntry: un AP asociado a la controladora."""

    kind: Literal["wlan_controller_ap"]
    ap_mac: str = Field(max_length=17)
    name: str | None = _text(255)
    location: str | None = _text(255)
    operation_status: int | None = Field(default=None, ge=1, le=255)
    software_version: str | None = _text(128)
    model: str | None = _text(128)
    serial: str | None = _text(128)
    ip_address: str | None = Field(default=None, max_length=45)
    ethernet_mac: str | None = Field(default=None, max_length=17)

    @field_validator("ap_mac")
    @classmethod
    def _ap_mac(cls, value: str) -> str:
        return _strict_mac(value) or value

    @field_validator("ethernet_mac")
    @classmethod
    def _eth(cls, value: str | None) -> str | None:
        return _lenient_mac(value)

    @field_validator("ip_address")
    @classmethod
    def _addr(cls, value: str | None) -> str | None:
        return _ip(value)


class WlanControllerRadioRecord(RequestModel):
    """AIRESPACE-WIRELESS-MIB bsnAPIfEntry: una radio (slot) de un AP de la controladora."""

    kind: Literal["wlan_controller_radio"]
    ap_mac: str = Field(max_length=17)
    slot: int = Field(ge=0, le=255)
    radio_type: int | None = Field(default=None, ge=1, le=255)
    channel: int | None = Field(default=None, ge=1, le=255)
    oper_status: Literal[1, 2] | None = None
    clients: int | None = Field(default=None, ge=0, le=100_000)

    @field_validator("ap_mac")
    @classmethod
    def _ap_mac(cls, value: str) -> str:
        return _strict_mac(value) or value


class WlanEssRecord(RequestModel):
    """AIRESPACE-WIRELESS-MIB bsnDot11EssEntry: una WLAN configurada."""

    kind: Literal["wlan_ess"]
    ess_index: int = _INDEX
    ssid: str | None = _text(64)
    clients: int | None = Field(default=None, ge=0, le=1_000_000)


class WlanStationRecord(RequestModel):
    """AIRESPACE-WIRELESS-MIB bsnMobileStationEntry, minimizado (sin usuario ni IP)."""

    kind: Literal["wlan_station"]
    mac: str = Field(max_length=17)
    ap_mac: str | None = Field(default=None, max_length=17)
    slot: int | None = Field(default=None, ge=0, le=255)
    ess_index: int | None = Field(default=None, ge=1, le=2**31 - 1)
    ssid: str | None = _text(64)
    status: int | None = Field(default=None, ge=0, le=255)
    protocol: int | None = Field(default=None, ge=1, le=255)

    @field_validator("mac")
    @classmethod
    def _station(cls, value: str) -> str:
        return _strict_mac(value) or value

    @field_validator("ap_mac")
    @classmethod
    def _ap_mac(cls, value: str | None) -> str | None:
        return _lenient_mac(value)


class WlanUnifiSystemRecord(RequestModel):
    """UBNT-UniFi-MIB unifiApSystem: identidad del propio AP UniFi."""

    kind: Literal["wlan_unifi_system"]
    ip_address: str | None = Field(default=None, max_length=45)
    model: str | None = _text(128)
    firmware: str | None = _text(128)

    @field_validator("ip_address")
    @classmethod
    def _addr(cls, value: str | None) -> str | None:
        return _ip(value)


class WlanVapRecord(RequestModel):
    """UBNT-UniFi-MIB unifiVapEntry: un VAP (BSS) del AP."""

    kind: Literal["wlan_vap"]
    vap_index: int = _INDEX
    bssid: str | None = Field(default=None, max_length=17)
    ssid: str | None = _text(64)
    name: str | None = _text(64)
    channel: int | None = Field(default=None, ge=1, le=255)
    radio: str | None = Field(default=None, max_length=8, pattern=r"^[A-Za-z0-9]+$")
    clients: int | None = Field(default=None, ge=0, le=100_000)

    @field_validator("bssid")
    @classmethod
    def _bssid(cls, value: str | None) -> str | None:
        return _lenient_mac(value)


SnmpRecord = Annotated[
    SystemRecord
    | EntityRecord
    | InterfaceRecord
    | IfStackRecord
    | LldpLocalRecord
    | LldpLocalPortRecord
    | LldpRemoteRecord
    | CdpNeighborRecord
    | BridgeBaseRecord
    | BridgePortRecord
    | MacEntryRecord
    | VlanRecord
    | PvidRecord
    | WlanSourceRecord
    | WlanDot11RadioRecord
    | WlanControllerApRecord
    | WlanControllerRadioRecord
    | WlanEssRecord
    | WlanStationRecord
    | WlanUnifiSystemRecord
    | WlanVapRecord,
    Field(discriminator="kind"),
]

SensorModuleName = Literal[
    "system", "entity", "interfaces", "lldp", "cdp", "bridge", "vlan", "wlan"
]
SensorModuleStatus = Literal["complete", "partial", "unsupported", "failed", "skipped"]
SensorSnmpError = Literal[
    "timeout",
    "host_unreachable",
    "auth_failed",
    "unsupported_version",
    "oid_unavailable",
    "partial",
    "cancelled",
    "limit_exceeded",
    "malformed_response",
    "internal",
]


class SnmpJobSummary(RequestModel):
    """Resumen SNMP que el sensor añade al cerrar un job snmp_inventory."""

    modules: dict[SensorModuleName, SensorModuleStatus] = Field(max_length=8)
    error_code: SensorSnmpError | None = None
    requests: int = Field(default=0, ge=0, le=10_000_000)
    varbinds: int = Field(default=0, ge=0, le=100_000_000)
    truncated: bool = False


class SnmpJobCredentials(ResponseModel):
    """Secretos de UN job, solo en la respuesta de start (nunca en poll, jobs ni logs).

    El sensor los mantiene en memoria mientras dura el job y no los escribe en disco.
    """

    profile_id: UUID
    secret_revision: int
    snmp_version: Literal["v3", "v2c"]
    username: str | None = None
    auth_protocol: str | None = None
    priv_protocol: str | None = None
    auth_password: str | None = None
    priv_password: str | None = None
    community: str | None = None
