"""Contratos de la API de infraestructura de red (Fase 6B, docs/snmp-network-intelligence.md).

Superficie del dashboard (sesión + RBAC):
- perfiles de credenciales SNMP (solo snmp_credentials:manage). Los secretos son de solo
  escritura: entran en la creación o en la rotación y nunca vuelven a salir por la API;
- equipos de red administrables, su inventario (interfaces, vecinos LLDP/CDP, VLANs, tablas
  MAC) y el historial de consultas (lectura: monitoring:read);
- solicitar y cancelar consultas SNMP (network:poll) y registrar o editar equipos
  (network:manage).

Toda la información de inventario es evidencia observada por un sensor del site del equipo.
La API la presenta con su procedencia (fuente, sensor, hora) y nunca la convierte en una
afirmación más fuerte que la evidencia: un vecino LLDP es "informado por el equipo", no un
enlace confirmado, y un equipo sin consulta reciente no se muestra como online.
"""

import ipaddress
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import Field, SecretStr, field_validator, model_validator

from app.discovery.probes import normalize_mac
from app.schemas.common import RequestModel, ResponseModel

SnmpVersion = Literal["v3", "v2c"]
# SNMPv3 siempre authPriv: noAuthNoPriv y authNoPriv no se aceptan (sin cifrado, la
# respuesta viaja en claro y en authNoPriv el inventario queda expuesto en la red del site).
SnmpSecurityLevel = Literal["authPriv", "community"]
# MD5 y DES no se ofrecen: están rotos o son demasiado débiles para un despliegue nuevo.
SnmpAuthProtocol = Literal["sha", "sha224", "sha256", "sha384", "sha512"]
SnmpPrivProtocol = Literal["aes128", "aes192", "aes256"]
SnmpProfileStatus = Literal["active", "revoked"]

DeviceClassification = Literal[
    "managed_switch", "router", "access_point", "firewall", "unclassified"
]
ClassificationConfidence = Literal["high", "medium", "low", "none"]
# Estado de monitorización derivado al leer (nunca guardado): así no queda desfasado.
MonitoringStatus = Literal[
    "archived",
    "disabled",
    "credentials_pending",
    "sensor_pending",
    "never_polled",
    "polling",
    "ok",
    "partial",
    "failing",
    # Fase 6D: consultas periódicas pausadas tras fallos repetidos sin SNMP utilizable.
    "paused",
]
# "recent" = la última consulta correcta es reciente; "historical" = solo hay evidencia
# antigua (la UI no debe presentar el equipo como disponible); "none" = nunca se consultó.
EvidenceFreshness = Literal["recent", "historical", "none"]
PollStatus = Literal["queued", "running", "succeeded", "partial", "failed", "cancelled", "expired"]
# "check" (Fase 6D): verificación de compatibilidad, solo el módulo system.
PollTrigger = Literal["manual", "scheduled", "check"]
ModuleName = Literal["system", "entity", "interfaces", "lldp", "cdp", "bridge", "vlan", "wlan"]
ModuleStatus = Literal["complete", "partial", "unsupported", "failed", "skipped"]
# Fase 6D: diagnóstico SNMP del equipo (app.models.network.SNMP_STATUSES). Taxonomía propia:
# nunca el nombre de una excepción del colector.
SnmpDeviceStatus = Literal[
    "unverified",
    "compatible",
    "no_response",
    "timeout",
    "unreachable",
    "auth_failed",
    "unsupported_version",
    "malformed_response",
    "collector_error",
]
# Taxonomía de errores que la UI muestra diferenciados (docs, sección Troubleshooting).
SnmpErrorCode = Literal[
    "timeout",
    "host_unreachable",
    "auth_failed",
    "unsupported_version",
    "oid_unavailable",
    "no_lldp",
    "no_cdp",
    "partial",
    "sensor_offline",
    "sensor_lost",
    "credentials_unavailable",
    "job_expired",
    "job_rejected",
    "cancelled",
    "limit_exceeded",
    "malformed_response",
    "internal",
]
PortKind = Literal["physical", "lag", "logical", "vlan", "loopback", "tunnel", "wireless", "other"]
AdminStatus = Literal["up", "down", "testing", "unknown"]
OperStatus = Literal[
    "up", "down", "testing", "unknown", "dormant", "not_present", "lower_layer_down"
]
NeighborProtocol = Literal["lldp", "cdp"]
LocalPortMatch = Literal["if_index", "if_name", "if_descr", "unmatched"]
RemoteMatchBasis = Literal["chassis_mac", "mgmt_address", "sys_name"]
MacStatus = Literal["learned", "mgmt", "self", "other", "invalid"]
VlanSource = Literal["fdb_vlan_map", "fdb_id_assumed", "none"]
# Valoración de dónde está conectada una MAC. Nunca "confirmado": una tabla CAM es evidencia
# de reenvío, no de cableado.
MacLocation = Literal["edge_candidate", "uplink_or_shared", "unknown"]

# Comunidades por defecto de fábrica: aceptarlas sería documentar una credencial pública.
_DEFAULT_COMMUNITIES = frozenset({"public", "private"})
_TEXT = r"^[^\x00-\x1f\x7f]+$"


def _secret(value: SecretStr | None, field: str, low: int, high: int) -> None:
    if value is None:
        return
    raw = value.get_secret_value()
    if not low <= len(raw) <= high:
        raise ValueError(f"{field} must have between {low} and {high} characters")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in raw):
        raise ValueError(f"{field} must not contain control characters")


# --- perfiles de credenciales SNMP --------------------------------------------------------------


class SnmpProfileRead(ResponseModel):
    """Metadatos de un perfil. Nunca incluye passwords, claves ni comunidades."""

    profile_id: UUID
    site_id: UUID
    site_name: str
    name: str
    description: str | None
    snmp_version: SnmpVersion
    security_level: SnmpSecurityLevel
    username: str | None
    auth_protocol: SnmpAuthProtocol | None
    priv_protocol: SnmpPrivProtocol | None
    status: SnmpProfileStatus
    # Solo indica que hay un secreto guardado (cifrado) y cuándo cambió por última vez.
    secret_configured: bool
    secret_updated_at: datetime | None
    # Revisión del secreto: sube con cada rotación (diagnóstico de jobs en curso).
    secret_revision: int
    devices_count: int
    created_at: datetime
    created_by: str | None
    updated_at: datetime
    revoked_at: datetime | None
    revoked_by: str | None
    revoke_reason: str | None
    version: int


class SnmpProfileList(ResponseModel):
    items: list[SnmpProfileRead]
    # False si el servidor no tiene configurado el almacén cifrado de secretos: la UI lo
    # explica y no ofrece crear ni rotar perfiles.
    secret_store_available: bool
    v2c_allowed: bool


class SnmpProfileCreate(RequestModel):
    site_id: UUID
    name: str = Field(min_length=1, max_length=100, pattern=_TEXT)
    description: str | None = Field(default=None, max_length=500, pattern=_TEXT)
    snmp_version: SnmpVersion
    username: str | None = Field(default=None, min_length=1, max_length=64, pattern=_TEXT)
    auth_protocol: SnmpAuthProtocol | None = None
    priv_protocol: SnmpPrivProtocol | None = None
    auth_password: SecretStr | None = None
    priv_password: SecretStr | None = None
    community: SecretStr | None = None

    @model_validator(mode="after")
    def _check(self) -> "SnmpProfileCreate":
        check_credentials(self.snmp_version, self, require_all=True)
        return self


def check_credentials(
    version: str, body: "SnmpProfileCreate | SnmpProfileRotate", require_all: bool
) -> None:
    """Reglas comunes de creación y rotación (versión y longitud de cada secreto).

    RFC 3414 exige al menos 8 caracteres en las passphrases de SNMPv3; por debajo, la clave
    localizada es trivial de atacar por fuerza bruta con una captura del tráfico.
    """
    _secret(body.auth_password, "auth_password", 8, 128)
    _secret(body.priv_password, "priv_password", 8, 128)
    _secret(body.community, "community", 1, 64)
    if version == "v3":
        if body.community is not None:
            raise ValueError("community is only valid for SNMPv2c profiles")
        if require_all:
            missing = [
                name
                for name in ("username", "auth_protocol", "priv_protocol")
                if getattr(body, name) is None
            ]
            if body.auth_password is None:
                missing.append("auth_password")
            if body.priv_password is None:
                missing.append("priv_password")
            if missing:
                raise ValueError("SNMPv3 authPriv requires: " + ", ".join(missing))
        if (
            body.auth_password is not None
            and body.priv_password is not None
            and body.auth_password.get_secret_value() == body.priv_password.get_secret_value()
        ):
            # Con la misma passphrase, romper una clave da la otra.
            raise ValueError("auth_password and priv_password must differ")
    else:
        if any(
            getattr(body, name) is not None
            for name in ("username", "auth_protocol", "priv_protocol")
        ) or (body.auth_password is not None or body.priv_password is not None):
            raise ValueError("SNMPv2c profiles only take a community")
        if require_all and body.community is None:
            raise ValueError("SNMPv2c requires a community")
        if (
            body.community is not None
            and body.community.get_secret_value().lower() in _DEFAULT_COMMUNITIES
        ):
            raise ValueError("factory default communities are not accepted")


class SnmpProfileUpdate(RequestModel):
    """Solo metadatos. Cambiar usuario, protocolos o secretos es una rotación auditada."""

    version: int = Field(ge=1)
    name: str | None = Field(default=None, min_length=1, max_length=100, pattern=_TEXT)
    description: str | None = Field(default=None, max_length=500, pattern=_TEXT)


class SnmpProfileRotate(RequestModel):
    """Sustituye los secretos (todos los de la versión del perfil) y, en v3, opcionalmente
    usuario y protocolos. La versión SNMP del perfil no cambia: un perfil v2c no se convierte
    en v3 (se crea otro y se reasignan los equipos)."""

    version: int = Field(ge=1)
    username: str | None = Field(default=None, min_length=1, max_length=64, pattern=_TEXT)
    auth_protocol: SnmpAuthProtocol | None = None
    priv_protocol: SnmpPrivProtocol | None = None
    auth_password: SecretStr | None = None
    priv_password: SecretStr | None = None
    community: SecretStr | None = None


class SnmpProfileRevoke(RequestModel):
    version: int = Field(ge=1)
    reason: str = Field(min_length=1, max_length=500, pattern=_TEXT)


# --- equipos ------------------------------------------------------------------------------------


class DeviceClassificationEvidence(ResponseModel):
    # Fuente de la evidencia: "lldp_capabilities", "sys_services", "bridge_mib",
    # "ip_forwarding", "sys_object_id", "if_type".
    source: str
    detail: str


class DeviceProfileRef(ResponseModel):
    profile_id: UUID
    name: str
    snmp_version: SnmpVersion
    status: SnmpProfileStatus


class DeviceSensorRef(ResponseModel):
    sensor_id: UUID
    name: str
    # Estado efectivo del sensor (online/offline/stale/pending/disabled/revoked).
    status: str


class NetworkDeviceRead(ResponseModel):
    device_id: UUID
    site_id: UUID
    site_name: str
    # Nombre que muestra la UI: el del admin, si no sysName, si no la dirección.
    display_name: str
    name: str | None
    management_address: str
    snmp_port: int
    asset_id: UUID | None
    status: Literal["active", "archived"]
    monitoring_enabled: bool
    monitoring_status: MonitoringStatus
    freshness: EvidenceFreshness
    sys_name: str | None
    sys_descr: str | None
    sys_object_id: str | None
    sys_location: str | None
    sys_uptime_seconds: int | None
    # Fabricante solo si sysObjectID cae bajo un número de empresa IANA conocido o ENTITY-MIB
    # lo informa; nunca deducido de sysDescr.
    vendor: str | None
    vendor_source: Literal["sys_object_id", "entity_mib"] | None
    enterprise_number: int | None
    model: str | None
    firmware: str | None
    serial_number: str | None
    classification: DeviceClassification
    classification_confidence: ClassificationConfidence
    classification_evidence: list[DeviceClassificationEvidence]
    layer3: bool | None
    profile: DeviceProfileRef | None
    sensor: DeviceSensorRef | None
    last_poll_at: datetime | None
    last_success_at: datetime | None
    last_error_code: SnmpErrorCode | None
    last_error_at: datetime | None
    consecutive_failures: int
    snmp_status: SnmpDeviceStatus
    # Pausa automática de las consultas periódicas (motivo = snmp_status que la provocó).
    monitoring_paused_at: datetime | None
    monitoring_pause_reason: SnmpDeviceStatus | None
    interfaces_total: int
    interfaces_up: int
    neighbors_total: int
    vlans_total: int
    mac_entries_total: int
    created_at: datetime
    updated_at: datetime
    version: int


class NetworkDeviceCounts(ResponseModel):
    total: int
    by_classification: dict[str, int]
    by_monitoring_status: dict[str, int]


class NetworkDeviceList(ResponseModel):
    items: list[NetworkDeviceRead]
    total: int
    limit: int
    offset: int
    counts: NetworkDeviceCounts


class LldpLocalRead(ResponseModel):
    chassis_id: str | None
    chassis_id_subtype: str | None
    sys_name: str | None
    capabilities_enabled: list[str]


class EntityRead(ResponseModel):
    """Componentes chassis/stack de ENTITY-MIB tal y como los informa el equipo."""

    index: int
    phys_class: str
    description: str | None
    name: str | None
    model_name: str | None
    serial_number: str | None
    hardware_rev: str | None
    firmware_rev: str | None
    software_rev: str | None
    mfg_name: str | None


class NetworkDeviceDetail(NetworkDeviceRead):
    lldp_local: LldpLocalRead | None
    entities: list[EntityRead]
    base_bridge_address: str | None
    bridge_ports: int | None
    # Módulos de la última consulta correcta o parcial y su resultado.
    last_modules: dict[str, ModuleStatus]
    can_poll: bool
    poll_blockers: list[str]


class NetworkDeviceCreate(RequestModel):
    site_id: UUID
    management_address: str = Field(min_length=2, max_length=45)
    snmp_port: int = Field(default=161, ge=1, le=65535)
    name: str | None = Field(default=None, min_length=1, max_length=100, pattern=_TEXT)
    profile_id: UUID | None = None
    sensor_id: UUID | None = None
    monitoring_enabled: bool = False
    asset_id: UUID | None = None

    @field_validator("management_address")
    @classmethod
    def _address(cls, value: str) -> str:
        address = ipaddress.ip_address(value)
        if address.is_multicast or address.is_unspecified or address.is_loopback:
            raise ValueError("management address must be a unicast host address")
        return str(address)


class NetworkDeviceUpdate(RequestModel):
    """Campos opcionales; `clear_profile`/`clear_sensor` quitan la asignación de forma
    explícita (un null ausente no debe borrar nada por accidente)."""

    version: int = Field(ge=1)
    name: str | None = Field(default=None, min_length=1, max_length=100, pattern=_TEXT)
    snmp_port: int | None = Field(default=None, ge=1, le=65535)
    profile_id: UUID | None = None
    sensor_id: UUID | None = None
    clear_profile: bool = False
    clear_sensor: bool = False
    monitoring_enabled: bool | None = None


class NetworkDeviceResume(RequestModel):
    version: int = Field(ge=1)


class NetworkDeviceArchive(RequestModel):
    version: int = Field(ge=1)
    reason: str | None = Field(default=None, max_length=500, pattern=_TEXT)


class NetworkCandidate(ResponseModel):
    """Activo descubierto (6A) que podría ser un equipo administrable aún no registrado."""

    asset_id: UUID
    site_id: UUID
    site_name: str
    address: str
    hostname: str | None
    device_type: str | None
    device_type_reason: str | None
    mac_address: str | None
    last_seen_at: datetime | None


class NetworkCandidateList(ResponseModel):
    items: list[NetworkCandidate]


# --- inventario ---------------------------------------------------------------------------------


class InterfaceRef(ResponseModel):
    interface_id: UUID
    name: str
    port_kind: PortKind


class NetworkInterfaceRead(ResponseModel):
    interface_id: UUID
    if_index: int
    name: str
    if_name: str | None
    if_descr: str | None
    if_alias: str | None
    if_type: int | None
    port_kind: PortKind
    mac: str | None
    admin_status: AdminStatus
    oper_status: OperStatus
    speed_mbps: int | None
    mtu: int | None
    in_octets: int | None
    out_octets: int | None
    counters_hc: bool
    in_errors: int | None
    out_errors: int | None
    in_discards: int | None
    out_discards: int | None
    counters_at: datetime | None
    bridge_port: int | None
    pvid: int | None
    untagged_vlans: list[int]
    tagged_vlans: list[int]
    is_trunk: bool
    lag_parent: InterfaceRef | None
    lag_members: int
    mac_count: int
    neighbor_count: int
    present: bool
    first_seen_at: datetime
    last_seen_at: datetime
    evidence_source: str


class NetworkInterfaceList(ResponseModel):
    items: list[NetworkInterfaceRead]
    total: int
    limit: int
    offset: int


class DeviceRef(ResponseModel):
    device_id: UUID
    display_name: str


class NetworkNeighborRead(ResponseModel):
    neighbor_id: UUID
    protocol: NeighborProtocol
    local_interface: InterfaceRef | None
    local_port_label: str | None
    local_port_match: LocalPortMatch
    remote_chassis_id: str | None
    remote_chassis_id_subtype: str | None
    remote_port_id: str | None
    remote_port_id_subtype: str | None
    remote_port_descr: str | None
    remote_sys_name: str | None
    remote_sys_descr: str | None
    remote_platform: str | None
    remote_software: str | None
    remote_mgmt_address: str | None
    remote_capabilities: list[str]
    remote_native_vlan: int | None
    # Equipo registrado del MISMO site al que corresponde el vecino, con la base del cruce.
    remote_device: DeviceRef | None
    remote_match_basis: RemoteMatchBasis | None
    # El otro extremo también informa de este equipo: evidencia más fuerte para 6D, pero
    # sigue sin ser un enlace confirmado físicamente.
    reciprocal: bool
    assessment: Literal["reported_by_device"]
    present: bool
    first_seen_at: datetime
    last_seen_at: datetime
    sensor_id: UUID | None
    evidence_source: str


class NetworkNeighborList(ResponseModel):
    items: list[NetworkNeighborRead]
    total: int
    limit: int
    offset: int


class NetworkVlanRead(ResponseModel):
    vlan_id: int
    name: str | None
    source: Literal["q_bridge_static", "q_bridge_current"]
    untagged_ports: int
    tagged_ports: int
    present: bool
    first_seen_at: datetime
    last_seen_at: datetime


class NetworkVlanList(ResponseModel):
    items: list[NetworkVlanRead]


class AssetRef(ResponseModel):
    asset_id: UUID
    display_name: str


class NetworkMacEntryRead(ResponseModel):
    entry_id: UUID
    mac: str
    vlan_id: int | None
    vlan_source: VlanSource
    bridge_port: int | None
    interface: InterfaceRef | None
    status: MacStatus
    location: MacLocation
    location_reason: str
    port_mac_count: int
    # Activo del MISMO site con esa MAC (nunca de otro site, aunque la MAC coincida).
    asset: AssetRef | None
    present: bool
    first_seen_at: datetime
    last_seen_at: datetime


class NetworkMacEntryList(ResponseModel):
    items: list[NetworkMacEntryRead]
    total: int
    limit: int
    offset: int
    truncated: bool


class MacLocationRead(NetworkMacEntryRead):
    device: DeviceRef
    site_id: UUID
    site_name: str


class MacLocationList(ResponseModel):
    mac: str
    items: list[MacLocationRead]


class MacQuery(RequestModel):
    mac: str

    @field_validator("mac")
    @classmethod
    def _mac(cls, value: str) -> str:
        normalized = normalize_mac(value)
        if normalized is None:
            raise ValueError("invalid MAC address")
        return normalized


# --- consultas (polls) --------------------------------------------------------------------------


class PollCounts(ResponseModel):
    interfaces: int = 0
    neighbors: int = 0
    vlans: int = 0
    mac_entries: int = 0
    records: int = 0
    # Fase 6C.3: los recuentos wlan_* se guardan en la consulta pero no se exponen aquí (el
    # contrato del dashboard no cambia); el inventario Wi-Fi tiene su API en /network/wlan.


class PollChanges(ResponseModel):
    interfaces_added: int = 0
    interfaces_removed: int = 0
    oper_status_changes: int = 0
    neighbors_added: int = 0
    neighbors_removed: int = 0
    classification_changed: bool = False


class NetworkPollRead(ResponseModel):
    poll_id: UUID
    device_id: UUID
    site_id: UUID
    sensor_id: UUID | None
    sensor_name: str | None
    sensor_job_id: UUID | None
    status: PollStatus
    trigger: PollTrigger
    requested_by: str
    snmp_version: SnmpVersion | None
    modules_requested: list[str]
    modules: dict[str, ModuleStatus]
    error_code: SnmpErrorCode | None
    error_message: str | None
    counts: PollCounts
    changes: PollChanges
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class NetworkPollList(ResponseModel):
    items: list[NetworkPollRead]
    total: int
    limit: int
    offset: int
