"""Contratos Wi-Fi / AP / WLAN (Fase 6C.3, docs/wlan-discovery.md).

Dos superficies:
- Entrada de los agentes: campo opcional `wireless` de POST /inventory (WirelessReport). Un
  agente autenticado sigue siendo una fuente no confiable: tamaños, rangos y texto acotados.
  Lo estructuralmente inválido es 422; un valor bien formado pero inutilizable (BSSID
  multicast o todo ceros) se descarta (None) en lugar de rechazar el inventario entero.
- API del dashboard bajo /api/v1/network/wlan (lectura monitoring:read, gestión
  network:manage). Todo dato lleva su procedencia y su confianza; lo que la fuente no da es
  null, nunca un valor supuesto.
"""

import re
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator, model_validator

from app.discovery.probes import normalize_mac
from app.schemas.common import RequestModel, ResponseModel
from app.schemas.telemetry import MAX_FUTURE_SKEW

MAX_WIRELESS_INTERFACES = 8
MAX_WIRELESS_NETWORKS = 256
_PRINTABLE = r"^[^\x00-\x1f\x7f]*$"
# MAC con ":" o "-" (lo que dan system_profiler, netsh y nmcli). Otra forma es 422.
_MAC_FORMAT = re.compile(r"^[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}$")

WirelessStatus = Literal["ok", "no_adapter", "permission_limited", "unsupported", "error"]
WirelessSource = Literal["macos_system_profiler", "windows_netsh", "linux_nmcli"]
Band = Literal["2.4", "5", "6"]


def _mac(value: str | None) -> str | None:
    if value is None:
        return None
    if not _MAC_FORMAT.match(value):
        raise ValueError("invalid MAC address format")
    # Bien formada pero no unicast utilizable (00:00..., multicast): no identifica nada.
    return normalize_mac(value)


class WirelessInterface(RequestModel):
    name: str = Field(min_length=1, max_length=64, pattern=_PRINTABLE)
    mac: str | None = Field(default=None, max_length=17)
    connected_ssid: str | None = Field(default=None, max_length=64, pattern=_PRINTABLE)
    connected_bssid: str | None = Field(default=None, max_length=17)

    @field_validator("mac", "connected_bssid")
    @classmethod
    def _macs(cls, value: str | None) -> str | None:
        return _mac(value)


class WirelessNetwork(RequestModel):
    ssid: str | None = Field(default=None, max_length=64, pattern=_PRINTABLE)
    bssid: str | None = Field(default=None, max_length=17)
    channel: int | None = Field(default=None, ge=1, le=233)
    frequency_mhz: int | None = Field(default=None, ge=2400, le=7125)
    band: Band | None = None
    security: str | None = Field(default=None, max_length=64, pattern=_PRINTABLE)
    signal_dbm: int | None = Field(default=None, ge=-120, le=0)
    signal_quality: int | None = Field(default=None, ge=0, le=100)
    phy_mode: str | None = Field(default=None, max_length=32, pattern=_PRINTABLE)
    connected: bool = False

    @field_validator("bssid")
    @classmethod
    def _bssid(cls, value: str | None) -> str | None:
        return _mac(value)


class WirelessReport(RequestModel):
    """Observación pasiva del sistema operativo del agente (sin escaneo activo propio).

    Ver docs/agent-protocol.md. Un agente antiguo no envía el campo y nada cambia.
    """

    status: WirelessStatus
    source: WirelessSource
    collected_at: AwareDatetime
    interfaces: list[WirelessInterface] = Field(
        default_factory=list, max_length=MAX_WIRELESS_INTERFACES
    )
    networks: list[WirelessNetwork] = Field(default_factory=list, max_length=MAX_WIRELESS_NETWORKS)

    @field_validator("collected_at")
    @classmethod
    def _collected(cls, value: datetime) -> datetime:
        value = value.astimezone(UTC)
        if value > datetime.now(UTC) + MAX_FUTURE_SKEW:
            raise ValueError("collected_at is too far in the future")
        return value


# --- API del dashboard ------------------------------------------------------------------------

WlanSource = Literal["snmp_ieee802dot11", "snmp_airespace", "snmp_unifi", "agent"]
WlanConfidence = Literal["reported_by_device", "observed"]
AuthorizationStatus = Literal["unknown", "authorized", "external"]
ApReportedStatus = Literal["up", "down", "transitional", "unknown"]
# "recent": visto dentro de la ventana de frescura; "historical": solo evidencia antigua (la UI
# no debe presentarlo como activo); se deriva al leer, nunca se guarda.
WlanFreshness = Literal["recent", "historical"]
Protection = Literal[
    "open", "owe", "wep", "wpa", "wpa_wpa2", "wpa2", "wpa2_wpa3", "wpa3", "rsn", "legacy", "unknown"
]
IdentityConfidence = Literal["confirmed", "probable", "observation_only"]
ClientState = Literal[
    "associated",
    "authenticated",
    "connected",
    "idle",
    "power_save",
    "disassociated",
    "pending",
    "probing",
    "excluded",
    "unknown",
]
FindingCode = Literal[
    "open_network", "wep", "wpa1", "wpa1_allowed", "legacy_privacy", "tkip_allowed"
]
SourceAvailability = Literal["available", "partial", "unavailable", "not_configured"]


class WlanSiteRef(ResponseModel):
    site_id: UUID
    site_name: str


class WlanDeviceRef(ResponseModel):
    device_id: UUID
    display_name: str


class WlanAssetRef(ResponseModel):
    asset_id: UUID
    display_name: str


class WlanSensorRef(ResponseModel):
    sensor_id: UUID
    name: str


class WlanApRef(ResponseModel):
    access_point_id: UUID
    display_name: str


class WlanRadio(ResponseModel):
    slot: int
    band: Band | None = None
    channel: int | None = None
    ssid: str | None = None
    standard: str | None = None
    status: Literal["up", "down"] | None = None
    clients: int | None = None


class WlanConfigFinding(ResponseModel):
    """Observación técnica de configuración insegura. Visible en la API; NO contribuye al
    Risk Engine (no hay una política aprobada que lo haga)."""

    code: FindingCode
    severity: Literal["info"] = "info"
    contributes_to_risk: Literal[False] = False
    detail: str


class WlanLinkEvidence(ResponseModel):
    basis: Literal["management_ip", "mac", "source_device"]
    value: str
    method: Literal["automatic", "manual"]
    at: datetime
    by: str | None = None


class WlanAccessPointRead(ResponseModel):
    access_point_id: UUID
    site_id: UUID
    site_name: str
    display_name: str
    name: str | None
    vendor: str | None
    model: str | None
    serial_number: str | None
    firmware: str | None
    location: str | None
    management_ip: str | None
    ethernet_mac: str | None
    radio_mac: str | None
    reported_status: ApReportedStatus
    source: WlanSource
    confidence: WlanConfidence
    reported_by: WlanDeviceRef | None
    sensor: WlanSensorRef | None
    network_device: WlanDeviceRef | None
    asset: WlanAssetRef | None
    authorization_status: AuthorizationStatus
    authorization_reason: str | None
    authorization_by: str | None
    authorization_at: datetime | None
    present: bool
    freshness: WlanFreshness
    first_seen_at: datetime
    last_seen_at: datetime
    radios: list[WlanRadio]
    bss_count: int
    client_count: int
    ssids: list[str]
    version: int


class WlanAccessPointList(ResponseModel):
    items: list[WlanAccessPointRead]
    total: int
    limit: int
    offset: int


class WlanObservationRead(ResponseModel):
    observation_id: int
    entity: Literal["access_point", "bss", "client"]
    entity_id: UUID
    source: WlanSource
    confidence: WlanConfidence
    observed_at: datetime
    received_at: datetime
    poll_id: UUID | None
    sensor: WlanSensorRef | None
    reported_by: WlanDeviceRef | None
    agent_asset: WlanAssetRef | None
    data: dict[str, str | int | float | bool | None]


class WlanObservationList(ResponseModel):
    items: list[WlanObservationRead]
    total: int
    limit: int
    offset: int


class WlanBssRead(ResponseModel):
    bss_id: UUID
    site_id: UUID
    site_name: str
    bssid: str
    bssid_randomized: bool
    ssid: str | None
    band: Band | None
    channel: int | None
    frequency_mhz: int | None
    protection: Protection | None
    protection_reported: str | None
    standard: str | None
    signal_dbm: int | None
    signal_quality: int | None
    client_count: int | None
    # Siempre null en esta fase: ninguna fuente da una VLAN verificable.
    vlan_id: int | None
    access_point: WlanApRef | None
    source: WlanSource
    sources: list[WlanSource]
    confidence: WlanConfidence
    reported_by: WlanDeviceRef | None
    last_agent: WlanAssetRef | None
    authorization_status: AuthorizationStatus
    authorization_reason: str | None
    authorization_by: str | None
    authorization_at: datetime | None
    findings: list[WlanConfigFinding]
    present: bool
    freshness: WlanFreshness
    first_seen_at: datetime
    last_seen_at: datetime
    last_snmp_seen_at: datetime | None
    last_agent_seen_at: datetime | None
    version: int


class WlanBssList(ResponseModel):
    items: list[WlanBssRead]
    total: int
    limit: int
    offset: int


class WlanAccessPointDetail(WlanAccessPointRead):
    link_suppressed: bool
    link_evidence: dict[str, WlanLinkEvidence]
    bss: list[WlanBssRead]
    findings: list[WlanConfigFinding]
    # Las 50 observaciones más recientes del AP y de sus BSS (el resto: /observations).
    observations: list[WlanObservationRead]


class WlanSsidRead(ResponseModel):
    """Agregado por SSID dentro de UN site (el mismo SSID en dos sites son dos filas)."""

    site_id: UUID
    site_name: str
    ssid: str | None
    bss_count: int
    bss_recent: int
    access_point_count: int
    bands: list[Band]
    protections: list[Protection]
    sources: list[WlanSource]
    configured_on_controllers: int
    controller_client_count: int | None
    client_count: int | None
    authorized_bss: int
    external_bss: int
    unknown_bss: int
    findings: list[FindingCode]
    last_seen_at: datetime


class WlanSsidList(ResponseModel):
    items: list[WlanSsidRead]
    total: int
    limit: int
    offset: int


class WlanClientRead(ResponseModel):
    client_id: UUID
    site_id: UUID
    site_name: str
    mac: str | None
    mac_randomized: bool
    bssid: str | None
    ssid: str | None
    access_point: WlanApRef | None
    radio_slot: int | None
    band: Band | None
    standard: str | None
    state: ClientState
    source: WlanSource
    identity_confidence: IdentityConfidence
    asset: WlanAssetRef | None
    # "manual": un admin lo asoció (Fase 7B.2, asset_identity_links).
    correlation_basis: Literal["agent_self", "mac_match", "agent_reported_mac", "manual"] | None
    reported_by: WlanDeviceRef | None
    present: bool
    freshness: WlanFreshness
    first_seen_at: datetime
    last_seen_at: datetime


class WlanClientList(ResponseModel):
    items: list[WlanClientRead]
    total: int
    limit: int
    offset: int


class WlanSourceStatus(ResponseModel):
    """Disponibilidad de datos de una fuente en el ámbito pedido."""

    source: Literal["snmp", "agent"]
    availability: SourceAvailability
    # SNMP: sensores con snmp.wlan y equipos cuya última consulta trajo wlan, por estado.
    # Agente: agentes con informe wireless, por estado (ok, no_adapter, permission_limited...).
    reporters: int
    by_status: dict[str, int]
    last_seen_at: datetime | None
    detail: str


class WlanOverview(ResponseModel):
    site_id: UUID | None
    access_points: int
    access_points_recent: int
    access_points_by_authorization: dict[str, int]
    access_points_by_status: dict[str, int]
    bss: int
    bss_recent: int
    bss_observed_only: int
    bss_by_band: dict[str, int]
    ssids: int
    clients: int
    clients_recent: int
    clients_by_identity: dict[str, int]
    insecure_bss: int
    findings_by_code: dict[str, int]
    sources: list[WlanSourceStatus]
    # Recordatorio explícito para la UI: las observaciones no alimentan el Risk Engine.
    risk_engine_contribution: Literal[False] = False


class WlanAuthorizationUpdate(RequestModel):
    status: AuthorizationStatus
    reason: str | None = Field(default=None, min_length=1, max_length=500, pattern=_PRINTABLE)
    # Concurrencia optimista: si se envía y no coincide, 409.
    version: int | None = Field(default=None, ge=1)


class WlanLinkRequest(RequestModel):
    asset_id: UUID | None = None
    network_device_id: UUID | None = None

    @model_validator(mode="after")
    def _one(self) -> "WlanLinkRequest":
        if self.asset_id is None and self.network_device_id is None:
            raise ValueError("asset_id or network_device_id is required")
        return self


class WlanUnlinkRequest(RequestModel):
    target: Literal["asset", "network_device", "all"] = "all"
    reason: str | None = Field(default=None, min_length=1, max_length=500, pattern=_PRINTABLE)
