"""Contratos de la API de fuentes DHCP, leases e identidad de activos (Fase 6E.2).

Ver docs/dhcp-identity.md. Ningún contrato lleva rutas de fichero: una fuente de sensor se
refiere por el nombre que el propio sensor define en su configuración.
"""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import Field, model_validator

from app.schemas.common import RequestModel, ResponseModel

DhcpSourceKind = Literal["lease_import", "sensor_file"]
DhcpFormat = Literal["dnsmasq", "isc_dhcpd", "kea_csv", "windows_dhcp_csv", "generic_csv"]
DhcpSourceStatus = Literal["pending", "ok", "error", "disabled"]
LeaseState = Literal["active", "expired", "released", "unknown"]
LeaseMatch = Literal[
    "mac_ip", "mac_moved", "ip_only", "randomized_mac", "ambiguous", "no_asset", "expired"
]
IdentityField = Literal["name", "label", "ip", "mac", "vendor", "device_type"]
# Por qué un activo sigue sin nombre (o solo con fabricante). La UI traduce cada código.
UnidentifiedReason = Literal[
    "no_name_sources",
    "randomized_mac",
    "only_generic_names",
    "dhcp_source_missing",
    "dhcp_no_lease",
    "dhcp_lease_unusable_name",
    "names_stale",
    "only_vendor",
]

# Mismo patrón que el sensor 0.6.0 para [[dhcp_lease_files]].name.
SENSOR_SOURCE_NAME = r"^[a-z0-9_-]{1,64}$"
SOURCE_NAME = r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$"


class DhcpSiteRef(ResponseModel):
    id: UUID
    name: str


class DhcpSourceCreate(RequestModel):
    site_id: UUID | None = Field(default=None, description="Site; without it, the default site")
    name: str = Field(pattern=SOURCE_NAME)
    kind: DhcpSourceKind
    format: DhcpFormat
    sensor_id: UUID | None = None
    sensor_source_name: str | None = Field(default=None, pattern=SENSOR_SOURCE_NAME)
    poll_interval_minutes: int = Field(default=0, ge=0, le=1440)

    @model_validator(mode="after")
    def _kind_fields(self) -> "DhcpSourceCreate":
        if self.kind == "sensor_file":
            if self.sensor_id is None or self.sensor_source_name is None:
                raise ValueError("sensor_file sources need sensor_id and sensor_source_name")
        elif self.sensor_id is not None or self.sensor_source_name is not None:
            raise ValueError("lease_import sources do not take a sensor")
        elif self.poll_interval_minutes:
            raise ValueError("lease_import sources are not polled")
        return self


class DhcpSourceUpdate(RequestModel):
    version: int = Field(ge=1)
    enabled: bool | None = None
    format: DhcpFormat | None = None
    poll_interval_minutes: int | None = Field(default=None, ge=0, le=1440)


class DhcpSourceRead(ResponseModel):
    id: UUID
    site: DhcpSiteRef
    name: str
    kind: DhcpSourceKind
    format: DhcpFormat
    sensor_id: UUID | None
    sensor_name: str | None
    sensor_source_name: str | None
    poll_interval_minutes: int
    status: DhcpSourceStatus
    last_requested_at: datetime | None
    last_import_at: datetime | None
    last_error_code: str | None
    # {"lines", "parsed", "skipped", "truncated", "matched", "named", "ambiguous"}.
    last_stats: dict[str, Any] | None
    lease_count: int
    created_by: str
    created_at: datetime
    updated_at: datetime
    version: int


class DhcpSourceList(ResponseModel):
    items: list[DhcpSourceRead]


class DhcpImportIn(RequestModel):
    # Texto del fichero (el navegador lo lee y lo envía como texto). El tope efectivo es
    # DHCP_IMPORT_MAX_KB; este solo evita que pydantic construya cadenas absurdas.
    content: str = Field(min_length=1, max_length=3 * 1024 * 1024)
    version: int = Field(ge=1)


class DhcpImportResult(ResponseModel):
    source: DhcpSourceRead
    lines: int
    parsed: int
    skipped: int
    truncated: bool
    matched: int
    named: int
    ambiguous: int


class DhcpReadRequested(ResponseModel):
    source: DhcpSourceRead
    sensor_job_id: UUID


class DhcpLeaseRead(ResponseModel):
    source_id: UUID
    source_name: str
    ip: str
    mac: str
    mac_randomized: bool
    hostname: str | None
    hostname_usable: bool
    state: LeaseState
    starts_at: datetime | None
    ends_at: datetime | None
    match: LeaseMatch
    asset_id: UUID | None
    asset_name: str | None
    first_seen_at: datetime
    last_seen_at: datetime


class DhcpLeaseList(ResponseModel):
    items: list[DhcpLeaseRead]
    total: int
    limit: int
    offset: int


class AssetWifiRef(ResponseModel):
    ssid: str | None
    bssid: str | None
    access_point_name: str | None
    band: str | None
    state: str
    last_seen_at: datetime


class AssetIdentityRead(ResponseModel):
    """Identidad de un activo con su evidencia. `display_name` es lo que muestra la UI:
    la etiqueta personalizada si existe; si no, el nombre automático."""

    asset_id: UUID
    display_name: str
    custom_label: str | None
    automatic_name: str | None
    name_source: str | None
    # Todos los nombres observados ({"source", "value", "kind", "selected", "confirmed",
    # "stale"}), incluido el elegido.
    names: list[dict[str, Any]]
    ip: str
    mac: str | None
    mac_randomized: bool
    vendor: str | None
    device_type: str | None
    classification_confidence: str | None
    leases: list[DhcpLeaseRead]
    wifi: AssetWifiRef | None
    unidentified_reasons: list[UnidentifiedReason]


class AssetIdentityHistoryEntry(ResponseModel):
    field: IdentityField
    old_value: str | None
    new_value: str | None
    source: str
    confidence: str
    observed_at: datetime


class AssetIdentityHistory(ResponseModel):
    asset_id: UUID
    items: list[AssetIdentityHistoryEntry]
    next_before_id: int | None
