import unicodedata
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import Field, field_validator

from app.discovery.device_types import ClassificationConfidence, DeviceType
from app.models.asset import AssetCriticality, AssetStatus, MonitoringMethod
from app.models.asset_context import AssetRole
from app.models.risk import RiskConfidence, RiskLevel
from app.schemas.common import RequestModel, ResponseModel
from app.schemas.telemetry import TelemetrySnapshot


class ClassificationEvidence(ResponseModel):
    """Una evidencia de la identificación: de dónde sale (source) y qué se observó (value)."""

    # agent_hostname, agent_os, reverse_dns, mdns, netbios, upnp, ssdp, mac_vendor,
    # mac_random, ports o gateway.
    source: str
    value: str


class ObservedName(ResponseModel):
    """Corrección 6C: un nombre observado con su procedencia (source) y su clase (kind).

    kind: agent (hostname del agente), device (publicado por el propio equipo), dhcp (DNS
    local del router; inferido), dns (DNS de dominio) o generic (valor por defecto de un SO,
    nunca se usa como nombre). `selected` marca el nombre automático elegido; `confirmed` es
    la confirmación directa del DNS inverso (null si no se comprobó o no aplica) y `stale`
    indica que ninguna fuente lo ha repetido en los últimos NAME_STALE_DAYS días.
    """

    source: str
    value: str
    kind: Literal["agent", "device", "dhcp", "dns", "generic"]
    selected: bool
    confirmed: bool | None = None
    stale: bool = False


# Corrección 6C: límites de la etiqueta personalizada. 64 caracteres caben en una celda de
# tabla y en el título de un informe; el límite de bytes de la columna es el mismo.
LABEL_MAX = 64
# Categorías Unicode prohibidas: controles (Cc), formato (Cf: incluye los caracteres
# invisibles de ancho cero y los de cambio de dirección que permiten disfrazar un nombre,
# p. ej. "Alexa\u202eala S"), uso privado, sustitutos y separadores de línea/párrafo.
_LABEL_FORBIDDEN = {"Cc", "Cf", "Co", "Cs", "Zl", "Zp"}


def normalize_label(value: str) -> str:
    """Forma canónica de una etiqueta: NFC, sin espacios repetidos ni en los extremos.

    Lanza ValueError si queda vacía, supera LABEL_MAX o contiene caracteres de control,
    invisibles o de cambio de dirección.
    """
    text = unicodedata.normalize("NFC", value)
    if any(unicodedata.category(ch) in _LABEL_FORBIDDEN for ch in text):
        raise ValueError("label contains control, invisible or bidirectional characters")
    text = " ".join(text.split())
    if not text:
        raise ValueError("label must not be blank; send null to remove it")
    if len(text) > LABEL_MAX:
        raise ValueError(f"label must be at most {LABEL_MAX} characters")
    return text


class AssetDeviceTypeUpdate(RequestModel):
    """PATCH /assets/{id}/device-type (Fase 7A.4). `device_type: null` vuelve al automático.

    `version` es custom_label_version tal y como la leyó el cliente (el mismo token protege
    todo lo que una persona fija a mano en la identidad del activo).
    """

    device_type: DeviceType | None
    version: int = Field(ge=0, le=2**31 - 1)


class AssetLabelUpdate(RequestModel):
    """PATCH /assets/{id}/label. `label: null` elimina la etiqueta (vuelve el nombre automático).

    `version` es custom_label_version tal y como la leyó el cliente: si cambió entretanto,
    409 asset_label_conflict y no se guarda nada.
    """

    # Margen sobre LABEL_MAX antes de normalizar (espacios repetidos que se compactan).
    label: str | None = Field(max_length=LABEL_MAX * 4)
    version: int = Field(ge=0, le=2**31 - 1)

    @field_validator("label")
    @classmethod
    def _label(cls, value: str | None) -> str | None:
        return None if value is None else normalize_label(value)


class AssetRead(ResponseModel):
    asset_id: UUID
    # Etiqueta personalizada, nombre resuelto, hostname, DNS inverso o la IP: siempre
    # presente. La UI prefiere custom_label y device_name y usa un texto de reserva
    # ("Dispositivo desconocido") en vez de la IP.
    display_name: str
    # Corrección 6C: nombre visible puesto por una persona (null = nombre automático) y su
    # versión para la concurrencia optimista de PATCH /assets/{id}/label.
    custom_label: str | None = None
    custom_label_version: int = 0
    custom_label_updated_at: datetime | None = None
    custom_label_updated_by: str | None = None
    # Fase 7A.4: tipo fijado a mano (null = automático). device_type ya lo refleja.
    manual_device_type: str | None = None
    monitoring_method: MonitoringMethod
    # Reported by the agent; null for assets only seen on the network.
    hostname: str | None
    os_name: str | None
    os_version: str | None
    architecture: str | None
    primary_ip: str
    agent_version: str | None
    # Agent assets: the agent's liveness (as before). Others: their network status.
    status: AssetStatus
    # Liveness of the agent (null without agent) and reachability on the network (null
    # until a discovery run sees it).
    agent_status: AssetStatus | None
    network_status: AssetStatus | None
    first_seen_at: datetime
    last_seen_at: datetime | None
    created_at: datetime
    updated_at: datetime
    latest_telemetry: TelemetrySnapshot | None
    # Network view (discovery); null/empty when unknown.
    mac_address: str | None
    reverse_dns: str | None
    # Organización registrada del prefijo de la MAC (OUI) y su marca corta: es el fabricante
    # de la NIC, no necesariamente el del dispositivo (device_vendor).
    vendor: str | None
    network_adapter_vendor: str | None
    # Identificación (Fase 4E). device_type: pc, laptop, server, mobile, tablet, console,
    # printer, router, network_switch, access_point, iot, voice_assistant, smart_tv, nas,
    # virtual_machine; null = desconocido.
    device_type: str | None
    device_type_reason: str | None
    # Nombre resuelto por prioridad y su fuente (agent_hostname, reverse_dns, mdns, netbios,
    # upnp, vendor_model); null si nada lo nombra.
    device_name: str | None
    name_source: str | None
    device_vendor: str | None
    device_model: str | None
    # SO deducido desde la red (sin versión); null en activos con agente (ver os_name).
    probable_os: str | None
    classification_confidence: ClassificationConfidence | None
    classification_evidence: list[ClassificationEvidence]
    # Corrección 6C: nombres observados con procedencia (vacío hasta la siguiente
    # identificación de los activos anteriores a la migración 0037).
    observed_names: list[ObservedName] = Field(default_factory=list)
    # Fase 6D.3: por qué el activo tiene (o no) nombre, para que la UI explique un
    # "Dispositivo desconocido" en vez de dejarlo en blanco: labelled (etiqueta manual), named
    # (nombre automático con evidencia), generic_only (solo nombres genéricos de SO como
    # "linux.local", que nunca se eligen) o unnamed (ninguna fuente lo nombró).
    name_status: Literal["labelled", "named", "generic_only", "unnamed"] = "unnamed"
    discovery_sources: list[str]
    discovery_network: str | None
    discovered_at: datetime | None
    last_network_seen_at: datetime | None
    # Open TCP ports reachable from the Sentra server.
    open_ports: list[int]
    # Fase 4I: criticidad (la cambia un admin) y riesgo actual del Risk Engine; null hasta
    # el primer cálculo. El detalle y la explicación están en /risk/assets/{id}.
    criticality: AssetCriticality
    # Fase 4L: rol confirmado por un admin ("unknown" si nadie lo confirmó). El resto del
    # contexto está en /assets/{id}/context; aquí solo lo compacto para el listado.
    role: AssetRole
    risk_score: int | None
    risk_level: RiskLevel | None
    risk_confidence: RiskConfidence | None
    # Fase 5C.1: ciclo de vida. Archivado = oculto por defecto con todo su historial.
    archived_at: datetime | None = None
    archived_by: str | None = None
    archive_reason: str | None = None
    # Versión para concurrencia optimista de archivar/restaurar/borrar/reconciliar.
    lifecycle_version: int = 0
    # Tuvo agente alguna vez (Managed): nunca se borra físicamente, solo se archiva.
    managed_history: bool = False
    # Estado de las fuentes de eventos informado por el agente (journal, sshd, sudo,
    # auditd... o canales de Windows) y cuándo llegó; null si el agente no lo informa.
    event_coverage: dict[str, str] | None = None
    event_coverage_at: datetime | None = None
    # Fase 5C.2: ciclo de vida derivado (app/services/asset_lifecycle_policy.py). Ningún
    # estado se guarda: se calcula al leer con la política configurada.
    lifecycle_state: Literal["active", "offline", "stale", "cleanup_candidate", "archived"] = (
        "active"
    )
    lifecycle_source: Literal["discovered", "monitored", "managed"] = "discovered"
    # Scans de discovery completos y exitosos seguidos que no lo vieron.
    missed_discovery_scans: int = 0
    last_activity_at: datetime | None = None
    # Fase 5F: site del activo. La misma IP en dos sites son dos activos distintos.
    site_id: UUID
    site_name: str


class AssetList(ResponseModel):
    items: list[AssetRead]
    # Activos que cumplen los filtros (todas las páginas).
    total: int
    # Fase 4M: la lista siempre está paginada en el servidor.
    limit: int
    offset: int
    # Recuento por estado efectivo (online/offline/unknown) con los demás filtros aplicados.
    status_counts: dict[str, int]
