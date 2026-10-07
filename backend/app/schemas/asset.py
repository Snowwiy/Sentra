from datetime import datetime
from uuid import UUID

from app.discovery.device_types import ClassificationConfidence
from app.models.asset import AssetCriticality, AssetStatus, MonitoringMethod
from app.models.asset_context import AssetRole
from app.models.risk import RiskConfidence, RiskLevel
from app.schemas.common import ResponseModel
from app.schemas.telemetry import TelemetrySnapshot


class ClassificationEvidence(ResponseModel):
    """Una evidencia de la identificación: de dónde sale (source) y qué se observó (value)."""

    # agent_hostname, agent_os, reverse_dns, mdns, netbios, upnp, ssdp, mac_vendor,
    # mac_random, ports o gateway.
    source: str
    value: str


class AssetRead(ResponseModel):
    asset_id: UUID
    # Nombre resuelto, hostname, DNS inverso o la IP: siempre presente. La UI prefiere
    # device_name y usa un texto de reserva ("Dispositivo desconocido") en vez de la IP.
    display_name: str
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


class AssetList(ResponseModel):
    items: list[AssetRead]
    # Activos que cumplen los filtros (todas las páginas).
    total: int
    # Fase 4M: la lista siempre está paginada en el servidor.
    limit: int
    offset: int
    # Recuento por estado efectivo (online/offline/unknown) con los demás filtros aplicados.
    status_counts: dict[str, int]
