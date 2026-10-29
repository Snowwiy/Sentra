"""Contratos de la API de topología (Fase 6D, docs/topology-engine.md).

Los nombres de campos, valores y códigos de error son el contrato con el frontend y los
informes v2. Los nodos no se guardan: cada lectura los compone desde el inventario (activo,
equipo de red, AP o identidad externa), así nombre, etiqueta y riesgo nunca se desfasan.
"""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import Field

from app.schemas.asset import ObservedName
from app.schemas.common import RequestModel, ResponseModel

NodeKind = Literal["asset", "network_device", "wlan_ap", "external"]
LinkKind = Literal["physical", "logical", "observed", "candidate", "unknown"]
LinkMedium = Literal["wired", "wireless", "unknown"]
LinkConfidence = Literal["high", "medium", "low"]
LinkRelation = Literal[
    "lldp",
    "cdp",
    "fdb_edge",
    "fdb_shared",
    "fdb_unmapped",
    "wlan_association",
    "wlan_managed_by",
    "default_gateway",
]
ReviewState = Literal["unreviewed", "accepted", "rejected"]
NodeRole = Literal["infrastructure", "endpoint", "unknown"]
IdentityConfidence = Literal["high", "medium", "low", "none"]
BuildStatus = Literal["running", "succeeded", "failed"]
BuildTrigger = Literal["manual", "scheduled"]
GroupKind = Literal["network", "unassigned"]
# Sin caracteres de control (incluidos saltos de línea): la nota se muestra en tablas y en
# la auditoría y no debe poder falsear líneas de log ni romper la maquetación.
_PLAIN = r"^[^\x00-\x1f\x7f]*$"


class TopologySiteRef(ResponseModel):
    id: UUID
    name: str


class TopologyBuild(ResponseModel):
    """Una reconstrucción del grafo de un site. `counts`: enteros con claves fijas
    (links_created, links_updated, links_absent, links_present, links_dropped, nodes,
    ambiguous_macs, skipped_cross_site)."""

    id: UUID
    site_id: UUID
    status: BuildStatus
    trigger: BuildTrigger
    requested_by: str | None
    started_at: datetime
    finished_at: datetime | None
    duration_ms: int | None
    counts: dict[str, int] | None
    error_code: str | None


class TopologyLimits(ResponseModel):
    max_nodes: int
    max_links: int


class TopologyNode(ResponseModel):
    """Nodo compuesto al leer. `label` es lo que se muestra (etiqueta personalizada y, sin
    ella, el nombre automático); `automatic_name` es el nombre sin la etiqueta."""

    id: str
    kind: NodeKind
    label: str
    automatic_name: str | None
    custom_label: str | None
    asset_id: UUID | None
    network_device_id: UUID | None
    ip: str | None
    mac: str | None
    vendor: str | None
    device_type: str | None
    role: NodeRole
    status: str | None
    managed: bool | None
    risk_score: int | None
    risk_level: str | None
    criticality: str | None
    groups: list[str]
    sources: list[str]
    identity_confidence: IdentityConfidence
    link_count: int


class TopologyLink(ResponseModel):
    id: UUID
    source: str
    target: str
    kind: LinkKind
    medium: LinkMedium
    relation: LinkRelation
    confidence: LinkConfidence
    source_port: str | None
    target_port: str | None
    evidence_sources: list[str]
    present: bool
    first_seen_at: datetime
    last_seen_at: datetime
    last_evidence_at: datetime | None
    review_state: ReviewState


class TopologyEvidence(ResponseModel):
    source: str
    detail: str
    observed_at: datetime | None


class TopologyLinkDetail(TopologyLink):
    evidence: list[TopologyEvidence]
    # Datos que informó el vecino externo (chasis, sysName, plataforma, dirección de gestión,
    # puerto). Solo evidencia: no identifica ningún activo.
    target_external: dict[str, Any] | None
    review_note: str | None
    reviewed_by: str | None
    reviewed_at: datetime | None
    version: int


class TopologyLinkList(ResponseModel):
    items: list[TopologyLink]
    total: int
    limit: int
    offset: int


class TopologyGroup(ResponseModel):
    id: str
    kind: GroupKind
    cidr: str | None
    name: str | None
    node_count: int


TopologyLimitation = Literal[
    "nodes_without_link_evidence", "no_physical_link_evidence", "access_point_not_inventoried"
]


class TopologyCoverage(ResponseModel):
    """Fase 7B-Fix1: cuántos nodos tienen evidencia de conexión y qué limita el grafo."""

    nodes: int
    nodes_without_links: int
    unlinked_by_type: dict[str, int]
    links_by_kind: dict[str, int]
    limitations: list[TopologyLimitation]


class TopologyGraph(ResponseModel):
    site: TopologySiteRef
    generated_at: datetime
    last_build: TopologyBuild | None
    truncated: bool
    limits: TopologyLimits
    nodes: list[TopologyNode]
    links: list[TopologyLink]
    groups: list[TopologyGroup]
    coverage: TopologyCoverage


class TopologyNodeDetail(ResponseModel):
    node: TopologyNode
    links: list[TopologyLink]
    observed_names: list[ObservedName]
    # Ruta del frontend al detalle del inventario (activo, equipo o AP); null si es externo.
    inventory_path: str | None


class TopologyEvidenceAvailability(ResponseModel):
    lldp_cdp: bool
    fdb: bool
    wlan: bool
    agent_gateways: bool


class TopologyStatus(ResponseModel):
    site: TopologySiteRef
    last_build: TopologyBuild | None
    links_present: int
    links_by_kind: dict[str, int]
    evidence_available: TopologyEvidenceAvailability


class TopologyReviewUpdate(RequestModel):
    """Revisión humana. No cambia kind ni confidence: un humano no convierte un candidato en
    un enlace físico; solo acepta, rechaza (lo oculta del grafo por defecto) o lo devuelve a
    sin revisar."""

    review_state: ReviewState
    note: str | None = Field(default=None, max_length=500, pattern=_PLAIN)
    version: int = Field(ge=1, le=2_147_483_647)


class TopologyRebuildRequest(RequestModel):
    site_id: UUID | None = None
