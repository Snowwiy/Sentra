"""Catálogo cerrado del Analyst Tool Engine (Fase 7A, docs/analyst-tool-engine.md).

Cada herramienta reutiliza el servicio que ya existe para su dominio (activos, telemetría,
árbol de procesos, eventos, detecciones, vulnerabilidades, exposición, riesgo, topología,
identidad, Response, incidentes): el motor no duplica reglas de negocio, solo las expone con
un contrato tipado, acotado y auditado.

Tres categorías:
- read: lecturas puras. El motor las ejecuta en una transacción READ ONLY con
  statement_timeout, así que no pueden escribir aunque un servicio lo intentara.
- investigation: preparan o recogen evidencia sin cambiar el estado de Sentra salvo dejar
  constancia (vista previa de Response, discovery acotado de un host, recogida forense de
  solo lectura en una investigación). Las que delegan crean una ejecución de Response.
- action: cambian algo (ejecutar una acción de Response, abrir o enlazar un caso). Siempre
  vista previa + confirmación explícita; nunca contención (aislar/liberar), que solo existe
  en su flujo propio con sus dobles confirmaciones.

Ninguna herramienta acepta comandos, scripts, rutas de ejecutable, URLs ni SQL
(registry.validate_registry lo comprueba al importar).
"""

from datetime import datetime, timedelta
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field
from sqlalchemy import select

from app.core.exceptions import NotFoundError, PermissionDeniedError
from app.core.permissions import Permission
from app.detection.config import DetectionConfig
from app.dhcp.service import DhcpService
from app.endpoint.service import EndpointReadService
from app.models.alert import Alert
from app.models.asset import Asset
from app.models.change import ChangeCategory
from app.models.detection import (
    Detection,
    DetectionConfidence,
    DetectionSeverity,
    DetectionStatus,
)
from app.models.event import EventLevel, SystemEvent
from app.models.incident import Incident, IncidentLevel
from app.models.response import ResponseExecution
from app.models.site import Site
from app.models.tool import ToolExecution
from app.models.vulnerability import VulnerabilityFinding
from app.repositories.asset_repository import AssetRepository
from app.response.catalog import ACTIONS, FORENSIC_ACTIONS, LookbackParams
from app.response.handlers import ActionContext, collect_response_bundle, collect_timeline
from app.risk.config import RiskConfig
from app.schemas.asset import AssetList, AssetRead
from app.schemas.change import ChangeList
from app.schemas.common import RequestModel, ResponseModel
from app.schemas.detection import DetectionDetail, DetectionList
from app.schemas.dhcp import AssetIdentityHistory, AssetIdentityRead
from app.schemas.discovery import ExposureRead
from app.schemas.endpoint import ProcessInstanceDetail, ProcessTree
from app.schemas.event import EventList, EventRead
from app.schemas.incident import IncidentAssign, IncidentCreate, IncidentPromote
from app.schemas.response import ExecutionList, ExecutionOut, ExecutionRequest, PreviewOut
from app.schemas.risk import RiskAssetDetail
from app.schemas.telemetry import TelemetryHistory
from app.schemas.topology_history import NetworkChangeList
from app.schemas.vulnerability import FindingList
from app.services.alert_service import AlertThresholds
from app.services.asset_lifecycle_policy import LifecyclePolicy
from app.services.asset_service import AssetFilter, AssetService
from app.services.detection_service import DetectionFilter, DetectionService
from app.services.exposure_service import ExposureService
from app.services.incident_service import IncidentService
from app.services.incident_service import Operator as IncidentOperator
from app.services.inventory_service import InventoryService
from app.services.response_service import Operator as ResponseOperator
from app.services.response_service import ResponseService
from app.services.risk_service import RiskService
from app.services.telemetry_service import TelemetryService
from app.services.vulnerability_service import FindingFilter, VulnerabilityService
from app.tools.registry import (
    EvidenceRef,
    ToolContext,
    ToolDefinition,
    ToolOutput,
    ToolPreview,
    validate_registry,
)
from app.topology.history_service import TopologyHistoryService
from app.vulnerabilities.engine import VulnerabilityConfig

READ = Permission.MONITORING_READ
# Topes de las herramientas (además de los propios de cada servicio).
MAX_HOURS = 168
EVIDENCE_REFS = 25


# --- Utilidades -------------------------------------------------------------------------------


def _heartbeat(ctx: ToolContext) -> timedelta:
    return timedelta(seconds=ctx.settings.heartbeat_timeout_seconds)


def load_asset(ctx: ToolContext, public_id: UUID) -> Asset:
    """Activo dentro del alcance de site pedido (fuera de él = 404, sin revelar que existe)."""
    asset = AssetRepository(ctx.session).get_by_public_id(public_id)
    if asset is None or (ctx.site_id is not None and asset.site_id != ctx.site_id):
        raise NotFoundError("Asset not found")
    return asset


def _incident(ctx: ToolContext, public_id: UUID) -> Incident:
    incident = ctx.session.scalar(select(Incident).where(Incident.public_id == public_id))
    if incident is None:
        raise NotFoundError("Incident not found")
    return incident


def _response(ctx: ToolContext) -> ResponseService:
    return ResponseService(ctx.session, ctx.settings, ctx.discovery_runner)


def _response_op(ctx: ToolContext) -> ResponseOperator:
    return ResponseOperator(ctx.user, ctx.actor, ctx.permissions)


def _incident_op(ctx: ToolContext) -> IncidentOperator:
    return IncidentOperator(ctx.user, ctx.actor, Permission.INCIDENTS_ADMIN in ctx.permissions)


def _ref(
    kind: str, public_id: object, label: str | None = None, at: datetime | None = None
) -> EvidenceRef:
    return EvidenceRef(kind, str(public_id), (label or "")[:200] or None, at)


def _asset_ref(asset: Asset) -> EvidenceRef:
    return _ref("asset", asset.public_id, asset.display_name, asset.last_seen_at)


def _response_disabled(settings: Any) -> str | None:
    return None if settings.response_enabled else "response_disabled"


class AssetTarget(RequestModel):
    asset_id: UUID


# --- 1. Activos y su historial ----------------------------------------------------------------


class AssetLookupIn(RequestModel):
    # Texto a buscar en etiqueta, nombre, DNS inverso, IP o MAC (no es una consulta SQL).
    text: str = Field(min_length=2, max_length=128)
    include_archived: bool = False
    limit: int = Field(default=20, ge=1, le=50)


def asset_lookup(ctx: ToolContext, params: AssetLookupIn) -> ToolOutput:
    service = AssetService(
        ctx.session, _heartbeat(ctx), LifecyclePolicy.from_settings(ctx.settings)
    )
    result = service.list_assets(
        AssetFilter(
            search=params.text,
            archived="include" if params.include_archived else "exclude",
            site_id=ctx.site_id,
        ),
        sort="name",
        limit=params.limit,
        offset=0,
        descending=False,
    )
    return ToolOutput(
        f"{result.total} activos coinciden con «{params.text}»",
        result,
        [
            _ref("asset", a.asset_id, a.display_name, a.last_seen_at)
            for a in result.items[:EVIDENCE_REFS]
        ],
        {"sources": ["assets"], "matched": result.total, "returned": len(result.items)},
    )


class AssetProfileOut(ResponseModel):
    asset: AssetRead
    risk: dict[str, Any] | None
    agent: dict[str, Any]
    open_detections: int
    open_alerts: int
    active_findings: dict[str, int]
    active_threat_matches: int
    active_incidents: int


def asset_profile(ctx: ToolContext, params: AssetTarget) -> ToolOutput:
    asset = load_asset(ctx, params.asset_id)
    service = AssetService(
        ctx.session, _heartbeat(ctx), LifecyclePolicy.from_settings(ctx.settings)
    )
    read = service.get_asset(asset.public_id)
    # Mismo resumen que la acción collect_response_bundle de Response (una sola definición).
    bundle = collect_response_bundle(_action_ctx(ctx, asset, LookbackParams())).data
    out = AssetProfileOut(
        asset=read,
        risk=bundle["risk"],
        agent=bundle["agent"],
        open_detections=bundle["open_detections"],
        open_alerts=bundle["open_alerts"],
        active_findings=bundle["active_findings"],
        active_threat_matches=bundle["active_threat_matches"],
        active_incidents=bundle["active_incidents"],
    )
    return ToolOutput(
        f"{asset.display_name}: {out.open_detections} detecciones abiertas,"
        f" {out.active_incidents} incidentes activos",
        out,
        [_asset_ref(asset)],
        {"sources": ["assets", "asset_risk", "detections", "alerts", "findings", "incidents"]},
    )


class AssetHistoryIn(RequestModel):
    asset_id: UUID
    category: ChangeCategory | None = None
    limit: int = Field(default=50, ge=1, le=200)


class AssetHistoryOut(ResponseModel):
    changes: ChangeList
    identity: AssetIdentityHistory


def asset_history(ctx: ToolContext, params: AssetHistoryIn) -> ToolOutput:
    asset = load_asset(ctx, params.asset_id)
    detection = DetectionConfig.from_settings(ctx.settings)
    changes = InventoryService(
        ctx.session, AlertThresholds.from_settings(ctx.settings), detection
    ).changes(asset.public_id, params.category, params.limit)
    identity = DhcpService(ctx.session, ctx.settings).identity_history(
        asset.public_id, None, params.limit
    )
    out = AssetHistoryOut(changes=changes, identity=identity)
    refs = [_asset_ref(asset)] + [
        _ref("change", c.change_id, c.item, c.detected_at) for c in changes.items[:EVIDENCE_REFS]
    ]
    return ToolOutput(
        f"{len(changes.items)} cambios y {len(identity.items)} cambios de identidad",
        out,
        refs,
        {"sources": ["asset_changes", "asset_identity_history"], "limit": params.limit},
    )


# --- 2. Telemetría ----------------------------------------------------------------------------


class TelemetryIn(RequestModel):
    asset_id: UUID
    limit: int = Field(default=60, ge=1, le=500)


def telemetry_recent(ctx: ToolContext, params: TelemetryIn) -> ToolOutput:
    asset = load_asset(ctx, params.asset_id)
    history = TelemetryService(ctx.session, AlertThresholds.from_settings(ctx.settings)).history(
        asset.public_id, params.limit
    )
    return ToolOutput(
        f"{len(history.items)} muestras de telemetría de {asset.display_name}",
        history,
        [_asset_ref(asset)],
        {"sources": ["telemetry_samples"], "limit": params.limit},
    )


# --- 3. Procesos y árbol de procesos ----------------------------------------------------------


class ProcessTreeIn(RequestModel):
    asset_id: UUID
    # Instancia cuyos hijos se piden (32 hex, como en la API del árbol).
    parent: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")
    at: datetime | None = None
    search: str | None = Field(default=None, min_length=1, max_length=128)
    limit: int = Field(default=100, ge=1, le=200)


def process_tree(ctx: ToolContext, params: ProcessTreeIn) -> ToolOutput:
    asset = load_asset(ctx, params.asset_id)
    tree = EndpointReadService(ctx.session, ctx.settings).process_tree(
        asset.public_id, params.parent, params.at, params.search, params.limit
    )
    data = tree.model_dump(mode="json")
    nodes = data.get("items") or data.get("nodes") or []
    return ToolOutput(
        f"{len(nodes)} procesos en el nivel pedido de {asset.display_name}",
        tree,
        [_asset_ref(asset)],
        {"sources": ["process_instances"], "at": params.at.isoformat() if params.at else None},
    )


class ProcessInstanceIn(RequestModel):
    asset_id: UUID
    instance_key: str = Field(pattern=r"^[0-9a-f]{32}$")


def process_instance(ctx: ToolContext, params: ProcessInstanceIn) -> ToolOutput:
    asset = load_asset(ctx, params.asset_id)
    detail = EndpointReadService(ctx.session, ctx.settings).instance(
        asset.public_id, params.instance_key
    )
    return ToolOutput(
        f"Proceso {params.instance_key[:8]}… con sus antecesores",
        detail,
        [_asset_ref(asset), _ref("process", params.instance_key)],
        {"sources": ["process_instances", "endpoint_activity"]},
    )


# --- 4. Eventos de seguridad ------------------------------------------------------------------


class EventSearchIn(RequestModel):
    asset_id: UUID
    hours: int = Field(default=24, ge=1, le=MAX_HOURS)
    min_level: EventLevel | None = None
    channel: str | None = Field(default=None, min_length=1, max_length=255)
    event_code: int | None = Field(default=None, ge=0, le=65535)
    limit: int = Field(default=100, ge=1, le=200)


def events_search(ctx: ToolContext, params: EventSearchIn) -> ToolOutput:
    asset = load_asset(ctx, params.asset_id)
    since = ctx.now - timedelta(hours=params.hours)
    stmt = select(SystemEvent).where(
        SystemEvent.asset_id == asset.id, SystemEvent.occurred_at >= since
    )
    if params.min_level is not None:
        order = [EventLevel.INFO, EventLevel.WARNING, EventLevel.ERROR, EventLevel.CRITICAL]
        stmt = stmt.where(SystemEvent.level.in_(order[order.index(params.min_level) :]))
    if params.channel:
        stmt = stmt.where(SystemEvent.channel == params.channel)
    if params.event_code is not None:
        stmt = stmt.where(SystemEvent.event_code == params.event_code)
    rows = ctx.session.scalars(
        stmt.order_by(SystemEvent.occurred_at.desc(), SystemEvent.id.desc()).limit(params.limit + 1)
    ).all()
    items = [
        EventRead(
            event_id=e.public_id,
            asset_id=asset.public_id,
            hostname=asset.display_name,
            source=e.source,
            channel=e.channel,
            event_code=e.event_code,
            event_type=e.event_type,
            provider=e.provider,
            level=e.level,
            message=e.message,
            record_id=e.record_id,
            computer=e.computer,
            data=e.data,
            occurred_at=e.occurred_at,
        )
        for e in rows[: params.limit]
    ]
    out = EventList(items=items, total=len(items), has_more=len(rows) > params.limit)
    return ToolOutput(
        f"{len(items)} eventos en {params.hours} h" + (" (hay más)" if out.has_more else ""),
        out,
        [_asset_ref(asset)]
        + [_ref("event", e.event_id, e.provider, e.occurred_at) for e in items[:EVIDENCE_REFS]],
        {"sources": ["system_events"], "since": since.isoformat(), "hours": params.hours},
    )


# --- 5. Detecciones y correlaciones -----------------------------------------------------------


class DetectionSearchIn(RequestModel):
    asset_id: UUID | None = None
    status: DetectionStatus | None = None
    active: bool = True
    min_severity: DetectionSeverity | None = None
    confidence: DetectionConfidence | None = None
    rule_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9-]{3,64}$")
    hours: int | None = Field(default=None, ge=1, le=24 * 90)
    limit: int = Field(default=50, ge=1, le=200)


def detections_search(ctx: ToolContext, params: DetectionSearchIn) -> ToolOutput:
    asset = load_asset(ctx, params.asset_id) if params.asset_id else None
    result = DetectionService(ctx.session, DetectionConfig.from_settings(ctx.settings)).list(
        DetectionFilter(
            status=params.status,
            active=params.active,
            min_severity=params.min_severity,
            confidence=params.confidence,
            rule_id=params.rule_id,
            asset_public_id=asset.public_id if asset else None,
            since=ctx.now - timedelta(hours=params.hours) if params.hours else None,
            site_id=ctx.site_id,
        ),
        params.limit,
    )
    refs = [
        _ref("detection", d.detection_id, f"{d.rule_id} {d.title}", d.last_seen_at)
        for d in result.items[:EVIDENCE_REFS]
    ]
    return ToolOutput(
        f"{result.total} detecciones" + (f" de {asset.display_name}" if asset else ""),
        result,
        ([_asset_ref(asset)] if asset else []) + refs,
        {"sources": ["detections"], "returned": len(result.items)},
    )


class DetectionRef(RequestModel):
    detection_id: UUID


def detection_get(ctx: ToolContext, params: DetectionRef) -> ToolOutput:
    detail = DetectionService(ctx.session, DetectionConfig.from_settings(ctx.settings)).get(
        params.detection_id
    )
    asset = load_asset(ctx, detail.asset_id)
    refs = [_asset_ref(asset), _ref("detection", detail.detection_id, detail.rule_id)]
    return ToolOutput(
        f"{detail.rule_id} {detail.title} ({detail.severity}, confianza {detail.confidence})",
        detail,
        refs,
        {"sources": ["detections", "detection_evidence"], "rule_version": detail.rule_version},
    )


# --- 6. Vulnerabilidades ----------------------------------------------------------------------


class VulnAssessIn(RequestModel):
    asset_id: UUID
    active: bool = True
    limit: int = Field(default=50, ge=1, le=200)


def vulnerabilities_assess(ctx: ToolContext, params: VulnAssessIn) -> ToolOutput:
    asset = load_asset(ctx, params.asset_id)
    result = VulnerabilityService(
        ctx.session, VulnerabilityConfig.from_settings(ctx.settings)
    ).list_findings(
        FindingFilter(asset_id=asset.id, active=params.active),
        "priority",
        True,
        params.limit,
        0,
    )
    refs = [_asset_ref(asset)] + [
        _ref("finding", f.finding_id, f.vulnerability_id, f.last_seen_at)
        for f in result.items[:EVIDENCE_REFS]
    ]
    return ToolOutput(
        f"{result.total} vulnerabilidades {'activas ' if params.active else ''}en"
        f" {asset.display_name}",
        result,
        refs,
        {"sources": ["vulnerability_findings", "vulnerability_intel"], "order": "priority"},
    )


# --- 7. Exposición y puertos ------------------------------------------------------------------


def exposure_ports(ctx: ToolContext, params: AssetTarget) -> ToolOutput:
    asset = load_asset(ctx, params.asset_id)
    exposure = ExposureService(ctx.session, ctx.settings).exposure(asset.public_id)
    data = exposure.model_dump(mode="json")
    ports = data.get("ports") or []
    return ToolOutput(
        f"{len(ports)} puertos registrados en {asset.display_name}",
        exposure,
        [_asset_ref(asset)],
        {"sources": ["asset_ports", "asset_inventories"]},
    )


# --- 8. Riesgo y contribuciones ---------------------------------------------------------------


def risk_explain(ctx: ToolContext, params: AssetTarget) -> ToolOutput:
    asset = load_asset(ctx, params.asset_id)
    detail = RiskService(
        ctx.session, RiskConfig.from_settings(ctx.settings), _heartbeat(ctx)
    ).detail(asset.public_id)
    refs = [_asset_ref(asset)] + [
        _ref("detection", d.detection_id, d.title) for d in detail.active_detections[:10]
    ]
    return ToolOutput(
        f"Riesgo {detail.score} ({detail.level}) con {len(detail.contributions)} contribuciones",
        detail,
        refs,
        {"sources": ["asset_risk", "risk_contributions"], "formula": detail.formula_version},
    )


# --- 9. Timeline -------------------------------------------------------------------------------


class TimelineIn(RequestModel):
    asset_id: UUID
    hours: int = Field(default=24, ge=1, le=MAX_HOURS)


class TimelineItem(ResponseModel):
    at: str
    kind: str
    title: str
    severity: str | None = None
    status: str | None = None
    ref: str


class TimelineOut(ResponseModel):
    hours: int
    since: str
    counts: dict[str, int]
    events_in_window: int
    items: list[TimelineItem]


def _action_ctx(ctx: ToolContext, asset: Asset, params: BaseModel) -> ActionContext:
    return ActionContext(
        session=ctx.session,
        settings=ctx.settings,
        actor=ctx.actor,
        user=ctx.user,
        permissions=ctx.permissions,
        params=params,
        now=ctx.now,
        asset=asset,
    )


def timeline_build(ctx: ToolContext, params: TimelineIn) -> ToolOutput:
    asset = load_asset(ctx, params.asset_id)
    # Misma reconstrucción que la acción collect_timeline (una sola definición del orden).
    result = collect_timeline(_action_ctx(ctx, asset, LookbackParams(hours=params.hours)))
    out = TimelineOut.model_validate(result.data)
    refs = [_asset_ref(asset)] + [
        _ref(item.kind, item.ref, item.title, datetime.fromisoformat(item.at))
        for item in out.items[:EVIDENCE_REFS]
    ]
    return ToolOutput(
        result.summary,
        out,
        refs,
        {"sources": ["detections", "alerts", "asset_changes", "system_events"]},
    )


# --- 10. Topología y cambios -------------------------------------------------------------------


class TopologyChangesIn(RequestModel):
    site_id: UUID | None = None
    asset_id: UUID | None = None
    days: int = Field(default=7, ge=1, le=90)
    limit: int = Field(default=100, ge=1, le=200)


def topology_changes(ctx: ToolContext, params: TopologyChangesIn) -> ToolOutput:
    asset = load_asset(ctx, params.asset_id) if params.asset_id else None
    if asset is not None:
        site = ctx.session.get(Site, asset.site_id)
    elif params.site_id is not None:
        site = ctx.session.scalar(select(Site).where(Site.public_id == params.site_id))
    else:
        site = ctx.session.get(Site, ctx.site_id) if ctx.site_id else _default_site(ctx)
    if site is None or (ctx.site_id is not None and site.id != ctx.site_id):
        raise NotFoundError("Site not found")
    since = ctx.now - timedelta(days=params.days)
    changes = TopologyHistoryService(ctx.session, ctx.settings).list_changes(
        site,
        change_type=None,
        status=None,
        subject=None,
        asset=asset.public_id if asset else None,
        start=since,
        end=None,
        subnet=None,
        limit=params.limit,
        offset=0,
    )
    data = changes.model_dump(mode="json")
    return ToolOutput(
        f"{data.get('total', len(data.get('items', [])))} cambios de red en {params.days} días"
        f" ({site.name})",
        changes,
        [_ref("site", site.public_id, site.name)] + ([_asset_ref(asset)] if asset else []),
        {"sources": ["network_changes"], "since": since.isoformat(), "site": site.name},
    )


def _default_site(ctx: ToolContext) -> Site | None:
    return ctx.session.scalar(select(Site).where(Site.is_default))


# --- 11. Identidad del dispositivo ------------------------------------------------------------


class IdentityEvidenceOut(ResponseModel):
    identity: AssetIdentityRead
    device_type_reason: str | None
    device_model: str | None
    probable_os: str | None
    evidence: list[dict[str, Any]]
    observations: dict[str, Any]


def identity_evidence(ctx: ToolContext, params: AssetTarget) -> ToolOutput:
    asset = load_asset(ctx, params.asset_id)
    identity = DhcpService(ctx.session, ctx.settings).asset_identity(asset.public_id)
    observations = dict(asset.identity_observations or {})
    out = IdentityEvidenceOut(
        identity=identity,
        device_type_reason=asset.device_type_reason,
        device_model=asset.device_model,
        probable_os=asset.probable_os,
        evidence=list(asset.classification_evidence or []),
        observations=observations,
    )
    confidence = identity.classification_confidence or "desconocida"
    return ToolOutput(
        f"{identity.display_name}: tipo {identity.device_type or 'desconocido'},"
        f" confianza {confidence}, {len(out.evidence)} evidencias",
        out,
        [_asset_ref(asset)],
        {"sources": ["assets.classification_evidence", "identity_observations", "dhcp_leases"]},
    )


# --- 12. Discovery acotado (delegado en Response: start_discovery) -----------------------------


class ScanHostIn(RequestModel):
    asset_id: UUID
    reason: str | None = Field(default=None, min_length=3, max_length=500)


class DelegatedOut(ResponseModel):
    execution: ExecutionOut


def _delegate(
    ctx: ToolContext,
    action_id: str,
    target_type: Literal["asset", "incident"],
    target_id: UUID,
    parameters: dict[str, Any],
    *,
    reason: str | None,
    confirm: bool,
    investigation_id: UUID | None = None,
    detection_id: UUID | None = None,
) -> ToolOutput:
    execution = _response(ctx).execute(
        _response_op(ctx),
        ExecutionRequest(
            action_id=action_id,
            target_type=target_type,
            target_id=target_id,
            parameters=parameters,
            incident_id=ctx.incident_public_id,
            detection_id=detection_id,
            investigation_id=investigation_id,
            confirm=confirm,
            reason=reason,
            idempotency_key=ctx.idempotency_key,
        ),
    )

    response_pk = ctx.session.scalar(
        select(ResponseExecution.id).where(ResponseExecution.public_id == execution.execution_id)
    )
    refs = [_ref("response_execution", execution.execution_id, execution.action_name)]
    if execution.asset_id:
        refs.append(_ref("asset", execution.asset_id, execution.target_label))
    return ToolOutput(
        f"{execution.action_name}: {execution.status}"
        + (" (ya existía)" if execution.deduplicated else ""),
        DelegatedOut(execution=execution),
        refs,
        {"sources": ["response_executions"], "delegated_action": action_id},
        response_execution_id=response_pk,
    )


def discovery_scan_host(ctx: ToolContext, params: ScanHostIn) -> ToolOutput:
    asset = load_asset(ctx, params.asset_id)
    return _delegate(
        ctx, "start_discovery", "asset", asset.public_id, {}, reason=params.reason, confirm=False
    )


# --- 13. Recogida forense autorizada ------------------------------------------------------------

ForensicAction = Literal[
    "forensic_processes",
    "forensic_connections",
    "forensic_services",
    "forensic_scheduled_tasks",
    "forensic_persistence",
    "forensic_sessions",
    "forensic_network_config",
    "forensic_firewall_state",
]


class ForensicCollectIn(RequestModel):
    asset_id: UUID
    investigation_id: UUID
    action_id: ForensicAction
    reason: str | None = Field(default=None, min_length=3, max_length=500)


def forensics_collect(ctx: ToolContext, params: ForensicCollectIn) -> ToolOutput:
    asset = load_asset(ctx, params.asset_id)
    return _delegate(
        ctx,
        params.action_id,
        "asset",
        asset.public_id,
        {},
        reason=params.reason,
        confirm=False,
        investigation_id=params.investigation_id,
    )


# --- 14. Preparar respuestas e investigaciones --------------------------------------------------

# Acciones que las herramientas pueden preparar o ejecutar: el catálogo de Response salvo la
# contención (aislar/liberar solo desde su flujo con dobles confirmaciones) y lo reservado.
DELEGABLE_ACTIONS = tuple(
    sorted(
        action.id
        for action in ACTIONS.values()
        if action.available and action.category != "containment"
    )
)


class ResponsePrepareIn(RequestModel):
    action_id: str = Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")
    target_type: Literal["asset", "incident"] = "asset"
    target_id: UUID
    # Parámetros de la acción: los valida el modelo cerrado de la acción (extra=forbid).
    parameters: dict[str, Any] = Field(default_factory=dict)
    detection_id: UUID | None = None
    investigation_id: UUID | None = None


class ResponsePrepareOut(ResponseModel):
    preview: PreviewOut
    delegable: bool


def _check_delegable(action_id: str) -> None:
    if action_id not in DELEGABLE_ACTIONS:
        raise NotFoundError("Unknown or non-delegable response action")


def _target_in_scope(ctx: ToolContext, target_type: str, target_id: UUID) -> None:
    if target_type == "asset":
        load_asset(ctx, target_id)
    else:
        _incident(ctx, target_id)


def response_prepare(ctx: ToolContext, params: ResponsePrepareIn) -> ToolOutput:
    _check_delegable(params.action_id)
    _target_in_scope(ctx, params.target_type, params.target_id)
    preview = _response(ctx).preview(
        _response_op(ctx),
        ExecutionRequest(
            action_id=params.action_id,
            target_type=params.target_type,
            target_id=params.target_id,
            parameters=params.parameters,
            incident_id=ctx.incident_public_id,
            detection_id=params.detection_id,
            investigation_id=params.investigation_id,
        ),
    )
    out = ResponsePrepareOut(preview=preview, delegable=True)
    verdict = "permitida" if preview.allowed else f"bloqueada ({len(preview.blockers)})"
    return ToolOutput(
        f"{preview.action_name} sobre {preview.target_label}: {verdict}",
        out,
        [_ref(params.target_type, params.target_id, preview.target_label)],
        {"sources": ["response_policy"], "risk_level": preview.risk_level},
    )


# --- Acción: ejecutar una acción de Response tras vista previa -----------------------------------


class ResponseExecuteIn(ResponsePrepareIn):
    reason: str | None = Field(default=None, min_length=3, max_length=500)


def _response_request(
    ctx: ToolContext, params: ResponseExecuteIn, confirm: bool
) -> ExecutionRequest:
    return ExecutionRequest(
        action_id=params.action_id,
        target_type=params.target_type,
        target_id=params.target_id,
        parameters=params.parameters,
        incident_id=ctx.incident_public_id,
        detection_id=params.detection_id,
        investigation_id=params.investigation_id,
        confirm=confirm,
        reason=params.reason,
        idempotency_key=ctx.idempotency_key,
    )


def response_execute_preview(ctx: ToolContext, params: ResponseExecuteIn) -> ToolPreview:
    _check_delegable(params.action_id)
    _target_in_scope(ctx, params.target_type, params.target_id)
    preview = _response(ctx).preview(_response_op(ctx), _response_request(ctx, params, False))
    return ToolPreview(
        summary=f"{preview.action_name} sobre {preview.target_label} (riesgo {preview.risk_level})",
        allowed=preview.allowed,
        effects=[preview.expected_effect, *preview.preconditions],
        blockers=[b.model_dump() for b in preview.blockers],
        warnings=[w.model_dump() for w in preview.warnings],
        data=preview.model_dump(mode="json"),
    )


def response_execute(ctx: ToolContext, params: ResponseExecuteIn) -> ToolOutput:
    _check_delegable(params.action_id)
    _target_in_scope(ctx, params.target_type, params.target_id)
    action = ACTIONS[params.action_id]
    return _delegate(
        ctx,
        params.action_id,
        params.target_type,
        params.target_id,
        params.parameters,
        reason=params.reason,
        # La confirmación de la herramienta ES la confirmación de la acción: solo se llega
        # aquí desde confirm() tras una vista previa vigente del mismo usuario o aprobador.
        confirm=action.requires_confirmation,
        investigation_id=params.investigation_id,
        detection_id=params.detection_id,
    )


# --- 15. Crear o vincular casos ------------------------------------------------------------------

CaseSource = Literal["detection", "alert", "finding", "asset"]


class CaseOpenIn(RequestModel):
    source: CaseSource
    source_id: UUID
    title: str | None = Field(default=None, min_length=3, max_length=200)
    priority: IncidentLevel | None = None
    # Solo para source=asset (sin detección de la que derivarla).
    severity: IncidentLevel = IncidentLevel.MEDIUM
    # Responsable: él mismo (null) u otro usuario (solo admin, política 4K).
    owner_user_id: UUID | None = None


class CaseOut(ResponseModel):
    incident_id: UUID
    key: str
    title: str
    status: str
    owner: str | None
    created: bool


def _case_out(ctx: ToolContext, incident: Incident, created: bool) -> CaseOut:
    from app.incidents.workflow import incident_key
    from app.models.user import User

    owner = ctx.session.get(User, incident.owner_user_id) if incident.owner_user_id else None
    return CaseOut(
        incident_id=incident.public_id,
        key=incident_key(incident.number),
        title=incident.title,
        status=incident.status.value,
        owner=owner.username if owner else None,
        created=created,
    )


def _existing_case(ctx: ToolContext, params: CaseOpenIn) -> Incident | None:
    """Caso activo que ya contiene la detección o alerta (no se duplica)."""
    from app.models.incident import ACTIVE_STATUSES, IncidentAlert, IncidentDetection

    if params.source == "detection":
        link = (
            select(IncidentDetection.incident_id)
            .join(Detection, Detection.id == IncidentDetection.detection_id)
            .where(Detection.public_id == params.source_id)
        )
    elif params.source == "alert":
        link = (
            select(IncidentAlert.incident_id)
            .join(Alert, Alert.id == IncidentAlert.alert_id)
            .where(Alert.public_id == params.source_id)
        )
    else:
        return None
    return ctx.session.scalar(
        select(Incident).where(Incident.id.in_(link), Incident.status.in_(ACTIVE_STATUSES))
    )


def _source_label(ctx: ToolContext, params: CaseOpenIn) -> str:
    if params.source == "detection":
        row = ctx.session.scalar(select(Detection).where(Detection.public_id == params.source_id))
        if row is None:
            raise NotFoundError("Detection not found")
        load_asset(ctx, _asset_public_id(ctx, row.asset_id))
        return f"{row.rule_id} {row.title}"
    if params.source == "alert":
        alert = ctx.session.scalar(select(Alert).where(Alert.public_id == params.source_id))
        if alert is None:
            raise NotFoundError("Alert not found")
        if alert.asset_id is not None:
            load_asset(ctx, _asset_public_id(ctx, alert.asset_id))
        return alert.message
    if params.source == "finding":
        finding = ctx.session.scalar(
            select(VulnerabilityFinding).where(VulnerabilityFinding.public_id == params.source_id)
        )
        if finding is None:
            raise NotFoundError("Finding not found")
        load_asset(ctx, _asset_public_id(ctx, finding.asset_id))
        return f"{finding.vuln_external_id} {finding.title}"
    return load_asset(ctx, params.source_id).display_name


def _asset_public_id(ctx: ToolContext, asset_pk: int) -> UUID:
    asset = ctx.session.get(Asset, asset_pk)
    if asset is None:
        raise NotFoundError("Asset not found")
    return asset.public_id


def case_open_preview(ctx: ToolContext, params: CaseOpenIn) -> ToolPreview:
    label = _source_label(ctx, params)
    existing = _existing_case(ctx, params)
    if existing is not None:
        out = _case_out(ctx, existing, False)
        return ToolPreview(
            summary=f"La {params.source} ya está en {out.key}: se reutilizará ese caso",
            allowed=True,
            effects=[f"Sin caso nuevo: se devuelve {out.key}"],
            data={"existing": out.model_dump(mode="json"), "source": label},
        )
    effects = [f"Se crea un incidente desde {params.source}: {label[:120]}"]
    if params.owner_user_id is not None:
        effects.append("Se asigna al responsable indicado (política de asignación 4K)")
    return ToolPreview(
        summary=f"Abrir un caso desde {params.source}",
        allowed=True,
        effects=effects,
        data={"source": label, "priority": params.priority, "severity": params.severity},
    )


def case_open(ctx: ToolContext, params: CaseOpenIn) -> ToolOutput:
    _source_label(ctx, params)
    existing = _existing_case(ctx, params)
    service = IncidentService(ctx.session, _incident_op(ctx))
    if existing is not None:
        incident, created = existing, False
    else:
        promote = IncidentPromote(title=params.title, priority=params.priority)
        if params.source == "detection":
            incident = service.promote_detection(params.source_id, promote)
        elif params.source == "alert":
            incident = service.promote_alert(params.source_id, promote)
        elif params.source == "finding":
            incident = service.promote_vulnerability(params.source_id, promote)
        else:
            asset = load_asset(ctx, params.source_id)
            incident = service.create(
                IncidentCreate(
                    title=params.title or f"Investigación de {asset.display_name}"[:200],
                    severity=params.severity,
                    priority=params.priority or params.severity,
                    asset_ids=[asset.public_id],
                )
            )
        created = True
    # Con responsable explícito se asigna (política 4K); sin él, quien abre un caso nuevo y
    # sin dueño lo asume, como en la UI de incidentes.
    if params.owner_user_id is not None or (created and incident.owner_user_id is None):
        incident = service.assign(
            incident.public_id,
            IncidentAssign(version=incident.version, user_id=params.owner_user_id),
        )
    out = _case_out(ctx, incident, created)
    return ToolOutput(
        f"{out.key} {'creado' if created else 'reutilizado'}"
        + (f", responsable {out.owner}" if out.owner else ""),
        out,
        [_ref("incident", incident.public_id, out.key), _ref(params.source, params.source_id)],
        {"sources": ["incidents"], "source": params.source},
        incident_id=incident.id,
    )


EvidenceKind = Literal["detection", "alert", "asset", "tool_execution"]


class CaseLinkIn(RequestModel):
    incident_id: UUID
    kind: EvidenceKind
    evidence_id: UUID


class CaseLinkOut(ResponseModel):
    incident_id: UUID
    kind: str
    evidence_id: UUID
    linked: bool


def case_link_preview(ctx: ToolContext, params: CaseLinkIn) -> ToolPreview:
    incident = _incident(ctx, params.incident_id)
    _evidence_exists(ctx, params)
    from app.incidents.workflow import incident_key, is_frozen

    key = incident_key(incident.number)
    if is_frozen(incident.status):
        return ToolPreview(
            summary=f"{key} está cerrado o fusionado",
            allowed=False,
            blockers=[{"code": "incident_frozen", "message": "El caso no admite cambios"}],
        )
    return ToolPreview(
        summary=f"Vincular {params.kind} a {key}",
        allowed=True,
        effects=[f"Se añade la evidencia ({params.kind}) al caso y a su timeline"],
    )


def _evidence_exists(ctx: ToolContext, params: CaseLinkIn) -> None:
    if params.kind == "asset":
        load_asset(ctx, params.evidence_id)
        return
    model: Any = {"detection": Detection, "alert": Alert, "tool_execution": ToolExecution}[
        params.kind
    ]
    if ctx.session.scalar(select(model.id).where(model.public_id == params.evidence_id)) is None:
        raise NotFoundError(f"{params.kind} not found")


def case_link(ctx: ToolContext, params: CaseLinkIn) -> ToolOutput:
    incident = _incident(ctx, params.incident_id)
    _evidence_exists(ctx, params)
    service = IncidentService(ctx.session, _incident_op(ctx))
    if params.kind == "detection":
        linked = service.attach_detection(params.incident_id, params.evidence_id)
    elif params.kind == "alert":
        linked = service.attach_alert(params.incident_id, params.evidence_id)
    elif params.kind == "asset":
        linked = service.add_asset(params.incident_id, params.evidence_id)
    else:
        execution = ctx.session.scalar(
            select(ToolExecution).where(ToolExecution.public_id == params.evidence_id)
        )
        assert execution is not None  # noqa: S101  (comprobado arriba)
        if execution.actor_user_id != ctx.user.id and not ctx.has(Permission.TOOLS_MANAGE):
            raise PermissionDeniedError("Only your own tool executions can be linked")
        linked = execution.incident_id != incident.id
        execution.incident_id = incident.id
        service.add_note(
            params.incident_id,
            f"Evidencia de herramienta {execution.tool_id} v{execution.tool_version}"
            f" ({execution.public_id}): {execution.summary or execution.status}."
            f" SHA-256 de la salida: {execution.output_sha256 or 'sin salida'}",
        )
    out = CaseLinkOut(
        incident_id=params.incident_id,
        kind=params.kind,
        evidence_id=params.evidence_id,
        linked=bool(linked),
    )
    return ToolOutput(
        "Evidencia vinculada" if linked else "La evidencia ya estaba en el caso",
        out,
        [_ref("incident", params.incident_id), _ref(params.kind, params.evidence_id)],
        {"sources": ["incidents"]},
        incident_id=incident.id,
    )


# --- 16. Resultados de operaciones previas ------------------------------------------------------


class OperationsIn(RequestModel):
    asset_id: UUID | None = None
    incident_id: UUID | None = None
    tool_id: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_.]{2,63}$")
    limit: int = Field(default=20, ge=1, le=100)


class ToolRunSummary(ResponseModel):
    execution_id: UUID
    tool_id: str
    tool_version: int
    status: str
    actor: str
    summary: str | None
    output_sha256: str | None
    created_at: datetime
    finished_at: datetime | None


class OperationsOut(ResponseModel):
    tool_executions: list[ToolRunSummary]
    response_executions: ExecutionList


def operations_history(ctx: ToolContext, params: OperationsIn) -> ToolOutput:
    asset = load_asset(ctx, params.asset_id) if params.asset_id else None
    incident = _incident(ctx, params.incident_id) if params.incident_id else None
    query = select(ToolExecution)
    if not ctx.has(Permission.TOOLS_MANAGE):
        # Sin tools:manage solo se ven las ejecuciones propias (la entrada puede contener
        # filtros que otro analista no quiere compartir; la evidencia del caso sí se comparte
        # vinculándola).
        query = query.where(ToolExecution.actor_user_id == ctx.user.id)
    if asset is not None:
        query = query.where(ToolExecution.asset_id == asset.id)
    if incident is not None:
        query = query.where(ToolExecution.incident_id == incident.id)
    if params.tool_id:
        query = query.where(ToolExecution.tool_id == params.tool_id)
    if ctx.site_id is not None:
        query = query.where(ToolExecution.site_id == ctx.site_id)
    rows = ctx.session.scalars(
        query.order_by(ToolExecution.created_at.desc(), ToolExecution.id.desc()).limit(params.limit)
    ).all()
    runs = [
        ToolRunSummary(
            execution_id=r.public_id,
            tool_id=r.tool_id,
            tool_version=r.tool_version,
            status=r.status,
            actor=r.actor,
            summary=r.summary,
            output_sha256=r.output_sha256,
            created_at=r.created_at,
            finished_at=r.finished_at,
        )
        for r in rows
    ]
    if ctx.has(Permission.RESPONSE_READ):
        responses = _response(ctx).list_executions(
            asset_public_id=asset.public_id if asset else None,
            incident_public_id=incident.public_id if incident else None,
            limit=params.limit,
            site_id=ctx.site_id,
        )
    else:
        responses = ExecutionList(items=[], total=0)
    out = OperationsOut(tool_executions=runs, response_executions=responses)
    refs = [_ref("tool_execution", r.execution_id, r.tool_id, r.created_at) for r in runs[:10]]
    refs += [
        _ref("response_execution", e.execution_id, e.action_name, e.created_at)
        for e in responses.items[:10]
    ]
    return ToolOutput(
        f"{len(runs)} ejecuciones de herramientas y {responses.total} de Response",
        out,
        refs,
        {"sources": ["tool_executions", "response_executions"]},
    )


# --- Registro ------------------------------------------------------------------------------------

_T = Permission.TELEMETRY_READ

TOOLS: dict[str, ToolDefinition] = {
    tool.id: tool
    for tool in (
        ToolDefinition(
            id="asset.lookup",
            version=1,
            name="Buscar activos",
            description="Busca activos por IP, MAC, nombre o etiqueta dentro del site pedido.",
            category="read",
            scope="site",
            risk_level="none",
            permissions=(READ,),
            input_model=AssetLookupIn,
            output_model=AssetList,
            handler=asset_lookup,
            max_rows=50,
            sources=("assets",),
        ),
        ToolDefinition(
            id="asset.profile",
            version=1,
            name="Ficha del activo",
            description="Identidad, estado, agente, riesgo y contadores de trabajo abierto.",
            category="read",
            scope="asset",
            risk_level="none",
            permissions=(READ,),
            input_model=AssetTarget,
            output_model=AssetProfileOut,
            handler=asset_profile,
            sources=("assets", "asset_risk", "detections", "alerts", "findings", "incidents"),
        ),
        ToolDefinition(
            id="asset.history",
            version=1,
            name="Historial del activo",
            description="Cambios de inventario, red y estado, más el historial de identidad.",
            category="read",
            scope="asset",
            risk_level="none",
            permissions=(READ,),
            input_model=AssetHistoryIn,
            output_model=AssetHistoryOut,
            handler=asset_history,
            sources=("asset_changes", "asset_identity_history"),
        ),
        ToolDefinition(
            id="telemetry.recent",
            version=1,
            name="Telemetría reciente",
            description="Últimas muestras de CPU, RAM, disco y red del agente.",
            category="read",
            scope="asset",
            risk_level="none",
            permissions=(READ,),
            input_model=TelemetryIn,
            output_model=TelemetryHistory,
            handler=telemetry_recent,
            max_rows=500,
            sources=("telemetry_samples",),
        ),
        ToolDefinition(
            id="process.tree",
            version=1,
            name="Árbol de procesos",
            description="Un nivel del árbol de procesos (raíces o hijos), en un instante o"
            " reciente; con búsqueda por nombre, ruta o PID.",
            category="read",
            scope="asset",
            risk_level="none",
            permissions=(READ, _T),
            input_model=ProcessTreeIn,
            output_model=ProcessTree,
            handler=process_tree,
            required_capabilities=("agent>=0.5.0",),
            sources=("process_instances",),
        ),
        ToolDefinition(
            id="process.instance",
            version=1,
            name="Detalle de proceso",
            description="Una instancia de proceso con su cadena de antecesores, usuario, firma,"
            " hash y últimas conexiones.",
            category="read",
            scope="asset",
            risk_level="none",
            permissions=(READ, _T),
            input_model=ProcessInstanceIn,
            output_model=ProcessInstanceDetail,
            handler=process_instance,
            required_capabilities=("agent>=0.5.0",),
            sources=("process_instances", "endpoint_activity"),
        ),
        ToolDefinition(
            id="events.search",
            version=1,
            name="Eventos de seguridad",
            description="Eventos del activo en una ventana acotada, por nivel, canal o código.",
            category="read",
            scope="asset",
            risk_level="none",
            permissions=(READ,),
            input_model=EventSearchIn,
            output_model=EventList,
            handler=events_search,
            sources=("system_events",),
        ),
        ToolDefinition(
            id="detections.search",
            version=1,
            name="Buscar detecciones",
            description="Detecciones y correlaciones por activo, estado, severidad, regla o"
            " ventana temporal.",
            category="read",
            scope="site",
            risk_level="none",
            permissions=(READ,),
            input_model=DetectionSearchIn,
            output_model=DetectionList,
            handler=detections_search,
            sources=("detections",),
        ),
        ToolDefinition(
            id="detections.get",
            version=1,
            name="Detalle de detección",
            description="Una detección con su explicación, evidencias, timeline y contexto.",
            category="read",
            scope="asset",
            risk_level="none",
            permissions=(READ,),
            input_model=DetectionRef,
            output_model=DetectionDetail,
            handler=detection_get,
            sources=("detections", "detection_evidence"),
        ),
        ToolDefinition(
            id="vulnerabilities.assess",
            version=1,
            name="Vulnerabilidades del activo",
            description="Findings del activo ordenados por prioridad, con su estado técnico,"
            " razonamiento, KEV y EPSS.",
            category="read",
            scope="asset",
            risk_level="none",
            permissions=(READ, Permission.VULNERABILITIES_READ),
            input_model=VulnAssessIn,
            output_model=FindingList,
            handler=vulnerabilities_assess,
            sources=("vulnerability_findings", "vulnerability_intel"),
        ),
        ToolDefinition(
            id="exposure.ports",
            version=1,
            name="Exposición y puertos",
            description="Puertos abiertos y cerrados con su servicio, proceso propietario"
            " (si hay agente) y primera/última vez vistos.",
            category="read",
            scope="asset",
            risk_level="none",
            permissions=(READ,),
            input_model=AssetTarget,
            output_model=ExposureRead,
            handler=exposure_ports,
            sources=("asset_ports", "asset_inventories"),
        ),
        ToolDefinition(
            id="risk.explain",
            version=1,
            name="Riesgo y contribuciones",
            description="Score, nivel, confianza y ledger de contribuciones que lo suman.",
            category="read",
            scope="asset",
            risk_level="none",
            permissions=(READ,),
            input_model=AssetTarget,
            output_model=RiskAssetDetail,
            handler=risk_explain,
            sources=("asset_risk", "risk_contributions"),
        ),
        ToolDefinition(
            id="timeline.build",
            version=1,
            name="Reconstruir timeline",
            description="Detecciones, alertas, cambios y eventos relevantes en orden"
            " cronológico (máximo 200 elementos).",
            category="read",
            scope="asset",
            risk_level="none",
            permissions=(READ,),
            input_model=TimelineIn,
            output_model=TimelineOut,
            handler=timeline_build,
            sources=("detections", "alerts", "asset_changes", "system_events"),
        ),
        ToolDefinition(
            id="topology.changes",
            version=1,
            name="Cambios de topología",
            description="Cambios de red detectados (enlaces, dispositivos, direcciones) de un"
            " site o de un activo.",
            category="read",
            scope="site",
            risk_level="none",
            permissions=(READ,),
            input_model=TopologyChangesIn,
            output_model=NetworkChangeList,
            handler=topology_changes,
            sources=("network_changes",),
        ),
        ToolDefinition(
            id="identity.evidence",
            version=1,
            name="Evidencia de identificación",
            description="Por qué Sentra cree que el dispositivo es lo que dice: nombres"
            " observados, fabricante, leases DHCP, huellas y conflictos.",
            category="read",
            scope="asset",
            risk_level="none",
            permissions=(READ,),
            input_model=AssetTarget,
            output_model=IdentityEvidenceOut,
            handler=identity_evidence,
            sources=("assets", "dhcp_leases", "identity_observations"),
        ),
        ToolDefinition(
            id="operations.history",
            version=1,
            name="Operaciones previas",
            description="Ejecuciones anteriores de herramientas (propias, o todas con"
            " tools:manage) y de Response del activo o del caso.",
            category="read",
            scope="site",
            risk_level="none",
            permissions=(READ,),
            input_model=OperationsIn,
            output_model=OperationsOut,
            handler=operations_history,
            sources=("tool_executions", "response_executions"),
        ),
        ToolDefinition(
            id="discovery.scan_host",
            version=1,
            name="Escanear el host",
            description="Discovery de la IP principal del activo (un host), siempre dentro de"
            " las redes autorizadas. Delegado en la acción start_discovery de Response.",
            category="investigation",
            scope="asset",
            risk_level="low",
            permissions=(READ, Permission.DISCOVERY_RUN, Permission.RESPONSE_EXECUTE),
            input_model=ScanHostIn,
            output_model=DelegatedOut,
            handler=discovery_scan_host,
            availability=_response_disabled,
            timeout_seconds=30,
            sources=("response_executions", "discovery_jobs"),
        ),
        ToolDefinition(
            id="forensics.collect",
            version=1,
            name="Recogida forense",
            description="Recogida de solo lectura en el equipo (procesos, conexiones,"
            " servicios, persistencia...) dentro de una investigación abierta.",
            category="investigation",
            scope="asset",
            risk_level="low",
            permissions=(
                READ,
                Permission.FORENSICS_ACQUIRE,
                Permission.RESPONSE_EXECUTE,
            ),
            input_model=ForensicCollectIn,
            output_model=DelegatedOut,
            handler=forensics_collect,
            availability=_response_disabled,
            timeout_seconds=30,
            required_capabilities=tuple(sorted(FORENSIC_ACTIONS - {"forensic_file_metadata"})),
            sources=("response_executions", "forensic_artifacts"),
        ),
        ToolDefinition(
            id="response.prepare",
            version=1,
            name="Preparar respuesta",
            description="Vista previa de una acción del catálogo de Response: efecto,"
            " precondiciones, bloqueos y rol necesario. No ejecuta nada.",
            category="investigation",
            scope="asset",
            risk_level="none",
            permissions=(READ, Permission.RESPONSE_EXECUTE),
            input_model=ResponsePrepareIn,
            output_model=ResponsePrepareOut,
            handler=response_prepare,
            availability=_response_disabled,
            sources=("response_policy",),
        ),
        ToolDefinition(
            id="response.execute",
            version=1,
            name="Ejecutar acción de respuesta",
            description="Ejecuta una acción del catálogo de Response tras vista previa y"
            " confirmación. Nunca contención (aislar o liberar), que tiene su propio flujo.",
            category="action",
            scope="asset",
            risk_level="medium",
            permissions=(READ, Permission.RESPONSE_EXECUTE),
            input_model=ResponseExecuteIn,
            output_model=DelegatedOut,
            handler=response_execute,
            policy="preview_confirm",
            preview=response_execute_preview,
            availability=_response_disabled,
            timeout_seconds=60,
            sources=("response_executions",),
        ),
        ToolDefinition(
            id="case.open",
            version=1,
            name="Abrir caso",
            description="Abre un incidente desde una detección, alerta, vulnerabilidad o"
            " activo (o reutiliza el caso activo que ya la contiene) y lo asigna.",
            category="action",
            scope="asset",
            risk_level="low",
            permissions=(Permission.INCIDENTS_READ, Permission.INCIDENTS_MANAGE),
            input_model=CaseOpenIn,
            output_model=CaseOut,
            handler=case_open,
            policy="preview_confirm",
            preview=case_open_preview,
            sources=("incidents",),
        ),
        ToolDefinition(
            id="case.link_evidence",
            version=1,
            name="Vincular evidencia al caso",
            description="Añade una detección, alerta, activo o ejecución de herramienta a un"
            " caso abierto (con su SHA-256 en la nota del caso).",
            category="action",
            scope="incident",
            risk_level="low",
            permissions=(Permission.INCIDENTS_READ, Permission.INCIDENTS_MANAGE),
            input_model=CaseLinkIn,
            output_model=CaseLinkOut,
            handler=case_link,
            policy="preview_confirm",
            preview=case_link_preview,
            sources=("incidents",),
        ),
    )
}

# Herramientas que escriben (delegan en Response o casos): no se ejecutan en READ ONLY.
WRITING_TOOLS = frozenset(
    {"discovery.scan_host", "forensics.collect", "response.prepare"}
    | {tool.id for tool in TOOLS.values() if tool.category == "action"}
)

validate_registry(TOOLS)


def get_tool(tool_id: str) -> ToolDefinition | None:
    return TOOLS.get(tool_id)
