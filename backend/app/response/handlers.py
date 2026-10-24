"""Handlers de las acciones de servidor del catálogo (Fase 5D).

Cada handler reutiliza el servicio que ya existe para esa capacidad (Risk Engine, motor de
detección, motor de vulnerabilidades, discovery, incidentes, ciclo de vida): Response no
duplica lógica de negocio, solo la invoca con un objetivo y parámetros ya validados.

Los handlers no comprueban permisos ni estado del objetivo: eso lo hace la política común
(app/response/policy.py) ANTES de llegar aquí, igual para preview y ejecución. Un handler
que falla lanza ActionFailedError (código estable) o un SentraError del servicio llamado; el
motor lo registra como failed sin ocultarlo.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.exceptions import IncidentAlreadyLinkedError
from app.core.permissions import Permission
from app.detection.config import DetectionConfig
from app.detection.engine import DetectionEngine
from app.discovery.targets import TargetError
from app.incidents.workflow import incident_key, is_frozen
from app.models.alert import Alert, AlertStatus
from app.models.asset import Asset
from app.models.change import AssetChange
from app.models.detection import Detection, DetectionStatus
from app.models.event import EventLevel, SystemEvent
from app.models.incident import ACTIVE_STATUSES, Incident, IncidentAsset
from app.models.risk import AssetRisk
from app.models.threat_intel import ThreatIntelMatch
from app.models.user import User
from app.models.vulnerability import VulnerabilityFinding
from app.risk.config import RiskConfig
from app.risk.engine import RiskEngine
from app.schemas.incident import IncidentCreate, IncidentPromote
from app.services import audit_service
from app.services.alert_service import AlertThresholds
from app.services.asset_lifecycle_policy import LifecyclePolicy
from app.services.asset_lifecycle_service import AssetLifecycleService, credential_active
from app.services.audit_service import Actor
from app.services.incident_service import THREAT_MATCH_ACTIVE, IncidentService, Operator
from app.vulnerabilities import workflow as vuln_workflow
from app.vulnerabilities.engine import VulnerabilityConfig, VulnerabilityEngine
from app.vulnerabilities.queue import mark_dirty

# Límites de lo que una acción de evidencia guarda en su resultado (además del tope global
# RESPONSE_RESULT_MAX_KB): un timeline nunca copia la base de datos entera.
TIMELINE_PER_KIND = 50
TIMELINE_MAX_ITEMS = 200
TITLE_MAX = 200


@dataclass(frozen=True)
class Issue:
    """Bloqueo o aviso de la política: código estable + mensaje para la UI."""

    code: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message}


class ActionFailedError(Exception):
    """La acción se intentó y falló: queda como failed con este código."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class ActionResult:
    summary: str
    data: dict[str, Any] = field(default_factory=dict)
    # Incidente creado o reutilizado: se enlaza a la ejecución para la trazabilidad.
    incident_id: int | None = None


@dataclass
class ActionContext:
    session: Session
    settings: Settings
    actor: Actor
    user: User | None
    permissions: frozenset[Permission]
    params: BaseModel
    now: datetime
    asset: Asset | None = None
    incident: Incident | None = None
    detection: Detection | None = None
    # Fábrica del runner de discovery (inyectable en tests); solo la usa start_discovery.
    discovery_runner: Callable[[], Any] | None = None
    # Fase 6E.6: investigación de una recogida forense (models.forensics.Investigation).
    investigation: Any = None
    # Fase 6E.7: sesión de aislamiento que origina la orden (models.isolation.IsolationSession).
    isolation: Any = None


def _thresholds(settings: Settings) -> AlertThresholds:
    return AlertThresholds.from_settings(settings)


def _asset(ctx: ActionContext) -> Asset:
    if ctx.asset is None:  # la política ya lo garantiza; defensa si alguien llama directo
        raise ActionFailedError("target_missing", "The action needs an asset target")
    return ctx.asset


def agent_dispatch(ctx: ActionContext) -> ActionResult:
    """Marca de las acciones de agente: el motor encola un comando y nunca llama aquí."""
    raise ActionFailedError("agent_action", "Agent actions are dispatched as commands")


# --- Reevaluaciones ------------------------------------------------------------------------------


def recalculate_risk(ctx: ActionContext) -> ActionResult:
    asset = _asset(ctx)
    run = RiskEngine(
        ctx.session, RiskConfig.from_settings(ctx.settings), _thresholds(ctx.settings)
    ).recalculate([asset.id], ctx.now)
    if run.errors:
        raise ActionFailedError("risk_calculation_failed", "The risk engine could not calculate")
    risk = ctx.session.get(AssetRisk, asset.id)
    score = risk.score if risk else None
    level = risk.level.value if risk else None
    return ActionResult(f"Riesgo recalculado: {score} ({level})", {"score": score, "level": level})


def reevaluate_detections(ctx: ActionContext) -> ActionResult:
    asset = _asset(ctx)
    hours = int(getattr(ctx.params, "hours", 24))
    # Sin reglas custom: solo se marcan señales para la próxima vuelta del motor (el job
    # carga las reglas). reevaluate() es idempotente: lo ya detectado no se duplica.
    engine = DetectionEngine(
        ctx.session, DetectionConfig.from_settings(ctx.settings), load_custom=False
    )
    queued = engine.reevaluate(ctx.now - timedelta(hours=hours), asset.id)
    return ActionResult(
        f"{queued} señales en cola para reevaluar (últimas {hours} h)",
        {"signals_queued": queued, "hours": hours},
    )


def refresh_threat_context(ctx: ActionContext) -> ActionResult:
    asset = _asset(ctx)
    mark_dirty(ctx.session, [asset.id], "threat_intel")
    active = ctx.session.scalar(
        select(func.count())
        .select_from(VulnerabilityFinding)
        .where(
            VulnerabilityFinding.asset_id == asset.id,
            VulnerabilityFinding.status.in_(vuln_workflow.ACTIVE_STATUSES),
        )
    )
    return ActionResult(
        f"Repriorización encolada para {active or 0} findings activos",
        {"queued": True, "active_findings": int(active or 0)},
    )


def reevaluate_vulnerabilities(ctx: ActionContext) -> ActionResult:
    asset = _asset(ctx)
    run = VulnerabilityEngine(
        ctx.session, VulnerabilityConfig.from_settings(ctx.settings), _thresholds(ctx.settings)
    ).evaluate([asset.id], ctx.now)
    data = run.as_dict()
    audit_service.record(
        ctx.session,
        ctx.actor,
        "vulnerability_evaluation_started",
        target_type="asset",
        target_id=asset.public_id,
        details={"mode": "immediate", "via": "response", **data},
        commit=False,
    )
    return ActionResult(
        f"Vulnerabilidades evaluadas: {data.get('created', 0)} nuevas,"
        f" {data.get('resolved', 0)} resueltas",
        data,
    )


# --- Discovery -----------------------------------------------------------------------------------


def check_discovery(ctx: ActionContext) -> list[Issue]:
    asset = ctx.asset
    if asset is None:
        return []
    scope = ctx.settings.discovery_scope()
    if not scope.enabled:
        return [Issue("discovery_disabled", "Discovery is disabled on this server")]
    try:
        scope.resolve(asset.primary_ip)
    except (TargetError, ValueError):
        return [
            Issue(
                "discovery_target_refused",
                "The asset address is outside the networks allowed for discovery",
            )
        ]
    return []


def start_discovery(ctx: ActionContext) -> ActionResult:
    asset = _asset(ctx)
    if ctx.discovery_runner is None:
        raise ActionFailedError("discovery_unavailable", "Discovery runner unavailable")
    # Un solo host: la IP principal del activo, revalidada por el runner contra la allowlist.
    job_id = ctx.discovery_runner().submit(asset.primary_ip, "response")
    return ActionResult(
        f"Discovery encolado para {asset.primary_ip}",
        {"job_id": str(job_id), "target": asset.primary_ip},
    )


# --- Evidencia (solo lectura) ---------------------------------------------------------------


def _clip(value: object, limit: int = TITLE_MAX) -> str:
    return " ".join(str(value or "").split())[:limit]


def collect_timeline(ctx: ActionContext) -> ActionResult:
    asset = _asset(ctx)
    hours = int(getattr(ctx.params, "hours", 24))
    since = ctx.now - timedelta(hours=hours)
    session = ctx.session
    items: list[dict[str, Any]] = []
    for detection in session.scalars(
        select(Detection)
        .where(Detection.asset_id == asset.id, Detection.last_seen_at >= since)
        .order_by(Detection.last_seen_at.desc())
        .limit(TIMELINE_PER_KIND)
    ):
        items.append(
            {
                "at": detection.last_seen_at.isoformat(),
                "kind": "detection",
                "title": _clip(detection.title),
                "severity": detection.severity.value,
                "status": detection.status.value,
                "ref": str(detection.public_id),
            }
        )
    for alert in session.scalars(
        select(Alert)
        .where(Alert.asset_id == asset.id, Alert.opened_at >= since)
        .order_by(Alert.opened_at.desc())
        .limit(TIMELINE_PER_KIND)
    ):
        items.append(
            {
                "at": alert.opened_at.isoformat(),
                "kind": "alert",
                "title": _clip(alert.message),
                "severity": alert.severity.value,
                "status": alert.status.value,
                "ref": str(alert.public_id),
            }
        )
    for change in session.scalars(
        select(AssetChange)
        .where(AssetChange.asset_id == asset.id, AssetChange.detected_at >= since)
        .order_by(AssetChange.detected_at.desc())
        .limit(TIMELINE_PER_KIND)
    ):
        items.append(
            {
                "at": change.detected_at.isoformat(),
                "kind": "change",
                "title": _clip(f"{change.category.value} {change.kind.value}: {change.item}"),
                "ref": str(change.public_id),
            }
        )
    notable = (EventLevel.WARNING, EventLevel.ERROR, EventLevel.CRITICAL)
    for event in session.scalars(
        select(SystemEvent)
        .where(
            SystemEvent.asset_id == asset.id,
            SystemEvent.occurred_at >= since,
            SystemEvent.level.in_(notable),
        )
        .order_by(SystemEvent.occurred_at.desc())
        .limit(TIMELINE_PER_KIND)
    ):
        items.append(
            {
                "at": event.occurred_at.isoformat(),
                "kind": "event",
                "title": _clip(f"{event.provider} {event.event_code or ''}: {event.message}"),
                "severity": event.level.value,
                "ref": str(event.public_id),
            }
        )
    events_total = session.scalar(
        select(func.count())
        .select_from(SystemEvent)
        .where(SystemEvent.asset_id == asset.id, SystemEvent.occurred_at >= since)
    )
    items.sort(key=lambda item: item["at"], reverse=True)
    items = items[:TIMELINE_MAX_ITEMS]
    counts = {
        kind: sum(1 for i in items if i["kind"] == kind)
        for kind in ("detection", "alert", "change", "event")
    }
    return ActionResult(
        f"Timeline de {hours} h: {len(items)} elementos",
        {
            "hours": hours,
            "since": since.isoformat(),
            "counts": counts,
            "events_in_window": int(events_total or 0),
            "items": items,
        },
    )


def collect_response_bundle(ctx: ActionContext) -> ActionResult:
    asset = _asset(ctx)
    session = ctx.session

    def count(model: Any, *where: Any) -> int:
        return int(session.scalar(select(func.count()).select_from(model).where(*where)) or 0)

    risk = session.get(AssetRisk, asset.id)
    findings = dict(
        session.execute(
            select(VulnerabilityFinding.severity, func.count())
            .where(
                VulnerabilityFinding.asset_id == asset.id,
                VulnerabilityFinding.status.in_(vuln_workflow.ACTIVE_STATUSES),
            )
            .group_by(VulnerabilityFinding.severity)
        ).all()
    )
    data = {
        "asset": {
            "name": asset.display_name,
            "primary_ip": asset.primary_ip,
            "os": asset.os_name,
            "os_version": asset.os_version,
            "monitoring": asset.monitoring_method.value,
            "status": asset.status.value,
            "last_seen_at": asset.last_seen_at.isoformat() if asset.last_seen_at else None,
            "archived": asset.is_archived,
            "criticality": asset.criticality.value,
        },
        "agent": {
            "present": asset.agent_id is not None,
            "version": asset.agent_version,
            "credential_active": credential_active(asset),
            "capabilities": sorted(asset.agent_capabilities or []),
        },
        "risk": {"score": risk.score, "level": risk.level.value} if risk else None,
        "open_detections": count(
            Detection, Detection.asset_id == asset.id, Detection.status != DetectionStatus.RESOLVED
        ),
        "open_alerts": count(
            Alert, Alert.asset_id == asset.id, Alert.status != AlertStatus.RESOLVED
        ),
        "active_findings": {str(k): int(v) for k, v in findings.items()},
        "active_threat_matches": count(
            ThreatIntelMatch,
            ThreatIntelMatch.asset_id == asset.id,
            ThreatIntelMatch.status.in_(THREAT_MATCH_ACTIVE),
        ),
        "active_incidents": count(
            Incident,
            Incident.id.in_(
                select(IncidentAsset.incident_id).where(IncidentAsset.asset_id == asset.id)
            ),
            Incident.status.in_(ACTIVE_STATUSES),
        ),
    }
    return ActionResult(
        f"Resumen de {asset.display_name}: {data['open_detections']} detecciones abiertas,"
        f" {data['active_incidents']} incidentes activos",
        data,
    )


# --- Casos ---------------------------------------------------------------------------------------


def _operator(ctx: ActionContext) -> Operator:
    if ctx.user is None:
        raise ActionFailedError("actor_required", "This action needs a dashboard user")
    return Operator(ctx.user, ctx.actor, Permission.INCIDENTS_ADMIN in ctx.permissions)


def open_incident(ctx: ActionContext) -> ActionResult:
    asset = _asset(ctx)
    service = IncidentService(ctx.session, _operator(ctx))
    title = getattr(ctx.params, "title", None)
    severity = ctx.params.severity  # type: ignore[attr-defined]
    priority = ctx.params.priority  # type: ignore[attr-defined]
    if ctx.detection is not None:
        try:
            incident = service.promote_detection(
                ctx.detection.public_id, IncidentPromote(title=title, priority=priority)
            )
        except IncidentAlreadyLinkedError as exc:
            # La detección ya está en un caso activo: se devuelve ese caso en vez de abrir un
            # duplicado (anti incident-flood de la Fase 4K).
            ctx.session.rollback()
            existing_id = (exc.details or [{}])[0].get("incident_id")
            existing = ctx.session.scalar(select(Incident).where(Incident.public_id == existing_id))
            if existing is None:
                raise ActionFailedError("incident_conflict", exc.message) from exc
            return ActionResult(
                f"La detección ya está en {incident_key(existing.number)}",
                {
                    "incident_id": str(existing.public_id),
                    "key": incident_key(existing.number),
                    "existing": True,
                },
                incident_id=existing.id,
            )
    else:
        incident = service.create(
            IncidentCreate(
                title=title or _clip(f"Response: {asset.display_name}", 200),
                severity=severity,
                priority=priority,
                asset_ids=[asset.public_id],
            )
        )
    key = incident_key(incident.number)
    return ActionResult(
        f"Incidente {key} abierto",
        {"incident_id": str(incident.public_id), "key": key, "existing": False},
        incident_id=incident.id,
    )


def check_incident_open(ctx: ActionContext) -> list[Issue]:
    if ctx.incident is not None and is_frozen(ctx.incident.status):
        return [Issue("incident_closed", "The incident is closed or merged")]
    return []


def add_incident_note(ctx: ActionContext) -> ActionResult:
    if ctx.incident is None:
        raise ActionFailedError("target_missing", "The action needs an incident target")
    body = ctx.params.body  # type: ignore[attr-defined]
    note = IncidentService(ctx.session, _operator(ctx)).add_note(ctx.incident.public_id, body)
    return ActionResult(
        f"Nota añadida a {incident_key(ctx.incident.number)}",
        {"note_id": str(note.public_id), "chars": len(body)},
        incident_id=ctx.incident.id,
    )


# --- Ciclo de vida -------------------------------------------------------------------------------


def check_archivable(ctx: ActionContext) -> list[Issue]:
    if ctx.asset is not None and credential_active(ctx.asset):
        return [Issue("agent_active", "Revoke the agent before archiving its asset")]
    return []


def archive_asset(ctx: ActionContext) -> ActionResult:
    asset = _asset(ctx)
    reason = ctx.params.reason  # type: ignore[attr-defined]
    service = AssetLifecycleService(
        ctx.session,
        timedelta(seconds=ctx.settings.heartbeat_timeout_seconds),
        LifecyclePolicy.from_settings(ctx.settings),
    )
    # Misma puerta que POST /assets/{id}/archive (5C.1): versión, agente activo, ya archivado.
    archived = service.archive(asset.public_id, reason, asset.lifecycle_version, ctx.actor)
    audit_service.record(
        ctx.session,
        ctx.actor,
        "asset_archived",
        target_type="asset",
        target_id=asset.public_id,
        details={
            "reason": archived.archive_reason,
            "managed": archived.ever_managed,
            "via": "response",
        },
        commit=False,
    )
    return ActionResult("Activo archivado", {"archived": True})


# --- Fase 6E.6/6E.7: comprobaciones previas -------------------------------------------------------


def check_investigation(ctx: ActionContext) -> list[Issue]:
    """Una recogida forense siempre pertenece a una investigación abierta del mismo activo:
    así toda evidencia tiene caso, operador y cadena de custodia desde el primer momento."""
    investigation = ctx.investigation
    if investigation is None:
        return [Issue("investigation_required", "Forensic actions run inside an investigation")]
    if investigation.status != "open":
        return [Issue("investigation_closed", "The investigation is closed")]
    if ctx.asset is None or investigation.asset_id != ctx.asset.id:
        return [Issue("investigation_mismatch", "The investigation belongs to another asset")]
    return []


def check_file_path(ctx: ActionContext) -> list[Issue]:
    issues = check_investigation(ctx)
    path = str(getattr(ctx.params, "path", ""))
    os_name = (ctx.asset.os_name or "").lower() if ctx.asset is not None else ""
    windows_style = len(path) > 2 and path[1] == ":" and path[2] in "\\/"
    if os_name.startswith("windows") and not windows_style:
        issues.append(Issue("path_platform_mismatch", "Use an absolute Windows path (C:\\...)"))
    elif os_name and not os_name.startswith("windows") and not path.startswith("/"):
        issues.append(Issue("path_platform_mismatch", "Use an absolute POSIX path (/...)"))
    return issues


def check_isolation_session(ctx: ActionContext) -> list[Issue]:
    """isolate_host y release_isolation solo salen del flujo de aislamiento (sesión con
    confirmación, duración y previsualización), nunca de una ejecución suelta de Response."""
    session = ctx.isolation
    if session is None:
        return [Issue("isolation_session_required", "Isolation is managed from its own flow")]
    if ctx.asset is None or session.asset_id != ctx.asset.id:
        return [Issue("isolation_mismatch", "The isolation session belongs to another asset")]
    return []
