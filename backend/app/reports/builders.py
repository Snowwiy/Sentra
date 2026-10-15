"""Builders de datos de informes (Fase 5E): consultas acotadas → snapshot estructurado.

Reglas comunes a todos los tipos:
- Se ejecutan dentro de UNA transacción REPEATABLE READ de solo lectura abierta por el
  worker (services/report_service.py): todas las secciones ven la misma foto de la base de
  datos y `ctx.cutoff` es el inicio de esa transacción ("Datos a fecha de").
- Nunca SELECT * de tablas grandes: conteos con GROUP BY y filas con LIMIT max_rows + 1
  (para saber si se truncó) ordenadas de forma estable. Sin N+1: los datos relacionados de
  una lista se cargan con una consulta por relación, no por fila.
- Solo columnas seguras: nunca hashes de tokens del agente ni de identidad de máquina ni
  sesiones. Todo JSON libre pasa por app/reports/redaction.py.
- El Risk Engine, el Detection Engine y la política de ciclo de vida son la única fuente de
  verdad: aquí se LEEN sus resultados guardados, no se recalcula ninguna fórmula.

El resultado de cada builder es JSON simple (str, int, float, bool, None, listas y dicts),
apto para JSONB, hash canónico y render determinista.
"""

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import ColumnElement, String, and_, case, cast, false, func, literal, or_, select
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.asset import Asset, MonitoringMethod
from app.models.asset_lineage import AssetAgentLineage
from app.models.audit import AuditEvent
from app.models.change import AssetChange, ChangeCategory
from app.models.detection import Detection, DetectionEvidence
from app.models.incident import (
    ACTIVE_STATUSES as INCIDENT_ACTIVE,
)
from app.models.incident import (
    Incident,
    IncidentActivity,
    IncidentAlert,
    IncidentAsset,
    IncidentDetection,
    IncidentNote,
    IncidentThreatMatch,
    IncidentVulnerability,
)
from app.models.inventory import AssetInventory
from app.models.response import Playbook, PlaybookRun, ResponseExecution
from app.models.risk import AssetRisk, RiskContributionRecord, RiskSnapshot
from app.models.threat_intel import ThreatIndicator, ThreatIntelMatch, ThreatIntelSource
from app.models.user import User
from app.models.vulnerability import VulnerabilityFinding
from app.reports import summary as phrases
from app.reports.catalog import ReportDefinition
from app.reports.redaction import redact, redact_text
from app.reports.scope import DataScope
from app.repositories.asset_repository import effective_status_expr
from app.services.asset_lifecycle_policy import (
    LifecyclePolicy,
    evaluate,
    lifecycle_source,
    stale_condition,
)
from app.vulnerabilities.workflow import ACTIVE_STATUSES as VULN_ACTIVE

DETECTION_ACTIVE = ("open", "acknowledged")
FAILED_EXECUTIONS = ("failed", "timed_out")
# Acciones de auditoría que describen el ciclo de vida de activos (5C.1/5C.2).
LIFECYCLE_AUDIT_ACTIONS = (
    "asset_archived",
    "asset_restored",
    "asset_deleted",
    "asset_cleanup_executed",
    "agent_asset_reconciled",
    "agent_reassigned",
)
# Claves de details de esas entradas que se copian (identificadores, nunca credenciales).
_LIFECYCLE_DETAIL_KEYS = ("reason", "reconciliation_id", "reconciled_into", "display_name")
TOP_RISK_ASSETS = 10
EXECUTIVE_TOP_ASSETS = 5
MAX_EVIDENCE_PER_DETECTION = 5
MAX_RISK_POINTS = 200


# Alias corto para las frases de conteo de los resúmenes.
_cp = phrases.count_phrase


class BuildError(Exception):
    """Fallo controlado de un builder (código y mensaje seguros para el usuario)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class BuildContext:
    session: Session
    definition: ReportDefinition
    filters: dict[str, Any]
    time_from: datetime | None
    time_to: datetime | None
    cutoff: datetime
    scope: DataScope
    max_rows: int
    heartbeat_timeout: timedelta
    lifecycle_policy: LifecyclePolicy
    stale_inventory_hours: int
    # Cancelación/plazo: el worker la comprueba entre secciones (lanza si toca parar).
    checkpoint: Callable[[], None] = field(default=lambda: None)

    @property
    def start(self) -> datetime | None:
        return self.time_from

    @property
    def end(self) -> datetime:
        # El final del rango nunca supera la hora de corte de los datos.
        return min(self.time_to, self.cutoff) if self.time_to else self.cutoff


# --- Utilidades ---------------------------------------------------------------------------


def iso(value: datetime | None) -> str | None:
    return value.isoformat().replace("+00:00", "Z") if value is not None else None


def _uuid(value: UUID | None) -> str | None:
    return str(value) if value is not None else None


def _text(value: Any, limit: int = 300) -> str | None:
    if value is None:
        return None
    return redact_text(str(value), limit)


def _enum(value: Any) -> str | None:
    if value is None:
        return None
    return str(getattr(value, "value", value))


def _table(rows: list[dict[str, Any]], total: int, limit: int) -> dict[str, Any]:
    return {"total": total, "truncated": total > limit, "rows": rows[:limit]}


def _ids(values: Iterable[str] | None) -> list[UUID]:
    return [UUID(v) for v in values or ()]


def _in_range(column: Any, ctx: BuildContext) -> ColumnElement[bool]:
    condition: ColumnElement[bool] = column <= ctx.end
    if ctx.start is not None:
        condition = and_(column >= ctx.start, condition)
    return condition


def _overlaps(first: Any, last: Any, ctx: BuildContext) -> ColumnElement[bool]:
    """Actividad [first, last] que se solapa con el rango del informe."""
    condition: ColumnElement[bool] = first <= ctx.end
    if ctx.start is not None:
        condition = and_(last >= ctx.start, condition)
    return condition


def _platform_expr() -> Any:
    return func.lower(func.coalesce(Asset.os_name, Asset.probable_os, ""))


def _platform_condition(platforms: Sequence[str]) -> ColumnElement[bool]:
    platform = _platform_expr()
    parts: list[ColumnElement[bool]] = []
    if "windows" in platforms:
        parts.append(platform.like("%windows%"))
    if "linux" in platforms:
        parts.append(platform.like("%linux%"))
    if "other" in platforms:
        parts.append(and_(~platform.like("%windows%"), ~platform.like("%linux%")))
    return or_(*parts) if parts else false()


def platform_of(asset: Asset) -> str:
    name = (asset.os_name or asset.probable_os or "").lower()
    if "windows" in name:
        return "windows"
    if "linux" in name:
        return "linux"
    return "other"


def asset_conditions(ctx: BuildContext) -> list[ColumnElement[bool]]:
    """Condiciones comunes sobre `Asset`: visibilidad, archivados, ids y plataformas."""
    conditions = [ctx.scope.asset_condition()]
    if not ctx.filters.get("include_archived"):
        conditions.append(Asset.archived_at.is_(None))
    if ctx.filters.get("asset_ids"):
        conditions.append(Asset.public_id.in_(_ids(ctx.filters["asset_ids"])))
    if ctx.filters.get("platforms"):
        conditions.append(_platform_condition(ctx.filters["platforms"]))
    # Un activo creado después de la hora de corte no existía para este informe.
    conditions.append(Asset.first_seen_at <= ctx.cutoff)
    return conditions


def scoped_asset_ids(ctx: BuildContext) -> Any:
    """Subconsulta de ids internos de activos del alcance (sin JOIN en cada sección)."""
    return select(Asset.id).where(*asset_conditions(ctx))


def _names(session: Session, asset_ids: Iterable[int | None]) -> dict[int, tuple[str, str]]:
    ids = {i for i in asset_ids if i is not None}
    if not ids:
        return {}
    rows = session.execute(
        select(
            Asset.id,
            Asset.public_id,
            Asset.device_name,
            Asset.hostname,
            Asset.reverse_dns,
            Asset.primary_ip,
        ).where(Asset.id.in_(ids))
    ).all()
    return {
        r.id: (str(r.public_id), r.device_name or r.hostname or r.reverse_dns or r.primary_ip)
        for r in rows
    }


def _usernames(session: Session, user_ids: Iterable[int | None]) -> dict[int, str]:
    ids = {i for i in user_ids if i is not None}
    if not ids:
        return {}
    rows = session.execute(select(User.id, User.username).where(User.id.in_(ids))).all()
    return {user_id: username for user_id, username in rows}


def _count_by(session: Session, column: Any, *conditions: Any) -> dict[str, int]:
    rows = session.execute(
        select(cast(column, String), func.count()).where(*conditions).group_by(column)
    ).all()
    return {str(key): int(count) for key, count in rows if key is not None}


def _ordered(counts: dict[str, int], order: Sequence[str]) -> dict[str, int]:
    """Mismas claves en el mismo orden siempre (render determinista), con ceros."""
    out = {key: counts.get(key, 0) for key in order}
    for key in sorted(set(counts) - set(order)):
        out[key] = counts[key]
    return out


def _trend_unit(ctx: BuildContext) -> str:
    if ctx.start is None:
        return "week"
    return "day" if ctx.end - ctx.start <= timedelta(days=92) else "week"


def _trend(ctx: BuildContext, column: Any, *conditions: Any) -> list[dict[str, Any]]:
    """Serie por día (o semana en rangos largos) en UTC. La sesión fija TIME ZONE UTC."""
    unit = _trend_unit(ctx)
    bucket = func.date_trunc(unit, column)
    rows = ctx.session.execute(
        select(bucket, func.count())
        .where(_in_range(column, ctx), *conditions)
        .group_by(bucket)
        .order_by(bucket)
    ).all()
    return [{"bucket": iso(b), "count": int(c)} for b, c in rows]


# --- Activos --------------------------------------------------------------------------------


def _asset_source(asset: Asset) -> str:
    return lifecycle_source(asset).value


def asset_metrics(ctx: BuildContext) -> dict[str, Any]:
    session = ctx.session
    conditions = asset_conditions(ctx)
    status = effective_status_expr(ctx.cutoff, ctx.heartbeat_timeout)
    by_status = _ordered(
        {
            str(s): int(c)
            for s, c in session.execute(
                select(status, func.count()).where(*conditions).group_by(status)
            ).all()
        },
        ("online", "offline", "unknown"),
    )
    managed = or_(
        Asset.agent_id.is_not(None),
        Asset.ever_managed,
        Asset.monitoring_method == MonitoringMethod.AGENT,
    )
    source_expr = case(
        (managed, literal("managed")),
        (Asset.monitoring_method == MonitoringMethod.AGENTLESS, literal("monitored")),
        else_=literal("discovered"),
    )
    by_source = _ordered(
        {
            str(s): int(c)
            for s, c in session.execute(
                select(source_expr, func.count()).where(*conditions).group_by(source_expr)
            ).all()
        },
        ("managed", "monitored", "discovered"),
    )
    stale = session.scalar(
        select(func.count()).where(*conditions, stale_condition(ctx.lifecycle_policy, ctx.cutoff))
    )
    cleanup = session.scalar(
        select(func.count()).where(
            *conditions, stale_condition(ctx.lifecycle_policy, ctx.cutoff, purgeable_only=True)
        )
    )
    archived = session.scalar(
        select(func.count()).where(*conditions, Asset.archived_at.is_not(None))
    )
    return {
        "total": sum(by_status.values()),
        "by_status": by_status,
        "by_source": by_source,
        "stale": int(stale or 0),
        "cleanup_candidates": int(cleanup or 0),
        "archived": int(archived or 0),
    }


def asset_rows(ctx: BuildContext, limit: int | None = None) -> dict[str, Any]:
    session = ctx.session
    limit = limit or ctx.max_rows
    conditions = asset_conditions(ctx)
    total = session.scalar(select(func.count()).where(*conditions)) or 0
    status = effective_status_expr(ctx.cutoff, ctx.heartbeat_timeout).label("effective_status")
    rows = session.execute(
        select(Asset, status, AssetRisk.score, AssetRisk.level)
        .outerjoin(AssetRisk, AssetRisk.asset_id == Asset.id)
        .where(*conditions)
        .order_by(AssetRisk.score.desc().nulls_last(), Asset.id)
        .limit(limit)
    ).all()
    items = []
    for asset, effective, score, level in rows:
        view = evaluate(asset, ctx.cutoff, ctx.lifecycle_policy, online=effective == "online")
        items.append(
            {
                "id": str(asset.public_id),
                "name": _text(asset.display_name, 255),
                "hostname": _text(asset.hostname, 255),
                "ip": asset.primary_ip,
                "mac": asset.mac_address,
                "platform": _text(asset.os_name or asset.probable_os, 64),
                "os_version": _text(asset.os_version, 128),
                "source": view.source.value,
                "status": str(effective),
                "lifecycle_state": view.state.value,
                "criticality": _enum(asset.criticality),
                "risk_score": score,
                "risk_level": _enum(level),
                "agent_version": asset.agent_version,
                "first_seen_at": iso(asset.first_seen_at),
                "last_activity_at": iso(view.last_activity_at),
                "archived": asset.archived_at is not None,
            }
        )
    return _table(items, int(total), limit)


# --- Detecciones y alertas ------------------------------------------------------------------


def _detection_conditions(ctx: BuildContext) -> list[ColumnElement[bool]]:
    conditions: list[ColumnElement[bool]] = [
        Detection.asset_id.in_(scoped_asset_ids(ctx)),
        Detection.created_at <= ctx.cutoff,
    ]
    if ctx.filters.get("detection_ids"):
        conditions.append(Detection.public_id.in_(_ids(ctx.filters["detection_ids"])))
    else:
        conditions.append(_overlaps(Detection.first_seen_at, Detection.last_seen_at, ctx))
    if ctx.filters.get("severities"):
        conditions.append(cast(Detection.severity, String).in_(ctx.filters["severities"]))
    if ctx.filters.get("statuses") and ctx.definition.id == "detection":
        conditions.append(cast(Detection.status, String).in_(ctx.filters["statuses"]))
    return conditions


def detection_metrics(ctx: BuildContext) -> dict[str, Any]:
    conditions = _detection_conditions(ctx)
    session = ctx.session
    by_severity = _ordered(
        _count_by(session, Detection.severity, *conditions),
        ("critical", "high", "medium", "low", "informational"),
    )
    by_status = _ordered(
        _count_by(session, Detection.status, *conditions), ("open", "acknowledged", "resolved")
    )
    top_rules = [
        {"rule_id": rule, "title": _text(title, 255), "count": int(count)}
        for rule, title, count in session.execute(
            select(Detection.rule_id, func.min(Detection.title), func.count())
            .where(*conditions)
            .group_by(Detection.rule_id)
            .order_by(func.count().desc(), Detection.rule_id)
            .limit(10)
        ).all()
    ]
    return {
        "total": sum(by_severity.values()),
        "by_severity": by_severity,
        "by_status": by_status,
        "top_rules": top_rules,
    }


def detection_rows(ctx: BuildContext, with_evidence: bool = False) -> dict[str, Any]:
    session = ctx.session
    conditions = _detection_conditions(ctx)
    total = session.scalar(select(func.count()).select_from(Detection).where(*conditions)) or 0
    detections = list(
        session.scalars(
            select(Detection)
            .where(*conditions)
            .order_by(Detection.last_seen_at.desc(), Detection.id)
            .limit(ctx.max_rows)
        )
    )
    names = _names(session, (d.asset_id for d in detections))
    ids = [d.id for d in detections]
    incidents: dict[int, list[str]] = {}
    contributions: dict[int, float] = {}
    if ids:
        for detection_id, number in session.execute(
            select(IncidentDetection.detection_id, Incident.number)
            .join(Incident, Incident.id == IncidentDetection.incident_id)
            .where(IncidentDetection.detection_id.in_(ids), Incident.created_at <= ctx.cutoff)
            .order_by(Incident.number)
        ).all():
            if detection_id is not None:
                incidents.setdefault(detection_id, []).append(f"INC-{number:06d}")
        # Contribución al riesgo ACTUAL (la guardada por el Risk Engine en su último cálculo).
        latest = (
            select(RiskSnapshot.asset_id, func.max(RiskSnapshot.id).label("snapshot_id"))
            .where(RiskSnapshot.calculated_at <= ctx.cutoff)
            .group_by(RiskSnapshot.asset_id)
            .subquery()
        )
        for detection_id, points in session.execute(
            select(RiskContributionRecord.detection_id, func.sum(RiskContributionRecord.points))
            .join(latest, latest.c.snapshot_id == RiskContributionRecord.snapshot_id)
            .where(RiskContributionRecord.detection_id.in_(ids))
            .group_by(RiskContributionRecord.detection_id)
        ).all():
            if detection_id is not None:
                contributions[detection_id] = round(float(points or 0), 2)
    evidence: dict[int, list[dict[str, Any]]] = {}
    if with_evidence and ids:
        ranked = (
            select(
                DetectionEvidence,
                func.row_number()
                .over(
                    partition_by=DetectionEvidence.detection_id,
                    order_by=(DetectionEvidence.occurred_at, DetectionEvidence.id),
                )
                .label("position"),
            )
            .where(DetectionEvidence.detection_id.in_(ids))
            .subquery()
        )
        for row in session.execute(
            select(ranked)
            .where(ranked.c.position <= MAX_EVIDENCE_PER_DETECTION)
            .order_by(ranked.c.detection_id, ranked.c.occurred_at, ranked.c.id)
        ).all():
            evidence.setdefault(row.detection_id, []).append(
                {
                    "occurred_at": iso(row.occurred_at),
                    "kind": row.signal_kind,
                    "role": row.role,
                    "source_type": row.source_type,
                    "source_id": row.source_id,
                    "summary": _text(row.summary, 500),
                    "data": redact(row.data) if row.data else None,
                }
            )
    rows = []
    for d in detections:
        asset_ref = names.get(d.asset_id, (None, None))
        rows.append(
            {
                "id": str(d.public_id),
                "rule_id": d.rule_id,
                "rule_version": d.rule_version,
                "title": _text(d.title, 255),
                "severity": _enum(d.severity),
                "confidence": _enum(d.confidence),
                "status": _enum(d.status),
                "asset_id": asset_ref[0],
                "asset": _text(asset_ref[1], 255),
                "first_seen_at": iso(d.first_seen_at),
                "last_seen_at": iso(d.last_seen_at),
                "occurrences": d.occurrence_count,
                "mitre": d.mitre_technique,
                "summary": _text(d.summary, 1000),
                "incidents": incidents.get(d.id, []),
                "risk_points": contributions.get(d.id),
                "evidence": evidence.get(d.id, []) if with_evidence else None,
            }
        )
    return _table(rows, int(total), ctx.max_rows)


def _alert_conditions(ctx: BuildContext) -> list[ColumnElement[bool]]:
    resolved_after: ColumnElement[bool] = Alert.resolved_at.is_(None)
    if ctx.start is not None:
        resolved_after = or_(resolved_after, Alert.resolved_at >= ctx.start)
    return [
        Alert.asset_id.in_(scoped_asset_ids(ctx)),
        Alert.opened_at <= ctx.end,
        resolved_after,
    ]


def alert_section(ctx: BuildContext) -> dict[str, Any]:
    session = ctx.session
    conditions = _alert_conditions(ctx)
    by_severity = _ordered(
        _count_by(session, Alert.severity, *conditions), ("critical", "warning", "info")
    )
    total = sum(by_severity.values())
    alerts = list(
        session.scalars(
            select(Alert)
            .where(*conditions)
            .order_by(Alert.opened_at.desc(), Alert.id)
            .limit(ctx.max_rows)
        )
    )
    names = _names(session, (a.asset_id for a in alerts))
    rows = [
        {
            "id": str(a.public_id),
            "rule": _enum(a.rule),
            "severity": _enum(a.severity),
            "status": _enum(a.status),
            "asset": _text(names.get(a.asset_id, (None, None))[1], 255),
            "message": _text(a.message, 500),
            "opened_at": iso(a.opened_at),
            "resolved_at": iso(a.resolved_at),
        }
        for a in alerts
    ]
    return {"by_severity": by_severity, "table": _table(rows, total, ctx.max_rows)}


# --- Incidentes -----------------------------------------------------------------------------


def _incident_conditions(ctx: BuildContext) -> list[ColumnElement[bool]]:
    conditions: list[ColumnElement[bool]] = [Incident.created_at <= ctx.cutoff]
    if ctx.filters.get("incident_ids"):
        conditions.append(Incident.public_id.in_(_ids(ctx.filters["incident_ids"])))
    if ctx.filters.get("asset_ids") or ctx.filters.get("platforms"):
        conditions.append(
            Incident.id.in_(
                select(IncidentAsset.incident_id).where(
                    IncidentAsset.asset_id.in_(scoped_asset_ids(ctx))
                )
            )
        )
    return conditions


def incident_section(ctx: BuildContext) -> dict[str, Any]:
    session = ctx.session
    base = _incident_conditions(ctx)
    open_now = session.scalar(
        select(func.count()).where(*base, Incident.status.in_(INCIDENT_ACTIVE))
    )
    opened = session.scalar(select(func.count()).where(*base, _in_range(Incident.created_at, ctx)))
    resolved = session.scalar(
        select(func.count()).where(
            *base, Incident.resolved_at.is_not(None), _in_range(Incident.resolved_at, ctx)
        )
    )
    active_by_severity = _ordered(
        _count_by(session, Incident.severity, *base, Incident.status.in_(INCIDENT_ACTIVE)),
        ("critical", "high", "medium", "low"),
    )
    listed = [
        *base,
        or_(
            Incident.status.in_(INCIDENT_ACTIVE),
            _in_range(Incident.created_at, ctx),
            Incident.resolved_at.is_not(None) & _in_range(Incident.resolved_at, ctx),
        ),
    ]
    total = session.scalar(select(func.count()).where(*listed)) or 0
    incidents = list(
        session.scalars(
            select(Incident)
            .where(*listed)
            .order_by(Incident.created_at.desc(), Incident.id)
            .limit(ctx.max_rows)
        )
    )
    users = _usernames(session, (i.owner_user_id for i in incidents))
    rows = [
        {
            "id": str(i.public_id),
            "number": f"INC-{i.number:06d}",
            "title": _text(i.title, 200),
            "severity": _enum(i.severity),
            "priority": _enum(i.priority),
            "status": _enum(i.status),
            "owner": users.get(i.owner_user_id) if i.owner_user_id else None,
            "created_at": iso(i.created_at),
            "resolved_at": iso(i.resolved_at),
        }
        for i in incidents
    ]
    return {
        "open_now": int(open_now or 0),
        "opened": int(opened or 0),
        "resolved": int(resolved or 0),
        "active_by_severity": active_by_severity,
        "table": _table(rows, int(total), ctx.max_rows),
    }


# --- Vulnerabilidades -----------------------------------------------------------------------


def _finding_row(f: VulnerabilityFinding, asset: tuple[str | None, str | None]) -> dict[str, Any]:
    return {
        "id": str(f.public_id),
        "vulnerability": f.vuln_external_id,
        "cve": f.intel_cve,
        "title": _text(f.title, 300),
        "severity": f.severity,
        "cvss": f.cvss_score,
        "match_state": f.match_state,
        "confidence": f.confidence,
        "status": f.status,
        "component": _text(f.component_name, 512),
        "installed_version": _text(f.installed_version, 128),
        "fixed_version": _text(f.fixed_version, 128),
        "source": f.source,
        "asset_id": asset[0],
        "asset": _text(asset[1], 255),
        "first_seen_at": iso(f.first_seen_at),
        "last_seen_at": iso(f.last_seen_at),
        "inventory_observed_at": iso(f.inventory_observed_at),
        "resolved_at": iso(f.resolved_at),
        "priority": f.priority_score,
    }


def vulnerability_section(ctx: BuildContext) -> dict[str, Any]:
    session = ctx.session
    in_scope = [
        VulnerabilityFinding.asset_id.in_(scoped_asset_ids(ctx)),
        VulnerabilityFinding.created_at <= ctx.cutoff,
    ]
    if ctx.filters.get("severities"):
        in_scope.append(VulnerabilityFinding.severity.in_(ctx.filters["severities"]))
    if ctx.filters.get("statuses"):
        in_scope.append(VulnerabilityFinding.status.in_(ctx.filters["statuses"]))
    active = VulnerabilityFinding.status.in_(sorted(VULN_ACTIVE))
    stale_before = ctx.cutoff - timedelta(hours=ctx.stale_inventory_hours)
    groups: dict[str, ColumnElement[bool]] = {
        # Nunca se mezclan: confirmado, probable y potencial son evidencias distintas.
        "confirmed": and_(active, VulnerabilityFinding.match_state == "confirmed"),
        "probable": and_(active, VulnerabilityFinding.match_state == "probable"),
        "potential": and_(active, VulnerabilityFinding.match_state == "potential"),
        "resolved": and_(
            VulnerabilityFinding.status == "resolved",
            VulnerabilityFinding.resolved_at.is_not(None),
            _in_range(VulnerabilityFinding.resolved_at, ctx),
        ),
        "stale_evidence": and_(
            active,
            VulnerabilityFinding.match_state.in_(("confirmed", "probable", "potential")),
            VulnerabilityFinding.inventory_observed_at < stale_before,
        ),
    }
    out: dict[str, Any] = {"stale_inventory_hours": ctx.stale_inventory_hours}
    severity_order = ("critical", "high", "medium", "low", "informational")
    for name, condition in groups.items():
        ctx.checkpoint()
        by_severity = _ordered(
            _count_by(session, VulnerabilityFinding.severity, *in_scope, condition), severity_order
        )
        total = sum(by_severity.values())
        findings = list(
            session.scalars(
                select(VulnerabilityFinding)
                .where(*in_scope, condition)
                .order_by(
                    VulnerabilityFinding.severity_rank.desc(),
                    VulnerabilityFinding.priority_score.desc(),
                    VulnerabilityFinding.id,
                )
                .limit(ctx.max_rows)
            )
        )
        names = _names(session, (f.asset_id for f in findings))
        rows = [_finding_row(f, names.get(f.asset_id, (None, None))) for f in findings]
        out[name] = {"by_severity": by_severity, "table": _table(rows, total, ctx.max_rows)}
    out["assets_affected"] = int(
        session.scalar(
            select(func.count(func.distinct(VulnerabilityFinding.asset_id))).where(
                *in_scope, or_(groups["confirmed"], groups["probable"])
            )
        )
        or 0
    )
    return out


# --- Riesgo ---------------------------------------------------------------------------------


def _contribution_list(raw: Any, limit: int = 8) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    items = []
    for entry in raw[:limit]:
        if not isinstance(entry, dict):
            continue
        items.append(
            {
                "category": _text(entry.get("category"), 32),
                "label": _text(entry.get("label"), 255),
                "points": entry.get("points")
                if isinstance(entry.get("points"), int | float)
                else None,
                "rule_id": _text(entry.get("rule_id"), 32),
            }
        )
    return items


def risk_section(ctx: BuildContext, top: int = TOP_RISK_ASSETS) -> dict[str, Any]:
    session = ctx.session
    assets = scoped_asset_ids(ctx)
    scored = [AssetRisk.asset_id.in_(assets), AssetRisk.calculated_at.is_not(None)]
    if ctx.filters.get("risk_levels"):
        scored.append(cast(AssetRisk.level, String).in_(ctx.filters["risk_levels"]))
    by_level = _ordered(
        _count_by(session, AssetRisk.level, *scored),
        ("critical", "high", "medium", "low", "informational"),
    )
    total_assets = (
        session.scalar(select(func.count()).select_from(Asset).where(Asset.id.in_(assets))) or 0
    )
    top_rows = session.execute(
        select(AssetRisk, Asset)
        .join(Asset, Asset.id == AssetRisk.asset_id)
        .where(*scored)
        .order_by(AssetRisk.score.desc(), Asset.id)
        .limit(top)
    ).all()
    top_assets = [
        {
            "asset_id": str(asset.public_id),
            "asset": _text(asset.display_name, 255),
            "score": risk.score,
            "level": _enum(risk.level),
            "confidence": _enum(risk.confidence),
            "top_factor": _text(risk.top_factor, 255),
            "formula_version": risk.formula_version,
            "calculated_at": iso(risk.calculated_at),
            "contributions": _contribution_list(risk.contributions),
        }
        for risk, asset in top_rows
    ]
    ctx.checkpoint()
    snapshot_scope = [RiskSnapshot.asset_id.in_(assets), _in_range(RiskSnapshot.calculated_at, ctx)]
    transitions = _ordered(
        _count_by(
            session, RiskSnapshot.transition, *snapshot_scope, RiskSnapshot.transition.is_not(None)
        ),
        ("up", "down"),
    )
    changes = session.execute(
        select(RiskSnapshot, Asset.public_id, Asset.device_name, Asset.hostname, Asset.primary_ip)
        .join(Asset, Asset.id == RiskSnapshot.asset_id)
        .where(*snapshot_scope, RiskSnapshot.transition.is_not(None))
        .order_by(RiskSnapshot.calculated_at.desc(), RiskSnapshot.id)
        .limit(ctx.max_rows)
    ).all()
    change_total = sum(transitions.values())
    change_rows = [
        {
            "asset_id": str(public_id),
            "asset": _text(device or host or ip, 255),
            "at": iso(snap.calculated_at),
            "previous_level": _enum(snap.previous_level),
            "level": _enum(snap.level),
            "previous_score": snap.previous_score,
            "score": snap.score,
            "transition": snap.transition,
            "reason": snap.reason,
            "top_factor": _text(snap.top_factor, 255),
        }
        for snap, public_id, device, host, ip in changes
    ]
    unit = _trend_unit(ctx)
    bucket = func.date_trunc(unit, RiskSnapshot.calculated_at)
    evolution = [
        {
            "bucket": iso(b),
            "avg_score": round(float(avg or 0), 1),
            "max_score": int(mx or 0),
            "samples": int(n),
        }
        for b, avg, mx, n in session.execute(
            select(bucket, func.avg(RiskSnapshot.score), func.max(RiskSnapshot.score), func.count())
            .where(*snapshot_scope)
            .group_by(bucket)
            .order_by(bucket)
            .limit(MAX_RISK_POINTS)
        ).all()
    ]
    return {
        "assets_in_scope": int(total_assets),
        "by_level": by_level,
        "unscored": max(int(total_assets) - sum(by_level.values()), 0)
        if not ctx.filters.get("risk_levels")
        else None,
        "top_assets": top_assets,
        "transitions": transitions,
        "changes": _table(change_rows, change_total, ctx.max_rows),
        "evolution": evolution,
        "trend_unit": unit,
    }


# --- Threat intelligence --------------------------------------------------------------------


def threat_section(ctx: BuildContext, asset_ids: Any | None = None) -> dict[str, Any]:
    session = ctx.session
    conditions = [
        ThreatIntelMatch.asset_id.in_(
            asset_ids if asset_ids is not None else scoped_asset_ids(ctx)
        ),
        ThreatIntelMatch.matched_at <= ctx.cutoff,
        _overlaps(ThreatIntelMatch.first_observed_at, ThreatIntelMatch.last_observed_at, ctx),
    ]
    by_classification = _count_by(session, ThreatIntelMatch.classification, *conditions)
    by_status = _count_by(session, ThreatIntelMatch.status, *conditions)
    total = sum(by_status.values())
    rows = session.execute(
        select(ThreatIntelMatch, ThreatIndicator.indicator_type, ThreatIntelSource.name)
        .join(ThreatIndicator, ThreatIndicator.id == ThreatIntelMatch.indicator_id)
        .join(ThreatIntelSource, ThreatIntelSource.id == ThreatIndicator.source_id)
        .where(*conditions)
        .order_by(ThreatIntelMatch.last_observed_at.desc(), ThreatIntelMatch.id)
        .limit(ctx.max_rows)
    ).all()
    names = _names(session, (m.asset_id for m, _, _ in rows))
    items = [
        {
            "id": str(m.public_id),
            "indicator_type": indicator_type,
            "observed_value": _text(m.observed_value, 255),
            "observation_type": m.observation_type,
            "classification": m.classification,
            "match_confidence": m.match_confidence,
            "source": _text(source, 200),
            "status": m.status,
            "asset": _text(names.get(m.asset_id, (None, None))[1], 255),
            "first_observed_at": iso(m.first_observed_at),
            "last_observed_at": iso(m.last_observed_at),
        }
        for m, indicator_type, source in rows
    ]
    return {
        "by_classification": dict(sorted(by_classification.items())),
        "by_status": dict(sorted(by_status.items())),
        "table": _table(items, total, ctx.max_rows),
    }


# --- Response -------------------------------------------------------------------------------


def _duration(start: datetime | None, end: datetime | None) -> float | None:
    if start is None or end is None:
        return None
    return round((end - start).total_seconds(), 1)


def _execution_conditions(ctx: BuildContext) -> list[ColumnElement[bool]]:
    conditions: list[ColumnElement[bool]] = [ResponseExecution.created_at <= ctx.cutoff]
    if ctx.filters.get("execution_ids"):
        conditions.append(ResponseExecution.public_id.in_(_ids(ctx.filters["execution_ids"])))
    else:
        conditions.append(_in_range(ResponseExecution.created_at, ctx))
    if ctx.filters.get("playbook_ids"):
        # playbook_ids son ids públicos de Playbook (validados en el servicio).
        conditions.append(
            ResponseExecution.playbook_run_id.in_(
                select(PlaybookRun.id).where(
                    PlaybookRun.playbook_id.in_(_playbook_pks(ctx.filters["playbook_ids"]))
                )
            )
        )
    if (
        ctx.filters.get("asset_ids")
        or ctx.filters.get("platforms")
        or not ctx.filters.get("include_archived")
    ):
        # Ejecuciones sobre activos fuera del alcance no cuentan; las de incidente (sin
        # activo) solo si no se filtró por activos.
        in_assets = ResponseExecution.asset_id.in_(scoped_asset_ids(ctx))
        if ctx.filters.get("asset_ids") or ctx.filters.get("platforms"):
            conditions.append(in_assets)
        else:
            conditions.append(or_(ResponseExecution.asset_id.is_(None), in_assets))
    if ctx.filters.get("statuses") and ctx.definition.id == "response_activity":
        conditions.append(ResponseExecution.status.in_(ctx.filters["statuses"]))
    return conditions


def _playbook_pks(public_ids: list[str]) -> Any:
    return select(Playbook.id).where(Playbook.public_id.in_(_ids(public_ids)))


def execution_rows(ctx: BuildContext, conditions: list[ColumnElement[bool]]) -> dict[str, Any]:
    session = ctx.session
    total = (
        session.scalar(select(func.count()).select_from(ResponseExecution).where(*conditions)) or 0
    )
    executions = list(
        session.scalars(
            select(ResponseExecution)
            .where(*conditions)
            .order_by(ResponseExecution.created_at, ResponseExecution.id)
            .limit(ctx.max_rows)
        )
    )
    run_ids = {e.playbook_run_id for e in executions if e.playbook_run_id is not None}
    runs: dict[int, tuple[str, str, int]] = {}
    if run_ids:
        runs = {
            r.id: (str(r.public_id), r.playbook_name, r.playbook_version)
            for r in session.scalars(select(PlaybookRun).where(PlaybookRun.id.in_(run_ids)))
        }
    incidents: dict[int, int] = {}
    incident_ids = {e.incident_id for e in executions if e.incident_id is not None}
    if incident_ids:
        found = session.execute(
            select(Incident.id, Incident.number).where(Incident.id.in_(incident_ids))
        ).all()
        incidents = {incident_id: number for incident_id, number in found}
    rows = []
    for e in executions:
        run = runs.get(e.playbook_run_id) if e.playbook_run_id is not None else None
        number = incidents.get(e.incident_id) if e.incident_id is not None else None
        rows.append(
            {
                "id": str(e.public_id),
                "action": e.action_id,
                "risk_level": e.risk_level,
                "status": e.status,
                "target_type": e.target_type,
                "target": _text(e.target_label, 255),
                "target_id": _uuid(e.target_public_id),
                "actor": e.actor,
                "playbook": f"{run[1]} v{run[2]}" if run else None,
                "playbook_run_id": run[0] if run else None,
                "step": e.step_index,
                "incident": f"INC-{number:06d}" if number else None,
                "confirmed": e.confirmed,
                "reason": _text(e.reason, 500),
                "result_summary": _text(e.result_summary, 500),
                "error_code": e.error_code,
                "error_message": _text(e.error_message, 500),
                "created_at": iso(e.created_at),
                "started_at": iso(e.started_at),
                "finished_at": iso(e.finished_at),
                "duration_seconds": _duration(e.started_at or e.created_at, e.finished_at),
            }
        )
    return _table(rows, int(total), ctx.max_rows)


def response_section(ctx: BuildContext) -> dict[str, Any]:
    session = ctx.session
    conditions = _execution_conditions(ctx)
    by_status = dict(sorted(_count_by(session, ResponseExecution.status, *conditions).items()))
    by_action = dict(sorted(_count_by(session, ResponseExecution.action_id, *conditions).items()))
    failed = sum(by_status.get(s, 0) for s in FAILED_EXECUTIONS)
    run_conditions = [PlaybookRun.created_at <= ctx.cutoff]
    if ctx.filters.get("playbook_ids"):
        run_conditions.append(
            PlaybookRun.playbook_id.in_(_playbook_pks(ctx.filters["playbook_ids"]))
        )
    elif ctx.filters.get("execution_ids"):
        run_conditions.append(
            PlaybookRun.id.in_(
                select(ResponseExecution.playbook_run_id).where(
                    ResponseExecution.public_id.in_(_ids(ctx.filters["execution_ids"]))
                )
            )
        )
    else:
        run_conditions.append(_in_range(PlaybookRun.created_at, ctx))
    if ctx.filters.get("asset_ids") or ctx.filters.get("platforms"):
        run_conditions.append(PlaybookRun.asset_id.in_(scoped_asset_ids(ctx)))
    runs_total = (
        session.scalar(select(func.count()).select_from(PlaybookRun).where(*run_conditions)) or 0
    )
    runs = [
        {
            "id": str(r.public_id),
            "playbook": _text(r.playbook_name, 120),
            "version": r.playbook_version,
            "status": r.status,
            "target": _text(r.target_label, 255),
            "actor": r.actor,
            "steps": len(r.steps or []),
            "current_step": r.current_step,
            "error_code": r.error_code,
            "created_at": iso(r.created_at),
            "finished_at": iso(r.finished_at),
            "duration_seconds": _duration(r.created_at, r.finished_at),
        }
        for r in session.scalars(
            select(PlaybookRun)
            .where(*run_conditions)
            .order_by(PlaybookRun.created_at, PlaybookRun.id)
            .limit(ctx.max_rows)
        )
    ]
    return {
        "total": sum(by_status.values()),
        "failed": failed,
        "by_status": by_status,
        "by_action": by_action,
        "executions": execution_rows(ctx, conditions),
        "playbook_runs": _table(runs, int(runs_total), ctx.max_rows),
    }


# --- Cambios y ciclo de vida ----------------------------------------------------------------


def change_rows(ctx: BuildContext, categories: Sequence[ChangeCategory] | None) -> dict[str, Any]:
    session = ctx.session
    conditions = [
        AssetChange.asset_id.in_(scoped_asset_ids(ctx)),
        _in_range(AssetChange.detected_at, ctx),
    ]
    if categories:
        conditions.append(AssetChange.category.in_(categories))
    total = session.scalar(select(func.count()).select_from(AssetChange).where(*conditions)) or 0
    changes = list(
        session.scalars(
            select(AssetChange)
            .where(*conditions)
            .order_by(AssetChange.detected_at.desc(), AssetChange.id)
            .limit(ctx.max_rows)
        )
    )
    names = _names(session, (c.asset_id for c in changes))
    rows = [
        {
            "asset": _text(names.get(c.asset_id, (None, None))[1], 255),
            "category": _enum(c.category),
            "kind": _enum(c.kind),
            "item": _text(c.item, 512),
            "detected_at": iso(c.detected_at),
        }
        for c in changes
    ]
    return _table(rows, int(total), ctx.max_rows)


def lifecycle_section(ctx: BuildContext) -> dict[str, Any]:
    session = ctx.session
    conditions = asset_conditions(ctx)
    new_conditions = [*conditions, _in_range(Asset.first_seen_at, ctx)]
    new_total = session.scalar(select(func.count()).where(*new_conditions)) or 0
    new_assets = list(
        session.scalars(
            select(Asset)
            .where(*new_conditions)
            .order_by(Asset.first_seen_at.desc(), Asset.id)
            .limit(ctx.max_rows)
        )
    )
    new_rows = [
        {
            "id": str(a.public_id),
            "name": _text(a.display_name, 255),
            "ip": a.primary_ip,
            "mac": a.mac_address,
            "source": _asset_source(a),
            "platform": _text(a.os_name or a.probable_os, 64),
            "first_seen_at": iso(a.first_seen_at),
            "discovery_network": a.discovery_network,
        }
        for a in new_assets
    ]
    ctx.checkpoint()
    stale_rows_q = (
        select(Asset)
        .where(*conditions, stale_condition(ctx.lifecycle_policy, ctx.cutoff))
        .order_by(Asset.id)
        .limit(ctx.max_rows)
    )
    stale_total = (
        session.scalar(
            select(func.count()).where(
                *conditions, stale_condition(ctx.lifecycle_policy, ctx.cutoff)
            )
        )
        or 0
    )
    stale_rows = []
    for a in session.scalars(stale_rows_q):
        view = evaluate(a, ctx.cutoff, ctx.lifecycle_policy, online=False)
        stale_rows.append(
            {
                "id": str(a.public_id),
                "name": _text(a.display_name, 255),
                "source": view.source.value,
                "state": view.state.value,
                "last_activity_at": iso(view.last_activity_at),
                "stale_for_hours": view.stale_for_hours,
            }
        )
    # Archivados, restaurados, borrados y reconciliaciones: de la auditoría (append-only),
    # que conserva quién y cuándo aunque el activo cambie o desaparezca después.
    audit_conditions = [
        AuditEvent.action.in_(LIFECYCLE_AUDIT_ACTIONS),
        AuditEvent.result == "success",
        _in_range(AuditEvent.created_at, ctx),
    ]
    if ctx.filters.get("asset_ids"):
        audit_conditions.append(AuditEvent.target_id.in_(ctx.filters["asset_ids"]))
    by_action = _ordered(
        _count_by(session, AuditEvent.action, *audit_conditions), LIFECYCLE_AUDIT_ACTIONS
    )
    events = [
        {
            "at": iso(e.created_at),
            "action": e.action,
            "actor": e.actor,
            "target_type": e.target_type,
            "target_id": e.target_id,
            "details": {
                k: _text(v, 200)
                for k, v in (e.details or {}).items()
                if k in _LIFECYCLE_DETAIL_KEYS
            },
        }
        for e in session.scalars(
            select(AuditEvent)
            .where(*audit_conditions)
            .order_by(AuditEvent.created_at, AuditEvent.id)
            .limit(ctx.max_rows)
        )
    ]
    lineage_conditions = [
        AssetAgentLineage.asset_id.in_(scoped_asset_ids(ctx)),
        _in_range(AssetAgentLineage.ended_at, ctx),
    ]
    lineage = list(
        session.scalars(
            select(AssetAgentLineage)
            .where(*lineage_conditions)
            .order_by(AssetAgentLineage.ended_at, AssetAgentLineage.id)
            .limit(ctx.max_rows)
        )
    )
    names = _names(session, [x.asset_id for x in lineage] + [x.related_asset_id for x in lineage])
    lineage_total = (
        session.scalar(
            select(func.count()).select_from(AssetAgentLineage).where(*lineage_conditions)
        )
        or 0
    )
    lineage_rows = [
        {
            "asset": _text(names.get(x.asset_id, (None, None))[1], 255),
            "agent_id": str(x.agent_id),
            "agent_version": x.agent_version,
            "end_reason": x.end_reason,
            "related_asset": _text(names.get(x.related_asset_id, (None, None))[1], 255)
            if x.related_asset_id
            else None,
            "reconciliation_id": str(x.reconciliation_id),
            "actor": x.actor,
            "ended_at": iso(x.ended_at),
        }
        for x in lineage
    ]
    return {
        "new_assets": _table(new_rows, int(new_total), ctx.max_rows),
        "stale": _table(stale_rows, int(stale_total), ctx.max_rows),
        "events_by_action": by_action,
        "events": _table(events, sum(by_action.values()), ctx.max_rows),
        "reconciliations": _table(lineage_rows, int(lineage_total), ctx.max_rows),
    }


def duplicate_section(ctx: BuildContext) -> dict[str, Any]:
    """Posibles duplicados con la MISMA lógica de 5C.2 (AssetLifecycleService)."""
    from app.services.asset_lifecycle_service import AssetLifecycleService

    service = AssetLifecycleService(ctx.session, ctx.heartbeat_timeout, ctx.lifecycle_policy)
    pairs = service.duplicate_pairs("medium").items
    wanted = set(ctx.filters.get("asset_ids") or [])
    rows = []
    for pair in pairs:
        ids = {str(pair.asset.asset_id), str(pair.candidate.asset_id)}
        if wanted and not ids & wanted:
            continue
        rows.append(
            {
                "asset": _text(pair.asset.display_name, 255),
                "candidate": _text(pair.candidate.display_name, 255),
                "confidence": pair.confidence,
                "reasons": [str(r) for r in pair.reasons][:10],
                "reconcilable": pair.reconcilable,
            }
        )
    return _table(rows[: ctx.max_rows], len(rows), ctx.max_rows)


# --- Activo individual ----------------------------------------------------------------------


def _single_asset(ctx: BuildContext) -> Asset:
    public_id = UUID(ctx.filters["asset_ids"][0])
    asset = ctx.session.scalar(
        select(Asset).where(Asset.public_id == public_id, ctx.scope.asset_condition())
    )
    if asset is None:
        raise BuildError("report_target_not_found", "The asset no longer exists")
    if asset.archived_at is not None and not ctx.filters.get("include_archived"):
        raise BuildError("report_asset_archived", "The asset is archived")
    return asset


def asset_identity(ctx: BuildContext, asset: Asset) -> dict[str, Any]:
    status = ctx.session.scalar(
        select(effective_status_expr(ctx.cutoff, ctx.heartbeat_timeout)).where(Asset.id == asset.id)
    )
    view = evaluate(asset, ctx.cutoff, ctx.lifecycle_policy, online=status == "online")
    return {
        "id": str(asset.public_id),
        "name": _text(asset.display_name, 255),
        "hostname": _text(asset.hostname, 255),
        "device_name": _text(asset.device_name, 255),
        "reverse_dns": _text(asset.reverse_dns, 255),
        "ip": asset.primary_ip,
        "mac": asset.mac_address,
        "vendor": _text(asset.vendor or asset.device_vendor, 128),
        "model": _text(asset.device_model, 128),
        "device_type": asset.device_type,
        "platform": _text(asset.os_name or asset.probable_os, 64),
        "os_version": _text(asset.os_version, 128),
        "architecture": asset.architecture,
        "criticality": _enum(asset.criticality),
        "monitoring_method": _enum(asset.monitoring_method),
        "status": str(status),
        "source": view.source.value,
        "lifecycle_state": view.state.value,
        "last_activity_at": iso(view.last_activity_at),
        "stale_for_hours": view.stale_for_hours,
        "first_seen_at": iso(asset.first_seen_at),
        "last_seen_at": iso(asset.last_seen_at),
        "archived_at": iso(asset.archived_at),
        "archived_by": asset.archived_by,
        "archive_reason": _text(asset.archive_reason, 500),
    }


def asset_agent(ctx: BuildContext, asset: Asset) -> dict[str, Any]:
    # Del agente solo identificadores y estado: NUNCA agent_token_hash ni machine_id_hash.
    lineage = list(
        ctx.session.scalars(
            select(AssetAgentLineage)
            .where(AssetAgentLineage.asset_id == asset.id, AssetAgentLineage.ended_at <= ctx.cutoff)
            .order_by(AssetAgentLineage.ended_at, AssetAgentLineage.id)
            .limit(50)
        )
    )
    return {
        "agent_id": _uuid(asset.agent_id),
        "agent_version": asset.agent_version,
        "installation_method": asset.agent_installation_method,
        "credential_state": (
            None
            if asset.agent_id is None
            else "revoked"
            if asset.agent_token_revoked_at is not None
            else "active"
        ),
        "credential_issued_at": iso(asset.agent_token_issued_at),
        "credential_revoked_at": iso(asset.agent_token_revoked_at),
        "capabilities": [str(c)[:48] for c in (asset.agent_capabilities or [])][:30],
        "lineage": [
            {
                "agent_id": str(x.agent_id),
                "agent_version": x.agent_version,
                "end_reason": x.end_reason,
                "ended_at": iso(x.ended_at),
                "actor": x.actor,
                "reconciliation_id": str(x.reconciliation_id),
            }
            for x in lineage
        ],
    }


def asset_inventory(ctx: BuildContext, asset: Asset) -> dict[str, Any] | None:
    data = AssetInventory.data

    def length(key: str) -> Any:
        return func.coalesce(
            func.jsonb_array_length(
                func.coalesce(data[key], cast(literal("[]"), AssetInventory.data.type))
            ),
            0,
        )

    row = ctx.session.execute(
        select(
            AssetInventory.collected_at,
            length("software"),
            length("services"),
            length("accounts"),
            length("interfaces"),
            length("disks"),
            data["software_source"].astext,
        ).where(AssetInventory.asset_id == asset.id)
    ).first()
    if row is None:
        return None
    collected, software, services, accounts, interfaces, disks, source = row
    return {
        "collected_at": iso(collected),
        "software": int(software),
        "services": int(services),
        "accounts": int(accounts),
        "interfaces": int(interfaces),
        "disks": int(disks),
        "software_source": source,
    }


def asset_incidents(ctx: BuildContext, asset: Asset) -> dict[str, Any]:
    rows = (
        ctx.session.execute(
            select(Incident)
            .join(IncidentAsset, IncidentAsset.incident_id == Incident.id)
            .where(IncidentAsset.asset_id == asset.id, Incident.created_at <= ctx.cutoff)
            .order_by(Incident.created_at.desc(), Incident.id)
            .limit(ctx.max_rows + 1)
        )
        .scalars()
        .all()
    )
    items = [
        {
            "id": str(i.public_id),
            "number": f"INC-{i.number:06d}",
            "title": _text(i.title, 200),
            "severity": _enum(i.severity),
            "status": _enum(i.status),
            "created_at": iso(i.created_at),
            "resolved_at": iso(i.resolved_at),
        }
        for i in rows
    ]
    return _table(items, len(items), ctx.max_rows)


def asset_discovery(asset: Asset) -> dict[str, Any]:
    return {
        "sources": [str(s)[:32] for s in (asset.discovery_sources or [])][:10],
        "network": asset.discovery_network,
        "discovered_at": iso(asset.discovered_at),
        "last_network_seen_at": iso(asset.last_network_seen_at),
        "network_status": _enum(asset.network_status),
        "classification_confidence": _enum(asset.classification_confidence),
        "classification_evidence": redact(asset.classification_evidence or [])[:20],
    }


# --- Incidente individual -------------------------------------------------------------------


def _single_incident(ctx: BuildContext) -> Incident:
    public_id = UUID(ctx.filters["incident_ids"][0])
    incident = ctx.session.scalar(
        select(Incident).where(Incident.public_id == public_id, Incident.created_at <= ctx.cutoff)
    )
    if incident is None:
        raise BuildError("report_target_not_found", "The incident no longer exists")
    return incident


def incident_detail(ctx: BuildContext, incident: Incident) -> dict[str, Any]:
    session = ctx.session
    users = _usernames(
        session,
        (incident.owner_user_id, incident.created_by_user_id, incident.resolved_by_user_id),
    )
    merged_into = None
    if incident.merged_into_id:
        merged_into = session.scalar(
            select(Incident.number).where(Incident.id == incident.merged_into_id)
        )
    case = {
        "id": str(incident.public_id),
        "number": f"INC-{incident.number:06d}",
        "title": _text(incident.title, 200),
        "description": _text(incident.description, 4000),
        "status": _enum(incident.status),
        "severity": _enum(incident.severity),
        "priority": _enum(incident.priority),
        "confidence": _enum(incident.confidence),
        "owner": users.get(incident.owner_user_id) if incident.owner_user_id else None,
        "created_by": users.get(incident.created_by_user_id)
        if incident.created_by_user_id
        else None,
        "created_at": iso(incident.created_at),
        "updated_at": iso(incident.updated_at),
        "first_seen_at": iso(incident.first_seen_at),
        "last_seen_at": iso(incident.last_seen_at),
        "triaged_at": iso(incident.triaged_at),
        "resolved_at": iso(incident.resolved_at),
        "resolved_by": users.get(incident.resolved_by_user_id)
        if incident.resolved_by_user_id
        else None,
        "closed_at": iso(incident.closed_at),
        "resolution_category": _enum(incident.resolution_category),
        "resolution_summary": _text(incident.resolution_summary, 2000),
        "merged_into": f"INC-{merged_into:06d}" if merged_into else None,
        "risk_score_snapshot": incident.risk_score_snapshot,
        "risk_level_snapshot": incident.risk_level_snapshot,
    }
    limit = ctx.max_rows

    def rows(model: Any, order: Any) -> list[Any]:
        return list(
            session.scalars(
                select(model)
                .where(model.incident_id == incident.id)
                .order_by(order, model.id)
                .limit(limit + 1)
            )
        )

    assets = [
        {
            "asset_id": str(x.asset_public_id),
            "asset": _text(x.asset_name, 255),
            "source": x.source,
            "added_at": iso(x.added_at),
        }
        for x in rows(IncidentAsset, IncidentAsset.added_at)
    ]
    detections = [
        {
            "detection_id": str(x.detection_public_id),
            "rule_id": x.rule_id,
            "title": _text(x.title, 255),
            "severity": x.severity,
            "kind": x.kind,
            "source": x.source,
            "attached_at": iso(x.attached_at),
        }
        for x in rows(IncidentDetection, IncidentDetection.attached_at)
    ]
    alerts = [
        {
            "alert_id": str(x.alert_public_id),
            "rule": x.rule,
            "severity": x.severity,
            "message": _text(x.message, 500),
            "source": x.source,
            "attached_at": iso(x.attached_at),
        }
        for x in rows(IncidentAlert, IncidentAlert.attached_at)
    ]
    vulnerabilities = [
        {
            "finding_id": str(x.finding_public_id),
            "vulnerability": x.vulnerability_id,
            "title": _text(x.title, 300),
            "severity": x.severity,
            "component": _text(x.component, 512),
            "installed_version": _text(x.installed_version, 128),
            "asset": _text(x.asset_name, 255),
            "attached_at": iso(x.attached_at),
        }
        for x in rows(IncidentVulnerability, IncidentVulnerability.attached_at)
    ]
    threats = [
        {
            "match_id": str(x.match_public_id),
            "indicator_type": x.indicator_type,
            "indicator": _text(x.indicator_value, 255),
            "classification": x.classification,
            "confidence": x.confidence,
            "source": _text(x.source_name, 200),
            "observed": _text(x.observed_value, 255),
            "asset": _text(x.asset_name, 255),
            "attached_at": iso(x.attached_at),
        }
        for x in rows(IncidentThreatMatch, IncidentThreatMatch.attached_at)
    ]
    notes = [
        {
            "id": str(x.public_id),
            "author": x.author,
            "created_at": iso(x.created_at),
            "body": _text(x.body, 4000),
        }
        for x in rows(IncidentNote, IncidentNote.created_at)
        if x.created_at <= ctx.cutoff
    ]
    # Línea de tiempo en orden cronológico estricto (hora y, a igualdad, orden de inserción).
    activity = list(
        session.scalars(
            select(IncidentActivity)
            .where(
                IncidentActivity.incident_id == incident.id,
                IncidentActivity.occurred_at <= ctx.cutoff,
            )
            .order_by(IncidentActivity.occurred_at, IncidentActivity.id)
            .limit(ctx.max_rows + 1)
        )
    )
    activity_total = (
        session.scalar(
            select(func.count())
            .select_from(IncidentActivity)
            .where(
                IncidentActivity.incident_id == incident.id,
                IncidentActivity.occurred_at <= ctx.cutoff,
            )
        )
        or 0
    )
    timeline = [
        {
            "at": iso(a.occurred_at),
            "action": a.action,
            "actor": a.actor,
            "entity_type": a.entity_type,
            "entity_id": a.entity_id,
            "summary": _text(a.summary, 300),
        }
        for a in activity
    ]
    executions = execution_rows(
        ctx,
        [ResponseExecution.incident_id == incident.id, ResponseExecution.created_at <= ctx.cutoff],
    )
    runs = [
        {
            "id": str(r.public_id),
            "playbook": _text(r.playbook_name, 120),
            "version": r.playbook_version,
            "status": r.status,
            "actor": r.actor,
            "created_at": iso(r.created_at),
            "finished_at": iso(r.finished_at),
        }
        for r in session.scalars(
            select(PlaybookRun)
            .where(PlaybookRun.incident_id == incident.id, PlaybookRun.created_at <= ctx.cutoff)
            .order_by(PlaybookRun.created_at, PlaybookRun.id)
            .limit(ctx.max_rows)
        )
    ]
    evidence_refs = (
        [{"type": "detection", "id": d["detection_id"]} for d in detections]
        + [{"type": "alert", "id": a["alert_id"]} for a in alerts]
        + [{"type": "vulnerability_finding", "id": v["finding_id"]} for v in vulnerabilities]
        + [{"type": "threat_match", "id": t["match_id"]} for t in threats]
        + [{"type": "response_execution", "id": e["id"]} for e in executions["rows"]]
    )
    return {
        "case": case,
        "assets": _table(assets, len(assets), limit),
        "detections": _table(detections, len(detections), limit),
        "alerts": _table(alerts, len(alerts), limit),
        "vulnerabilities": _table(vulnerabilities, len(vulnerabilities), limit),
        "threat_matches": _table(threats, len(threats), limit),
        "notes": _table(notes, len(notes), limit),
        "timeline": _table(timeline, int(activity_total), limit),
        "executions": executions,
        "playbook_runs": _table(runs, len(runs), limit),
        "evidence_refs": evidence_refs[: limit * 2],
    }


# --- Builders por tipo ----------------------------------------------------------------------


def build_executive(ctx: BuildContext) -> dict[str, Any]:
    assets = asset_metrics(ctx)
    ctx.checkpoint()
    risk = risk_section(ctx, top=EXECUTIVE_TOP_ASSETS)
    ctx.checkpoint()
    incidents = incident_section(ctx)
    detections = detection_metrics(ctx)
    ctx.checkpoint()
    vulns = vulnerability_section(ctx)
    response = response_section(ctx)
    critical_detections_active = (
        ctx.session.scalar(
            select(func.count()).where(
                Detection.asset_id.in_(scoped_asset_ids(ctx)),
                cast(Detection.severity, String) == "critical",
                cast(Detection.status, String).in_(DETECTION_ACTIVE),
                Detection.created_at <= ctx.cutoff,
            )
        )
        or 0
    )
    critical_assets = risk["by_level"].get("critical", 0)
    # El ejecutivo minimiza datos: solo nombre, nivel y score de los activos más riesgosos
    # (sin IP, sin ids, sin contribuciones detalladas).
    top = [
        {
            "asset": a["asset"],
            "level": a["level"],
            "score": a["score"],
            "top_factor": a["top_factor"],
        }
        for a in risk["top_assets"]
    ]
    confirmed = vulns["confirmed"]["table"]["total"] + vulns["probable"]["table"]["total"]
    critical_confirmed = (
        vulns["confirmed"]["by_severity"]["critical"] + vulns["probable"]["by_severity"]["critical"]
    )
    findings = []
    if critical_assets:
        findings.append(phrases.risk_level_sentence(critical_assets, "critical"))
    if incidents["active_by_severity"].get("critical"):
        n = incidents["active_by_severity"]["critical"]
        findings.append(f"{_cp(n, 'incidente crítico abierto', 'incidentes críticos abiertos')}.")
    if critical_confirmed:
        findings.append(
            _cp(
                critical_confirmed,
                "vulnerabilidad crítica confirmada o probable",
                "vulnerabilidades críticas confirmadas o probables",
            )
            + " sin resolver."
        )
    if critical_detections_active:
        findings.append(
            _cp(
                int(critical_detections_active),
                "detección crítica activa",
                "detecciones críticas activas",
            )
            + "."
        )
    if response["failed"]:
        findings.append(phrases.response_sentence(response["total"], response["failed"]))
    summary = [
        phrases.overall_status(
            critical_assets,
            incidents["active_by_severity"].get("critical", 0),
            int(critical_detections_active),
        ),
        phrases.monitored_assets_sentence(
            assets["total"], assets["by_status"]["online"], assets["by_status"]["offline"]
        ),
        phrases.risk_level_sentence(critical_assets, "critical"),
        phrases.incidents_sentence(
            incidents["open_now"], incidents["opened"], incidents["resolved"]
        ),
        phrases.detections_sentence(detections["total"], detections["by_severity"]),
        phrases.vulnerabilities_sentence(
            confirmed, critical_confirmed, vulns["potential"]["table"]["total"]
        ),
        phrases.response_sentence(response["total"], response["failed"]),
        phrases.risk_changes_sentence(risk["transitions"]["up"], risk["transitions"]["down"]),
    ]
    return {
        "summary": summary,
        "data": {
            "assets": assets,
            "risk": {
                "by_level": risk["by_level"],
                "unscored": risk["unscored"],
                "top_assets": top,
                "transitions": risk["transitions"],
            },
            "incidents": {
                "open_now": incidents["open_now"],
                "opened": incidents["opened"],
                "resolved": incidents["resolved"],
                "active_by_severity": incidents["active_by_severity"],
            },
            "detections": {"total": detections["total"], "by_severity": detections["by_severity"]},
            "vulnerabilities": {
                "confirmed": vulns["confirmed"]["by_severity"],
                "probable": vulns["probable"]["by_severity"],
                "potential_total": vulns["potential"]["table"]["total"],
                "resolved_in_period": vulns["resolved"]["table"]["total"],
                "assets_affected": vulns["assets_affected"],
            },
            "response": {
                "total": response["total"],
                "failed": response["failed"],
                "by_status": response["by_status"],
            },
            "trends": {
                "unit": _trend_unit(ctx),
                "detections": _trend(
                    ctx, Detection.first_seen_at, Detection.asset_id.in_(scoped_asset_ids(ctx))
                ),
                "incidents": _trend(ctx, Incident.created_at),
            },
            "findings": findings,
        },
    }


def build_technical(ctx: BuildContext) -> dict[str, Any]:
    assets = asset_metrics(ctx)
    inventory = asset_rows(ctx)
    ctx.checkpoint()
    lifecycle = {
        "stale": assets["stale"],
        "cleanup_candidates": assets["cleanup_candidates"],
        "archived": assets["archived"],
    }
    risk = risk_section(ctx)
    ctx.checkpoint()
    detections = detection_metrics(ctx)
    detection_table = detection_rows(ctx)
    ctx.checkpoint()
    alerts = alert_section(ctx)
    vulns = vulnerability_section(ctx)
    ctx.checkpoint()
    threats = threat_section(ctx)
    incidents = incident_section(ctx)
    ctx.checkpoint()
    response = response_section(ctx)
    changes = change_rows(
        ctx, (ChangeCategory.NETWORK, ChangeCategory.EXPOSURE, ChangeCategory.IDENTITY)
    )
    confirmed = vulns["confirmed"]["table"]["total"] + vulns["probable"]["table"]["total"]
    critical_confirmed = (
        vulns["confirmed"]["by_severity"]["critical"] + vulns["probable"]["by_severity"]["critical"]
    )
    summary = [
        phrases.monitored_assets_sentence(
            assets["total"], assets["by_status"]["online"], assets["by_status"]["offline"]
        ),
        phrases.risk_level_sentence(risk["by_level"].get("critical", 0), "critical"),
        phrases.detections_sentence(detections["total"], detections["by_severity"]),
        phrases.vulnerabilities_sentence(
            confirmed, critical_confirmed, vulns["potential"]["table"]["total"]
        ),
        phrases.incidents_sentence(
            incidents["open_now"], incidents["opened"], incidents["resolved"]
        ),
        phrases.response_sentence(response["total"], response["failed"]),
    ]
    return {
        "summary": summary,
        "data": {
            "assets": assets,
            "lifecycle": lifecycle,
            "risk": risk,
            "detections": detections,
            "alerts": alerts,
            "vulnerabilities": vulns,
            "threats": threats,
            "incidents": incidents,
            "response": response,
        },
        "tables": {
            "assets": inventory,
            "detections": detection_table,
            "alerts": alerts["table"],
            "vulnerabilities": _merge_tables(
                vulns["confirmed"]["table"], vulns["probable"]["table"], vulns["potential"]["table"]
            ),
            "incidents": incidents["table"],
            "changes": changes,
        },
    }


def _merge_tables(*tables: dict[str, Any]) -> dict[str, Any]:
    rows = [row for t in tables for row in t["rows"]]
    return {
        "total": sum(t["total"] for t in tables),
        "truncated": any(t["truncated"] for t in tables),
        "rows": rows,
    }


def build_incident(ctx: BuildContext) -> dict[str, Any]:
    incident = _single_incident(ctx)
    detail = incident_detail(ctx, incident)
    case = detail["case"]
    n_assets = detail["assets"]["total"]
    n_det = detail["detections"]["total"]
    summary = [
        f"{case['number']} ({phrases.severity_es(case['severity'])}), estado {case['status']}.",
        f"{_cp(n_assets, 'activo asociado', 'activos asociados')} y"
        f" {_cp(n_det, 'detección vinculada', 'detecciones vinculadas')}.",
        f"{_cp(detail['timeline']['total'], 'entrada', 'entradas')} en la línea de tiempo; "
        + _cp(detail["executions"]["total"], "ejecución de Response", "ejecuciones de Response")
        + ".",
    ]
    tables = {
        "timeline": detail["timeline"],
        "detections": detail["detections"],
        "alerts": detail["alerts"],
        "executions": detail["executions"],
    }
    return {"summary": summary, "data": detail, "tables": tables}


def build_asset(ctx: BuildContext) -> dict[str, Any]:
    asset = _single_asset(ctx)
    identity = asset_identity(ctx, asset)
    agent = asset_agent(ctx, asset)
    inventory = asset_inventory(ctx, asset)
    ctx.checkpoint()
    risk_row = ctx.session.scalar(select(AssetRisk).where(AssetRisk.asset_id == asset.id))
    risk = {
        "score": risk_row.score if risk_row else None,
        "level": _enum(risk_row.level) if risk_row else None,
        "confidence": _enum(risk_row.confidence) if risk_row else None,
        "calculated_at": iso(risk_row.calculated_at) if risk_row else None,
        "top_factor": _text(risk_row.top_factor, 255) if risk_row else None,
        "contributions": _contribution_list(risk_row.contributions, 20) if risk_row else [],
    }
    history = [
        {
            "at": iso(s.calculated_at),
            "score": s.score,
            "level": _enum(s.level),
            "transition": s.transition,
            "reason": s.reason,
        }
        for s in ctx.session.scalars(
            select(RiskSnapshot)
            .where(RiskSnapshot.asset_id == asset.id, _in_range(RiskSnapshot.calculated_at, ctx))
            .order_by(RiskSnapshot.calculated_at, RiskSnapshot.id)
            .limit(MAX_RISK_POINTS)
        )
    ]
    ctx.checkpoint()
    detections = detection_rows(ctx)
    vulns = vulnerability_section(ctx)
    incidents = asset_incidents(ctx, asset)
    threats = threat_section(ctx)
    ctx.checkpoint()
    response = response_section(ctx)
    changes = change_rows(ctx, None)
    vuln_table = _merge_tables(
        vulns["confirmed"]["table"], vulns["probable"]["table"], vulns["potential"]["table"]
    )
    summary = [
        f"Activo {identity['name']} ({identity['source']}), estado {identity['status']},"
        f" ciclo de vida {identity['lifecycle_state']}.",
        (
            f"Riesgo {risk['score']} ({phrases.level_es(str(risk['level']))})."
            if risk["level"]
            else "Riesgo aún sin calcular por el Risk Engine."
        ),
        f"{_cp(detections['total'], 'detección', 'detecciones')} en el período;"
        f" {_cp(vuln_table['total'], 'finding activo', 'findings activos')} de vulnerabilidad.",
    ]
    return {
        "summary": summary,
        "data": {
            "identity": identity,
            "agent": agent,
            "inventory": inventory,
            "risk": {**risk, "history": history},
            "vulnerability_groups": {
                k: vulns[k]["by_severity"]
                for k in ("confirmed", "probable", "potential", "resolved")
            },
            "threats": threats,
            "incidents": incidents,
            "response": {
                "total": response["total"],
                "failed": response["failed"],
                "by_status": response["by_status"],
            },
            "discovery": asset_discovery(asset),
        },
        "tables": {
            "detections": detections,
            "vulnerabilities": vuln_table,
            "changes": changes,
            "executions": response["executions"],
        },
    }


def build_vulnerability(ctx: BuildContext) -> dict[str, Any]:
    vulns = vulnerability_section(ctx)
    confirmed = vulns["confirmed"]["table"]["total"]
    probable = vulns["probable"]["table"]["total"]
    critical = (
        vulns["confirmed"]["by_severity"]["critical"] + vulns["probable"]["by_severity"]["critical"]
    )
    summary = [
        phrases.vulnerabilities_sentence(
            confirmed + probable, critical, vulns["potential"]["table"]["total"]
        ),
        f"{confirmed} confirmados, {probable} probables y"
        f" {vulns['potential']['table']['total']} potenciales"
        " (los potenciales no están confirmados).",
        _cp(vulns["resolved"]["table"]["total"], "finding resuelto", "findings resueltos")
        + " en el período; "
        + _cp(vulns["stale_evidence"]["table"]["total"], "finding", "findings")
        + " con evidencia de"
        f" inventario de más de {vulns['stale_inventory_hours']} h.",
    ]
    return {
        "summary": summary,
        "data": vulns,
        "tables": {
            "vulnerabilities": _merge_tables(
                vulns["confirmed"]["table"],
                vulns["probable"]["table"],
                vulns["potential"]["table"],
                vulns["resolved"]["table"],
            )
        },
    }


def build_risk(ctx: BuildContext) -> dict[str, Any]:
    risk = risk_section(ctx)
    levels = risk["by_level"]
    summary = [
        phrases.risk_level_sentence(levels.get("critical", 0), "critical"),
        phrases.risk_level_sentence(levels.get("high", 0), "high"),
        phrases.risk_changes_sentence(risk["transitions"]["up"], risk["transitions"]["down"]),
        "Valores leídos del Risk Engine (fuente única); el informe no recalcula el riesgo.",
    ]
    return {"summary": summary, "data": risk, "tables": {"changes": risk["changes"]}}


def build_detection(ctx: BuildContext) -> dict[str, Any]:
    metrics = detection_metrics(ctx)
    table = detection_rows(ctx, with_evidence=True)
    summary = [
        phrases.detections_sentence(metrics["total"], metrics["by_severity"]),
        f"{metrics['by_status'].get('open', 0)} abiertas,"
        f" {metrics['by_status'].get('acknowledged', 0)}"
        f" reconocidas y {metrics['by_status'].get('resolved', 0)} resueltas.",
    ]
    evidence_rows = [
        {
            "detection_id": row["id"],
            "rule_id": row["rule_id"],
            **{k: v for k, v in ev.items() if k != "data"},
        }
        for row in table["rows"]
        for ev in (row["evidence"] or [])
    ]
    return {
        "summary": summary,
        "data": metrics,
        "tables": {
            "detections": table,
            "evidence": _table(evidence_rows, len(evidence_rows), len(evidence_rows) or 1),
        },
    }


def build_response(ctx: BuildContext) -> dict[str, Any]:
    response = response_section(ctx)
    summary = [
        phrases.response_sentence(response["total"], response["failed"]),
        _cp(response["playbook_runs"]["total"], "ejecución de playbook", "ejecuciones de playbook")
        + " en el alcance.",
    ]
    return {
        "summary": summary,
        "data": {k: response[k] for k in ("total", "failed", "by_status", "by_action")},
        "tables": {
            "executions": response["executions"],
            "playbook_runs": response["playbook_runs"],
        },
    }


def build_lifecycle(ctx: BuildContext) -> dict[str, Any]:
    metrics = asset_metrics(ctx)
    lifecycle = lifecycle_section(ctx)
    ctx.checkpoint()
    duplicates = duplicate_section(ctx)
    changes = change_rows(
        ctx, (ChangeCategory.NETWORK, ChangeCategory.EXPOSURE, ChangeCategory.IDENTITY)
    )
    events = lifecycle["events_by_action"]
    summary = [
        f"{_cp(lifecycle['new_assets']['total'], 'activo nuevo', 'activos nuevos')} en el período.",
        f"{_cp(metrics['stale'], 'activo stale', 'activos stale')} y"
        f" {_cp(metrics['cleanup_candidates'], 'candidato', 'candidatos')} a limpieza"
        " a la hora de corte.",
        f"{events['asset_archived']} archivados, {events['asset_restored']} restaurados y"
        f" {events['agent_asset_reconciled']} reconciliaciones en el período.",
        f"{_cp(duplicates['total'], 'posible duplicado', 'posibles duplicados')}"
        " (misma IP no implica mismo equipo: solo evidencia de 5C.2).",
    ]
    return {
        "summary": summary,
        "data": {"assets": metrics, "events_by_action": events},
        "tables": {
            "new_assets": lifecycle["new_assets"],
            "stale": lifecycle["stale"],
            "events": lifecycle["events"],
            "duplicates": duplicates,
            "reconciliations": lifecycle["reconciliations"],
            "changes": changes,
        },
    }


BUILDERS: dict[str, Callable[[BuildContext], dict[str, Any]]] = {
    "executive_summary": build_executive,
    "technical": build_technical,
    "incident": build_incident,
    "asset": build_asset,
    "vulnerability": build_vulnerability,
    "risk": build_risk,
    "detection": build_detection,
    "response_activity": build_response,
    "lifecycle_change": build_lifecycle,
}
