"""Lecturas de incidentes (Fase 4K): listado, búsqueda, timeline, evidencia y sugerencias.

Todo lo que filtra u ordena por un campo elegido por el cliente pasa por mapas explícitos
(SORTS, filtros tipados): nunca se construye SQL con texto del usuario. Los listados siempre
van paginados y el timeline usa cursor (keyset) para no devolver la vida entera de un caso.
"""

import base64
import binascii
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from uuid import UUID

from sqlalchemy import (
    ColumnElement,
    String,
    and_,
    case,
    cast,
    func,
    literal,
    or_,
    select,
    tuple_,
    union_all,
)
from sqlalchemy.orm import Session

from app.core.exceptions import IncidentRelationError, NotFoundError
from app.core.permissions import Role
from app.incidents import workflow
from app.incidents.workflow import incident_key
from app.models.ai import AIInsight
from app.models.alert import Alert
from app.models.asset import Asset
from app.models.audit import AuditEvent
from app.models.detection import Detection, DetectionEvidence
from app.models.exposure import AssetPort, PortStateValue
from app.models.incident import (
    ACTIVE_STATUSES,
    Incident,
    IncidentActivity,
    IncidentAlert,
    IncidentAsset,
    IncidentDetection,
    IncidentLevel,
    IncidentNote,
    IncidentStatus,
)
from app.models.risk import AssetRisk, RiskSnapshot
from app.models.user import User
from app.repositories.alert_repository import escape_like
from app.schemas.incident import (
    AssignableUser,
    AssignableUserList,
    EvidenceEventRead,
    EvidenceExposureRead,
    EvidenceRiskRead,
    IncidentActivityRead,
    IncidentAuditEvent,
    IncidentAuditList,
    IncidentEvidence,
    IncidentList,
    IncidentNoteList,
    IncidentNoteRead,
    IncidentOverview,
    IncidentTimeline,
    RelatedIncident,
    RelatedIncidentList,
    TimelineItem,
)
from app.services.incident_service import (
    alert_links,
    alert_refs,
    detection_links,
    detection_refs,
    family_ids,
    risk_assets,
    summarize,
)

IncidentSort = Literal["last_activity", "created_at", "severity", "priority", "status", "number"]

# Campo permitido -> columna. Cualquier otro valor lo rechaza la validación de la ruta.
SORTS: dict[str, Any] = {
    "last_activity": Incident.last_activity_at,
    "created_at": Incident.created_at,
    # Enums de PostgreSQL: ordenan por declaración (low < ... < critical; open < ... < merged).
    "severity": Incident.severity,
    "priority": Incident.priority,
    "status": Incident.status,
    "number": Incident.number,
}

# INC-000123, inc-123 o 123: búsqueda exacta por número (índice único).
_NUMBER = re.compile(r"^(?:inc-?)?0*(\d{1,15})$", re.IGNORECASE)

# Sugerencias: ventana alrededor de la detección/alerta y número máximo de candidatos.
RELATED_WINDOW = timedelta(hours=24)
RELATED_LIMIT = 10
_REASON_SCORES = {
    "already_linked": 100,
    "evidence_overlap": 40,
    "same_asset": 30,
    "same_rule": 25,
    "correlation": 20,
    "same_account": 20,
    "time_window": 10,
}
EVIDENCE_EVENTS_LIMIT = 200


@dataclass(frozen=True)
class IncidentFilter:
    status: IncidentStatus | None = None
    # Solo casos vivos (open, triage, investigating, contained); se ignora con `status`.
    active: bool = False
    severity: IncidentLevel | None = None
    priority: IncidentLevel | None = None
    # "me", "unassigned" o el id público de un usuario.
    owner: str | None = None
    asset_public_id: UUID | None = None
    # Rango sobre created_at.
    since: datetime | None = None
    until: datetime | None = None
    search: str | None = None


class IncidentQueries:
    def __init__(self, session: Session, me: User | None = None) -> None:
        self._session = session
        self._me = me

    def _incident(self, public_id: UUID) -> Incident:
        incident = self._session.scalar(select(Incident).where(Incident.public_id == public_id))
        if incident is None:
            raise NotFoundError("Incident not found")
        return incident

    # --- Listado y búsqueda --------------------------------------------------------------------

    def _search(self, term: str) -> ColumnElement[bool]:
        """Número, título, hostname/IP del activo o título de detección.

        Los activos se resuelven primero en su tabla (pequeña, indexada por IP) y luego por
        el índice incident_assets.asset_id; el número usa el índice único. El título se
        compara con ILIKE (ver limitaciones en docs/incident-management.md).
        """
        pattern = f"%{escape_like(term)}%"
        conditions: list[ColumnElement[bool]] = [Incident.title.ilike(pattern, escape="\\")]
        number = _NUMBER.match(term)
        if number:
            conditions.append(Incident.number == int(number.group(1)))
        matching_assets = select(Asset.id).where(
            or_(
                Asset.hostname.ilike(pattern, escape="\\"),
                Asset.device_name.ilike(pattern, escape="\\"),
                Asset.primary_ip.ilike(pattern, escape="\\"),
            )
        )
        conditions.append(
            Incident.id.in_(
                select(IncidentAsset.incident_id).where(IncidentAsset.asset_id.in_(matching_assets))
            )
        )
        conditions.append(
            Incident.id.in_(
                select(IncidentDetection.incident_id).where(
                    IncidentDetection.title.ilike(pattern, escape="\\")
                )
            )
        )
        return or_(*conditions)

    def find(
        self, f: IncidentFilter, sort: IncidentSort, descending: bool, limit: int, offset: int
    ) -> IncidentList:
        stmt = select(Incident)
        if f.status is not None:
            stmt = stmt.where(Incident.status == f.status)
        elif f.active:
            stmt = stmt.where(Incident.status.in_(ACTIVE_STATUSES))
        if f.severity is not None:
            stmt = stmt.where(Incident.severity == f.severity)
        if f.priority is not None:
            stmt = stmt.where(Incident.priority == f.priority)
        if f.owner == "unassigned":
            stmt = stmt.where(Incident.owner_user_id.is_(None))
        elif f.owner == "me":
            stmt = stmt.where(Incident.owner_user_id == (self._me.id if self._me else -1))
        elif f.owner:
            try:
                owner_public = UUID(f.owner)
            except ValueError:
                raise NotFoundError("Owner not found") from None
            owner = self._session.scalar(select(User.id).where(User.public_id == owner_public))
            if owner is None:
                raise NotFoundError("Owner not found")
            stmt = stmt.where(Incident.owner_user_id == owner)
        if f.asset_public_id is not None:
            asset = self._session.scalar(
                select(Asset.id).where(Asset.public_id == f.asset_public_id)
            )
            if asset is None:
                raise NotFoundError("Asset not found")
            stmt = stmt.where(
                Incident.id.in_(
                    select(IncidentAsset.incident_id).where(IncidentAsset.asset_id == asset)
                )
            )
        if f.since is not None:
            stmt = stmt.where(Incident.created_at >= f.since)
        if f.until is not None:
            stmt = stmt.where(Incident.created_at <= f.until)
        if f.search:
            stmt = stmt.where(self._search(f.search))
        total = self._session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
        column = SORTS[sort]
        order = column.desc() if descending else column.asc()
        # Desempate estable por id: la paginación no repite ni salta filas.
        tie = Incident.id.desc() if descending else Incident.id.asc()
        page = list(self._session.scalars(stmt.order_by(order, tie).limit(limit).offset(offset)))
        return IncidentList(items=summarize(page, self._session), total=total)

    def overview(self) -> IncidentOverview:
        counts = {s: 0 for s in IncidentStatus}
        for status, count in self._session.execute(
            select(Incident.status, func.count())
            .where(Incident.status.in_(ACTIVE_STATUSES))
            .group_by(Incident.status)
        ):
            counts[status] = count
        active = Incident.status.in_(ACTIVE_STATUSES)
        critical, unassigned, mine, mean_age = self._session.execute(
            select(
                func.count().filter(Incident.severity == IncidentLevel.CRITICAL),
                func.count().filter(Incident.owner_user_id.is_(None)),
                func.count().filter(Incident.owner_user_id == (self._me.id if self._me else -1)),
                func.avg(func.extract("epoch", func.now() - Incident.created_at)),
            ).where(active)
        ).one()
        recent = self._session.execute(
            select(IncidentActivity, Incident)
            .join(Incident, Incident.id == IncidentActivity.incident_id)
            .order_by(IncidentActivity.occurred_at.desc(), IncidentActivity.id.desc())
            .limit(10)
        ).all()
        return IncidentOverview(
            open=counts[IncidentStatus.OPEN],
            triage=counts[IncidentStatus.TRIAGE],
            investigating=counts[IncidentStatus.INVESTIGATING],
            contained=counts[IncidentStatus.CONTAINED],
            critical=critical or 0,
            unassigned=unassigned or 0,
            assigned_to_me=mine or 0,
            mean_age_seconds=int(mean_age) if mean_age is not None else None,
            recent_activity=[
                IncidentActivityRead(
                    incident_id=incident.public_id,
                    incident_key=incident_key(incident.number),
                    incident_title=incident.title,
                    occurred_at=activity.occurred_at,
                    action=activity.action,
                    actor=activity.actor,
                    summary=activity.summary,
                )
                for activity, incident in recent
            ],
        )

    def assignable_users(self) -> AssignableUserList:
        users = self._session.scalars(
            select(User)
            .where(User.is_active.is_(True), User.role.in_([Role.ANALYST.value, Role.ADMIN.value]))
            .order_by(User.username)
            .limit(500)
        )
        return AssignableUserList(
            items=[
                AssignableUser(user_id=u.public_id, username=u.username, role=u.role) for u in users
            ]
        )

    # --- Notas, auditoría --------------------------------------------------------------------

    def notes(self, public_id: UUID, limit: int, offset: int) -> IncidentNoteList:
        incident = self._incident(public_id)
        family = family_ids(self._session, incident.id)
        where = IncidentNote.incident_id.in_(family)
        total = (
            self._session.scalar(select(func.count()).select_from(IncidentNote).where(where)) or 0
        )
        rows = self._session.execute(
            select(IncidentNote, Incident.number)
            .join(Incident, Incident.id == IncidentNote.incident_id)
            .where(where)
            .order_by(IncidentNote.created_at.desc(), IncidentNote.id.desc())
            .limit(limit)
            .offset(offset)
        ).all()
        return IncidentNoteList(
            items=[
                IncidentNoteRead(
                    note_id=note.public_id,
                    author=note.author,
                    body=note.body,
                    created_at=note.created_at,
                    incident_key=incident_key(number),
                )
                for note, number in rows
            ],
            total=total,
        )

    def audit(self, public_id: UUID, limit: int, offset: int) -> IncidentAuditList:
        incident = self._incident(public_id)
        where = and_(
            AuditEvent.target_type == "incident", AuditEvent.target_id == str(incident.public_id)
        )
        total = self._session.scalar(select(func.count()).select_from(AuditEvent).where(where)) or 0
        rows = self._session.scalars(
            select(AuditEvent)
            .where(where)
            .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
            .limit(limit)
            .offset(offset)
        )
        return IncidentAuditList(
            items=[
                IncidentAuditEvent(
                    created_at=e.created_at,
                    actor=e.actor,
                    action=e.action,
                    result=e.result,
                    details=e.details,
                )
                for e in rows
            ],
            total=total,
        )

    # --- Timeline ----------------------------------------------------------------------------

    def timeline(
        self,
        public_id: UUID,
        limit: int,
        cursor: str | None,
        since: datetime | None,
        until: datetime | None,
    ) -> IncidentTimeline:
        """Timeline unificado, del más reciente al más antiguo, paginado por cursor.

        Une por referencia (UNION ALL) la actividad del caso y sus notas con los tiempos
        REALES de lo relacionado: evidencias (eventos), detecciones/correlaciones, alertas,
        transiciones de nivel de riesgo de sus activos e insights de IA. Nada se copia y
        ningún elemento lleva una hora inventada: lo que no tiene hora propia (una detección
        ya purgada) no aparece salvo por su actividad de adjunto.
        """
        incident = self._incident(public_id)
        family = family_ids(self._session, incident.id)
        detection_ids = (
            select(IncidentDetection.detection_id)
            .where(
                IncidentDetection.incident_id.in_(family),
                IncidentDetection.detection_id.is_not(None),
            )
            .distinct()
            .scalar_subquery()
        )
        alert_ids = (
            select(IncidentAlert.alert_id)
            .where(IncidentAlert.incident_id.in_(family), IncidentAlert.alert_id.is_not(None))
            .distinct()
            .scalar_subquery()
        )
        asset_ids = (
            select(IncidentAsset.asset_id)
            .where(IncidentAsset.incident_id == incident.id, IncidentAsset.asset_id.is_not(None))
            .scalar_subquery()
        )
        current = literal(incident.id)
        none = cast(literal(None), String)

        def key(prefix: str, column: Any) -> Any:
            return func.concat(prefix, column)

        activity = select(
            IncidentActivity.occurred_at.label("ts"),
            literal("incident").label("src"),
            key("a", IncidentActivity.id).label("k"),
            IncidentActivity.action.label("action"),
            IncidentActivity.entity_type.label("etype"),
            IncidentActivity.entity_id.label("eid"),
            IncidentActivity.actor.label("actor"),
            IncidentActivity.summary.label("summary"),
            IncidentActivity.incident_id.label("origin"),
        ).where(IncidentActivity.incident_id.in_(family))
        notes = select(
            IncidentNote.created_at,
            literal("note"),
            key("n", IncidentNote.id),
            literal("note_added"),
            literal("note"),
            cast(IncidentNote.public_id, String),
            IncidentNote.author,
            func.left(IncidentNote.body, 280),
            IncidentNote.incident_id,
        ).where(IncidentNote.incident_id.in_(family))
        detections = select(
            Detection.first_seen_at,
            case((Detection.kind == "correlation", "correlation"), else_="detection"),
            key("d", Detection.id),
            none,
            literal("detection"),
            cast(Detection.public_id, String),
            none,
            func.concat(Detection.rule_id, ": ", Detection.title),
            current,
        ).where(Detection.id.in_(detection_ids))
        events = (
            select(
                DetectionEvidence.occurred_at,
                literal("event"),
                key("e", DetectionEvidence.id),
                none,
                DetectionEvidence.source_type,
                func.coalesce(DetectionEvidence.source_id, cast(Detection.public_id, String)),
                none,
                DetectionEvidence.summary,
                current,
            )
            .join(Detection, Detection.id == DetectionEvidence.detection_id)
            .where(DetectionEvidence.detection_id.in_(detection_ids))
        )
        alerts = select(
            Alert.opened_at,
            literal("alert"),
            key("l", Alert.id),
            none,
            literal("alert"),
            cast(Alert.public_id, String),
            none,
            Alert.message,
            current,
        ).where(Alert.id.in_(alert_ids))
        # Solo transiciones de nivel (no cada snapshot) en la ventana de investigación.
        window_start = (incident.first_seen_at or incident.created_at) - RELATED_WINDOW
        window_end = incident.closed_at or datetime.now(UTC)
        name = func.coalesce(Asset.device_name, Asset.hostname, Asset.reverse_dns, Asset.primary_ip)
        risk = (
            select(
                RiskSnapshot.calculated_at,
                literal("risk"),
                key("r", RiskSnapshot.id),
                none,
                literal("asset"),
                cast(Asset.public_id, String),
                none,
                func.concat(
                    "Riesgo de ",
                    name,
                    ": ",
                    func.coalesce(cast(RiskSnapshot.previous_level, String), "—"),
                    " → ",
                    cast(RiskSnapshot.level, String),
                    " (",
                    RiskSnapshot.score,
                    ")",
                ),
                current,
            )
            .join(Asset, Asset.id == RiskSnapshot.asset_id)
            .where(
                RiskSnapshot.asset_id.in_(asset_ids),
                RiskSnapshot.transition.is_not(None),
                RiskSnapshot.calculated_at >= window_start,
                RiskSnapshot.calculated_at <= window_end,
            )
        )
        insights = select(
            AIInsight.generated_at,
            literal("ai_insight"),
            key("i", AIInsight.id),
            AIInsight.kind,
            literal("ai_insight"),
            cast(AIInsight.public_id, String),
            AIInsight.requested_by,
            func.concat("Análisis de IA: ", AIInsight.kind),
            func.coalesce(AIInsight.incident_id, current),
        ).where(AIInsight.incident_id.in_(family))

        union = union_all(activity, notes, detections, events, alerts, risk, insights).subquery()
        stmt = select(union)
        if since is not None:
            stmt = stmt.where(union.c.ts >= since)
        if until is not None:
            stmt = stmt.where(union.c.ts <= until)
        position = _decode_cursor(cursor)
        if position is not None:
            stmt = stmt.where(tuple_(union.c.ts, union.c.k) < tuple_(*position))
        rows = self._session.execute(
            stmt.order_by(union.c.ts.desc(), union.c.k.desc()).limit(limit + 1)
        ).all()
        more = len(rows) > limit
        rows = rows[:limit]
        origins = {r.origin for r in rows}
        numbers = (
            dict(
                self._session.execute(
                    select(Incident.id, Incident.number).where(Incident.id.in_(origins))
                ).all()
            )
            if origins
            else {}
        )
        items = [
            TimelineItem(
                item_id=r.k,
                occurred_at=r.ts,
                source_type=r.src,
                action=r.action,
                entity_type=r.etype,
                entity_id=r.eid,
                actor=r.actor,
                summary=" ".join(str(r.summary or "").split())[:300],
                incident_key=incident_key(numbers.get(r.origin, incident.number)),
            )
            for r in rows
        ]
        next_cursor = _encode_cursor(rows[-1].ts, rows[-1].k) if more and rows else None
        return IncidentTimeline(items=items, next_cursor=next_cursor)

    # --- Evidencia -----------------------------------------------------------------------------

    def evidence(self, public_id: UUID) -> IncidentEvidence:
        """Evidencia agrupada: SIEMPRE derivada de las relaciones validadas del caso."""
        incident = self._incident(public_id)
        family = family_ids(self._session, incident.id)
        refs = detection_refs(
            self._session,
            detection_links(family)
            .order_by(IncidentDetection.attached_at, IncidentDetection.id)
            .limit(200),
        )
        detection_pks = select(IncidentDetection.detection_id).where(
            IncidentDetection.incident_id.in_(family), IncidentDetection.detection_id.is_not(None)
        )
        events_where = DetectionEvidence.detection_id.in_(detection_pks)
        events_total = (
            self._session.scalar(
                select(func.count()).select_from(DetectionEvidence).where(events_where)
            )
            or 0
        )
        events = self._session.execute(
            select(DetectionEvidence, Detection.public_id)
            .join(Detection, Detection.id == DetectionEvidence.detection_id)
            .where(events_where)
            .order_by(DetectionEvidence.occurred_at.desc(), DetectionEvidence.id.desc())
            .limit(EVIDENCE_EVENTS_LIMIT)
        ).all()
        assets = select(IncidentAsset.asset_id).where(
            IncidentAsset.incident_id == incident.id, IncidentAsset.asset_id.is_not(None)
        )
        ports = self._session.execute(
            select(AssetPort, Asset)
            .join(Asset, Asset.id == AssetPort.asset_id)
            .where(AssetPort.asset_id.in_(assets), AssetPort.state == PortStateValue.OPEN)
            .order_by(Asset.id, AssetPort.port)
            .limit(200)
        ).all()
        risks = risk_assets(self._session, incident.id)
        return IncidentEvidence(
            detections=[r for r in refs if r.kind != "correlation"],
            correlations=[r for r in refs if r.kind == "correlation"],
            events=[
                EvidenceEventRead(
                    detection_id=detection_public,
                    signal_kind=ev.signal_kind,
                    source_type=ev.source_type,
                    source_id=ev.source_id,
                    occurred_at=ev.occurred_at,
                    summary=ev.summary,
                )
                for ev, detection_public in events
            ],
            events_total=events_total,
            exposure=[
                EvidenceExposureRead(
                    asset_id=asset.public_id,
                    asset_name=asset.display_name,
                    protocol=port.protocol,
                    port=port.port,
                    service_hint=port.service_hint,
                    opened_at=port.opened_at,
                )
                for port, asset in ports
            ],
            alerts=alert_refs(
                self._session,
                alert_links(family)
                .order_by(IncidentAlert.attached_at, IncidentAlert.id)
                .limit(200),
            ),
            risk_contributions=[
                EvidenceRiskRead(
                    asset_id=r.asset_id, asset_name=r.name, contributions=r.top_contributors
                )
                for r in risks
                if r.top_contributors
            ],
        )

    # --- Sugerencias de incidentes relacionados (deduplicación) --------------------------------

    def related_for_detection(self, detection_id: UUID) -> RelatedIncidentList:
        row = self._session.execute(
            select(Detection, Asset)
            .join(Asset, Asset.id == Detection.asset_id)
            .where(Detection.public_id == detection_id)
        ).first()
        if row is None:
            raise NotFoundError("Detection not found")
        detection, asset = row[0], row[1]
        severity = workflow.severity_from_detection(detection.severity)
        return self._related(
            [detection], asset, detection.first_seen_at, detection.last_seen_at, None, severity
        )

    def related_for_alert(self, alert_id: UUID) -> RelatedIncidentList:
        row = self._session.execute(
            select(Alert, Asset)
            .join(Asset, Asset.id == Alert.asset_id)
            .where(Alert.public_id == alert_id)
        ).first()
        if row is None:
            raise NotFoundError("Alert not found")
        alert, asset = row[0], row[1]
        detections = list(
            self._session.scalars(select(Detection).where(Detection.alert_id == alert.id))
        )
        levels = [workflow.severity_from_detection(d.severity) for d in detections]
        severity = (
            workflow.max_level(levels) if levels else workflow.severity_from_alert(alert.severity)
        )
        first = min([alert.opened_at, *(d.first_seen_at for d in detections)])
        last = max(
            [alert.last_triggered_at or alert.opened_at, *(d.last_seen_at for d in detections)]
        )
        return self._related(detections, asset, first, last, alert, severity)

    def _related(
        self,
        detections: list[Detection],
        asset: Asset,
        first: datetime,
        last: datetime,
        alert: Alert | None,
        severity: IncidentLevel,
    ) -> RelatedIncidentList:
        """Casos ACTIVOS posiblemente relacionados, con los motivos. Nunca adjunta nada."""
        reasons: dict[int, set[str]] = {}

        def add(ids: Any, reason: str) -> None:
            for incident_id in ids:
                reasons.setdefault(int(incident_id), set()).add(reason)

        active = select(Incident.id).where(Incident.status.in_(ACTIVE_STATUSES))
        detection_pks = [d.id for d in detections]
        if detection_pks:
            add(
                self._session.scalars(
                    select(IncidentDetection.incident_id).where(
                        IncidentDetection.detection_id.in_(detection_pks),
                        IncidentDetection.incident_id.in_(active),
                    )
                ),
                "already_linked",
            )
        if alert is not None:
            add(
                self._session.scalars(
                    select(IncidentAlert.incident_id).where(
                        IncidentAlert.alert_id == alert.id, IncidentAlert.incident_id.in_(active)
                    )
                ),
                "already_linked",
            )
        add(
            self._session.scalars(
                select(IncidentAsset.incident_id).where(
                    IncidentAsset.asset_id == asset.id, IncidentAsset.incident_id.in_(active)
                )
            ),
            "same_asset",
        )
        rule_ids = {d.rule_id for d in detections}
        if rule_ids:
            add(
                self._session.scalars(
                    select(IncidentDetection.incident_id)
                    .where(
                        IncidentDetection.rule_id.in_(rule_ids),
                        IncidentDetection.incident_id.in_(active),
                    )
                    .distinct()
                    .limit(200)
                ),
                "same_rule",
            )
        if alert is not None and not detections:
            add(
                self._session.scalars(
                    select(IncidentAlert.incident_id)
                    .where(
                        IncidentAlert.rule == alert.rule.value,
                        IncidentAlert.incident_id.in_(active),
                    )
                    .distinct()
                    .limit(200)
                ),
                "same_rule",
            )
        # Evidencia compartida: la misma señal/evento respalda detecciones de ambos lados.
        if detection_pks:
            sources = (
                select(DetectionEvidence.source_id)
                .where(
                    DetectionEvidence.detection_id.in_(detection_pks),
                    DetectionEvidence.source_id.is_not(None),
                )
                .limit(200)
            )
            add(
                self._session.scalars(
                    select(IncidentDetection.incident_id)
                    .join(
                        DetectionEvidence,
                        DetectionEvidence.detection_id == IncidentDetection.detection_id,
                    )
                    .where(
                        DetectionEvidence.source_id.in_(sources),
                        IncidentDetection.detection_id.not_in(detection_pks),
                        IncidentDetection.incident_id.in_(active),
                    )
                    .distinct()
                    .limit(200)
                ),
                "evidence_overlap",
            )
        # Misma cuenta solo cuando la detección la registró (details.account): evidencia real.
        accounts = {
            str(d.details["account"]).strip().lower()
            for d in detections
            if isinstance(d.details, dict) and d.details.get("account")
        }
        if accounts:
            add(
                self._session.scalars(
                    select(IncidentDetection.incident_id)
                    .join(Detection, Detection.id == IncidentDetection.detection_id)
                    .where(
                        func.lower(Detection.details["account"].astext).in_(accounts),
                        IncidentDetection.detection_id.not_in(detection_pks),
                        IncidentDetection.incident_id.in_(active),
                    )
                    .distinct()
                    .limit(200)
                ),
                "same_account",
            )
        if any(d.kind == "correlation" for d in detections) or detection_pks:
            # Correlación: el caso ya contiene una correlación sobre el mismo activo.
            add(
                self._session.scalars(
                    select(IncidentDetection.incident_id)
                    .join(Detection, Detection.id == IncidentDetection.detection_id)
                    .where(
                        Detection.kind == "correlation",
                        Detection.asset_id == asset.id,
                        IncidentDetection.incident_id.in_(active),
                    )
                    .distinct()
                ),
                "correlation",
            )

        candidates = (
            list(self._session.scalars(select(Incident).where(Incident.id.in_(list(reasons)))))
            if reasons
            else []
        )
        scored: list[tuple[int, Incident, list[str]]] = []
        for incident in candidates:
            found = reasons[incident.id]
            start = (incident.first_seen_at or incident.created_at) - RELATED_WINDOW
            end = max(incident.last_seen_at or incident.created_at, incident.last_activity_at)
            if start <= last and first <= end + RELATED_WINDOW:
                found.add("time_window")
            # Coincidir solo en regla o cuenta, fuera de la ventana, es demasiado débil.
            if found <= {"same_rule", "same_account", "correlation"}:
                continue
            ordered = sorted(found, key=lambda r: -_REASON_SCORES[r])
            scored.append((sum(_REASON_SCORES[r] for r in found), incident, ordered))
        scored.sort(key=lambda item: (-item[0], -item[1].last_activity_at.timestamp()))
        top = scored[:RELATED_LIMIT]
        summaries = summarize([incident for _, incident, _ in top], self._session)
        risk = self._session.get(AssetRisk, asset.id)
        level = risk.level.value if risk is not None and risk.calculated_at else None
        return RelatedIncidentList(
            items=[
                RelatedIncident(incident=summary, reasons=reasons_, score=score)
                for (score, _, reasons_), summary in zip(top, summaries, strict=True)
            ],
            suggested_priority=workflow.suggested_priority(
                severity, level, asset.criticality.value
            ),
            suggested_severity=severity,
        )


# --- Cursor del timeline ------------------------------------------------------------------------


def _encode_cursor(ts: datetime, key: str) -> str:
    raw = f"{ts.isoformat()}|{key}".encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode_cursor(cursor: str | None) -> tuple[datetime, str] | None:
    """Cursor opaco "<timestamp>|<clave>". Uno manipulado se trata como inválido (422)."""
    if not cursor:
        return None
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        ts, key = base64.urlsafe_b64decode(padded.encode()).decode().split("|", 1)
        parsed = datetime.fromisoformat(ts)
    except (ValueError, binascii.Error, UnicodeDecodeError):
        raise IncidentRelationError("Invalid timeline cursor") from None
    if parsed.tzinfo is None or not re.fullmatch(r"[a-z]\d{1,19}", key):
        raise IncidentRelationError("Invalid timeline cursor")
    return parsed, key
