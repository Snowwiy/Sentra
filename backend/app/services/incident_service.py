"""Gestión de incidentes SOC (Fase 4K): creación, flujo de trabajo y detalle.

Responsabilidades y límites:
- un incidente es un caso humano: solo lo crea un analista (manual o promoviendo una
  detección/alerta). Nada en la ingesta ni en los motores 4H/4I crea incidentes;
- las relaciones (detecciones, alertas, activos) son referencias validadas en el servidor:
  el cliente envía ids públicos y aquí se comprueba que existen. La evidencia nunca la manda
  el cliente; se deriva de las detecciones enlazadas (no se copian filas de evidencia);
- el riesgo se LEE de 4I (asset_risk) para snapshots y contexto; nunca se recalcula ni se
  encola un recálculo desde aquí;
- concurrencia: cada mutación de campos bloquea la fila (SELECT ... FOR UPDATE) y compara
  `version`; si otro operador la cambió, 409 `incident_conflict` con la versión actual. Dos
  peticiones simultáneas se serializan en el lock y la segunda ve la versión nueva, así que
  ninguna sobrescribe a la otra en silencio;
- auditoría: cada cambio importante va a audit_events en la misma transacción (las rutas
  auditan además los intentos fallidos).
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import Select, func, select, text
from sqlalchemy.orm import Session

from app.core.exceptions import (
    IncidentAlreadyLinkedError,
    IncidentConflictError,
    IncidentRelationError,
    IncidentStateError,
    NotFoundError,
)
from app.core.permissions import Permission, Role
from app.incidents import workflow
from app.incidents.workflow import incident_key
from app.models.alert import Alert
from app.models.asset import Asset
from app.models.detection import Detection
from app.models.incident import (
    ACTIVE_STATUSES,
    Incident,
    IncidentActivity,
    IncidentAlert,
    IncidentAsset,
    IncidentConfidence,
    IncidentDetection,
    IncidentFeedback,
    IncidentLevel,
    IncidentNote,
    IncidentStatus,
    ResolutionCategory,
)
from app.models.risk import AssetRisk, RiskSnapshot
from app.models.user import User
from app.schemas.asset_context import AssetContextSnapshot
from app.schemas.incident import (
    IncidentAlertRef,
    IncidentAssetRef,
    IncidentAssign,
    IncidentCreate,
    IncidentDetail,
    IncidentDetectionRef,
    IncidentLink,
    IncidentMerge,
    IncidentMetrics,
    IncidentPromote,
    IncidentResolve,
    IncidentRiskAsset,
    IncidentRiskContext,
    IncidentRiskSnapshot,
    IncidentSummary,
    IncidentUpdate,
    IncidentUserRef,
)
from app.services import audit_service
from app.services.asset_context_service import context_values
from app.services.audit_service import Actor
from app.services.risk_service import _contribution

# Detalle: relaciones mostradas en la respuesta (el resto en /evidence y en el timeline).
DETAIL_RELATIONS_LIMIT = 50
RISK_ASSETS_LIMIT = 10
TOP_CONTRIBUTORS = 5
# Roles que pueden ser owner operacional de un caso (nunca viewer).
OWNER_ROLES = (Role.ANALYST.value, Role.ADMIN.value)


@dataclass(frozen=True)
class Operator:
    """Quién actúa: usuario del dashboard y si tiene permisos de administración de casos."""

    user: User
    actor: Actor
    is_admin: bool

    @classmethod
    def from_context(
        cls, user: User, client_ip: str | None, permissions: Iterable[Permission]
    ) -> "Operator":
        return cls(user, Actor.for_user(user, client_ip), Permission.INCIDENTS_ADMIN in permissions)


def _now() -> datetime:
    return datetime.now(UTC)


def _short(value: str, limit: int) -> str:
    # Resúmenes del timeline: una línea, acotada. El contenido lo escapa siempre la UI.
    flat = " ".join(value.split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


class IncidentService:
    def __init__(self, session: Session, operator: Operator) -> None:
        self._session = session
        self.op = operator

    # --- Utilidades de carga y bloqueo --------------------------------------------------------

    def _lock(self, public_id: UUID) -> Incident:
        # FOR UPDATE: serializa las mutaciones concurrentes del mismo caso. La segunda espera
        # al commit de la primera y compara su `version` con la ya incrementada.
        incident = self._session.scalar(
            select(Incident).where(Incident.public_id == public_id).with_for_update()
        )
        if incident is None:
            raise NotFoundError("Incident not found")
        return incident

    def _check_version(self, incident: Incident, version: int) -> None:
        if incident.version != version:
            raise IncidentConflictError(
                "The incident was changed by someone else; reload it and try again",
                details=[
                    {
                        "incident_id": str(incident.public_id),
                        "current_version": incident.version,
                        "status": incident.status.value,
                        "updated_at": incident.updated_at.isoformat(),
                        "updated_by": self._username(incident.updated_by_user_id),
                    }
                ],
            )

    def _username(self, user_id: int | None) -> str | None:
        if user_id is None:
            return None
        user = self._session.get(User, user_id)
        return user.username if user else None

    def _not_frozen(self, incident: Incident) -> None:
        if workflow.is_frozen(incident.status):
            raise IncidentStateError(
                "Incident is closed; reopen it before changing it"
                if incident.status == IncidentStatus.CLOSED
                else "Incident was merged into another incident and can no longer change"
            )

    def _touch(self, incident: Incident, now: datetime, bump: bool = True) -> None:
        incident.updated_at = now
        incident.last_activity_at = now
        incident.updated_by_user_id = self.op.user.id
        if bump:
            incident.version += 1

    def _activity(
        self,
        incident: Incident,
        action: str,
        summary: str,
        now: datetime,
        entity_type: str | None = None,
        entity_id: object = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        self._session.add(
            IncidentActivity(
                incident_id=incident.id,
                occurred_at=now,
                action=action,
                actor_user_id=self.op.user.id,
                actor=self.op.actor.name[:64],
                entity_type=entity_type,
                entity_id=str(entity_id)[:64] if entity_id is not None else None,
                summary=_short(summary, 300),
                details=details,
            )
        )
        incident.last_activity_at = now

    def _audit(
        self, action: str, incident: Incident, details: dict[str, Any] | None = None
    ) -> None:
        audit_service.record(
            self._session,
            self.op.actor,
            action,
            target_type="incident",
            target_id=incident.public_id,
            details={"incident": incident_key(incident.number), **(details or {})},
            commit=False,
        )

    # --- Creación ------------------------------------------------------------------------------

    def _new_incident(
        self,
        title: str,
        description: str | None,
        severity: IncidentLevel,
        priority: IncidentLevel,
        confidence: IncidentConfidence | None,
        now: datetime,
    ) -> Incident:
        incident = Incident(
            title=title,
            description=description or None,
            severity=severity,
            priority=priority,
            status=IncidentStatus.OPEN,
            confidence=confidence,
            created_by_user_id=self.op.user.id,
            updated_by_user_id=self.op.user.id,
            created_at=now,
            updated_at=now,
            last_activity_at=now,
            version=1,
        )
        self._session.add(incident)
        # flush: el número sale de la secuencia de PostgreSQL y lo necesitan actividad y audit.
        self._session.flush()
        self._activity(
            incident,
            "created",
            f"Incidente creado por {self.op.actor.name}",
            now,
            details={"severity": severity.value, "priority": priority.value},
        )
        return incident

    def create(self, payload: IncidentCreate) -> Incident:
        now = _now()
        assets = self._assets_by_public_id(payload.asset_ids)
        incident = self._new_incident(
            payload.title,
            payload.description,
            payload.severity,
            payload.priority,
            payload.confidence,
            now,
        )
        for asset in assets:
            self._link_asset(incident, asset, "manual", now)
        self._snapshot_risk(incident, now, "created")
        self._audit(
            "incident_created",
            incident,
            {"source": "manual", "assets": len(assets), "severity": payload.severity.value},
        )
        self._session.commit()
        return incident

    def _assets_by_public_id(self, public_ids: Sequence[UUID]) -> list[Asset]:
        unique = list(dict.fromkeys(public_ids))
        if not unique:
            return []
        assets = list(self._session.scalars(select(Asset).where(Asset.public_id.in_(unique))))
        if len(assets) != len(unique):
            # Una relación con un activo inexistente (id inventado o borrado) se rechaza entera.
            raise IncidentRelationError("One or more assets do not exist")
        order = {pid: i for i, pid in enumerate(unique)}
        return sorted(assets, key=lambda a: order[a.public_id])

    def _active_link(self, detection_pks: Sequence[int], alert_pks: Sequence[int]) -> None:
        """Rechaza promover algo que ya está en un caso activo (evita casos duplicados)."""
        subqueries = []
        if detection_pks:
            subqueries.append(
                select(IncidentDetection.incident_id).where(
                    IncidentDetection.detection_id.in_(detection_pks)
                )
            )
        if alert_pks:
            subqueries.append(
                select(IncidentAlert.incident_id).where(IncidentAlert.alert_id.in_(alert_pks))
            )
        for subquery in subqueries:
            existing = self._session.scalar(
                select(Incident)
                .where(Incident.id.in_(subquery), Incident.status.in_(ACTIVE_STATUSES))
                .order_by(Incident.number)
                .limit(1)
            )
            if existing is not None:
                key = incident_key(existing.number)
                raise IncidentAlreadyLinkedError(
                    f"Already part of active incident {key}; attach to it or open it instead",
                    details=[{"incident_id": str(existing.public_id), "key": key}],
                )

    def promote_detection(self, detection_id: UUID, payload: IncidentPromote) -> Incident:
        row = self._session.execute(
            select(Detection, Asset)
            .join(Asset, Asset.id == Detection.asset_id)
            .where(Detection.public_id == detection_id)
        ).first()
        if row is None:
            raise NotFoundError("Detection not found")
        detection, asset = row[0], row[1]
        self._active_link([detection.id], [])
        now = _now()
        severity = workflow.severity_from_detection(detection.severity)
        priority = payload.priority or self._suggested_priority(severity, [asset])
        incident = self._new_incident(
            payload.title or detection.title[:200],
            payload.description if payload.description is not None else detection.summary,
            severity,
            priority,
            workflow.confidence_from_detections([detection.confidence]),
            now,
        )
        self._link_detection(incident, detection, asset, "detection", now)
        if detection.alert_id is not None:
            alert = self._session.get(Alert, detection.alert_id)
            if alert is not None:
                self._link_alert(incident, alert, asset, "detection", now)
        self._snapshot_risk(incident, now, "created")
        self._audit(
            "incident_created",
            incident,
            {
                "source": "detection",
                "detection": str(detection.public_id),
                "rule": detection.rule_id,
            },
        )
        self._session.commit()
        return incident

    def promote_alert(self, alert_id: UUID, payload: IncidentPromote) -> Incident:
        row = self._session.execute(
            select(Alert, Asset)
            .join(Asset, Asset.id == Alert.asset_id)
            .where(Alert.public_id == alert_id)
        ).first()
        if row is None:
            raise NotFoundError("Alert not found")
        alert, asset = row[0], row[1]
        # Detecciones que generaron la alerta (security_detection): se reutilizan, nunca se
        # crea una detección nueva para abrir el caso.
        detections = list(
            self._session.scalars(select(Detection).where(Detection.alert_id == alert.id))
        )
        self._active_link([d.id for d in detections], [alert.id])
        now = _now()
        levels = [workflow.severity_from_detection(d.severity) for d in detections]
        severity = (
            workflow.max_level(levels) if levels else workflow.severity_from_alert(alert.severity)
        )
        priority = payload.priority or self._suggested_priority(severity, [asset])
        incident = self._new_incident(
            payload.title or alert.message[:200],
            payload.description,
            severity,
            priority,
            workflow.confidence_from_detections([d.confidence for d in detections]),
            now,
        )
        self._link_alert(incident, alert, asset, "alert", now)
        for detection in detections:
            self._link_detection(incident, detection, asset, "alert", now)
        self._snapshot_risk(incident, now, "created")
        self._audit(
            "incident_created",
            incident,
            {"source": "alert", "alert": str(alert.public_id), "detections": len(detections)},
        )
        self._session.commit()
        return incident

    def _suggested_priority(
        self, severity: IncidentLevel, assets: Sequence[Asset]
    ) -> IncidentLevel:
        best = workflow.suggested_priority(severity, None, None)
        for asset in assets:
            risk = self._session.get(AssetRisk, asset.id)
            level = risk.level.value if risk is not None and risk.calculated_at else None
            candidate = workflow.suggested_priority(severity, level, asset.criticality.value)
            best = workflow.max_level([best, candidate])
        return best

    # --- Relaciones ----------------------------------------------------------------------------

    def _link_asset(self, incident: Incident, asset: Asset, source: str, now: datetime) -> bool:
        exists = self._session.scalar(
            select(IncidentAsset.id).where(
                IncidentAsset.incident_id == incident.id, IncidentAsset.asset_id == asset.id
            )
        )
        if exists is not None:
            return False
        self._session.add(
            IncidentAsset(
                incident_id=incident.id,
                asset_id=asset.id,
                asset_public_id=asset.public_id,
                asset_name=asset.display_name[:255],
                source=source,
                added_at=now,
                added_by_user_id=self.op.user.id,
                # Fase 4L: contexto crítico del activo en el momento de vincularlo.
                context_snapshot=context_values(self._session, [asset])[asset.id].snapshot(now),
            )
        )
        # flush: un segundo enlace al mismo activo en esta transacción debe verlo.
        self._session.flush()
        self._activity(
            incident,
            "asset_added",
            f"Activo {asset.display_name} relacionado",
            now,
            "asset",
            asset.public_id,
            {"source": source},
        )
        return True

    def _widen_window(
        self, incident: Incident, first: datetime | None, last: datetime | None
    ) -> None:
        # Ventana real de la evidencia: solo se amplía con tiempos registrados por el host o
        # por Sentra, nunca con la hora de la acción del analista.
        if first is not None and (incident.first_seen_at is None or first < incident.first_seen_at):
            incident.first_seen_at = first
        if last is not None and (incident.last_seen_at is None or last > incident.last_seen_at):
            incident.last_seen_at = last

    def _link_detection(
        self, incident: Incident, detection: Detection, asset: Asset, source: str, now: datetime
    ) -> bool:
        exists = self._session.scalar(
            select(IncidentDetection.id).where(
                IncidentDetection.incident_id == incident.id,
                IncidentDetection.detection_id == detection.id,
            )
        )
        if exists is not None:
            return False
        self._session.add(
            IncidentDetection(
                incident_id=incident.id,
                detection_id=detection.id,
                detection_public_id=detection.public_id,
                rule_id=detection.rule_id,
                kind=detection.kind,
                title=detection.title[:255],
                severity=detection.severity.value,
                source=source,
                attached_at=now,
                attached_by_user_id=self.op.user.id,
            )
        )
        self._session.flush()
        self._widen_window(incident, detection.first_seen_at, detection.last_seen_at)
        label = "Correlación" if detection.kind == "correlation" else "Detección"
        self._activity(
            incident,
            "detection_attached",
            f"{label} {detection.rule_id} adjuntada: {detection.title}",
            now,
            "detection",
            detection.public_id,
            {"rule": detection.rule_id, "source": source},
        )
        self._link_asset(incident, asset, "detection" if source == "manual" else source, now)
        return True

    def _link_alert(
        self, incident: Incident, alert: Alert, asset: Asset, source: str, now: datetime
    ) -> bool:
        exists = self._session.scalar(
            select(IncidentAlert.id).where(
                IncidentAlert.incident_id == incident.id, IncidentAlert.alert_id == alert.id
            )
        )
        if exists is not None:
            return False
        self._session.add(
            IncidentAlert(
                incident_id=incident.id,
                alert_id=alert.id,
                alert_public_id=alert.public_id,
                rule=alert.rule.value,
                severity=alert.severity.value,
                message=alert.message[:500],
                source=source,
                attached_at=now,
                attached_by_user_id=self.op.user.id,
            )
        )
        self._session.flush()
        self._widen_window(incident, alert.opened_at, alert.last_triggered_at or alert.opened_at)
        self._activity(
            incident,
            "alert_attached",
            f"Alerta {alert.rule.value} adjuntada: {alert.message}",
            now,
            "alert",
            alert.public_id,
            {"rule": alert.rule.value, "source": source},
        )
        self._link_asset(incident, asset, "alert" if source == "manual" else source, now)
        return True

    def attach_detection(self, public_id: UUID, detection_id: UUID) -> bool:
        incident = self._lock(public_id)
        self._not_frozen(incident)
        row = self._session.execute(
            select(Detection, Asset)
            .join(Asset, Asset.id == Detection.asset_id)
            .where(Detection.public_id == detection_id)
        ).first()
        if row is None:
            raise NotFoundError("Detection not found")
        now = _now()
        added = self._link_detection(incident, row[0], row[1], "manual", now)
        if added:
            self._touch(incident, now, bump=False)
            self._audit("incident_detection_attached", incident, {"detection": str(detection_id)})
        self._session.commit()
        return added

    def attach_alert(self, public_id: UUID, alert_id: UUID) -> bool:
        incident = self._lock(public_id)
        self._not_frozen(incident)
        row = self._session.execute(
            select(Alert, Asset)
            .join(Asset, Asset.id == Alert.asset_id)
            .where(Alert.public_id == alert_id)
        ).first()
        if row is None:
            raise NotFoundError("Alert not found")
        alert, asset = row[0], row[1]
        now = _now()
        added = self._link_alert(incident, alert, asset, "manual", now)
        # La detección que originó la alerta forma parte de la misma evidencia.
        for detection in self._session.scalars(
            select(Detection).where(Detection.alert_id == alert.id)
        ):
            added = self._link_detection(incident, detection, asset, "alert", now) or added
        if added:
            self._touch(incident, now, bump=False)
            self._audit("incident_alert_attached", incident, {"alert": str(alert_id)})
        self._session.commit()
        return added

    def add_asset(self, public_id: UUID, asset_id: UUID) -> bool:
        incident = self._lock(public_id)
        self._not_frozen(incident)
        asset = self._session.scalar(select(Asset).where(Asset.public_id == asset_id))
        if asset is None:
            raise IncidentRelationError("Asset does not exist")
        now = _now()
        added = self._link_asset(incident, asset, "manual", now)
        if added:
            self._touch(incident, now, bump=False)
            self._audit("incident_updated", incident, {"asset_added": str(asset_id)})
        self._session.commit()
        return added

    # --- Edición y estados ---------------------------------------------------------------------

    def update(self, public_id: UUID, payload: IncidentUpdate) -> Incident:
        incident = self._lock(public_id)
        self._check_version(incident, payload.version)
        self._not_frozen(incident)
        fields = payload.model_fields_set - {"version"}
        changes: dict[str, Any] = {}
        for name in ("title", "severity", "priority"):
            if name in fields:
                value = getattr(payload, name)
                if value is None:
                    raise IncidentRelationError(f"{name} cannot be empty")
                if getattr(incident, name) != value:
                    changes[name] = value
        for name in ("description", "confidence"):
            value = getattr(payload, name)
            if name == "description" and value == "":
                value = None
            if name in fields and getattr(incident, name) != value:
                changes[name] = value
        new_status = payload.status if "status" in fields else None
        if new_status == incident.status:
            new_status = None
        if new_status is not None and (
            new_status in workflow.ACTION_ONLY
            or not workflow.can_transition(incident.status, new_status)
        ):
            raise IncidentStateError(
                f"Transition {incident.status.value} -> {new_status.value} is not allowed"
                " (resolve, close and reopen have their own action)"
            )
        if not changes and new_status is None:
            return incident

        now = _now()
        if changes:
            for name, value in changes.items():
                setattr(incident, name, value)
            # Título y descripción son texto libre: a la auditoría solo va que cambiaron.
            levels = {
                name: value.value
                for name, value in changes.items()
                if name in ("severity", "priority", "confidence") and value is not None
            }
            self._activity(
                incident,
                "updated",
                "Campos actualizados: " + ", ".join(sorted(changes)),
                now,
                details=levels or None,
            )
            self._audit("incident_updated", incident, {"fields": sorted(changes), **levels})
        if new_status is not None:
            self._set_status(incident, new_status, now)
        self._touch(incident, now)
        self._session.commit()
        return incident

    def _set_status(self, incident: Incident, new_status: IncidentStatus, now: datetime) -> None:
        previous = incident.status
        incident.status = new_status
        working = (IncidentStatus.TRIAGE, IncidentStatus.INVESTIGATING)
        if new_status in working and incident.triaged_at is None:
            incident.triaged_at = now
        if previous == IncidentStatus.RESOLVED:
            # Volver a investigar invalida la resolución vigente; su historial queda en la
            # actividad y en la auditoría.
            incident.resolved_at = None
            incident.resolved_by_user_id = None
            incident.resolution_category = None
            incident.resolution_summary = None
            incident.duplicate_of_id = None
        self._activity(
            incident,
            "status_changed",
            f"Estado: {previous.value} → {new_status.value}",
            now,
            details={"from": previous.value, "to": new_status.value},
        )
        self._audit(
            "incident_status_changed", incident, {"from": previous.value, "to": new_status.value}
        )

    def assign(self, public_id: UUID, payload: IncidentAssign) -> Incident:
        incident = self._lock(public_id)
        self._check_version(incident, payload.version)
        self._not_frozen(incident)
        if payload.user_id is None or payload.user_id == self.op.user.public_id:
            owner = self.op.user
        else:
            if not self.op.is_admin:
                # Política 4K: un analyst solo se asigna a sí mismo; asignar a otros es de
                # admin (incidents:admin). Ver docs/incident-management.md.
                raise IncidentRelationError("Only an administrator can assign incidents to others")
            found = self._session.scalar(select(User).where(User.public_id == payload.user_id))
            if found is None:
                raise IncidentRelationError("Owner does not exist")
            owner = found
        if not owner.is_active or owner.role not in OWNER_ROLES:
            raise IncidentRelationError(
                "Owner must be an active analyst or admin (viewers cannot own incidents)"
            )
        if (
            not self.op.is_admin
            and incident.owner_user_id is not None
            and incident.owner_user_id != owner.id
        ):
            raise IncidentRelationError(
                "The incident already has an owner; an administrator must reassign it"
            )
        if incident.owner_user_id == owner.id:
            return incident
        now = _now()
        previous = self._username(incident.owner_user_id)
        incident.owner_user_id = owner.id
        incident.assigned_at = now
        incident.assigned_by_user_id = self.op.user.id
        self._activity(
            incident,
            "assigned",
            f"Asignado a {owner.username}" + (f" (antes {previous})" if previous else ""),
            now,
            "user",
            owner.public_id,
            {"owner": owner.username, "previous": previous},
        )
        self._audit("incident_assigned", incident, {"owner": owner.username, "previous": previous})
        self._touch(incident, now)
        self._session.commit()
        return incident

    def unassign(self, public_id: UUID, version: int) -> Incident:
        incident = self._lock(public_id)
        self._check_version(incident, version)
        self._not_frozen(incident)
        if incident.owner_user_id is None:
            return incident
        if not self.op.is_admin and incident.owner_user_id != self.op.user.id:
            raise IncidentRelationError("Only the owner or an administrator can unassign")
        now = _now()
        previous = self._username(incident.owner_user_id)
        incident.owner_user_id = None
        incident.assigned_at = None
        incident.assigned_by_user_id = None
        self._activity(
            incident,
            "unassigned",
            f"Sin asignar (antes {previous})",
            now,
            details={"previous": previous},
        )
        self._audit("incident_unassigned", incident, {"previous": previous})
        self._touch(incident, now)
        self._session.commit()
        return incident

    def add_note(self, public_id: UUID, body: str) -> IncidentNote:
        incident = self._lock(public_id)
        self._not_frozen(incident)
        now = _now()
        note = IncidentNote(
            incident_id=incident.id,
            author_user_id=self.op.user.id,
            author=self.op.actor.name[:64],
            body=body,
            created_at=now,
        )
        self._session.add(note)
        self._session.flush()
        # Las notas son append-only y no chocan entre sí: no cambian `version`, así dos
        # analistas pueden anotar a la vez sin conflictos. La nota misma es el elemento del
        # timeline (no se duplica en la actividad). Su texto no va a la auditoría.
        self._touch(incident, now, bump=False)
        self._audit(
            "incident_note_added", incident, {"note": str(note.public_id), "chars": len(body)}
        )
        self._session.commit()
        return note

    def resolve(self, public_id: UUID, payload: IncidentResolve) -> Incident:
        incident = self._lock(public_id)
        self._check_version(incident, payload.version)
        self._not_frozen(incident)
        if not workflow.can_resolve(incident.status):
            raise IncidentStateError(
                f"An incident in status {incident.status.value} cannot be resolved"
            )
        duplicate: Incident | None = None
        if payload.duplicate_of is not None:
            if payload.category != ResolutionCategory.DUPLICATE:
                raise IncidentRelationError("duplicate_of is only valid with category duplicate")
            duplicate = self._session.scalar(
                select(Incident).where(Incident.public_id == payload.duplicate_of)
            )
            if duplicate is None or duplicate.id == incident.id:
                raise IncidentRelationError("duplicate_of must be another existing incident")
            if duplicate.status == IncidentStatus.MERGED:
                raise IncidentRelationError("duplicate_of cannot be a merged incident")
        now = _now()
        previous = incident.status
        incident.status = IncidentStatus.RESOLVED
        incident.resolved_at = now
        incident.resolved_by_user_id = self.op.user.id
        incident.resolution_category = payload.category
        incident.resolution_summary = payload.summary or None
        incident.duplicate_of_id = duplicate.id if duplicate else None
        if payload.category == ResolutionCategory.FALSE_POSITIVE:
            self._false_positive_feedback(incident, payload.summary, now)
        duplicate_key = incident_key(duplicate.number) if duplicate else None
        self._activity(
            incident,
            "resolved",
            f"Resuelto como {payload.category.value}"
            + (f" (duplicado de {duplicate_key})" if duplicate_key else ""),
            now,
            "incident" if duplicate else None,
            duplicate.public_id if duplicate else None,
            {"from": previous.value, "category": payload.category.value},
        )
        self._snapshot_risk(incident, now, "resolved")
        self._snapshot_context(incident, now)
        self._audit(
            "incident_resolved",
            incident,
            {
                "from": previous.value,
                "category": payload.category.value,
                "duplicate_of": duplicate_key,
            },
        )
        self._touch(incident, now)
        self._session.commit()
        return incident

    def _false_positive_feedback(
        self, incident: Incident, reason: str | None, now: datetime
    ) -> None:
        """Guarda el veredicto por regla para tuning futuro. NO toca reglas ni severidades."""
        rows = self._session.execute(
            select(IncidentDetection, Detection.rule_version)
            .outerjoin(Detection, Detection.id == IncidentDetection.detection_id)
            .where(IncidentDetection.incident_id == incident.id)
        ).all()
        for link, rule_version in rows:
            self._session.add(
                IncidentFeedback(
                    incident_id=incident.id,
                    detection_id=link.detection_id,
                    detection_public_id=link.detection_public_id,
                    rule_id=link.rule_id,
                    rule_version=rule_version,
                    verdict=ResolutionCategory.FALSE_POSITIVE.value,
                    reason=reason,
                    created_by_user_id=self.op.user.id,
                    created_at=now,
                )
            )

    def close(self, public_id: UUID, version: int) -> Incident:
        incident = self._lock(public_id)
        self._check_version(incident, version)
        if not workflow.can_close(incident.status):
            raise IncidentStateError("Only a resolved incident can be closed")
        now = _now()
        incident.status = IncidentStatus.CLOSED
        incident.closed_at = now
        self._activity(incident, "closed", "Incidente cerrado", now, details={"from": "resolved"})
        self._audit("incident_closed", incident)
        self._touch(incident, now)
        self._session.commit()
        return incident

    def reopen(self, public_id: UUID, version: int) -> Incident:
        incident = self._lock(public_id)
        self._check_version(incident, version)
        if not workflow.can_reopen(incident.status):
            raise IncidentStateError("Only a closed incident can be reopened")
        now = _now()
        previous = incident.resolution_category.value if incident.resolution_category else None
        incident.status = IncidentStatus.OPEN
        incident.closed_at = None
        incident.resolved_at = None
        incident.resolved_by_user_id = None
        incident.resolution_category = None
        incident.resolution_summary = None
        incident.duplicate_of_id = None
        self._activity(
            incident,
            "reopened",
            "Incidente reabierto",
            now,
            details={"previous_resolution": previous},
        )
        self._audit("incident_reopened", incident, {"previous_resolution": previous})
        self._touch(incident, now)
        self._session.commit()
        return incident

    def merge(self, public_id: UUID, payload: IncidentMerge) -> Incident:
        """Fusiona el incidente `public_id` (origen) en `payload.target_id` (destino).

        El origen conserva su número, notas, actividad, relaciones y snapshots y queda en
        estado merged apuntando al destino. Las relaciones se COPIAN al destino (no se
        mueven), así el historial del origen sigue intacto; el timeline y las notas del
        destino incluyen las del origen. Nada se borra.
        """
        if payload.target_id == public_id:
            raise IncidentRelationError("An incident cannot be merged into itself")
        # Bloqueo en orden de id para que dos merges cruzados (A->B y B->A) no se bloqueen
        # mutuamente (deadlock): el segundo espera y luego ve el primero ya fusionado.
        locked = {
            i.public_id: i
            for i in self._session.scalars(
                select(Incident)
                .where(Incident.public_id.in_([public_id, payload.target_id]))
                .order_by(Incident.id)
                .with_for_update()
            )
        }
        source = locked.get(public_id)
        if source is None:
            raise NotFoundError("Incident not found")
        target = locked.get(payload.target_id)
        if target is None:
            raise IncidentRelationError("Merge target does not exist")
        self._check_version(source, payload.version)
        self._check_version(target, payload.target_version)
        if IncidentStatus.MERGED in (source.status, target.status):
            # También impide ciclos: un incidente ya absorbido nunca vuelve a participar.
            raise IncidentStateError("Merged incidents cannot be merged again")
        if IncidentStatus.CLOSED in (source.status, target.status):
            raise IncidentStateError("Reopen closed incidents before merging them")
        now = _now()
        copied = self._copy_relations(source, target, now)
        self._widen_window(target, source.first_seen_at, source.last_seen_at)
        source_status = source.status
        source.status = IncidentStatus.MERGED
        source.merged_into_id = target.id
        source.merged_at = now
        target_key, source_key = incident_key(target.number), incident_key(source.number)
        self._activity(
            source,
            "merged_into",
            f"Fusionado en {target_key}",
            now,
            "incident",
            target.public_id,
            {"from": source_status.value, "target": target_key},
        )
        self._activity(
            target,
            "merged",
            f"{source_key} fusionado en este incidente",
            now,
            "incident",
            source.public_id,
            {"source": source_key, **copied},
        )
        self._audit(
            "incident_merged",
            source,
            {"target": target_key, "target_id": str(target.public_id), **copied},
        )
        self._touch(source, now)
        self._touch(target, now)
        self._session.commit()
        return target

    def _copy_relations(self, source: Incident, target: Incident, now: datetime) -> dict[str, int]:
        counts = {"detections": 0, "alerts": 0, "assets": 0}
        user_id = self.op.user.id
        have_detections = set(
            self._session.scalars(
                select(IncidentDetection.detection_public_id).where(
                    IncidentDetection.incident_id == target.id
                )
            )
        )
        for d in self._session.scalars(
            select(IncidentDetection).where(IncidentDetection.incident_id == source.id)
        ):
            if d.detection_public_id in have_detections:
                continue
            self._session.add(
                IncidentDetection(
                    incident_id=target.id,
                    detection_id=d.detection_id,
                    detection_public_id=d.detection_public_id,
                    rule_id=d.rule_id,
                    kind=d.kind,
                    title=d.title,
                    severity=d.severity,
                    source="merge",
                    attached_at=now,
                    attached_by_user_id=user_id,
                )
            )
            counts["detections"] += 1
        have_alerts = set(
            self._session.scalars(
                select(IncidentAlert.alert_public_id).where(IncidentAlert.incident_id == target.id)
            )
        )
        for a in self._session.scalars(
            select(IncidentAlert).where(IncidentAlert.incident_id == source.id)
        ):
            if a.alert_public_id in have_alerts:
                continue
            self._session.add(
                IncidentAlert(
                    incident_id=target.id,
                    alert_id=a.alert_id,
                    alert_public_id=a.alert_public_id,
                    rule=a.rule,
                    severity=a.severity,
                    message=a.message,
                    source="merge",
                    attached_at=now,
                    attached_by_user_id=user_id,
                )
            )
            counts["alerts"] += 1
        have_assets = set(
            self._session.scalars(
                select(IncidentAsset.asset_public_id).where(IncidentAsset.incident_id == target.id)
            )
        )
        for s in self._session.scalars(
            select(IncidentAsset).where(IncidentAsset.incident_id == source.id)
        ):
            if s.asset_public_id in have_assets:
                continue
            self._session.add(
                IncidentAsset(
                    incident_id=target.id,
                    asset_id=s.asset_id,
                    asset_public_id=s.asset_public_id,
                    asset_name=s.asset_name,
                    source="merge",
                    added_at=now,
                    added_by_user_id=user_id,
                    # El contexto histórico es el del vínculo original, no el de la fusión.
                    context_snapshot=s.context_snapshot,
                )
            )
            counts["assets"] += 1
        return counts

    # --- Contexto del activo (Fase 4L, solo lectura) -------------------------------------------

    def _snapshot_context(self, incident: Incident, now: datetime) -> None:
        """Guarda el contexto crítico ACTUAL de cada activo del caso al resolverlo."""
        rows = self._session.execute(
            select(IncidentAsset, Asset)
            .join(Asset, Asset.id == IncidentAsset.asset_id)
            .where(IncidentAsset.incident_id == incident.id)
        ).all()
        values = context_values(self._session, [asset for _, asset in rows])
        for link, asset in rows:
            link.resolved_context_snapshot = values[asset.id].snapshot(now)

    # --- Riesgo (solo lectura de 4I) -----------------------------------------------------------

    def _snapshot_risk(self, incident: Incident, now: datetime, reason: str) -> None:
        """Copia el riesgo ACTUAL del activo relacionado más arriesgado (sin recalcular)."""
        self._session.flush()
        row = self._session.execute(
            select(AssetRisk, Asset)
            .join(Asset, Asset.id == AssetRisk.asset_id)
            .join(IncidentAsset, IncidentAsset.asset_id == AssetRisk.asset_id)
            .where(IncidentAsset.incident_id == incident.id, AssetRisk.calculated_at.is_not(None))
            .order_by(AssetRisk.score.desc(), AssetRisk.asset_id)
            .limit(1)
        ).first()
        if row is None:
            return
        risk, asset = row[0], row[1]
        snapshot_id = self._session.scalar(
            select(RiskSnapshot.id)
            .where(RiskSnapshot.asset_id == asset.id)
            .order_by(RiskSnapshot.calculated_at.desc(), RiskSnapshot.id.desc())
            .limit(1)
        )
        incident.risk_score_snapshot = risk.score
        incident.risk_level_snapshot = risk.level.value
        incident.risk_confidence_snapshot = risk.confidence.value
        incident.risk_snapshot_at = risk.calculated_at
        incident.risk_snapshot_id = snapshot_id
        self._activity(
            incident,
            "risk_snapshot",
            f"Riesgo de {asset.display_name}: {risk.level.value} ({risk.score})",
            now,
            "asset",
            asset.public_id,
            {
                "reason": reason,
                "score": risk.score,
                "level": risk.level.value,
                "confidence": risk.confidence.value,
            },
        )


# --- Lecturas compartidas (detalle, listados, evidencia) ----------------------------------------


def get_incident(session: Session, public_id: UUID) -> Incident:
    incident = session.scalar(select(Incident).where(Incident.public_id == public_id))
    if incident is None:
        raise NotFoundError("Incident not found")
    return incident


def user_refs(session: Session, ids: Iterable[int | None]) -> dict[int, IncidentUserRef]:
    wanted = {i for i in ids if i is not None}
    if not wanted:
        return {}
    return {
        u.id: IncidentUserRef(
            user_id=u.public_id, username=u.username, role=u.role, active=u.is_active
        )
        for u in session.scalars(select(User).where(User.id.in_(wanted)))
    }


def asset_names(session: Session, incident_ids: Sequence[int]) -> dict[int, tuple[list[str], int]]:
    """Hasta 3 nombres de activos y el total por incidente, en una sola consulta (sin N+1)."""
    if not incident_ids:
        return {}
    numbered = (
        select(
            IncidentAsset.incident_id,
            IncidentAsset.asset_name,
            func.row_number()
            .over(partition_by=IncidentAsset.incident_id, order_by=IncidentAsset.id)
            .label("n"),
            func.count().over(partition_by=IncidentAsset.incident_id).label("total"),
        )
        .where(IncidentAsset.incident_id.in_(incident_ids))
        .subquery()
    )
    result: dict[int, tuple[list[str], int]] = {}
    for incident_id, name, _, total in session.execute(
        select(numbered).where(numbered.c.n <= 3).order_by(numbered.c.incident_id, numbered.c.n)
    ):
        names, _ = result.get(incident_id, ([], 0))
        names.append(name)
        result[incident_id] = (names, total)
    return result


def summarize(incidents: Sequence[Incident], session: Session) -> list[IncidentSummary]:
    users = user_refs(session, (i.owner_user_id for i in incidents))
    assets = asset_names(session, [i.id for i in incidents])
    result = []
    for i in incidents:
        names, count = assets.get(i.id, ([], 0))
        result.append(
            IncidentSummary(
                incident_id=i.public_id,
                number=i.number,
                key=incident_key(i.number),
                title=i.title,
                severity=i.severity,
                priority=i.priority,
                status=i.status,
                confidence=i.confidence,
                owner=users.get(i.owner_user_id) if i.owner_user_id else None,
                assets=names,
                asset_count=count,
                last_activity_at=i.last_activity_at,
                created_at=i.created_at,
                updated_at=i.updated_at,
                version=i.version,
            )
        )
    return result


def family_ids(session: Session, incident_id: int) -> list[int]:
    """El incidente y todos los absorbidos por él (merge directo o encadenado)."""
    rows = session.execute(
        text(
            "WITH RECURSIVE family(id) AS ("
            " SELECT CAST(:id AS BIGINT)"
            " UNION SELECT i.id FROM incidents i JOIN family f ON i.merged_into_id = f.id"
            ") SELECT id FROM family"
        ),
        {"id": incident_id},
    )
    return [int(r[0]) for r in rows]


def _link(incident: Incident | None) -> IncidentLink | None:
    if incident is None:
        return None
    return IncidentLink(
        incident_id=incident.public_id,
        key=incident_key(incident.number),
        title=incident.title,
        status=incident.status,
    )


def detection_links(incident_ids: Sequence[int]) -> Select[IncidentDetection, Detection, Asset]:
    # Una fila por detección aunque llegue por varios incidentes de la familia (merge).
    first = (
        select(func.min(IncidentDetection.id))
        .where(IncidentDetection.incident_id.in_(incident_ids))
        .group_by(IncidentDetection.detection_public_id)
    )
    return (
        select(IncidentDetection, Detection, Asset)
        .outerjoin(Detection, Detection.id == IncidentDetection.detection_id)
        .outerjoin(Asset, Asset.id == Detection.asset_id)
        .where(IncidentDetection.id.in_(first))
    )


def detection_refs(
    session: Session, stmt: Select[IncidentDetection, Detection, Asset]
) -> list[IncidentDetectionRef]:
    refs = []
    for link, detection, asset in session.execute(stmt):
        refs.append(
            IncidentDetectionRef(
                detection_id=link.detection_public_id,
                rule_id=link.rule_id,
                kind=link.kind,
                title=link.title,
                severity=detection.severity.value if detection else link.severity,
                status=detection.status.value if detection else None,
                confidence=detection.confidence.value if detection else None,
                available=detection is not None,
                asset_id=asset.public_id if asset else None,
                hostname=asset.display_name if asset else None,
                first_seen_at=detection.first_seen_at if detection else None,
                last_seen_at=detection.last_seen_at if detection else None,
                source=link.source,
                attached_at=link.attached_at,
            )
        )
    return refs


def alert_links(incident_ids: Sequence[int]) -> Select[IncidentAlert, Alert, Asset]:
    first = (
        select(func.min(IncidentAlert.id))
        .where(IncidentAlert.incident_id.in_(incident_ids))
        .group_by(IncidentAlert.alert_public_id)
    )
    return (
        select(IncidentAlert, Alert, Asset)
        .outerjoin(Alert, Alert.id == IncidentAlert.alert_id)
        .outerjoin(Asset, Asset.id == Alert.asset_id)
        .where(IncidentAlert.id.in_(first))
    )


def alert_refs(
    session: Session, stmt: Select[IncidentAlert, Alert, Asset]
) -> list[IncidentAlertRef]:
    refs = []
    for link, alert, asset in session.execute(stmt):
        refs.append(
            IncidentAlertRef(
                alert_id=link.alert_public_id,
                rule=link.rule,
                severity=alert.severity.value if alert else link.severity,
                status=alert.status.value if alert else None,
                message=link.message,
                available=alert is not None,
                asset_id=asset.public_id if asset else None,
                hostname=asset.display_name if asset else None,
                opened_at=alert.opened_at if alert else None,
                source=link.source,
                attached_at=link.attached_at,
            )
        )
    return refs


def _points(raw: object) -> float:
    if not isinstance(raw, dict):
        return 0.0
    try:
        return abs(float(raw.get("points") or 0))
    except (TypeError, ValueError):
        return 0.0


def risk_assets(session: Session, incident_id: int) -> list[IncidentRiskAsset]:
    """Riesgo actual (4I) de los activos del caso: lectura de asset_risk, sin recalcular."""
    rows = session.execute(
        select(Asset, AssetRisk)
        .join(IncidentAsset, IncidentAsset.asset_id == Asset.id)
        .outerjoin(AssetRisk, AssetRisk.asset_id == Asset.id)
        .where(IncidentAsset.incident_id == incident_id)
        .order_by(AssetRisk.score.desc().nulls_last(), Asset.id)
        .limit(RISK_ASSETS_LIMIT)
    ).all()
    result = []
    for asset, risk in rows:
        evaluated = risk is not None and risk.calculated_at is not None
        raw = (risk.contributions or []) if evaluated and risk else []
        top = sorted((c for c in raw if isinstance(c, dict)), key=_points, reverse=True)
        result.append(
            IncidentRiskAsset(
                asset_id=asset.public_id,
                name=asset.display_name,
                evaluated=evaluated,
                score=risk.score if evaluated and risk else None,
                level=risk.level.value if evaluated and risk else None,
                confidence=risk.confidence.value if evaluated and risk else None,
                calculated_at=risk.calculated_at if risk else None,
                changed_at=risk.changed_at if risk else None,
                top_contributors=[_contribution(c) for c in top[:TOP_CONTRIBUTORS]],
            )
        )
    return result


def _context_snapshot(raw: object) -> AssetContextSnapshot | None:
    """Snapshot JSONB -> API; un valor corrupto no tira el detalle del incidente."""
    if not isinstance(raw, dict):
        return None
    try:
        return AssetContextSnapshot.model_validate(raw)
    except ValueError:
        return None


def _seconds(start: datetime, end: datetime | None) -> int | None:
    return int((end - start).total_seconds()) if end is not None else None


def detail(session: Session, incident: Incident) -> IncidentDetail:
    users = user_refs(
        session,
        [
            incident.owner_user_id,
            incident.created_by_user_id,
            incident.assigned_by_user_id,
            incident.updated_by_user_id,
            incident.resolved_by_user_id,
        ],
    )
    (summary,) = summarize([incident], session)
    family = family_ids(session, incident.id)
    asset_rows = session.execute(
        select(IncidentAsset, Asset)
        .outerjoin(Asset, Asset.id == IncidentAsset.asset_id)
        .where(IncidentAsset.incident_id == incident.id)
        .order_by(IncidentAsset.id)
        .limit(DETAIL_RELATIONS_LIMIT)
    ).all()
    # Contexto actual de los activos del caso en una consulta (sin N+1).
    contexts = context_values(session, [asset for _, asset in asset_rows if asset is not None])
    detections_stmt = detection_links(family)
    detections_total = (
        session.scalar(select(func.count()).select_from(detections_stmt.subquery())) or 0
    )
    detections = detection_refs(
        session,
        detections_stmt.order_by(IncidentDetection.attached_at, IncidentDetection.id).limit(
            DETAIL_RELATIONS_LIMIT
        ),
    )
    alerts_stmt = alert_links(family)
    alerts_total = session.scalar(select(func.count()).select_from(alerts_stmt.subquery())) or 0
    alerts = alert_refs(
        session,
        alerts_stmt.order_by(IncidentAlert.attached_at, IncidentAlert.id).limit(
            DETAIL_RELATIONS_LIMIT
        ),
    )
    notes_total = (
        session.scalar(
            select(func.count())
            .select_from(IncidentNote)
            .where(IncidentNote.incident_id.in_(family))
        )
        or 0
    )
    related_ids = [i for i in (incident.duplicate_of_id, incident.merged_into_id) if i is not None]
    related = (
        {i.id: i for i in session.scalars(select(Incident).where(Incident.id.in_(related_ids)))}
        if related_ids
        else {}
    )
    merged_from = list(
        session.scalars(
            select(Incident).where(Incident.merged_into_id == incident.id).order_by(Incident.number)
        )
    )
    end = incident.closed_at or incident.resolved_at
    if incident.status not in (IncidentStatus.RESOLVED, IncidentStatus.CLOSED):
        end = incident.merged_at
    return IncidentDetail(
        **summary.model_dump(),
        description=incident.description,
        first_seen_at=incident.first_seen_at,
        last_seen_at=incident.last_seen_at,
        triaged_at=incident.triaged_at,
        resolved_at=incident.resolved_at,
        closed_at=incident.closed_at,
        resolution_category=incident.resolution_category,
        resolution_summary=incident.resolution_summary,
        duplicate_of=_link(related.get(incident.duplicate_of_id or 0)),
        merged_into=_link(related.get(incident.merged_into_id or 0)),
        merged_at=incident.merged_at,
        merged_from=[link for i in merged_from if (link := _link(i)) is not None],
        created_by=users.get(incident.created_by_user_id or 0),
        assigned_by=users.get(incident.assigned_by_user_id or 0),
        assigned_at=incident.assigned_at,
        updated_by=users.get(incident.updated_by_user_id or 0),
        resolved_by=users.get(incident.resolved_by_user_id or 0),
        risk=IncidentRiskContext(
            snapshot=IncidentRiskSnapshot(
                score=incident.risk_score_snapshot,
                level=incident.risk_level_snapshot,
                confidence=incident.risk_confidence_snapshot,
                taken_at=incident.risk_snapshot_at,
            ),
            assets=risk_assets(session, incident.id),
        ),
        asset_refs=[
            IncidentAssetRef(
                asset_id=link.asset_public_id,
                name=asset.display_name if asset else link.asset_name,
                exists=asset is not None,
                primary_ip=asset.primary_ip if asset else None,
                source=link.source,
                added_at=link.added_at,
                context=contexts[asset.id].brief() if asset else None,
                context_snapshot=_context_snapshot(link.context_snapshot),
                resolved_context_snapshot=_context_snapshot(link.resolved_context_snapshot),
            )
            for link, asset in asset_rows
        ],
        detections=detections,
        detections_total=detections_total,
        alerts=alerts,
        alerts_total=alerts_total,
        notes_total=notes_total,
        metrics=IncidentMetrics(
            # Edad hasta la resolución/cierre si ya terminó: dato observado, no un SLA.
            age_seconds=int(((end or _now()) - incident.created_at).total_seconds()),
            time_to_triage_seconds=_seconds(incident.created_at, incident.triaged_at),
            time_to_resolve_seconds=_seconds(incident.created_at, incident.resolved_at),
        ),
        allowed_transitions=workflow.patch_targets(incident.status),
    )
