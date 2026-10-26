"""Tareas de caso y solicitudes de control de red (Fase 7A.6, docs/case-operations.md).

Extiende el servicio de incidentes (4K) en lugar de crear un motor de casos paralelo: usa su
bloqueo del caso, su actividad (timeline) y su auditoría. Reglas:

- Asignar una tarea no ejecuta nada. Una tarea solo cambia de estado y acumula evidencia
  (referencias validadas) y un resultado; las acciones técnicas tienen su propio flujo.
- Quién puede asignar: el owner del caso y los admins asignan a cualquier analyst o admin
  activo; el resto solo puede tomar para sí una tarea sin responsable.
- Quién puede trabajar una tarea: su responsable, quien la creó, el owner del caso o un admin;
  una tarea sin responsable, cualquiera con incidents:manage.
- Una solicitud de control de red la aprueba o rechaza un admin (network_controls:approve).
  Aprobarla no aplica nada: se evalúan los puntos de control instalados y, como en 7A no hay
  ninguno, queda `no_enforcement_point` con lo que haría falta. Si alguien la aplica fuera de
  Sentra, se registra quién, cuándo y dónde (`applied_manually`). Nada de esto se dispara
  desde el riesgo ni desde una clasificación: solo por petición de un usuario.
"""

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.exceptions import (
    CaseTaskConflictError,
    CaseTaskStateError,
    IncidentRelationError,
    NetworkControlConflictError,
    NetworkControlStateError,
    NotFoundError,
    PermissionDeniedError,
)
from app.incidents import network_controls
from app.incidents.workflow import incident_key
from app.models.alert import Alert
from app.models.asset import Asset
from app.models.case_operations import (
    OPEN_CONTROL_STATUSES,
    OPEN_TASK_STATUSES,
    IncidentTask,
    NetworkControlRequest,
)
from app.models.detection import Detection
from app.models.incident import Incident, IncidentAsset
from app.models.response import ResponseExecution
from app.models.site import Site
from app.models.tool import ToolExecution
from app.models.user import User
from app.models.vulnerability import VulnerabilityFinding
from app.schemas.case_operations import (
    ControlCapabilities,
    ControlCapability,
    ControlScope,
    EnforcementRead,
    NetworkControlApplied,
    NetworkControlCreate,
    NetworkControlDecision,
    NetworkControlRead,
    NetworkControlReject,
    TaskAssetRef,
    TaskAssign,
    TaskCreate,
    TaskEvidenceAdd,
    TaskEvidenceRead,
    TaskRead,
    TaskUpdate,
)
from app.services.incident_service import OWNER_ROLES, IncidentService, user_refs

MAX_TASK_EVIDENCE = 50
MAX_CONTROL_DAYS = 365
# Transiciones de una tarea. Terminada o cancelada solo puede reabrirse (vuelve a `open`).
TASK_TRANSITIONS: dict[str, frozenset[str]] = {
    "open": frozenset({"in_progress", "blocked", "done", "cancelled"}),
    "in_progress": frozenset({"open", "blocked", "done", "cancelled"}),
    "blocked": frozenset({"open", "in_progress", "cancelled"}),
    "done": frozenset({"open"}),
    "cancelled": frozenset({"open"}),
}
FINAL_TASK_STATUSES = frozenset({"done", "cancelled"})


def _now() -> datetime:
    return datetime.now(UTC)


class CaseOperationsService(IncidentService):
    # --- Utilidades -------------------------------------------------------------------------

    def _incident_for_update(self, incident_id: int) -> Incident:
        incident = self._session.scalar(
            select(Incident).where(Incident.id == incident_id).with_for_update()
        )
        if incident is None:
            raise NotFoundError("Incident not found")
        return incident

    def _task(self, task_id: UUID, version: int | None = None) -> tuple[IncidentTask, Incident]:
        """Tarea bloqueada junto con su caso (primero el caso: mismo orden que el resto)."""
        incident_id = self._session.scalar(
            select(IncidentTask.incident_id).where(IncidentTask.public_id == task_id)
        )
        if incident_id is None:
            raise NotFoundError("Task not found")
        incident = self._incident_for_update(incident_id)
        task = self._session.scalar(
            select(IncidentTask).where(IncidentTask.public_id == task_id).with_for_update()
        )
        if task is None or task.incident_id != incident.id:
            # Se movió a otro caso (merge) entre las dos lecturas: el cliente debe recargar.
            raise CaseTaskConflictError("The task moved to another incident; reload it")
        if version is not None and task.version != version:
            raise CaseTaskConflictError(
                "The task was changed by someone else; reload it and try again",
                details=[{"task_id": str(task.public_id), "current_version": task.version}],
            )
        return task, incident

    def _user(self, public_id: UUID) -> User:
        user = self._session.scalar(select(User).where(User.public_id == public_id))
        if user is None:
            raise IncidentRelationError("User does not exist")
        if not user.is_active or user.role not in OWNER_ROLES:
            raise IncidentRelationError(
                "Tasks can only be assigned to active analysts or admins (not viewers)"
            )
        return user

    def _is_lead(self, incident: Incident) -> bool:
        """Owner del caso o admin: puede delegar y reasignar."""
        return self.op.is_admin or incident.owner_user_id == self.op.user.id

    def _can_work(self, task: IncidentTask, incident: Incident) -> bool:
        if self._is_lead(incident) or task.assignee_user_id is None:
            return True
        return self.op.user.id in (task.assignee_user_id, task.created_by_user_id)

    def _require_work(self, task: IncidentTask, incident: Incident) -> None:
        if not self._can_work(task, incident):
            raise PermissionDeniedError(
                "Only the assignee, the task creator, the incident owner or an administrator "
                "can change this task"
            )

    def _task_activity(
        self,
        incident: Incident,
        task: IncidentTask,
        action: str,
        summary: str,
        now: datetime,
        details: dict[str, Any] | None = None,
    ) -> None:
        self._activity(incident, action, summary, now, "task", task.public_id, details)
        # Como las notas: el trabajo de una tarea no choca con la edición del caso, así que no
        # cambia la `version` del incidente.
        self._touch(incident, now, bump=False)
        self._audit(
            f"incident_{action}",
            incident,
            {"task": str(task.public_id), "kind": task.kind, **(details or {})},
        )

    # --- Tareas -----------------------------------------------------------------------------

    def create_task(self, incident_public_id: UUID, payload: TaskCreate) -> IncidentTask:
        incident = self._lock(incident_public_id)
        self._not_frozen(incident)
        now = _now()
        asset_id: int | None = None
        if payload.asset_id is not None:
            asset_id = self._session.scalar(
                select(IncidentAsset.asset_id).where(
                    IncidentAsset.incident_id == incident.id,
                    IncidentAsset.asset_public_id == payload.asset_id,
                )
            )
            if asset_id is None:
                raise IncidentRelationError("The asset is not part of this incident")
        assignee: User | None = None
        if payload.assignee_user_id is not None:
            assignee = self._user(payload.assignee_user_id)
            if assignee.id != self.op.user.id and not self._is_lead(incident):
                raise PermissionDeniedError(
                    "Only the incident owner or an administrator can assign tasks to others"
                )
        task = IncidentTask(
            incident_id=incident.id,
            kind=payload.kind,
            title=payload.title,
            description=payload.description or None,
            status="open",
            asset_id=asset_id,
            assignee_user_id=assignee.id if assignee else None,
            assignee=assignee.username if assignee else None,
            assigned_at=now if assignee else None,
            created_by_user_id=self.op.user.id,
            created_by=self.op.actor.name[:64],
            evidence=[],
            due_at=payload.due_at,
            created_at=now,
            updated_at=now,
            version=1,
        )
        self._session.add(task)
        self._session.flush()
        summary = f"Tarea creada: {task.title}"
        if assignee is not None:
            summary += f" (asignada a {assignee.username})"
        self._task_activity(
            incident,
            task,
            "task_created",
            summary,
            now,
            {"assignee": assignee.username if assignee else None},
        )
        self._session.commit()
        return task

    def update_task(self, task_id: UUID, payload: TaskUpdate) -> IncidentTask:
        task, incident = self._task(task_id, payload.version)
        self._not_frozen(incident)
        self._require_work(task, incident)
        now = _now()
        changes: dict[str, Any] = {}
        final = task.status in FINAL_TASK_STATUSES
        editing = {"title", "description", "due_at", "result"} & payload.model_fields_set
        if final and editing and payload.status != "open":
            raise CaseTaskStateError("Reopen the task before editing it")
        if payload.title is not None and payload.title != task.title:
            task.title = payload.title
            changes["title"] = True
        if "description" in payload.model_fields_set and payload.description != task.description:
            task.description = payload.description or None
            changes["description"] = True
        if "due_at" in payload.model_fields_set and payload.due_at != task.due_at:
            task.due_at = payload.due_at
            changes["due_at"] = payload.due_at.isoformat() if payload.due_at else None
        if payload.result is not None and payload.result != task.result:
            task.result = payload.result
            changes["result"] = True
        if payload.status is not None and payload.status != task.status:
            allowed = TASK_TRANSITIONS[task.status]
            if payload.status not in allowed:
                raise CaseTaskStateError(
                    f"A task cannot go from {task.status} to {payload.status}",
                    details=[{"status": task.status, "allowed": sorted(allowed)}],
                )
            if payload.status == "done" and not (task.result or "").strip():
                raise CaseTaskStateError("A finished task needs a result")
            previous = task.status
            task.status = payload.status
            if payload.status == "in_progress" and task.started_at is None:
                task.started_at = now
            if payload.status in FINAL_TASK_STATUSES:
                task.completed_at = now
                task.completed_by = self.op.actor.name[:64]
            elif previous in FINAL_TASK_STATUSES:
                task.completed_at = None
                task.completed_by = None
            changes["status"] = {"from": previous, "to": payload.status}
        if not changes:
            return task
        task.updated_at = now
        task.version += 1
        status_change = changes.get("status")
        summary = (
            f"Tarea {task.title}: {status_change['from']} -> {status_change['to']}"
            if isinstance(status_change, dict)
            else f"Tarea {task.title} actualizada"
        )
        # El texto del resultado no va a la auditoría (puede ser largo); solo que cambió.
        self._task_activity(incident, task, "task_updated", summary, now, changes)
        self._session.commit()
        return task

    def assign_task(self, task_id: UUID, payload: TaskAssign) -> IncidentTask:
        task, incident = self._task(task_id, payload.version)
        self._not_frozen(incident)
        if task.status in FINAL_TASK_STATUSES:
            raise CaseTaskStateError("Reopen the task before reassigning it")
        target = (
            self.op.user
            if payload.user_id is None or payload.user_id == self.op.user.public_id
            else self._user(payload.user_id)
        )
        if target.id == self.op.user.id:
            if target.role not in OWNER_ROLES:
                raise IncidentRelationError("Viewers cannot take tasks")
            taken = task.assignee_user_id not in (None, self.op.user.id)
            if taken and not self._is_lead(incident):
                raise PermissionDeniedError(
                    "The task already has an assignee; the incident owner or an administrator "
                    "must reassign it"
                )
        elif not self._is_lead(incident):
            raise PermissionDeniedError(
                "Only the incident owner or an administrator can assign tasks to others"
            )
        if task.assignee_user_id == target.id:
            return task
        now = _now()
        previous = task.assignee
        task.assignee_user_id = target.id
        task.assignee = target.username
        task.assigned_at = now
        task.updated_at = now
        task.version += 1
        self._task_activity(
            incident,
            task,
            "task_assigned",
            f"Tarea {task.title} asignada a {target.username}",
            now,
            {"assignee": target.username, "previous": previous},
        )
        self._session.commit()
        return task

    def unassign_task(self, task_id: UUID, version: int) -> IncidentTask:
        task, incident = self._task(task_id, version)
        self._not_frozen(incident)
        if task.assignee_user_id is None:
            return task
        if task.assignee_user_id != self.op.user.id and not self._is_lead(incident):
            raise PermissionDeniedError(
                "Only the assignee, the incident owner or an administrator can unassign"
            )
        now = _now()
        previous = task.assignee
        task.assignee_user_id = None
        task.assignee = None
        task.assigned_at = None
        task.updated_at = now
        task.version += 1
        self._task_activity(
            incident,
            task,
            "task_unassigned",
            f"Tarea {task.title} sin responsable (antes {previous})",
            now,
            {"previous": previous},
        )
        self._session.commit()
        return task

    def add_task_evidence(self, task_id: UUID, payload: TaskEvidenceAdd) -> IncidentTask:
        task, incident = self._task(task_id, payload.version)
        self._not_frozen(incident)
        self._require_work(task, incident)
        if task.status in FINAL_TASK_STATUSES:
            raise CaseTaskStateError("Reopen the task before adding evidence")
        current = list(task.evidence or [])
        if any(e.get("type") == payload.type and e.get("id") == str(payload.id) for e in current):
            return task
        if len(current) >= MAX_TASK_EVIDENCE:
            raise CaseTaskStateError(f"A task holds at most {MAX_TASK_EVIDENCE} evidence items")
        label = self._evidence_label(payload.type, payload.id, incident)
        now = _now()
        current.append(
            {
                "type": payload.type,
                "id": str(payload.id),
                "label": label[:200],
                "added_by": self.op.actor.name[:64],
                "added_at": now.isoformat(),
            }
        )
        # Lista nueva: SQLAlchemy no detecta cambios dentro de un JSONB mutado en sitio.
        task.evidence = current
        task.updated_at = now
        task.version += 1
        self._task_activity(
            incident,
            task,
            "task_evidence_added",
            f"Evidencia añadida a {task.title}: {label[:120]}",
            now,
            {"type": payload.type, "id": str(payload.id)},
        )
        self._session.commit()
        return task

    def _evidence_label(self, kind: str, public_id: UUID, incident: Incident) -> str:
        """Etiqueta derivada en el servidor; la referencia tiene que existir."""
        if kind == "detection":
            detection = self._session.scalar(
                select(Detection).where(Detection.public_id == public_id)
            )
            if detection is not None:
                return f"Detección {detection.rule_id}: {detection.title}"
        elif kind == "alert":
            alert = self._session.scalar(select(Alert).where(Alert.public_id == public_id))
            if alert is not None:
                return f"Alerta: {alert.message}"
        elif kind == "asset":
            asset = self._session.scalar(select(Asset).where(Asset.public_id == public_id))
            if asset is not None:
                return f"Activo {asset.display_name}"
        elif kind == "vulnerability":
            finding = self._session.scalar(
                select(VulnerabilityFinding).where(VulnerabilityFinding.public_id == public_id)
            )
            if finding is not None:
                return f"{finding.vuln_external_id} {finding.title}"
        elif kind == "tool_execution":
            execution = self._session.scalar(
                select(ToolExecution).where(ToolExecution.public_id == public_id)
            )
            # El historial de herramientas es privado (tools:manage para ver el de otros): solo
            # se adjunta una ejecución propia, del mismo caso, o por un admin.
            if execution is not None and (
                self.op.is_admin
                or execution.actor_user_id == self.op.user.id
                or execution.incident_id == incident.id
            ):
                return f"Herramienta {execution.tool_id} ({execution.status})"
        elif kind == "response_execution":
            response = self._session.scalar(
                select(ResponseExecution).where(ResponseExecution.public_id == public_id)
            )
            if response is not None:
                return f"Response {response.action_id} ({response.status})"
        raise IncidentRelationError(f"The referenced {kind} does not exist")

    # --- Solicitudes de control de red --------------------------------------------------------

    def _control(
        self, control_id: UUID, version: int | None = None
    ) -> tuple[NetworkControlRequest, Incident]:
        incident_id = self._session.scalar(
            select(NetworkControlRequest.incident_id).where(
                NetworkControlRequest.public_id == control_id
            )
        )
        if incident_id is None:
            raise NotFoundError("Network control request not found")
        incident = self._incident_for_update(incident_id)
        control = self._session.scalar(
            select(NetworkControlRequest)
            .where(NetworkControlRequest.public_id == control_id)
            .with_for_update()
        )
        if control is None or control.incident_id != incident.id:
            raise NetworkControlConflictError("The request moved to another incident; reload it")
        if version is not None and control.version != version:
            raise NetworkControlConflictError(
                "The request was changed by someone else; reload it and try again",
                details=[
                    {"control_id": str(control.public_id), "current_version": control.version}
                ],
            )
        now = _now()
        if self._expire(control, incident, now):
            self._session.commit()
            raise NetworkControlStateError("The request expired")
        return control, incident

    def _expire(self, control: NetworkControlRequest, incident: Incident, now: datetime) -> bool:
        if control.status not in OPEN_CONTROL_STATUSES or control.expires_at is None:
            return False
        if control.expires_at > now:
            return False
        control.status = "expired"
        control.updated_at = now
        control.version += 1
        self._activity(
            incident,
            "network_control_expired",
            f"Solicitud de control caducada: {describe(control)}",
            now,
            "network_control",
            control.public_id,
        )
        return True

    def _control_activity(
        self,
        incident: Incident,
        control: NetworkControlRequest,
        action: str,
        summary: str,
        now: datetime,
        details: dict[str, Any] | None = None,
    ) -> None:
        self._activity(
            incident, action, summary, now, "network_control", control.public_id, details
        )
        self._touch(incident, now, bump=False)
        self._audit(
            action,
            incident,
            {
                "control": str(control.public_id),
                "control_type": control.control_type,
                "target": control.target,
                **(details or {}),
            },
        )

    def request_control(
        self, incident_public_id: UUID, payload: NetworkControlCreate
    ) -> NetworkControlRequest:
        incident = self._lock(incident_public_id)
        self._not_frozen(incident)
        now = _now()
        if payload.expires_at is not None:
            if payload.expires_at <= now:
                raise IncidentRelationError("expires_at must be in the future")
            if payload.expires_at > now + timedelta(days=MAX_CONTROL_DAYS):
                raise IncidentRelationError(f"expires_at is at most {MAX_CONTROL_DAYS} days away")
        asset_id: int | None = None
        site_id: int | None = None
        label = "Toda la instalación"
        if payload.asset_id is not None:
            row = self._session.execute(
                select(IncidentAsset.asset_id, IncidentAsset.asset_name).where(
                    IncidentAsset.incident_id == incident.id,
                    IncidentAsset.asset_public_id == payload.asset_id,
                )
            ).first()
            if row is None or row[0] is None:
                raise IncidentRelationError("The asset is not part of this incident")
            asset_id, label = row[0], f"Activo {row[1]}"
        elif payload.site_id is not None:
            site = self._session.scalar(select(Site).where(Site.public_id == payload.site_id))
            if site is None:
                raise IncidentRelationError("Site does not exist")
            site_id, label = site.id, f"Site {site.name}"
        task_pk: int | None = None
        if payload.task_id is not None:
            task_pk = self._session.scalar(
                select(IncidentTask.id).where(
                    IncidentTask.public_id == payload.task_id,
                    IncidentTask.incident_id == incident.id,
                )
            )
            if task_pk is None:
                raise IncidentRelationError("The task is not part of this incident")
        control = NetworkControlRequest(
            incident_id=incident.id,
            task_id=task_pk,
            control_type=payload.control_type,
            target=payload.target,
            direction=payload.direction,
            asset_id=asset_id,
            site_id=site_id,
            scope_label=label[:255],
            justification=payload.justification,
            status="pending_approval",
            enforcement_status="not_evaluated",
            expires_at=payload.expires_at,
            requested_by_user_id=self.op.user.id,
            requested_by=self.op.actor.name[:64],
            created_at=now,
            updated_at=now,
            version=1,
        )
        self._session.add(control)
        self._session.flush()
        self._control_activity(
            incident,
            control,
            "network_control_requested",
            f"Solicitud de control: {describe(control)} ({label})",
            now,
            {"scope": label},
        )
        self._session.commit()
        return control

    def approve_control(
        self, control_id: UUID, payload: NetworkControlDecision
    ) -> NetworkControlRequest:
        control, incident = self._control(control_id, payload.version)
        if control.status != "pending_approval":
            raise NetworkControlStateError("Only pending requests can be approved")
        now = _now()
        evaluation = network_controls.evaluate(control.control_type)
        control.status = "approved"
        control.decided_by_user_id = self.op.user.id
        control.decided_by = self.op.actor.name[:64]
        control.decided_at = now
        control.decision_note = payload.note or None
        control.enforcement = evaluation
        # Sin un punto de control instalado no se aplica nada: queda la decisión registrada.
        control.enforcement_status = (
            "no_enforcement_point" if not evaluation["points"] else "not_evaluated"
        )
        control.updated_at = now
        control.version += 1
        self_approved = control.requested_by_user_id == self.op.user.id
        self._control_activity(
            incident,
            control,
            "network_control_approved",
            f"Control aprobado: {describe(control)}. Sentra no lo aplica (sin punto de control)",
            now,
            {"self_approved": self_approved, "enforcement_points": len(evaluation["points"])},
        )
        self._session.commit()
        return control

    def reject_control(
        self, control_id: UUID, payload: NetworkControlReject
    ) -> NetworkControlRequest:
        control, incident = self._control(control_id, payload.version)
        if control.status != "pending_approval":
            raise NetworkControlStateError("Only pending requests can be rejected")
        now = _now()
        control.status = "rejected"
        control.decided_by_user_id = self.op.user.id
        control.decided_by = self.op.actor.name[:64]
        control.decided_at = now
        control.decision_note = payload.note
        control.updated_at = now
        control.version += 1
        self._control_activity(
            incident,
            control,
            "network_control_rejected",
            f"Control rechazado: {describe(control)}",
            now,
        )
        self._session.commit()
        return control

    def cancel_control(
        self, control_id: UUID, version: int, can_approve: bool
    ) -> NetworkControlRequest:
        control, incident = self._control(control_id, version)
        if control.status not in OPEN_CONTROL_STATUSES:
            raise NetworkControlStateError("Only pending or approved requests can be cancelled")
        if control.requested_by_user_id != self.op.user.id and not can_approve:
            raise PermissionDeniedError(
                "Only the requester or an approver can cancel a network control request"
            )
        now = _now()
        applied = control.enforcement_status == "applied_manually"
        control.status = "cancelled"
        control.updated_at = now
        control.version += 1
        summary = f"Solicitud de control cancelada: {describe(control)}"
        if applied:
            # Se aplicó fuera de Sentra: cancelar aquí no la retira, hay que hacerlo allí.
            summary += ". Estaba aplicada manualmente: retirarla en el punto de control"
        self._control_activity(
            incident,
            control,
            "network_control_cancelled",
            summary,
            now,
            {"was_applied_manually": applied},
        )
        self._session.commit()
        return control

    def mark_control_applied(
        self, control_id: UUID, payload: NetworkControlApplied
    ) -> NetworkControlRequest:
        control, incident = self._control(control_id, payload.version)
        if control.status != "approved" or control.enforcement_status != "no_enforcement_point":
            raise NetworkControlStateError(
                "Only approved requests without an enforcement point can be marked as applied"
            )
        now = _now()
        control.enforcement_status = "applied_manually"
        control.applied_by_user_id = self.op.user.id
        control.applied_by = self.op.actor.name[:64]
        control.applied_at = now
        control.applied_note = payload.note
        control.updated_at = now
        control.version += 1
        self._control_activity(
            incident,
            control,
            "network_control_applied",
            f"Control aplicado fuera de Sentra: {describe(control)}",
            now,
        )
        self._session.commit()
        return control


def describe(control: NetworkControlRequest) -> str:
    """Frase corta del control para el timeline (sin la justificación)."""
    target = control.target or {}
    direction = f" ({control.direction})" if control.direction else ""
    if control.control_type == "block_port":
        return f"bloquear {target.get('protocol')}/{target.get('port')}{direction}"
    if control.control_type == "block_service":
        port = f":{target['port']}" if target.get("port") else ""
        return f"bloquear servicio {target.get('service')}{port}{direction}"
    if control.control_type == "block_address":
        return f"bloquear {target.get('cidr')}{direction}"
    if control.control_type == "block_domain":
        return f"bloquear dominio {target.get('domain')}"
    if control.control_type == "restrict_site_access":
        return f"restringir acceso a {target.get('domain')}"
    return f"impedir subidas a {target.get('destination')}"


def expire_controls(session: Session, now: datetime | None = None) -> int:
    """Barrido periódico (job response-engine): pendientes o aprobadas cuyo plazo venció."""
    now = now or _now()
    rows = list(
        session.scalars(
            select(NetworkControlRequest)
            .where(
                NetworkControlRequest.status.in_(OPEN_CONTROL_STATUSES),
                NetworkControlRequest.expires_at.is_not(None),
                NetworkControlRequest.expires_at <= now,
            )
            .order_by(NetworkControlRequest.id)
            .limit(500)
            .with_for_update(skip_locked=True)
        )
    )
    for control in rows:
        control.status = "expired"
        control.updated_at = now
        control.version += 1
    if rows:
        session.commit()
    return len(rows)


# --- Lecturas ----------------------------------------------------------------------------------


def task_reads(session: Session, tasks: Sequence[IncidentTask]) -> list[TaskRead]:
    if not tasks:
        return []
    now = _now()
    incidents = {
        i.id: i
        for i in session.scalars(
            select(Incident).where(Incident.id.in_({t.incident_id for t in tasks}))
        )
    }
    assets = {
        a.id: a
        for a in session.scalars(
            select(Asset).where(Asset.id.in_({t.asset_id for t in tasks if t.asset_id}))
        )
    }
    users = user_refs(session, [t.assignee_user_id for t in tasks])
    items: list[TaskRead] = []
    for task in tasks:
        incident = incidents[task.incident_id]
        asset = assets.get(task.asset_id or 0)
        items.append(
            TaskRead(
                task_id=task.public_id,
                incident_id=incident.public_id,
                incident_key=incident_key(incident.number),
                kind=task.kind,
                title=task.title,
                description=task.description,
                status=task.status,
                asset=TaskAssetRef(asset_id=asset.public_id, name=asset.display_name)
                if asset
                else None,
                assignee=users.get(task.assignee_user_id or 0),
                assignee_name=task.assignee,
                assigned_at=task.assigned_at,
                created_by=task.created_by,
                created_at=task.created_at,
                updated_at=task.updated_at,
                started_at=task.started_at,
                completed_at=task.completed_at,
                completed_by=task.completed_by,
                due_at=task.due_at,
                overdue=bool(
                    task.due_at and task.due_at < now and task.status in OPEN_TASK_STATUSES
                ),
                result=task.result,
                evidence=[TaskEvidenceRead.model_validate(e) for e in task.evidence or []],
                version=task.version,
                allowed_transitions=sorted(TASK_TRANSITIONS[task.status]),
            )
        )
    return items


def list_tasks(
    session: Session,
    *,
    incident_id: int | None = None,
    assignee_user_id: int | None = None,
    statuses: Sequence[str] = (),
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[TaskRead], int]:
    query = select(IncidentTask)
    if incident_id is not None:
        query = query.where(IncidentTask.incident_id == incident_id)
    if assignee_user_id is not None:
        query = query.where(IncidentTask.assignee_user_id == assignee_user_id)
    if statuses:
        query = query.where(IncidentTask.status.in_(statuses))
    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = list(
        session.scalars(
            query.order_by(IncidentTask.created_at.desc(), IncidentTask.id.desc())
            .limit(limit)
            .offset(offset)
        )
    )
    return task_reads(session, rows), total


def get_task(session: Session, task_id: UUID) -> TaskRead:
    task = session.scalar(select(IncidentTask).where(IncidentTask.public_id == task_id))
    if task is None:
        raise NotFoundError("Task not found")
    return task_reads(session, [task])[0]


def control_reads(
    session: Session, controls: Sequence[NetworkControlRequest]
) -> list[NetworkControlRead]:
    if not controls:
        return []
    incidents = {
        i.id: i
        for i in session.scalars(
            select(Incident).where(Incident.id.in_({c.incident_id for c in controls}))
        )
    }
    tasks = dict(
        session.execute(
            select(IncidentTask.id, IncidentTask.public_id).where(
                IncidentTask.id.in_({c.task_id for c in controls if c.task_id})
            )
        ).all()
    )
    assets = dict(
        session.execute(
            select(Asset.id, Asset.public_id).where(
                Asset.id.in_({c.asset_id for c in controls if c.asset_id})
            )
        ).all()
    )
    sites = dict(
        session.execute(
            select(Site.id, Site.public_id).where(
                Site.id.in_({c.site_id for c in controls if c.site_id})
            )
        ).all()
    )
    items: list[NetworkControlRead] = []
    for control in controls:
        incident = incidents[control.incident_id]
        if control.asset_id is not None:
            scope_type = "asset"
        elif control.site_id is not None:
            scope_type = "site"
        else:
            scope_type = "global"
        items.append(
            NetworkControlRead(
                control_id=control.public_id,
                incident_id=incident.public_id,
                incident_key=incident_key(incident.number),
                task_id=tasks.get(control.task_id or 0),
                control_type=control.control_type,
                target=control.target,
                direction=control.direction,
                scope=ControlScope(
                    type=scope_type,
                    asset_id=assets.get(control.asset_id or 0),
                    site_id=sites.get(control.site_id or 0),
                    label=control.scope_label,
                ),
                justification=control.justification,
                status=control.status,
                enforcement_status=control.enforcement_status,
                enforcement=EnforcementRead.model_validate(control.enforcement)
                if control.enforcement
                else None,
                expires_at=control.expires_at,
                requested_by=control.requested_by,
                created_at=control.created_at,
                updated_at=control.updated_at,
                decided_by=control.decided_by,
                decided_at=control.decided_at,
                decision_note=control.decision_note,
                self_approved=control.decided_by_user_id is not None
                and control.decided_by_user_id == control.requested_by_user_id
                and control.status != "rejected",
                applied_by=control.applied_by,
                applied_at=control.applied_at,
                applied_note=control.applied_note,
                version=control.version,
            )
        )
    return items


def list_controls(
    session: Session,
    *,
    incident_id: int | None = None,
    statuses: Sequence[str] = (),
    control_type: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[NetworkControlRead], int]:
    query = select(NetworkControlRequest)
    if incident_id is not None:
        query = query.where(NetworkControlRequest.incident_id == incident_id)
    if statuses:
        query = query.where(NetworkControlRequest.status.in_(statuses))
    if control_type is not None:
        query = query.where(NetworkControlRequest.control_type == control_type)
    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = list(
        session.scalars(
            query.order_by(NetworkControlRequest.created_at.desc(), NetworkControlRequest.id.desc())
            .limit(limit)
            .offset(offset)
        )
    )
    return control_reads(session, rows), total


def get_control(session: Session, control_id: UUID) -> NetworkControlRead:
    control = session.scalar(
        select(NetworkControlRequest).where(NetworkControlRequest.public_id == control_id)
    )
    if control is None:
        raise NotFoundError("Network control request not found")
    return control_reads(session, [control])[0]


def capabilities() -> ControlCapabilities:
    items = []
    for control_type, requirement in network_controls.REQUIREMENTS.items():
        points = network_controls.enforcement_points(control_type)
        items.append(
            ControlCapability(
                control_type=control_type,
                available=bool(points),
                points=points,
                needs=requirement.needs,
                note=requirement.note,
            )
        )
    return ControlCapabilities(any_available=any(i.available for i in items), items=items)
