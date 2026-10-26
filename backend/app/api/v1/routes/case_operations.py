"""Tareas de caso y solicitudes de control de red (Fase 7A.6). Ver docs/case-operations.md.

Permisos (comprobados en el backend en cada petición):
- incidents:read: ver tareas, solicitudes y qué puntos de control existen;
- incidents:manage: crear y trabajar tareas, pedir controles y cancelar los propios;
- network_controls:approve (admin): aprobar, rechazar, cancelar cualquiera y registrar que
  un control se aplicó fuera de Sentra.

Aprobar no ejecuta nada en la red: ver app/incidents/network_controls.py.
"""

from collections.abc import Callable
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status

from app.api.auth import actor, require_permission
from app.api.deps import DbSession
from app.api.responses import error_responses
from app.core.exceptions import SentraError
from app.core.permissions import Permission
from app.schemas.case_operations import (
    ControlCapabilities,
    ControlStatus,
    ControlType,
    NetworkControlApplied,
    NetworkControlCreate,
    NetworkControlDecision,
    NetworkControlList,
    NetworkControlRead,
    NetworkControlReject,
    TaskAssign,
    TaskCreate,
    TaskEvidenceAdd,
    TaskList,
    TaskRead,
    TaskStatus,
    TaskUpdate,
    TaskVersioned,
)
from app.schemas.incident import IncidentVersioned
from app.services import audit_service
from app.services.auth_service import AuthContext
from app.services.case_operations_service import (
    CaseOperationsService,
    capabilities,
    get_control,
    get_task,
    list_controls,
    list_tasks,
)
from app.services.incident_service import Operator, get_incident

router = APIRouter(tags=["case-operations"], responses=error_responses(401, 403))

Reader = Annotated[AuthContext, Depends(require_permission(Permission.INCIDENTS_READ))]
Manager = Annotated[AuthContext, Depends(require_permission(Permission.INCIDENTS_MANAGE))]
Approver = Annotated[AuthContext, Depends(require_permission(Permission.NETWORK_CONTROLS_APPROVE))]

_MUTATION_ERRORS = error_responses(404, 409, 422)


def _service(session: DbSession, ctx: AuthContext) -> CaseOperationsService:
    return CaseOperationsService(
        session, Operator.from_context(ctx.user, ctx.client_ip, ctx.permissions)
    )


def _audited[T](
    session: DbSession,
    ctx: AuthContext,
    action: str,
    target_type: str,
    target: object,
    run: Callable[[], T],
) -> T:
    """Ejecuta la operación; si falla (403/404/409/422) audita el intento con su código."""
    try:
        return run()
    except SentraError as exc:
        session.rollback()
        audit_service.record(
            session,
            actor(ctx),
            action,
            audit_service.FAILURE,
            target_type,
            target,
            details={"error": exc.code},
        )
        raise


# --- Tareas ------------------------------------------------------------------------------------


@router.get(
    "/incidents/{incident_id}/tasks", response_model=TaskList, responses=error_responses(404)
)
def incident_tasks(incident_id: UUID, _: Reader, session: DbSession) -> TaskList:
    incident = get_incident(session, incident_id)
    items, total = list_tasks(session, incident_id=incident.id, limit=200)
    return TaskList(items=items, total=total)


@router.post(
    "/incidents/{incident_id}/tasks",
    response_model=TaskRead,
    status_code=status.HTTP_201_CREATED,
    responses=_MUTATION_ERRORS,
)
def create_task(
    incident_id: UUID, payload: TaskCreate, ctx: Manager, session: DbSession
) -> TaskRead:
    service = _service(session, ctx)
    task = _audited(
        session,
        ctx,
        "incident_task_created",
        "incident",
        incident_id,
        lambda: service.create_task(incident_id, payload),
    )
    return get_task(session, task.public_id)


@router.get("/tasks", response_model=TaskList)
def tasks(
    ctx: Reader,
    session: DbSession,
    # Solo las tareas asignadas al usuario de la sesión ("mis tareas").
    mine: bool = False,
    task_status: Annotated[list[TaskStatus] | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> TaskList:
    items, total = list_tasks(
        session,
        assignee_user_id=ctx.user.id if mine else None,
        statuses=task_status or (),
        limit=limit,
        offset=offset,
    )
    return TaskList(items=items, total=total)


@router.get("/tasks/{task_id}", response_model=TaskRead, responses=error_responses(404))
def task_detail(task_id: UUID, _: Reader, session: DbSession) -> TaskRead:
    return get_task(session, task_id)


@router.patch("/tasks/{task_id}", response_model=TaskRead, responses=_MUTATION_ERRORS)
def update_task(task_id: UUID, payload: TaskUpdate, ctx: Manager, session: DbSession) -> TaskRead:
    service = _service(session, ctx)
    _audited(
        session,
        ctx,
        "incident_task_updated",
        "task",
        task_id,
        lambda: service.update_task(task_id, payload),
    )
    return get_task(session, task_id)


@router.post("/tasks/{task_id}/assign", response_model=TaskRead, responses=_MUTATION_ERRORS)
def assign_task(task_id: UUID, payload: TaskAssign, ctx: Manager, session: DbSession) -> TaskRead:
    service = _service(session, ctx)
    _audited(
        session,
        ctx,
        "incident_task_assigned",
        "task",
        task_id,
        lambda: service.assign_task(task_id, payload),
    )
    return get_task(session, task_id)


@router.post("/tasks/{task_id}/unassign", response_model=TaskRead, responses=_MUTATION_ERRORS)
def unassign_task(
    task_id: UUID, payload: TaskVersioned, ctx: Manager, session: DbSession
) -> TaskRead:
    service = _service(session, ctx)
    _audited(
        session,
        ctx,
        "incident_task_unassigned",
        "task",
        task_id,
        lambda: service.unassign_task(task_id, payload.version),
    )
    return get_task(session, task_id)


@router.post("/tasks/{task_id}/evidence", response_model=TaskRead, responses=_MUTATION_ERRORS)
def add_task_evidence(
    task_id: UUID, payload: TaskEvidenceAdd, ctx: Manager, session: DbSession
) -> TaskRead:
    service = _service(session, ctx)
    _audited(
        session,
        ctx,
        "incident_task_evidence_added",
        "task",
        task_id,
        lambda: service.add_task_evidence(task_id, payload),
    )
    return get_task(session, task_id)


# --- Solicitudes de control de red --------------------------------------------------------------


@router.get("/network-controls", response_model=NetworkControlList, responses=error_responses(404))
def network_controls(
    _: Reader,
    session: DbSession,
    incident_id: UUID | None = None,
    control_status: Annotated[list[ControlStatus] | None, Query(alias="status")] = None,
    control_type: ControlType | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> NetworkControlList:
    incident_pk = get_incident(session, incident_id).id if incident_id is not None else None
    items, total = list_controls(
        session,
        incident_id=incident_pk,
        statuses=control_status or (),
        control_type=control_type,
        limit=limit,
        offset=offset,
    )
    return NetworkControlList(items=items, total=total)


@router.get("/network-controls/capabilities", response_model=ControlCapabilities)
def network_control_capabilities(_: Reader) -> ControlCapabilities:
    """Puntos de control instalados por tipo. En 7A, ninguno: Sentra no aplica controles."""
    return capabilities()


@router.get(
    "/network-controls/{control_id}",
    response_model=NetworkControlRead,
    responses=error_responses(404),
)
def network_control_detail(control_id: UUID, _: Reader, session: DbSession) -> NetworkControlRead:
    return get_control(session, control_id)


@router.post(
    "/incidents/{incident_id}/network-controls",
    response_model=NetworkControlRead,
    status_code=status.HTTP_201_CREATED,
    responses=_MUTATION_ERRORS,
)
def request_network_control(
    incident_id: UUID, payload: NetworkControlCreate, ctx: Manager, session: DbSession
) -> NetworkControlRead:
    service = _service(session, ctx)
    control = _audited(
        session,
        ctx,
        "network_control_requested",
        "incident",
        incident_id,
        lambda: service.request_control(incident_id, payload),
    )
    return get_control(session, control.public_id)


@router.post(
    "/network-controls/{control_id}/approve",
    response_model=NetworkControlRead,
    responses=_MUTATION_ERRORS,
)
def approve_network_control(
    control_id: UUID, payload: NetworkControlDecision, ctx: Approver, session: DbSession
) -> NetworkControlRead:
    service = _service(session, ctx)
    _audited(
        session,
        ctx,
        "network_control_approved",
        "network_control",
        control_id,
        lambda: service.approve_control(control_id, payload),
    )
    return get_control(session, control_id)


@router.post(
    "/network-controls/{control_id}/reject",
    response_model=NetworkControlRead,
    responses=_MUTATION_ERRORS,
)
def reject_network_control(
    control_id: UUID, payload: NetworkControlReject, ctx: Approver, session: DbSession
) -> NetworkControlRead:
    service = _service(session, ctx)
    _audited(
        session,
        ctx,
        "network_control_rejected",
        "network_control",
        control_id,
        lambda: service.reject_control(control_id, payload),
    )
    return get_control(session, control_id)


@router.post(
    "/network-controls/{control_id}/cancel",
    response_model=NetworkControlRead,
    responses=_MUTATION_ERRORS,
)
def cancel_network_control(
    control_id: UUID, payload: IncidentVersioned, ctx: Manager, session: DbSession
) -> NetworkControlRead:
    service = _service(session, ctx)
    can_approve = ctx.has(Permission.NETWORK_CONTROLS_APPROVE)
    _audited(
        session,
        ctx,
        "network_control_cancelled",
        "network_control",
        control_id,
        lambda: service.cancel_control(control_id, payload.version, can_approve),
    )
    return get_control(session, control_id)


@router.post(
    "/network-controls/{control_id}/mark-applied",
    response_model=NetworkControlRead,
    responses=_MUTATION_ERRORS,
)
def mark_network_control_applied(
    control_id: UUID, payload: NetworkControlApplied, ctx: Approver, session: DbSession
) -> NetworkControlRead:
    """Registra que el control se aplicó FUERA de Sentra (Sentra no lo aplica)."""
    service = _service(session, ctx)
    _audited(
        session,
        ctx,
        "network_control_applied",
        "network_control",
        control_id,
        lambda: service.mark_control_applied(control_id, payload),
    )
    return get_control(session, control_id)
