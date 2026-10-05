"""Gestión de incidentes SOC (Fase 4K). Ver docs/incident-management.md.

Permisos (comprobados en el backend en cada petición; ocultar botones es solo UX):
- incidents:read  (viewer, analyst, admin): listar y ver casos, timeline, evidencia, notas;
- incidents:manage (analyst, admin): crear, promover, estados de trabajo, notas, adjuntar,
  asignarse, resolver;
- incidents:admin (admin): asignar a otros, cerrar, reabrir y fusionar.

Todas las mutaciones usan la sesión del dashboard con CSRF (require_permission) y quedan en
audit_events, también los intentos fallidos (404/409/422).
"""

from collections.abc import Callable
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Body, Depends, Query, status

from app.api.auth import actor, require_permission
from app.api.deps import DbSession
from app.api.params import text_query
from app.api.responses import error_responses
from app.core.exceptions import SentraError
from app.core.permissions import Permission
from app.incidents.workflow import incident_key
from app.models.incident import IncidentLevel, IncidentStatus
from app.schemas.incident import (
    AssignableUserList,
    IncidentAssign,
    IncidentAuditList,
    IncidentCreate,
    IncidentDetail,
    IncidentEvidence,
    IncidentList,
    IncidentMerge,
    IncidentNoteCreate,
    IncidentNoteList,
    IncidentNoteRead,
    IncidentOverview,
    IncidentPromote,
    IncidentResolve,
    IncidentTimeline,
    IncidentUpdate,
    IncidentVersioned,
    RelatedIncidentList,
)
from app.services import audit_service
from app.services.auth_service import AuthContext
from app.services.incident_queries import IncidentFilter, IncidentQueries, IncidentSort
from app.services.incident_service import (
    IncidentService,
    Operator,
    detail,
    get_incident,
)

router = APIRouter(tags=["incidents"], responses=error_responses(401, 403))

Reader = Annotated[AuthContext, Depends(require_permission(Permission.INCIDENTS_READ))]
Manager = Annotated[AuthContext, Depends(require_permission(Permission.INCIDENTS_MANAGE))]
Admin = Annotated[AuthContext, Depends(require_permission(Permission.INCIDENTS_ADMIN))]

_MUTATION_ERRORS = error_responses(404, 409, 422)


def _service(session: DbSession, ctx: AuthContext) -> IncidentService:
    return IncidentService(session, Operator.from_context(ctx.user, ctx.client_ip, ctx.permissions))


def _audited[T](
    session: DbSession,
    ctx: AuthContext,
    action: str,
    target_type: str,
    target: object,
    run: Callable[[], T],
) -> T:
    """Ejecuta la operación; si falla (404/409/422) audita el intento con su código."""
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


def _detail(session: DbSession, incident_id: UUID) -> IncidentDetail:
    return detail(session, get_incident(session, incident_id))


# --- Lecturas --------------------------------------------------------------------------------


@router.get("/incidents", response_model=IncidentList, responses=error_responses(404))
def list_incidents(
    ctx: Reader,
    session: DbSession,
    status: IncidentStatus | None = None,
    # Solo casos vivos (open, triage, investigating, contained); se ignora con `status`.
    active: bool = False,
    severity: IncidentLevel | None = None,
    priority: IncidentLevel | None = None,
    # "me", "unassigned" o el id público de un usuario.
    owner: Annotated[
        str | None, Query(max_length=36, pattern=r"^(me|unassigned|[0-9a-f-]{36})$")
    ] = None,
    asset_id: UUID | None = None,
    # Rango sobre la fecha de creación.
    since: datetime | None = None,
    until: datetime | None = None,
    # INC-000123, título, hostname, IP o título de detección.
    q: Annotated[str | None, text_query(200)] = None,
    sort: IncidentSort = "last_activity",
    order: Literal["asc", "desc"] = "desc",
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> IncidentList:
    return IncidentQueries(session, ctx.user).find(
        IncidentFilter(
            status=status,
            active=active,
            severity=severity,
            priority=priority,
            owner=owner,
            asset_public_id=asset_id,
            since=since,
            until=until,
            search=q.strip() if q and q.strip() else None,
        ),
        sort,
        order == "desc",
        limit,
        offset,
    )


@router.get("/incidents/overview", response_model=IncidentOverview)
def incidents_overview(ctx: Reader, session: DbSession) -> IncidentOverview:
    """Resumen SOC: casos por estado, críticos, sin asignar, míos y actividad reciente."""
    return IncidentQueries(session, ctx.user).overview()


@router.get("/incidents/assignees", response_model=AssignableUserList)
def incident_assignees(_: Manager, session: DbSession) -> AssignableUserList:
    """Usuarios activos que pueden ser owner (analyst y admin; nunca viewer)."""
    return IncidentQueries(session).assignable_users()


@router.get(
    "/incidents/{incident_id}", response_model=IncidentDetail, responses=error_responses(404)
)
def get_incident_detail(incident_id: UUID, _: Reader, session: DbSession) -> IncidentDetail:
    return _detail(session, incident_id)


@router.get(
    "/incidents/{incident_id}/timeline",
    response_model=IncidentTimeline,
    responses=error_responses(404),
)
def incident_timeline(
    incident_id: UUID,
    _: Reader,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    cursor: Annotated[str | None, Query(max_length=200)] = None,
    since: datetime | None = None,
    until: datetime | None = None,
) -> IncidentTimeline:
    """Timeline unificado, más reciente primero, paginado con `cursor` (next_cursor)."""
    return IncidentQueries(session).timeline(incident_id, limit, cursor, since, until)


@router.get(
    "/incidents/{incident_id}/evidence",
    response_model=IncidentEvidence,
    responses=error_responses(404),
)
def incident_evidence(incident_id: UUID, _: Reader, session: DbSession) -> IncidentEvidence:
    return IncidentQueries(session).evidence(incident_id)


@router.get(
    "/incidents/{incident_id}/notes",
    response_model=IncidentNoteList,
    responses=error_responses(404),
)
def incident_notes(
    incident_id: UUID,
    _: Reader,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> IncidentNoteList:
    return IncidentQueries(session).notes(incident_id, limit, offset)


@router.get(
    "/incidents/{incident_id}/audit",
    response_model=IncidentAuditList,
    responses=error_responses(404),
)
def incident_audit(
    incident_id: UUID,
    _: Reader,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> IncidentAuditList:
    """Auditoría de este caso (sin secretos: los detalles ya están filtrados)."""
    return IncidentQueries(session).audit(incident_id, limit, offset)


@router.get(
    "/detections/{detection_id}/related-incidents",
    response_model=RelatedIncidentList,
    responses=error_responses(404),
)
def detection_related_incidents(
    detection_id: UUID, ctx: Reader, session: DbSession
) -> RelatedIncidentList:
    """Casos activos posiblemente relacionados (sugerencia; nada se adjunta solo)."""
    return IncidentQueries(session, ctx.user).related_for_detection(detection_id)


@router.get(
    "/alerts/{alert_id}/related-incidents",
    response_model=RelatedIncidentList,
    responses=error_responses(404),
)
def alert_related_incidents(alert_id: UUID, ctx: Reader, session: DbSession) -> RelatedIncidentList:
    return IncidentQueries(session, ctx.user).related_for_alert(alert_id)


# --- Creación ---------------------------------------------------------------------------------


@router.post(
    "/incidents",
    response_model=IncidentDetail,
    status_code=status.HTTP_201_CREATED,
    responses=_MUTATION_ERRORS,
)
def create_incident(payload: IncidentCreate, ctx: Manager, session: DbSession) -> IncidentDetail:
    service = _service(session, ctx)
    incident = _audited(
        session, ctx, "incident_created", "incident", None, lambda: service.create(payload)
    )
    return _detail(session, incident.public_id)


@router.post(
    "/detections/{detection_id}/incident",
    response_model=IncidentDetail,
    status_code=status.HTTP_201_CREATED,
    responses=_MUTATION_ERRORS,
)
def promote_detection(
    detection_id: UUID,
    ctx: Manager,
    session: DbSession,
    payload: Annotated[IncidentPromote | None, Body()] = None,
) -> IncidentDetail:
    """Crea un incidente desde la detección (reutiliza detección, activo, alerta y riesgo)."""
    service = _service(session, ctx)
    incident = _audited(
        session,
        ctx,
        "incident_created",
        "detection",
        detection_id,
        lambda: service.promote_detection(detection_id, payload or IncidentPromote()),
    )
    return _detail(session, incident.public_id)


@router.post(
    "/alerts/{alert_id}/incident",
    response_model=IncidentDetail,
    status_code=status.HTTP_201_CREATED,
    responses=_MUTATION_ERRORS,
)
def promote_alert(
    alert_id: UUID,
    ctx: Manager,
    session: DbSession,
    payload: Annotated[IncidentPromote | None, Body()] = None,
) -> IncidentDetail:
    """Crea un incidente desde la alerta (reutiliza su detección y activo si existen)."""
    service = _service(session, ctx)
    incident = _audited(
        session,
        ctx,
        "incident_created",
        "alert",
        alert_id,
        lambda: service.promote_alert(alert_id, payload or IncidentPromote()),
    )
    return _detail(session, incident.public_id)


# --- Flujo de trabajo -------------------------------------------------------------------------


@router.patch("/incidents/{incident_id}", response_model=IncidentDetail, responses=_MUTATION_ERRORS)
def update_incident(
    incident_id: UUID, payload: IncidentUpdate, ctx: Manager, session: DbSession
) -> IncidentDetail:
    service = _service(session, ctx)
    action = "incident_status_changed" if payload.status is not None else "incident_updated"
    _audited(
        session,
        ctx,
        action,
        "incident",
        incident_id,
        lambda: service.update(incident_id, payload),
    )
    return _detail(session, incident_id)


@router.post(
    "/incidents/{incident_id}/assign", response_model=IncidentDetail, responses=_MUTATION_ERRORS
)
def assign_incident(
    incident_id: UUID, payload: IncidentAssign, ctx: Manager, session: DbSession
) -> IncidentDetail:
    """Sin `user_id`: asignarse a uno mismo. A otro usuario: solo admin (incidents:admin)."""
    service = _service(session, ctx)
    _audited(
        session,
        ctx,
        "incident_assigned",
        "incident",
        incident_id,
        lambda: service.assign(incident_id, payload),
    )
    return _detail(session, incident_id)


@router.post(
    "/incidents/{incident_id}/unassign", response_model=IncidentDetail, responses=_MUTATION_ERRORS
)
def unassign_incident(
    incident_id: UUID, payload: IncidentVersioned, ctx: Manager, session: DbSession
) -> IncidentDetail:
    service = _service(session, ctx)
    _audited(
        session,
        ctx,
        "incident_unassigned",
        "incident",
        incident_id,
        lambda: service.unassign(incident_id, payload.version),
    )
    return _detail(session, incident_id)


@router.post(
    "/incidents/{incident_id}/notes",
    response_model=IncidentNoteRead,
    status_code=status.HTTP_201_CREATED,
    responses=_MUTATION_ERRORS,
)
def add_incident_note(
    incident_id: UUID, payload: IncidentNoteCreate, ctx: Manager, session: DbSession
) -> IncidentNoteRead:
    """Nota append-only. Texto plano no confiable: la UI nunca lo interpreta como HTML."""
    service = _service(session, ctx)
    note = _audited(
        session,
        ctx,
        "incident_note_added",
        "incident",
        incident_id,
        lambda: service.add_note(incident_id, payload.body),
    )
    incident = get_incident(session, incident_id)
    return IncidentNoteRead(
        note_id=note.public_id,
        author=note.author,
        body=note.body,
        created_at=note.created_at,
        incident_key=incident_key(incident.number),
    )


@router.post(
    "/incidents/{incident_id}/resolve", response_model=IncidentDetail, responses=_MUTATION_ERRORS
)
def resolve_incident(
    incident_id: UUID, payload: IncidentResolve, ctx: Manager, session: DbSession
) -> IncidentDetail:
    """Exige categoría de resolución. Reconocer (acknowledge) NO es resolver."""
    service = _service(session, ctx)
    _audited(
        session,
        ctx,
        "incident_resolved",
        "incident",
        incident_id,
        lambda: service.resolve(incident_id, payload),
    )
    return _detail(session, incident_id)


@router.post(
    "/incidents/{incident_id}/close", response_model=IncidentDetail, responses=_MUTATION_ERRORS
)
def close_incident(
    incident_id: UUID, payload: IncidentVersioned, ctx: Admin, session: DbSession
) -> IncidentDetail:
    service = _service(session, ctx)
    _audited(
        session,
        ctx,
        "incident_closed",
        "incident",
        incident_id,
        lambda: service.close(incident_id, payload.version),
    )
    return _detail(session, incident_id)


@router.post(
    "/incidents/{incident_id}/reopen", response_model=IncidentDetail, responses=_MUTATION_ERRORS
)
def reopen_incident(
    incident_id: UUID, payload: IncidentVersioned, ctx: Admin, session: DbSession
) -> IncidentDetail:
    service = _service(session, ctx)
    _audited(
        session,
        ctx,
        "incident_reopened",
        "incident",
        incident_id,
        lambda: service.reopen(incident_id, payload.version),
    )
    return _detail(session, incident_id)


@router.post(
    "/incidents/{incident_id}/merge", response_model=IncidentDetail, responses=_MUTATION_ERRORS
)
def merge_incident(
    incident_id: UUID, payload: IncidentMerge, ctx: Admin, session: DbSession
) -> IncidentDetail:
    """Fusiona este incidente EN `target_id`; devuelve el destino. No borra historial."""
    service = _service(session, ctx)
    target = _audited(
        session,
        ctx,
        "incident_merged",
        "incident",
        incident_id,
        lambda: service.merge(incident_id, payload),
    )
    return _detail(session, target.public_id)


@router.post(
    "/incidents/{incident_id}/detections/{detection_id}",
    response_model=IncidentDetail,
    responses=_MUTATION_ERRORS,
)
def attach_detection(
    incident_id: UUID, detection_id: UUID, ctx: Manager, session: DbSession
) -> IncidentDetail:
    """Adjunta una detección existente (idempotente: repetirlo no duplica nada)."""
    service = _service(session, ctx)
    _audited(
        session,
        ctx,
        "incident_detection_attached",
        "incident",
        incident_id,
        lambda: service.attach_detection(incident_id, detection_id),
    )
    return _detail(session, incident_id)


@router.post(
    "/incidents/{incident_id}/alerts/{alert_id}",
    response_model=IncidentDetail,
    responses=_MUTATION_ERRORS,
)
def attach_alert(
    incident_id: UUID, alert_id: UUID, ctx: Manager, session: DbSession
) -> IncidentDetail:
    service = _service(session, ctx)
    _audited(
        session,
        ctx,
        "incident_alert_attached",
        "incident",
        incident_id,
        lambda: service.attach_alert(incident_id, alert_id),
    )
    return _detail(session, incident_id)


@router.post(
    "/incidents/{incident_id}/assets/{asset_id}",
    response_model=IncidentDetail,
    responses=_MUTATION_ERRORS,
)
def add_incident_asset(
    incident_id: UUID, asset_id: UUID, ctx: Manager, session: DbSession
) -> IncidentDetail:
    service = _service(session, ctx)
    _audited(
        session,
        ctx,
        "incident_updated",
        "incident",
        incident_id,
        lambda: service.add_asset(incident_id, asset_id),
    )
    return _detail(session, incident_id)
