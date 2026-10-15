"""Administración de sensores distribuidos (Fase 5F, docs/distributed-sensors.md).

Leer sensores y sus jobs es monitoring:read: nunca incluye credenciales ni hashes. Tokens de
enrolamiento, revocar, deshabilitar, habilitar y pedir rotación exigen sensors:manage (solo
admin): dan o quitan a un proceso remoto la capacidad de observar una red.
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status

from app.api.auth import READ, actor, require_permission
from app.api.deps import AppSettings, DbSession
from app.api.responses import error_responses
from app.core.permissions import Permission
from app.schemas.site import (
    SensorAction,
    SensorEnrollmentCreate,
    SensorEnrollmentCreated,
    SensorEnrollmentList,
    SensorEnrollmentRead,
    SensorJobList,
    SensorList,
    SensorRead,
    SensorRevoke,
)
from app.services.auth_service import AuthContext
from app.services.sensor_service import SensorService
from app.services.site_service import resolve_site

router = APIRouter(prefix="/sensors", tags=["sensors"], responses=error_responses(401, 403))
Manager = Annotated[AuthContext, Depends(require_permission(Permission.SENSORS_MANAGE))]


def get_sensor_service(session: DbSession, settings: AppSettings) -> SensorService:
    return SensorService(session, settings)


Service = Annotated[SensorService, Depends(get_sensor_service)]
SiteFilter = Annotated[UUID | None, Query()]


# Rutas fijas antes que /{sensor_id}: "enrollment-tokens" no es un UUID.
@router.get(
    "/enrollment-tokens", response_model=SensorEnrollmentList, responses=error_responses(404)
)
def list_enrollment_tokens(
    service: Service, session: DbSession, _: Manager, site_id: SiteFilter = None
) -> SensorEnrollmentList:
    return service.enrollment_tokens(resolve_site(session, site_id))


@router.post(
    "/enrollment-tokens",
    response_model=SensorEnrollmentCreated,
    status_code=status.HTTP_201_CREATED,
    responses=error_responses(404, 409),
)
def create_enrollment_token(
    body: SensorEnrollmentCreate, service: Service, ctx: Manager
) -> SensorEnrollmentCreated:
    """El token se devuelve UNA vez; el servidor solo guarda su SHA-256."""
    return service.create_enrollment_token(body, actor(ctx))


@router.post(
    "/enrollment-tokens/{enrollment_id}/revoke",
    response_model=SensorEnrollmentRead,
    responses=error_responses(404, 409),
)
def revoke_enrollment_token(
    enrollment_id: UUID, service: Service, ctx: Manager
) -> SensorEnrollmentRead:
    return service.revoke_enrollment_token(enrollment_id, actor(ctx))


@router.get("", response_model=SensorList, dependencies=[READ], responses=error_responses(404))
def list_sensors(service: Service, session: DbSession, site_id: SiteFilter = None) -> SensorList:
    return service.list(resolve_site(session, site_id))


@router.get(
    "/{sensor_id}", response_model=SensorRead, dependencies=[READ], responses=error_responses(404)
)
def get_sensor(sensor_id: UUID, service: Service) -> SensorRead:
    return service.get(sensor_id)


@router.get(
    "/{sensor_id}/jobs",
    response_model=SensorJobList,
    dependencies=[READ],
    responses=error_responses(404),
)
def sensor_jobs(
    sensor_id: UUID, service: Service, limit: Annotated[int, Query(ge=1, le=200)] = 20
) -> SensorJobList:
    return service.jobs(sensor_id, limit)


@router.post("/{sensor_id}/revoke", response_model=SensorRead, responses=error_responses(404, 409))
def revoke_sensor(
    sensor_id: UUID, body: SensorRevoke, service: Service, ctx: Manager
) -> SensorRead:
    """Irreversible: la credencial deja de valer y sus jobs abiertos se cancelan. El
    historial (observaciones, activos, auditoría) se conserva."""
    return service.revoke(sensor_id, body, actor(ctx))


@router.post("/{sensor_id}/disable", response_model=SensorRead, responses=error_responses(404, 409))
def disable_sensor(
    sensor_id: UUID, body: SensorAction, service: Service, ctx: Manager
) -> SensorRead:
    return service.disable(sensor_id, body, actor(ctx))


@router.post("/{sensor_id}/enable", response_model=SensorRead, responses=error_responses(404, 409))
def enable_sensor(
    sensor_id: UUID, body: SensorAction, service: Service, ctx: Manager
) -> SensorRead:
    return service.enable(sensor_id, body, actor(ctx))


@router.post(
    "/{sensor_id}/rotate-credential",
    response_model=SensorRead,
    responses=error_responses(404, 409),
)
def rotate_sensor_credential(
    sensor_id: UUID, body: SensorAction, service: Service, ctx: Manager
) -> SensorRead:
    """Marca la rotación como pendiente; el sensor la ejecuta en su siguiente heartbeat. El
    secreto nuevo solo viaja al sensor: el admin nunca lo ve."""
    return service.request_rotation(sensor_id, body, actor(ctx))
