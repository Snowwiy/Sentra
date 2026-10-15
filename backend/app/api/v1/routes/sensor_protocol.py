"""Protocolo máquina-a-servidor de los sensores (Fase 5F, docs/sensor-security.md).

No usa la sesión del dashboard ni CSRF: el sensor se autentica con su credencial Bearer
propia (solo se guarda su SHA-256) y el enrolamiento con un token de un solo uso en
X-Sensor-Enrollment-Token. Siempre iniciado por el sensor (HTTPS saliente, compatible con
NAT): el servidor nunca abre conexiones hacia la red remota.

El site de todo lo que envía el sensor sale de su credencial, nunca del cuerpo. Límites:
tamaño de cuerpo (SENSOR_MAX_REQUEST_KB, middleware), enrolamiento por IP y heartbeat/poll
por sensor (429 con Retry-After), lotes y observaciones acotados en el servicio.
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Request, status

from app.api.auth import client_ip
from app.api.deps import AgentToken, AppSettings, DbSession, Thresholds
from app.api.responses import error_responses
from app.core.exceptions import RateLimitedError
from app.core.rate_limit import Limiter
from app.schemas.site import (
    SensorEnrollRequest,
    SensorEnrollResponse,
    SensorHeartbeatRequest,
    SensorHeartbeatResponse,
    SensorJobComplete,
    SensorJobCompleted,
    SensorJobStart,
    SensorJobStarted,
    SensorPollRequest,
    SensorPollResponse,
    SensorResultsRequest,
    SensorResultsResponse,
    SensorRotateResponse,
)
from app.services.sensor_service import SensorProtocol

router = APIRouter(prefix="/sensor", tags=["sensor protocol"])

EnrollmentHeader = Annotated[str | None, Header(alias="X-Sensor-Enrollment-Token")]
# Misma extracción Bearer que los agentes (auto_error=False: la ausencia da el 401 propio).
Credential = AgentToken


def get_sensor_protocol(session: DbSession, settings: AppSettings) -> SensorProtocol:
    return SensorProtocol(session, settings)


Protocol = Annotated[SensorProtocol, Depends(get_sensor_protocol)]


def _limit(request: Request, name: str, key: str, scope: str) -> None:
    limiter: Limiter = getattr(request.app.state, name)
    wait = limiter.acquire(key)
    if wait > 0:
        raise RateLimitedError("Too many sensor requests, retry later", wait, scope)


def limit_enroll(request: Request) -> None:
    """Frena la prueba masiva de tokens: por dirección, antes de tocar la base de datos."""
    _limit(request, "sensor_enroll_limiter", client_ip(request) or "unknown", "sensor_enroll")


_AUTH = error_responses(401, 403, 413, 429)


@router.post(
    "/enroll",
    response_model=SensorEnrollResponse,
    status_code=status.HTTP_201_CREATED,
    responses=_AUTH,
    dependencies=[Depends(limit_enroll)],
)
def enroll(
    body: SensorEnrollRequest,
    request: Request,
    protocol: Protocol,
    token: EnrollmentHeader = None,
) -> SensorEnrollResponse:
    return protocol.enroll(token, body, client_ip(request))


@router.post("/heartbeat", response_model=SensorHeartbeatResponse, responses=_AUTH)
def heartbeat(
    body: SensorHeartbeatRequest, request: Request, protocol: Protocol, credential: Credential
) -> SensorHeartbeatResponse:
    sensor = protocol.authenticate(credential)
    _limit(request, "sensor_heartbeat_limiter", str(sensor.public_id), "sensor_heartbeat")
    return protocol.heartbeat(sensor, body)


@router.post("/jobs/poll", response_model=SensorPollResponse, responses=_AUTH)
def poll(
    body: SensorPollRequest, request: Request, protocol: Protocol, credential: Credential
) -> SensorPollResponse:
    sensor = protocol.authenticate(credential)
    _limit(request, "sensor_poll_limiter", str(sensor.public_id), "sensor_poll")
    return protocol.poll(sensor, body)


@router.post(
    "/jobs/{job_id}/start",
    response_model=SensorJobStarted,
    responses=error_responses(401, 403, 404, 409, 413, 429),
)
def start_job(
    job_id: UUID, body: SensorJobStart, protocol: Protocol, credential: Credential
) -> SensorJobStarted:
    sensor = protocol.authenticate(credential, allow_disabled=False)
    return protocol.start(sensor, job_id, body)


@router.post(
    "/jobs/{job_id}/results",
    response_model=SensorResultsResponse,
    responses=error_responses(401, 403, 404, 409, 413, 429),
)
def job_results(
    job_id: UUID, body: SensorResultsRequest, protocol: Protocol, credential: Credential
) -> SensorResultsResponse:
    sensor = protocol.authenticate(credential, allow_disabled=False)
    return protocol.results(sensor, job_id, body)


@router.post(
    "/jobs/{job_id}/complete",
    response_model=SensorJobCompleted,
    responses=error_responses(401, 403, 404, 409, 413, 429),
)
def complete_job(
    job_id: UUID,
    body: SensorJobComplete,
    protocol: Protocol,
    credential: Credential,
    thresholds: Thresholds,
) -> SensorJobCompleted:
    sensor = protocol.authenticate(credential, allow_disabled=False)
    return protocol.complete(sensor, job_id, body, thresholds)


@router.post("/credential/rotate", response_model=SensorRotateResponse, responses=_AUTH)
def rotate_credential(
    request: Request, protocol: Protocol, credential: Credential
) -> SensorRotateResponse:
    sensor = protocol.authenticate(credential, allow_disabled=False)
    return protocol.rotate(sensor, client_ip(request))
