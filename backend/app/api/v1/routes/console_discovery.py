"""Consola del dashboard: iniciar y cancelar descubrimientos de red.

SENSIBLE: es una operación activa sobre la red. Desde la Fase 4G exige sesión y el permiso
discovery:run (admin y analyst; viewer solo puede consultar). Ninguna clave (ADMIN_API_KEY)
llega al navegador.

La validación del target se repite aquí aunque el frontend solo ofrezca redes autorizadas:
el navegador no es una frontera de seguridad.
"""

import logging
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, status

from app.api.auth import actor, require_permission
from app.api.deps import DbSession, get_exposure_service
from app.api.responses import error_responses
from app.core.exceptions import DiscoveryDisabledError, DiscoveryTargetError, SentraError
from app.core.permissions import Permission
from app.discovery.targets import TargetError
from app.schemas.discovery import DiscoveryJobCreate, DiscoveryJobDetail
from app.services import audit_service
from app.services.auth_service import AuthContext
from app.services.discovery_runner import DiscoveryRunner, get_discovery_runner
from app.services.discovery_service import request_cancel
from app.services.exposure_service import ExposureService

logger = logging.getLogger(__name__)

VIA = "dashboard"

router = APIRouter(
    prefix="/console/discovery",
    tags=["console"],
    responses=error_responses(401, 403),
)
Operator = Annotated[AuthContext, Depends(require_permission(Permission.DISCOVERY_RUN))]
Runner = Annotated[DiscoveryRunner, Depends(get_discovery_runner)]
Exposure = Annotated[ExposureService, Depends(get_exposure_service)]


@router.post(
    "/jobs",
    response_model=DiscoveryJobDetail,
    status_code=status.HTTP_202_ACCEPTED,
    responses=error_responses(409),
)
def start_discovery(
    payload: DiscoveryJobCreate,
    runner: Runner,
    exposure: Exposure,
    ctx: Operator,
    session: DbSession,
) -> DiscoveryJobDetail:
    """Encola un descubrimiento y responde al momento (202) con el job en cola.

    El scan corre en segundo plano; la web sigue su estado con GET /discovery/jobs/{id}.
    """
    try:
        if not runner.service.scope.enabled:
            raise DiscoveryDisabledError(
                "Network discovery is disabled: set DISCOVERY_ALLOWED_NETWORKS on the server"
            )
        try:
            public_id = runner.submit(payload.target, VIA)
        except TargetError as exc:
            # Mismo motivo que daría la CLI (fuera de la allowlist, demasiado grande,
            # multicast, pública...). No incluye nada que no haya enviado el propio cliente.
            raise DiscoveryTargetError(str(exc)) from exc
    except SentraError as exc:
        audit_service.record(
            session,
            actor(ctx),
            "discovery_started",
            audit_service.FAILURE,
            "network",
            payload.target,
            details={"error": exc.code},
        )
        raise
    audit_service.record(
        session,
        actor(ctx),
        "discovery_started",
        target_type="discovery_job",
        target_id=public_id,
        details={"target": payload.target},
    )
    # Auditoría: quién (vía) y qué red; nunca credenciales ni cabeceras.
    logger.info(
        "discovery requested", extra={"target": payload.target, "via": VIA, "job": str(public_id)}
    )
    return exposure.job(public_id)


@router.post(
    "/jobs/{job_id}/cancel",
    response_model=DiscoveryJobDetail,
    responses=error_responses(404, 409),
)
def cancel_discovery(
    job_id: UUID, session: DbSession, exposure: Exposure, ctx: Operator
) -> DiscoveryJobDetail:
    """Cancela un job en cola al momento, o pide parar uno en curso (efectivo en segundos).

    Un scan cancelado nunca concluye que un host desapareció o que un puerto se cerró.
    """
    try:
        request_cancel(session, job_id)
    except SentraError as exc:
        session.rollback()
        audit_service.record(
            session,
            actor(ctx),
            "discovery_cancelled",
            audit_service.FAILURE,
            "discovery_job",
            job_id,
            details={"error": exc.code},
        )
        raise
    audit_service.record(
        session,
        actor(ctx),
        "discovery_cancelled",
        target_type="discovery_job",
        target_id=job_id,
    )
    logger.info("discovery cancel requested", extra={"job": str(job_id), "via": VIA})
    return exposure.job(job_id)
