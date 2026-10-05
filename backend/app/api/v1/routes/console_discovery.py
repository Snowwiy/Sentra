"""Consola del dashboard: iniciar y cancelar descubrimientos de red.

SENSIBLE y TEMPORAL, igual que routes/console.py: misma guarda `require_local_console`
(DASHBOARD_ADMIN_ENABLED, navegador en el propio servidor, Origin y cabecera de consola),
así un equipo de la LAN puede ver la página Red pero recibe 403 al intentar escanear. Se
sustituirá por login/RBAC. Ninguna clave (ADMIN_API_KEY) llega al navegador.

La validación del target se repite aquí aunque el frontend solo ofrezca redes autorizadas:
el navegador no es una frontera de seguridad.
"""

import logging
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, status

from app.api.console import require_local_console
from app.api.deps import DbSession, get_exposure_service
from app.api.responses import error_responses
from app.core.exceptions import DiscoveryDisabledError, DiscoveryTargetError
from app.discovery.targets import TargetError
from app.schemas.discovery import DiscoveryJobCreate, DiscoveryJobDetail
from app.services.discovery_runner import DiscoveryRunner, get_discovery_runner
from app.services.discovery_service import request_cancel
from app.services.exposure_service import ExposureService

logger = logging.getLogger(__name__)

VIA = "dashboard"

router = APIRouter(
    prefix="/console/discovery",
    tags=["console"],
    dependencies=[Depends(require_local_console)],
    responses=error_responses(403),
)
Runner = Annotated[DiscoveryRunner, Depends(get_discovery_runner)]
Exposure = Annotated[ExposureService, Depends(get_exposure_service)]


@router.post(
    "/jobs",
    response_model=DiscoveryJobDetail,
    status_code=status.HTTP_202_ACCEPTED,
    responses=error_responses(409),
)
def start_discovery(
    payload: DiscoveryJobCreate, runner: Runner, exposure: Exposure
) -> DiscoveryJobDetail:
    """Encola un descubrimiento y responde al momento (202) con el job en cola.

    El scan corre en segundo plano; la web sigue su estado con GET /discovery/jobs/{id}.
    """
    if not runner.service.scope.enabled:
        raise DiscoveryDisabledError(
            "Network discovery is disabled: set DISCOVERY_ALLOWED_NETWORKS on the server"
        )
    try:
        public_id = runner.submit(payload.target, VIA)
    except TargetError as exc:
        # Mismo motivo que daría la CLI (fuera de la allowlist, demasiado grande, multicast,
        # pública...). No incluye nada que no haya enviado el propio cliente.
        raise DiscoveryTargetError(str(exc)) from exc
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
def cancel_discovery(job_id: UUID, session: DbSession, exposure: Exposure) -> DiscoveryJobDetail:
    """Cancela un job en cola al momento, o pide parar uno en curso (efectivo en segundos).

    Un scan cancelado nunca concluye que un host desapareció o que un puerto se cerró.
    """
    request_cancel(session, job_id)
    logger.info("discovery cancel requested", extra={"job": str(job_id), "via": VIA})
    return exposure.job(job_id)
