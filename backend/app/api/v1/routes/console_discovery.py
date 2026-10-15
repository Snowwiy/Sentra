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
from sqlalchemy import select

from app.api.auth import actor, require_permission
from app.api.deps import AppSettings, DbSession, get_exposure_service
from app.api.responses import error_responses
from app.core.config import Settings
from app.core.exceptions import (
    DiscoveryDisabledError,
    DiscoveryOptionsError,
    DiscoveryTargetError,
    DiscoveryTuneForbiddenError,
    SentraError,
    SiteValidationError,
)
from app.core.permissions import Permission
from app.discovery.profiles import ProfileError, ResolvedProfile, resolve
from app.discovery.targets import TargetError
from app.models.discovery import DiscoveryJob
from app.models.site import SensorJob
from app.schemas.discovery import DiscoveryJobCreate, DiscoveryJobDetail
from app.services import audit_service
from app.services.auth_service import AuthContext
from app.services.discovery_runner import DiscoveryRunner, get_discovery_runner
from app.services.discovery_service import request_cancel
from app.services.exposure_service import ExposureService
from app.services.sensor_service import SensorService
from app.services.site_service import default_site_id, resolve_site

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
    responses=error_responses(404, 409, 422),
)
def start_discovery(
    payload: DiscoveryJobCreate,
    runner: Runner,
    exposure: Exposure,
    ctx: Operator,
    session: DbSession,
    settings: AppSettings,
) -> DiscoveryJobDetail:
    """Encola un descubrimiento y responde al momento (202) con el job en cola.

    El scan corre en segundo plano; la web sigue su estado con GET /discovery/jobs/{id}.
    """
    try:
        profile = _resolve_profile(payload, settings, ctx)
        if payload.execution_target == "sensor":
            # Fase 5F: lo ejecuta un sensor del site, dentro de las redes autorizadas del site
            # (validado en el servidor: el sensor y el formulario no son una frontera).
            if payload.site_id is None or payload.sensor_id is None:
                raise SiteValidationError(
                    "discovery_sensor_required", "site_id and sensor_id are required"
                )
            public_id = SensorService(session, settings).create_discovery(
                payload.target, payload.site_id, payload.sensor_id, actor(ctx), VIA, profile
            )
        else:
            # El discovery del propio servidor solo existe en el site por defecto: su
            # allowlist (DISCOVERY_ALLOWED_NETWORKS) es la red local del servidor.
            site = resolve_site(session, payload.site_id)
            if site is not None and site != default_site_id(session):
                raise SiteValidationError(
                    "discovery_local_default_site_only",
                    "Local discovery only runs in the default site; use a sensor",
                )
            if not runner.service.scope.enabled:
                raise DiscoveryDisabledError(
                    "Network discovery is disabled: set DISCOVERY_ALLOWED_NETWORKS on the server"
                )
            try:
                public_id = runner.submit(payload.target, VIA, profile)
            except ProfileError as exc:
                raise DiscoveryOptionsError(exc.code, str(exc), exc.details) from exc
            except TargetError as exc:
                # Mismo motivo que daría la CLI (fuera de la allowlist, demasiado grande,
                # multicast, pública...). No incluye nada que no haya enviado el propio cliente.
                raise DiscoveryTargetError(str(exc)) from exc
    except SentraError as exc:
        session.rollback()
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
        details={
            "target": payload.target,
            "execution_target": payload.execution_target,
            "site_id": str(payload.site_id) if payload.site_id else None,
            "sensor_id": str(payload.sensor_id) if payload.sensor_id else None,
            "profile": payload.profile,
            "ports": list(profile.ports) if profile is not None else None,
            "limits": profile.limits.as_dict() if profile is not None else None,
        },
    )
    # Auditoría: quién (vía) y qué red; nunca credenciales ni cabeceras.
    logger.info(
        "discovery requested", extra={"target": payload.target, "via": VIA, "job": str(public_id)}
    )
    return exposure.job(public_id)


def _resolve_profile(
    payload: DiscoveryJobCreate, settings: Settings, ctx: AuthContext
) -> ResolvedProfile | None:
    """Fase 6A: valida perfil, puertos y límites en el servidor (el formulario no manda).

    Sin perfil es el discovery básico de siempre y no admite opciones avanzadas.
    """
    limits = payload.limits.model_dump(exclude_none=True) if payload.limits else {}
    if payload.profile is None:
        if payload.ports is not None or limits:
            raise DiscoveryOptionsError(
                "discovery_options_require_profile", "ports and limits require a scan profile"
            )
        return None
    try:
        return resolve(
            settings,
            payload.profile,
            payload.ports,
            limits or None,
            can_tune=ctx.has(Permission.DISCOVERY_TUNE),
        )
    except PermissionError as exc:
        raise DiscoveryTuneForbiddenError(str(exc)) from exc
    except ProfileError as exc:
        raise DiscoveryOptionsError(exc.code, str(exc), exc.details) from exc


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
    sensor_job = session.scalar(
        select(SensorJob.public_id)
        .join(DiscoveryJob, DiscoveryJob.id == SensorJob.discovery_job_id)
        .where(DiscoveryJob.public_id == job_id)
    )
    if sensor_job is not None:
        audit_service.record(
            session,
            actor(ctx),
            "sensor_job_cancelled",
            target_type="sensor_job",
            target_id=sensor_job,
            details={"discovery_job_id": str(job_id)},
        )
    logger.info("discovery cancel requested", extra={"job": str(job_id), "via": VIA})
    return exposure.job(job_id)
