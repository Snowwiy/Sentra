"""Identidad de dispositivos (Fase 7B.2, docs/device-identity-wifi.md).

- ficha por niveles, sugerencias, comparación de dos registros y asociaciones: lectura con
  monitoring:read;
- vista previa, crear y revocar una asociación manual: identity:manage (solo admin). Cada
  intento queda auditado, también los rechazados.

Nada aquí fusiona registros: asociar archiva el alias (o fija el cliente Wi-Fi) y revocar
lo deshace.
"""

from datetime import timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from app.api.auth import READ, actor, require_permission
from app.api.deps import AppSettings, DbSession
from app.api.responses import error_responses
from app.core.exceptions import SentraError
from app.core.permissions import Permission
from app.schemas.identity import (
    AssetIdentityProfile,
    IdentityCandidateList,
    IdentityComparison,
    IdentityLinkCreate,
    IdentityLinkList,
    IdentityLinkPreview,
    IdentityLinkRead,
    IdentityLinkRequest,
    IdentityLinkRevoke,
)
from app.services import audit_service
from app.services.auth_service import AuthContext
from app.services.device_identity import DeviceIdentityService

router = APIRouter(tags=["identity"], responses=error_responses(401, 403))
Manager = Annotated[AuthContext, Depends(require_permission(Permission.IDENTITY_MANAGE))]


def get_service(session: DbSession, settings: AppSettings) -> DeviceIdentityService:
    return DeviceIdentityService(session, timedelta(seconds=settings.heartbeat_timeout_seconds))


Service = Annotated[DeviceIdentityService, Depends(get_service)]


def _audited_failure(
    session: DbSession, ctx: AuthContext, action: str, target: object, exc: SentraError
) -> None:
    session.rollback()
    audit_service.record(
        session,
        actor(ctx),
        action,
        audit_service.FAILURE,
        "asset",
        target,
        details={"error": exc.code},
    )


@router.get(
    "/assets/{asset_id}/identity/profile",
    response_model=AssetIdentityProfile,
    dependencies=[READ],
    responses=error_responses(404),
)
def asset_identity_profile(asset_id: UUID, service: Service) -> AssetIdentityProfile:
    """Ficha por niveles (nombre, fabricante, tipo, SO) con fuente, vigencia y estado."""
    return service.profile(asset_id)


@router.get(
    "/assets/{asset_id}/identity/candidates",
    response_model=IdentityCandidateList,
    dependencies=[READ],
    responses=error_responses(404),
)
def identity_candidates(asset_id: UUID, service: Service) -> IdentityCandidateList:
    """Registros que podrían ser el mismo dispositivo, con evidencia. Solo sugiere."""
    return service.candidates(asset_id)


@router.get(
    "/identity/compare",
    response_model=IdentityComparison,
    dependencies=[READ],
    responses=error_responses(404, 422),
)
def compare(
    left: Annotated[UUID, Query()], right: Annotated[UUID, Query()], service: Service
) -> IdentityComparison:
    return service.compare(left, right)


@router.get(
    "/identity/links",
    response_model=IdentityLinkList,
    dependencies=[READ],
    responses=error_responses(404),
)
def list_links(
    service: Service,
    asset_id: UUID | None = None,
    wlan_client_id: UUID | None = None,
    active: bool | None = None,
) -> IdentityLinkList:
    return service.list_links(asset_id, wlan_client_id, active)


@router.post(
    "/identity/links/preview",
    response_model=IdentityLinkPreview,
    responses=error_responses(404, 422),
)
def preview_link(body: IdentityLinkRequest, _: Manager, service: Service) -> IdentityLinkPreview:
    """Qué haría la asociación y por qué se permitiría o no. No cambia nada."""
    return service.preview(body)


@router.post(
    "/identity/links",
    response_model=IdentityLinkRead,
    status_code=201,
    responses=error_responses(404, 409, 422),
)
def create_link(
    body: IdentityLinkCreate, ctx: Manager, service: Service, session: DbSession
) -> IdentityLinkRead:
    try:
        return service.create(body, actor(ctx))
    except SentraError as exc:
        _audited_failure(session, ctx, "identity_link_created", body.target_asset_id, exc)
        raise


@router.post(
    "/identity/links/{link_id}/revoke",
    response_model=IdentityLinkRead,
    responses=error_responses(404, 409),
)
def revoke_link(
    link_id: UUID, body: IdentityLinkRevoke, ctx: Manager, service: Service, session: DbSession
) -> IdentityLinkRead:
    try:
        return service.revoke(link_id, body.reason, actor(ctx))
    except SentraError as exc:
        _audited_failure(session, ctx, "identity_link_revoked", link_id, exc)
        raise
