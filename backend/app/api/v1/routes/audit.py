"""Registro de auditoría (solo lectura, permiso audit:read)."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.api.auth import require_permission
from app.api.deps import DbSession
from app.api.responses import error_responses
from app.core.permissions import Permission
from app.schemas.audit import AuditEventList
from app.services import audit_service

router = APIRouter(
    prefix="/audit",
    tags=["audit"],
    dependencies=[Depends(require_permission(Permission.AUDIT_READ))],
    responses=error_responses(401, 403),
)


@router.get("", response_model=AuditEventList)
def list_audit_events(
    session: DbSession,
    action: Annotated[str | None, Query(pattern=r"^[a-z_]{1,64}$")] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> AuditEventList:
    return audit_service.list_events(session, limit, offset, action)
