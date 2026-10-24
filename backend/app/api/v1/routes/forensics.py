"""Investigación forense remota (Fase 6E.6). Ver docs/forensic-investigation.md.

La recogida se pide con POST /response/executions (acción `forensic_*` e `investigation_id`):
misma política, permisos y cola de comandos que cualquier acción de Response. Aquí están los
casos, la evidencia guardada, las notas y el paquete ZIP.

Permisos: forensics:read (ver), forensics:acquire (crear casos y notas; recoger además exige
response:execute), forensics:download (paquete, auditado) y forensics:manage (admin: cerrar,
reabrir y retención legal).
"""

from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response, status

from app.api.auth import actor, require_permission
from app.api.deps import AppSettings, DbSession
from app.api.responses import error_responses
from app.core.permissions import Permission
from app.schemas.common import RequestModel
from app.schemas.forensics import (
    ArtifactDetail,
    InvestigationCreate,
    InvestigationDetail,
    InvestigationList,
    InvestigationRead,
    InvestigationVersion,
    LegalHoldUpdate,
    NoteCreate,
    NoteRead,
)
from app.services.auth_service import AuthContext
from app.services.forensics_service import ForensicsService
from app.services.site_service import resolve_site

router = APIRouter(
    prefix="/investigations", tags=["forensics"], responses=error_responses(401, 403)
)

READ = Depends(require_permission(Permission.FORENSICS_READ))
Acquirer = Annotated[AuthContext, Depends(require_permission(Permission.FORENSICS_ACQUIRE))]
Downloader = Annotated[AuthContext, Depends(require_permission(Permission.FORENSICS_DOWNLOAD))]
Manager = Annotated[AuthContext, Depends(require_permission(Permission.FORENSICS_MANAGE))]
_MUTATION_ERRORS = error_responses(404, 409, 422)


def get_service(session: DbSession, settings: AppSettings) -> ForensicsService:
    return ForensicsService(session, settings)


Service = Annotated[ForensicsService, Depends(get_service)]


class PackageRequest(RequestModel):
    # Paquete con artefactos cuyo hash no coincidió: solo si se acepta el aviso.
    acknowledge_mismatch: bool = False


@router.get("", response_model=InvestigationList, dependencies=[READ])
def list_investigations(
    service: Service,
    session: DbSession,
    asset_id: UUID | None = None,
    status_filter: Annotated[Literal["open", "closed"] | None, Query(alias="status")] = None,
    site_id: UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> InvestigationList:
    return service.list_investigations(
        asset_id, status_filter, resolve_site(session, site_id), limit, offset
    )


@router.post(
    "",
    response_model=InvestigationRead,
    status_code=status.HTTP_201_CREATED,
    responses=_MUTATION_ERRORS,
)
def create_investigation(
    body: InvestigationCreate, ctx: Acquirer, service: Service
) -> InvestigationRead:
    return service.create(body, actor(ctx))


@router.get(
    "/{investigation_id}",
    response_model=InvestigationDetail,
    dependencies=[READ],
    responses=error_responses(404),
)
def get_investigation(investigation_id: UUID, service: Service) -> InvestigationDetail:
    return service.detail(investigation_id)


@router.get(
    "/{investigation_id}/artifacts/{artifact_id}",
    response_model=ArtifactDetail,
    dependencies=[READ],
    responses=error_responses(404),
)
def get_artifact(investigation_id: UUID, artifact_id: UUID, service: Service) -> ArtifactDetail:
    """Contenido del artefacto tal como se recibió (JSON canónico ya verificado)."""
    return service.artifact(investigation_id, artifact_id)


@router.post(
    "/{investigation_id}/notes",
    response_model=NoteRead,
    status_code=status.HTTP_201_CREATED,
    responses=_MUTATION_ERRORS,
)
def add_note(investigation_id: UUID, body: NoteCreate, ctx: Acquirer, service: Service) -> NoteRead:
    return service.add_note(investigation_id, body, actor(ctx))


@router.post(
    "/{investigation_id}/close", response_model=InvestigationRead, responses=_MUTATION_ERRORS
)
def close_investigation(
    investigation_id: UUID, body: InvestigationVersion, ctx: Manager, service: Service
) -> InvestigationRead:
    return service.set_status(investigation_id, "closed", body.version, actor(ctx))


@router.post(
    "/{investigation_id}/reopen", response_model=InvestigationRead, responses=_MUTATION_ERRORS
)
def reopen_investigation(
    investigation_id: UUID, body: InvestigationVersion, ctx: Manager, service: Service
) -> InvestigationRead:
    return service.set_status(investigation_id, "open", body.version, actor(ctx))


@router.post(
    "/{investigation_id}/legal-hold", response_model=InvestigationRead, responses=_MUTATION_ERRORS
)
def legal_hold(
    investigation_id: UUID, body: LegalHoldUpdate, ctx: Manager, service: Service
) -> InvestigationRead:
    return service.set_legal_hold(investigation_id, body.legal_hold, body.version, actor(ctx))


@router.post(
    "/{investigation_id}/package",
    response_class=Response,
    responses={
        **error_responses(404, 409, 413),
        200: {"content": {"application/zip": {}}, "description": "Evidence package (ZIP)"},
    },
)
def download_package(
    investigation_id: UUID, body: PackageRequest, ctx: Downloader, service: Service
) -> Response:
    """ZIP con manifest.json (hashes y cadena de custodia), evidence/ e interpretations/.
    POST y no GET: genera un registro y una entrada de auditoría (pasa por CSRF)."""
    data, digest, filename = service.package(
        investigation_id, body.acknowledge_mismatch, actor(ctx)
    )
    return Response(
        content=data,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Sentra-SHA256": digest,
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        },
    )
