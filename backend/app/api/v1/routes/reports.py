"""Reporting y exportación de evidencias (Fase 5E). Ver docs/reporting.md.

Permisos (comprobados en el backend en cada petición; ocultar botones es solo UX):
- reports:read (viewer, analyst, admin): catálogo, historial, detalle y descarga;
- reports:generate (analyst, admin): preview, generar y cancelar los propios;
- reports:admin (admin): resumen ejecutivo, técnico global, cancelar ajenos y borrar.

Ver un informe exige además los permisos de lectura de dominio de su tipo; un informe que el
rol no puede ver responde 404, igual que uno inexistente. La descarga es solo por id: el
cliente nunca envía rutas ni nombres de fichero.
"""

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response, status

from app.api.auth import actor, require_permission
from app.api.deps import AppSettings, DbSession
from app.api.responses import error_responses
from app.core.permissions import Permission
from app.reports.storage import ArtifactStorage
from app.schemas.report import (
    ReportCatalog,
    ReportCreate,
    ReportList,
    ReportOut,
    ReportPreview,
    ReportRequest,
)
from app.services.auth_service import AuthContext
from app.services.report_service import ReportService, Requester

router = APIRouter(prefix="/reports", tags=["reports"], responses=error_responses(401, 403))

Reader = Annotated[AuthContext, Depends(require_permission(Permission.REPORTS_READ))]
Generator = Annotated[AuthContext, Depends(require_permission(Permission.REPORTS_GENERATE))]
Admin = Annotated[AuthContext, Depends(require_permission(Permission.REPORTS_ADMIN))]

ReportStatus = Literal["pending", "running", "succeeded", "failed", "cancelled", "expired"]
_MUTATION_ERRORS = error_responses(404, 409, 422)


def get_report_service(session: DbSession, settings: AppSettings) -> ReportService:
    return ReportService(session, settings)


def get_report_storage(settings: AppSettings) -> ArtifactStorage:
    return ArtifactStorage(settings.report_output_dir)


Service = Annotated[ReportService, Depends(get_report_service)]
Storage = Annotated[ArtifactStorage, Depends(get_report_storage)]


def _req(ctx: AuthContext) -> Requester:
    return Requester(ctx.user, actor(ctx), ctx.permissions)


@router.get("/catalog", response_model=ReportCatalog)
def catalog(ctx: Reader, service: Service) -> ReportCatalog:
    """Tipos de informe visibles para el rol, con formatos, filtros y límites."""
    return service.catalog(_req(ctx))


@router.post("/preview", response_model=ReportPreview, responses=_MUTATION_ERRORS)
def preview(body: ReportRequest, ctx: Generator, service: Service) -> ReportPreview:
    """Valida la petición y estima el alcance. No crea informe, trabajo ni fichero."""
    return service.preview(_req(ctx), body)


@router.post(
    "",
    response_model=ReportOut,
    status_code=status.HTTP_202_ACCEPTED,
    responses={**_MUTATION_ERRORS, **error_responses(429)},
)
def create_report(body: ReportCreate, ctx: Generator, service: Service) -> ReportOut:
    """Encola la generación. Misma idempotency_key o petición viva idéntica: el mismo informe."""
    return service.create(_req(ctx), body)


@router.get("", response_model=ReportList)
def list_reports(
    ctx: Reader,
    service: Service,
    report_type: Annotated[str | None, Query(max_length=64)] = None,
    report_status: Annotated[ReportStatus | None, Query(alias="status")] = None,
    requested_by: Annotated[str | None, Query(max_length=64)] = None,
    created_from: datetime | None = None,
    created_to: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> ReportList:
    return service.list_reports(
        _req(ctx),
        report_type=report_type,
        status=report_status,
        requested_by=requested_by,
        created_from=created_from,
        created_to=created_to,
        limit=limit,
        offset=offset,
    )


@router.get("/{report_id}", response_model=ReportOut, responses=error_responses(404))
def get_report(report_id: UUID, ctx: Reader, service: Service) -> ReportOut:
    return service.get(_req(ctx), report_id)


@router.get(
    "/{report_id}/artifact",
    response_class=Response,
    responses={
        **error_responses(404, 409, 410),
        200: {"content": {"application/octet-stream": {}}, "description": "Artifact bytes"},
    },
)
def download_artifact(report_id: UUID, ctx: Reader, service: Service, storage: Storage) -> Response:
    """Descarga como adjunto, tras revalidar RBAC, estado y SHA-256 del fichero."""
    artifact, data = service.download(_req(ctx), report_id, storage)
    headers = {
        # Nombre generado por el servidor (tipo, fecha, fragmento de uuid): sin comillas ni
        # caracteres que necesiten escape.
        "Content-Disposition": f'attachment; filename="{artifact.filename}"',
        "X-Sentra-SHA256": artifact.sha256,
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
        # Si alguien abre el HTML directamente desde la API, el navegador lo aísla: sin
        # scripts, sin formularios y sin origen propio.
        "Content-Security-Policy": "sandbox; default-src 'none'; style-src 'unsafe-inline';"
        " img-src data:; frame-ancestors 'none'",
    }
    return Response(content=data, media_type=artifact.content_type, headers=headers)


@router.post("/{report_id}/cancel", response_model=ReportOut, responses=_MUTATION_ERRORS)
def cancel_report(report_id: UUID, ctx: Generator, service: Service) -> ReportOut:
    """Pending: cancelado ya. Running: el worker lo detiene y nunca termina succeeded."""
    return service.cancel(_req(ctx), report_id)


@router.delete("/{report_id}", response_model=ReportOut, responses=_MUTATION_ERRORS)
def delete_report(report_id: UUID, ctx: Admin, service: Service, storage: Storage) -> ReportOut:
    """Borra el artefacto y deja la fila como rastro (status expired, checksum, auditoría)."""
    return service.delete(_req(ctx), report_id, storage)
