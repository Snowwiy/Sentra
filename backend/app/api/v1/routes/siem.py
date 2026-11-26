"""Integración SIEM en el dashboard (Fase 7F, docs/fase-7f.md).

Permisos propios, separados de monitoring:read y de NDR:
- siem:read (todos los roles): catálogo de conectores, fuentes, su salud y agregados;
- siem:evidence (analyst y admin): eventos individuales (IPs, usuarios, mensajes, extracto
  del registro original);
- siem:manage (admin): registrar, cambiar, habilitar o retirar fuentes e importar ficheros.
  Siempre auditado.

Nada aquí contacta con un sistema externo: las fuentes envían a través de un sensor del site
(HTTPS saliente) o un admin importa un fichero exportado. Ninguna URL, comando o texto de un
evento se sigue o se ejecuta.
"""

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response, status

from app.api.auth import actor, require_permission
from app.api.deps import AppSettings, DbSession
from app.api.responses import error_responses
from app.core.permissions import Permission
from app.schemas.siem import (
    SiemBatchAccepted,
    SiemConnectorList,
    SiemEventDetail,
    SiemEventList,
    SiemImportRequest,
    SiemOverview,
    SiemSourceCreate,
    SiemSourceList,
    SiemSourceRead,
    SiemSourceUpdate,
)
from app.schemas.siem_hunting import (
    IncidentSiemEventList,
    SiemCaseAttach,
    SiemEvidenceExport,
    SiemExportRequest,
    SiemRelated,
    SiemSavedSearchCreate,
    SiemSavedSearchList,
    SiemSavedSearchRead,
    SiemSearchRequest,
    SiemSearchResult,
    SiemTimeline,
)
from app.services.auth_service import AuthContext
from app.services.incident_service import IncidentService, Operator
from app.services.site_service import resolve_site
from app.siem.analysis import siem_analyzers
from app.siem.investigation import SiemInvestigationService
from app.siem.service import SiemService

router = APIRouter(prefix="/siem", tags=["siem"], responses=error_responses(401, 403))

SIEM_READ = Depends(require_permission(Permission.SIEM_READ))
SIEM_EVIDENCE = Depends(require_permission(Permission.SIEM_EVIDENCE))
Manager = Annotated[AuthContext, Depends(require_permission(Permission.SIEM_MANAGE))]
SiteFilter = Annotated[UUID | None, Query()]
Limit = Annotated[int, Query(ge=1, le=500)]
Offset = Annotated[int, Query(ge=0, le=100_000)]


def get_siem_service(session: DbSession, settings: AppSettings) -> SiemService:
    return SiemService(session, settings)


Siem = Annotated[SiemService, Depends(get_siem_service)]


@router.get("/connectors", response_model=SiemConnectorList, dependencies=[SIEM_READ])
def list_connectors() -> SiemConnectorList:
    """Conectores disponibles, con su versión, transportes y política de severidad."""
    return SiemService.list_connectors()


@router.get(
    "/overview",
    response_model=SiemOverview,
    dependencies=[SIEM_READ],
    responses=error_responses(404),
)
def overview(
    service: Siem,
    session: DbSession,
    site_id: SiteFilter = None,
    hours: Annotated[int, Query(ge=1, le=168)] = 24,
) -> SiemOverview:
    return service.overview(resolve_site(session, site_id), hours)


@router.get(
    "/sources",
    response_model=SiemSourceList,
    dependencies=[SIEM_READ],
    responses=error_responses(404),
)
def list_sources(service: Siem, session: DbSession, site_id: SiteFilter = None) -> SiemSourceList:
    return service.list_sources(resolve_site(session, site_id))


@router.post(
    "/sources",
    response_model=SiemSourceRead,
    status_code=status.HTTP_201_CREATED,
    responses=error_responses(404, 409, 422),
)
def create_source(body: SiemSourceCreate, service: Siem, ctx: Manager) -> SiemSourceRead:
    """Registra una fuente. Queda deshabilitada salvo que se pida lo contrario."""
    return service.create_source(body, actor(ctx))


@router.get(
    "/sources/{siem_source_id}",
    response_model=SiemSourceRead,
    dependencies=[SIEM_READ],
    responses=error_responses(404),
)
def get_source(siem_source_id: UUID, service: Siem) -> SiemSourceRead:
    return service.get_source(siem_source_id)


@router.put(
    "/sources/{siem_source_id}",
    response_model=SiemSourceRead,
    responses=error_responses(404, 409, 422),
)
def update_source(
    siem_source_id: UUID, body: SiemSourceUpdate, service: Siem, ctx: Manager
) -> SiemSourceRead:
    return service.update_source(siem_source_id, body, actor(ctx))


@router.delete(
    "/sources/{siem_source_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    responses=error_responses(404, 409),
)
def delete_source(siem_source_id: UUID, service: Siem, ctx: Manager) -> Response:
    """Retira una fuente DESHABILITADA y sus eventos. Auditado con el recuento borrado."""
    service.delete_source(siem_source_id, actor(ctx))
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/sources/{siem_source_id}/import",
    response_model=SiemBatchAccepted,
    responses=error_responses(404, 409, 413, 422, 429),
)
def import_records(
    siem_source_id: UUID, body: SiemImportRequest, service: Siem, ctx: Manager
) -> SiemBatchAccepted:
    """Importa un fichero exportado (una línea por registro) en una fuente `upload`."""
    return service.import_records(siem_source_id, body, actor(ctx), siem_analyzers())


@router.get(
    "/events",
    response_model=SiemEventList,
    dependencies=[SIEM_EVIDENCE],
    responses=error_responses(404, 422),
)
def list_events(
    service: Siem,
    session: DbSession,
    site_id: SiteFilter = None,
    source_id: UUID | None = None,
    event_type: Annotated[str | None, Query(pattern=r"^[a-z0-9_.]{1,48}$")] = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: Limit = 100,
    offset: Offset = 0,
) -> SiemEventList:
    return service.list_events(
        resolve_site(session, site_id), source_id, event_type, since, until, limit, offset
    )


@router.get(
    "/events/{event_id}",
    response_model=SiemEventDetail,
    dependencies=[SIEM_EVIDENCE],
    responses=error_responses(404),
)
def get_event(event_id: UUID, service: Siem) -> SiemEventDetail:
    return service.get_event(event_id)


# --- Fase 7F.6: hunting e investigación ------------------------------------------------------
# Todo exige siem:evidence: devuelve eventos individuales. Añadir a un caso exige además
# incidents:manage, y leer la evidencia SIEM de un caso, incidents:read.

Evidence = Annotated[AuthContext, Depends(require_permission(Permission.SIEM_EVIDENCE))]
INCIDENTS_READ = Depends(require_permission(Permission.INCIDENTS_READ))
IncidentManager = Annotated[AuthContext, Depends(require_permission(Permission.INCIDENTS_MANAGE))]


def get_investigation(session: DbSession, settings: AppSettings) -> SiemInvestigationService:
    return SiemInvestigationService(session, settings)


Investigation = Annotated[SiemInvestigationService, Depends(get_investigation)]


@router.post(
    "/search",
    response_model=SiemSearchResult,
    dependencies=[SIEM_EVIDENCE],
    responses=error_responses(404, 422, 503),
)
def search_events(
    body: SiemSearchRequest, service: Investigation, session: DbSession
) -> SiemSearchResult:
    """Búsqueda tipada con ventana obligatoria, cursor y tiempo máximo (statement_timeout)."""
    return service.search(body, resolve_site(session, body.site_id))


@router.get("/searches", response_model=SiemSavedSearchList)
def list_saved_searches(service: Investigation, ctx: Evidence) -> SiemSavedSearchList:
    return service.list_saved(ctx.user)


@router.post(
    "/searches",
    response_model=SiemSavedSearchRead,
    status_code=status.HTTP_201_CREATED,
    responses=error_responses(409, 422),
)
def create_saved_search(
    body: SiemSavedSearchCreate, service: Investigation, ctx: Evidence
) -> SiemSavedSearchRead:
    return service.create_saved(ctx.user, body)


@router.delete(
    "/searches/{search_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    responses=error_responses(404),
)
def delete_saved_search(search_id: UUID, service: Investigation, ctx: Evidence) -> Response:
    service.delete_saved(ctx.user, search_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/events/export",
    response_model=SiemEvidenceExport,
    responses=error_responses(422),
)
def export_events(
    body: SiemExportRequest, service: Investigation, ctx: Evidence
) -> SiemEvidenceExport:
    """Paquete JSON de evidencia con hashes. Auditado (quién, cuántos, SHA-256)."""
    return service.export(body.event_ids, body.reason, actor(ctx))


@router.get(
    "/events/{event_id}/related",
    response_model=SiemRelated,
    dependencies=[SIEM_EVIDENCE],
    responses=error_responses(404),
)
def related_events(event_id: UUID, service: Investigation) -> SiemRelated:
    return service.related(event_id)


@router.get(
    "/timeline",
    response_model=SiemTimeline,
    dependencies=[SIEM_EVIDENCE],
    responses=error_responses(404, 422),
)
def asset_timeline(
    asset_id: UUID, since: datetime, until: datetime, service: Investigation
) -> SiemTimeline:
    return service.timeline(asset_id, since, until)


@router.post(
    "/events/{event_id}/incidents/{incident_id}",
    response_model=IncidentSiemEventList,
    dependencies=[SIEM_EVIDENCE],
    responses=error_responses(404, 409, 422),
)
def attach_to_incident(
    event_id: UUID,
    incident_id: UUID,
    service: Investigation,
    ctx: IncidentManager,
    session: DbSession,
    body: SiemCaseAttach | None = None,
) -> IncidentSiemEventList:
    """Añade el evento a un caso como evidencia (copia + hash). Idempotente."""
    event, snapshot = service.snapshot(event_id)
    incidents = IncidentService(
        session, Operator.from_context(ctx.user, ctx.client_ip, ctx.permissions)
    )
    incidents.attach_siem_event(incident_id, event, snapshot, body.note if body else None)
    return service.incident_events(incident_id)


@router.get(
    "/incidents/{incident_id}/events",
    response_model=IncidentSiemEventList,
    dependencies=[SIEM_EVIDENCE, INCIDENTS_READ],
    responses=error_responses(404),
)
def incident_events(incident_id: UUID, service: Investigation) -> IncidentSiemEventList:
    return service.incident_events(incident_id)
