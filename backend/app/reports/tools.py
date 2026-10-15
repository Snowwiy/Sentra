"""Herramientas de Reporting para la futura Analyst Console (Fase 5E): sin chat ni LLM.

Registro CERRADO de funciones con nombre estable que envuelven el mismo ReportService que la
API y la UI: misma validación, mismo RBAC, misma auditoría. Los argumentos se validan con los
mismos modelos de la API (extra=forbid): una consola no puede pedir nada que un usuario no
pueda pedir por la API. `reports.download_metadata` devuelve solo metadatos (nombre, tamaño,
SHA-256, enlace relativo de la API), nunca el contenido ni rutas del disco.

No hay herramientas genéricas: un nombre desconocido es un KeyError. Los resúmenes son las
frases deterministas del snapshot; la IA no interviene en ningún informe.
"""

from collections.abc import Callable
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import Field

from app.core.exceptions import PermissionDeniedError
from app.core.permissions import Permission
from app.schemas.common import RequestModel
from app.schemas.report import ReportCreate, ReportRequest
from app.services.report_service import ReportNotReadyError, ReportService, Requester


class _NoArgs(RequestModel):
    pass


class _ReportRef(RequestModel):
    report_id: UUID


class _ListArgs(RequestModel):
    report_type: str | None = Field(default=None, max_length=64)
    status: Literal["pending", "running", "succeeded", "failed", "cancelled", "expired"] | None = (
        None
    )
    created_from: datetime | None = None
    created_to: datetime | None = None
    limit: int = Field(default=25, ge=1, le=100)
    offset: int = Field(default=0, ge=0, le=100_000)


def _require_read(req: Requester) -> None:
    if not req.has(Permission.REPORTS_READ):
        raise PermissionDeniedError("Reading reports requires reports:read")


def _catalog(service: ReportService, req: Requester, args: dict[str, Any]) -> Any:
    _NoArgs.model_validate(args)
    _require_read(req)
    return service.catalog(req).model_dump(mode="json")


def _preview(service: ReportService, req: Requester, args: dict[str, Any]) -> Any:
    return service.preview(req, ReportRequest.model_validate(args)).model_dump(mode="json")


def _generate(service: ReportService, req: Requester, args: dict[str, Any]) -> Any:
    return service.create(req, ReportCreate.model_validate(args)).model_dump(mode="json")


def _status(service: ReportService, req: Requester, args: dict[str, Any]) -> Any:
    _require_read(req)
    return service.get(req, _ReportRef.model_validate(args).report_id).model_dump(mode="json")


def _list(service: ReportService, req: Requester, args: dict[str, Any]) -> Any:
    _require_read(req)
    query = _ListArgs.model_validate(args)
    return service.list_reports(req, **query.model_dump()).model_dump(mode="json")


def _download_metadata(service: ReportService, req: Requester, args: dict[str, Any]) -> Any:
    _require_read(req)
    report = service.get(req, _ReportRef.model_validate(args).report_id)
    if report.status != "succeeded" or report.artifact is None:
        raise ReportNotReadyError("The report is not ready")
    return {
        "report_id": str(report.id),
        "filename": report.artifact.filename,
        "content_type": report.artifact.content_type,
        "size_bytes": report.artifact.size_bytes,
        "sha256": report.artifact.sha256,
        "snapshot_sha256": report.snapshot_sha256,
        "cutoff_at": report.cutoff_at.isoformat() if report.cutoff_at else None,
        # Ruta relativa de la API: la descarga real revalida RBAC, estado y checksum.
        "download_path": f"/api/v1/reports/{report.id}/artifact",
    }


Tool = Callable[[ReportService, Requester, dict[str, Any]], Any]

TOOLS: dict[str, Tool] = {
    "reports.catalog": _catalog,
    "reports.preview": _preview,
    "reports.generate": _generate,
    "reports.status": _status,
    "reports.list": _list,
    "reports.download_metadata": _download_metadata,
}


def call(service: ReportService, req: Requester, name: str, args: dict[str, Any]) -> Any:
    """Ejecuta una herramienta del registro y devuelve JSON simple."""
    tool = TOOLS[name]  # KeyError para cualquier nombre fuera del registro
    return tool(service, req, dict(args))
