"""Reporting Engine (Fase 5E): validación, trabajos, generación, descarga y retención.

La API, la UI y la futura Analyst Console (app/reports/tools.py) pasan todas por aquí, con
la misma validación, el mismo RBAC y la misma auditoría:

1. Petición → `_normalize`: catálogo cerrado, permisos (generar + lectura de dominio),
   formato, filtros por tipo, ids existentes y acotados, rango UTC validado. El preview y la
   creación usan exactamente la misma función: lo que el preview acepta, se puede generar.
2. Trabajo persistente (`reports`): idempotencia por clave del cliente e índice único de
   peticiones vivas; colas acotadas por usuario y en total. La petición HTTP no espera.
3. Worker (job report-worker, un solo proceso a la vez por advisory lock): recupera trabajos
   huérfanos, toma uno pendiente (FOR UPDATE SKIP LOCKED), lee TODOS los datos en una sola
   transacción REPEATABLE READ de solo lectura (hora de corte común), renderiza desde el
   snapshot, escribe el fichero de forma atómica y finaliza con un lock de fila: un trabajo
   cancelado a mitad nunca queda como succeeded.
4. Descarga: solo por id de informe, revalidando RBAC, estado y SHA-256 del fichero.

Nunca se borra nada automáticamente salvo con REPORT_RETENTION_DAYS (sin valor: se conserva).
"""

import hashlib
import logging
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import ColumnElement, Engine, func, or_, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.exceptions import (
    ConflictError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitedError,
    SentraError,
)
from app.core.permissions import Permission
from app.models.asset import Asset
from app.models.detection import Detection
from app.models.incident import Incident
from app.models.report import (
    ACTIVE_REPORT_STATUSES,
    CANCELLED,
    EXPIRED,
    FAILED,
    PENDING,
    RUNNING,
    SUCCEEDED,
    Report,
    ReportArtifact,
)
from app.models.response import Playbook, ResponseExecution
from app.models.site import Site
from app.models.user import User
from app.reports import builders
from app.reports.builders import BuildContext, BuildError, iso
from app.reports.catalog import (
    CLASSIFICATIONS,
    CONTENT_TYPES,
    DEFINITIONS,
    EXTENSIONS,
    FILTER_NAMES,
    PLATFORMS,
    RISK_LEVELS,
    ReportDefinition,
    get_definition,
)
from app.reports.exports import build_bundle, canonical_json, render_csv, sha256
from app.reports.render_html import render_html
from app.reports.render_pdf import render_pdf
from app.reports.scope import DataScope
from app.reports.storage import ArtifactStorage, StorageError, new_key
from app.reports.templates import render_document
from app.schemas.report import (
    ReportArtifactOut,
    ReportCatalog,
    ReportCreate,
    ReportLimits,
    ReportList,
    ReportOut,
    ReportPreview,
    ReportRequest,
    ReportTypeOut,
    ReportWarning,
)
from app.services import audit_service
from app.services.asset_lifecycle_policy import LifecyclePolicy
from app.services.audit_service import Actor

logger = logging.getLogger(__name__)

TIMEZONE = "UTC"
PRESETS = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30),
           "90d": timedelta(days=90)}  # fmt: skip
# Tolerancia de reloj del navegador para el final de un rango personalizado.
CLOCK_SKEW = timedelta(minutes=5)
# Tope del snapshot serializado guardado en JSONB (además de REPORT_MAX_ROWS por tabla).
MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
# Margen del lease sobre REPORT_JOB_TIMEOUT_SECONDS antes de dar un trabajo por huérfano.
LEASE_MARGIN = timedelta(seconds=60)
RETENTION_BATCH = 100
SYSTEM = Actor("system")


class ReportsDisabledError(ConflictError):
    code = "reports_disabled"


class ReportValidationError(SentraError):
    status_code = 422
    code = "report_invalid"

    def __init__(self, code: str, message: str, details: list[dict[str, Any]] | None = None):
        super().__init__(message, details)
        self.code = code


class ReportConflictError(ConflictError):
    code = "report_conflict"


class ReportStateError(ConflictError):
    code = "report_invalid_state"


class ReportNotReadyError(ConflictError):
    code = "report_not_ready"


class ReportQueueFullError(RateLimitedError):
    code = "report_queue_full"


class ReportArtifactUnavailableError(SentraError):
    status_code = 410
    code = "report_artifact_unavailable"


class ReportIntegrityError(ConflictError):
    code = "report_integrity_failed"


class _StopError(Exception):
    """Interrumpe la generación (cancelación pedida o plazo agotado)."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Requester:
    """Quién pide: usuario (None para CLI/sistema), actor de auditoría y permisos efectivos."""

    user: User | None
    actor: Actor
    permissions: frozenset[Permission]

    def has(self, permission: Permission) -> bool:
        return permission in self.permissions


@dataclass(frozen=True)
class Normalized:
    definition: ReportDefinition
    format: str
    classification: str
    time_from: datetime | None
    time_to: datetime | None
    preset: str | None
    filters: dict[str, Any]
    scope: dict[str, Any]
    title: str


def _now() -> datetime:
    return datetime.now(UTC)


def can_view(permissions: frozenset[Permission], definition: ReportDefinition) -> bool:
    """Ver o descargar un informe exige reports:read y los permisos de dominio de su tipo."""
    return Permission.REPORTS_READ in permissions and definition.domain_permissions <= permissions


def visible_types(permissions: frozenset[Permission]) -> list[str]:
    return [d.id for d in DEFINITIONS if can_view(permissions, d)]


def _can_generate(permissions: frozenset[Permission], definition: ReportDefinition) -> bool:
    return (
        Permission.REPORTS_GENERATE in permissions
        and definition.generate_permission in permissions
        and definition.domain_permissions <= permissions
    )


def build_context(
    settings: Settings,
    n: Normalized,
    cutoff: datetime,
    session: Session,
    permissions: frozenset[Permission],
    checkpoint: Callable[[], None] | None = None,
) -> BuildContext:
    """Contexto de lectura común al preview (estimación) y al worker (snapshot)."""
    return BuildContext(
        session=session,
        definition=n.definition,
        filters=n.filters,
        time_from=n.time_from,
        time_to=n.time_to,
        cutoff=cutoff,
        scope=DataScope(permissions),
        max_rows=settings.report_max_rows,
        heartbeat_timeout=timedelta(seconds=settings.heartbeat_timeout_seconds),
        lifecycle_policy=LifecyclePolicy.from_settings(settings),
        stale_inventory_hours=settings.vuln_stale_inventory_hours,
        checkpoint=checkpoint or (lambda: None),
    )


def _filename(report: Report, artifact_id: UUID) -> str:
    # Solo valores de servidor: tipo del catálogo, fecha y fragmento del id. Nunca títulos,
    # hostnames ni nada que venga del usuario o de los datos.
    stamp = report.created_at.astimezone(UTC).strftime("%Y%m%d-%H%M%S")
    kind = report.report_type.replace("_", "-")
    return f"sentra-{kind}-{stamp}-{artifact_id.hex[:8]}.{EXTENSIONS[report.format]}"


class ReportService:
    def __init__(self, session: Session, settings: Settings) -> None:
        self._session = session
        self._settings = settings

    # --- Catálogo --------------------------------------------------------------------------

    def _max_days(self, definition: ReportDefinition) -> int:
        configured = self._settings.report_max_range_days
        return min(configured, definition.max_range_days or configured)

    def catalog(self, req: Requester) -> ReportCatalog:
        items = [
            ReportTypeOut(
                id=d.id,
                name=d.name,
                description=d.description,
                audience=d.audience,
                template_version=d.template_version,
                supported_formats=list(d.supported_formats),
                filters=list(d.filters),
                required_filters=list(d.required_filters),
                severity_values=list(d.severity_values),
                status_values=list(d.status_values),
                risk_level_values=list(RISK_LEVELS) if "risk_levels" in d.filters else [],
                platform_values=list(PLATFORMS) if "platforms" in d.filters else [],
                uses_range=d.uses_range,
                max_range_days=self._max_days(d),
                can_generate=_can_generate(req.permissions, d) and self._settings.report_enabled,
            )
            for d in DEFINITIONS
            if can_view(req.permissions, d)
        ]
        return ReportCatalog(
            items=items,
            classifications=list(CLASSIFICATIONS),
            limits=ReportLimits(
                max_range_days=self._settings.report_max_range_days,
                max_ids=self._settings.report_max_assets,
                max_rows=self._settings.report_max_rows,
            ),
            enabled=self._settings.report_enabled,
        )

    # --- Validación común (preview y creación) ---------------------------------------------

    def _require_enabled(self) -> None:
        if not self._settings.report_enabled:
            raise ReportsDisabledError("Reporting is disabled on this server")

    def _normalize(self, req: Requester, body: ReportRequest, now: datetime) -> Normalized:
        # La ruta ya lo exige; se repite aquí para las herramientas (app/reports/tools.py).
        if not req.has(Permission.REPORTS_GENERATE):
            raise PermissionDeniedError("Generating reports requires reports:generate")
        definition = get_definition(body.report_type)
        if definition is None:
            raise ReportValidationError("report_type_unknown", "Unknown report type")
        if not definition.domain_permissions <= req.permissions or not req.has(
            definition.generate_permission
        ):
            raise PermissionDeniedError("Your role does not allow generating this report type")
        if body.format not in definition.supported_formats:
            raise ReportValidationError(
                "report_format_unsupported",
                "Format not supported by this report type"
                f" ({', '.join(definition.supported_formats)})",
            )
        filters = self._filters(definition, body)
        if (
            definition.id == "technical"
            and not filters.get("asset_ids")
            and not filters.get("incident_ids")
            and not req.has(Permission.REPORTS_ADMIN)
        ):
            # El técnico GLOBAL (sin activos ni incidentes concretos) es solo de admin.
            raise PermissionDeniedError("A global technical report requires reports:admin")
        time_from, time_to, preset = self._range(definition, body, now)
        scope = self._scope(definition, filters)
        return Normalized(
            definition=definition,
            format=body.format,
            classification=body.classification,
            time_from=time_from,
            time_to=time_to,
            preset=preset,
            filters=filters,
            scope=scope,
            title=self._title(definition, scope),
        )

    def _filters(self, definition: ReportDefinition, body: ReportRequest) -> dict[str, Any]:
        raw = body.filters
        out: dict[str, Any] = {}
        if raw.site_id is not None:
            # Fase 5F: válido para todos los tipos; se guarda el uuid y se comprueba que existe.
            site = self._session.scalar(select(Site).where(Site.public_id == raw.site_id))
            if site is None:
                raise ReportValidationError(
                    "report_target_not_found", "Site not found", [{"filter": "site_id"}]
                )
            out["site_id"] = str(site.public_id)
        limit = self._settings.report_max_assets
        allowed_values = {
            "severities": definition.severity_values,
            "statuses": definition.status_values,
            "risk_levels": RISK_LEVELS,
            "platforms": PLATFORMS,
        }
        for name in FILTER_NAMES:
            value = getattr(raw, name)
            if not value:
                continue
            if name not in definition.filters:
                raise ReportValidationError(
                    "report_filter_not_supported",
                    f"Filter {name} is not supported by this report type",
                    [{"filter": name}],
                )
            if name == "include_archived":
                out[name] = True
                continue
            if name.endswith("_ids"):
                ids = sorted({str(v) for v in value})
                if len(ids) > limit:
                    raise ReportValidationError(
                        "report_scope_too_large",
                        f"Too many ids in {name} (maximum {limit})",
                        [{"filter": name, "maximum": limit}],
                    )
                out[name] = ids
                continue
            values = sorted(set(value))
            invalid = [v for v in values if v not in allowed_values[name]]
            if invalid:
                raise ReportValidationError(
                    "report_filter_invalid",
                    f"Invalid values for {name}",
                    [{"filter": name, "invalid": invalid[:10]}],
                )
            out[name] = values
        for name in definition.required_filters:
            if len(out.get(name) or []) != 1:
                raise ReportValidationError(
                    "report_filter_required",
                    f"This report type needs exactly one id in {name}",
                    [{"filter": name}],
                )
        return out

    def _range(
        self, definition: ReportDefinition, body: ReportRequest, now: datetime
    ) -> tuple[datetime | None, datetime | None, str | None]:
        if not definition.uses_range:
            return None, None, None
        preset = body.range.preset
        if preset == "custom":
            start, end = body.range.from_, body.range.to
            if start is None or end is None:
                raise ReportValidationError(
                    "report_range_invalid", "A custom range needs from and to"
                )
            start, end = start.astimezone(UTC), end.astimezone(UTC)
            if start >= end:
                raise ReportValidationError("report_range_invalid", "from must be before to")
            if end > now + CLOCK_SKEW:
                raise ReportValidationError("report_range_invalid", "to cannot be in the future")
            end = min(end, now)
            if start >= end:
                raise ReportValidationError("report_range_invalid", "from must be before to")
        else:
            if body.range.from_ is not None or body.range.to is not None:
                raise ReportValidationError(
                    "report_range_invalid", "from/to are only accepted with preset=custom"
                )
            end = now
            start = now - PRESETS[preset]
        max_days = self._max_days(definition)
        if end - start > timedelta(days=max_days):
            raise ReportValidationError(
                "report_range_too_large",
                f"The range exceeds the maximum of {max_days} days",
                [{"maximum_days": max_days}],
            )
        return start, end, preset

    def _scope(self, definition: ReportDefinition, filters: dict[str, Any]) -> dict[str, Any]:
        """Comprueba que los ids existen y guarda sus nombres en el momento de pedirlo."""
        session = self._session
        scope: dict[str, Any] = {}

        def missing(name: str, wanted: list[str], found: set[str]) -> None:
            absent = [i for i in wanted if i not in found]
            if absent:
                raise ReportValidationError(
                    "report_target_not_found",
                    f"Some ids in {name} do not exist",
                    [{"filter": name, "ids": absent[:10]}],
                )

        if filters.get("site_id"):
            site = session.scalar(select(Site).where(Site.public_id == UUID(filters["site_id"])))
            if site is not None:
                scope["site"] = {"id": str(site.public_id), "name": site.name}
        if filters.get("asset_ids"):
            wanted = filters["asset_ids"]
            assets = list(
                session.scalars(select(Asset).where(Asset.public_id.in_([UUID(i) for i in wanted])))
            )
            missing("asset_ids", wanted, {str(a.public_id) for a in assets})
            archived = [str(a.public_id) for a in assets if a.archived_at is not None]
            if archived and not filters.get("include_archived"):
                # Un activo archivado solo entra si se pide explícitamente (include_archived).
                raise ReportValidationError(
                    "report_asset_archived",
                    "Archived assets need include_archived=true",
                    [{"ids": archived[:10]}],
                )
            scope["assets"] = [
                {
                    "id": str(a.public_id),
                    "name": a.display_name[:255],
                    "archived": a.archived_at is not None,
                }
                for a in sorted(assets, key=lambda a: str(a.public_id))
            ]
        if filters.get("incident_ids"):
            wanted = filters["incident_ids"]
            incidents = list(
                session.scalars(
                    select(Incident).where(Incident.public_id.in_([UUID(i) for i in wanted]))
                )
            )
            missing("incident_ids", wanted, {str(i.public_id) for i in incidents})
            scope["incidents"] = [
                {"id": str(i.public_id), "name": f"INC-{i.number:06d}"}
                for i in sorted(incidents, key=lambda i: i.number)
            ]
        for name, column in (
            ("detection_ids", Detection.public_id),
            ("execution_ids", ResponseExecution.public_id),
            ("playbook_ids", Playbook.public_id),
        ):
            if filters.get(name):
                wanted = filters[name]
                found = {
                    str(v)
                    for v in session.scalars(
                        select(column).where(column.in_([UUID(i) for i in wanted]))
                    )
                }
                missing(name, wanted, found)
                scope[name.removesuffix("_ids") + "s"] = len(wanted)
        return scope

    @staticmethod
    def _title(definition: ReportDefinition, scope: dict[str, Any]) -> str:
        if definition.id == "incident" and scope.get("incidents"):
            return f"{definition.name} {scope['incidents'][0]['name']}"[:200]
        if definition.id == "asset" and scope.get("assets"):
            return f"{definition.name}: {scope['assets'][0]['name']}"[:200]
        return definition.name

    @staticmethod
    def _request_hash(req: Requester, n: Normalized) -> str:
        # Mismo usuario + misma petición = mismo hash. El preset (no sus horas exactas) entra
        # en el hash: dos clics seguidos con "7d" son la misma petición.
        payload = {
            "user": req.user.id if req.user else req.actor.name,
            "type": n.definition.id,
            "format": n.format,
            "classification": n.classification,
            "filters": n.filters,
            "range": n.preset if n.preset != "custom" else [iso(n.time_from), iso(n.time_to)],
        }
        return hashlib.sha256(canonical_json(payload)).hexdigest()

    # --- Preview -----------------------------------------------------------------------------

    def preview(self, req: Requester, body: ReportRequest) -> ReportPreview:
        """Metadatos y alcance aproximado. No crea informe, trabajo ni fichero."""
        self._require_enabled()
        now = _now()
        n = self._normalize(req, body, now)
        counts, warnings = self._estimate(req, n, now)
        return ReportPreview(
            report_type=n.definition.id,
            name=n.definition.name,
            format=n.format,
            classification=n.classification,
            template_version=n.definition.template_version,
            time_from=n.time_from,
            time_to=n.time_to,
            timezone=TIMEZONE,
            filters=n.filters,
            sections=list(n.definition.sections),
            scope={**n.scope, **counts},
            warnings=warnings,
            can_generate=True,
        )

    def _estimate(
        self, req: Requester, n: Normalized, now: datetime
    ) -> tuple[dict[str, int], list[ReportWarning]]:
        ctx = build_context(self._settings, n, now, self._session, req.permissions)
        session = self._session
        counts: dict[str, int] = {
            "assets": int(
                session.scalar(select(func.count()).where(*builders.asset_conditions(ctx))) or 0
            )
        }
        d = n.definition.id
        if d in ("technical", "detection", "asset", "executive_summary"):
            counts["detections"] = int(
                session.scalar(
                    select(func.count())
                    .select_from(Detection)
                    .where(*builders._detection_conditions(ctx))
                )
                or 0
            )
        if d in ("technical", "response_activity", "asset", "executive_summary"):
            counts["executions"] = int(
                session.scalar(
                    select(func.count())
                    .select_from(ResponseExecution)
                    .where(*builders._execution_conditions(ctx))
                )
                or 0
            )
        warnings: list[ReportWarning] = []
        limit = self._settings.report_max_rows
        if any(v > limit for k, v in counts.items() if k != "assets") or (
            d in ("technical", "lifecycle_change") and counts["assets"] > limit
        ):
            warnings.append(
                ReportWarning(
                    code="rows_truncated",
                    message=f"Some tables exceed {limit} rows:"
                    f" only the first {limit} will be included",
                )
            )
        if n.filters.get("include_archived"):
            warnings.append(
                ReportWarning(code="includes_archived", message="Archived assets are included")
            )
        if d == "vulnerability":
            warnings.append(
                ReportWarning(
                    code="potential_not_confirmed",
                    message="Potential findings are listed separately and are not confirmed",
                )
            )
        if n.definition.audience == "executive":
            warnings.append(
                ReportWarning(
                    code="executive_minimized",
                    message="The executive summary omits IDs, IP addresses and technical evidence",
                )
            )
        return counts, warnings

    # --- Creación ----------------------------------------------------------------------------

    def create(self, req: Requester, body: ReportCreate) -> ReportOut:
        self._require_enabled()
        now = _now()
        n = self._normalize(req, body, now)
        request_hash = self._request_hash(req, n)
        user_id = req.user.id if req.user else None
        if body.idempotency_key and user_id is not None:
            existing = self._session.scalar(
                select(Report).where(
                    Report.created_by_user_id == user_id,
                    Report.idempotency_key == body.idempotency_key,
                )
            )
            if existing is not None:
                if existing.request_hash != request_hash:
                    raise ReportConflictError("This idempotency key was used for another request")
                return self.out(req, existing, deduplicated=True)
        active = self._session.scalar(
            select(Report).where(
                Report.request_hash == request_hash, Report.status.in_(ACTIVE_REPORT_STATUSES)
            )
        )
        if active is not None:
            return self.out(req, active, deduplicated=True)
        self._check_queue(user_id)
        report = Report(
            public_id=uuid.uuid4(),
            report_type=n.definition.id,
            template_version=n.definition.template_version,
            title=n.title,
            format=n.format,
            classification=n.classification,
            status=PENDING,
            created_by=req.actor.name[:64],
            created_by_user_id=user_id,
            created_at=now,
            time_from=n.time_from,
            time_to=n.time_to,
            timezone=TIMEZONE,
            filters=n.filters,
            scope=n.scope,
            summary=None,
            idempotency_key=body.idempotency_key,
            request_hash=request_hash,
            attempts=0,
            version=1,
        )
        try:
            with self._session.begin_nested():
                self._session.add(report)
                self._session.flush()
        except IntegrityError:
            # Otra petición igual ganó la carrera (clave de idempotencia o petición viva):
            # se devuelve la suya, nunca se crean dos.
            other = self._session.scalar(
                select(Report).where(
                    or_(
                        (Report.request_hash == request_hash)
                        & Report.status.in_(ACTIVE_REPORT_STATUSES),
                        (Report.created_by_user_id == user_id)
                        & (Report.idempotency_key == body.idempotency_key),
                    )
                )
            )
            if other is None:
                raise ReportConflictError("A concurrent identical request is in progress") from None
            return self.out(req, other, deduplicated=True)
        self._audit(req.actor, "report_requested", report)
        self._session.commit()
        return self.out(req, report)

    def _check_queue(self, user_id: int | None) -> None:
        active = Report.status.in_(ACTIVE_REPORT_STATUSES)
        total = self._session.scalar(select(func.count()).select_from(Report).where(active)) or 0
        if total >= self._settings.report_max_queued_total:
            raise ReportQueueFullError("The report queue is full; try again later", 30, "reports")
        if user_id is not None:
            mine = (
                self._session.scalar(
                    select(func.count())
                    .select_from(Report)
                    .where(active, Report.created_by_user_id == user_id)
                )
                or 0
            )
            if mine >= self._settings.report_max_concurrent:
                raise ReportQueueFullError(
                    "You already have the maximum number of reports in progress", 10, "reports"
                )

    # --- Lectura ------------------------------------------------------------------------------

    def _get(self, req: Requester, public_id: UUID, lock: bool = False) -> Report:
        query = select(Report).where(Report.public_id == public_id)
        if lock:
            query = query.with_for_update()
        report = self._session.scalar(query)
        definition = get_definition(report.report_type) if report else None
        # Un informe que el rol no puede ver responde igual que uno inexistente (sin IDOR).
        if report is None or definition is None or not can_view(req.permissions, definition):
            raise NotFoundError("Report not found")
        return report

    def get(self, req: Requester, public_id: UUID) -> ReportOut:
        return self.out(req, self._get(req, public_id))

    def list_reports(
        self,
        req: Requester,
        *,
        report_type: str | None = None,
        status: str | None = None,
        requested_by: str | None = None,
        created_from: datetime | None = None,
        created_to: datetime | None = None,
        limit: int = 25,
        offset: int = 0,
    ) -> ReportList:
        conditions: list[ColumnElement[bool]] = [
            Report.report_type.in_(visible_types(req.permissions))
        ]
        if report_type:
            conditions.append(Report.report_type == report_type)
        if status:
            conditions.append(Report.status == status)
        if requested_by:
            conditions.append(Report.created_by == requested_by)
        if created_from:
            conditions.append(Report.created_at >= created_from)
        if created_to:
            conditions.append(Report.created_at <= created_to)
        total = (
            self._session.scalar(select(func.count()).select_from(Report).where(*conditions)) or 0
        )
        rows = list(
            self._session.scalars(
                select(Report)
                .where(*conditions)
                .order_by(Report.created_at.desc(), Report.id.desc())
                .limit(limit)
                .offset(offset)
            )
        )
        artifacts = self._artifacts([r.id for r in rows])
        return ReportList(
            items=[
                self.out(req, r, artifact=artifacts.get(r.id), with_artifact=False) for r in rows
            ],
            total=int(total),
        )

    def _artifacts(self, report_ids: list[int]) -> dict[int, ReportArtifact]:
        if not report_ids:
            return {}
        return {
            a.report_id: a
            for a in self._session.scalars(
                select(ReportArtifact).where(
                    ReportArtifact.report_id.in_(report_ids), ReportArtifact.deleted_at.is_(None)
                )
            )
        }

    def out(
        self,
        req: Requester,
        report: Report,
        *,
        deduplicated: bool = False,
        artifact: ReportArtifact | None = None,
        with_artifact: bool = True,
    ) -> ReportOut:
        definition = get_definition(report.report_type)
        if with_artifact and artifact is None:
            artifact = self._session.scalar(
                select(ReportArtifact).where(
                    ReportArtifact.report_id == report.id, ReportArtifact.deleted_at.is_(None)
                )
            )
        active = report.status in ACTIVE_REPORT_STATUSES
        own = req.user is not None and report.created_by_user_id == req.user.id
        return ReportOut(
            id=report.public_id,
            report_type=report.report_type,
            name=definition.name if definition else report.report_type,
            title=report.title,
            format=report.format,
            classification=report.classification,
            status=report.status,
            template_version=report.template_version,
            requested_by=report.created_by,
            created_at=report.created_at,
            started_at=report.started_at,
            finished_at=report.finished_at,
            cutoff_at=report.cutoff_at,
            time_from=report.time_from,
            time_to=report.time_to,
            timezone=report.timezone,
            filters=report.filters,
            scope=report.scope,
            summary=list(report.summary or []),
            artifact=ReportArtifactOut(
                filename=artifact.filename,
                content_type=artifact.content_type,
                size_bytes=artifact.size_bytes,
                sha256=artifact.sha256,
                created_at=artifact.created_at,
            )
            if artifact is not None
            else None,
            snapshot_sha256=report.snapshot_sha256,
            error_code=report.error_code,
            error_message=report.error_message,
            cancel_requested=report.cancel_requested_at is not None,
            deduplicated=deduplicated,
            can_cancel=active
            and req.has(Permission.REPORTS_GENERATE)
            and (own or req.has(Permission.REPORTS_ADMIN)),
            can_delete=req.has(Permission.REPORTS_ADMIN)
            and not active
            and report.status != EXPIRED,
            version=report.version,
        )

    # --- Cancelar y borrar --------------------------------------------------------------------

    def cancel(self, req: Requester, public_id: UUID) -> ReportOut:
        report = self._get(req, public_id, lock=True)
        own = req.user is not None and report.created_by_user_id == req.user.id
        if not own and not req.has(Permission.REPORTS_ADMIN):
            raise PermissionDeniedError("Only the requester or an admin can cancel this report")
        now = _now()
        if report.status == PENDING:
            # Aún nadie lo generaba: se cancela ya.
            report.status = CANCELLED
            report.finished_at = now
            report.cancel_requested_at = now
            report.error_code = "cancelled"
        elif report.status == RUNNING:
            # El worker lo comprueba entre secciones y antes de finalizar (bajo lock de fila):
            # nunca llegará a succeeded.
            report.cancel_requested_at = report.cancel_requested_at or now
        else:
            raise ReportStateError("The report already finished")
        report.version += 1
        self._audit(
            req.actor,
            "report_cancelled",
            report,
            {"was": "pending" if report.status == CANCELLED else "running"},
        )
        self._session.commit()
        return self.out(req, report)

    def delete(self, req: Requester, public_id: UUID, storage: ArtifactStorage) -> ReportOut:
        if not req.has(Permission.REPORTS_ADMIN):
            raise PermissionDeniedError("Deleting reports requires reports:admin")
        report = self._get(req, public_id, lock=True)
        if report.status in ACTIVE_REPORT_STATUSES:
            raise ReportStateError("Cancel the report before deleting it")
        if report.status == EXPIRED:
            raise ReportStateError("The report was already deleted or expired")
        checksum = _expire(self._session, report, storage, req.actor.name)
        self._audit(req.actor, "report_deleted", report, {"sha256": checksum})
        self._session.commit()
        return self.out(req, report)

    # --- Descarga ------------------------------------------------------------------------------

    def download(
        self, req: Requester, public_id: UUID, storage: ArtifactStorage
    ) -> tuple[ReportArtifact, bytes]:
        report = self._get(req, public_id)
        if report.status == EXPIRED:
            raise ReportArtifactUnavailableError("The report artifact expired or was deleted")
        if report.status != SUCCEEDED:
            raise ReportNotReadyError("The report is not ready")
        artifact = self._session.scalar(
            select(ReportArtifact).where(
                ReportArtifact.report_id == report.id, ReportArtifact.deleted_at.is_(None)
            )
        )
        if artifact is None:
            raise ReportArtifactUnavailableError("The report artifact is not available")
        try:
            data = storage.read(
                artifact.storage_key, self._settings.report_max_artifact_mb * 1024 * 1024
            )
        except StorageError:
            # Fichero borrado a mano, purgado a la vez o ruta manipulada: falla cerrado.
            raise ReportArtifactUnavailableError("The report artifact is not available") from None
        if sha256(data) != artifact.sha256:
            # Alguien modificó el fichero en disco: no se entrega y queda en la auditoría.
            self._audit(
                req.actor,
                "report_integrity_failed",
                report,
                {"sha256": artifact.sha256},
                result=audit_service.FAILURE,
            )
            self._session.commit()
            raise ReportIntegrityError("The artifact does not match its recorded SHA-256")
        self._audit(
            req.actor,
            "report_downloaded",
            report,
            {"sha256": artifact.sha256, "size_bytes": artifact.size_bytes},
        )
        self._session.commit()
        return artifact, data

    # --- Auditoría -----------------------------------------------------------------------------

    def _audit(
        self,
        actor: Actor,
        action: str,
        report: Report,
        extra: dict[str, Any] | None = None,
        result: str = audit_service.SUCCESS,
    ) -> None:
        _audit(self._session, actor, action, report, extra, result)


def _audit(
    session: Session,
    actor: Actor,
    action: str,
    report: Report,
    extra: dict[str, Any] | None = None,
    result: str = audit_service.SUCCESS,
) -> None:
    # Solo identificadores, enums y checksums: los filtros son ids y valores de catálogo ya
    # validados; nunca hay credenciales en un informe ni en su petición.
    details: dict[str, Any] = {
        "report_type": report.report_type,
        "format": report.format,
        "classification": report.classification,
        "filters": report.filters,
        "scope": {
            k: (len(v) if isinstance(v, list) else v) for k, v in (report.scope or {}).items()
        },
        "time_from": iso(report.time_from),
        "time_to": iso(report.time_to),
    }
    details.update(extra or {})
    audit_service.record(
        session, actor, action, result, target_type="report", target_id=report.public_id,
        details=details, commit=False,
    )  # fmt: skip


def _expire(session: Session, report: Report, storage: ArtifactStorage, by: str) -> str | None:
    """Borra el fichero y deja la fila como rastro (metadata, resumen y checksum)."""
    artifact = session.scalar(
        select(ReportArtifact).where(ReportArtifact.report_id == report.id).with_for_update()
    )
    checksum = None
    now = _now()
    if artifact is not None and artifact.deleted_at is None:
        checksum = artifact.sha256
        # Primero la fila (una descarga posterior ya ve "no disponible") y después el
        # fichero; si el borrado del fichero falla, la fila ya no lo ofrece igualmente.
        artifact.deleted_at = now
        session.flush()
        storage.delete(artifact.storage_key)
    report.status = EXPIRED
    report.expired_at = now
    report.expired_by = by[:64]
    report.snapshot = None
    report.version += 1
    return checksum


# --- Worker ---------------------------------------------------------------------------------


class ReportWorker:
    """Genera los informes pendientes. Lo ejecuta el job report-worker (o los tests)."""

    def __init__(
        self,
        engine: Engine,
        settings: Settings,
        storage: ArtifactStorage | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._engine = engine
        self._settings = settings
        self._storage = storage or ArtifactStorage(settings.report_output_dir)
        self._clock = clock

    @property
    def storage(self) -> ArtifactStorage:
        return self._storage

    def _session(self) -> Session:
        return Session(bind=self._engine, expire_on_commit=False)

    def run_once(self, max_jobs: int = 5) -> dict[str, int]:
        counts = {"recovered": self.recover_stale(), "generated": 0, "expired": 0}
        for _ in range(max_jobs):
            report_id = self._claim()
            if report_id is None:
                break
            self.generate(report_id)
            counts["generated"] += 1
        counts["expired"] = self.purge_expired()
        try:
            self._storage.purge_temp(self._settings.report_job_timeout_seconds * 2, time.time())
        except OSError:
            logger.warning("could not purge temporary report files", exc_info=True)
        return counts

    def recover_stale(self) -> int:
        """Trabajos running cuyo lease venció: el proceso que los generaba murió."""
        now = _now()
        recovered = 0
        with self._session() as session:
            stale = list(
                session.scalars(
                    select(Report)
                    .where(Report.status == RUNNING, Report.lease_until < now)
                    .with_for_update(skip_locked=True)
                    .limit(50)
                )
            )
            for report in stale:
                report.status = FAILED
                report.finished_at = now
                report.lease_until = None
                report.error_code = "report_interrupted"
                report.error_message = "Generation was interrupted (server restart or crash)"
                report.version += 1
                _audit(
                    session,
                    SYSTEM,
                    "report_failed",
                    report,
                    {"error_code": "report_interrupted"},
                    audit_service.FAILURE,
                )
                recovered += 1
            session.commit()
        return recovered

    def _claim(self) -> int | None:
        now = _now()
        with self._session() as session:
            report = session.scalar(
                select(Report)
                .where(Report.status == PENDING)
                .order_by(Report.created_at, Report.id)
                .with_for_update(skip_locked=True)
                .limit(1)
            )
            if report is None:
                return None
            report.status = RUNNING
            report.started_at = now
            report.attempts += 1
            report.lease_until = (
                now + timedelta(seconds=self._settings.report_job_timeout_seconds) + LEASE_MARGIN
            )
            report.version += 1
            session.commit()
            return report.id

    def generate(self, report_id: int) -> None:
        started = self._clock()
        deadline = started + self._settings.report_job_timeout_seconds
        with self._session() as session:
            report = session.get(Report, report_id)
            if report is None or report.status != RUNNING:
                return
            requester_permissions = self._permissions_of(session, report)

            def checkpoint() -> None:
                if self._clock() > deadline:
                    raise _StopError("report_timeout")
                requested = session.execute(
                    select(Report.cancel_requested_at).where(Report.id == report_id)
                ).scalar()
                session.commit()  # no retener la transacción de lectura entre secciones
                if requested is not None:
                    raise _StopError("cancelled")

            key: str | None = None
            try:
                snapshot, summary, cutoff = self._build(report, requester_permissions, checkpoint)
                checkpoint()
                data, digest_snapshot, snapshot_bytes = self._render(report, snapshot)
                limit = self._settings.report_max_artifact_mb * 1024 * 1024
                if len(data) > limit:
                    raise BuildError(
                        "report_artifact_too_large",
                        "The artifact exceeds REPORT_MAX_ARTIFACT_MB"
                        f" ({self._settings.report_max_artifact_mb} MB)",
                    )
                checkpoint()
                artifact_id = uuid.uuid4()
                key = new_key(report.created_at, artifact_id, EXTENSIONS[report.format])
                self._storage.write_atomic(key, data)
                self._finalize(
                    session, report_id, artifact_id, key, data, snapshot, summary, cutoff,
                    digest_snapshot, snapshot_bytes,
                )  # fmt: skip
            except _StopError as stop:
                self._discard(key)
                session.rollback()
                self._finish_stopped(session, report_id, stop.code)
            except BuildError as error:
                self._discard(key)
                session.rollback()
                self._fail(session, report_id, error.code, error.message)
            except Exception:
                logger.exception("report generation failed", extra={"report_id": report_id})
                self._discard(key)
                session.rollback()
                self._fail(
                    session, report_id, "report_generation_failed", "Report generation failed"
                )

    def _discard(self, key: str | None) -> None:
        if key is not None:
            self._storage.delete(key)

    @staticmethod
    def _permissions_of(session: Session, report: Report) -> frozenset[Permission]:
        # Los datos se leen con los permisos ACTUALES de quien lo pidió (si le quitaron el rol
        # entre la petición y la generación, el alcance se reduce en vez de ampliarse).
        from app.core.permissions import permissions_for

        if report.created_by_user_id is None:
            return frozenset(Permission)
        user = session.get(User, report.created_by_user_id)
        if user is None or not user.is_active:
            return frozenset()
        return permissions_for(user.role)

    def _build(
        self, report: Report, permissions: frozenset[Permission], checkpoint: Callable[[], None]
    ) -> tuple[dict[str, Any], list[str], datetime]:
        definition = get_definition(report.report_type)
        if definition is None:
            raise BuildError("report_type_unknown", "Unknown report type")
        if not definition.domain_permissions <= permissions:
            raise BuildError("report_forbidden", "The requester can no longer read this data")
        normalized = Normalized(
            definition=definition,
            format=report.format,
            classification=report.classification,
            time_from=report.time_from,
            time_to=report.time_to,
            preset=None,
            filters=dict(report.filters or {}),
            scope=dict(report.scope or {}),
            title=report.title,
        )
        # UNA transacción REPEATABLE READ de solo lectura para todas las secciones: misma
        # foto de la base de datos aunque los datos cambien mientras se genera. now() es el
        # inicio de la transacción = hora de corte común ("Datos a fecha de").
        snapshot_engine = self._engine.execution_options(isolation_level="REPEATABLE READ")
        with Session(bind=snapshot_engine) as snap:
            snap.execute(text("SET TRANSACTION READ ONLY"))
            snap.execute(text("SET LOCAL TIME ZONE 'UTC'"))
            cutoff = snap.scalar(select(func.now()))
            if cutoff is None:  # pragma: no cover - now() siempre devuelve valor
                raise BuildError("report_generation_failed", "Could not read the cutoff time")
            cutoff = cutoff.astimezone(UTC)
            ctx = build_context(self._settings, normalized, cutoff, snap, permissions, checkpoint)
            result = builders.BUILDERS[definition.id](ctx)
            snap.rollback()
        generated = _now()
        meta = {
            "report_id": str(report.public_id),
            "report_type": definition.id,
            "report_name": definition.name,
            "title": report.title,
            "template_version": definition.template_version,
            "requested_by": report.created_by,
            "requested_at": iso(report.created_at),
            "generated_at": iso(generated),
            "cutoff_at": iso(cutoff),
            "time_from": iso(report.time_from),
            "time_to": iso(min(report.time_to, cutoff) if report.time_to else None),
            "timezone": report.timezone,
            "classification": report.classification,
            "format": report.format,
            "filters": report.filters,
            "scope": report.scope,
        }
        snapshot = {
            "meta": meta,
            "summary": result["summary"],
            "data": result["data"],
            "tables": result.get("tables", {}),
        }
        return snapshot, list(result["summary"]), cutoff

    def _render(self, report: Report, snapshot: dict[str, Any]) -> tuple[bytes, str, int]:
        encoded = canonical_json(snapshot)
        if len(encoded) > MAX_SNAPSHOT_BYTES:
            raise BuildError(
                "report_snapshot_too_large", "The report data is too large; narrow the filters"
            )
        digest = sha256(encoded)
        definition = get_definition(report.report_type)
        if definition is None:
            raise BuildError("report_type_unknown", "Unknown report type")
        document = render_document(snapshot)
        generated = snapshot["meta"]["generated_at"]
        if report.format == "html":
            data = render_html(document)
        elif report.format == "pdf":
            data = render_pdf(document, generated)
        elif report.format == "csv":
            if definition.csv_table is None:
                raise BuildError("report_format_unsupported", "CSV is not available for this type")
            data = render_csv(definition.csv_table, snapshot["tables"].get(definition.csv_table))
        else:
            stamp = datetime.fromisoformat(snapshot["meta"]["cutoff_at"].replace("Z", "+00:00"))
            data = build_bundle(
                snapshot,
                render_html(document),
                render_pdf(document, generated),
                definition.evidence_tables,
                stamp,
            )
        return data, digest, len(encoded)

    def _finalize(
        self,
        session: Session,
        report_id: int,
        artifact_id: UUID,
        key: str,
        data: bytes,
        snapshot: dict[str, Any],
        summary: list[str],
        cutoff: datetime,
        snapshot_digest: str,
        snapshot_bytes: int,
    ) -> None:
        now = _now()
        try:
            # Lock de fila: una cancelación concurrente o la recuperación de huérfanos no se
            # cruzan con la finalización. Solo un running sin cancelación termina succeeded.
            report = session.scalar(
                select(Report)
                .where(Report.id == report_id)
                .with_for_update()
                # La sesión del worker ya tiene esta fila en memoria: se relee de la BD
                # para ver una cancelación que otra petición confirmó entre medias.
                .execution_options(populate_existing=True)
            )
            if report is None or report.status != RUNNING or report.cancel_requested_at is not None:
                session.rollback()
                self._discard(key)
                if report is not None and report.status == RUNNING:
                    self._finish_stopped(session, report_id, "cancelled")
                return
            digest = sha256(data)
            session.add(
                ReportArtifact(
                    public_id=artifact_id,
                    report_id=report.id,
                    format=report.format,
                    filename=_filename(report, artifact_id),
                    content_type=CONTENT_TYPES[report.format],
                    storage_key=key,
                    size_bytes=len(data),
                    sha256=digest,
                    created_at=now,
                )
            )
            report.status = SUCCEEDED
            report.finished_at = now
            report.lease_until = None
            report.cutoff_at = cutoff
            report.snapshot = snapshot
            report.snapshot_sha256 = snapshot_digest
            report.snapshot_bytes = snapshot_bytes
            report.summary = summary
            report.error_code = None
            report.error_message = None
            report.version += 1
            actor = Actor(report.created_by, report.created_by_user_id)
            _audit(
                session,
                actor,
                "report_generated",
                report,
                {"sha256": digest, "size_bytes": len(data), "snapshot_sha256": snapshot_digest},
            )
            if report.format == "evidence":
                _audit(
                    session,
                    actor,
                    "evidence_bundle_generated",
                    report,
                    {"sha256": digest, "size_bytes": len(data)},
                )
            session.commit()
        except Exception:
            session.rollback()
            self._discard(key)
            raise

    def _finish_stopped(self, session: Session, report_id: int, code: str) -> None:
        if code != "cancelled":
            self._fail(session, report_id, code, "Generation exceeded REPORT_JOB_TIMEOUT_SECONDS")
            return
        report = session.scalar(
            select(Report)
            .where(Report.id == report_id)
            .with_for_update()
            # La sesión del worker ya tiene esta fila en memoria: se relee de la BD
            # para ver una cancelación que otra petición confirmó entre medias.
            .execution_options(populate_existing=True)
        )
        if report is None or report.status != RUNNING:
            session.rollback()
            return
        report.status = CANCELLED
        report.finished_at = _now()
        report.lease_until = None
        report.error_code = "cancelled"
        report.version += 1
        _audit(session, SYSTEM, "report_cancelled", report, {"was": "running"})
        session.commit()

    def _fail(self, session: Session, report_id: int, code: str, message: str) -> None:
        report = session.scalar(
            select(Report)
            .where(Report.id == report_id)
            .with_for_update()
            # La sesión del worker ya tiene esta fila en memoria: se relee de la BD
            # para ver una cancelación que otra petición confirmó entre medias.
            .execution_options(populate_existing=True)
        )
        if report is None or report.status != RUNNING:
            session.rollback()
            return
        report.status = FAILED
        report.finished_at = _now()
        report.lease_until = None
        report.error_code = code[:64]
        report.error_message = message[:500]
        report.version += 1
        _audit(
            session, SYSTEM, "report_failed", report, {"error_code": code}, audit_service.FAILURE
        )
        session.commit()

    def purge_expired(self) -> int:
        """Retención (REPORT_RETENTION_DAYS). Sin valor no borra nada. Acotada por vuelta."""
        days = self._settings.report_retention_days
        if not days:
            return 0
        cutoff = _now() - timedelta(days=days)
        expired = 0
        with self._session() as session:
            reports = list(
                session.scalars(
                    select(Report)
                    .where(
                        Report.status.in_((SUCCEEDED, FAILED, CANCELLED)),
                        Report.finished_at < cutoff,
                    )
                    .order_by(Report.finished_at, Report.id)
                    .with_for_update(skip_locked=True)
                    .limit(RETENTION_BATCH)
                )
            )
            for report in reports:
                checksum = _expire(session, report, self._storage, "retention")
                _audit(
                    session,
                    SYSTEM,
                    "report_expired",
                    report,
                    {"sha256": checksum, "retention_days": days},
                )
                expired += 1
            session.commit()
        return expired


def mark_stale_on_startup(session: Session) -> int:
    """Utilidad para la CLI: cierra como failed todo running (servicio parado del todo)."""
    result = session.execute(
        update(Report)
        .where(Report.status == RUNNING)
        .values(
            status=FAILED, error_code="report_interrupted", finished_at=_now(), lease_until=None
        )
    )
    session.commit()
    return int(getattr(result, "rowcount", 0) or 0)


__all__ = ["ReportService", "ReportWorker", "Requester", "build_context", "can_view"]
