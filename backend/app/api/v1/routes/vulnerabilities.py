"""Vulnerability & Exposure Management (Fase 5B).

Permisos:
- vulnerabilities:read (todos los roles): findings, detalle, historial, resumen, exposición,
  vulnerabilidades de un activo y catálogo importado;
- vulnerabilities:manage (analyst, admin): reconocer, en mitigación, resolver (con motivo) y
  abrir un incidente desde un finding (además exige incidents:manage);
- vulnerabilities:admin (admin): aceptar riesgo, falso positivo, reabrir, previsualizar e
  importar el catálogo y forzar una reevaluación.

Nada de esto contacta con los activos ni con Internet: el catálogo es local y la remediación
es texto. Cada cambio queda auditado (también los intentos fallidos).
"""

from collections.abc import Callable
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select

from app.api.auth import actor, require_permission
from app.api.deps import AppSettings, DbSession, Thresholds
from app.api.params import text_query
from app.api.responses import error_responses
from app.core.exceptions import NotFoundError, PermissionDeniedError, SentraError
from app.core.permissions import Permission
from app.incidents.workflow import incident_key
from app.models.audit import AuditEvent
from app.models.incident import IncidentLevel
from app.models.vulnerability import AssetVulnerabilityState
from app.schemas.audit import AuditEventList, AuditEventRead
from app.schemas.incident import IncidentDetail, IncidentPromote
from app.schemas.vulnerability import (
    AssetVulnerabilities,
    CatalogImportIn,
    CatalogImportResult,
    CatalogIn,
    CatalogList,
    CatalogPreview,
    EvaluateIn,
    EvaluateResult,
    ExposureOverview,
    FindingAcceptRisk,
    FindingAction,
    FindingDecision,
    FindingDetail,
    FindingHistory,
    FindingIncidentIn,
    FindingList,
    FindingResolve,
    FindingThreatIntel,
    VulnerabilityOverview,
)
from app.services import audit_service
from app.services.auth_service import AuthContext
from app.services.incident_service import IncidentService, Operator, detail
from app.services.vulnerability_catalog_service import VulnerabilityCatalogService
from app.services.vulnerability_service import (
    TARGET,
    FindingFilter,
    FindingSort,
    VulnerabilityService,
)
from app.vulnerabilities import workflow
from app.vulnerabilities.engine import VulnerabilityConfig, VulnerabilityEngine, add_history
from app.vulnerabilities.queue import mark_dirty
from app.vulnerabilities.sources import UploadedSource

router = APIRouter(tags=["vulnerabilities"])

Reader = Annotated[AuthContext, Depends(require_permission(Permission.VULNERABILITIES_READ))]
Manager = Annotated[AuthContext, Depends(require_permission(Permission.VULNERABILITIES_MANAGE))]
Admin = Annotated[AuthContext, Depends(require_permission(Permission.VULNERABILITIES_ADMIN))]
AuditReader = Annotated[AuthContext, Depends(require_permission(Permission.AUDIT_READ))]

Severity = Literal["informational", "low", "medium", "high", "critical"]
MatchState = Literal["confirmed", "probable", "potential", "unknown", "not_affected"]
Status = Literal[
    "open", "acknowledged", "mitigating", "resolved", "accepted_risk", "false_positive"
]
ExposureState = Literal["internet_exposed", "observed", "listening", "not_observed", "unknown"]
VulnId = Annotated[str, Query(max_length=64, pattern=r"^[A-Za-z][A-Za-z0-9._:-]{1,63}$")]
SourceKey = Annotated[str, Query(max_length=64, pattern=r"^[a-z0-9][a-z0-9._-]{1,63}$")]
CATALOG_TARGET = "vulnerability_catalog"


def get_config(settings: AppSettings) -> VulnerabilityConfig:
    return VulnerabilityConfig.from_settings(settings)


Config = Annotated[VulnerabilityConfig, Depends(get_config)]


def get_service(session: DbSession, config: Config, thresholds: Thresholds) -> VulnerabilityService:
    return VulnerabilityService(session, config, thresholds)


Service = Annotated[VulnerabilityService, Depends(get_service)]


def get_catalog(session: DbSession, settings: AppSettings) -> VulnerabilityCatalogService:
    return VulnerabilityCatalogService(session, settings)


Catalog = Annotated[VulnerabilityCatalogService, Depends(get_catalog)]


def _failed[T](
    session: DbSession,
    ctx: AuthContext,
    action: str,
    target_type: str,
    target: str | None,
    run: Callable[[], T],
) -> T:
    """Ejecuta un cambio; si falla, deja constancia del intento (con el código, sin datos)."""
    try:
        return run()
    except SentraError as exc:
        session.rollback()
        audit_service.record(
            session,
            actor(ctx),
            action,
            audit_service.FAILURE,
            target_type,
            target,
            details={"error": exc.code},
        )
        raise


def _filter(
    status: Status | None,
    active: bool,
    severity: Severity | None,
    match_state: MatchState | None,
    confidence: Literal["high", "medium", "low"] | None,
    exposure: ExposureState | None,
    vulnerability_id: str | None,
    source: str | None,
    stale: bool | None,
    q: str | None,
    asset_id: int | None = None,
    known_exploited: bool | None = None,
    epss_min: float | None = None,
    intel_stale: bool | None = None,
) -> FindingFilter:
    return FindingFilter(
        status=status,
        active=active,
        severity=severity,
        match_state=match_state,
        confidence=confidence,
        exposure_state=exposure,
        asset_id=asset_id,
        vulnerability_id=vulnerability_id.upper()
        if vulnerability_id and vulnerability_id.upper().startswith("CVE-")
        else vulnerability_id,
        source=source,
        stale=stale,
        search=q.strip() if q and q.strip() else None,
        known_exploited=known_exploited,
        epss_min=epss_min,
        intel_stale=intel_stale,
    )


# --- Lectura -----------------------------------------------------------------------------------


@router.get("/vulnerabilities/overview", response_model=VulnerabilityOverview)
def vulnerabilities_overview(_: Reader, service: Service) -> VulnerabilityOverview:
    """Tarjetas del resumen. Las potenciales nunca cuentan como confirmadas."""
    return service.overview()


@router.get("/vulnerabilities/findings", response_model=FindingList)
def list_findings(
    _: Reader,
    service: Service,
    status: Status | None = None,
    # Solo los que necesitan trabajo (open, acknowledged, mitigating); ignorado con status.
    active: bool = False,
    severity: Severity | None = None,
    match_state: MatchState | None = None,
    confidence: Literal["high", "medium", "low"] | None = None,
    exposure: ExposureState | None = None,
    asset_id: UUID | None = None,
    vulnerability_id: VulnId | None = None,
    source: SourceKey | None = None,
    stale: bool | None = None,
    # CVE/advisory, título, producto, editor, hostname o IP.
    q: Annotated[str | None, text_query(200)] = None,
    # Fase 5C: en CISA KEV (fuente activa), EPSS mínimo (0-1) e inteligencia caducada.
    kev: bool | None = None,
    epss_min: Annotated[float | None, Query(ge=0, le=1)] = None,
    intel_stale: bool | None = None,
    sort: FindingSort = "priority",
    order: Literal["asc", "desc"] = "desc",
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> FindingList:
    internal = None
    if asset_id is not None:
        ids = service.asset_ids([asset_id])
        if not ids:
            return FindingList(items=[], total=0)
        internal = ids[0]
    f = _filter(
        status, active, severity, match_state, confidence, exposure, vulnerability_id, source,
        stale, q, internal, kev, epss_min, intel_stale,
    )  # fmt: skip
    return service.list_findings(f, sort, order == "desc", limit, offset)


@router.get(
    "/vulnerabilities/findings/{finding_id}",
    response_model=FindingDetail,
    responses=error_responses(404),
)
def get_finding(finding_id: UUID, ctx: Reader, service: Service) -> FindingDetail:
    return service.get(
        finding_id,
        can_manage=ctx.has(Permission.VULNERABILITIES_MANAGE),
        can_admin=ctx.has(Permission.VULNERABILITIES_ADMIN),
    )


@router.get(
    "/vulnerabilities/findings/{finding_id}/threat-intel",
    response_model=FindingThreatIntel,
    responses=error_responses(403, 404),
)
def finding_threat_intel(finding_id: UUID, ctx: Reader, service: Service) -> FindingThreatIntel:
    """Fase 5C: KEV/EPSS del CVE del finding con procedencia, historial y discrepancias."""
    if not ctx.has(Permission.THREAT_INTEL_READ):
        raise PermissionDeniedError("Requires threat_intel:read")
    return service.threat_intel(finding_id)


@router.get(
    "/vulnerabilities/findings/{finding_id}/history",
    response_model=FindingHistory,
    responses=error_responses(404),
)
def finding_history(
    finding_id: UUID,
    _: Reader,
    service: Service,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
    offset: Annotated[int, Query(ge=0, le=10_000)] = 0,
) -> FindingHistory:
    return service.history(finding_id, limit, offset)


@router.get(
    "/vulnerabilities/findings/{finding_id}/audit",
    response_model=AuditEventList,
)
def finding_audit(
    finding_id: UUID,
    _: AuditReader,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=10_000)] = 0,
) -> AuditEventList:
    rows = session.scalars(
        select(AuditEvent)
        .where(AuditEvent.target_type == TARGET, AuditEvent.target_id == str(finding_id))
        .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return AuditEventList(items=[AuditEventRead.model_validate(row) for row in rows])


@router.get(
    "/assets/{asset_id}/vulnerabilities",
    response_model=AssetVulnerabilities,
    responses=error_responses(404),
)
def asset_vulnerabilities(
    asset_id: UUID,
    _: Reader,
    service: Service,
    status: Status | None = None,
    active: bool = False,
    severity: Severity | None = None,
    match_state: MatchState | None = None,
    sort: FindingSort = "priority",
    order: Literal["asc", "desc"] = "desc",
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> AssetVulnerabilities:
    f = _filter(status, active, severity, match_state, None, None, None, None, None, None)
    return service.asset_findings(asset_id, f, sort, order == "desc", limit, offset)


@router.get("/vulnerabilities/exposure", response_model=ExposureOverview)
def exposure_overview(
    _: Reader,
    service: Service,
    sensitive: bool = False,
    new: bool = False,
    with_vulnerabilities: bool = False,
    asset_id: UUID | None = None,
    port: Annotated[int | None, Query(ge=1, le=65535)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> ExposureOverview:
    """Exposición consolidada (Discovery 4D + contexto 4L + findings). Un puerto abierto no
    es una vulnerabilidad."""
    return service.exposure(
        sensitive_only=sensitive,
        new_only=new,
        with_vulnerabilities=with_vulnerabilities,
        asset_public_id=asset_id,
        port=port,
        limit=limit,
        offset=offset,
    )


@router.get("/vulnerabilities/catalog", response_model=CatalogList)
def catalog_records(
    _: Reader,
    catalog: Catalog,
    source: SourceKey | None = None,
    severity: Severity | None = None,
    # Prefijo del identificador: "CVE-2024-" o un id completo.
    q: Annotated[str | None, Query(max_length=64, pattern=r"^[A-Za-z0-9._:-]*$")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> CatalogList:
    return catalog.list_records(
        source=source, severity=severity, search=q or None, limit=limit, offset=offset
    )


# --- Flujo de trabajo --------------------------------------------------------------------------


def _act(
    finding_id: UUID,
    action: str,
    ctx: AuthContext,
    service: VulnerabilityService,
    session: DbSession,
    version: int,
    reason: str | None,
    **extra: object,
) -> FindingDetail:
    def run() -> FindingDetail:
        finding = service.apply_action(finding_id, action, version, reason, actor(ctx), **extra)  # type: ignore[arg-type]
        details: dict[str, object] = {"to": workflow.ACTIONS[action]}
        if reason:
            details["reason"] = reason[:200]
        if extra.get("accepted_until") is not None:
            details["accepted_until"] = str(extra["accepted_until"])
        if extra.get("override_evidence"):
            details["override_evidence"] = True
        service.audit(actor(ctx), workflow.AUDIT_ACTIONS[action], finding, details=details)
        session.commit()
        return service.get(
            finding_id,
            can_manage=ctx.has(Permission.VULNERABILITIES_MANAGE),
            can_admin=ctx.has(Permission.VULNERABILITIES_ADMIN),
        )

    return _failed(session, ctx, workflow.AUDIT_ACTIONS[action], TARGET, str(finding_id), run)


_STATE_ERRORS = error_responses(404, 409)


@router.post(
    "/vulnerabilities/findings/{finding_id}/acknowledge",
    response_model=FindingDetail,
    responses=_STATE_ERRORS,
)
def acknowledge_finding(
    finding_id: UUID, body: FindingAction, ctx: Manager, service: Service, session: DbSession
) -> FindingDetail:
    return _act(finding_id, "acknowledge", ctx, service, session, body.version, body.reason)


@router.post(
    "/vulnerabilities/findings/{finding_id}/mitigating",
    response_model=FindingDetail,
    responses=_STATE_ERRORS,
)
def mitigating_finding(
    finding_id: UUID, body: FindingAction, ctx: Manager, service: Service, session: DbSession
) -> FindingDetail:
    return _act(finding_id, "mitigating", ctx, service, session, body.version, body.reason)


@router.post(
    "/vulnerabilities/findings/{finding_id}/resolve",
    response_model=FindingDetail,
    responses=_STATE_ERRORS,
)
def resolve_finding(
    finding_id: UUID, body: FindingResolve, ctx: Manager, service: Service, session: DbSession
) -> FindingDetail:
    """Resolver a mano exige motivo; si la evidencia dice vulnerable, también
    override_evidence. Si la evidencia cambia después, la evaluación lo reabre."""
    return _act(
        finding_id,
        "resolve",
        ctx,
        service,
        session,
        body.version,
        body.reason,
        override_evidence=body.override_evidence,
    )


@router.post(
    "/vulnerabilities/findings/{finding_id}/accept-risk",
    response_model=FindingDetail,
    responses=_STATE_ERRORS,
)
def accept_risk(
    finding_id: UUID, body: FindingAcceptRisk, ctx: Admin, service: Service, session: DbSession
) -> FindingDetail:
    """Solo admin, con motivo y caducidad opcional (al vencer vuelve a open, auditado)."""
    return _act(
        finding_id,
        "accept-risk",
        ctx,
        service,
        session,
        body.version,
        body.reason,
        accepted_until=body.accepted_until,
    )


@router.post(
    "/vulnerabilities/findings/{finding_id}/false-positive",
    response_model=FindingDetail,
    responses=_STATE_ERRORS,
)
def false_positive(
    finding_id: UUID, body: FindingDecision, ctx: Admin, service: Service, session: DbSession
) -> FindingDetail:
    """Solo admin, con motivo. Se reevalúa si cambia la versión o el registro del catálogo."""
    return _act(finding_id, "false-positive", ctx, service, session, body.version, body.reason)


@router.post(
    "/vulnerabilities/findings/{finding_id}/reopen",
    response_model=FindingDetail,
    responses=_STATE_ERRORS,
)
def reopen_finding(
    finding_id: UUID, body: FindingDecision, ctx: Admin, service: Service, session: DbSession
) -> FindingDetail:
    return _act(finding_id, "reopen", ctx, service, session, body.version, body.reason)


@router.post(
    "/vulnerabilities/findings/{finding_id}/incident",
    response_model=IncidentDetail,
    status_code=201,
    responses=_STATE_ERRORS,
)
def incident_from_finding(
    finding_id: UUID,
    body: FindingIncidentIn,
    ctx: Manager,
    service: Service,
    session: DbSession,
) -> IncidentDetail:
    """Abre un incidente (4K) desde el finding. Nunca automático: lo decide un analista."""
    if not ctx.has(Permission.INCIDENTS_MANAGE):
        raise PermissionDeniedError("Creating incidents requires incidents:manage")

    def run() -> IncidentDetail:
        finding = service.lock(finding_id, body.version)
        operator = Operator.from_context(ctx.user, ctx.client_ip, ctx.permissions)
        incidents = IncidentService(session, operator)
        incident = incidents.promote_vulnerability(
            finding_id,
            IncidentPromote(
                title=body.title,
                description=body.description,
                priority=IncidentLevel(body.priority) if body.priority else None,
            ),
        )
        add_history(
            session,
            finding,
            "incident_created",
            incident.created_at,
            actor=actor(ctx).name,
            actor_user_id=ctx.user.id,
            to_value=incident_key(incident.number),
            details={"incident_id": str(incident.public_id)},
        )
        service.audit(
            actor(ctx),
            "vulnerability_incident_created",
            finding,
            details={"incident": str(incident.public_id)},
        )
        session.commit()
        return detail(session, incident)

    return _failed(session, ctx, "vulnerability_incident_created", TARGET, str(finding_id), run)


# --- Evaluación y catálogo (admin) -------------------------------------------------------------


@router.post(
    "/vulnerabilities/evaluate", response_model=EvaluateResult, responses=error_responses(404)
)
def evaluate(
    body: EvaluateIn,
    ctx: Admin,
    session: DbSession,
    config: Config,
    thresholds: Thresholds,
    service: Service,
) -> EvaluateResult:
    """Un activo: se evalúa ya. Todos: se encolan y el job los procesa por lotes."""
    if body.asset_id is not None:
        ids = service.asset_ids([body.asset_id])
        if not ids:
            raise NotFoundError("Asset not found")
        run = VulnerabilityEngine(session, config, thresholds).evaluate(ids)
        audit_service.record(
            session,
            actor(ctx),
            "vulnerability_evaluation_started",
            target_type="asset",
            target_id=body.asset_id,
            details={"mode": "immediate", **run.as_dict()},
            commit=False,
        )
        session.commit()
        return EvaluateResult(
            mode="immediate",
            assets=run.assets,
            created=run.created,
            updated=run.updated,
            resolved=run.resolved,
            reopened=run.reopened,
        )
    engine = VulnerabilityEngine(session, config, thresholds)
    engine.seed_missing(limit=100_000)
    ids = list(session.scalars(select(AssetVulnerabilityState.asset_id)))
    mark_dirty(session, ids, "manual")
    audit_service.record(
        session,
        actor(ctx),
        "vulnerability_evaluation_started",
        target_type="vulnerabilities",
        details={"mode": "queued", "assets": len(ids)},
        commit=False,
    )
    session.commit()
    return EvaluateResult(mode="queued", assets=len(ids))


@router.post("/vulnerabilities/catalog/preview", response_model=CatalogPreview)
def catalog_preview(body: CatalogIn, _: Admin, catalog: Catalog) -> CatalogPreview:
    """Valida y cuenta (new, updated, unchanged, invalid). No guarda NADA."""
    return catalog.preview(UploadedSource(body.content))


@router.post(
    "/vulnerabilities/catalog/import",
    response_model=CatalogImportResult,
    responses=error_responses(409),
)
def catalog_import(
    body: CatalogImportIn, ctx: Admin, catalog: Catalog, session: DbSession
) -> CatalogImportResult:
    """Importa el catálogo previsualizado (mismo sha256) en una transacción."""

    def run() -> CatalogImportResult:
        result, created = catalog.import_catalog(
            UploadedSource(body.content), actor(ctx), body.expected_sha256, body.skip_invalid
        )
        audit_service.record(
            session,
            actor(ctx),
            "vulnerability_catalog_imported" if created else "vulnerability_catalog_updated",
            target_type=CATALOG_TARGET,
            target_id=result.source,
            details={
                "sha256": result.sha256,
                "revision": result.revision,
                "new": result.new,
                "updated": result.updated,
                "unchanged": result.unchanged,
                "invalid": result.invalid,
                "assets_queued": result.assets_queued,
                "via": "api",
            },
            commit=False,
        )
        session.commit()
        return result

    return _failed(session, ctx, "vulnerability_catalog_imported", CATALOG_TARGET, None, run)
