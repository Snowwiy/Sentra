"""Threat Intelligence & Exploitability Context (Fase 5C). Ver docs/threat-intelligence.md.

Permisos:
- threat_intel:read (todos los roles): resumen, fuentes (sin secretos ni URLs completas),
  historial de sincronizaciones, indicadores y matches;
- threat_intel:triage (analyst, admin): reconocer, descartar o reabrir un match y abrir un
  incidente desde él (además exige incidents:manage);
- threat_intel:manage (admin): crear, configurar, activar, desactivar y archivar fuentes,
  pedir una sincronización, importar IOCs y forzar el matching retroactivo.

Ninguna ruta descarga nada ni acepta URLs: "Sincronizar ahora" solo marca la fuente y el
job la sincroniza (si THREAT_INTEL_SYNC_ENABLED=true) desde la URL configurada en el
servidor. Cada cambio queda auditado, también los intentos fallidos.
"""

from collections.abc import Callable
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select

from app.api.auth import actor, require_permission
from app.api.deps import AppSettings, DbSession
from app.api.params import text_query
from app.api.responses import error_responses
from app.core.exceptions import (
    PermissionDeniedError,
    SentraError,
    ThreatIntelConflictError,
    ThreatIntelError,
)
from app.core.permissions import Permission
from app.models.asset import Asset
from app.models.incident import IncidentLevel
from app.schemas.incident import IncidentDetail, IncidentPromote
from app.schemas.threat_intel import (
    IndicatorDetail,
    IndicatorList,
    MatchAction,
    MatchDecision,
    MatchDetail,
    MatchIncidentIn,
    MatchList,
    ReevaluateResult,
    ThreatImportConfirm,
    ThreatImportIn,
    ThreatImportPreview,
    ThreatImportResult,
    ThreatIntelOverview,
    ThreatInvalidRecord,
    ThreatSourceAction,
    ThreatSourceCreate,
    ThreatSourceList,
    ThreatSourceRead,
    ThreatSourceUpdate,
    ThreatSyncList,
)
from app.services import audit_service
from app.services.auth_service import AuthContext
from app.services.incident_service import IncidentService, Operator, detail
from app.services.threat_intel_service import (
    IndicatorFilter,
    IndicatorSort,
    MatchFilter,
    MatchSort,
    ThreatIntelService,
)
from app.threat_intel.config import ThreatIntelConfig
from app.threat_intel.errors import IntelFormatError
from app.threat_intel.sync import ThreatIntelSyncer

router = APIRouter(prefix="/threat-intel", tags=["threat-intel"])

Reader = Annotated[AuthContext, Depends(require_permission(Permission.THREAT_INTEL_READ))]
Triage = Annotated[AuthContext, Depends(require_permission(Permission.THREAT_INTEL_TRIAGE))]
Manager = Annotated[AuthContext, Depends(require_permission(Permission.THREAT_INTEL_MANAGE))]

IndicatorType = Literal[
    "ipv4", "ipv6", "cidr", "domain", "hostname", "url", "sha256", "sha1", "md5", "email"
]
Classification = Literal["malicious", "suspicious", "benign", "unknown"]
Confidence = Literal["low", "medium", "high"]
MatchStatus = Literal["open", "acknowledged", "dismissed"]
ObservationType = Literal["auth_source_ip", "connection_remote_ip", "asset_address", "asset_name"]
SOURCE_TARGET = "threat_source"
MATCH_TARGET = "threat_match"


def get_config(settings: AppSettings) -> ThreatIntelConfig:
    return ThreatIntelConfig.from_settings(settings)


Config = Annotated[ThreatIntelConfig, Depends(get_config)]


def get_service(session: DbSession, config: Config) -> ThreatIntelService:
    return ThreatIntelService(session, config)


Service = Annotated[ThreatIntelService, Depends(get_service)]


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
    except IntelFormatError as exc:
        session.rollback()
        audit_service.record(
            session, actor(ctx), action, audit_service.FAILURE, target_type, target,
            details={"error": exc.code},
        )  # fmt: skip
        raise ThreatIntelError(exc.code, str(exc)) from None
    except SentraError as exc:
        session.rollback()
        audit_service.record(
            session, actor(ctx), action, audit_service.FAILURE, target_type, target,
            details={"error": exc.code},
        )  # fmt: skip
        raise


# --- Resumen y fuentes -------------------------------------------------------------------------


@router.get("/overview", response_model=ThreatIntelOverview)
def overview(_: Reader, service: Service) -> ThreatIntelOverview:
    """Tarjetas del resumen. Sin fuentes activas: status "none_configured" (no es un error)."""
    return service.overview()


@router.get("/sources", response_model=ThreatSourceList)
def list_sources(_: Reader, service: Service, archived: bool = False) -> ThreatSourceList:
    return service.sources(include_archived=archived)


@router.post(
    "/sources", response_model=ThreatSourceRead, status_code=201, responses=error_responses(409)
)
def create_source(
    body: ThreatSourceCreate, ctx: Manager, service: Service, session: DbSession
) -> ThreatSourceRead:
    def run() -> ThreatSourceRead:
        source = service.create_source(body, actor(ctx))
        audit_service.record(
            session,
            actor(ctx),
            "threat_source_created",
            target_type=SOURCE_TARGET,
            target_id=source.source_key,
            details={"provider": source.provider, "trust": source.trust},
            commit=False,
        )
        session.commit()
        return service.source_read(source)

    return _failed(session, ctx, "threat_source_created", SOURCE_TARGET, body.source_key, run)


@router.patch(
    "/sources/{source_id}", response_model=ThreatSourceRead, responses=error_responses(404, 409)
)
def update_source(
    source_id: int, body: ThreatSourceUpdate, ctx: Manager, service: Service, session: DbSession
) -> ThreatSourceRead:
    def run() -> ThreatSourceRead:
        source, changes = service.update_source(source_id, body)
        if changes:
            audit_service.record(
                session,
                actor(ctx),
                "threat_source_updated",
                target_type=SOURCE_TARGET,
                target_id=source.source_key,
                details={"changes": changes},
                commit=False,
            )
        session.commit()
        return service.source_read(source)

    return _failed(session, ctx, "threat_source_updated", SOURCE_TARGET, str(source_id), run)


def _toggle(
    source_id: int,
    body: ThreatSourceAction,
    ctx: AuthContext,
    service: ThreatIntelService,
    session: DbSession,
    action: Literal["enable", "disable", "archive"],
) -> ThreatSourceRead:
    audit_action = {
        "enable": "threat_source_enabled",
        "disable": "threat_source_disabled",
        "archive": "threat_source_archived",
    }[action]

    def run() -> ThreatSourceRead:
        if action == "archive":
            source = service.archive(source_id, body.revision)
        else:
            source = service.set_enabled(source_id, body.revision, action == "enable")
        audit_service.record(
            session,
            actor(ctx),
            audit_action,
            target_type=SOURCE_TARGET,
            target_id=source.source_key,
            commit=False,
        )
        session.commit()
        return service.source_read(source)

    return _failed(session, ctx, audit_action, SOURCE_TARGET, str(source_id), run)


_SOURCE_ERRORS = error_responses(404, 409, 422)


@router.post(
    "/sources/{source_id}/enable", response_model=ThreatSourceRead, responses=_SOURCE_ERRORS
)
def enable_source(
    source_id: int, body: ThreatSourceAction, ctx: Manager, service: Service, session: DbSession
) -> ThreatSourceRead:
    return _toggle(source_id, body, ctx, service, session, "enable")


@router.post(
    "/sources/{source_id}/disable", response_model=ThreatSourceRead, responses=_SOURCE_ERRORS
)
def disable_source(
    source_id: int, body: ThreatSourceAction, ctx: Manager, service: Service, session: DbSession
) -> ThreatSourceRead:
    """La inteligencia de la fuente deja de contar (prioridad, riesgo, matching) sin borrarse."""
    return _toggle(source_id, body, ctx, service, session, "disable")


@router.post(
    "/sources/{source_id}/archive", response_model=ThreatSourceRead, responses=_SOURCE_ERRORS
)
def archive_source(
    source_id: int, body: ThreatSourceAction, ctx: Manager, service: Service, session: DbSession
) -> ThreatSourceRead:
    """En lugar de borrar: los matches, el historial y los incidentes la siguen citando."""
    return _toggle(source_id, body, ctx, service, session, "archive")


@router.post(
    "/sources/{source_id}/sync",
    response_model=ThreatSourceRead,
    status_code=202,
    responses=_SOURCE_ERRORS,
)
def request_sync(
    source_id: int, ctx: Manager, service: Service, session: DbSession
) -> ThreatSourceRead:
    """Pide una sincronización; la hace el job (la petición nunca descarga nada)."""

    def run() -> ThreatSourceRead:
        source = service.request_sync(source_id, actor(ctx))
        audit_service.record(
            session,
            actor(ctx),
            "threat_sync_requested",
            target_type=SOURCE_TARGET,
            target_id=source.source_key,
            commit=False,
        )
        session.commit()
        return service.source_read(source)

    return _failed(session, ctx, "threat_sync_requested", SOURCE_TARGET, str(source_id), run)


@router.get(
    "/sources/{source_id}/syncs", response_model=ThreatSyncList, responses=error_responses(404)
)
def source_syncs(
    source_id: int,
    _: Reader,
    service: Service,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> ThreatSyncList:
    return service.syncs(source_id, limit, offset)


# --- Indicadores -------------------------------------------------------------------------------


@router.get("/indicators", response_model=IndicatorList)
def list_indicators(
    _: Reader,
    service: Service,
    type: IndicatorType | None = None,
    classification: Classification | None = None,
    confidence: Confidence | None = None,
    source_id: Annotated[int | None, Query(ge=1)] = None,
    state: Literal["active", "revoked", "expired", "not_yet_valid"] | None = None,
    matched: bool | None = None,
    tag: Annotated[str | None, Query(max_length=64, pattern=r"^[^\x00-\x1f\x7f]+$")] = None,
    # Prefijo del valor normalizado (índice): "203.0.113." o "evil.".
    q: Annotated[str | None, text_query(200)] = None,
    sort: IndicatorSort = "retrieved_at",
    order: Literal["asc", "desc"] = "desc",
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
) -> IndicatorList:
    f = IndicatorFilter(
        indicator_type=type,
        classification=classification,
        confidence=confidence,
        source_id=source_id,
        state=state,
        matched=matched,
        tag=tag,
        search=q.strip() if q and q.strip() else None,
    )
    return service.indicators(f, sort, order == "desc", limit, offset)


@router.get(
    "/indicators/{indicator_id}", response_model=IndicatorDetail, responses=error_responses(404)
)
def get_indicator(indicator_id: UUID, _: Reader, service: Service) -> IndicatorDetail:
    return service.indicator(indicator_id)


@router.post("/reevaluate", response_model=ReevaluateResult)
def reevaluate(ctx: Manager, service: Service, session: DbSession) -> ReevaluateResult:
    """Vuelve a buscar todos los IOCs activos en los datos locales (lo hace el job)."""
    queued = service.reevaluate()
    audit_service.record(
        session,
        actor(ctx),
        "threat_intel_reevaluation_requested",
        target_type=SOURCE_TARGET,
        details={"indicators": queued},
        commit=False,
    )
    session.commit()
    return ReevaluateResult(indicators_queued=queued)


# --- Matches -----------------------------------------------------------------------------------


@router.get("/matches", response_model=MatchList)
def list_matches(
    _: Reader,
    service: Service,
    session: DbSession,
    status: MatchStatus | None = None,
    # Sin status: solo los no descartados.
    active: bool = False,
    classification: Classification | None = None,
    observation_type: ObservationType | None = None,
    asset_id: UUID | None = None,
    source_id: Annotated[int | None, Query(ge=1)] = None,
    sort: MatchSort = "last_observed_at",
    order: Literal["asc", "desc"] = "desc",
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> MatchList:
    internal = None
    if asset_id is not None:
        internal = session.scalar(select(Asset.id).where(Asset.public_id == asset_id))
        if internal is None:
            return MatchList(items=[], total=0)
    f = MatchFilter(
        status=status,
        active=active,
        classification=classification,
        observation_type=observation_type,
        asset_id=internal,
        source_id=source_id,
    )
    return service.matches(f, sort, order == "desc", limit, offset)


@router.get("/matches/{match_id}", response_model=MatchDetail, responses=error_responses(404))
def get_match(match_id: UUID, ctx: Reader, service: Service) -> MatchDetail:
    return service.match(match_id, can_triage=ctx.has(Permission.THREAT_INTEL_TRIAGE))


def _act(
    match_id: UUID,
    action: str,
    ctx: AuthContext,
    service: ThreatIntelService,
    session: DbSession,
    version: int,
    reason: str | None,
) -> MatchDetail:
    def run() -> MatchDetail:
        match = service.apply_action(match_id, action, version, reason, actor(ctx))
        details: dict[str, object] = {"action": action, "to": match.status}
        if reason:
            details["reason"] = reason[:200]
        audit_service.record(
            session,
            actor(ctx),
            "threat_intel_match_updated",
            target_type=MATCH_TARGET,
            target_id=match.public_id,
            details=details,
            commit=False,
        )
        session.commit()
        return service.match(match_id, can_triage=True)

    return _failed(session, ctx, "threat_intel_match_updated", MATCH_TARGET, str(match_id), run)


_MATCH_ERRORS = error_responses(404, 409)


@router.post("/matches/{match_id}/acknowledge", response_model=MatchDetail, responses=_MATCH_ERRORS)
def acknowledge_match(
    match_id: UUID, body: MatchAction, ctx: Triage, service: Service, session: DbSession
) -> MatchDetail:
    return _act(match_id, "acknowledge", ctx, service, session, body.version, body.reason)


@router.post("/matches/{match_id}/dismiss", response_model=MatchDetail, responses=_MATCH_ERRORS)
def dismiss_match(
    match_id: UUID, body: MatchDecision, ctx: Triage, service: Service, session: DbSession
) -> MatchDetail:
    """Falso positivo (IP compartida, CDN, indicador viejo): deja de aportar riesgo."""
    return _act(match_id, "dismiss", ctx, service, session, body.version, body.reason)


@router.post("/matches/{match_id}/reopen", response_model=MatchDetail, responses=_MATCH_ERRORS)
def reopen_match(
    match_id: UUID, body: MatchDecision, ctx: Triage, service: Service, session: DbSession
) -> MatchDetail:
    return _act(match_id, "reopen", ctx, service, session, body.version, body.reason)


@router.post(
    "/matches/{match_id}/incident",
    response_model=IncidentDetail,
    status_code=201,
    responses=_MATCH_ERRORS,
)
def incident_from_match(
    match_id: UUID, body: MatchIncidentIn, ctx: Triage, service: Service, session: DbSession
) -> IncidentDetail:
    """Abre un incidente (4K) desde el match. Nunca automático: lo decide un analista."""
    if not ctx.has(Permission.INCIDENTS_MANAGE):
        raise PermissionDeniedError("Creating incidents requires incidents:manage")

    def run() -> IncidentDetail:
        match = service.match_row(match_id, lock=True)
        if match.version != body.version:
            raise ThreatIntelConflictError(
                "The match changed; reload it", details=[{"version": match.version}]
            )
        operator = Operator.from_context(ctx.user, ctx.client_ip, ctx.permissions)
        incident = IncidentService(session, operator).promote_threat_match(
            match_id,
            IncidentPromote(
                title=body.title,
                description=body.description,
                priority=IncidentLevel(body.priority) if body.priority else None,
            ),
        )
        audit_service.record(
            session,
            actor(ctx),
            "threat_intel_incident_created",
            target_type=MATCH_TARGET,
            target_id=match.public_id,
            details={"incident": str(incident.public_id)},
            commit=False,
        )
        session.commit()
        return detail(session, incident)

    return _failed(session, ctx, "threat_intel_incident_created", MATCH_TARGET, str(match_id), run)


# --- Importación (admin) -----------------------------------------------------------------------


def _syncer(session: DbSession, config: ThreatIntelConfig) -> ThreatIntelSyncer:
    return ThreatIntelSyncer(session, config)


@router.post(
    "/import/preview", response_model=ThreatImportPreview, responses=error_responses(404, 422)
)
def import_preview(
    body: ThreatImportIn, ctx: Manager, session: DbSession, config: Config
) -> ThreatImportPreview:
    """Valida y cuenta (nuevos, cambiados, iguales, inválidos, no soportados). No guarda."""

    def run() -> ThreatImportPreview:
        preview = _syncer(session, config).preview_import(
            body.source_id, body.format, body.content.encode("utf-8")
        )
        return ThreatImportPreview(
            source_key=preview.source_key,
            format=preview.format,
            sha256=preview.sha256,
            size_bytes=preview.size_bytes,
            source_version=preview.source_version,
            total=preview.total,
            valid=preview.valid,
            new=preview.new,
            updated=preview.updated,
            unchanged=preview.unchanged,
            invalid=preview.invalid,
            invalid_records=[
                ThreatInvalidRecord(
                    index=r.index, reference=r.reference, code=r.code, message=r.message
                )
                for r in preview.invalid_records
            ],
            unsupported=preview.unsupported,
            by_type=preview.by_type,
            not_matchable=preview.not_matchable,
        )

    return _failed(session, ctx, "threat_import_previewed", SOURCE_TARGET, str(body.source_id), run)


@router.post("/import", response_model=ThreatImportResult, responses=error_responses(404, 409, 422))
def import_indicators(
    body: ThreatImportConfirm, ctx: Manager, session: DbSession, config: Config
) -> ThreatImportResult:
    """Importa el fichero previsualizado (mismo sha256) en una transacción (todo o nada)."""

    def run() -> ThreatImportResult:
        result = _syncer(session, config).import_indicators(
            body.source_id,
            body.format,
            body.content.encode("utf-8"),
            actor(ctx),
            expected_sha256=body.expected_sha256,
            skip_invalid=body.skip_invalid,
            trigger="api",
        )
        session.commit()
        return ThreatImportResult(
            source_key=result.source_key,
            sha256=result.sha256,
            new=result.new,
            updated=result.updated,
            unchanged=result.unchanged,
            invalid=result.invalid,
            pending_match=result.pending_match,
        )

    return _failed(session, ctx, "threat_imported", SOURCE_TARGET, str(body.source_id), run)
