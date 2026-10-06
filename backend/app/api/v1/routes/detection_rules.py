"""Reglas de detección (Fase 5A): catálogo, CRUD versionado, pruebas e importación Sigma.

Permisos (comprobados en el backend en cada petición):
- rules:read (todos los roles): listado, detalle, versiones, diff, exportación;
- rules:test (analyst, admin): validar, prueba sintética y vista previa Sigma, sin efectos;
- rules:manage (admin): crear, editar, activar, retirar, restaurar, importar Sigma y la
  prueba histórica (lee datos reales; además lleva su propio límite por usuario).

Todo cambio y todo intento fallido de cambio queda en audit_events con target
"detection_rule". El contenido de las reglas es NO confiable: nunca se ejecuta.
"""

from collections.abc import Callable
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Path, Query, Request, status

from app.api.auth import actor, require_permission
from app.api.deps import AppSettings, DbSession, get_detection_config
from app.api.params import text_query
from app.api.responses import error_responses
from app.core.exceptions import RateLimitedError, SentraError
from app.core.permissions import Permission
from app.core.rate_limit import Limiter
from app.detection.config import DetectionConfig
from app.models.detection import DetectionSeverity
from app.schemas.audit import AuditEventList
from app.schemas.detection_rule import (
    RULE_UID_PATTERN,
    CompileStatusName,
    DetectionRuleList,
    HistoricalTestIn,
    HistoricalTestResult,
    RuleCatalog,
    RuleCreate,
    RuleDetail,
    RuleDiff,
    RuleSourceName,
    RuleStateChange,
    RuleStatusName,
    RuleTestIn,
    RuleTestResult,
    RuleUpdate,
    RuleValidateIn,
    RuleValidation,
    RuleVersionDetail,
    RuleVersionList,
    SigmaImportIn,
    SigmaImportResult,
    SigmaIn,
    SigmaPreview,
    SigmaSource,
    SortField,
)
from app.services import audit_service
from app.services.auth_service import AuthContext
from app.services.detection_rule_service import TARGET, DetectionRuleService, RuleFilter

router = APIRouter(tags=["detection-rules"])

Reader = Annotated[AuthContext, Depends(require_permission(Permission.RULES_READ))]
Tester = Annotated[AuthContext, Depends(require_permission(Permission.RULES_TEST))]
Manager = Annotated[AuthContext, Depends(require_permission(Permission.RULES_MANAGE))]
AuditReader = Annotated[AuthContext, Depends(require_permission(Permission.AUDIT_READ))]
# Validado en la ruta: nada que no sea un identificador de regla llega al servicio ni a logs.
RuleId = Annotated[str, Path(max_length=32, pattern=RULE_UID_PATTERN)]
VersionNumber = Annotated[int, Path(ge=1, le=100_000)]


def get_rule_service(
    session: DbSession,
    settings: AppSettings,
    config: Annotated[DetectionConfig, Depends(get_detection_config)],
) -> DetectionRuleService:
    return DetectionRuleService(session, settings, config)


Service = Annotated[DetectionRuleService, Depends(get_rule_service)]


def _audited[T](
    session: DbSession,
    ctx: AuthContext,
    action: str,
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
            TARGET,
            target,
            details={"error": exc.code},
        )
        raise


# --- Lectura -----------------------------------------------------------------------------------


@router.get("/detection-rules", response_model=DetectionRuleList)
def list_detection_rules(
    _: Reader,
    service: Service,
    source: RuleSourceName | None = None,
    rule_status: Annotated[RuleStatusName | None, Query(alias="status")] = None,
    enabled: bool | None = None,
    compile_status: CompileStatusName | None = None,
    severity: DetectionSeverity | None = None,
    logsource: Annotated[str | None, Query(max_length=32, pattern=r"^[a-z_]+$")] = None,
    mitre: Annotated[str | None, Query(max_length=16, pattern=r"^[A-Za-z0-9.]+$")] = None,
    q: Annotated[str | None, text_query(200)] = None,
    sort: SortField = "title",
    order: Literal["asc", "desc"] = "asc",
    # Sin paginar devuelve todo: la UI de 4H (filtro por regla) lo usa así.
    limit: Annotated[int, Query(ge=1, le=1000)] = 1000,
    offset: Annotated[int, Query(ge=0, le=10_000)] = 0,
) -> DetectionRuleList:
    """Catálogo unificado: built-in (código), custom y Sigma (base de datos)."""
    return service.list_rules(
        RuleFilter(
            source=source,
            status=rule_status,
            enabled=enabled,
            compile_status=compile_status,
            severity=severity,
            logsource=logsource,
            mitre=mitre,
            search=q.strip() if q and q.strip() else None,
            sort=sort,
            descending=order == "desc",
        ),
        limit,
        offset,
    )


@router.get("/detection-rules/catalog", response_model=RuleCatalog)
def rule_catalog(_: Reader, service: Service) -> RuleCatalog:
    """Logsources, campos, operadores y límites que acepta el editor (y el compilador)."""
    return service.catalog()


@router.get("/detection-rules/{rule_id}", response_model=RuleDetail, responses=error_responses(404))
def get_detection_rule(rule_id: RuleId, _: Reader, service: Service) -> RuleDetail:
    return service.get(rule_id)


@router.get(
    "/detection-rules/{rule_id}/versions",
    response_model=RuleVersionList,
    responses=error_responses(404),
)
def list_rule_versions(rule_id: RuleId, _: Reader, service: Service) -> RuleVersionList:
    return service.versions(rule_id)


@router.get(
    "/detection-rules/{rule_id}/versions/{version}",
    response_model=RuleVersionDetail,
    responses=error_responses(404),
)
def get_rule_version(
    rule_id: RuleId, version: VersionNumber, _: Reader, service: Service
) -> RuleVersionDetail:
    return service.version(rule_id, version)


@router.get(
    "/detection-rules/{rule_id}/diff", response_model=RuleDiff, responses=error_responses(404)
)
def diff_rule_versions(
    rule_id: RuleId,
    _: Reader,
    service: Service,
    from_version: Annotated[int, Query(alias="from", ge=1, le=100_000)],
    to_version: Annotated[int, Query(alias="to", ge=1, le=100_000)],
) -> RuleDiff:
    return service.diff(rule_id, from_version, to_version)


@router.get("/detection-rules/{rule_id}/export", responses=error_responses(404))
def export_rule(rule_id: RuleId, _: Reader, service: Service) -> dict[str, Any]:
    """Definición declarativa de la versión vigente (JSON sentra-rule-export/1)."""
    return service.export(rule_id)


@router.get(
    "/detection-rules/{rule_id}/sigma-source",
    response_model=SigmaSource,
    responses=error_responses(404),
)
def rule_sigma_source(rule_id: RuleId, _: Reader, service: Service) -> SigmaSource:
    """YAML Sigma original de la versión vigente (la UI lo muestra como texto, nunca HTML)."""
    return SigmaSource(rule_id=rule_id, yaml=service.sigma_source(rule_id))


@router.get(
    "/detection-rules/{rule_id}/audit",
    response_model=AuditEventList,
    responses=error_responses(404),
)
def rule_audit(
    rule_id: RuleId,
    _: AuditReader,
    service: Service,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=10_000)] = 0,
) -> AuditEventList:
    return service.audit(rule_id, limit, offset)


# --- Validación y pruebas sin efectos ----------------------------------------------------------


@router.post("/detection-rules/validate", response_model=RuleValidation)
def validate_rule(body: RuleValidateIn, _: Tester, service: Service) -> RuleValidation:
    """Compila una definición sin guardarla: errores, avisos y complejidad."""
    return service.validate(body)


@router.post(
    "/detection-rules/test", response_model=RuleTestResult, responses=error_responses(404, 409)
)
def test_rule(
    body: RuleTestIn, ctx: Tester, service: Service, session: DbSession
) -> RuleTestResult:
    """Prueba con eventos sintéticos, en memoria: no crea detecciones ni alertas."""
    result = _audited(
        session, ctx, "rule_tested", body.rule_id, lambda: service.test_synthetic(body)
    )
    audit_service.record(
        session,
        actor(ctx),
        "rule_tested",
        target_type=TARGET,
        target_id=body.rule_id,
        details={"mode": "synthetic", "events": len(body.events), "matched": result.matched},
    )
    return result


def _limit_historical(request: Request, ctx: Manager) -> AuthContext:
    limiter: Limiter = request.app.state.rule_test_limiter
    wait = limiter.acquire(f"user:{ctx.user.id}")
    if wait > 0:
        raise RateLimitedError("Too many historical rule tests, retry later", wait, "rule_test")
    return ctx


@router.post(
    "/detection-rules/test/historical",
    response_model=HistoricalTestResult,
    responses=error_responses(401, 403, 404, 409, 429),
)
def test_rule_historical(
    body: HistoricalTestIn,
    ctx: Annotated[AuthContext, Depends(_limit_historical)],
    service: Service,
    session: DbSession,
) -> HistoricalTestResult:
    """Ejecuta la regla sobre datos reales recientes en una transacción de solo lectura.

    Acotado en rango, filas y tiempo; una sola prueba a la vez en todo el despliegue. No crea
    detecciones, alertas, incidentes ni recalcula riesgo, y nunca usa la IA.
    """
    result = _audited(
        session, ctx, "rule_tested", body.rule_id, lambda: service.test_historical(body)
    )
    audit_service.record(
        session,
        actor(ctx),
        "rule_tested",
        target_type=TARGET,
        target_id=body.rule_id,
        details={
            "mode": "historical",
            "since": result.since.isoformat(),
            "until": result.until.isoformat(),
            "scanned": result.scanned,
            "matched": result.matched,
            "truncated": result.truncated,
        },
    )
    return result


# --- Cambios (rules:manage) --------------------------------------------------------------------


@router.post(
    "/detection-rules",
    response_model=RuleDetail,
    status_code=status.HTTP_201_CREATED,
    responses=error_responses(401, 403),
)
def create_rule(body: RuleCreate, ctx: Manager, service: Service, session: DbSession) -> RuleDetail:
    """Crea una regla personalizada en borrador (versión 1). Activarla es otra acción."""
    return _audited(session, ctx, "rule_created", None, lambda: service.create(body, actor(ctx)))


@router.patch(
    "/detection-rules/{rule_id}",
    response_model=RuleDetail,
    responses=error_responses(401, 403, 404, 409),
)
def update_rule(
    rule_id: RuleId, body: RuleUpdate, ctx: Manager, service: Service, session: DbSession
) -> RuleDetail:
    """Un cambio de contenido crea una versión nueva; sin cambios reales no crea ninguna."""
    uid = rule_id
    return _audited(
        session, ctx, "rule_updated", uid, lambda: service.update(uid, body, actor(ctx))
    )


def _state_route(action: str, audit_action: str) -> Callable[..., RuleDetail]:
    def handler(
        rule_id: RuleId, body: RuleStateChange, ctx: Manager, service: Service, session: DbSession
    ) -> RuleDetail:
        uid = rule_id
        return _audited(
            session,
            ctx,
            audit_action,
            uid,
            lambda: service.set_state(
                uid, action, body.revision, body.acknowledge_partial, actor(ctx)
            ),
        )

    handler.__name__ = f"{action}_rule"
    handler.__doc__ = {
        "enable": "Activa la regla (solo si compila y es soportada; partial exige confirmar).",
        "disable": "Desactiva la regla; deja de evaluarse en el siguiente lote.",
        "retire": "Retira la regla: no se borra, conserva versiones y detecciones.",
        "unretire": "Recupera una regla retirada (queda desactivada).",
    }[action]
    return handler


for _action, _audit in (
    ("enable", "rule_enabled"),
    ("disable", "rule_disabled"),
    ("retire", "rule_retired"),
    ("unretire", "rule_unretired"),
):
    router.post(
        f"/detection-rules/{{rule_id}}/{_action}",
        response_model=RuleDetail,
        responses=error_responses(401, 403, 404, 409),
    )(_state_route(_action, _audit))


@router.post(
    "/detection-rules/{rule_id}/versions/{version}/restore",
    response_model=RuleDetail,
    responses=error_responses(401, 403, 404, 409),
)
def restore_rule_version(
    rule_id: RuleId,
    version: VersionNumber,
    body: RuleStateChange,
    ctx: Manager,
    service: Service,
    session: DbSession,
) -> RuleDetail:
    """Crea una versión nueva con el contenido de `version` (la historia no se reescribe)."""
    uid = rule_id
    return _audited(
        session,
        ctx,
        "rule_version_created",
        uid,
        lambda: service.restore(uid, version, body.revision, actor(ctx)),
    )


# --- Sigma -------------------------------------------------------------------------------------


@router.post("/sigma/preview", response_model=SigmaPreview)
def sigma_preview(body: SigmaIn, _: Tester, service: Service) -> SigmaPreview:
    """Analiza un YAML Sigma sin guardar nada: qué se soporta, qué no y por qué."""
    return service.sigma_preview(body.yaml)


@router.post(
    "/sigma/import",
    response_model=SigmaImportResult,
    responses=error_responses(401, 403, 409),
)
def sigma_import(
    body: SigmaImportIn, ctx: Manager, service: Service, session: DbSession
) -> SigmaImportResult:
    """Importa una regla Sigma. Nunca queda activa: se revisa y se activa a mano."""
    return _audited(
        session, ctx, "rule_import_failed", None, lambda: service.sigma_import(body, actor(ctx))
    )
