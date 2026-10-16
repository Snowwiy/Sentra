import logging
import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app import __version__
from app.ai.config import AIConfig
from app.api.auth import ApiLimits
from app.api.v1.router import api_router
from app.core.body_limit import BodySizeLimitMiddleware
from app.core.config import Settings, get_settings
from app.core.exceptions import register_exception_handlers
from app.core.logging import configure_logging
from app.core.middleware import request_logging_middleware
from app.core.production import enforce_production
from app.core.proxy import HttpsRequiredMiddleware, TrustedProxyMiddleware
from app.core.rate_limit import make_limiter
from app.db.migrations import expected_heads, is_up_to_date
from app.db.session import get_engine, get_sessionmaker
from app.services.ai_service import AIRuntime, default_provider_factory
from app.services.auth_service import LoginGuard
from app.services.background import (
    PeriodicJob,
    discovery_job,
    purge_old_data,
    run_asset_cleanup,
    run_detection_engine,
    run_network_maintenance,
    run_report_worker,
    run_response_engine,
    run_risk_engine,
    run_sensor_maintenance,
    run_threat_intel,
    run_vulnerability_engine,
    sweep_offline_assets,
)
from app.services.discovery_runner import stop_discovery_runner
from app.services.local_model_service import LocalAIState
from app.services.retention_service import RetentionPolicy

logger = logging.getLogger(__name__)

DISCOVERY_FIRST_RUN_SECONDS = 60
# Fase 6B: cada cuánto se buscan equipos con la consulta periódica vencida. El intervalo real
# de cada equipo es SNMP_POLL_INTERVAL_MINUTES; esto solo fija la granularidad.
NETWORK_MAINTENANCE_SECONDS = 60


def _log_schema_state() -> None:
    # The API still starts when the schema is behind (so /health can report it), but the
    # operator gets an explicit instruction instead of a stream of 500s.
    try:
        with get_sessionmaker()() as session:
            if not is_up_to_date(session):
                logger.error(
                    "database schema is behind the code; run: alembic upgrade head",
                    extra={"expected": sorted(expected_heads())},
                )
    except Exception:
        logger.warning("could not verify database schema at startup", exc_info=True)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    _log_schema_state()
    jobs: list[PeriodicJob] = []
    if settings.background_jobs_enabled:
        jobs.append(
            PeriodicJob(
                "offline-sweeper", settings.offline_sweep_interval_seconds, sweep_offline_assets
            )
        )
        # Fase 4H: evaluación de señales del motor de detección, fuera de las peticiones.
        if settings.detection_enabled:
            jobs.append(
                PeriodicJob(
                    "detection-engine",
                    settings.detection_eval_interval_seconds,
                    run_detection_engine,
                )
            )
        # Fase 4I: cola de recálculo y decay del Risk Engine, fuera de las peticiones.
        if settings.risk_enabled:
            jobs.append(
                PeriodicJob("risk-engine", settings.risk_eval_interval_seconds, run_risk_engine)
            )
        # Fase 5B: cola de evaluación de vulnerabilidades, refresco y caducidad de riesgos
        # aceptados, fuera de las peticiones (nunca en cada heartbeat).
        if settings.vuln_enabled:
            jobs.append(
                PeriodicJob(
                    "vulnerability-engine",
                    settings.vuln_eval_interval_seconds,
                    run_vulnerability_engine,
                )
            )
        # Fase 5C: sincronización (solo con THREAT_INTEL_SYNC_ENABLED) y matching de IOCs.
        if settings.threat_intel_enabled:
            jobs.append(
                PeriodicJob(
                    "threat-intel", settings.threat_intel_eval_interval_seconds, run_threat_intel
                )
            )
        # Fase 5C.2: limpieza automática de descubiertos elegibles. Opt-in explícito.
        if settings.asset_auto_cleanup:
            jobs.append(
                PeriodicJob(
                    "asset-cleanup",
                    settings.asset_cleanup_interval_minutes * 60,
                    run_asset_cleanup,
                )
            )
        # Fase 5D: TTL de comandos, plazos y avance de playbooks (nunca ejecuta nada nuevo).
        if settings.response_enabled:
            jobs.append(
                PeriodicJob(
                    "response-engine",
                    settings.response_sweep_interval_seconds,
                    run_response_engine,
                )
            )
        # Fase 5E: cola de informes. La petición HTTP solo crea el trabajo; aquí se genera.
        if settings.report_enabled:
            jobs.append(
                PeriodicJob(
                    "report-worker",
                    settings.report_worker_interval_seconds,
                    run_report_worker,
                )
            )
        # Fase 5F: plazos y leases de los jobs de sensor (sin sensores no hay nada que hacer;
        # el poll de cada sensor también lo aplica de forma perezosa).
        jobs.append(
            PeriodicJob(
                "sensor-maintenance",
                settings.sensor_sweep_interval_seconds,
                run_sensor_maintenance,
            )
        )
        # Fase 6B: solo si hay consultas periódicas o retención del historial de red (opt-in).
        if settings.snmp_poll_interval_minutes or settings.snmp_history_retention_days:
            jobs.append(
                PeriodicJob(
                    "network-maintenance", NETWORK_MAINTENANCE_SECONDS, run_network_maintenance
                )
            )
        # Only when a retention period is configured: by default nothing is ever deleted.
        if RetentionPolicy.from_settings(settings).enabled:
            jobs.append(
                PeriodicJob("retention", settings.retention_sweep_interval_seconds, purge_old_data)
            )
        # Only with an allowlist and an interval: by default nothing is ever probed.
        if settings.discovery_interval_minutes and settings.discovery_scope().enabled:
            stop = threading.Event()
            schedule = PeriodicJob(
                "discovery",
                settings.discovery_interval_minutes * 60,
                discovery_job(stop),
                stop=stop,
                # A fresh install shows the network soon, not one interval later.
                first_run_after=DISCOVERY_FIRST_RUN_SECONDS,
            )
            # Para GET /discovery/schedule (próxima ejecución, en curso).
            app.state.discovery_schedule = schedule
            jobs.append(schedule)
    for job in jobs:
        job.start()
    yield
    # Fase 4M, apagado ordenado: primero /health/ready deja de estar listo (el proxy deja
    # de enviar tráfico nuevo), luego se paran los jobs (ninguno empieza una vuelta nueva y
    # los largos se interrumpen), después el discovery y la IA, y al final el pool.
    app.state.draining = True
    logger.info("shutting down", extra={"jobs": [job.name for job in jobs]})
    for job in jobs:
        job.stop()
    # Antes de cerrar el pool: el scan en curso del dashboard se cancela (resultado parcial,
    # sin inferencias negativas) y los jobs en cola se cierran, sin dejar huérfanos.
    stop_discovery_runner()
    # Fase 4J.2: sin esperar a un SHA-256 de GB en curso; el benchmark es un hilo daemon
    # acotado por su plazo y el registro "running" se cierra como interrumpido al volver.
    app.state.ai_local.shutdown()
    get_engine().dispose()


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(
        settings.log_level,
        settings.log_format,
        settings.log_file,
        settings.log_file_max_mb,
        settings.log_file_backups,
    )
    # Fase 4M: en producción, una configuración insegura impide arrancar (sin secretos en
    # el mensaje). Ver core/production.py y `python -m app.cli production-check`.
    enforce_production(settings)

    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        lifespan=lifespan,
        # Interactive docs are a development aid only.
        docs_url=None if settings.is_production else "/docs",
        redoc_url=None,
        openapi_url=None if settings.is_production else "/openapi.json",
    )

    if settings.cors_origin_list:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origin_list,
            # Cookie de sesión en peticiones de otro origen configurado (dashboard servido
            # aparte). Seguro solo porque la lista es explícita: nunca "*" (lo impide el
            # validador de CORS_ORIGINS).
            allow_credentials=True,
            # Only what the API actually uses; widen deliberately when new verbs appear.
            # Fase 5C.1: DELETE para el borrado de activos descubiertos sin historial.
            allow_methods=["GET", "POST", "PATCH", "DELETE"],
            # X-CSRF-Token: token anti-CSRF de las peticiones mutables (api/auth.py).
            allow_headers=["Content-Type", "X-Request-ID", "X-CSRF-Token"],
            # Fase 5E: la UI verifica el SHA-256 de la descarga con esta cabecera.
            expose_headers=["X-Sentra-SHA256"],
        )
    if settings.allowed_host_list:
        # Rechaza cabeceras Host desconocidas (DNS rebinding, enlaces generados con un Host
        # falso). Opcional para no romper el acceso por IP en la LAN de desarrollo.
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_host_list)
    app.middleware("http")(request_logging_middleware)
    if settings.is_production:
        # Después del proxy de confianza (que fija el esquema real) y antes que todo lo demás.
        app.add_middleware(HttpsRequiredMiddleware)
    # Oversized bodies are refused before any other work.
    # Fase 5F: el protocolo de sensores tiene su propio tope (SENSOR_MAX_REQUEST_KB).
    app.add_middleware(
        BodySizeLimitMiddleware,
        max_bytes=settings.max_request_bytes,
        prefix_limits=(("/api/v1/sensor/", settings.sensor_max_request_kb * 1024),),
    )
    # Added last so it runs first (Fase 4M): IP del cliente y esquema reales solo desde
    # TRUSTED_PROXIES; el resto de capas (logs, rate limiting, CSRF, HTTPS) ya los ven.
    app.add_middleware(TrustedProxyMiddleware, networks=settings.trusted_proxy_networks)
    register_exception_handlers(app)
    app.state.draining = False
    # Límites por aplicación: en memoria o en PostgreSQL según RATE_LIMIT_BACKEND
    # (core/rate_limit.py). El engine se resuelve al usarlo, nunca al crear la app.
    backend = settings.effective_rate_limit_backend
    app.state.login_guard = LoginGuard(settings, get_engine)
    app.state.register_limiter = make_limiter(
        backend, "agent_register", settings.agent_register_max_per_minute, 60, get_engine
    )
    app.state.api_limits = ApiLimits(
        mutations=make_limiter(
            backend, "api_mutations", settings.api_mutations_per_user_per_minute, 60, get_engine
        ),
        searches=make_limiter(
            backend, "api_searches", settings.api_searches_per_user_per_minute, 60, get_engine
        ),
    )
    # Fase 5F: enrolamiento de sensores por IP; heartbeat y poll por sensor.
    app.state.sensor_enroll_limiter = make_limiter(
        backend, "sensor_enroll", settings.sensor_enroll_max_per_minute, 60, get_engine
    )
    app.state.sensor_heartbeat_limiter = make_limiter(
        backend, "sensor_heartbeat", settings.sensor_heartbeat_max_per_minute, 60, get_engine
    )
    app.state.sensor_poll_limiter = make_limiter(
        backend, "sensor_poll", settings.sensor_poll_max_per_minute, 60, get_engine
    )
    # Fase 5A: pruebas históricas de reglas por usuario (además del lock global de 1 a la vez).
    app.state.rule_test_limiter = make_limiter(
        backend, "rule_test", settings.rule_test_per_minute, 60, get_engine
    )
    # Fase 4J: límites de la IA y fábrica del proveedor (los tests inyectan uno falso).
    # Nada se conecta al proveedor al arrancar: la IA solo actúa bajo demanda.
    app.state.ai_runtime = AIRuntime(AIConfig.from_settings(settings), backend, get_engine)
    app.state.ai_provider_factory = default_provider_factory
    # Fase 4J.2: gestor de modelos locales. No detecta hardware ni contacta el runtime al
    # arrancar ni lanza benchmarks: todo ocurre al abrir la página o por acción del admin.
    app.state.ai_local = LocalAIState()
    app.include_router(api_router)
    return app


app = create_app()
