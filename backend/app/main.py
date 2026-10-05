import logging
import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app import __version__
from app.api.v1.router import api_router
from app.core.body_limit import BodySizeLimitMiddleware
from app.core.config import get_settings
from app.core.exceptions import register_exception_handlers
from app.core.logging import configure_logging
from app.core.middleware import request_logging_middleware
from app.core.rate_limit import RateLimiter
from app.db.migrations import expected_heads, is_up_to_date
from app.db.session import get_engine, get_sessionmaker
from app.services.auth_service import LoginGuard
from app.services.background import (
    PeriodicJob,
    discovery_job,
    purge_old_data,
    sweep_offline_assets,
)
from app.services.discovery_runner import stop_discovery_runner
from app.services.retention_service import RetentionPolicy

logger = logging.getLogger(__name__)

DISCOVERY_FIRST_RUN_SECONDS = 60


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
    for job in jobs:
        job.stop()
    # Antes de cerrar el pool: el scan en curso del dashboard se cancela (resultado parcial,
    # sin inferencias negativas) y los jobs en cola se cierran, sin dejar huérfanos.
    stop_discovery_runner()
    get_engine().dispose()


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)

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
            allow_methods=["GET", "POST", "PATCH"],
            # X-CSRF-Token: token anti-CSRF de las peticiones mutables (api/auth.py).
            allow_headers=["Content-Type", "X-Request-ID", "X-CSRF-Token"],
        )
    if settings.allowed_host_list:
        # Rechaza cabeceras Host desconocidas (DNS rebinding, enlaces generados con un Host
        # falso). Opcional para no romper el acceso por IP en la LAN de desarrollo.
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_host_list)
    app.middleware("http")(request_logging_middleware)
    # Added last so it runs first: oversized bodies are refused before any other work.
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_bytes)
    register_exception_handlers(app)
    # Límites en memoria, uno por aplicación (core/rate_limit.py).
    app.state.login_guard = LoginGuard(settings)
    app.state.register_limiter = RateLimiter(settings.agent_register_max_per_minute, 60)
    app.include_router(api_router)
    return app


app = create_app()
