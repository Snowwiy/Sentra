import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.v1.router import api_router
from app.core.body_limit import BodySizeLimitMiddleware
from app.core.config import get_settings
from app.core.exceptions import register_exception_handlers
from app.core.logging import configure_logging
from app.core.middleware import request_logging_middleware
from app.db.migrations import expected_heads, is_up_to_date
from app.db.session import get_engine, get_sessionmaker
from app.services.background import PeriodicJob, sweep_offline_assets

logger = logging.getLogger(__name__)


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
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    _log_schema_state()
    jobs: list[PeriodicJob] = []
    if settings.background_jobs_enabled:
        jobs.append(
            PeriodicJob(
                "offline-sweeper", settings.offline_sweep_interval_seconds, sweep_offline_assets
            )
        )
    for job in jobs:
        job.start()
    yield
    for job in jobs:
        job.stop()
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
            # Only what the API actually uses; widen deliberately when new verbs appear.
            allow_methods=["GET", "POST"],
            allow_headers=["Content-Type", "X-Request-ID"],
        )
    app.middleware("http")(request_logging_middleware)
    # Added last so it runs first: oversized bodies are refused before any other work.
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_bytes)
    register_exception_handlers(app)
    app.include_router(api_router)
    return app


app = create_app()
