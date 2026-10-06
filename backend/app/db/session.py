from collections.abc import Iterator
from functools import lru_cache

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings, get_settings


def build_engine(
    url: str,
    *,
    pool_size: int = 5,
    max_overflow: int = 10,
    pool_timeout: float = 30,
    pool_recycle: int = -1,
    connect_timeout: int = 5,
    statement_timeout_seconds: int | None = None,
) -> Engine:
    # Force UTC on every connection so timestamps are never shifted by the server timezone.
    options = "-c timezone=utc"
    if statement_timeout_seconds:
        # Fase 4M: una consulta colgada no retiene una conexión del pool para siempre. Solo
        # en el engine de la API y sus jobs; Alembic llama sin este valor (migraciones largas).
        options += f" -c statement_timeout={statement_timeout_seconds * 1000}"
    return create_engine(
        url,
        pool_pre_ping=True,
        # Pool acotado (Fase 4M): nunca conexiones ilimitadas; agotado, la petición espera
        # pool_timeout y recibe 503 reintentable (core/exceptions.py).
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_timeout=pool_timeout,
        pool_recycle=pool_recycle,
        connect_args={
            "options": options,
            # Fail fast when PostgreSQL is down so /health answers 503 instead of hanging
            # and requests do not pile up waiting on the OS TCP timeout.
            "connect_timeout": connect_timeout,
            # Identifica las conexiones de Sentra en pg_stat_activity.
            "application_name": "sentra-api",
        },
    )


def engine_from_settings(settings: Settings) -> Engine:
    return build_engine(
        settings.database_url,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        pool_timeout=settings.db_pool_timeout_seconds,
        pool_recycle=settings.db_pool_recycle_seconds or -1,
        connect_timeout=settings.db_connect_timeout_seconds,
        statement_timeout_seconds=settings.db_statement_timeout_seconds,
    )


@lru_cache
def get_engine() -> Engine:
    return engine_from_settings(get_settings())


@lru_cache
def get_sessionmaker() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), expire_on_commit=False)


def get_db() -> Iterator[Session]:
    with get_sessionmaker()() as session:
        yield session
