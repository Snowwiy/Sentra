from collections.abc import Iterator
from functools import lru_cache

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings


def build_engine(url: str) -> Engine:
    return create_engine(
        url,
        pool_pre_ping=True,
        connect_args={
            # Force UTC on every connection so timestamps are never shifted by the server timezone.
            "options": "-c timezone=utc",
            # Fail fast when PostgreSQL is down so /health answers 503 instead of hanging
            # and requests do not pile up waiting on the OS TCP timeout.
            "connect_timeout": 5,
        },
    )


@lru_cache
def get_engine() -> Engine:
    return build_engine(get_settings().database_url)


@lru_cache
def get_sessionmaker() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), expire_on_commit=False)


def get_db() -> Iterator[Session]:
    with get_sessionmaker()() as session:
        yield session
