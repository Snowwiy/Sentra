import logging

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app import __version__
from app.db.migrations import is_up_to_date
from app.schemas.health import CheckStatus, HealthRead

logger = logging.getLogger(__name__)


class HealthService:
    def __init__(self, session: Session) -> None:
        self._session = session

    def check(self) -> HealthRead:
        database = self._check_database()
        checks: dict[str, CheckStatus] = {
            "api": "ok",
            "database": database,
            # Only meaningful once the database answers.
            "migrations": self._check_migrations() if database == "ok" else "error",
        }
        healthy = all(value == "ok" for value in checks.values())
        return HealthRead(
            status="ok" if healthy else "degraded", version=__version__, checks=checks
        )

    def _check_database(self) -> CheckStatus:
        try:
            self._session.execute(text("SELECT 1"))
        except SQLAlchemyError:
            logger.warning("Database health check failed", exc_info=True)
            return "error"
        return "ok"

    def _check_migrations(self) -> CheckStatus:
        try:
            if is_up_to_date(self._session):
                return "ok"
        except SQLAlchemyError:
            logger.warning("Migration health check failed", exc_info=True)
            return "error"
        logger.error("Database schema is not at the expected migration; run alembic upgrade head")
        return "error"
