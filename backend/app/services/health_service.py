import logging

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.db.migrations import is_up_to_date
from app.schemas.health import CheckStatus, ReadinessRead

logger = logging.getLogger(__name__)


class HealthService:
    def __init__(self, session: Session) -> None:
        self._session = session

    def readiness(self, draining: bool = False) -> ReadinessRead:
        database = self._check_database()
        checks: dict[str, CheckStatus] = {
            # Durante el apagado ordenado deja de estar listo antes de cerrar conexiones, así
            # un balanceador o el reverse proxy dejan de enviar tráfico nuevo.
            "api": "error" if draining else "ok",
            "database": database,
            # Only meaningful once the database answers.
            "migrations": self._check_migrations() if database == "ok" else "error",
        }
        ready = all(value == "ok" for value in checks.values())
        return ReadinessRead(status="ready" if ready else "not_ready", checks=checks)

    def _check_database(self) -> CheckStatus:
        try:
            self._session.execute(text("SELECT 1"))
        except SQLAlchemyError:
            # Sin traza: una caída de la base repetiría la misma pila en cada sondeo.
            logger.warning("Database readiness check failed")
            return "error"
        return "ok"

    def _check_migrations(self) -> CheckStatus:
        try:
            if is_up_to_date(self._session):
                return "ok"
        except SQLAlchemyError:
            logger.warning("Migration readiness check failed")
            return "error"
        logger.error("Database schema is not at the expected migration; run alembic upgrade head")
        return "error"
