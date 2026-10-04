"""Compare the database schema version with the code's Alembic head.

Running new code against an un-migrated database makes every query on a new column fail with
a 500. Detecting it lets /health report the real problem and the startup log say what to run.
"""

from functools import lru_cache
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.orm import Session

BACKEND_DIR = Path(__file__).resolve().parents[2]


@lru_cache
def expected_heads() -> frozenset[str]:
    # Read from the migration scripts shipped with this code, once per process.
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    return frozenset(ScriptDirectory.from_config(config).get_heads())


def current_revisions(session: Session) -> frozenset[str]:
    try:
        rows = session.execute(text("SELECT version_num FROM alembic_version"))
    except ProgrammingError:
        # Table missing: the database was never migrated. Roll back so the failed statement
        # does not poison the rest of the session's transaction.
        session.rollback()
        return frozenset()
    return frozenset(row[0] for row in rows)


def is_up_to_date(session: Session) -> bool:
    return current_revisions(session) == expected_heads()
