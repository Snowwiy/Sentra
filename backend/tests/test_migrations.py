"""Migrations and ORM models must describe the same schema.

The suite already runs every migration down and up (see conftest). These checks add the other
half: a model change without its migration (or a migration that diverges from the models)
fails here, instead of surfacing as a 500 on the first query that touches the new column.
"""

from collections.abc import Sequence
from typing import Any

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import Engine, inspect

from app.db.base import Base
from app.db.migrations import expected_heads

# Imported for its side effect: every model registers its table on Base.metadata.
import app.models  # noqa: F401  # isort: skip


def test_models_match_the_migrated_schema(engine: Engine) -> None:
    with engine.connect() as connection:
        # Same comparison options as alembic/env.py, so this equals `alembic check`.
        context = MigrationContext.configure(connection, opts={"compare_type": True})
        differences: list[Any] = compare_metadata(context, Base.metadata)

    assert differences == [], f"models and migrations differ: {differences}"


def test_every_foreign_key_is_indexed(engine: Engine) -> None:
    # PostgreSQL does not index the referencing side of a foreign key. Without an index,
    # every deleted parent row (retention purges, asset deletion) makes the ON DELETE action
    # scan the whole child table: 51 s per 5000 deleted events was measured with 100k alerts
    # before ix_alerts_source_event existed. Checked on the migrated database itself.
    inspector = inspect(engine)
    missing = []
    for table in inspector.get_table_names():
        prefixes: list[Sequence[str | None]] = [
            i["column_names"] for i in inspector.get_indexes(table)
        ]
        prefixes += [u["column_names"] for u in inspector.get_unique_constraints(table)]
        prefixes.append(inspector.get_pk_constraint(table)["constrained_columns"])
        for fk in inspector.get_foreign_keys(table):
            columns = fk["constrained_columns"]
            if not any(list(p[: len(columns)]) == columns for p in prefixes):
                missing.append(f"{table}({', '.join(columns)})")

    assert missing == [], f"foreign keys without an index: {missing}"


def test_migration_history_has_a_single_head() -> None:
    # Two heads (e.g. two branches each adding a migration) make `alembic upgrade head` fail
    # and /health report the schema as out of date forever.
    assert len(expected_heads()) == 1
