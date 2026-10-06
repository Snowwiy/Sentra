"""Rendimiento de Asset Context (Fase 4L) con datos SINTÉTICOS.

Mide, contra el PostgreSQL de DATABASE_URL (nunca producción), las lecturas de contexto con
10 000 activos por defecto: ~70 % con contexto guardado, ~30 % con etiquetas, historial de
cambios y detecciones abiertas. Para cada lectura da la mediana en ms y las sentencias SQL por
petición: deben ser constantes, no crecer con el número de activos de la página (sin N+1).

Uso (desde backend/, con el entorno del backend activo):

    $env:PYTHONPATH = "."   # (Linux: PYTHONPATH=. delante del comando)
    python ../qa/perf_asset_context.py [--assets 10000]

Crea activos "perf-ctx-…" y los borra al final (ON DELETE CASCADE se lleva contexto,
etiquetas, historial y detecciones). No toca otros datos. Úsalo en una base QA.
"""

import argparse
import statistics
import sys
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, event, func, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from app.db.session import get_engine, get_sessionmaker
from app.models.asset import Asset, AssetCriticality
from app.models.asset_context import AssetEnvironment, AssetRole, NetworkZone
from app.services.asset_context_service import AssetContextService
from app.services.asset_service import AssetFilter, AssetService

PREFIX = "perf-ctx-"


@contextmanager
def count_statements(engine: Engine) -> Iterator[list[str]]:
    statements: list[str] = []

    def before(_conn: Any, _cursor: Any, statement: str, *_args: Any) -> None:
        statements.append(statement)

    event.listen(engine, "before_cursor_execute", before)
    try:
        yield statements
    finally:
        event.remove(engine, "before_cursor_execute", before)


def timed(fn: Callable[[], Any], repeat: int = 5) -> tuple[float, Any]:
    """Mediana en milisegundos de `repeat` ejecuciones."""
    samples, result = [], None
    for _ in range(repeat):
        start = time.perf_counter()
        result = fn()
        samples.append((time.perf_counter() - start) * 1000)
    return statistics.median(samples), result


def seed(session: Session, assets: int) -> list[int]:
    now = datetime.now(UTC)
    session.execute(
        text(
            """
            INSERT INTO assets (public_id, agent_id, monitoring_method, hostname, os_name,
                primary_ip, status, first_seen_at, last_seen_at, created_at, updated_at,
                criticality)
            SELECT gen_random_uuid(), gen_random_uuid(), 'agent', :prefix || lpad(g::text, 5, '0'),
                'Windows', '10.251.' || (g / 250) || '.' || (g % 250 + 1), 'online', :now, :now,
                :now, :now,
                (ARRAY['low','medium','medium','high','critical'])[1 + g % 5]::asset_criticality
            FROM generate_series(1, :n) AS g
            """
        ),
        {"prefix": PREFIX, "now": now, "n": assets},
    )
    ids = list(
        session.scalars(
            select(Asset.id).where(Asset.hostname.like(f"{PREFIX}%")).order_by(Asset.id)
        )
    )
    # Contexto para 7 de cada 10 activos; el resto queda "unknown" sin fila.
    session.execute(
        text(
            """
            INSERT INTO asset_context (asset_id, role, environment, data_sensitivity,
                network_zone, internet_exposed, owner, department, provenance, version,
                updated_at, updated_by)
            SELECT id,
                (ARRAY['workstation','server','database','web_server','printer','unknown'])
                    [1 + n % 6]::asset_role,
                (ARRAY['production','staging','development','lab','unknown'])
                    [1 + n % 5]::asset_environment,
                (ARRAY['internal','confidential','restricted','unknown'])
                    [1 + n % 4]::asset_data_sensitivity,
                (ARRAY['user','server','dmz','management','unknown'])
                    [1 + n % 5]::asset_network_zone,
                CASE n % 3 WHEN 0 THEN true WHEN 1 THEN false ELSE NULL END,
                'owner-' || (n % 40), 'Dept ' || (n % 25), '{}'::jsonb, 1, :now, 'perf'
            FROM (SELECT id, row_number() OVER (ORDER BY id) AS n FROM assets
                  WHERE id = ANY(:ids)) AS a
            WHERE n % 10 < 7
            """
        ),
        {"ids": ids, "now": now},
    )
    session.execute(
        text(
            """
            INSERT INTO asset_tags (asset_id, tag, created_at)
            SELECT id, t, :now
            FROM (SELECT id, row_number() OVER (ORDER BY id) AS n FROM assets
                  WHERE id = ANY(:ids)) AS a
            CROSS JOIN LATERAL (VALUES ('tag-' || (n % 50)), ('pci')) AS v(t)
            WHERE n % 10 < 3
            """
        ),
        {"ids": ids, "now": now},
    )
    # Historial: 5 cambios por activo con contexto, uno de exposición.
    session.execute(
        text(
            """
            INSERT INTO asset_context_changes (asset_id, changed_at, field, old_value,
                new_value, source, actor)
            SELECT c.asset_id, :now - (k || ' hours')::interval,
                (ARRAY['role','owner','environment','internet_exposed','tags'])[k],
                'old', 'new', 'manual', 'perf'
            FROM asset_context c CROSS JOIN generate_series(1, 5) AS k
            WHERE c.asset_id = ANY(:ids)
            """
        ),
        {"ids": ids, "now": now},
    )
    # Dos detecciones abiertas por activo para el resumen de amenaza.
    session.execute(
        text(
            """
            INSERT INTO detections (public_id, asset_id, rule_id, rule_version, kind, dedup_key,
                severity, confidence, status, title, summary, occurrence_count, first_seen_at,
                last_seen_at, created_at, updated_at)
            SELECT gen_random_uuid(), (:ids)[1 + g % cardinality(:ids)], 'DEF-001', 1, 'single',
                'perf-ctx-' || g,
                (ARRAY['low','medium','high','critical'])[1 + g % 4]::detection_severity,
                'medium', 'open', 'Detección perf ' || g, 'sintética', 1,
                :since, :now, :now, :now
            FROM generate_series(0, cardinality(:ids) * 2 - 1) AS g
            """
        ),
        {"ids": ids, "now": now, "since": now - timedelta(hours=2)},
    )
    session.commit()
    for table in ("assets", "asset_context", "asset_tags", "asset_context_changes", "detections"):
        session.execute(text(f"ANALYZE {table}"))
    session.commit()
    return ids


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--assets", type=int, default=10_000)
    args = parser.parse_args()

    engine = get_engine()
    session = get_sessionmaker()()
    ids: list[int] = []
    try:
        start = time.perf_counter()
        session.execute(delete(Asset).where(Asset.hostname.like(f"{PREFIX}%")))
        session.commit()
        ids = seed(session, args.assets)
        contexts = session.scalar(
            text("SELECT count(*) FROM asset_context WHERE asset_id = ANY(:ids)"), {"ids": ids}
        )
        print(
            f"[seed] {len(ids)} assets, {contexts} contexts in {time.perf_counter() - start:.1f} s"
        )
        assets = AssetService(session, timedelta(seconds=120))
        contexts_service = AssetContextService(session)
        target = session.scalar(select(Asset.public_id).where(Asset.id == ids[len(ids) // 2]))
        if target is None:
            raise RuntimeError("no synthetic asset found")
        cases: dict[str, Callable[[], Any]] = {
            "list all (no page)": lambda: assets.list_assets(AssetFilter()),
            "list page 50": lambda: assets.list_assets(AssetFilter(), limit=50),
            "list page 100": lambda: assets.list_assets(AssetFilter(), limit=50, offset=4950),
            "list sort criticality": lambda: assets.list_assets(
                AssetFilter(), sort="criticality", limit=50
            ),
            "filter criticality": lambda: assets.list_assets(
                AssetFilter(criticality=AssetCriticality.CRITICAL), limit=50
            ),
            "filter role=server": lambda: assets.list_assets(
                AssetFilter(role=AssetRole.SERVER), limit=50
            ),
            "filter role=unknown": lambda: assets.list_assets(
                AssetFilter(role=AssetRole.UNKNOWN), limit=50
            ),
            "filter env+zone": lambda: assets.list_assets(
                AssetFilter(environment=AssetEnvironment.DEVELOPMENT, network_zone=NetworkZone.DMZ),
                limit=50,
            ),
            "filter internet=true": lambda: assets.list_assets(
                AssetFilter(internet_exposed="true"), limit=50
            ),
            "filter internet=unknown": lambda: assets.list_assets(
                AssetFilter(internet_exposed="unknown"), limit=50
            ),
            "filter department": lambda: assets.list_assets(
                AssetFilter(department="dept 7"), limit=50
            ),
            "filter tag": lambda: assets.list_assets(AssetFilter(tag="tag-2"), limit=50),
            "asset detail": lambda: assets.get_asset(target),
            "context": lambda: contexts_service.get(target),
            "context history": lambda: contexts_service.history(target, 20, 0),
            "context options": contexts_service.options,
            "threat summary": lambda: contexts_service.threat_summary(target),
        }
        for name, fn in cases.items():
            with count_statements(engine) as statements:
                ms, result = timed(fn)
            total = getattr(result, "total", "")
            print(
                f"[read] {name:<24} {ms:7.1f} ms  sql/request={len(statements) // 5}"
                + (f"  total={total}" if total != "" else "")
            )
        return 0
    finally:
        session.rollback()
        # Por prefijo y no por ids: también limpia restos de una ejecución interrumpida.
        session.execute(delete(Asset).where(Asset.hostname.like(f"{PREFIX}%")))
        session.commit()
        session.close()
        with get_sessionmaker()() as check:
            left = check.scalar(
                select(func.count()).select_from(Asset).where(Asset.hostname.like(f"{PREFIX}%"))
            )
            print(f"cleanup: {left} perf assets left")


if __name__ == "__main__":
    sys.exit(main())
