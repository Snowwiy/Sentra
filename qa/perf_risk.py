"""Rendimiento del motor de riesgo (Fase 4I) con datos SINTÉTICOS.

Mide, contra el PostgreSQL de DATABASE_URL (nunca producción):

1. Primera evaluación de todos los activos (seed + cola), en activos por segundo y sentencias
   SQL por lote: deben ser constantes por lote, no por activo (sin N+1).
2. Recálculo completo sin cambios (cola entera otra vez): no debe crear historial.
3. Pasada de decay una hora después.
4. Lecturas del dashboard con un historial grande: resumen, listado con filtros y orden,
   detalle, tendencia 24h/7d/30d y contribuciones, con sentencias SQL por petición.

Uso (desde backend/, con el entorno del backend activo):

    $env:PYTHONPATH = "."   # (Linux: PYTHONPATH=. delante del comando)
    python ../qa/perf_risk.py [--assets 1000] [--detections 20000] [--history-per-asset 200]

Crea activos "perf-risk-…" y los borra al final (ON DELETE CASCADE se lleva detecciones,
evidencias, puertos, riesgo e historial). No toca otros activos. Ejecútalo en una base QA
propia o con el job de riesgo de la API QA parado: si no, ese job puede adelantarse.
"""

import argparse
import statistics
import sys
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, event, func, select, text, update
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.session import get_engine, get_sessionmaker
from app.models.asset import Asset
from app.models.risk import AssetRisk, RiskLevel, RiskSnapshot
from app.risk.config import RiskConfig
from app.risk.engine import RiskEngine, RiskRun
from app.services.risk_service import RiskFilter, RiskService

PREFIX = "perf-risk-"


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


def seed(session: Session, assets: int, detections: int) -> list[int]:
    """Activos, detecciones (15 % activas), correlaciones con señales compartidas y puertos."""
    now = datetime.now(UTC)
    session.execute(
        text(
            """
            INSERT INTO assets (public_id, agent_id, monitoring_method, hostname, os_name,
                primary_ip, status, first_seen_at, last_seen_at, created_at, updated_at,
                device_type, criticality)
            SELECT gen_random_uuid(), gen_random_uuid(), 'agent', :prefix || lpad(g::text, 5, '0'),
                'Windows', '10.251.' || (g / 250) || '.' || (g % 250 + 1), 'online', :now, :now,
                :now, :now, (ARRAY['pc','server','laptop',NULL])[1 + g % 4],
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
    # Detecciones simples: mezcla de reglas, severidades, estados y antigüedad (hasta ~14 días).
    session.execute(
        text(
            """
            INSERT INTO detections (public_id, asset_id, rule_id, rule_version, kind, dedup_key,
                severity, confidence, status, title, summary, occurrence_count, first_seen_at,
                last_seen_at, created_at, updated_at, resolved_at)
            SELECT gen_random_uuid(), (:ids)[1 + g % cardinality(:ids)],
                (ARRAY['AUTH-001','DEF-001','NET-001','PER-001','PROC-001'])[1 + g % 5], 1,
                'single', 'perf-risk-' || g,
                (ARRAY['informational','low','medium','high','critical'])[1 + g % 5]
                    ::detection_severity,
                (ARRAY['low','medium','high'])[1 + g % 3]::detection_confidence,
                CASE WHEN g % 20 = 0 THEN 'open' WHEN g % 20 = 1 THEN 'acknowledged'
                     WHEN g % 20 = 2 THEN 'open' ELSE 'resolved' END::detection_status,
                'Detección sintética ' || g, 'Resumen sintético de riesgo', 1 + g % 7,
                :now - ((g % 20000) || ' minutes')::interval,
                :now - ((g % 20000) || ' minutes')::interval, :now, :now,
                CASE WHEN g % 20 > 2 THEN :now - ((g % 5000) || ' minutes')::interval END
            FROM generate_series(1, :total) AS g
            """
        ),
        {"ids": ids, "total": detections, "now": now},
    )
    # Correlaciones en 1 de cada 10 activos: comparten señal con un AUTH-001 activo del activo.
    session.execute(
        text(
            """
            WITH burst AS (
                INSERT INTO detections (public_id, asset_id, rule_id, rule_version, kind,
                    dedup_key, severity, confidence, status, title, summary, occurrence_count,
                    first_seen_at, last_seen_at, created_at, updated_at)
                SELECT gen_random_uuid(), a, r.rule_id, 1, r.kind, 'perf-risk-corr-' || a,
                    r.severity::detection_severity, 'high', 'open', r.rule_id, 'sintética', 1,
                    :now, :now, :now, :now
                FROM unnest(:ids) WITH ORDINALITY AS t(a, n)
                CROSS JOIN (VALUES ('AUTH-001', 'single', 'medium'),
                    ('CORR-001', 'correlation', 'high')) AS r(rule_id, kind, severity)
                WHERE n % 10 = 0
                RETURNING id, asset_id
            )
            INSERT INTO detection_evidence (detection_id, signal_id, signal_kind, role,
                source_type, occurred_at, summary, created_at)
            SELECT id, 900000000000 + asset_id * 10 + k, 'auth_failure', 'failure', 'event',
                :now, 'evidencia', :now
            FROM burst CROSS JOIN generate_series(1, 3) AS k
            """
        ),
        {"ids": ids, "now": now},
    )
    # Exposición: RDP abierto en 1 de cada 4 activos y SMB en 1 de cada 6.
    session.execute(
        text(
            """
            INSERT INTO asset_ports (asset_id, protocol, port, state, first_seen_at, opened_at,
                last_seen_at, misses)
            SELECT a, 'tcp', p, 'open', :now - interval '3 days', :now - interval '3 days',
                :now, 0
            FROM unnest(:ids) WITH ORDINALITY AS t(a, n)
            CROSS JOIN (VALUES (3389, 4), (445, 6)) AS ports(p, every)
            WHERE n % every = 0
            """
        ),
        {"ids": ids, "now": now},
    )
    session.commit()
    for table in ("assets", "detections", "detection_evidence", "asset_ports"):
        session.execute(text(f"ANALYZE {table}"))
    session.commit()
    return ids


def seed_history(session: Session, ids: list[int], per_asset: int) -> int:
    """Historial sintético: `per_asset` puntos por activo repartidos en 30 días."""
    session.execute(
        text(
            """
            INSERT INTO risk_snapshots (public_id, asset_id, calculated_at, score, level,
                confidence, previous_score, previous_level, transition, reason, formula_version)
            SELECT gen_random_uuid(), a,
                now() - ((k * 43200 / :per) || ' minutes')::interval,
                (a * 7 + k * 13) % 101,
                CASE WHEN (a * 7 + k * 13) % 101 >= 80 THEN 'critical'
                     WHEN (a * 7 + k * 13) % 101 >= 60 THEN 'high'
                     WHEN (a * 7 + k * 13) % 101 >= 40 THEN 'medium'
                     WHEN (a * 7 + k * 13) % 101 >= 20 THEN 'low'
                     ELSE 'informational' END::risk_level,
                'medium', NULL, NULL, NULL, 'material_change', 1
            FROM unnest(:ids) AS a CROSS JOIN generate_series(1, :per) AS k
            """
        ),
        {"ids": ids, "per": per_asset},
    )
    session.commit()
    session.execute(text("ANALYZE risk_snapshots"))
    session.commit()
    return len(ids) * per_asset


def report(name: str, run: RiskRun, elapsed: float, statements: int) -> None:
    rate = run.assets / elapsed if elapsed else 0
    print(
        f"[{name}] {run.assets} assets in {elapsed:.2f} s ({rate:.0f} assets/s); "
        f"snapshots {run.snapshots}, transitions {run.transitions}, errors {run.errors}, "
        f"sql {statements} ({statements / max(1, run.assets):.2f}/asset)"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--assets", type=int, default=1000)
    parser.add_argument("--detections", type=int, default=20_000)
    parser.add_argument("--history-per-asset", type=int, default=200)
    args = parser.parse_args()

    settings = get_settings()
    config = RiskConfig.from_settings(settings)
    engine = get_engine()
    session = get_sessionmaker()()
    ids: list[int] = []
    errors = 0
    try:
        start = time.perf_counter()
        ids = seed(session, args.assets, args.detections)
        total_detections = session.scalar(
            text("SELECT count(*) FROM detections WHERE asset_id = ANY(:ids)"), {"ids": ids}
        )
        print(
            f"[seed] {len(ids)} assets, {total_detections} detections "
            f"in {time.perf_counter() - start:.1f} s"
        )
        risk = RiskEngine(session, config)
        # Solo los activos perf: los demás de la base no entran en la medida.
        session.execute(delete(AssetRisk).where(AssetRisk.asset_id.in_(ids)))
        session.commit()

        # 1. Primera evaluación.
        with count_statements(engine) as statements:
            start = time.perf_counter()
            risk.seed_missing(limit=len(ids) + 10_000)
            run = risk.process_dirty(max_batches=10_000)
            elapsed = time.perf_counter() - start
        report("initial", run, elapsed, len(statements))
        errors += run.errors
        levels = dict(
            session.execute(
                select(AssetRisk.level, func.count())
                .where(AssetRisk.asset_id.in_(ids))
                .group_by(AssetRisk.level)
            ).all()
        )
        print("         levels: " + ", ".join(f"{k}={levels.get(k, 0)}" for k in RiskLevel))

        # 2. Recálculo completo sin cambios: no debería generar historial nuevo.
        session.execute(
            update(AssetRisk).where(AssetRisk.asset_id.in_(ids)).values(dirty_at=func.now())
        )
        session.commit()
        with count_statements(engine) as statements:
            start = time.perf_counter()
            run = risk.process_dirty(max_batches=10_000)
            elapsed = time.perf_counter() - start
        report("recompute", run, elapsed, len(statements))
        errors += run.errors

        # 3. Decay una hora después (las detecciones se hacen más antiguas).
        later = datetime.now(UTC) + timedelta(hours=1)
        with count_statements(engine) as statements:
            start = time.perf_counter()
            run = risk.process_decay(later, max_batches=10_000)
            elapsed = time.perf_counter() - start
        report("decay+1h", run, elapsed, len(statements))
        errors += run.errors

        # 4. Lecturas del dashboard con historial grande.
        start = time.perf_counter()
        points = seed_history(session, ids, args.history_per_asset)
        print(f"[seed] {points} history points in {time.perf_counter() - start:.1f} s")
        timeout = timedelta(seconds=settings.heartbeat_timeout_seconds)
        service = RiskService(session, config, timeout)
        target = session.scalar(select(Asset.public_id).where(Asset.id == ids[len(ids) // 2]))
        if target is None:
            raise RuntimeError("no synthetic asset found")
        cases: dict[str, Callable[[], Any]] = {
            "overview": service.overview,
            "list score desc": lambda: service.list_assets(RiskFilter(), "score", True, 50, 0),
            "list level=critical": lambda: service.list_assets(
                RiskFilter(level=RiskLevel.CRITICAL), "score", True, 50, 0
            ),
            "list search+sort name": lambda: service.list_assets(
                RiskFilter(search="perf-risk-004"), "name", False, 50, 0
            ),
            "list page 10": lambda: service.list_assets(RiskFilter(), "changed_at", True, 50, 450),
            "detail": lambda: service.detail(target),
            "history 24h": lambda: service.history(target, "24h"),
            "history 7d": lambda: service.history(target, "7d"),
            "history 30d": lambda: service.history(target, "30d"),
            "contributions": lambda: service.contributions(target, None),
        }
        for name, fn in cases.items():
            with count_statements(engine) as statements:
                ms, _ = timed(fn)
            print(f"[read] {name:<22} {ms:7.1f} ms  sql/request={len(statements) // 5}")
        snapshots = session.scalar(
            select(func.count()).select_from(RiskSnapshot).where(RiskSnapshot.asset_id.in_(ids))
        )
        print(f"[size] risk_snapshots for perf assets: {snapshots}")
        return 0 if errors == 0 else 1
    finally:
        session.rollback()
        if ids:
            session.execute(delete(Asset).where(Asset.id.in_(ids)))
            session.commit()
        session.close()
        with get_sessionmaker()() as check:
            left = check.scalar(
                select(func.count()).select_from(Asset).where(Asset.hostname.like(f"{PREFIX}%"))
            )
            print(f"cleanup: {left} perf assets left")


if __name__ == "__main__":
    sys.exit(main())
