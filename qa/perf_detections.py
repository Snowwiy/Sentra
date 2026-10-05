"""Rendimiento del motor de detección (Fase 4H) con datos SINTÉTICOS.

Mide, contra el PostgreSQL de DATABASE_URL (nunca producción):

1. Coste en la ingesta: extraer y guardar señales de un lote de 50 eventos (lo que se suma a
   POST /events; evaluar reglas no ocurre en la petición).
2. Rendimiento del job: señales evaluadas por segundo con todas las reglas activas.
3. Lecturas del analista con un histórico grande de detecciones: listado con filtros,
   detalle y el plan de PostgreSQL (EXPLAIN ANALYZE) de las consultas principales, contando
   sentencias SQL por petición (sin N+1).

Uso (desde backend/, con el entorno del backend activo):

    $env:PYTHONPATH = "."   # (Linux: PYTHONPATH=. delante del comando)
    python ../qa/perf_detections.py [--assets 200] [--events-per-asset 50] [--history 50000]

Crea activos "perf-…" y los borra al final (ON DELETE CASCADE se lleva señales, eventos,
detecciones y evidencias). No toca otros activos. Ejecútalo con el job del motor de una API
QA parado o en una base QA propia: si no, ese job puede adelantarse y evaluar las señales.
"""

import argparse
import statistics
import sys
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, event, func, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.session import get_engine, get_sessionmaker
from app.detection.config import DetectionConfig
from app.detection.engine import DetectionEngine
from app.detection.recorder import SignalRecorder
from app.models.asset import Asset, MonitoringMethod
from app.models.detection import Detection, DetectionSeverity, DetectionSignal, DetectionStatus
from app.models.event import EventLevel, SystemEvent
from app.schemas.detection import DetectionList
from app.services.detection_service import DetectionFilter, DetectionService

SECURITY = "Microsoft-Windows-Security-Auditing"
PREFIX = "perf-"


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


def synthetic_events(asset_id: int, count: int, now: datetime) -> list[SystemEvent]:
    """Mezcla realista: sobre todo fallos de inicio de sesión, algún éxito y cambios."""
    events: list[SystemEvent] = []
    for i in range(count):
        at = now - timedelta(seconds=count - i)
        user = f"user{i % 3}"
        code, level, data = (
            4625,
            EventLevel.WARNING,
            {
                "TargetUserName": user,
                "IpAddress": "10.99.0.5",
                "LogonType": "3",
            },
        )
        if i % 10 == 9:
            code, level = 4624, EventLevel.INFO
            data = {"TargetUserName": user, "TargetUserSid": f"S-1-5-21-9-9-9-{1000 + i % 3}",
                    "LogonType": "10"}  # fmt: skip
        elif i % 25 == 7:
            code, level, data = (
                7045,
                EventLevel.INFO,
                {
                    "ServiceName": f"PerfSvc{i}",
                    "ImagePath": "C:\\Users\\Public\\perf.exe",
                },
            )
        elif i % 25 == 13:
            code, level, data = 4720, EventLevel.INFO, {"TargetUserName": f"new{i}"}
        events.append(
            SystemEvent(
                public_id=uuid.uuid4(),
                asset_id=asset_id,
                source="windows_eventlog",
                channel="Security" if code != 7045 else "System",
                record_id=i + 1,
                event_code=code,
                provider=SECURITY if code != 7045 else "Service Control Manager",
                level=level,
                message="perf",
                data=data,
                occurred_at=at,
            )
        )
    return events


def create_assets(session: Session, count: int) -> list[int]:
    ids = []
    for i in range(count):
        asset = Asset(
            agent_id=uuid.uuid4(),
            monitoring_method=MonitoringMethod.AGENT,
            hostname=f"{PREFIX}{i:04d}",
            os_name="Windows",
            primary_ip=f"10.250.{i // 250}.{i % 250 + 1}",
            first_seen_at=datetime.now(UTC),
            last_seen_at=datetime.now(UTC),
        )
        session.add(asset)
        session.flush()
        ids.append(asset.id)
    session.commit()
    return ids


def seed_history(session: Session, asset_ids: list[int], total: int) -> None:
    """Histórico de detecciones (90 % resueltas) con 5 evidencias cada una, en SQL masivo."""
    session.execute(
        text(
            """
            INSERT INTO detections (public_id, asset_id, rule_id, rule_version, kind, dedup_key,
                severity, confidence, status, title, summary, occurrence_count, first_seen_at,
                last_seen_at, created_at, updated_at, resolved_at)
            SELECT gen_random_uuid(), (:ids)[1 + g % cardinality(:ids)],
                (ARRAY['AUTH-001','DEF-001','NET-001','PER-001','PROC-001'])[1 + g % 5], 1,
                'single', 'hist-' || g,
                (ARRAY['informational','low','medium','high','critical'])[1 + g % 5]
                    ::detection_severity,
                (ARRAY['low','medium','high'])[1 + g % 3]::detection_confidence,
                CASE WHEN g % 10 = 0 THEN 'open' ELSE 'resolved' END::detection_status,
                'Detección sintética ' || g, 'Resumen sintético de rendimiento', 1,
                now() - (g || ' minutes')::interval, now() - (g || ' minutes')::interval,
                now(), now(),
                CASE WHEN g % 10 = 0 THEN NULL ELSE now() END
            FROM generate_series(1, :total) AS g
            """
        ),
        {"ids": asset_ids, "total": total},
    )
    session.execute(
        text(
            """
            INSERT INTO detection_evidence (detection_id, signal_id, signal_kind, role,
                source_type, occurred_at, summary, created_at)
            SELECT d.id, NULL, 'auth_failure', NULL, 'event', d.last_seen_at, 'evidencia', now()
            FROM detections d JOIN assets a ON a.id = d.asset_id
            CROSS JOIN generate_series(1, 5)
            WHERE a.hostname LIKE 'perf-%'
            """
        )
    )
    session.commit()
    session.execute(text("ANALYZE detections"))
    session.execute(text("ANALYZE detection_evidence"))
    session.commit()


def explain(session: Session, stmt: Any) -> str:
    compiled = stmt.compile(
        dialect=session.get_bind().dialect, compile_kwargs={"literal_binds": True}
    )
    rows = session.execute(text(f"EXPLAIN (ANALYZE, BUFFERS OFF) {compiled}")).scalars().all()
    return "\n".join(f"      {row}" for row in rows)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--assets", type=int, default=200)
    parser.add_argument("--events-per-asset", type=int, default=50)
    parser.add_argument("--history", type=int, default=50_000)
    parser.add_argument("--explain", action="store_true", help="print the query plans")
    args = parser.parse_args()

    config = DetectionConfig.from_settings(get_settings())
    engine = get_engine()
    session = get_sessionmaker()()
    now = datetime.now(UTC)
    asset_ids: list[int] = []
    try:
        asset_ids = create_assets(session, args.assets)
        print(f"assets: {len(asset_ids)}  events/asset: {args.events_per_asset}")

        # 1. Ingesta: extracción + INSERT de señales por lote (lo que añade POST /events).
        recorder = SignalRecorder(session, config)
        per_batch = []
        for asset_id in asset_ids:
            events = synthetic_events(asset_id, args.events_per_asset, now)
            session.add_all(events)
            session.flush()
            start = time.perf_counter()
            recorder.record_events(asset_id, events)
            per_batch.append((time.perf_counter() - start) * 1000)
        session.commit()
        signals = session.scalar(
            select(func.count())
            .select_from(DetectionSignal)
            .where(DetectionSignal.asset_id.in_(asset_ids))
        )
        print(
            f"[ingest] {len(per_batch)} batches of {args.events_per_asset} events: "
            f"median {statistics.median(per_batch):.1f} ms, "
            f"p95 {sorted(per_batch)[int(len(per_batch) * 0.95) - 1]:.1f} ms; signals: {signals}"
        )

        # 2. Job del motor: todas las reglas sobre todas las señales pendientes.
        detector = DetectionEngine(session, config)
        start = time.perf_counter()
        total = created = updated = errors = 0
        while True:
            run = detector.process_pending()
            total, created = total + run.signals, created + run.created
            updated, errors = updated + run.updated, errors + run.rule_errors
            if run.signals == 0:
                break
        elapsed = time.perf_counter() - start
        print(
            f"[engine] {total} signals in {elapsed:.2f} s "
            f"({total / elapsed if elapsed else 0:.0f} signals/s); "
            f"detections created {created}, updated {updated}, rule errors {errors}"
        )

        # 3. Lecturas del analista sobre un histórico grande.
        start = time.perf_counter()
        seed_history(session, asset_ids, args.history)
        print(f"[seed] {args.history} historical detections in {time.perf_counter() - start:.1f} s")
        service = DetectionService(session, config)
        target = session.scalar(
            select(Asset.public_id).where(Asset.id == asset_ids[len(asset_ids) // 2])
        )
        cases: dict[str, DetectionFilter] = {
            "active (default view)": DetectionFilter(active=True),
            "all statuses": DetectionFilter(),
            "severity=critical": DetectionFilter(severity=DetectionSeverity.CRITICAL),
            "one asset": DetectionFilter(asset_public_id=target),
            "rule AUTH-001 last 24h": DetectionFilter(rule_id="AUTH-001",
                                                       since=now - timedelta(hours=24)),
            "text search": DetectionFilter(search="sintética 4242"),
        }  # fmt: skip
        for name, filt in cases.items():

            def listing(f: DetectionFilter = filt) -> DetectionList:
                return service.list(f, limit=100)

            with count_statements(engine) as statements:
                ms, page = timed(listing)
            print(
                f"[list] {name:<24} {ms:7.1f} ms  total={page.total:<6} "
                f"sql/request={len(statements) // 5}"
            )
        sample = session.scalar(
            select(Detection.public_id).where(Detection.asset_id.in_(asset_ids)).limit(1)
        )
        if sample is None:
            raise RuntimeError("no synthetic detection found")
        with count_statements(engine) as statements:
            ms, _ = timed(lambda: service.get(sample))
        print(f"[detail] with evidence     {ms:7.1f} ms  sql/request={len(statements) // 5}")
        if args.explain:
            base = service._base()  # solo para enseñar el plan
            for name, stmt in {
                "active list": base.where(Detection.status != DetectionStatus.RESOLVED)
                .order_by(Detection.last_seen_at.desc(), Detection.id.desc())
                .limit(100),
                "asset list": base.where(Detection.asset_id == asset_ids[0])
                .order_by(Detection.last_seen_at.desc(), Detection.id.desc())
                .limit(100),
            }.items():
                print(f"[plan] {name}\n{explain(session, stmt)}")
        return 0 if errors == 0 else 1
    finally:
        session.rollback()
        if asset_ids:
            session.execute(delete(Asset).where(Asset.id.in_(asset_ids)))
            session.commit()
        session.close()
        # Las filas insertadas aquí son todas de los activos perf-: verificar que no queda nada.
        with get_sessionmaker()() as check:
            left = check.scalar(
                select(func.count()).select_from(Asset).where(Asset.hostname.like(f"{PREFIX}%"))
            )
            print(f"cleanup: {left} perf assets left")


if __name__ == "__main__":
    sys.exit(main())
