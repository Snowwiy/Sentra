"""Rendimiento de Incident Management (Fase 4K) con datos SINTÉTICOS.

Mide, contra el PostgreSQL de DATABASE_URL (nunca producción), las lecturas del SOC con un
volumen grande: por defecto 10 000 incidentes, 50 000 relaciones (40 000 detecciones +
10 000 activos) y 100 000 elementos de actividad (más 10 000 notas). Para cada lectura da la
mediana en ms y las sentencias SQL por petición: deben ser constantes, no crecer con el
número de filas de la página (sin N+1).

Uso (desde backend/, con el entorno del backend activo):

    $env:PYTHONPATH = "."   # (Linux: PYTHONPATH=. delante del comando)
    python ../qa/perf_incidents.py [--incidents 10000] [--activity-per-incident 10]

Crea activos "perf-inc-…" e incidentes con título "perf-inc …" y los borra al final (ON DELETE
CASCADE se lleva relaciones, notas y actividad). No toca otros datos. Úsalo en una base QA.
"""

import argparse
import statistics
import sys
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, event, func, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from app.db.session import get_engine, get_sessionmaker
from app.models.asset import Asset
from app.models.detection import Detection
from app.models.incident import Incident, IncidentActivity, IncidentDetection, IncidentStatus
from app.services.incident_queries import IncidentFilter, IncidentQueries
from app.services.incident_service import detail, get_incident

PREFIX = "perf-inc-"
TITLE = "perf-inc "


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


def seed(session: Session, assets: int, incidents: int, per_incident: int) -> list[int]:
    now = datetime.now(UTC)
    session.execute(
        text(
            """
            INSERT INTO assets (public_id, agent_id, monitoring_method, hostname, os_name,
                primary_ip, status, first_seen_at, last_seen_at, created_at, updated_at,
                criticality)
            SELECT gen_random_uuid(), gen_random_uuid(), 'agent', :prefix || lpad(g::text, 5, '0'),
                'Windows', '10.252.' || (g / 250) || '.' || (g % 250 + 1), 'online', :now, :now,
                :now, :now, 'medium'
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
    # Cuatro detecciones por incidente (la última es una correlación).
    session.execute(
        text(
            """
            INSERT INTO detections (public_id, asset_id, rule_id, rule_version, kind, dedup_key,
                severity, confidence, status, title, summary, occurrence_count, first_seen_at,
                last_seen_at, created_at, updated_at)
            SELECT gen_random_uuid(), (:ids)[1 + (g / 4) % cardinality(:ids)],
                CASE WHEN g % 4 = 3 THEN 'CORR-001'
                     ELSE (ARRAY['AUTH-001','DEF-001','PROC-001'])[1 + g % 3] END, 1,
                CASE WHEN g % 4 = 3 THEN 'correlation' ELSE 'single' END, 'perf-inc-' || g,
                (ARRAY['low','medium','high','critical'])[1 + g % 4]::detection_severity,
                'medium', 'open', 'Detección perf ' || g, 'sintética', 1,
                :now - ((g % 20000) || ' minutes')::interval,
                :now - ((g % 20000) || ' minutes')::interval, :now, :now
            FROM generate_series(0, :total - 1) AS g
            """
        ),
        {"ids": ids, "total": incidents * 4, "now": now},
    )
    session.execute(
        text(
            """
            INSERT INTO incidents (public_id, title, severity, priority, status, created_at,
                updated_at, last_activity_at, first_seen_at, last_seen_at, version)
            SELECT gen_random_uuid(), :title || g,
                (ARRAY['low','medium','high','critical'])[1 + g % 4]::incident_level,
                (ARRAY['low','medium','high','critical'])[1 + (g / 3) % 4]::incident_level,
                (ARRAY['open','triage','investigating','contained','resolved','closed'])
                    [1 + g % 6]::incident_status,
                :now - ((g % 40000) || ' minutes')::interval, :now,
                :now - ((g % 30000) || ' minutes')::interval,
                :now - ((g % 40000) || ' minutes')::interval, :now, 1
            FROM generate_series(1, :n) AS g
            """
        ),
        {"title": TITLE, "n": incidents, "now": now},
    )
    session.execute(
        text(
            """
            WITH i AS (
                SELECT id, row_number() OVER (ORDER BY id) - 1 AS n FROM incidents
                WHERE title LIKE :like
            ), d AS (
                SELECT d.*, row_number() OVER (ORDER BY d.id) - 1 AS n FROM detections d
                WHERE dedup_key LIKE 'perf-inc-%'
            )
            INSERT INTO incident_detections (incident_id, detection_id, detection_public_id,
                rule_id, kind, title, severity, source, attached_at)
            SELECT i.id, d.id, d.public_id, d.rule_id, d.kind, d.title, d.severity::text,
                'promoted', :now
            FROM d JOIN i ON i.n = d.n / 4
            """
        ),
        {"like": f"{TITLE}%", "now": now},
    )
    session.execute(
        text(
            """
            INSERT INTO incident_assets (incident_id, asset_id, asset_public_id, asset_name,
                source, added_at)
            SELECT DISTINCT ON (l.incident_id) l.incident_id, a.id, a.public_id, a.hostname,
                'detection', :now
            FROM incident_detections l JOIN detections d ON d.id = l.detection_id
            JOIN assets a ON a.id = d.asset_id
            WHERE a.hostname LIKE :prefix
            ORDER BY l.incident_id, l.id
            """
        ),
        {"prefix": f"{PREFIX}%", "now": now},
    )
    session.execute(
        text(
            """
            INSERT INTO incident_activity (incident_id, occurred_at, action, actor, entity_type,
                entity_id, summary)
            SELECT i.id, i.created_at + (k || ' minutes')::interval,
                (ARRAY['created','status_changed','assigned','note_added','detection_attached'])
                    [1 + k % 5], 'perf', 'incident', i.public_id::text, 'Actividad sintética ' || k
            FROM incidents i CROSS JOIN generate_series(1, :per) AS k
            WHERE i.title LIKE :like
            """
        ),
        {"like": f"{TITLE}%", "per": per_incident},
    )
    session.execute(
        text(
            """
            INSERT INTO incident_notes (public_id, incident_id, author, body, created_at)
            SELECT gen_random_uuid(), id, 'perf', 'Nota sintética', created_at
            FROM incidents WHERE title LIKE :like
            """
        ),
        {"like": f"{TITLE}%"},
    )
    session.commit()
    for table in (
        "assets",
        "detections",
        "incidents",
        "incident_detections",
        "incident_assets",
        "incident_activity",
        "incident_notes",
    ):
        session.execute(text(f"ANALYZE {table}"))
    session.commit()
    return ids


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--assets", type=int, default=500)
    parser.add_argument("--incidents", type=int, default=10_000)
    parser.add_argument("--activity-per-incident", type=int, default=10)
    args = parser.parse_args()

    engine = get_engine()
    session = get_sessionmaker()()
    ids: list[int] = []
    try:
        start = time.perf_counter()
        ids = seed(session, args.assets, args.incidents, args.activity_per_incident)
        mine = select(Incident.id).where(Incident.title.like(f"{TITLE}%"))
        relations = (session.scalar(
            select(func.count()).select_from(IncidentDetection)
            .where(IncidentDetection.incident_id.in_(mine))
        ) or 0) + (session.scalar(
            text("SELECT count(*) FROM incident_assets WHERE asset_id = ANY(:ids)"), {"ids": ids}
        ) or 0)  # fmt: skip
        activity = session.scalar(
            select(func.count())
            .select_from(IncidentActivity)
            .where(IncidentActivity.incident_id.in_(mine))
        )
        print(
            f"[seed] {args.incidents} incidents, {relations} relations, {activity} activity "
            f"rows in {time.perf_counter() - start:.1f} s"
        )
        queries = IncidentQueries(session, None)
        target = session.scalars(
            select(Incident).where(Incident.title.like(f"{TITLE}%")).order_by(Incident.id)
        ).all()[args.incidents // 2]
        detection = session.scalar(
            select(Detection.public_id)
            .join(IncidentDetection, IncidentDetection.detection_id == Detection.id)
            .where(IncidentDetection.incident_id == target.id)
        )
        if detection is None:
            raise RuntimeError("no synthetic detection found")
        first = queries.timeline(target.public_id, 50, None, None, None)
        cases: dict[str, Callable[[], Any]] = {
            "overview": queries.overview,
            "list last_activity": lambda: queries.find(
                IncidentFilter(), "last_activity", True, 50, 0
            ),
            "list active+critical": lambda: queries.find(
                IncidentFilter(active=True, severity=target.severity), "priority", True, 50, 0
            ),
            "list status=triage": lambda: queries.find(
                IncidentFilter(status=IncidentStatus.TRIAGE), "created_at", True, 50, 0
            ),
            "list unassigned": lambda: queries.find(
                IncidentFilter(owner="unassigned"), "last_activity", True, 50, 0
            ),
            "list page 100": lambda: queries.find(IncidentFilter(), "number", False, 50, 4950),
            "search INC number": lambda: queries.find(
                IncidentFilter(search=f"INC-{target.number:06d}"), "last_activity", True, 50, 0
            ),
            "search hostname": lambda: queries.find(
                IncidentFilter(search=f"{PREFIX}00042"), "last_activity", True, 50, 0
            ),
            "search IP": lambda: queries.find(
                IncidentFilter(search="10.252.0.42"), "last_activity", True, 50, 0
            ),
            "search title/detection": lambda: queries.find(
                IncidentFilter(search="Detección perf 1234"), "last_activity", True, 50, 0
            ),
            "detail": lambda: detail(session, get_incident(session, target.public_id)),
            "timeline page 1": lambda: queries.timeline(target.public_id, 50, None, None, None),
            "timeline page 2": lambda: queries.timeline(
                target.public_id, 50, first.next_cursor, None, None
            ),
            "evidence": lambda: queries.evidence(target.public_id),
            "notes": lambda: queries.notes(target.public_id, 50, 0),
            "related (detection)": lambda: queries.related_for_detection(detection),
        }
        for name, fn in cases.items():
            with count_statements(engine) as statements:
                ms, _ = timed(fn)
            print(f"[read] {name:<24} {ms:7.1f} ms  sql/request={len(statements) // 5}")
        return 0
    finally:
        session.rollback()
        session.execute(delete(Incident).where(Incident.title.like(f"{TITLE}%")))
        if ids:
            session.execute(delete(Asset).where(Asset.id.in_(ids)))
        session.commit()
        session.close()
        with get_sessionmaker()() as check:
            left = check.scalar(
                select(func.count()).select_from(Incident).where(Incident.title.like(f"{TITLE}%"))
            )
            print(f"cleanup: {left} perf incidents left")


if __name__ == "__main__":
    sys.exit(main())
