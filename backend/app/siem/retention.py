"""Retención de la integración SIEM (Fase 7F.1).

Activa por defecto: los eventos externos son lo que más puede crecer en un SOC. Se borra por
lotes acotados (DELETE ... WHERE id IN (SELECT ... LIMIT n)) con un commit entre lotes, para
que una purga grande no bloquee la tabla ni llene el WAL de golpe en hardware modesto.

Orden: primero la edad (retención de cada fuente o la global) y después el tope global
SIEM_MAX_STORED_EVENTS, que borra los más antiguos si se supera.
"""

from datetime import datetime, timedelta

from sqlalchemy import delete, func, select, text
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models.siem import SiemBatch, SiemEvent, SiemSource

DELETE_CHUNK = 5000
# Como mucho estos lotes por pasada (250 000 filas); lo que quede sale en la siguiente.
MAX_CHUNKS = 50


def _delete_chunks(session: Session, condition: object) -> int:
    total = 0
    for _ in range(MAX_CHUNKS):
        ids = select(SiemEvent.id).where(condition).limit(DELETE_CHUNK)  # type: ignore[arg-type]
        result = session.execute(delete(SiemEvent).where(SiemEvent.id.in_(ids.scalar_subquery())))
        deleted = int(getattr(result, "rowcount", 0) or 0)
        session.commit()
        total += deleted
        if deleted < DELETE_CHUNK:
            break
    return total


def _estimated_rows(session: Session) -> int:
    """Estimación barata del número de eventos (estadísticas de PostgreSQL), sin COUNT(*)."""
    value = session.scalar(
        text("SELECT reltuples::bigint FROM pg_class WHERE oid = 'siem_events'::regclass")
    )
    return max(0, int(value or 0))


def purge_siem(session: Session, settings: Settings, now: datetime) -> dict[str, int]:
    counts = {"siem_events": 0, "siem_batches": 0}
    for source_id, days in session.execute(select(SiemSource.id, SiemSource.retention_days)).all():
        effective = days or settings.siem_event_retention_days
        if effective is None:
            continue
        cutoff = now - timedelta(days=effective)
        counts["siem_events"] += _delete_chunks(
            session, (SiemEvent.source_id == source_id) & (SiemEvent.observed_at < cutoff)
        )
    cap = settings.siem_max_stored_events
    if cap and _estimated_rows(session) > cap:
        exact = int(session.scalar(select(func.count()).select_from(SiemEvent)) or 0)
        excess = exact - cap
        if excess > 0:
            # Umbral: el id del evento más reciente que sobra (los ids crecen con la llegada).
            threshold = session.scalar(
                select(SiemEvent.id).order_by(SiemEvent.id).offset(excess - 1).limit(1)
            )
            if threshold is not None:
                counts["siem_events_capped"] = _delete_chunks(session, SiemEvent.id <= threshold)
    if settings.siem_batch_retention_days is not None:
        cutoff = now - timedelta(days=settings.siem_batch_retention_days)
        result = session.execute(delete(SiemBatch).where(SiemBatch.received_at < cutoff))
        counts["siem_batches"] = int(getattr(result, "rowcount", 0) or 0)
    return counts
