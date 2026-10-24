"""Métricas medidas de la telemetría de endpoint y de la detección de comportamiento (6E.5).

Todo sale de marcas de tiempo guardadas, no de estimaciones:
- retraso de ingesta: received_at - occurred_at de cada evento de la última hora (incluye el
  intervalo de sondeo del agente y su cola offline);
- latencia de detección: created_at de la detección - occurred_at de la primera evidencia,
  para las reglas BEH-* de las últimas 24 horas (incluye el retraso de ingesta y el ciclo
  del job del motor).
"""

from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.detection import Detection
from app.models.endpoint import EndpointActivity
from app.schemas.common import ResponseModel


class EndpointMetrics(ResponseModel):
    window_hours: int
    events_last_hour: int
    assets_reporting_last_hour: int
    ingest_lag_p50_seconds: float | None
    ingest_lag_p95_seconds: float | None
    ingest_lag_max_seconds: float | None
    behavior_detections_24h: int
    detection_latency_p50_seconds: float | None
    detection_latency_p95_seconds: float | None


def _round(value: object) -> float | None:
    return round(float(value), 3) if value is not None else None  # type: ignore[arg-type]


def endpoint_metrics(session: Session, now: datetime | None = None) -> EndpointMetrics:
    now = now or datetime.now(UTC)
    hour = now - timedelta(hours=1)
    lag = func.extract("epoch", EndpointActivity.received_at - EndpointActivity.occurred_at)
    events = session.execute(
        select(
            func.count(),
            func.count(func.distinct(EndpointActivity.asset_id)),
            func.percentile_cont(0.5).within_group(lag),
            func.percentile_cont(0.95).within_group(lag),
            func.max(lag),
        ).where(EndpointActivity.received_at >= hour)
    ).one()
    day = now - timedelta(hours=24)
    latency = func.extract("epoch", Detection.created_at - Detection.first_seen_at)
    detections = session.execute(
        select(
            func.count(),
            func.percentile_cont(0.5).within_group(latency),
            func.percentile_cont(0.95).within_group(latency),
        ).where(Detection.rule_id.like("BEH-%"), Detection.created_at >= day)
    ).one()
    return EndpointMetrics(
        window_hours=1,
        events_last_hour=int(events[0] or 0),
        assets_reporting_last_hour=int(events[1] or 0),
        ingest_lag_p50_seconds=_round(events[2]),
        ingest_lag_p95_seconds=_round(events[3]),
        ingest_lag_max_seconds=_round(events[4]),
        behavior_detections_24h=int(detections[0] or 0),
        detection_latency_p50_seconds=_round(detections[1]),
        detection_latency_p95_seconds=_round(detections[2]),
    )
