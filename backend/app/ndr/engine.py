"""Job periódico ndr-engine (Fase 7E.3): líneas base horarias y beaconing.

Lo que necesita historia (más de una ventana de exportación) se evalúa aquí, fuera de la
ingesta, sobre los flujos ya guardados:

- Horas completas: por equipo interno (IP privada) del site, bytes enviados y destinos
  distintos. Se compara con su línea base (Welford) y luego se aprende la hora, salvo que
  sea anómala. Aproximación documentada: un flujo largo cuenta en la hora de su último
  segmento (los contadores del sensor son acumulados por flujo).
- Beaconing: pares (origen interno, destino externo, puerto) con muchas conexiones en las
  últimas horas a intervalos casi constantes.

Idempotente por cursor: cada hora se agrega una sola vez aunque el job corra cada 5 minutos.
"""

import itertools
import logging
import math
import statistics
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models.ndr import NdrBaseline, NdrEngineCursor, NdrFlow
from app.ndr.addresses import is_external, is_internal
from app.ndr.anomalies import Finding, record_finding
from app.ndr.rules import BEH_001, BEH_002, BEH_003

logger = logging.getLogger(__name__)

HOURLY = "hourly"
MAX_HOURS_PER_RUN = 24
MAX_ENTITIES_PER_HOUR = 5000
BYTES_SIGMA = 4.0
BYTES_SIGMA_PROBABLE = 8.0
BYTES_MIN = 50 * 1024 * 1024
BYTES_PROBABLE_MIN = 500 * 1024 * 1024
FANOUT_SIGMA = 4.0
FANOUT_MIN = 50
BEACON_WINDOW = timedelta(hours=6)
BEACON_MIN_CONNECTIONS = 12
BEACON_MAX_CV = 0.15
BEACON_MIN_INTERVAL = 10.0
BEACON_MAX_INTERVAL = 3600.0
BEACON_MAX_CANDIDATES = 200


def _hour(value: datetime) -> datetime:
    return value.replace(minute=0, second=0, microsecond=0)


def _cursor(session: Session, name: str, default: datetime) -> NdrEngineCursor:
    row = session.get(NdrEngineCursor, name, with_for_update=True)
    if row is None:
        row = NdrEngineCursor(name=name, position=default, updated_at=datetime.now(UTC))
        session.add(row)
        session.flush()
    return row


def run_ndr_engine(
    session: Session, settings: Settings, now: datetime | None = None
) -> dict[str, int]:
    now = now or datetime.now(UTC)
    hours = _hourly(session, settings, now)
    beacons = _beaconing(session, now)
    session.commit()
    return {"hours": hours, "beacons": beacons}


# --- líneas base horarias -----------------------------------------------------------------


def _hourly(session: Session, settings: Settings, now: datetime) -> int:
    current = _hour(now)
    cursor = _cursor(session, HOURLY, current - timedelta(hours=1))
    processed = 0
    while cursor.position < current and processed < MAX_HOURS_PER_RUN:
        start = cursor.position
        _aggregate_hour(session, settings, start, start + timedelta(hours=1))
        cursor.position = start + timedelta(hours=1)
        cursor.updated_at = now
        processed += 1
    return processed


def _aggregate_hour(session: Session, settings: Settings, start: datetime, end: datetime) -> None:
    rows = session.execute(
        select(
            NdrFlow.site_id,
            NdrFlow.src_ip,
            func.sum(NdrFlow.bytes_out),
            func.count(func.distinct(NdrFlow.dst_ip)),
        )
        .where(NdrFlow.last_seen >= start, NdrFlow.last_seen < end)
        .group_by(NdrFlow.site_id, NdrFlow.src_ip)
        .order_by(func.sum(NdrFlow.bytes_out).desc())
        .limit(MAX_ENTITIES_PER_HOUR * 4)
    ).all()
    entities = [(site, ip, int(b or 0), int(d)) for site, ip, b, d in rows if is_internal(ip)]
    for site_id, ip, sent, destinations in entities[:MAX_ENTITIES_PER_HOUR]:
        _evaluate(session, settings, site_id, ip, "bytes_out", float(sent), start)
        _evaluate(session, settings, site_id, ip, "destinations", float(destinations), start)


def _baseline(session: Session, site_id: int, ip: str, metric: str) -> NdrBaseline:
    row = session.scalar(
        select(NdrBaseline).where(
            NdrBaseline.site_id == site_id,
            NdrBaseline.entity_ip == ip,
            NdrBaseline.metric == metric,
        )
    )
    if row is None:
        row = NdrBaseline(
            site_id=site_id,
            entity_ip=ip,
            metric=metric,
            samples=0,
            mean=0.0,
            m2=0.0,
            updated_at=datetime.now(UTC),
        )
        session.add(row)
    return row


def _evaluate(
    session: Session,
    settings: Settings,
    site_id: int,
    ip: str,
    metric: str,
    value: float,
    bucket: datetime,
) -> None:
    row = _baseline(session, site_id, ip, metric)
    if row.last_bucket is not None and row.last_bucket >= bucket:
        return  # esa hora ya se aprendió (reintento del job tras un fallo).
    anomalous = False
    if row.samples >= settings.ndr_baseline_min_samples:
        std = math.sqrt(row.m2 / (row.samples - 1)) if row.samples > 1 else 0.0
        anomalous = _check(session, site_id, ip, metric, value, row.mean, std, row.samples, bucket)
    if not anomalous:
        # Welford: media y suma de cuadrados en una pasada, estable numéricamente.
        row.samples += 1
        delta = value - row.mean
        row.mean += delta / row.samples
        row.m2 += delta * (value - row.mean)
    row.last_value = value
    row.last_bucket = bucket
    row.updated_at = datetime.now(UTC)


def _check(
    session: Session,
    site_id: int,
    ip: str,
    metric: str,
    value: float,
    mean: float,
    std: float,
    samples: int,
    bucket: datetime,
) -> bool:
    # Un equipo muy constante (std ~ 0) no debe alertar por cualquier variación mínima: el
    # umbral nunca baja del 25 % de la media.
    spread = max(std, mean * 0.25, 1.0)
    evidence: dict[str, Any] = {
        "ip": ip,
        "hour": bucket,
        "value": value,
        "baseline_mean": round(mean, 2),
        "baseline_std": round(std, 2),
        "samples": samples,
    }
    if metric == "bytes_out":
        if value < BYTES_MIN or value <= mean + BYTES_SIGMA * spread:
            return False
        probable = value >= BYTES_PROBABLE_MIN and value > mean + BYTES_SIGMA_PROBABLE * spread
        record_finding(
            session,
            site_id,
            None,
            Finding(
                rule=BEH_001,
                dedup_key=ip,
                verdict="probable" if probable else "suspicious",
                severity="high" if probable else "medium",
                summary=(
                    f"{ip} envió {value / 1_048_576:.0f} MB en una hora; su media es"
                    f" {mean / 1_048_576:.1f} MB."
                ),
                evidence=evidence,
                at=bucket + timedelta(hours=1),
                subject_ip=ip,
            ),
        )
        return True
    if value < FANOUT_MIN or value <= mean + FANOUT_SIGMA * spread:
        return False
    record_finding(
        session,
        site_id,
        None,
        Finding(
            rule=BEH_002,
            dedup_key=ip,
            verdict="suspicious",
            severity="medium",
            summary=(
                f"{ip} contactó con {value:.0f} destinos en una hora; lo habitual son {mean:.0f}."
            ),
            evidence=evidence,
            at=bucket + timedelta(hours=1),
            subject_ip=ip,
        ),
    )
    return True


# --- beaconing ----------------------------------------------------------------------------


def _beaconing(session: Session, now: datetime) -> int:
    since = now - BEACON_WINDOW
    candidates = session.execute(
        select(NdrFlow.site_id, NdrFlow.src_ip, NdrFlow.dst_ip, NdrFlow.dst_port, func.count())
        .where(NdrFlow.first_seen >= since, NdrFlow.dst_port.is_not(None))
        .group_by(NdrFlow.site_id, NdrFlow.src_ip, NdrFlow.dst_ip, NdrFlow.dst_port)
        .having(func.count() >= BEACON_MIN_CONNECTIONS)
        .order_by(func.count().desc())
        .limit(BEACON_MAX_CANDIDATES * 4)
    ).all()
    found = 0
    checked = 0
    for site_id, src, dst, port, count in candidates:
        if not (is_internal(src) and is_external(dst)):
            continue
        checked += 1
        if checked > BEACON_MAX_CANDIDATES:
            break
        times = list(
            session.scalars(
                select(NdrFlow.first_seen)
                .where(
                    NdrFlow.site_id == site_id,
                    NdrFlow.src_ip == src,
                    NdrFlow.dst_ip == dst,
                    NdrFlow.dst_port == port,
                    NdrFlow.first_seen >= since,
                )
                .order_by(NdrFlow.first_seen)
            )
        )
        intervals = [(b - a).total_seconds() for a, b in itertools.pairwise(times)]
        intervals = [i for i in intervals if i > 0]
        if len(intervals) < BEACON_MIN_CONNECTIONS - 1:
            continue
        mean = statistics.fmean(intervals)
        if not BEACON_MIN_INTERVAL <= mean <= BEACON_MAX_INTERVAL:
            continue
        cv = statistics.pstdev(intervals) / mean
        if cv > BEACON_MAX_CV:
            continue
        found += 1
        record_finding(
            session,
            site_id,
            None,
            Finding(
                rule=BEH_003,
                dedup_key=f"{src}|{dst}|{port}",
                verdict="suspicious",
                severity="medium",
                summary=(
                    f"{src} conecta con {dst}:{port} cada {mean:.0f} s de forma muy regular"
                    f" ({len(times)} conexiones en 6 h, variación {cv * 100:.1f} %)."
                ),
                evidence={
                    "src_ip": src,
                    "dst_ip": dst,
                    "dst_port": port,
                    "connections": int(count),
                    "mean_interval_seconds": round(mean, 1),
                    "coefficient_of_variation": round(cv, 4),
                },
                at=times[-1],
                subject_ip=src,
            ),
        )
    return found
