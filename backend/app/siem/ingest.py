"""Pipeline de ingesta SIEM (Fase 7F.1): validación → normalización → deduplicación →
almacenamiento → analizadores (detección y correlación) en la misma transacción.

Garantías:
- Autorización por lote (sensor): la fuente debe ser de ESE sensor, estar habilitada, ser de
  transporte `sensor`, coincidir el alias de entrada, y el sensor (con la capacidad y una
  versión soportada) y su site deben estar activos. Si no, 403 siem_not_authorized. El
  `source_id` del cuerpo solo SELECCIONA entre las fuentes del sensor: un sensor no puede
  escribir en una fuente ajena ni de otro site.
- Idempotencia: el recibo (fuente, batch_id) es único y cada evento tiene una clave de
  deduplicación única por fuente; un reenvío o una relectura no duplican nada.
- Concurrencia: la fila de la fuente se bloquea (FOR UPDATE) hasta el commit, así que los
  lotes de una fuente se procesan de uno en uno en cualquier número de workers y la cuota y
  los contadores son coherentes sin memoria compartida.
- Backpressure: por encima de la cuota por minuto de la fuente se responde 429 siem_quota con
  Retry-After; el sensor conserva el lote en su spool.
- Reloj: una marca del futuro más allá de SENSOR_MAX_CLOCK_SKEW_SECONDS se recorta a la de
  recepción (time_quality=clamped); una más antigua que la retención se rechaza (too_old):
  se purgaría en la siguiente pasada y solo ocuparía espacio.
- Un registro malformado se rechaza y se cuenta por motivo; nunca tumba el lote ni la API.
"""

import logging
import time
import uuid
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.exceptions import SiemNotAuthorizedError, SiemQuotaError, SiemValidationError
from app.models.siem import SiemBatch, SiemEvent, SiemSource
from app.models.site import Sensor, Site
from app.schemas.siem import SiemBatchAccepted, SiemBatchIn
from app.sensors.catalog import SIEM_CAPABILITY, version_status
from app.siem import fields
from app.siem.catalog import NormalizeContext, get_connector
from app.siem.contract import SCHEMA_VERSION, NormalizedEvent, RawRecord, RecordRejectedError

logger = logging.getLogger(__name__)

# Filas por INSERT: 40 columnas x 500 filas queda lejos del límite de 65535 parámetros.
INSERT_CHUNK = 500
QUOTA_WINDOW = timedelta(minutes=1)


@dataclass
class IngestedSiem:
    """Lo que entró en un lote, para los analizadores (detección, correlación) que se
    ejecutan en la misma transacción. Solo ids: cada analizador lee lo que necesita."""

    source: SiemSource
    site: Site
    sensor: Sensor | None
    received_at: datetime
    event_ids: list[int] = field(default_factory=list)


Analyzer = Callable[[Session, Settings, IngestedSiem], None]


@dataclass
class _Outcome:
    rows: list[dict[str, Any]] = field(default_factory=list)
    rejected: Counter[str] = field(default_factory=Counter)
    newest: datetime | None = None


def effective_retention_days(source: SiemSource, settings: Settings) -> int | None:
    return source.retention_days or settings.siem_event_retention_days


class SiemIngest:
    def __init__(
        self,
        session: Session,
        settings: Settings,
        analyzers: Sequence[Analyzer] = (),
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._session = session
        self._settings = settings
        self._analyzers = analyzers
        self._now = now

    # --- autorización -----------------------------------------------------------------------

    def authorize_sensor(self, sensor: Sensor, body: SiemBatchIn) -> SiemSource:
        """Fuente del lote, bloqueada hasta el commit; 403 si el sensor no puede escribir."""
        source = self._session.scalar(
            select(SiemSource).where(SiemSource.public_id == body.source_id).with_for_update()
        )
        site = self._session.get(Site, sensor.site_id)
        reasons = []
        if source is None or source.sensor_id != sensor.id:
            reasons.append("source")
        elif (
            not source.enabled
            or source.transport != "sensor"
            or source.input_name != body.input
            or source.site_id != sensor.site_id
        ):
            reasons.append("source_state")
        if SIEM_CAPABILITY not in (sensor.capabilities or []):
            reasons.append("capability")
        if sensor.status != "active" or site is None or site.status != "active":
            reasons.append("status")
        if (
            version_status(
                sensor.sensor_version,
                self._settings.sensor_min_version,
                self._settings.sensor_recommended_version,
            )
            == "unsupported"
        ):
            reasons.append("version")
        if reasons or source is None:
            logger.info(
                "siem batch rejected",
                extra={"sensor": str(sensor.public_id), "reasons": reasons},
            )
            raise SiemNotAuthorizedError("This sensor is not authorized for that SIEM source")
        if len(body.records) > self._settings.siem_max_records_per_batch:
            raise SiemValidationError("siem_batch_too_large", "Too many records in the batch")
        return source

    # --- entrada ----------------------------------------------------------------------------

    def process(
        self,
        source: SiemSource,
        batch_id: uuid.UUID,
        records: Sequence[RawRecord],
        origin: str,
        sensor: Sensor | None = None,
        stats: dict[str, Any] | None = None,
    ) -> SiemBatchAccepted:
        """Procesa un lote de una fuente ya autorizada y BLOQUEADA por quien llama."""
        started = time.perf_counter()
        session = self._session
        now = self._now()
        existing = session.scalar(
            select(SiemBatch.id).where(
                SiemBatch.source_id == source.id, SiemBatch.batch_id == batch_id
            )
        )
        if existing is not None:
            # Reenvío de un lote ya guardado (el emisor no recibió la respuesta): nada que hacer
            # y no consume cuota.
            session.commit()
            return SiemBatchAccepted(
                batch_id=batch_id,
                duplicate=True,
                records=len(records),
                accepted=0,
                duplicates=0,
                rejected=0,
                reject_reasons={},
            )
        self._spend_quota(source, len(records), now)
        site = session.get(Site, source.site_id)
        if site is None:  # FK RESTRICT: no debería ocurrir
            raise SiemNotAuthorizedError("The source has no site")
        outcome = self._normalize(source, records, now)
        inserted = self._store(source, sensor, outcome.rows)
        duplicates = len(outcome.rows) - len(inserted)
        dropped = 0
        if stats:
            dropped = sum(
                int(stats.get(key) or 0)
                for key in ("dropped_oversize", "dropped_peer", "dropped_rate", "spool_dropped")
            )
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        session.add(
            SiemBatch(
                source_id=source.id,
                site_id=source.site_id,
                batch_id=batch_id,
                origin=origin,
                received_at=now,
                records=len(records),
                accepted=len(inserted),
                duplicates=duplicates,
                rejected=sum(outcome.rejected.values()),
                reject_reasons=dict(outcome.rejected) or None,
                stats=stats,
                processing_ms=elapsed_ms,
            )
        )
        self._update_source(source, records, outcome, inserted, duplicates, dropped, now, origin)
        context = IngestedSiem(source, site, sensor, now, [row_id for row_id, _ in inserted])
        if context.event_ids:
            for analyzer in self._analyzers:
                analyzer(session, self._settings, context)
        session.commit()
        return SiemBatchAccepted(
            batch_id=batch_id,
            duplicate=False,
            records=len(records),
            accepted=len(inserted),
            duplicates=duplicates,
            rejected=sum(outcome.rejected.values()),
            reject_reasons=dict(outcome.rejected),
        )

    def _spend_quota(self, source: SiemSource, count: int, now: datetime) -> None:
        start = source.quota_window_start
        if start is None or now - start >= QUOTA_WINDOW or now < start:
            source.quota_window_start = now
            source.quota_window_count = 0
            start = now
        # Un lote nunca supera SIEM_MAX_RECORDS_PER_BATCH; si la cuota es menor que un lote, el
        # primer lote de la ventana pasa igualmente (si no, nunca entraría ninguno).
        if source.quota_window_count > 0 and source.quota_window_count + count > (
            source.max_events_per_minute
        ):
            retry = (start + QUOTA_WINDOW - now).total_seconds()
            source.last_error_code = "siem_quota"
            source.last_error_at = now
            # El error de cuota se guarda (salud de la fuente) aunque el lote se rechace.
            self._session.commit()
            raise SiemQuotaError(
                "SIEM source quota exceeded, retry later",
                retry,
                "siem_quota",
                [{"reason": "siem_quota"}],
            )
        source.quota_window_count += count

    def _normalize(
        self, source: SiemSource, records: Sequence[RawRecord], now: datetime
    ) -> _Outcome:
        settings = self._settings
        connector = get_connector(source.source_type)
        outcome = _Outcome()
        if connector is None:
            outcome.rejected["unknown_connector"] += len(records)
            return outcome
        ctx = NormalizeContext(
            config=dict(source.config or {}), raw_store_bytes=settings.siem_raw_store_bytes
        )
        limit_future = now + timedelta(seconds=settings.sensor_max_clock_skew_seconds)
        retention = effective_retention_days(source, settings)
        oldest = now - timedelta(days=retention) if retention else None
        max_bytes = settings.siem_max_record_bytes
        seen: set[str] = set()
        for record in records:
            if len(record.raw.encode("utf-8", "surrogatepass")) > max_bytes:
                outcome.rejected["too_large"] += 1
                continue
            try:
                event = connector.normalize(record, ctx)
                event.validate()
            except RecordRejectedError as exc:
                outcome.rejected[exc.reason] += 1
                continue
            except Exception:
                # Un normalizador con un bug no tumba el lote: el registro se rechaza y se
                # registra el fallo (sin el contenido, que puede ser sensible).
                logger.exception(
                    "siem normalizer failed", extra={"source_type": source.source_type}
                )
                outcome.rejected["normalizer_error"] += 1
                continue
            collected = record.collected_at
            if collected is not None and collected > limit_future:
                collected = now
            observed = event.observed_at
            quality = "source"
            if observed is None:
                observed = collected or now
                quality = "receiver"
            elif observed > limit_future:
                observed = collected if collected is not None and collected <= now else now
                quality = "clamped"
            if oldest is not None and observed < oldest:
                outcome.rejected["too_old"] += 1
                continue
            dedup = fields.identity_hash(source.source_type, event.identity)
            if dedup in seen:
                # Duplicado dentro del mismo lote: lo cuenta el recuento de duplicados.
                outcome.rows.append({"__dup__": True})
                continue
            seen.add(dedup)
            outcome.rows.append(
                self._row(
                    source,
                    event,
                    record,
                    dedup,
                    observed,
                    collected,
                    quality,
                    now,
                    connector.version,
                )
            )
            if quality == "source" and (outcome.newest is None or observed > outcome.newest):
                outcome.newest = observed
        return outcome

    @staticmethod
    def _row(
        source: SiemSource,
        event: NormalizedEvent,
        record: RawRecord,
        dedup: str,
        observed: datetime,
        collected: datetime | None,
        quality: str,
        now: datetime,
        version: str,
    ) -> dict[str, Any]:
        return {
            "event_id": uuid.uuid4(),
            "source_id": source.id,
            "site_id": source.site_id,
            "sensor_id": source.sensor_id if record.transport != "upload" else None,
            "dedup_key": dedup,
            "schema_version": SCHEMA_VERSION,
            "normalization_version": f"{source.source_type}/{version}"[:32],
            "source_type": source.source_type,
            "event_type": event.event_type[:48],
            "category": event.category,
            "observed_at": observed,
            "collected_at": collected,
            "received_at": now,
            "time_quality": quality,
            "severity": event.severity,
            "source_severity": event.source_severity[:32] if event.source_severity else None,
            "confidence": event.confidence,
            "hostname": event.hostname,
            "src_ip": event.src_ip,
            "dst_ip": event.dst_ip,
            "src_port": event.src_port,
            "dst_port": event.dst_port,
            "protocol": event.protocol,
            "username": event.username,
            "process_name": event.process_name,
            "action": event.action,
            "outcome": event.outcome,
            "signature_id": event.signature_id,
            "rule_id": event.rule_id,
            "message": event.message,
            "tags": event.tags,
            "mitre_techniques": event.mitre_techniques,
            "external_id": event.external_id,
            "flow_ref": event.flow_ref,
            "raw_reference": record.reference[:255],
            "evidence_hash": fields.sha256_text(record.raw),
            "raw_excerpt": event.excerpt,
            "data": fields.data(event.data) if event.data else None,
        }

    def _store(
        self, source: SiemSource, sensor: Sensor | None, rows: list[dict[str, Any]]
    ) -> list[tuple[int, str]]:
        real = [row for row in rows if "__dup__" not in row]
        inserted: list[tuple[int, str]] = []
        for start in range(0, len(real), INSERT_CHUNK):
            chunk = real[start : start + INSERT_CHUNK]
            result = self._session.execute(
                pg_insert(SiemEvent)
                .values(chunk)
                .on_conflict_do_nothing(constraint="uq_siem_events_source_dedup")
                .returning(SiemEvent.id, SiemEvent.dedup_key)
            )
            inserted.extend((int(r[0]), str(r[1])) for r in result.all())
        return inserted

    def _update_source(
        self,
        source: SiemSource,
        records: Sequence[RawRecord],
        outcome: _Outcome,
        inserted: list[tuple[int, str]],
        duplicates: int,
        dropped: int,
        now: datetime,
        origin: str,
    ) -> None:
        rejected = sum(outcome.rejected.values())
        source.events_received += len(records)
        source.events_accepted += len(inserted)
        source.events_rejected += rejected
        source.events_duplicate += duplicates
        source.events_dropped += dropped
        source.last_batch_records = len(records)
        source.last_batch_rejected = rejected
        if records and rejected == len(records):
            # Nada se pudo normalizar: probablemente el formato no es el del conector.
            source.last_error_code = "all_records_rejected"
            source.last_error_at = now
        else:
            source.last_success_at = now
        if outcome.newest is not None:
            if source.last_event_at is None or outcome.newest > source.last_event_at:
                source.last_event_at = outcome.newest
            if origin == "sensor":
                # Retraso del lote: del evento más reciente a su recepción. Una importación
                # manual de datos históricos no es "retraso" de la fuente.
                source.lag_seconds = max(0, int((now - outcome.newest).total_seconds()))
