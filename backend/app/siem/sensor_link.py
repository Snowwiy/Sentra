"""Relación sensor ↔ fuentes SIEM: bloque `config.siem` del heartbeat y estado reportado.

El servidor solo envía ALIAS de entrada y límites: nunca puertos, rutas, direcciones ni
órdenes. El sensor reenvía únicamente la intersección entre lo que su operador declaró en
sensor.toml y las fuentes que un admin habilitó aquí (doble control, como NDR).
"""

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models.siem import SiemSource
from app.models.site import Sensor
from app.schemas.siem import SensorSiemConfig, SensorSiemSource, SiemHealthIn
from app.sensors.catalog import SIEM_CAPABILITY

SIEM_SPOOL_MAX_MB = 128
SIEM_SPOOL_MAX_AGE_HOURS = 24
FLUSH_INTERVAL_SECONDS = 5


def is_siem_capable(sensor: Sensor) -> bool:
    return SIEM_CAPABILITY in (sensor.capabilities or [])


def sensor_siem_config(
    session: Session, settings: Settings, sensor: Sensor, jobs_enabled: bool
) -> SensorSiemConfig | None:
    """Bloque `config.siem` o None para sensores sin la capacidad (anteriores a 0.9.0). Un
    sensor deshabilitado, de un site inactivo o con versión no soportada recibe la lista
    vacía: deja de reenviar en el siguiente heartbeat."""
    if not is_siem_capable(sensor):
        return None
    rows = (
        list(
            session.scalars(
                select(SiemSource)
                .where(
                    SiemSource.sensor_id == sensor.id,
                    SiemSource.site_id == sensor.site_id,
                    SiemSource.enabled.is_(True),
                    SiemSource.transport == "sensor",
                    SiemSource.input_name.is_not(None),
                )
                .order_by(SiemSource.id)
            )
        )
        if jobs_enabled
        else []
    )
    return SensorSiemConfig(
        enabled=bool(rows),
        revision=sum(row.revision for row in rows),
        sources=[
            SensorSiemSource(
                source_id=row.public_id,
                input=str(row.input_name),
                source_type=row.source_type,
                revision=row.revision,
            )
            for row in rows
        ],
        max_records_per_batch=settings.siem_max_records_per_batch,
        max_batch_bytes=settings.sensor_max_request_kb * 1024,
        max_record_bytes=settings.siem_max_record_bytes,
        flush_interval_seconds=FLUSH_INTERVAL_SECONDS,
        spool_max_mb=SIEM_SPOOL_MAX_MB,
        spool_max_age_hours=SIEM_SPOOL_MAX_AGE_HOURS,
    )


def record_siem_health(session: Session, sensor: Sensor, body: SiemHealthIn, now: datetime) -> None:
    """Guarda en cada fuente del sensor lo que su receptor reporta (por alias)."""
    by_input = {item.name: item for item in body.inputs}
    sources = list(
        session.scalars(
            select(SiemSource).where(
                SiemSource.sensor_id == sensor.id, SiemSource.enabled.is_(True)
            )
        )
    )
    applied = body.config_revision == sum(source.revision for source in sources)
    for source in sources:
        item = by_input.get(source.input_name or "")
        if item is None:
            # El servidor habilitó la fuente pero el receptor no la reporta: o aún no aplicó
            # la configuración, o el alias no está declarado en su sensor.toml.
            if applied and body.state in ("running", "degraded", "error"):
                source.reported_state = "not_declared"
                source.reported = {"error_code": "input_not_reported"}
                source.reported_at = now
            continue
        source.reported_state = item.state
        source.reported_at = now
        source.reported = item.model_dump(mode="json", exclude={"name", "source_id"})
