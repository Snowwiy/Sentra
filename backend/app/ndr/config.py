"""Configuración de captura NDR que el servidor impone a cada sensor (Fase 7E.1).

El servidor solo envía ALIAS de interfaz y límites: nunca nombres de dispositivo, filtros BPF
ni órdenes. El sensor captura únicamente la intersección entre lo que su operador declaró en
sensor.toml y lo que aquí se aprueba (doble control), y recorta otra vez cada límite.
"""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models.ndr import NdrCaptureConfig
from app.models.site import Sensor
from app.schemas.ndr import SensorNdrConfig
from app.sensors.catalog import NDR_CAPABILITY

# Spool local del sensor para NDR: tope que el servidor ordena (el sensor aplica el menor
# entre este y el de su sensor.toml). Un día de lotes cubre una caída larga del enlace.
NDR_SPOOL_MAX_MB = 256
NDR_SPOOL_MAX_AGE_HOURS = 24


def is_capable(sensor: Sensor) -> bool:
    return NDR_CAPABILITY in (sensor.capabilities or [])


def capture_config(session: Session, sensor_id: int) -> NdrCaptureConfig | None:
    return session.scalar(select(NdrCaptureConfig).where(NdrCaptureConfig.sensor_id == sensor_id))


def sensor_ndr_config(
    session: Session, settings: Settings, sensor: Sensor, jobs_enabled: bool
) -> SensorNdrConfig | None:
    """Bloque `config.ndr` o None para sensores sin la capacidad (anteriores a 0.8.0 o sin
    [ndr] local). Un sensor deshabilitado, de un site inactivo o con versión no soportada
    recibe enabled=false: deja de capturar en el siguiente heartbeat."""
    if not is_capable(sensor):
        return None
    row = capture_config(session, sensor.id)
    enabled = bool(row is not None and row.enabled and row.interfaces and jobs_enabled)
    return SensorNdrConfig(
        enabled=enabled,
        revision=row.revision if row is not None else 0,
        interfaces=list(row.interfaces) if row is not None and enabled else [],
        promiscuous=row.promiscuous if row is not None else False,
        snaplen=row.snaplen if row is not None else 512,
        max_flows=row.max_flows if row is not None else 20_000,
        max_packets_per_second=row.max_packets_per_second if row is not None else 20_000,
        max_cpu_percent=row.max_cpu_percent if row is not None else 40,
        export_interval_seconds=row.export_interval_seconds if row is not None else 60,
        flow_idle_timeout_seconds=row.flow_idle_timeout_seconds if row is not None else 120,
        flow_active_timeout_seconds=row.flow_active_timeout_seconds if row is not None else 300,
        max_records_per_batch=settings.ndr_max_records_per_batch,
        max_batch_bytes=settings.sensor_max_request_kb * 1024,
        spool_max_mb=NDR_SPOOL_MAX_MB,
        spool_max_age_hours=NDR_SPOOL_MAX_AGE_HOURS,
        arp_metadata=row.arp_metadata if row is not None else True,
        dns_metadata=row.dns_metadata if row is not None else False,
        dhcp_metadata=row.dhcp_metadata if row is not None else True,
        tls_metadata=row.tls_metadata if row is not None else False,
    )
