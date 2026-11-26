"""Estado de una fuente SIEM, calculado al leer (Fase 7F.1).

`healthy` exige una prueba de vida reciente: un reporte del receptor del sensor (en marcha) o
un lote aceptado. Guardar una configuración deja la fuente en `configured`, nunca en
`healthy`. Un navegador desconectado no cambia nada aquí: el estado es el de la ingesta.
"""

from datetime import datetime, timedelta

from app.core.config import Settings
from app.models.siem import SiemSource
from app.models.site import Sensor

# Un error de cuota o de autorización cuenta como degradación durante este tiempo.
RECENT_ERROR = timedelta(minutes=10)
# Proporción de registros rechazados en el último lote que degrada la fuente.
REJECT_RATIO_DEGRADED = 0.1


def _later(a: datetime | None, b: datetime | None) -> datetime | None:
    if a is None:
        return b
    if b is None:
        return a
    return max(a, b)


def source_status(
    source: SiemSource, sensor: Sensor | None, settings: Settings, now: datetime
) -> tuple[str, list[str]]:
    if not source.enabled:
        return "disabled", []
    reasons: list[str] = []
    rejected_ratio = (
        source.last_batch_rejected / source.last_batch_records if source.last_batch_records else 0.0
    )
    recent_error = (
        source.last_error_code is not None
        and source.last_error_at is not None
        and now - source.last_error_at <= RECENT_ERROR
        and (source.last_success_at is None or source.last_error_at >= source.last_success_at)
    )
    if source.transport == "upload":
        if source.last_success_at is None and source.last_error_at is None:
            return "configured", []
        if recent_error or (source.last_success_at is None and source.last_error_code):
            return "error", [source.last_error_code or "import_failed"]
        if rejected_ratio > 0:
            return "degraded", ["rejected_records"]
        return "healthy", []

    if source.sensor_id is None or sensor is None or sensor.status == "revoked":
        return "error", ["sensor_missing"]
    last_contact = _later(source.reported_at, source.last_success_at)
    if last_contact is None:
        return "configured", []
    offline_after = timedelta(minutes=settings.siem_source_offline_minutes)
    # Offline: ni el receptor reporta ni llegan lotes, o el propio sensor dejó de hablar.
    sensor_stale = sensor.last_seen_at is not None and now - sensor.last_seen_at > offline_after
    if sensor_stale or now - last_contact > offline_after:
        return "offline", ["no_recent_report"]
    if sensor.status != "active":
        return "error", ["sensor_disabled"]
    reported = source.reported or {}
    if source.reported_state in ("error", "not_declared"):
        code = reported.get("error_code") or source.reported_state
        return "error", [str(code)]
    if source.reported_state == "degraded":
        reasons.extend(str(r) for r in reported.get("degraded_reasons") or ["receiver_degraded"])
    if recent_error and source.last_error_code:
        reasons.append(source.last_error_code)
    if source.lag_seconds is not None and source.lag_seconds > settings.siem_lag_degraded_seconds:
        reasons.append("lag")
    if rejected_ratio > REJECT_RATIO_DEGRADED:
        reasons.append("rejected_records")
    if reasons:
        return "degraded", sorted(set(reasons))
    return "healthy", []
