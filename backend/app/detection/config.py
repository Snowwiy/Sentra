"""Configuración centralizada del motor: umbrales y ventanas de todas las reglas.

Las reglas nunca leen variables de entorno ni tienen ventanas propias escritas a mano: todo
pasa por DetectionConfig, construida una vez desde Settings (DETECTION_*).
"""

from dataclasses import dataclass, field
from datetime import timedelta

from app.core.config import Settings, parse_name_list
from app.models.detection import DetectionSeverity


@dataclass(frozen=True)
class DetectionConfig:
    enabled: bool = True
    auth_failure_threshold: int = 5
    auth_failure_window: timedelta = timedelta(minutes=5)
    correlation_window: timedelta = timedelta(minutes=15)
    change_window: timedelta = timedelta(minutes=60)
    repeat_threshold: int = 3
    repeat_window: timedelta = timedelta(hours=24)
    max_event_age: timedelta = timedelta(hours=24)
    signal_retention: timedelta = timedelta(hours=48)
    # Nombres en minúsculas.
    security_services: frozenset[str] = field(
        default_factory=lambda: frozenset({"windefend", "mpssvc", "eventlog"})
    )
    # None: las detecciones no abren alertas.
    alert_min_severity: DetectionSeverity | None = DetectionSeverity.HIGH
    disabled_rules: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def from_settings(cls, settings: Settings) -> "DetectionConfig":
        alert = settings.detection_alert_min_severity
        return cls(
            enabled=settings.detection_enabled,
            auth_failure_threshold=settings.detection_auth_failure_threshold,
            auth_failure_window=timedelta(minutes=settings.detection_auth_failure_window_minutes),
            correlation_window=timedelta(minutes=settings.detection_correlation_window_minutes),
            change_window=timedelta(minutes=settings.detection_change_window_minutes),
            repeat_threshold=settings.detection_repeat_threshold,
            repeat_window=timedelta(minutes=settings.detection_repeat_window_minutes),
            max_event_age=timedelta(hours=settings.detection_max_event_age_hours),
            signal_retention=timedelta(hours=settings.detection_signal_retention_hours),
            security_services=frozenset(
                name.lower() for name in parse_name_list(settings.detection_security_services)
            ),
            alert_min_severity=None if alert == "off" else DetectionSeverity(alert),
            disabled_rules=frozenset(parse_name_list(settings.detection_disabled_rules)),
        )

    def windows(self) -> dict[str, int]:
        """Ventanas en minutos, para documentarlas en GET /detection-rules."""
        return {
            "auth_failure_window": int(self.auth_failure_window.total_seconds() // 60),
            "correlation_window": int(self.correlation_window.total_seconds() // 60),
            "change_window": int(self.change_window.total_seconds() // 60),
            "repeat_window": int(self.repeat_window.total_seconds() // 60),
        }
