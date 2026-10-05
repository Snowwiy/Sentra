"""State machine y reglas puras de los incidentes (Fase 4K), sin base de datos.

Toda decisión sobre estados vive aquí: rutas, servicio y UI preguntan a este módulo en vez
de repetir `if status == ...`. Cambiar el flujo es cambiar TRANSITIONS (y sus tests).
"""

from app.models.alert import AlertSeverity
from app.models.detection import DetectionConfidence, DetectionSeverity
from app.models.incident import (
    LEVEL_RANK,
    IncidentConfidence,
    IncidentLevel,
    IncidentStatus,
)

S = IncidentStatus

# Transiciones de trabajo (PATCH status). resolved y closed tienen acción propia porque
# exigen datos (categoría de resolución) o permisos distintos (cerrar es de admin).
TRANSITIONS: dict[IncidentStatus, frozenset[IncidentStatus]] = {
    S.OPEN: frozenset({S.TRIAGE, S.INVESTIGATING}),
    S.TRIAGE: frozenset({S.INVESTIGATING, S.RESOLVED}),
    S.INVESTIGATING: frozenset({S.CONTAINED, S.RESOLVED}),
    S.CONTAINED: frozenset({S.INVESTIGATING, S.RESOLVED}),
    S.RESOLVED: frozenset({S.CLOSED, S.INVESTIGATING}),
    # closed -> open solo mediante la acción explícita reopen (admin).
    S.CLOSED: frozenset(),
    # merged es terminal: el caso vivo es el incidente que lo absorbió.
    S.MERGED: frozenset(),
}

# Destinos que no se alcanzan con un PATCH de estado sino con su acción dedicada.
ACTION_ONLY = frozenset({S.RESOLVED, S.CLOSED, S.OPEN, S.MERGED})

# Un caso cerrado o fusionado no admite cambios (ni notas ni adjuntos) salvo reopen: así
# nada modifica en silencio un caso que alguien dio por terminado.
FROZEN = frozenset({S.CLOSED, S.MERGED})


def can_transition(current: IncidentStatus, target: IncidentStatus) -> bool:
    return target in TRANSITIONS[current]


def patch_targets(current: IncidentStatus) -> list[IncidentStatus]:
    """Estados alcanzables con PATCH desde `current`, en el orden del flujo."""
    return [s for s in IncidentStatus if s in TRANSITIONS[current] and s not in ACTION_ONLY]


def can_resolve(current: IncidentStatus) -> bool:
    return can_transition(current, S.RESOLVED)


def can_close(current: IncidentStatus) -> bool:
    return can_transition(current, S.CLOSED)


def can_reopen(current: IncidentStatus) -> bool:
    return current == S.CLOSED


def is_frozen(current: IncidentStatus) -> bool:
    return current in FROZEN


# --- Severity / priority / confidence --------------------------------------------------------

_DETECTION_SEVERITY = {
    # "informational" no existe en la escala de incidentes: un caso abierto por algo
    # informativo es, como mínimo, de gravedad baja.
    DetectionSeverity.INFORMATIONAL: IncidentLevel.LOW,
    DetectionSeverity.LOW: IncidentLevel.LOW,
    DetectionSeverity.MEDIUM: IncidentLevel.MEDIUM,
    DetectionSeverity.HIGH: IncidentLevel.HIGH,
    DetectionSeverity.CRITICAL: IncidentLevel.CRITICAL,
}

_ALERT_SEVERITY = {
    AlertSeverity.INFO: IncidentLevel.LOW,
    AlertSeverity.WARNING: IncidentLevel.MEDIUM,
    AlertSeverity.CRITICAL: IncidentLevel.CRITICAL,
}

_CONFIDENCE = {
    DetectionConfidence.LOW: IncidentConfidence.LOW,
    DetectionConfidence.MEDIUM: IncidentConfidence.MEDIUM,
    DetectionConfidence.HIGH: IncidentConfidence.HIGH,
}
_LEVELS = list(IncidentLevel)


def severity_from_detection(severity: DetectionSeverity) -> IncidentLevel:
    return _DETECTION_SEVERITY[severity]


def severity_from_alert(severity: AlertSeverity) -> IncidentLevel:
    return _ALERT_SEVERITY[severity]


def confidence_from_detections(values: list[DetectionConfidence]) -> IncidentConfidence | None:
    """La mayor confianza de la evidencia real; None sin detecciones (no se inventa)."""
    if not values:
        return None
    best = max(values, key=lambda c: list(DetectionConfidence).index(c))
    return _CONFIDENCE[best]


def max_level(levels: list[IncidentLevel]) -> IncidentLevel:
    return max(levels, key=lambda level: LEVEL_RANK[level])


def suggested_priority(
    severity: IncidentLevel, risk_level: str | None, criticality: str | None
) -> IncidentLevel:
    """Prioridad SUGERIDA para un caso nuevo; el analista la confirma o la cambia.

    Parte de la gravedad y sube un escalón si el contexto lo justifica (riesgo del activo
    high/critical según 4I o criticidad de negocio high). Deliberadamente no es un mapeo
    1:1 ni deja que el riesgo decida por sí solo: nunca baja la prioridad por debajo de la
    gravedad ni sube más de un escalón.
    """
    rank = LEVEL_RANK[severity]
    if risk_level in ("high", "critical") or criticality == "high":
        rank += 1
    return _LEVELS[min(rank, len(_LEVELS) - 1)]


def incident_key(number: int) -> str:
    return f"INC-{number:06d}"
