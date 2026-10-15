"""Frases deterministas para los resúmenes de informes (Fase 5E). Sin modelo de lenguaje.

Cada frase sale de un número o una lista concreta del snapshot, con plural correcto y sin
adjetivos que el dato no respalde ("3 activos presentan nivel de riesgo crítico", nunca "su
organización está bajo ataque"). Son funciones puras: tests/test_reports.py comprueba el
texto exacto, así que un cambio de redacción exige subir template_version del tipo.
"""

from collections.abc import Mapping

_LEVELS_ES = {
    "informational": "informativo",
    "low": "bajo",
    "medium": "medio",
    "high": "alto",
    "critical": "crítico",
}
_SEVERITY_ES = {
    "informational": "informativa",
    "low": "baja",
    "medium": "media",
    "high": "alta",
    "critical": "crítica",
}


def level_es(level: str) -> str:
    return _LEVELS_ES.get(level, level)


def severity_es(severity: str) -> str:
    return _SEVERITY_ES.get(severity, severity)


def count_phrase(count: int, singular: str, plural: str) -> str:
    """'1 activo', '3 activos'."""
    return f"{count} {singular if count == 1 else plural}"


def risk_level_sentence(count: int, level: str) -> str:
    name = level_es(level)
    if count == 0:
        return f"Ningún activo presenta nivel de riesgo {name}."
    if count == 1:
        return f"1 activo presenta nivel de riesgo {name}."
    return f"{count} activos presentan nivel de riesgo {name}."


def monitored_assets_sentence(total: int, online: int, offline: int) -> str:
    if total == 0:
        return "No hay activos monitorizados en el alcance del informe."
    return (
        f"{count_phrase(total, 'activo monitorizado', 'activos monitorizados')}:"
        f" {online} en línea y {offline} sin conexión."
    )


def incidents_sentence(open_now: int, opened: int, resolved: int) -> str:
    return (
        f"{count_phrase(open_now, 'incidente abierto', 'incidentes abiertos')} a la hora de"
        f" corte; {opened} abiertos y {resolved} resueltos en el período."
    )


def detections_sentence(total: int, by_severity: Mapping[str, int]) -> str:
    if total == 0:
        return "No hubo detecciones en el período."
    critical = by_severity.get("critical", 0)
    high = by_severity.get("high", 0)
    return (
        f"{count_phrase(total, 'detección', 'detecciones')} en el período"
        f" ({critical} de severidad crítica y {high} alta)."
    )


def vulnerabilities_sentence(confirmed: int, critical_confirmed: int, potential: int) -> str:
    if confirmed == 0 and potential == 0:
        return "No hay findings de vulnerabilidad activos."
    found = count_phrase(
        confirmed,
        "vulnerabilidad confirmada o probable activa",
        "vulnerabilidades confirmadas o probables activas",
    )
    return f"{found} ({critical_confirmed} críticas) y {potential} potenciales sin confirmar."


def response_sentence(total: int, failed: int) -> str:
    if total == 0:
        return "No hubo ejecuciones de Response en el período."
    return (
        f"{count_phrase(total, 'ejecución de Response', 'ejecuciones de Response')} en el"
        f" período; {count_phrase(failed, 'terminó', 'terminaron')} en fallo o timeout."
    )


def risk_changes_sentence(up: int, down: int) -> str:
    if up == 0 and down == 0:
        return "El riesgo de los activos no cambió de nivel en el período."
    return f"El riesgo subió de nivel {up} veces y bajó {down} veces en el período."


def overall_status(critical_assets: int, critical_incidents: int, critical_detections: int) -> str:
    """Estado general del resumen ejecutivo: solo hechos contados, sin especular."""
    if critical_assets or critical_incidents or critical_detections:
        parts = []
        if critical_assets:
            parts.append(count_phrase(critical_assets, "activo", "activos") + " en riesgo crítico")
        if critical_incidents:
            parts.append(
                count_phrase(critical_incidents, "incidente crítico", "incidentes críticos")
                + " abiertos"
            )
        if critical_detections:
            parts.append(
                count_phrase(critical_detections, "detección crítica", "detecciones críticas")
                + " activas"
            )
        return "Requiere atención: " + ", ".join(parts) + "."
    return "Sin elementos críticos abiertos a la hora de corte."
