"""Política central de lectura de evidencias sensibles de endpoint (Fase 7D.1, H02).

Problema que resuelve: la telemetría avanzada del endpoint (Fase 6E: procesos con su línea
de comando, usuario, ejecutable, hash, firma, padre y conexiones) exige `telemetry:read`, que
el rol viewer no tiene. Pero el motor de detecciones COPIA esos datos a la detección (resumen,
`details`) y a su evidencia (`detection_evidence.data` y `summary`), y de ahí viajan a
incidentes, alertas, informes, herramientas y contexto de IA, que solo piden
`monitoring:read`. Sin una regla común, cada copia era una puerta lateral.

Criterio (explícito, no por expresiones regulares):
- Una evidencia es "de endpoint" si su `source_type` es `endpoint_activity`.
- Una detección es "de endpoint" si su regla es de la categoría `behavior` (BEH-*, que solo
  se alimenta de telemetría 6E) o si alguna de sus evidencias es de endpoint (correlaciones
  y reglas custom que combinen fuentes).
- Sin `telemetry:read`, de lo que es de endpoint solo se entrega la ALLOWLIST de campos
  operativos de abajo (tipo de mecanismo, producto, hallazgos ya clasificados...). Todo lo
  demás se omite y se marca como retenido, en vez de intentar "limpiar" texto libre: un
  resumen o un campo nuevo que el motor añada mañana queda protegido por defecto.

La evidencia original nunca se modifica: solo cambia lo que se serializa para quien lee.
La autorización se decide con los permisos ACTUALES del usuario en cada petición (los roles
se resuelven de la base de datos en cada sesión), así que degradar un rol tiene efecto
inmediato también sobre datos ya generados.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from sqlalchemy import exists, or_, select
from sqlalchemy.sql.elements import ColumnElement

from app.core.permissions import Permission

# Permiso que protege el detalle de endpoint (el mismo que las rutas de telemetría 6E).
ENDPOINT_PERMISSION = Permission.TELEMETRY_READ
ENDPOINT_SOURCE_TYPES = frozenset({"endpoint_activity"})
# BEH-* solo se dispara con señales de telemetría de endpoint (app/detection/rules.py).
ENDPOINT_RULE_CATEGORIES = frozenset({"behavior"})

# Campos de `detection_evidence.data` de endpoint visibles con monitoring:read. Son
# clasificaciones o estados, nunca rutas, usuarios, líneas de comando, hashes ni direcciones.
SAFE_ENDPOINT_EVIDENCE_FIELDS = frozenset(
    {
        "source",
        "action",
        "mechanism",
        "product",
        "disabled",
        "profile",
        "enabled",
        "document_child",
        "cmdline_findings",
        "suspicious_target",
        "unusual_location",
        "protocol",
    }
)
# Claves de `detections.details` visibles con monitoring:read en detecciones de endpoint.
SAFE_ENDPOINT_DETAIL_KEYS = frozenset(
    {
        "findings",
        "mechanism",
        "unusual_location",
        "reason",
        "product",
        "disabled",
        "profile",
        "rule_version",
        "rule_uid",
        "count",
        "window_minutes",
    }
)

WITHHELD_NOTE = "El detalle de la actividad del endpoint requiere el permiso telemetry:read."


@dataclass(frozen=True)
class EvidenceAccess:
    """Qué puede ver quien lee. Se construye siempre desde sus permisos actuales."""

    endpoint: bool

    @classmethod
    def of(cls, permissions: Iterable[Permission]) -> "EvidenceAccess":
        return cls(endpoint=ENDPOINT_PERMISSION in frozenset(permissions))


# Valores con nombre para que una llamada interna diga explícitamente qué nivel usa.
FULL = EvidenceAccess(endpoint=True)
RESTRICTED = EvidenceAccess(endpoint=False)


def is_endpoint_evidence(source_type: str | None) -> bool:
    return source_type in ENDPOINT_SOURCE_TYPES


def is_endpoint_detection(rule_category: str | None, has_endpoint_evidence: bool) -> bool:
    return rule_category in ENDPOINT_RULE_CATEGORIES or has_endpoint_evidence


def endpoint_detection_clause(detection: Any, evidence: Any) -> ColumnElement[bool]:
    """Condición SQL equivalente a `is_endpoint_detection` (listados, búsquedas, informes).

    Recibe las clases (o alias) de Detection y DetectionEvidence para no importar modelos
    aquí: este módulo lo usan servicios que los modelos ya importan.
    """
    return or_(
        detection.rule_category.in_(sorted(ENDPOINT_RULE_CATEGORIES)),
        exists(
            select(evidence.id).where(
                evidence.detection_id == detection.id,
                evidence.source_type.in_(sorted(ENDPOINT_SOURCE_TYPES)),
            )
        ),
    )


def safe_detection_summary(title: str) -> str:
    """Resumen operativo de una detección de endpoint para quien no tiene telemetry:read.

    Solo el título de la regla (texto fijo del catálogo o de la regla custom), nunca los
    datos del host que el motor interpoló en el resumen original.
    """
    return f"{title}. {WITHHELD_NOTE}"


def filter_details(
    details: Mapping[str, Any] | None, access: EvidenceAccess, endpoint: bool
) -> tuple[dict[str, Any] | None, list[str]]:
    """`details` de una detección según el acceso. Devuelve (details, claves retenidas)."""
    if details is None:
        return None, []
    if access.endpoint or not endpoint:
        return dict(details), []
    kept = {k: v for k, v in details.items() if k in SAFE_ENDPOINT_DETAIL_KEYS}
    return kept, sorted(k for k in details if k not in SAFE_ENDPOINT_DETAIL_KEYS)


def filter_evidence_data(
    data: Mapping[str, Any] | None, source_type: str | None, access: EvidenceAccess
) -> tuple[dict[str, Any] | None, list[str]]:
    """`data` de una evidencia según el acceso. Devuelve (data, campos retenidos)."""
    if data is None:
        return None, []
    if access.endpoint or not is_endpoint_evidence(source_type):
        return dict(data), []
    kept = {k: v for k, v in data.items() if k in SAFE_ENDPOINT_EVIDENCE_FIELDS}
    return kept, sorted(k for k in data if k not in SAFE_ENDPOINT_EVIDENCE_FIELDS)


def evidence_summary(
    summary: str, signal_kind: str, source_type: str | None, access: EvidenceAccess
) -> str:
    """Línea del timeline: la original o, si es de endpoint y no hay acceso, una genérica.

    El resumen original de una evidencia de endpoint interpola ejecutable, usuario o destino
    (engine._evidence_summary): no se puede entregar parcialmente.
    """
    if access.endpoint or not is_endpoint_evidence(source_type):
        return summary
    return f"Actividad del endpoint ({signal_kind}). {WITHHELD_NOTE}"


def required_permissions(endpoint_content: bool) -> list[str]:
    """Permisos de contenido que hay que guardar con una copia (informe, IA, herramienta)."""
    return [ENDPOINT_PERMISSION.value] if endpoint_content else []


def missing_permissions(
    required: Iterable[str] | None, permissions: Iterable[Permission]
) -> list[str]:
    """Permisos de contenido guardados con una copia que el lector ya no tiene.

    Un valor desconocido (permiso retirado) cuenta como no concedido: falla cerrado.
    """
    have = {p.value for p in permissions}
    return sorted({str(p) for p in (required or [])} - have)
