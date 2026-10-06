"""Flujo de trabajo humano de un finding (Fase 5B), sin base de datos.

El estado técnico (match_state: confirmed, probable...) lo decide la evaluación; el estado
de trabajo (status) lo deciden las personas. Son independientes: un finding "confirmed"
puede estar "acknowledged" y uno "potential" puede marcarse "false_positive".

Toda regla de transición vive aquí: servicio, rutas y UI preguntan a este módulo.
"""

from collections.abc import Mapping

OPEN = "open"
ACKNOWLEDGED = "acknowledged"
MITIGATING = "mitigating"
RESOLVED = "resolved"
ACCEPTED_RISK = "accepted_risk"
FALSE_POSITIVE = "false_positive"

STATUSES = (OPEN, ACKNOWLEDGED, MITIGATING, RESOLVED, ACCEPTED_RISK, FALSE_POSITIVE)
# Necesitan trabajo: cuentan en las tarjetas "abiertas", en el riesgo y en las alertas.
ACTIVE_STATUSES = frozenset({OPEN, ACKNOWLEDGED, MITIGATING})
# Decisiones humanas que la evaluación respeta mientras la evidencia no cambie.
HUMAN_DECISIONS = frozenset({ACCEPTED_RISK, FALSE_POSITIVE})

# Resoluciones automáticas (la evaluación) y manual (una persona, con motivo).
RESOLVED_BY_INVENTORY = "resolved_by_inventory_change"
RESOLVED_BY_REMOVAL = "resolved_by_component_removal"
RESOLVED_BY_CATALOG = "resolved_by_catalog_update"
RESOLVED_MANUAL = "manual"
AUTO_RESOLUTIONS = frozenset({RESOLVED_BY_INVENTORY, RESOLVED_BY_REMOVAL, RESOLVED_BY_CATALOG})

# Acciones de la API -> estado destino.
ACTIONS: Mapping[str, str] = {
    "acknowledge": ACKNOWLEDGED,
    "mitigating": MITIGATING,
    "resolve": RESOLVED,
    "accept-risk": ACCEPTED_RISK,
    "false-positive": FALSE_POSITIVE,
    "reopen": OPEN,
}

# Desde qué estados se puede ejecutar cada acción.
_FROM: Mapping[str, frozenset[str]] = {
    "acknowledge": frozenset({OPEN}),
    "mitigating": frozenset({OPEN, ACKNOWLEDGED}),
    "resolve": frozenset({OPEN, ACKNOWLEDGED, MITIGATING}),
    "accept-risk": frozenset({OPEN, ACKNOWLEDGED, MITIGATING}),
    "false-positive": frozenset({OPEN, ACKNOWLEDGED, MITIGATING, ACCEPTED_RISK}),
    # Deshacer una decisión humana o una resolución manual (admin).
    "reopen": frozenset({RESOLVED, ACCEPTED_RISK, FALSE_POSITIVE}),
}
# Acciones que exigen motivo escrito.
REASON_REQUIRED = frozenset({"resolve", "accept-risk", "false-positive", "reopen"})
# Acciones solo de administrador (vulnerabilities:admin).
ADMIN_ACTIONS = frozenset({"accept-risk", "false-positive", "reopen"})

# Auditoría de cada acción (ver docs/vulnerability-management.md).
AUDIT_ACTIONS: Mapping[str, str] = {
    "acknowledge": "vulnerability_finding_acknowledged",
    "mitigating": "vulnerability_finding_updated",
    "resolve": "vulnerability_finding_resolved",
    "accept-risk": "vulnerability_risk_accepted",
    "false-positive": "vulnerability_false_positive",
    "reopen": "vulnerability_finding_reopened",
}

# Estados técnicos en los que la evidencia SÍ indica vulnerable: resolver a mano entonces
# exige confirmarlo explícitamente (la evidencia dice lo contrario).
EVIDENCE_VULNERABLE = frozenset({"confirmed", "probable"})


def can_apply(action: str, status: str) -> bool:
    return status in _FROM.get(action, frozenset())


def available_actions(status: str, *, admin: bool) -> list[str]:
    return [
        action
        for action in ACTIONS
        if can_apply(action, status) and (admin or action not in ADMIN_ACTIONS)
    ]
