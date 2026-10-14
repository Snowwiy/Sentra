"""Playbooks declarativos (Fase 5D): una lista ordenada de acciones del catálogo.

Un playbook NO es un script: cada paso es un `action_id` del catálogo con parámetros que
valida el modelo de esa acción (extra=forbid), más `on_success`/`on_failure` de un conjunto
cerrado y un plazo acotado. No hay variables, plantillas, expresiones, bucles ni condiciones:
nada que se pueda evaluar como código. Fail-stop por defecto.

Los built-in viven aquí (versionados en código) y se sincronizan con la tabla `playbooks`
al leer el catálogo: un cambio de pasos en una versión nueva de Sentra crea una versión nueva
del playbook sin tocar las ejecuciones pasadas.
"""

from dataclasses import dataclass
from typing import Any, Literal

from pydantic import Field, ValidationError, field_validator

from app.core.permissions import Permission
from app.response.catalog import RISK_RANK, ActionDefinition, get_action, minimum_role
from app.schemas.common import RequestModel

MAX_STEPS = 10
OnSuccess = Literal["continue", "stop"]
OnFailure = Literal["stop", "continue"]


class PlaybookStepIn(RequestModel):
    action_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]{1,63}$")
    parameters: dict[str, Any] = Field(default_factory=dict)
    on_success: OnSuccess = "continue"
    # "continue" solo se admite en pasos LOW (lecturas/reevaluaciones): seguir tras el fallo
    # de una mutación podría dejar el caso a medias.
    on_failure: OnFailure = "stop"
    timeout_seconds: int | None = Field(default=None, ge=10, le=3600)

    @field_validator("parameters")
    @classmethod
    def _small(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(value) > 10:
            raise ValueError("too many parameters")
        return value


class PlaybookError(ValueError):
    """Definición de playbook inválida: código estable y mensaje."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class ValidatedSteps:
    steps: list[dict[str, Any]]
    risk_level: str
    permissions: frozenset[Permission]
    requires_confirmation: bool

    @property
    def required_role(self) -> str:
        return minimum_role(self.permissions)


def validate_steps(raw_steps: list[PlaybookStepIn] | list[dict[str, Any]]) -> ValidatedSteps:
    """Valida los pasos contra el catálogo y devuelve su forma normalizada (la que se guarda)."""
    if not raw_steps:
        raise PlaybookError("playbook_empty", "A playbook needs at least one step")
    if len(raw_steps) > MAX_STEPS:
        raise PlaybookError("playbook_too_long", f"At most {MAX_STEPS} steps")
    steps: list[dict[str, Any]] = []
    permissions: set[Permission] = set()
    risk = "low"
    confirm = False
    for order, raw in enumerate(raw_steps, start=1):
        try:
            if isinstance(raw, PlaybookStepIn):
                step = raw
            elif not isinstance(raw, dict):
                raise PlaybookError("playbook_step_invalid", f"Step {order} is invalid")
            else:
                # Forma guardada (versión o copia del run): lleva `order`, que es posicional y
                # se recalcula; todo lo demás se revalida contra el catálogo actual.
                stored = {key: value for key, value in raw.items() if key != "order"}
                step = PlaybookStepIn.model_validate(stored)
        except ValidationError as exc:
            raise PlaybookError("playbook_step_invalid", f"Step {order} is invalid") from exc
        action = get_action(step.action_id)
        if action is None:
            raise PlaybookError("playbook_unknown_action", f"Step {order}: unknown action")
        if not action.available:
            raise PlaybookError(
                "playbook_action_unavailable", f"Step {order}: action not available"
            )
        if action.target_type != "asset":
            raise PlaybookError(
                "playbook_action_target", f"Step {order}: playbooks only run asset actions"
            )
        params = _validate_params(action, step.parameters, order)
        if step.on_failure == "continue" and RISK_RANK[action.risk_level] > RISK_RANK["low"]:
            raise PlaybookError(
                "playbook_unsafe_continue",
                f"Step {order}: only low-risk steps may continue after a failure",
            )
        timeout = min(step.timeout_seconds or action.timeout_seconds, 3600)
        steps.append(
            {
                "order": order,
                "action_id": action.id,
                "parameters": params,
                "on_success": step.on_success,
                "on_failure": step.on_failure,
                "timeout_seconds": timeout,
            }
        )
        permissions |= action.required_permissions
        if RISK_RANK[action.risk_level] > RISK_RANK[risk]:
            risk = action.risk_level
        confirm = confirm or action.requires_confirmation
    return ValidatedSteps(steps, risk, frozenset(permissions), confirm)


def _validate_params(
    action: ActionDefinition, params: dict[str, Any], order: int
) -> dict[str, Any]:
    try:
        model = action.params_model.model_validate(params)
    except ValidationError as exc:
        raise PlaybookError(
            "playbook_step_params", f"Step {order}: invalid parameters for {action.id}"
        ) from exc
    return model.model_dump(mode="json")


@dataclass(frozen=True)
class BuiltinPlaybook:
    key: str
    version: int
    name: str
    description: str
    steps: tuple[dict[str, Any], ...]


# Pocos y útiles. Solo acciones LOW que existen de verdad: un analyst puede ejecutarlos.
# Subir `version` al cambiar los pasos (las ejecuciones pasadas conservan su copia).
BUILTIN_PLAYBOOKS: tuple[BuiltinPlaybook, ...] = (
    BuiltinPlaybook(
        key="investigate_endpoint",
        version=1,
        name="Investigar endpoint",
        description="Recoge del agente inventario (incluye red y conexiones), procesos y eventos;"
        " después reevalúa detecciones, recalcula el riesgo y construye el timeline.",
        steps=(
            {"action_id": "collect_inventory"},
            {"action_id": "collect_processes"},
            {"action_id": "collect_events"},
            {"action_id": "reevaluate_detections"},
            {"action_id": "recalculate_risk"},
            {"action_id": "collect_timeline"},
        ),
    ),
    BuiltinPlaybook(
        key="refresh_asset_analysis",
        version=1,
        name="Refrescar análisis del activo",
        description="Repriorización de vulnerabilidades con la inteligencia local, reevaluación"
        " de detecciones, recálculo de riesgo y resumen de evidencia. No necesita agente.",
        steps=(
            {"action_id": "refresh_threat_context"},
            {"action_id": "reevaluate_detections"},
            {"action_id": "recalculate_risk"},
            {"action_id": "collect_response_bundle"},
        ),
    ),
    BuiltinPlaybook(
        key="investigate_detection",
        version=1,
        name="Investigar detección",
        description="Timeline del activo de la detección, reevaluación de detecciones, recálculo"
        " de riesgo y resumen de evidencia. No necesita agente ni cambia el caso.",
        steps=(
            {"action_id": "collect_timeline"},
            {"action_id": "reevaluate_detections"},
            {"action_id": "recalculate_risk"},
            {"action_id": "collect_response_bundle"},
        ),
    ),
)
