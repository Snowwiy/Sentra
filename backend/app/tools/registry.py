"""Tipos del registro de herramientas del Analyst Tool Engine (Fase 7A).

Una herramienta es una función con nombre estable y versión que hace UNA cosa sobre datos que
Sentra ya tiene (o delega UNA acción en el Response Engine), con:
- modelos Pydantic de entrada (extra=forbid) y de salida, publicados como JSON Schema;
- permisos de dominio que se exigen en el backend además de tools:execute;
- alcance (global, site, activo o incidente), riesgo y política de ejecución;
- plazo (statement_timeout), filas máximas y capacidades necesarias.

El registro es CERRADO (app/tools/catalog.py): no se pueden registrar herramientas desde la
API ni existe una herramienta genérica ("run", "http", "sql", "shell"). `validate_registry`
se ejecuta al importar el catálogo y rechaza cualquier modelo de entrada con un campo cuyo
nombre sugiera un comando, script, URL o consulta: una consola o un modelo futuro (7B/7C)
no puede pedir nada que un operador no pueda pedir con los mismos permisos por la API.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.permissions import ROLE_PERMISSIONS, Permission, Role
from app.models.user import User
from app.services.audit_service import Actor

ToolCategory = Literal["read", "investigation", "action"]
ToolScope = Literal["global", "site", "asset", "incident"]
ToolRisk = Literal["none", "low", "medium", "high", "critical"]
# direct: se ejecuta en la petición. preview_confirm: primero una vista previa sin efectos
# (estado previewed) y después una confirmación explícita, que queda registrada.
ExecutionPolicy = Literal["direct", "preview_confirm"]

# Nombres de campo de entrada prohibidos en todo el registro (comprobado al importar y en
# los tests): ninguna herramienta acepta código, comandos, rutas de ejecutable ni URLs.
FORBIDDEN_INPUT_FIELDS = frozenset(
    {
        "command",
        "cmd",
        "commandline",
        "command_line",
        "script",
        "shell",
        "exec",
        "executable",
        "code",
        "sql",
        "url",
        "uri",
        "template",
        "expression",
        "eval",
        "program",
        "args",
        "argv",
    }
)


@dataclass(frozen=True)
class EvidenceRef:
    """Referencia a un registro original que respalda la salida (no una copia de él)."""

    type: str
    id: str
    label: str | None = None
    at: datetime | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "id": self.id,
            "label": self.label,
            "at": self.at.isoformat() if self.at else None,
        }


@dataclass
class ToolOutput:
    summary: str
    data: BaseModel
    evidence: list[EvidenceRef] = field(default_factory=list)
    # Procedencia: fuentes consultadas, ventana temporal, límites aplicados, avisos.
    provenance: dict[str, Any] = field(default_factory=dict)
    # Ejecución de Response en la que delegó (acciones e investigaciones).
    response_execution_id: int | None = None
    # Incidente creado o enlazado (herramientas de casos).
    incident_id: int | None = None


@dataclass
class ToolPreview:
    """Vista previa de una herramienta de acción: qué haría, sin hacerlo."""

    summary: str
    allowed: bool
    effects: list[str] = field(default_factory=list)
    blockers: list[dict[str, str]] = field(default_factory=list)
    warnings: list[dict[str, str]] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolContext:
    session: Session
    settings: Settings
    user: User
    actor: Actor
    permissions: frozenset[Permission]
    now: datetime
    # Site pedido por el operador (id interno) o None = todos.
    site_id: int | None = None
    # Incidente de contexto (herramienta lanzada desde un caso).
    incident_public_id: UUID | None = None
    # Fábrica del runner de discovery (solo herramientas que delegan en start_discovery).
    discovery_runner: Callable[[], Any] | None = None
    # Clave de idempotencia de la ejecución, reutilizada al delegar en Response.
    idempotency_key: str | None = None

    def has(self, permission: Permission) -> bool:
        return permission in self.permissions


Handler = Callable[[ToolContext, Any], ToolOutput]
PreviewHandler = Callable[[ToolContext, Any], ToolPreview]
# Motivo por el que una herramienta no está disponible ahora (None = disponible).
Availability = Callable[[Settings], str | None]


@dataclass(frozen=True)
class ToolDefinition:
    id: str
    version: int
    name: str
    description: str
    category: ToolCategory
    scope: ToolScope
    risk_level: ToolRisk
    permissions: tuple[Permission, ...]
    input_model: type[BaseModel]
    output_model: type[BaseModel]
    handler: Handler
    policy: ExecutionPolicy = "direct"
    preview: PreviewHandler | None = None
    timeout_seconds: int = 15
    max_rows: int = 200
    # Capacidades del agente o del sensor que la herramienta necesita (informativo; la
    # política del Response Engine las vuelve a comprobar al delegar).
    required_capabilities: tuple[str, ...] = ()
    availability: Availability | None = None
    # Fuentes de datos que consulta (procedencia en el catálogo).
    sources: tuple[str, ...] = ()

    @property
    def required_permissions(self) -> frozenset[Permission]:
        return frozenset({Permission.TOOLS_EXECUTE, *self.permissions})

    @property
    def required_role(self) -> str:
        for role in (Role.VIEWER, Role.ANALYST, Role.ADMIN):
            if self.required_permissions <= ROLE_PERMISSIONS[role]:
                return role.value
        return Role.ADMIN.value

    def unavailable_reason(self, settings: Settings) -> str | None:
        return self.availability(settings) if self.availability else None


def _field_names(schema: dict[str, Any], seen: set[int]) -> set[str]:
    names: set[str] = set()
    if id(schema) in seen:
        return names
    seen.add(id(schema))
    for key, value in (schema.get("properties") or {}).items():
        names.add(key.lower())
        if isinstance(value, dict):
            names |= _field_names(value, seen)
    for definition in (schema.get("$defs") or {}).values():
        if isinstance(definition, dict):
            names |= _field_names(definition, seen)
    return names


def validate_registry(tools: dict[str, ToolDefinition]) -> None:
    """Invariantes del registro: ids estables, políticas coherentes y entradas sin código."""
    for tool_id, tool in tools.items():
        if tool_id != tool.id:
            raise ValueError(f"tool id mismatch: {tool_id}")
        if tool.input_model.model_config.get("extra") != "forbid":
            raise ValueError(f"{tool_id}: input model must forbid extra fields")
        forbidden = _field_names(tool.input_model.model_json_schema(), set()) & (
            FORBIDDEN_INPUT_FIELDS
        )
        if forbidden:
            raise ValueError(f"{tool_id}: forbidden input fields {sorted(forbidden)}")
        if tool.category == "action" and (tool.policy != "preview_confirm" or not tool.preview):
            # Toda acción pasa por vista previa y confirmación: nunca se ejecuta en un paso.
            raise ValueError(f"{tool_id}: action tools require preview_confirm")
        if tool.category == "read" and tool.risk_level != "none":
            raise ValueError(f"{tool_id}: read tools have no risk")
