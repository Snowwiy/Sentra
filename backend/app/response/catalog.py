"""Catálogo cerrado de acciones de Response (Fase 5D).

Es una allowlist en código: una acción existe solo si está en ACTIONS, con su modelo de
parámetros (extra=forbid) y su handler ya implementado. No hay forma de registrar acciones
desde la API ni de pasar un comando, script, ruta de ejecutable o plantilla: ningún modelo
de parámetros tiene un campo así (test_response.py lo comprueba sobre todo el catálogo).

Las acciones futuras de mayor riesgo (aislar, matar procesos, bloquear direcciones) están
listadas como `not_implemented`, sin handler: se ven en el catálogo para que el modelo sea
extensible, pero el motor las rechaza siempre (nunca hay un stub que pueda ejecutarse).
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal

from pydantic import Field

from app.core.permissions import ROLE_PERMISSIONS, Permission, Role
from app.core.platforms import is_macos
from app.models.incident import IncidentLevel
from app.response import handlers
from app.schemas.common import RequestModel

RiskLevel = Literal["low", "medium", "high", "critical"]
RISK_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}
Scope = Literal["server", "agent"]
TargetType = Literal["asset", "incident"]
Availability = Literal["available", "not_implemented"]
Platform = Literal["windows", "linux", "macos"]

# Tipos de comando que un agente puede declarar como capacidad (y los únicos que el servidor
# encola). El agente tiene su propia allowlist idéntica y rechaza cualquier otro tipo.
AGENT_COMMAND_TYPES = frozenset(
    {
        "collect_inventory",
        "collect_processes",
        "collect_events",
        "collect_telemetry",
        "collect_diagnostics",
    }
)


class NoParams(RequestModel):
    """Acción sin parámetros: cualquier campo enviado se rechaza (422)."""


class LookbackParams(RequestModel):
    # Ventana hacia atrás, acotada para que una petición no recorra meses de señales.
    hours: int = Field(default=24, ge=1, le=168)


class OpenIncidentParams(RequestModel):
    # Texto plano acotado (la UI lo muestra escapado, nunca como HTML).
    title: str | None = Field(default=None, min_length=3, max_length=200)
    severity: IncidentLevel = IncidentLevel.MEDIUM
    priority: IncidentLevel = IncidentLevel.MEDIUM


class IncidentNoteParams(RequestModel):
    body: str = Field(min_length=1, max_length=4000)


class ArchiveParams(RequestModel):
    reason: str = Field(min_length=3, max_length=500)


@dataclass(frozen=True)
class ActionDefinition:
    id: str
    name: str
    description: str
    category: str
    scope: Scope
    target_type: TargetType
    risk_level: RiskLevel
    # Permisos de dominio además de response:execute (y response:manage si es MEDIUM+).
    permissions: tuple[Permission, ...]
    expected_effect: str
    params_model: type[RequestModel] = NoParams
    destructive: bool = False
    requires_confirmation: bool = False
    # Agente: tipo de comando (= capacidad exigida) y plataformas soportadas.
    agent_command: str | None = None
    supported_platforms: frozenset[str] = field(default_factory=frozenset)
    # Plazo total de la ejecución (servidor: tope; agente: lease de cada entrega).
    timeout_seconds: int = 60
    # Entregas máximas de un comando (1 = sin reintento). Solo >1 si es idempotente.
    max_deliveries: int = 1
    idempotent: bool = True
    # Permitida sobre activos archivados (solo lecturas de evidencia).
    allow_archived: bool = False
    availability: Availability = "available"
    handler: Callable[[handlers.ActionContext], handlers.ActionResult] | None = None
    # Comprobación previa específica de la acción (mismos bloqueos en preview y ejecución).
    precheck: Callable[[handlers.ActionContext], list[handlers.Issue]] | None = None

    @property
    def requires_agent(self) -> bool:
        return self.scope == "agent"

    @property
    def required_permissions(self) -> frozenset[Permission]:
        """Todo lo que exige ejecutarla. MEDIUM o más: además response:manage (admin)."""
        needed = {Permission.RESPONSE_EXECUTE, *self.permissions}
        if RISK_RANK[self.risk_level] >= RISK_RANK["medium"]:
            needed.add(Permission.RESPONSE_MANAGE)
        return frozenset(needed)

    @property
    def required_role(self) -> str:
        return minimum_role(self.required_permissions)

    @property
    def available(self) -> bool:
        return self.availability == "available" and self.handler is not None


def minimum_role(needed: frozenset[Permission]) -> str:
    """Rol de menor privilegio que tiene todos esos permisos (informativo para la UI)."""
    for role in (Role.VIEWER, Role.ANALYST, Role.ADMIN):
        if needed <= ROLE_PERMISSIONS[role]:
            return role.value
    return Role.ADMIN.value


_AGENT_PLATFORMS = frozenset({"windows", "linux", "macos"})
_READ = Permission.MONITORING_READ


def _agent_action(
    action_id: str, name: str, description: str, effect: str, timeout: int = 300
) -> ActionDefinition:
    # Recolección de solo lectura en el endpoint: idempotente, así que se puede reentregar
    # una vez si el agente no devolvió resultado dentro del lease (reinicio, corte de red).
    return ActionDefinition(
        id=action_id,
        name=name,
        description=description,
        category="collection",
        scope="agent",
        target_type="asset",
        risk_level="low",
        permissions=(_READ,),
        expected_effect=effect,
        agent_command=action_id,
        supported_platforms=_AGENT_PLATFORMS,
        timeout_seconds=timeout,
        max_deliveries=2,
        handler=handlers.agent_dispatch,
    )


ACTIONS: dict[str, ActionDefinition] = {
    action.id: action
    for action in (
        # --- Agente: recolección de solo lectura ------------------------------------------------
        _agent_action(
            "collect_inventory",
            "Recolectar inventario",
            "Pide al agente un inventario completo ahora: interfaces, conexiones y puertos en"
            " escucha, servicios, software, cuentas y red.",
            "El agente envía un inventario nuevo por el canal normal de inventario.",
        ),
        _agent_action(
            "collect_processes",
            "Recolectar procesos",
            "Pide al agente una instantánea de procesos ahora.",
            "El agente envía una instantánea de procesos por el canal normal.",
        ),
        _agent_action(
            "collect_events",
            "Recolectar eventos",
            "Pide al agente que envíe ya los eventos pendientes de su fuente (Visor de eventos"
            " en Windows, journal en Linux, Unified Logging en macOS).",
            "El agente envía los eventos pendientes por el canal normal de eventos.",
        ),
        _agent_action(
            "collect_telemetry",
            "Recolectar telemetría",
            "Pide al agente una muestra de CPU, RAM, disco y uptime ahora.",
            "El agente envía una muestra de telemetría.",
        ),
        _agent_action(
            "collect_diagnostics",
            "Diagnóstico del agente",
            "Pide al agente su estado: versión, plataforma, intervalos, buffer y cobertura de"
            " eventos. Nunca incluye tokens, claves ni rutas de credenciales.",
            "El agente devuelve un diagnóstico estructurado; no cambia nada en el equipo.",
            timeout=120,
        ),
        # --- Servidor: reevaluaciones y lecturas ------------------------------------------------
        ActionDefinition(
            id="recalculate_risk",
            name="Recalcular riesgo",
            description="Recalcula ya el riesgo del activo con los datos actuales.",
            category="analysis",
            scope="server",
            target_type="asset",
            risk_level="low",
            permissions=(_READ,),
            expected_effect="Se recalcula la puntuación de riesgo del activo (puede cambiar su"
            " nivel y abrir o cerrar la alerta de riesgo según las reglas existentes).",
            handler=handlers.recalculate_risk,
        ),
        ActionDefinition(
            id="reevaluate_detections",
            name="Reevaluar detecciones",
            description="Vuelve a poner en cola las señales recientes del activo para el motor"
            " de detección (idempotente: lo ya detectado no se duplica).",
            category="analysis",
            scope="server",
            target_type="asset",
            risk_level="low",
            permissions=(_READ, Permission.DETECTIONS_MANAGE),
            params_model=LookbackParams,
            expected_effect="Las señales de la ventana indicada se reevalúan en la próxima"
            " vuelta del motor de detección.",
            handler=handlers.reevaluate_detections,
        ),
        ActionDefinition(
            id="refresh_threat_context",
            name="Refrescar contexto de amenazas",
            description="Encola la repriorización de las vulnerabilidades del activo con la"
            " inteligencia KEV/EPSS ya importada (no descarga nada).",
            category="analysis",
            scope="server",
            target_type="asset",
            risk_level="low",
            permissions=(_READ, Permission.VULNERABILITIES_READ, Permission.THREAT_INTEL_READ),
            expected_effect="La prioridad de sus findings se recalcula en la próxima vuelta del"
            " motor de vulnerabilidades.",
            handler=handlers.refresh_threat_context,
        ),
        ActionDefinition(
            id="reevaluate_vulnerabilities",
            name="Reevaluar vulnerabilidades",
            description="Evalúa ya las vulnerabilidades del activo contra el catálogo local."
            " Igual que la reevaluación existente, es solo para admin.",
            category="analysis",
            scope="server",
            target_type="asset",
            risk_level="low",
            permissions=(_READ, Permission.VULNERABILITIES_ADMIN),
            expected_effect="Se crean, actualizan o resuelven findings según el inventario y el"
            " catálogo actuales.",
            timeout_seconds=120,
            handler=handlers.reevaluate_vulnerabilities,
        ),
        ActionDefinition(
            id="start_discovery",
            name="Escanear la IP del activo",
            description="Lanza un discovery de la IP principal del activo (un solo host),"
            " siempre dentro de la allowlist de redes del servidor.",
            category="analysis",
            scope="server",
            target_type="asset",
            risk_level="low",
            permissions=(_READ, Permission.DISCOVERY_RUN),
            expected_effect="Se encola un discovery de un host; sondea la red desde el servidor"
            " (ICMP/TCP) igual que un discovery manual.",
            idempotent=False,
            precheck=handlers.check_discovery,
            handler=handlers.start_discovery,
        ),
        ActionDefinition(
            id="collect_timeline",
            name="Construir timeline",
            description="Reúne en orden cronológico detecciones, alertas, cambios y eventos"
            " relevantes del activo en la ventana indicada (solo lectura).",
            category="evidence",
            scope="server",
            target_type="asset",
            risk_level="low",
            permissions=(_READ,),
            params_model=LookbackParams,
            expected_effect="Solo lectura: el resultado queda guardado como evidencia de la"
            " ejecución.",
            allow_archived=True,
            handler=handlers.collect_timeline,
        ),
        ActionDefinition(
            id="collect_response_bundle",
            name="Resumen de respuesta",
            description="Resumen de evidencia del activo: estado, agente, riesgo, detecciones,"
            " alertas, vulnerabilidades, amenazas e incidentes abiertos (solo lectura).",
            category="evidence",
            scope="server",
            target_type="asset",
            risk_level="low",
            permissions=(_READ,),
            expected_effect="Solo lectura: el resumen queda guardado como evidencia.",
            allow_archived=True,
            handler=handlers.collect_response_bundle,
        ),
        # --- Servidor: mutaciones internas controladas (MEDIUM, admin + confirmación) -----------
        ActionDefinition(
            id="open_incident",
            name="Abrir incidente",
            description="Abre un incidente con el activo (o desde la detección de contexto)."
            " Si la detección ya está en un caso activo, devuelve ese caso.",
            category="case",
            scope="server",
            target_type="asset",
            risk_level="medium",
            permissions=(_READ, Permission.INCIDENTS_MANAGE),
            params_model=OpenIncidentParams,
            requires_confirmation=True,
            expected_effect="Se crea un incidente (o se reutiliza el activo existente de esa"
            " detección); queda en la auditoría y en el timeline del caso.",
            idempotent=False,
            handler=handlers.open_incident,
        ),
        ActionDefinition(
            id="add_incident_note",
            name="Añadir nota al incidente",
            description="Añade una nota de texto plano al incidente (append-only).",
            category="case",
            scope="server",
            target_type="incident",
            risk_level="medium",
            permissions=(Permission.INCIDENTS_READ, Permission.INCIDENTS_MANAGE),
            params_model=IncidentNoteParams,
            requires_confirmation=True,
            expected_effect="Se añade una nota al caso; las notas no se editan ni se borran.",
            idempotent=False,
            precheck=handlers.check_incident_open,
            handler=handlers.add_incident_note,
        ),
        ActionDefinition(
            id="archive_asset",
            name="Archivar activo",
            description="Archiva el activo con la misma política del ciclo de vida (5C.1):"
            " exige que su agente no tenga credencial activa. Reversible con Restaurar.",
            category="lifecycle",
            scope="server",
            target_type="asset",
            risk_level="medium",
            permissions=(_READ, Permission.ASSETS_MANAGE),
            params_model=ArchiveParams,
            requires_confirmation=True,
            expected_effect="El activo deja de verse por defecto y de contar en el resumen;"
            " conserva todo su historial. Las acciones de agente pendientes se cancelan.",
            idempotent=False,
            precheck=handlers.check_archivable,
            handler=handlers.archive_asset,
        ),
        # --- Futuras: visibles, nunca ejecutables en 5D -----------------------------------------
        ActionDefinition(
            id="isolate_host",
            name="Aislar equipo de la red",
            description="Reservada. Necesita una arquitectura propia de aislamiento reversible"
            " y aprobación separada; no existe en 5D.",
            category="containment",
            scope="agent",
            target_type="asset",
            risk_level="critical",
            permissions=(Permission.RESPONSE_MANAGE,),
            expected_effect="No disponible.",
            destructive=True,
            requires_confirmation=True,
            idempotent=False,
            availability="not_implemented",
        ),
        ActionDefinition(
            id="kill_process",
            name="Terminar proceso",
            description="Reservada. No existe en 5D: terminar procesos arbitrarios no está"
            " permitido.",
            category="containment",
            scope="agent",
            target_type="asset",
            risk_level="high",
            permissions=(Permission.RESPONSE_MANAGE,),
            expected_effect="No disponible.",
            destructive=True,
            requires_confirmation=True,
            idempotent=False,
            availability="not_implemented",
        ),
        ActionDefinition(
            id="block_network_address",
            name="Bloquear dirección de red",
            description="Reservada. Cambios de firewall necesitan una arquitectura propia y"
            " reversible; no existe en 5D.",
            category="containment",
            scope="agent",
            target_type="asset",
            risk_level="high",
            permissions=(Permission.RESPONSE_MANAGE,),
            expected_effect="No disponible.",
            destructive=True,
            requires_confirmation=True,
            idempotent=False,
            availability="not_implemented",
        ),
    )
}


def get_action(action_id: str) -> ActionDefinition | None:
    return ACTIONS.get(action_id)


def asset_platform(os_name: str | None) -> str | None:
    """Plataforma del activo según el SO de su agente ("windows", "linux", "macos" o None)."""
    name = (os_name or "").strip().lower()
    if name.startswith("windows"):
        return "windows"
    if name.startswith("linux"):
        return "linux"
    if is_macos(name):
        return "macos"
    return None
