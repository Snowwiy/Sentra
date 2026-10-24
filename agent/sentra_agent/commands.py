"""Comandos de Response del servidor (Fase 5D): allowlist cerrada, sin shell.

El agente nunca ejecuta lo que el servidor le diga: solo reconoce estos tipos, cada uno
mapeado a un handler escrito aquí que reutiliza los colectores de solo lectura que el agente
ya tiene (inventario, procesos, eventos, telemetría) o devuelve un diagnóstico propio. No
hay ningún tipo que acepte un comando, un script, una ruta o un argumento libre: un comando
con un tipo desconocido o con parámetros se rechaza sin ejecutar nada.

Fase 6E: se añaden las acciones forenses de solo lectura (`forensic_*`) y el aislamiento
(`isolate_host`, `release_isolation`). Solo `forensic_file_metadata`, `isolate_host` y
`release_isolation` aceptan parámetros, con claves exactas y tipos estrictos; la ruta de
`forensic_file_metadata` se valida además contra `forensics.allowed_roots` LOCAL. Cualquier
otro parámetro sigue siendo `invalid_params` sin ejecutar nada.

Los comandos llegan por POST /agents/commands/poll (con el token propio del agente) y solo
cuando el heartbeat avisa de que hay alguno pendiente. Cada request_id se ejecuta como mucho
una vez por ejecución del agente: si el servidor lo reentrega (se perdió la respuesta), se
reenvía el resultado guardado en lugar de recolectar otra vez.
"""

import sys
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from sentra_agent.forensics import (
    FORENSIC_FILE_METADATA,
    FORENSIC_TYPES,
    PathRejectedError,
    forensic_capabilities,
    validate_path,
)
from sentra_agent.isolation.exchange import parse_iso

# Debe coincidir con app/response/catalog.AGENT_COMMAND_TYPES del servidor.
COLLECT_INVENTORY = "collect_inventory"
COLLECT_PROCESSES = "collect_processes"
COLLECT_EVENTS = "collect_events"
COLLECT_TELEMETRY = "collect_telemetry"
COLLECT_DIAGNOSTICS = "collect_diagnostics"
ISOLATE_HOST = "isolate_host"
RELEASE_ISOLATION = "release_isolation"
COLLECT_TYPES = frozenset(
    {COLLECT_INVENTORY, COLLECT_PROCESSES, COLLECT_EVENTS, COLLECT_TELEMETRY, COLLECT_DIAGNOSTICS}
)
COMMAND_TYPES = COLLECT_TYPES | FORENSIC_TYPES | {ISOLATE_HOST, RELEASE_ISOLATION}
# Capacidades de telemetría (no son comandos): las anuncia el heartbeat (contrato 6E).
TELEMETRY_ACTIVITY = "telemetry_activity"
TELEMETRY_PROCESS_TREE = "telemetry_process_tree"
TELEMETRY_PROCESS_NETWORK = "telemetry_process_network"
TELEMETRY_SYSMON = "telemetry_sysmon"
KNOWN_CAPABILITIES = COMMAND_TYPES | {
    TELEMETRY_ACTIVITY,
    TELEMETRY_PROCESS_TREE,
    TELEMETRY_PROCESS_NETWORK,
    TELEMETRY_SYSMON,
}
# Parámetros admitidos: claves EXACTAS por tipo.
_PARAM_KEYS = {
    FORENSIC_FILE_METADATA: frozenset({"path", "hash"}),
    ISOLATE_HOST: frozenset({"session_id", "expires_at"}),
    RELEASE_ISOLATION: frozenset({"session_id"}),
}
# Resultados recordados para reentregas (acotado: no crece con el tiempo).
REMEMBERED_RESULTS = 64
# Resultados pendientes de enviar tras un corte de red (acotado igual).
MAX_UNSENT = 32
SUMMARY_MAX = 500


class CommandRejectedError(Exception):
    """Comando que el agente no ejecuta: tipo desconocido, forma inválida o parámetros."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def capabilities(
    platform: str | None = None,
    *,
    telemetry_activity: bool = False,
    process_tree: bool = False,
    process_network: bool = False,
    sysmon: bool = False,
    isolation: bool = False,
) -> list[str]:
    """Lo que este agente sabe hacer en este sistema (lo que declara al servidor).

    Eventos solo donde hay una fuente real (Visor de eventos en Windows, journal en Linux,
    Unified Logging en macOS). Fase 6E: las acciones forenses solo donde funcionan, la
    telemetría según el estado REAL de sus colectores (lo decide quien llama) y el
    aislamiento solo con el helper instalado, habilitado y sano, y nunca en macOS.
    """
    platform = platform or sys.platform
    found = {COLLECT_INVENTORY, COLLECT_PROCESSES, COLLECT_TELEMETRY, COLLECT_DIAGNOSTICS}
    if platform in ("win32", "darwin") or platform.startswith("linux"):
        found.add(COLLECT_EVENTS)
    found |= forensic_capabilities(platform)
    if telemetry_activity:
        found.add(TELEMETRY_ACTIVITY)
        if process_tree:
            found.add(TELEMETRY_PROCESS_TREE)
        if process_network:
            found.add(TELEMETRY_PROCESS_NETWORK)
        if sysmon and platform == "win32":
            found.add(TELEMETRY_SYSMON)
    if isolation and (platform == "win32" or platform.startswith("linux")):
        found |= {ISOLATE_HOST, RELEASE_ISOLATION}
    return sorted(found)


@dataclass(frozen=True)
class ParsedCommand:
    request_id: UUID
    kind: str
    params: dict[str, Any] = field(default_factory=dict)


def parse_command(raw: object) -> tuple[UUID, str]:
    """Compatibilidad 5D: (request_id, tipo) con las raíces forenses por defecto."""
    parsed = parse_command_full(raw)
    return parsed.request_id, parsed.kind


def parse_command_full(
    raw: object,
    allowed_roots: tuple[str, ...] | None = None,
    platform: str | None = None,
    extra_denied: tuple[str, ...] = (),
) -> ParsedCommand:
    """Valida la forma de un comando recibido y sus parámetros.

    Lanza CommandRejectedError para tipos fuera de la allowlist o con parámetros que no
    sean exactamente los previstos. Un request_id inválido lanza ValueError (no se puede ni
    responder).
    """
    if not isinstance(raw, dict):
        raise ValueError("command is not an object")
    request_id = UUID(str(raw.get("request_id")))
    kind = raw.get("type")
    if not isinstance(kind, str) or kind not in COMMAND_TYPES:
        raise CommandRejectedError("unknown_command", "Unknown command type")
    params = raw.get("params")
    expected = _PARAM_KEYS.get(kind)
    if expected is None:
        if params not in (None, {}):
            raise CommandRejectedError("invalid_params", "This command takes no parameters")
        return ParsedCommand(request_id, kind)
    if not isinstance(params, dict) or set(params) != expected:
        raise CommandRejectedError("invalid_params", "Parameters do not match the contract")
    if kind == FORENSIC_FILE_METADATA:
        if not isinstance(params["hash"], bool):
            raise CommandRejectedError("invalid_params", "hash must be true or false")
        try:
            path = validate_path(params["path"], allowed_roots, platform, extra_denied)
        except PathRejectedError as exc:
            raise CommandRejectedError(exc.code, str(exc)) from exc
        return ParsedCommand(request_id, kind, {"path": path, "hash": params["hash"]})
    session = _uuid_param(params["session_id"])
    if kind == RELEASE_ISOLATION:
        return ParsedCommand(request_id, kind, {"session_id": session})
    try:
        expires_at = parse_iso(params["expires_at"])
    except ValueError as exc:
        raise CommandRejectedError(
            "invalid_params", "expires_at must be ISO 8601 with zone"
        ) from exc
    return ParsedCommand(request_id, kind, {"session_id": session, "expires_at": expires_at})


def _uuid_param(value: object) -> UUID:
    if not isinstance(value, str) or len(value) > 64:
        raise CommandRejectedError("invalid_params", "session_id must be a UUID string")
    try:
        return UUID(value)
    except ValueError as exc:
        raise CommandRejectedError("invalid_params", "session_id must be a UUID string") from exc


def result_body(
    status: str, summary: str, data: dict[str, Any] | None = None, error_code: str | None = None
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "status": status,
        "summary": summary[:SUMMARY_MAX],
        "data": data or {},
    }
    if error_code:
        body["error_code"] = error_code
    return body


class CommandMemory:
    """Resultados ya calculados por request_id (reentrega) y los que faltan por enviar."""

    def __init__(self) -> None:
        self.done: OrderedDict[UUID, dict[str, Any]] = OrderedDict()
        self.unsent: OrderedDict[UUID, dict[str, Any]] = OrderedDict()

    def remember(self, request_id: UUID, body: dict[str, Any]) -> None:
        self.done[request_id] = body
        self.done.move_to_end(request_id)
        while len(self.done) > REMEMBERED_RESULTS:
            self.done.popitem(last=False)

    def queue_unsent(self, request_id: UUID, body: dict[str, Any]) -> None:
        self.unsent[request_id] = body
        while len(self.unsent) > MAX_UNSENT:
            # El más antiguo ya habrá caducado en el servidor (TTL): se descarta.
            self.unsent.popitem(last=False)
