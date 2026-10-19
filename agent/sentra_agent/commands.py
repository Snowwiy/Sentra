"""Comandos de Response del servidor (Fase 5D): allowlist cerrada, sin shell.

El agente nunca ejecuta lo que el servidor le diga: solo reconoce estos tipos, cada uno
mapeado a un handler escrito aquí que reutiliza los colectores de solo lectura que el agente
ya tiene (inventario, procesos, eventos, telemetría) o devuelve un diagnóstico propio. No
hay ningún tipo que acepte un comando, un script, una ruta o un argumento libre: un comando
con un tipo desconocido o con parámetros se rechaza sin ejecutar nada.

Los comandos llegan por POST /agents/commands/poll (con el token propio del agente) y solo
cuando el heartbeat avisa de que hay alguno pendiente. Cada request_id se ejecuta como mucho
una vez por ejecución del agente: si el servidor lo reentrega (se perdió la respuesta), se
reenvía el resultado guardado en lugar de recolectar otra vez.
"""

import sys
from collections import OrderedDict
from typing import Any
from uuid import UUID

# Debe coincidir con app/response/catalog.AGENT_COMMAND_TYPES del servidor.
COLLECT_INVENTORY = "collect_inventory"
COLLECT_PROCESSES = "collect_processes"
COLLECT_EVENTS = "collect_events"
COLLECT_TELEMETRY = "collect_telemetry"
COLLECT_DIAGNOSTICS = "collect_diagnostics"
COMMAND_TYPES = frozenset(
    {COLLECT_INVENTORY, COLLECT_PROCESSES, COLLECT_EVENTS, COLLECT_TELEMETRY, COLLECT_DIAGNOSTICS}
)
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


def capabilities(platform: str | None = None) -> list[str]:
    """Tipos que este agente sabe ejecutar en este sistema (lo que declara al servidor).

    Eventos solo donde hay una fuente real (Visor de eventos en Windows, journal en Linux,
    Unified Logging en macOS desde la Fase 6C.5): en otro sistema el servidor no debe
    ofrecer esa acción. Los cinco tipos son de solo lectura y en macOS reutilizan los
    mismos colectores que el envío periódico; no existe ningún tipo que actúe sobre el
    equipo, así que no hay nada más que declarar ni que implementar por plataforma.
    """
    platform = platform or sys.platform
    found = {COLLECT_INVENTORY, COLLECT_PROCESSES, COLLECT_TELEMETRY, COLLECT_DIAGNOSTICS}
    if platform in ("win32", "darwin") or platform.startswith("linux"):
        found.add(COLLECT_EVENTS)
    return sorted(found)


def parse_command(raw: object) -> tuple[UUID, str]:
    """Valida la forma de un comando recibido y devuelve (request_id, tipo).

    Lanza CommandRejectedError para tipos fuera de la allowlist o con parámetros: ninguno de
    los tipos actuales acepta parámetros, así que cualquier parámetro es sospechoso.
    Un request_id inválido lanza ValueError (no se puede ni responder).
    """
    if not isinstance(raw, dict):
        raise ValueError("command is not an object")
    request_id = UUID(str(raw.get("request_id")))
    kind = raw.get("type")
    if not isinstance(kind, str) or kind not in COMMAND_TYPES:
        raise CommandRejectedError("unknown_command", "Unknown command type")
    params = raw.get("params")
    if params not in (None, {}):
        raise CommandRejectedError("invalid_params", "This command takes no parameters")
    return request_id, kind


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
