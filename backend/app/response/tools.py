"""Herramientas para la futura Analyst Console (Fase 5D): solo preparación, sin chat ni LLM.

Un registro CERRADO de funciones con nombre estable (`response.execute`, `playbooks.list`...)
que envuelven el mismo ResponseService que usan la API y la UI: misma política, mismo RBAC,
misma auditoría. Los argumentos se validan con los mismos modelos de la API (extra=forbid), así
que una consola futura no puede pedir nada que un operador no pueda pedir por la API.

No hay herramientas genéricas (ni "run", ni "http", ni "sql"): un nombre desconocido es un
KeyError. Nada aquí decide por sí mismo: siempre hay un operador humano con su rol.
"""

from collections.abc import Callable
from typing import Any
from uuid import UUID

from pydantic import Field

from app.schemas.common import RequestModel
from app.schemas.response import ExecutionRequest, PlaybookRunRequest
from app.services.response_service import Operator, ResponseService


class _AssetFilter(RequestModel):
    asset_id: UUID | None = None


class _ExecutionRef(RequestModel):
    execution_id: UUID


class _PlaybookRun(PlaybookRunRequest):
    playbook_id: UUID = Field()


def _list_actions(service: ResponseService, op: Operator, args: dict[str, Any]) -> Any:
    return service.list_actions(op, _AssetFilter.model_validate(args).asset_id)


def _preview(service: ResponseService, op: Operator, args: dict[str, Any]) -> Any:
    return service.preview(op, ExecutionRequest.model_validate(args))


def _execute(service: ResponseService, op: Operator, args: dict[str, Any]) -> Any:
    return service.execute(op, ExecutionRequest.model_validate(args))


def _status(service: ResponseService, op: Operator, args: dict[str, Any]) -> Any:
    return service.get_execution(_ExecutionRef.model_validate(args).execution_id)


def _playbooks(service: ResponseService, op: Operator, args: dict[str, Any]) -> Any:
    return service.list_playbooks(op, _AssetFilter.model_validate(args).asset_id)


def _split(args: dict[str, Any]) -> tuple[UUID, PlaybookRunRequest]:
    request = _PlaybookRun.model_validate(args)
    body = PlaybookRunRequest.model_validate(request.model_dump(exclude={"playbook_id"}))
    return request.playbook_id, body


def _playbook_preview(service: ResponseService, op: Operator, args: dict[str, Any]) -> Any:
    playbook_id, body = _split(args)
    return service.preview_playbook(op, playbook_id, body)


def _playbook_execute(service: ResponseService, op: Operator, args: dict[str, Any]) -> Any:
    playbook_id, body = _split(args)
    return service.execute_playbook(op, playbook_id, body)


Tool = Callable[[ResponseService, Operator, dict[str, Any]], Any]

TOOLS: dict[str, Tool] = {
    "response.list_actions": _list_actions,
    "response.preview": _preview,
    "response.execute": _execute,
    "response.status": _status,
    "playbooks.list": _playbooks,
    "playbooks.preview": _playbook_preview,
    "playbooks.execute": _playbook_execute,
}


def call(service: ResponseService, op: Operator, name: str, args: dict[str, Any]) -> Any:
    """Ejecuta una herramienta del registro y devuelve su salida como JSON simple."""
    tool = TOOLS[name]  # KeyError para cualquier nombre fuera del registro
    result = tool(service, op, dict(args))
    return result.model_dump(mode="json")
