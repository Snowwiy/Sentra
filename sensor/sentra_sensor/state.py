"""Estado local NO secreto del sensor (última config del servidor, modo, último job).

Separado de la credencial a propósito: `status` y `diagnostics` pueden leerlo sin tocar el
secreto, y se puede adjuntar a una incidencia de soporte sin riesgo.
"""

import json
import socket
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentra_sensor.credentials import atomic_write_json

MODE_ACTIVE = "active"
MODE_DISABLED = "disabled"
MODE_REVOKED = "revoked"
MODE_UNAUTHORIZED = "unauthorized"


@dataclass
class LocalState:
    server_config: dict[str, Any] | None = None
    mode: str = MODE_ACTIVE
    last_successful_job_at: str | None = None
    last_heartbeat_at: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "server_config": self.server_config,
            "mode": self.mode,
            "last_successful_job_at": self.last_successful_job_at,
            "last_heartbeat_at": self.last_heartbeat_at,
        }


def load_state(path: Path) -> LocalState:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return LocalState()
    if not isinstance(data, dict):
        return LocalState()
    config = data.get("server_config")
    mode = data.get("mode")
    return LocalState(
        server_config=config if isinstance(config, dict) else None,
        mode=mode if isinstance(mode, str) else MODE_ACTIVE,
        last_successful_job_at=_str_or_none(data.get("last_successful_job_at")),
        last_heartbeat_at=_str_or_none(data.get("last_heartbeat_at")),
    )


def save_state(path: Path, state: LocalState) -> None:
    atomic_write_json(path, state.to_json())


def _str_or_none(value: object) -> str | None:
    return value if isinstance(value, str) else None


def platform_name(value: str | None = None) -> str:
    value = value or sys.platform
    if value == "win32":
        return "windows"
    if value.startswith("linux"):
        return "linux"
    return value[:32] or "unknown"


def host_metadata() -> dict[str, str]:
    """Metadatos seguros del host. Nunca variables de entorno, rutas de usuario ni secretos."""
    hostname = (socket.gethostname() or "unknown")[:255]
    return {"hostname": hostname, "platform": platform_name()}
