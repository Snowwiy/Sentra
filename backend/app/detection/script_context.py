"""Contexto de PowerShell y de puertos nuevos (Fase 7A.8). Ver docs/powershell-detections.md.

SCR-001, CORR-002 y NET-001 se dispararon en 6E con scripts y servicios del propio Sentra
(el instalador del agente, init_database.ps1, la API en 8000/TCP) sin que la detección dijera
qué script, qué proceso ni por qué. Aquí se reúne ese contexto para que la evidencia lo
lleve y para que una excepción pueda ser exacta (ruta + hash, puerto + ejecutable):

- del evento 4104 (agente 0.6.0): ruta del script, su SHA-256, bloque, PID, SID y las
  palabras que hicieron que PowerShell lo marcara. Nunca el contenido;
- de la telemetría de procesos (6E.4): el proceso con ese PID vivo en ese momento, su padre,
  ejecutable, firma, hash y usuario;
- del inventario del agente: qué proceso escucha en un puerto que discovery vio abierto.

La relación con Sentra es una pista, no una prueba: un nombre de script o de servicio se
falsifica con facilidad. Nada de esto rebaja la severidad ni cierra nada; solo una excepción
explícita, con alcance, caducidad y huella, evita una detección.
"""

import re
from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.detection import text
from app.models.endpoint import ProcessInstance
from app.models.inventory import AssetInventory

# Vocabulario que el agente 0.6.0 puede enviar (sentra_agent/events.py). Lo que no esté aquí
# se descarta: el servidor no guarda texto libre venido del host como "palabra clave".
POWERSHELL_KEYWORDS = frozenset(
    {
        "Add-Type",
        "DllImport",
        "DefineDynamicAssembly",
        "DefinePInvokeMethod",
        "InteropServices",
        "Marshal",
        "AllocHGlobal",
        "PtrToStructure",
        "PtrToString",
        "IntPtr",
        "FromBase64String",
        "ToBase64String",
        "EncodedCommand",
        "Bypass",
        "MemoryStream",
        "DeflateStream",
        "GZipStream",
        "Invoke-Expression",
        "DownloadString",
        "DownloadFile",
        "Net.WebClient",
        "Reflection.Assembly",
        "GetDelegateForFunctionPointer",
        "GetProcAddress",
        "LoadLibrary",
        "VirtualAlloc",
        "VirtualProtect",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "CreateThread",
        "OpenProcess",
        "kernel32",
        "advapi32",
        "AdjustTokenPrivileges",
        "MiniDumpWriteDump",
        "NonPublic",
        "BindingFlags",
        "GetField",
        "GetMethod",
        "InvokeMember",
        "Cryptography",
        "CreateDecryptor",
        "ScriptBlockLogging",
        "AmsiUtils",
    }
)
_KEYWORD_BY_FOLD = {word.casefold(): word for word in POWERSHELL_KEYWORDS}
# Palabras que también usan scripts administrativos legítimos (convertir un SecureString,
# llamar a una API de Windows). Su presencia explica el aviso pero no lo hace benigno.
COMMON_ADMIN_KEYWORDS = frozenset({"InteropServices", "Marshal", "PtrToString", "IntPtr"})

# Scripts y servicios que distribuye Sentra (nombres, en minúsculas).
SENTRA_SCRIPTS = frozenset(
    {
        "install-sentra-agent.ps1",
        "uninstall-sentra-agent.ps1",
        "install-sentra-sensor.ps1",
        "setup_windows.ps1",
        "init_database.ps1",
        "start_backend.ps1",
        "start_frontend.ps1",
        "start_agent.ps1",
    }
)
SENTRA_SERVICES = frozenset({"sentraagent", "sentrasensor", "sentraisolation"})
# Módulos con los que arrancan los componentes de Sentra (línea de comandos del proceso).
_SENTRA_MODULES = (
    ("sentra_agent", re.compile(r"(?i)-m\s+sentra_agent\b")),
    ("sentra_sensor", re.compile(r"(?i)-m\s+sentra_sensor\b")),
    ("sentra_api", re.compile(r"(?i)\buvicorn\b.*\bapp\.main:app\b")),
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
# Un proceso puede haber terminado poco antes de que llegara su evento: margen de búsqueda.
PROCESS_SLACK = timedelta(minutes=2)
CMDLINE_MAX = 512


def basename(path: str | None) -> str:
    """Último componente de una ruta Windows o POSIX, en minúsculas (como behavior.basename,
    que no se importa para no crear un ciclo con signals)."""
    if not path:
        return ""
    return re.split(r"[\\/]", path.strip())[-1].lower()


def _int(value: Any, low: int, high: int) -> int | None:
    if isinstance(value, str) and value.strip().isdigit():
        number = int(value.strip())
        return number if low <= number <= high else None
    return None


def keywords(value: Any) -> list[str]:
    if not isinstance(value, str):
        return []
    found = []
    for item in value.split(","):
        word = _KEYWORD_BY_FOLD.get(item.strip().casefold())
        if word and word not in found:
            found.append(word)
    return found[:12]


def sentra_module(cmdline: str | None) -> str | None:
    """Componente de Sentra por su línea de comandos (pista, no prueba)."""
    if not cmdline:
        return None
    for name, pattern in _SENTRA_MODULES:
        if pattern.search(cmdline):
            return name
    return None


def powershell_values(data: Mapping[str, Any]) -> dict[str, Any]:
    """Campos de un 4104 del agente 0.6.0, validados. Un agente anterior no envía ninguno."""
    path = text.clean_or_none(data.get("Path"), 512)
    digest = str(data.get("ScriptSha256") or "").strip().lower()
    block = str(data.get("ScriptBlockId") or "").strip().lower()
    name = basename(path) if path else None
    values: dict[str, Any] = {
        "script_path": path,
        "script_name": name,
        "script_sha256": digest if _SHA256.match(digest) else None,
        "script_block_id": block if _GUID.match(block) else None,
        "script_part": _int(data.get("MessageNumber"), 1, 100_000),
        "script_parts": _int(data.get("MessageTotal"), 1, 100_000),
        "pid": _int(data.get("ProcessID"), 0, 2**32 - 1),
        "user_sid": text.sid(data.get("UserID")),
        "keywords": keywords(data.get("SuspiciousKeywords")),
        # Sin ruta: tecleado en una consola o pasado con -Command/-EncodedCommand.
        "script_origin": "file" if path else ("inline" if block else None),
        "sentra_script": bool(name and name in SENTRA_SCRIPTS),
    }
    return values


def process_context(
    session: Session, asset_id: int, pid: int, at: datetime
) -> dict[str, Any] | None:
    """Proceso con ese PID vivo en `at` según la telemetría 6E.4, con su padre (o None).

    Los PID se reutilizan: solo vale una instancia que empezó antes de `at` y no había
    terminado (con un margen). Si hay varias, la más reciente.
    """
    process = session.scalars(
        select(ProcessInstance)
        .where(
            ProcessInstance.asset_id == asset_id,
            ProcessInstance.pid == pid,
            or_(ProcessInstance.started_at.is_(None), ProcessInstance.started_at <= at),
            or_(
                ProcessInstance.ended_at.is_(None),
                ProcessInstance.ended_at >= at - PROCESS_SLACK,
            ),
            ProcessInstance.last_seen_at >= at - timedelta(days=1),
        )
        .order_by(ProcessInstance.started_at.desc().nulls_last(), ProcessInstance.id.desc())
        .limit(1)
    ).first()
    if process is None:
        return None
    parent = None
    if process.parent_instance_key:
        parent = session.scalars(
            select(ProcessInstance).where(
                ProcessInstance.asset_id == asset_id,
                ProcessInstance.instance_key == process.parent_instance_key,
            )
        ).first()
    return {
        "process_name": basename(process.name or process.exe) or None,
        "process_exe": process.exe,
        "process_cmdline": text.clean_or_none(process.cmdline, CMDLINE_MAX),
        "process_user": process.username,
        "process_sha256": process.sha256,
        "process_signer": process.signer,
        "parent_name": (basename(parent.name or parent.exe) or None) if parent else None,
        "parent_exe": parent.exe if parent else None,
        "parent_cmdline": text.clean_or_none(parent.cmdline, CMDLINE_MAX) if parent else None,
        "sentra_component": sentra_module(parent.cmdline if parent else None)
        or sentra_module(process.cmdline),
    }


def listener_owner(session: Session, asset_id: int, port: int) -> dict[str, Any] | None:
    """Proceso que escucha en `port` según el último inventario del agente (o None)."""
    data = session.scalar(select(AssetInventory.data).where(AssetInventory.asset_id == asset_id))
    connections = data.get("connections") if isinstance(data, dict) else None
    if not isinstance(connections, list):
        return None
    listener = None
    for connection in connections:
        if (
            isinstance(connection, dict)
            and connection.get("status") == "listen"
            and connection.get("protocol") == "tcp"
            and connection.get("local_port") == port
        ):
            listener = connection
            # Una escucha en todas las interfaces explica mejor la exposición que una en
            # loopback del mismo puerto.
            if not str(connection.get("local_address") or "").startswith("127."):
                break
    if listener is None:
        return None
    owner: dict[str, Any] = {
        "listener_address": text.clean_or_none(listener.get("local_address"), 64),
        "name": basename(str(listener.get("process_name") or "")) or None,
    }
    pid = listener.get("pid")
    if isinstance(pid, int) and not isinstance(pid, bool) and pid > 0:
        owner["pid"] = pid
        process = session.scalars(
            select(ProcessInstance)
            .where(
                ProcessInstance.asset_id == asset_id,
                ProcessInstance.pid == pid,
                ProcessInstance.ended_at.is_(None),
            )
            .order_by(ProcessInstance.last_seen_at.desc())
            .limit(1)
        ).first()
        if process is not None:
            owner.update(
                {
                    "name": basename(process.name or process.exe) or owner["name"],
                    "exe": process.exe,
                    "sha256": process.sha256,
                    "signer": process.signer,
                    "process_user": process.username,
                    "process_cmdline": text.clean_or_none(process.cmdline, CMDLINE_MAX),
                    "sentra_component": sentra_module(process.cmdline),
                }
            )
    return owner
