"""Detección de comportamiento sobre la telemetría de endpoint (Fase 6E.5).

Extiende el Detection Engine existente, no lo sustituye: la ingesta (endpoint/service.py)
convierte en señales SOLO los eventos que encajan en algún patrón de este fichero, y las
reglas BEH-* (registradas en rules.py) deciden severidad, confianza y deduplicación con el
mismo motor, cooldown, evidencia y alertas que el resto.

Criterios (docs/behavioral-detection.md):
- ninguna regla responde sola: no hay aislamiento, kill ni bloqueo automático;
- la severidad la fija la regla, nunca un modelo de IA;
- una señal débil (ubicación inusual sin más) nunca pasa de confianza baja;
- los patrones son listas cerradas y explicables, no puntuaciones opacas.
"""

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.detection.signals import SignalDraft, SignalKind, SourceType, unusual_location

# --- patrones de proceso ----------------------------------------------------------------------

# Aplicaciones que abren documentos recibidos (correo, ofimática, lector PDF).
DOCUMENT_APPS = frozenset(
    {
        "winword.exe",
        "excel.exe",
        "powerpnt.exe",
        "outlook.exe",
        "msaccess.exe",
        "mspub.exe",
        "onenote.exe",
        "acrord32.exe",
        "acrobat.exe",
        "foxitreader.exe",
        "soffice.bin",
    }
)
# Intérpretes y binarios del sistema que se abusan para ejecutar código.
SHELLS = frozenset(
    {
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "msbuild.exe",
        "installutil.exe",
        "bitsadmin.exe",
        "certutil.exe",
        "sh",
        "bash",
        "dash",
        "zsh",
        "python",
        "python3",
        "perl",
    }
)

# Líneas de comando sospechosas: (identificador estable, patrón, descripción).
SUSPICIOUS_CMDLINE: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "powershell_encoded",
        re.compile(r"(?i)(?:^|\s)-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedcommand)\s"),
        "PowerShell con orden codificada (-EncodedCommand)",
    ),
    (
        "powershell_download",
        re.compile(
            r"(?i)(?:downloadstring|downloadfile|invoke-webrequest|iwr\s|invoke-restmethod|"
            r"net\.webclient|start-bitstransfer)[\s\S]{0,200}(?:iex|invoke-expression|\|\s*iex)"
            r"|(?:iex|invoke-expression)[\s\S]{0,200}(?:downloadstring|net\.webclient)"
        ),
        "PowerShell que descarga y ejecuta código",
    ),
    (
        "certutil_download",
        re.compile(r"(?i)certutil(?:\.exe)?\s.*-(?:urlcache|verifyctl).*https?://"),
        "certutil usado para descargar un fichero",
    ),
    (
        "bitsadmin_transfer",
        re.compile(r"(?i)bitsadmin(?:\.exe)?\s.*/transfer\s.*https?://"),
        "bitsadmin usado para descargar un fichero",
    ),
    (
        "mshta_remote",
        re.compile(r"(?i)mshta(?:\.exe)?\s+[\"']?(?:https?:|javascript:|vbscript:)"),
        "mshta ejecutando contenido remoto o en línea",
    ),
    (
        "regsvr32_remote",
        re.compile(r"(?i)regsvr32(?:\.exe)?\s.*/i:\s*[\"']?https?://"),
        "regsvr32 cargando un scriptlet remoto",
    ),
    (
        "pipe_to_shell",
        re.compile(r"(?i)(?:curl|wget)\s[^|;]*\|\s*(?:sudo\s+)?(?:ba|da|z)?sh\b"),
        "Descarga canalizada directamente a un intérprete (curl|sh)",
    ),
    (
        "base64_to_shell",
        re.compile(r"(?i)base64\s+(?:-d|--decode)[^|;]*\|\s*(?:ba|da|z)?sh\b"),
        "Contenido base64 decodificado y ejecutado en un intérprete",
    ),
)


def basename(path: str | None) -> str:
    if not path:
        return ""
    return re.split(r"[\\/]", path.strip())[-1].lower()


def cmdline_findings(cmdline: str | None) -> list[str]:
    if not cmdline:
        return []
    return [key for key, pattern, _ in SUSPICIOUS_CMDLINE if pattern.search(cmdline)]


CMDLINE_TEXT = {key: description for key, _, description in SUSPICIOUS_CMDLINE}


def is_private(address: str | None) -> bool:
    if not address:
        return True
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return True
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


@dataclass(frozen=True)
class ProcessFacts:
    """Lo que la extracción necesita del proceso y de su padre (instancias guardadas)."""

    name: str | None
    exe: str | None


# --- extracción de señales ----------------------------------------------------------------------


def _base(event: Any) -> dict[str, Any]:
    return {"event_uid": str(event.event_uid), "source": event.source, "action": event.action}


def process_start_signal(
    event: Any, parent: ProcessFacts | None, occurred_at: datetime
) -> SignalDraft | None:
    """Señal PROCESS_START solo si el inicio encaja en un patrón (si no, nada)."""
    data: Mapping[str, Any] = event.data
    name = basename(data.get("name") or data.get("exe"))
    parent_name = basename(parent.name or parent.exe) if parent else ""
    cmdline = data.get("cmdline")
    findings = cmdline_findings(cmdline)
    document_child = parent_name in DOCUMENT_APPS and name in SHELLS
    unusual = unusual_location(data.get("exe"))
    if not findings and not document_child and not unusual:
        return None
    return SignalDraft(
        kind=SignalKind.PROCESS_START,
        occurred_at=occurred_at,
        source_type=SourceType.ENDPOINT_ACTIVITY,
        subject=(data.get("exe") or name or None),
        source_id=str(event.event_uid),
        data={
            **_base(event),
            "instance_key": event.instance_key,
            "parent_instance_key": data.get("parent_instance_key"),
            "parent_relation": data.get("parent_relation"),
            "name": name or None,
            "exe": data.get("exe"),
            "cmdline": cmdline,
            "username": data.get("username"),
            "sha256": data.get("sha256"),
            "signer": data.get("signer"),
            "parent_name": parent_name or None,
            "parent_exe": parent.exe if parent else None,
            "document_child": document_child,
            "cmdline_findings": findings,
            "unusual_location": unusual,
        },
    )


def process_network_signal(
    event: Any, process: ProcessFacts | None, occurred_at: datetime
) -> SignalDraft | None:
    """Conexión saliente a Internet de un proceso que corre desde una ubicación inusual."""
    data: Mapping[str, Any] = event.data
    if event.action != "connect" or data.get("direction") == "inbound":
        return None
    if process is None or is_private(data.get("remote_address")):
        return None
    unusual = unusual_location(process.exe)
    if not unusual:
        return None
    return SignalDraft(
        kind=SignalKind.PROCESS_NETWORK,
        occurred_at=occurred_at,
        source_type=SourceType.ENDPOINT_ACTIVITY,
        subject=process.exe,
        source_id=str(event.event_uid),
        data={
            **_base(event),
            "instance_key": event.instance_key,
            "name": basename(process.name or process.exe) or None,
            "exe": process.exe,
            "remote_address": data.get("remote_address"),
            "remote_port": data.get("remote_port"),
            "protocol": data.get("protocol"),
            "unusual_location": unusual,
        },
    )


def persistence_signal(event: Any, occurred_at: datetime) -> SignalDraft | None:
    """Mecanismo de persistencia o tarea programada creado o modificado."""
    data: Mapping[str, Any] = event.data
    if event.action == "deleted":
        return None
    mechanism: Any
    if event.category == "scheduled_task":
        mechanism, target, location = "scheduled_task", data.get("exe"), data.get("path")
    else:
        mechanism = data.get("mechanism")
        target, location = data.get("target"), data.get("location")
    return SignalDraft(
        kind=SignalKind.PERSISTENCE_CHANGE,
        occurred_at=occurred_at,
        source_type=SourceType.ENDPOINT_ACTIVITY,
        subject=f"{mechanism}|{data.get('name') or location or ''}"[:255],
        source_id=str(event.event_uid),
        data={
            **_base(event),
            "mechanism": mechanism,
            "name": data.get("name"),
            "location": location,
            "target": target,
            "unusual_location": unusual_location(target),
            "suspicious_target": cmdline_findings(target),
        },
    )


PROTECTION_FIELDS = ("realtime_enabled", "antivirus_enabled", "tamper_protection")


def protection_signal(
    event: Any, previous: Mapping[str, Any] | None, occurred_at: datetime
) -> SignalDraft | None:
    """Protección que pasa de activa a inactiva respecto al último estado conocido.

    Sin estado anterior no se concluye nada: el primer informe es la línea base (un equipo
    que nunca tuvo protección no es un "desactivado" ahora).
    """
    if previous is None:
        return None
    data: Mapping[str, Any] = event.data
    turned_off = [f for f in PROTECTION_FIELDS if previous.get(f) is True and data.get(f) is False]
    if not turned_off:
        return None
    return SignalDraft(
        kind=SignalKind.PROTECTION_CHANGE,
        occurred_at=occurred_at,
        source_type=SourceType.ENDPOINT_ACTIVITY,
        subject=str(data.get("product") or "protection")[:255],
        source_id=str(event.event_uid),
        data={**_base(event), "product": data.get("product"), "disabled": turned_off},
    )


def firewall_signal(
    event: Any, previous: Mapping[str, Any] | None, occurred_at: datetime
) -> SignalDraft | None:
    if previous is None:
        return None
    data: Mapping[str, Any] = event.data
    if not (previous.get("enabled") is True and data.get("enabled") is False):
        return None
    return SignalDraft(
        kind=SignalKind.FIREWALL_CHANGE,
        occurred_at=occurred_at,
        source_type=SourceType.ENDPOINT_ACTIVITY,
        subject=str(data.get("profile") or "default")[:255],
        source_id=str(event.event_uid),
        data={**_base(event), "profile": data.get("profile"), "enabled": False},
    )


def state_key(category: str, data: Mapping[str, Any]) -> str:
    """Clave del estado comparable: producto (protección) o perfil (firewall)."""
    field = "product" if category == "protection" else "profile"
    return str(data.get(field) or "")
