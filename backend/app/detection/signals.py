"""Extracción de señales: de hechos en bruto a hechos de seguridad normalizados.

Funciones puras (sin base de datos) para que cada mapeo se pruebe por separado. Toda la
dependencia de ids de evento de Windows está aquí, en tablas, y no repartida por servicios:
las reglas solo conocen tipos de señal (SignalKind).

Los ids salen de lo que el agente realmente recoge (sentra_agent/events.py, CHANNELS); un
evento que el agente no envía no aparece aquí.
"""

import enum
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from app.detection import text
from app.discovery.ports import SENSITIVE_PORTS, SERVICE_HINTS
from app.models.change import ChangeCategory, ChangeKind
from app.models.event import EventLevel, SystemEvent


class SignalKind(enum.StrEnum):
    AUTH_FAILURE = "auth_failure"
    AUTH_SUCCESS = "auth_success"
    ACCOUNT_LOCKOUT = "account_lockout"
    ACCOUNT_CREATED = "account_created"
    ACCOUNT_ENABLED = "account_enabled"
    ACCOUNT_DISABLED = "account_disabled"
    ACCOUNT_DELETED = "account_deleted"
    ADMIN_GROUP_ADDED = "admin_group_added"
    ADMIN_GROUP_REMOVED = "admin_group_removed"
    AUDIT_POLICY_CHANGED = "audit_policy_changed"
    LOG_CLEARED = "log_cleared"
    SERVICE_INSTALLED = "service_installed"
    SERVICE_ADDED = "service_added"
    SECURITY_SERVICE_DOWN = "security_service_down"
    SERVICE_CRASHED = "service_crashed"
    UNEXPECTED_SHUTDOWN = "unexpected_shutdown"
    POWERSHELL_SUSPICIOUS = "powershell_suspicious"
    MALWARE_DETECTED = "malware_detected"
    ANTIMALWARE_DISABLED = "antimalware_disabled"
    PROCESS_NEW = "process_new"
    LISTEN_PORT_NEW = "listen_port_new"
    PORT_EXPOSED = "port_exposed"
    ASSET_DISCOVERED = "asset_discovered"
    ASSET_DISAPPEARED = "asset_disappeared"
    # Fase 5A: evento del sistema en bruto para reglas personalizadas por canal. Solo se
    # registra para canales con alguna regla activa (recorder.py): sin reglas, cero filas.
    EVENT = "event"
    # Fase 5C: un IOC casó con actividad local (evento o conexión) y la política de
    # THREAT_INTEL_DETECTION_POLICY lo permite. Lo emite app/threat_intel/matching.py.
    THREAT_INTEL_MATCH = "threat_intel_match"


class SourceType(enum.StrEnum):
    SYSTEM_EVENT = "system_event"
    INVENTORY = "inventory"
    PROCESS_SNAPSHOT = "process_snapshot"
    DISCOVERY = "discovery"
    THREAT_INTEL = "threat_intel"


@dataclass(frozen=True)
class SignalDraft:
    """Una señal antes de guardarse. `data` ya va acotado y saneado."""

    kind: SignalKind
    occurred_at: datetime
    source_type: SourceType
    subject: str | None = None
    source_id: str | None = None
    data: dict[str, Any] = field(default_factory=dict)


SECURITY = "Security"
SYSTEM = "System"
POWERSHELL = "Microsoft-Windows-PowerShell/Operational"
DEFENDER = "Microsoft-Windows-Windows Defender/Operational"

# Grupos privilegiados por SID, independiente del idioma de Windows ("Administradores").
_PRIVILEGED_BUILTIN = {
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-32-551": "Backup Operators",
    "S-1-5-32-555": "Remote Desktop Users",
}
# Grupos de dominio por RID final (S-1-5-21-<dominio>-RID).
_PRIVILEGED_DOMAIN_RID = {
    "512": "Domain Admins",
    "518": "Schema Admins",
    "519": "Enterprise Admins",
}

# Logons que no son de una persona: sistema, gestor de ventanas (DWM) y host de fuentes
# (UMFD) generan 4624 de tipo 2 en cada inicio de sesión y no aportan nada.
_SERVICE_SID_PREFIXES = ("S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-5-90-", "S-1-5-96-")
_SERVICE_DOMAINS = {"window manager", "font driver host", "nt authority"}

# 4719: AuditPolicyChanges lleva códigos de mensaje; "%%8448" = éxito eliminado y "%%8450" =
# fallo eliminado. Una auditoría que se quita es lo que interesa (ocultar actividad).
_AUDIT_REMOVED = ("%%8448", "%%8450")

_MALWARE_OUTCOME = {
    1116: "detected",
    1117: "action_taken",
    1118: "action_failed",
    1119: "critical_failure",
}
_ANTIMALWARE_FEATURE = {5001: "real-time protection", 5010: "antispyware", 5012: "antivirus"}


def privileged_group(group_sid: str | None) -> str | None:
    if group_sid is None:
        return None
    if group_sid in _PRIVILEGED_BUILTIN:
        return _PRIVILEGED_BUILTIN[group_sid]
    if group_sid.startswith("S-1-5-21-"):
        return _PRIVILEGED_DOMAIN_RID.get(group_sid.rsplit("-", 1)[-1])
    return None


# Rutas desde las que un ejecutable legítimo rara vez corre: carpetas temporales y públicas,
# escritura para cualquier usuario. No es una lista de "malware": es una señal débil que
# por sí sola da confianza baja (PROC-001) y que sube en correlación.
_UNUSUAL_WINDOWS = (
    (re.compile(r"\\appdata\\local\\temp\\"), "user temp folder"),
    (re.compile(r"^[a-z]:\\windows\\temp\\"), "Windows temp folder"),
    (re.compile(r"^[a-z]:\\users\\public\\"), "public user folder"),
    (re.compile(r"\\\$recycle\.bin\\"), "recycle bin"),
    (re.compile(r"^[a-z]:\\perflogs\\"), "PerfLogs folder"),
    (re.compile(r"^[a-z]:\\programdata\\[^\\]+$"), "ProgramData root"),
    (re.compile(r"\\appdata\\roaming\\[^\\]+$"), "AppData\\Roaming root"),
)
# Solo patrones de texto para clasificar rutas reportadas por el host (no se abre nada).
_UNUSUAL_POSIX = (
    (re.compile(r"^/tmp/"), "/tmp"),  # noqa: S108
    (re.compile(r"^/var/tmp/"), "/var/tmp"),  # noqa: S108
    (re.compile(r"^/dev/shm/"), "/dev/shm"),  # noqa: S108
)


def unusual_location(path: str | None) -> str | None:
    """Motivo si el ejecutable corre desde una ubicación inusual, o None."""
    if not path:
        return None
    lowered = path.strip().lower()
    # Linux: psutil añade " (deleted)" si el binario en ejecución se borró del disco.
    if lowered.endswith(" (deleted)"):
        return "binary deleted from disk while running"
    patterns = _UNUSUAL_POSIX if lowered.startswith("/") else _UNUSUAL_WINDOWS
    for pattern, reason in patterns:
        if pattern.search(lowered):
            return reason
    return None


def is_sensitive_port(port: int) -> bool:
    return port in SENSITIVE_PORTS


def _event_data(event: SystemEvent) -> Mapping[str, Any]:
    return event.data if isinstance(event.data, dict) else {}


def _base(event: SystemEvent) -> dict[str, Any]:
    return {
        "channel": event.channel,
        "event_code": event.event_code,
        "provider": event.provider,
        "record_id": event.record_id,
    }


def _account(data: Mapping[str, Any], prefix: str = "Target") -> dict[str, Any]:
    name_key = f"{prefix}UserName"
    sid_key = "TargetSid" if prefix == "Target" else f"{prefix}UserSid"
    return {
        "account": text.clean_or_none(data.get(name_key), 255),
        "domain": text.clean_or_none(data.get(f"{prefix}DomainName"), 255),
        "sid": text.sid(data.get(sid_key) or data.get(f"{prefix}UserSid")),
    }


def _actor(data: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "actor": text.clean_or_none(data.get("SubjectUserName"), 255),
        "actor_sid": text.sid(data.get("SubjectUserSid")),
    }


def _security_signal(event: SystemEvent) -> SignalDraft | None:
    data = _event_data(event)
    code = event.event_code
    draft = _draft_factory(event)
    if code in (4624, 4625):
        account = {
            "account": text.clean_or_none(data.get("TargetUserName"), 255),
            "domain": text.clean_or_none(data.get("TargetDomainName"), 255),
            "sid": text.sid(data.get("TargetUserSid")),
            "logon_type": text.clean_or_none(data.get("LogonType"), 8),
            "source_ip": text.clean_or_none(data.get("IpAddress"), 64),
            "workstation": text.clean_or_none(data.get("WorkstationName"), 255),
        }
        if code == 4625:
            account["status"] = text.clean_or_none(data.get("Status"), 16)
            account["sub_status"] = text.clean_or_none(data.get("SubStatus"), 16)
            return draft(SignalKind.AUTH_FAILURE, text.principal(account["account"]), account)
        sid = account["sid"] or ""
        domain = (account["domain"] or "").lower()
        if sid.startswith(_SERVICE_SID_PREFIXES) or domain in _SERVICE_DOMAINS:
            return None
        return draft(SignalKind.AUTH_SUCCESS, text.principal(account["account"]), account)
    account_kinds = {
        4720: SignalKind.ACCOUNT_CREATED,
        4722: SignalKind.ACCOUNT_ENABLED,
        4725: SignalKind.ACCOUNT_DISABLED,
        4726: SignalKind.ACCOUNT_DELETED,
        4740: SignalKind.ACCOUNT_LOCKOUT,
    }
    if code in account_kinds:
        values = {**_account(data), **_actor(data)}
        return draft(account_kinds[code], text.principal(values["account"]), values)
    if code in (4728, 4732, 4756, 4729, 4733, 4757):
        group_sid = text.sid(data.get("TargetSid"))
        group = privileged_group(group_sid)
        # Sin SID del grupo (agente anterior a 4H) no se sabe si es privilegiado: el inventario
        # (admin_granted) cubre ese caso sin depender del evento.
        if group is None:
            return None
        member = text.clean_or_none(data.get("MemberName"), 255)
        member_sid = text.sid(data.get("MemberSid"))
        values = {
            "account": member,
            "sid": member_sid,
            "group": group,
            "group_name": text.clean_or_none(data.get("TargetUserName"), 255),
            "group_sid": group_sid,
            **_actor(data),
        }
        added = code in (4728, 4732, 4756)
        kind = SignalKind.ADMIN_GROUP_ADDED if added else SignalKind.ADMIN_GROUP_REMOVED
        # Las cuentas locales llegan con MemberName "-": el SID es entonces el sujeto.
        return draft(kind, text.principal(member) or (member_sid or "").lower() or None, values)
    if code == 4719:
        changes = text.clean_or_none(data.get("AuditPolicyChanges"), 128)
        values = {
            "changes": changes,
            "subcategory_guid": text.clean_or_none(data.get("SubcategoryGuid"), 64),
            # None: el agente no envió el detalle (no se sabe si se quitó o se añadió).
            "removed": any(mark in changes for mark in _AUDIT_REMOVED) if changes else None,
            **_actor(data),
        }
        return draft(SignalKind.AUDIT_POLICY_CHANGED, None, values)
    if code == 1102:
        return draft(SignalKind.LOG_CLEARED, "security", {"log": "Security", **_actor(data)})
    return None


def _system_signal(event: SystemEvent) -> SignalDraft | None:
    data = _event_data(event)
    code = event.event_code
    provider = event.provider.lower()
    draft = _draft_factory(event)
    if code == 104 and "eventlog" in provider:
        log = text.clean_or_none(data.get("Channel"), 255) or "System"
        return draft(SignalKind.LOG_CLEARED, log.lower(), {"log": log, **_actor(data)})
    if code == 7045 and provider == "service control manager":
        name = text.clean_or_none(data.get("ServiceName"), 255)
        image = text.clean_or_none(data.get("ImagePath"))
        values = {
            "service": name,
            "image_path": image,
            "start_type": text.clean_or_none(data.get("StartType"), 32),
            "account": text.clean_or_none(data.get("AccountName"), 255),
            "unusual_location": unusual_location(_image_executable(image)),
        }
        return draft(SignalKind.SERVICE_INSTALLED, name.lower() if name else None, values)
    if code in (7031, 7034) and provider == "service control manager":
        name = text.clean_or_none(data.get("param1"), 255)
        return draft(SignalKind.SERVICE_CRASHED, name.lower() if name else None, {"service": name})
    if (code == 41 and provider == "microsoft-windows-kernel-power") or (
        code == 6008 and provider == "eventlog"
    ):
        values = {"bugcheck_code": text.clean_or_none(data.get("BugcheckCode"), 32)}
        return draft(SignalKind.UNEXPECTED_SHUTDOWN, None, values)
    return None


def _defender_signal(event: SystemEvent) -> SignalDraft | None:
    data = _event_data(event)
    code = event.event_code
    draft = _draft_factory(event)
    if code in _MALWARE_OUTCOME:
        threat = text.clean_or_none(data.get("Threat Name"), 255)
        values = {
            "threat": threat,
            "outcome": _MALWARE_OUTCOME[code],
            "defender_severity": text.clean_or_none(data.get("Severity Name"), 32),
            "category": text.clean_or_none(data.get("Category Name"), 64),
            "action": text.clean_or_none(data.get("Action Name"), 64),
            "path": text.clean_or_none(data.get("Path")),
            "user": text.clean_or_none(data.get("Detection User"), 255),
            "process": text.clean_or_none(data.get("Process Name")),
        }
        return draft(SignalKind.MALWARE_DETECTED, threat.lower() if threat else None, values)
    if code in _ANTIMALWARE_FEATURE:
        feature = _ANTIMALWARE_FEATURE[code]
        return draft(SignalKind.ANTIMALWARE_DISABLED, feature, {"feature": feature})
    return None


def _draft_factory(
    event: SystemEvent,
) -> Callable[[SignalKind, str | None, dict[str, Any]], SignalDraft]:
    def build(kind: SignalKind, subject: str | None, values: dict[str, Any]) -> SignalDraft:
        return SignalDraft(
            kind=kind,
            occurred_at=event.occurred_at,
            source_type=SourceType.SYSTEM_EVENT,
            subject=subject[:255] if subject else None,
            source_id=str(event.public_id),
            data=text.bounded_data({**_base(event), **values}),
        )

    return build


def _image_executable(image_path: str | None) -> str | None:
    """Ejecutable de un ImagePath de servicio (puede llevar comillas y argumentos)."""
    if not image_path:
        return None
    value = image_path.strip()
    if value.startswith('"'):
        return value[1:].split('"', 1)[0]
    lowered = value.lower()
    end = lowered.find(".exe")
    return value[: end + 4] if end != -1 else value.split(" ", 1)[0]


def signals_from_events(events: Iterable[SystemEvent], not_before: datetime) -> list[SignalDraft]:
    """Señales de eventos recién guardados (nunca de un reenvío, que no se inserta).

    `not_before`: eventos más antiguos no producen señales (primer envío de un agente,
    backlog muy viejo): el pasado no se convierte en detecciones nuevas.
    """
    drafts: list[SignalDraft] = []
    for event in events:
        if event.occurred_at < not_before:
            continue
        signal: SignalDraft | None = None
        if event.channel == SECURITY:
            signal = _security_signal(event)
        elif event.channel == SYSTEM:
            signal = _system_signal(event)
        elif event.channel == DEFENDER:
            signal = _defender_signal(event)
        elif (
            event.channel == POWERSHELL
            and event.event_code == 4104
            and event.level != EventLevel.INFO
        ):
            # PowerShell registra 4104 como Warning solo cuando el propio motor de scripts
            # marca el bloque como sospechoso. El agente no envía el contenido, así que esta
            # señal es todo lo que sabemos: por sí sola, confianza media (SCR-001).
            signal = _draft_factory(event)(SignalKind.POWERSHELL_SUSPICIOUS, None, {})
        if signal is not None:
            drafts.append(signal)
    return drafts


# Mensaje evaluable por reglas personalizadas: suficiente para "contains" sobre el texto
# habitual de un evento sin copiar los 4000 caracteres completos a cada señal.
RAW_MESSAGE_MAX = 1024


def raw_event_signals(
    events: Iterable[SystemEvent], not_before: datetime, channels: frozenset[str]
) -> list[SignalDraft]:
    """Señales EVENT (Fase 5A): copia acotada de cada evento de un canal con reglas activas.

    Mismas garantías que las demás señales: no se generan para backlog antiguo y los datos
    van saneados (texto de una línea, longitud acotada). Las claves son las rutas del
    catálogo de campos (app/detection/custom/catalog.py).
    """
    drafts: list[SignalDraft] = []
    for event in events:
        if event.occurred_at < not_before or event.channel not in channels:
            continue
        values: dict[str, Any] = {
            "channel": event.channel,
            "code": event.event_code,
            "provider": event.provider,
            "level": event.level.value,
            "computer": text.clean_or_none(event.computer, 255),
            "record_id": event.record_id,
            "message": text.clean(event.message, RAW_MESSAGE_MAX) or None,
        }
        for key, value in list(_event_data(event).items())[: text.MAX_FIELDS]:
            if isinstance(value, str):
                values[f"data.{text.clean(key, 64)}"] = text.clean(value)
        drafts.append(
            SignalDraft(
                kind=SignalKind.EVENT,
                occurred_at=event.occurred_at,
                source_type=SourceType.SYSTEM_EVENT,
                subject=f"{event.channel}:{event.event_code}"[:255],
                source_id=str(event.public_id),
                # Sin bounded_data: necesita más campos (base + hasta 24 de EventData) y el
                # mensaje más largo; cada valor ya se limpia y acota arriba.
                data={key: value for key, value in values.items() if value is not None},
            )
        )
    return drafts


class ChangeLike(Protocol):
    @property
    def category(self) -> ChangeCategory: ...
    @property
    def kind(self) -> ChangeKind: ...
    @property
    def item(self) -> str: ...
    @property
    def details(self) -> dict[str, Any] | None: ...


def signals_from_inventory_changes(
    changes: Sequence[ChangeLike], occurred_at: datetime, security_services: frozenset[str]
) -> list[SignalDraft]:
    """Señales de los cambios entre dos snapshots de inventario (change_detection.py).

    Reutiliza el diff existente en lugar de recalcularlo; el primer snapshot no tiene
    anterior, así que nunca produce señales (es la línea base).
    """
    drafts: list[SignalDraft] = []

    def add(kind: SignalKind, subject: str, values: dict[str, Any]) -> None:
        drafts.append(
            SignalDraft(
                kind=kind,
                occurred_at=occurred_at,
                source_type=SourceType.INVENTORY,
                subject=subject.lower()[:255],
                data=text.bounded_data(values),
            )
        )

    for change in changes:
        details = change.details or {}
        name = text.clean(change.item, 255)
        if change.category is ChangeCategory.SERVICE:
            if change.kind is ChangeKind.ADDED:
                add(
                    SignalKind.SERVICE_ADDED,
                    name,
                    {
                        "service": name,
                        "status": details.get("status"),
                        "start_type": details.get("start_type"),
                    },
                )
            elif name.lower() in security_services and (
                change.kind in (ChangeKind.STOPPED, ChangeKind.REMOVED)
                or (
                    change.kind is ChangeKind.START_TYPE_CHANGED
                    and str(details.get("after") or "").lower() == "disabled"
                )
            ):
                add(
                    SignalKind.SECURITY_SERVICE_DOWN,
                    name,
                    {
                        "service": name,
                        "change": change.kind.value,
                        "before": details.get("before"),
                        "after": details.get("after"),
                    },
                )
        elif change.category is ChangeCategory.ACCOUNT:
            account = {"account": name, "source": "inventory"}
            if change.kind is ChangeKind.ADDED:
                add(
                    SignalKind.ACCOUNT_CREATED,
                    name,
                    {
                        **account,
                        "is_admin": details.get("is_admin"),
                        "enabled": details.get("enabled"),
                    },
                )
                if details.get("is_admin") is True:
                    add(SignalKind.ADMIN_GROUP_ADDED, name, {**account, "group": "Administrators"})
            elif change.kind is ChangeKind.ADMIN_GRANTED:
                add(SignalKind.ADMIN_GROUP_ADDED, name, {**account, "group": "Administrators"})
            elif change.kind is ChangeKind.ADMIN_REVOKED:
                add(SignalKind.ADMIN_GROUP_REMOVED, name, {**account, "group": "Administrators"})
            elif change.kind is ChangeKind.ENABLED:
                add(SignalKind.ACCOUNT_ENABLED, name, account)
            elif change.kind is ChangeKind.DISABLED:
                add(SignalKind.ACCOUNT_DISABLED, name, account)
            elif change.kind is ChangeKind.REMOVED:
                add(SignalKind.ACCOUNT_DELETED, name, account)
    return drafts


# Puertos dinámicos (RPC de Windows, clientes): abren y cierran continuamente.
EPHEMERAL_PORT_START = 49152


def _listeners(connections: Any) -> dict[int, dict[str, Any]] | None:
    """Puertos TCP en escucha accesibles desde fuera (no loopback) de un inventario."""
    if not isinstance(connections, list) or not connections:
        return None
    found: dict[int, dict[str, Any]] = {}
    for connection in connections:
        if not isinstance(connection, dict) or connection.get("status") != "listen":
            continue
        if connection.get("protocol") != "tcp":
            continue
        port = connection.get("local_port")
        address = str(connection.get("local_address") or "")
        if not isinstance(port, int) or port <= 0 or port >= EPHEMERAL_PORT_START:
            continue
        if address.startswith("127.") or address == "::1":
            continue
        found.setdefault(port, connection)
    return found


def signals_from_listeners(
    previous: Mapping[str, Any], current: Mapping[str, Any], occurred_at: datetime
) -> list[SignalDraft]:
    """Puertos en escucha nuevos según el agente, con el proceso que los abrió.

    Diferente de la exposición de discovery (alcanzable desde el servidor): aquí sabemos qué
    proceso escucha, aunque no si un firewall lo bloquea. Sin lista anterior o con una lista
    vacía (fallo de recogida) no se concluye nada.
    """
    before = _listeners(previous.get("connections"))
    after = _listeners(current.get("connections"))
    if before is None or after is None:
        return []
    drafts = []
    for port in sorted(after.keys() - before.keys()):
        connection = after[port]
        drafts.append(
            SignalDraft(
                kind=SignalKind.LISTEN_PORT_NEW,
                occurred_at=occurred_at,
                source_type=SourceType.INVENTORY,
                subject=str(port),
                data=text.bounded_data(
                    {
                        "port": port,
                        "service_hint": SERVICE_HINTS.get(port),
                        "sensitive": is_sensitive_port(port),
                        "local_address": connection.get("local_address"),
                        "process": connection.get("process_name"),
                        "pid": connection.get("pid"),
                    }
                ),
            )
        )
    return drafts


def signal_from_discovery_change(
    kind: ChangeKind, item: str, occurred_at: datetime, details: Mapping[str, Any]
) -> SignalDraft | None:
    """Señales de discovery: reutiliza su línea base (la primera pasada nunca es cambio)."""
    if kind is ChangeKind.PORT_OPENED:
        port_text = item.split("/", 1)[0]
        if not port_text.isdigit():
            return None
        port = int(port_text)
        return SignalDraft(
            kind=SignalKind.PORT_EXPOSED,
            occurred_at=occurred_at,
            source_type=SourceType.DISCOVERY,
            subject=str(port),
            data=text.bounded_data(
                {
                    "port": port,
                    "service_hint": SERVICE_HINTS.get(port),
                    "sensitive": is_sensitive_port(port),
                    "discovery_job_id": details.get("discovery_job_id"),
                }
            ),
        )
    if kind is ChangeKind.DISAPPEARED:
        return SignalDraft(
            kind=SignalKind.ASSET_DISAPPEARED,
            occurred_at=occurred_at,
            source_type=SourceType.DISCOVERY,
            subject=text.clean(item, 64),
            data=text.bounded_data(
                {"address": item, "discovery_job_id": details.get("discovery_job_id")}
            ),
        )
    return None
