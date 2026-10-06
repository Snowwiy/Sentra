"""Logsources y catálogo de campos que una regla personalizada puede usar (Fase 5A).

Todo sale de datos que Sentra REALMENTE recibe y guarda:
- logsources de evento: canales que el agente de Windows recoge (sentra_agent/events.py,
  CHANNELS) con los campos estructurados de su lista cerrada DATA_FIELDS;
- logsources de señal: las señales normalizadas del motor 4H (app/detection/signals.py),
  con las claves que realmente escribe cada extractor.

Un campo que no está aquí no existe para las reglas: una regla (o una Sigma) que pida
CommandLine, ScriptBlockText o ParentImage se marca unsupported en vez de "coincidir" con un
valor vacío. Ampliar el catálogo exige que el agente recoja antes el dato (fase del agente).

Cada campo tiene un `path` explícito dentro del registro que se evalúa. Las reglas nunca
nombran columnas ni claves arbitrarias: solo nombres de este catálogo (también la consulta
histórica, que traduce únicamente campos de esta allowlist a SQL parametrizado).
"""

import enum
from dataclasses import dataclass, field

from app.detection.signals import DEFENDER, POWERSHELL, SECURITY, SYSTEM, SignalKind
from app.models.asset_context import AssetEnvironment, AssetRole, NetworkZone
from app.models.event import EventLevel

APPLICATION = "Application"
# Señal "evento en bruto" (Fase 5A): un SystemEvent tal cual, para reglas sobre canales.
EVENT_KIND = SignalKind.EVENT.value


class FieldType(enum.StrEnum):
    STRING = "string"
    INTEGER = "integer"
    BOOLEAN = "boolean"


class Support(enum.StrEnum):
    SUPPORTED = "supported"
    PARTIAL = "partial"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class FieldSpec:
    name: str
    type: FieldType
    # Dónde está el valor: clave en los datos de la señal, "$kind"/"$subject" (atributos de
    # la señal) o "$asset.<atributo>" (contexto del activo, ver runtime.asset_record).
    path: str
    description: str
    # Valores posibles cuando el dominio es cerrado (ayuda a la UI y valida reglas).
    values: tuple[str, ...] = ()

    @property
    def is_asset(self) -> bool:
        return self.path.startswith("$asset.")


@dataclass(frozen=True)
class LogSource:
    name: str
    title: str
    # Tipos de señal que alimentan el logsource (o EVENT_KIND con `channel`).
    kinds: frozenset[str]
    channel: str | None
    platforms: tuple[str, ...]
    support: Support
    fields: dict[str, FieldSpec]
    notes: str
    # Ids de evento que el agente envía en este canal (vacío = filtrado por nivel).
    event_codes: tuple[int, ...] = ()
    sigma_hint: str = ""

    @property
    def is_event(self) -> bool:
        return self.channel is not None


def _f(
    name: str,
    path: str,
    description: str,
    type_: FieldType = FieldType.STRING,
    values: tuple[str, ...] = (),
) -> FieldSpec:
    return FieldSpec(name, type_, path, description, values)


INT, BOOL = FieldType.INTEGER, FieldType.BOOLEAN

# --- Contexto del activo (Fase 4L), disponible en todos los logsources -----------------------
# Contexto ADMINISTRATIVO: sirve para acotar una regla ("solo en producción"), nunca puede
# ser la única condición (validator.py lo exige): "es un servidor crítico" no es un compromiso.
ASSET_FIELDS: dict[str, FieldSpec] = {
    spec.name: spec
    for spec in (
        _f("asset.hostname", "$asset.hostname", "Nombre del activo (en minúsculas)."),
        _f("asset.os", "$asset.os", "Sistema operativo informado (os_name, minúsculas)."),
        _f(
            "asset.criticality",
            "$asset.criticality",
            "Criticidad del activo.",
            values=("low", "medium", "high", "critical"),
        ),
        _f("asset.role", "$asset.role", "Rol (contexto 4L).", values=tuple(AssetRole)),
        _f(
            "asset.environment",
            "$asset.environment",
            "Entorno (contexto 4L).",
            values=tuple(AssetEnvironment),
        ),
        _f(
            "asset.network_zone",
            "$asset.network_zone",
            "Zona de red (contexto 4L).",
            values=tuple(NetworkZone),
        ),
        _f(
            "asset.internet_exposed",
            "$asset.internet_exposed",
            "Expuesto a Internet según el contexto 4L (si se conoce).",
            BOOL,
        ),
    )
}

# --- Campos estructurados que envía el agente de Windows (copia de DATA_FIELDS) -------------
# Copia deliberada: el backend no importa el agente. tests/test_rule_catalog.py comprueba que
# coincide con agent/sentra_agent/events.py para que no diverjan sin que nadie lo note.
AGENT_DATA_FIELDS: dict[str, tuple[str, ...]] = {
    SYSTEM: (
        "SubjectUserName",
        "SubjectDomainName",
        "Channel",
        "ServiceName",
        "ImagePath",
        "ServiceType",
        "StartType",
        "AccountName",
        "param1",
        "param2",
        "BugcheckCode",
    ),
    SECURITY: (
        "TargetUserName",
        "TargetDomainName",
        "TargetSid",
        "TargetUserSid",
        "SubjectUserName",
        "SubjectUserSid",
        "SubjectDomainName",
        "MemberName",
        "MemberSid",
        "LogonType",
        "IpAddress",
        "WorkstationName",
        "Status",
        "SubStatus",
        "CategoryId",
        "SubcategoryId",
        "SubcategoryGuid",
        "AuditPolicyChanges",
    ),
    DEFENDER: (
        "Threat Name",
        "Severity Name",
        "Category Name",
        "Action Name",
        "Path",
        "Detection User",
        "Process Name",
    ),
}
AGENT_EVENT_CODES: dict[str, tuple[int, ...]] = {
    SECURITY: (
        1102,
        4624,
        4625,
        4719,
        4720,
        4722,
        4725,
        4726,
        4728,
        4729,
        4732,
        4733,
        4740,
        4756,
        4757,
    ),
    DEFENDER: (1116, 1117, 1118, 1119, 5001, 5010, 5012),
}


def _event_fields(channel: str, message: bool) -> dict[str, FieldSpec]:
    specs = [
        _f("event.code", "code", "Id del evento de Windows (EventID).", INT),
        _f("event.provider", "provider", "Proveedor (Provider Name)."),
        _f("event.channel", "channel", "Canal del registro de eventos."),
        _f("event.level", "level", "Nivel normalizado.", values=tuple(EventLevel)),
        _f("event.computer", "computer", "Equipo registrado en el evento (<Computer>)."),
    ]
    if message:
        specs.append(
            _f(
                "event.message",
                "message",
                "Mensaje renderizado (idioma del sistema; se evalúan los primeros 1024"
                " caracteres con espacios normalizados).",
            )
        )
    for name in AGENT_DATA_FIELDS.get(channel, ()):
        specs.append(_f(f"event.data.{name}", f"data.{name}", f"EventData {name} (texto)."))
    return {spec.name: spec for spec in specs}


def _signal_fields(*specs: FieldSpec, kinds: frozenset[str]) -> dict[str, FieldSpec]:
    base = [_f("signal.kind", "$kind", "Tipo de señal normalizada.", values=tuple(sorted(kinds)))]
    return {spec.name: spec for spec in (*base, *specs)}


def _kinds(*kinds: SignalKind) -> frozenset[str]:
    return frozenset(kind.value for kind in kinds)


_EVENT_CODE = _f("event.code", "event_code", "Id del evento de origen (si vino de un evento).", INT)
_ACCOUNT = (
    _f("account.name", "account", "Cuenta afectada (tal como llega del host)."),
    _f("account.domain", "domain", "Dominio de la cuenta."),
    _f("account.sid", "sid", "SID de la cuenta (mayúsculas)."),
)
_ACTOR = (
    _f("actor.name", "actor", "Cuenta que hizo el cambio (SubjectUserName)."),
    _f("actor.sid", "actor_sid", "SID de quien hizo el cambio."),
)

_AUTH_KINDS = _kinds(SignalKind.AUTH_FAILURE, SignalKind.AUTH_SUCCESS, SignalKind.ACCOUNT_LOCKOUT)
_ACCOUNT_KINDS = _kinds(
    SignalKind.ACCOUNT_CREATED,
    SignalKind.ACCOUNT_ENABLED,
    SignalKind.ACCOUNT_DISABLED,
    SignalKind.ACCOUNT_DELETED,
    SignalKind.ADMIN_GROUP_ADDED,
    SignalKind.ADMIN_GROUP_REMOVED,
)
_SERVICE_KINDS = _kinds(
    SignalKind.SERVICE_INSTALLED,
    SignalKind.SERVICE_ADDED,
    SignalKind.SECURITY_SERVICE_DOWN,
    SignalKind.SERVICE_CRASHED,
)
_EXPOSURE_KINDS = _kinds(SignalKind.LISTEN_PORT_NEW, SignalKind.PORT_EXPOSED)
_DISCOVERY_KINDS = _kinds(SignalKind.ASSET_DISCOVERED, SignalKind.ASSET_DISAPPEARED)
_ANTIMALWARE_KINDS = _kinds(SignalKind.MALWARE_DETECTED, SignalKind.ANTIMALWARE_DISABLED)
_AUDIT_KINDS = _kinds(SignalKind.LOG_CLEARED, SignalKind.AUDIT_POLICY_CHANGED)
_EVENT_ONLY = frozenset({EVENT_KIND})

_SOURCES: tuple[LogSource, ...] = (
    LogSource(
        name="windows_security",
        title="Windows Security (eventos)",
        kinds=_EVENT_ONLY,
        channel=SECURITY,
        platforms=("windows",),
        support=Support.SUPPORTED,
        fields=_event_fields(SECURITY, message=True),
        event_codes=AGENT_EVENT_CODES[SECURITY],
        notes=(
            "Solo los ids que recoge el agente (logons, cuentas, grupos, política de auditoría,"
            " borrado del log). 4624 solo de tipos 2, 10 y 11. Requiere el agente como"
            " administrador."
        ),
        sigma_hint="product: windows, service: security",
    ),
    LogSource(
        name="windows_system",
        title="Windows System (eventos)",
        kinds=_EVENT_ONLY,
        channel=SYSTEM,
        platforms=("windows",),
        support=Support.SUPPORTED,
        fields=_event_fields(SYSTEM, message=True),
        notes=(
            "Eventos de nivel warning/error/critical más 104 y 7045. Campos estructurados solo"
            " para 104, 7045, 7031, 7034 y 41."
        ),
        sigma_hint="product: windows, service: system",
    ),
    LogSource(
        name="windows_application",
        title="Windows Application (eventos)",
        kinds=_EVENT_ONLY,
        channel=APPLICATION,
        platforms=("windows",),
        support=Support.SUPPORTED,
        fields=_event_fields(APPLICATION, message=True),
        notes="Solo eventos warning/error/critical y sin campos estructurados (solo mensaje).",
        sigma_hint="product: windows, service: application",
    ),
    LogSource(
        name="powershell",
        title="PowerShell Operational (eventos)",
        kinds=_EVENT_ONLY,
        channel=POWERSHELL,
        platforms=("windows",),
        support=Support.PARTIAL,
        fields=_event_fields(POWERSHELL, message=False),
        notes=(
            "Solo id, proveedor y nivel: el agente NO envía el mensaje ni el contenido del"
            " script (ScriptBlockText puede llevar credenciales). Reglas sobre el texto del"
            " script no son posibles."
        ),
        sigma_hint="product: windows, service: powershell",
    ),
    LogSource(
        name="windows_defender",
        title="Microsoft Defender (eventos)",
        kinds=_EVENT_ONLY,
        channel=DEFENDER,
        platforms=("windows",),
        support=Support.SUPPORTED,
        fields=_event_fields(DEFENDER, message=True),
        event_codes=AGENT_EVENT_CODES[DEFENDER],
        notes="Amenazas detectadas (1116-1119) y protección desactivada (5001/5010/5012).",
        sigma_hint="product: windows, service: windefend",
    ),
    LogSource(
        name="authentication",
        title="Autenticación (señales)",
        kinds=_AUTH_KINDS,
        channel=None,
        platforms=("windows",),
        support=Support.SUPPORTED,
        fields=_signal_fields(
            _EVENT_CODE,
            *_ACCOUNT,
            _f("logon.type", "logon_type", "Tipo de logon (texto: '2', '3', '10'...)."),
            _f("source.ip", "source_ip", "IP de origen del logon."),
            _f("source.workstation", "workstation", "Equipo de origen del logon."),
            _f("logon.status", "status", "Status de 4625 (p. ej. 0xc000006d)."),
            _f("logon.sub_status", "sub_status", "SubStatus de 4625."),
            *_ACTOR,
            kinds=_AUTH_KINDS,
        ),
        notes="Fallos y éxitos de logon y bloqueos de cuenta ya normalizados por el motor 4H.",
    ),
    LogSource(
        name="account",
        title="Cuentas y grupos privilegiados (señales)",
        kinds=_ACCOUNT_KINDS,
        channel=None,
        platforms=("windows", "linux"),
        support=Support.SUPPORTED,
        fields=_signal_fields(
            _EVENT_CODE,
            *_ACCOUNT,
            *_ACTOR,
            _f("group.name", "group", "Grupo privilegiado normalizado (Administrators...)."),
            _f("group.local_name", "group_name", "Nombre del grupo tal como lo da Windows."),
            _f("group.sid", "group_sid", "SID del grupo."),
            _f("account.source", "source", "'inventory' si viene del inventario."),
            _f("account.is_admin", "is_admin", "Cuenta nueva con privilegios (inventario).", BOOL),
            _f("account.enabled", "enabled", "Cuenta habilitada (inventario).", BOOL),
            kinds=_ACCOUNT_KINDS,
        ),
        notes=(
            "Eventos 4720-4757 en Windows y cambios de cuentas del inventario (Windows y"
            " Linux). En Linux solo hay inventario: sin actor ni SID."
        ),
    ),
    LogSource(
        name="service",
        title="Servicios (señales)",
        kinds=_SERVICE_KINDS,
        channel=None,
        platforms=("windows", "linux"),
        support=Support.SUPPORTED,
        fields=_signal_fields(
            _EVENT_CODE,
            _f("service.name", "service", "Nombre del servicio."),
            _f("service.image_path", "image_path", "Ruta del ejecutable (7045)."),
            _f("service.start_type", "start_type", "Tipo de inicio."),
            _f("service.account", "account", "Cuenta del servicio (7045)."),
            _f(
                "service.unusual_location",
                "unusual_location",
                "Motivo si el ejecutable está en una ruta inusual.",
            ),
            _f("service.status", "status", "Estado en el inventario."),
            _f("service.change", "change", "Cambio de inventario (stopped, removed...)."),
            _f("service.before", "before", "Valor anterior del cambio."),
            _f("service.after", "after", "Valor nuevo del cambio."),
            kinds=_SERVICE_KINDS,
        ),
        notes="Servicio instalado (7045), servicios nuevos o detenidos del inventario, caídas.",
    ),
    LogSource(
        name="process",
        title="Procesos nuevos (señales)",
        kinds=_kinds(SignalKind.PROCESS_NEW),
        channel=None,
        platforms=("windows", "linux"),
        support=Support.PARTIAL,
        fields=_signal_fields(
            _f("process.name", "name", "Nombre del proceso."),
            _f("process.path", "exe", "Ruta del ejecutable."),
            _f("process.pid", "pid", "PID.", INT),
            _f("process.ppid", "ppid", "PID del padre.", INT),
            _f("process.user", "username", "Usuario del proceso."),
            _f(
                "process.unusual_location",
                "unusual_location",
                "Motivo si el ejecutable está en una ruta inusual.",
            ),
            kinds=_kinds(SignalKind.PROCESS_NEW),
        ),
        notes=(
            "NO son eventos de creación de procesos: son ejecutables vistos por primera vez en"
            " el activo en los snapshots periódicos del agente. Sin línea de comandos ni"
            " proceso padre por ruta."
        ),
        sigma_hint="category: process_creation (parcial)",
    ),
    LogSource(
        name="network_exposure",
        title="Exposición de red (señales)",
        kinds=_EXPOSURE_KINDS,
        channel=None,
        platforms=("windows", "linux", "agentless"),
        support=Support.SUPPORTED,
        fields=_signal_fields(
            _f("network.port", "port", "Puerto TCP.", INT),
            _f("network.service_hint", "service_hint", "Servicio típico del puerto."),
            _f("network.sensitive", "sensitive", "Puerto sensible (RDP, SMB, bases...).", BOOL),
            _f("network.local_address", "local_address", "Dirección local de escucha."),
            _f("network.process", "process", "Proceso que escucha (agente)."),
            _f("network.pid", "pid", "PID que escucha (agente).", INT),
            kinds=_EXPOSURE_KINDS,
        ),
        notes="Puertos nuevos en escucha (agente) y puertos expuestos (discovery).",
    ),
    LogSource(
        name="discovery",
        title="Discovery de red (señales)",
        kinds=_DISCOVERY_KINDS,
        channel=None,
        platforms=("agentless",),
        support=Support.SUPPORTED,
        fields=_signal_fields(
            _f("discovery.address", "address", "Dirección IP."),
            _f("discovery.mac", "mac", "MAC."),
            _f("discovery.device_type", "device_type", "Tipo de dispositivo inferido."),
            _f("discovery.device_name", "device_name", "Nombre identificado."),
            _f("discovery.identified", "identified", "Se identificó el dispositivo.", BOOL),
            kinds=_DISCOVERY_KINDS,
        ),
        notes="Dispositivos nuevos tras la línea base de la red y activos desaparecidos.",
    ),
    LogSource(
        name="antimalware",
        title="Antimalware (señales)",
        kinds=_ANTIMALWARE_KINDS,
        channel=None,
        platforms=("windows",),
        support=Support.SUPPORTED,
        fields=_signal_fields(
            _EVENT_CODE,
            _f("threat.name", "threat", "Nombre de la amenaza."),
            _f("threat.outcome", "outcome", "detected, action_taken, action_failed..."),
            _f("threat.severity", "defender_severity", "Severidad según Defender."),
            _f("threat.category", "category", "Categoría según Defender."),
            _f("threat.action", "action", "Acción de Defender."),
            _f("threat.path", "path", "Ruta del fichero afectado."),
            _f("threat.user", "user", "Usuario de la detección."),
            _f("threat.process", "process", "Proceso relacionado."),
            _f("antimalware.feature", "feature", "Protección desactivada (5001/5010/5012)."),
            kinds=_ANTIMALWARE_KINDS,
        ),
        notes="Microsoft Defender normalizado. Otros antivirus no están soportados.",
    ),
    LogSource(
        name="audit",
        title="Registro y auditoría (señales)",
        kinds=_AUDIT_KINDS,
        channel=None,
        platforms=("windows",),
        support=Support.SUPPORTED,
        fields=_signal_fields(
            _EVENT_CODE,
            _f("log.name", "log", "Registro borrado (Security, System...)."),
            _f("audit.changes", "changes", "AuditPolicyChanges (códigos %%84xx)."),
            _f("audit.removed", "removed", "Se quitó auditoría (si se sabe).", BOOL),
            _f("audit.subcategory_guid", "subcategory_guid", "Subcategoría modificada."),
            *_ACTOR,
            kinds=_AUDIT_KINDS,
        ),
        notes="Borrado de registros (1102/104) y cambios de política de auditoría (4719).",
    ),
)

LOGSOURCES: dict[str, LogSource] = {source.name: source for source in _SOURCES}
# Canal de Windows -> logsource de eventos (para el filtro de la ingesta).
EVENT_LOGSOURCE_BY_CHANNEL: dict[str, str] = {
    source.channel: source.name for source in _SOURCES if source.channel is not None
}

# Categorías permitidas para una regla: las mismas que usan las built-in (el riesgo 4I y la
# UI las entienden), sin inventar una escala nueva.
CATEGORIES = (
    "authentication",
    "account",
    "scripting",
    "persistence",
    "process",
    "network",
    "defense",
    "system",
)
DEFAULT_CATEGORY: dict[str, str] = {
    "windows_security": "authentication",
    "windows_system": "system",
    "windows_application": "system",
    "powershell": "scripting",
    "windows_defender": "defense",
    "authentication": "authentication",
    "account": "account",
    "service": "persistence",
    "process": "process",
    "network_exposure": "network",
    "discovery": "network",
    "antimalware": "defense",
    "audit": "defense",
}


def fields_for(logsource: LogSource) -> dict[str, FieldSpec]:
    """Campos del logsource más el contexto del activo."""
    return {**logsource.fields, **ASSET_FIELDS}


# Matriz de compatibilidad documentada (docs/custom-detection-rules.md) y expuesta en
# GET /detection-rules/catalog para que la UI la muestre tal cual.
@dataclass(frozen=True)
class CompatibilityRow:
    area: str
    support: Support
    notes: str
    logsources: tuple[str, ...] = field(default_factory=tuple)


COMPATIBILITY: tuple[CompatibilityRow, ...] = (
    CompatibilityRow(
        "Windows Security",
        Support.SUPPORTED,
        "Ids recogidos por el agente con sus campos estructurados.",
        ("windows_security", "authentication", "account", "audit"),
    ),
    CompatibilityRow(
        "Windows System",
        Support.SUPPORTED,
        "Warning/error/critical, 104 y 7045.",
        ("windows_system", "service"),
    ),
    CompatibilityRow(
        "Windows Application", Support.SUPPORTED, "Solo mensaje.", ("windows_application",)
    ),
    CompatibilityRow(
        "PowerShell",
        Support.PARTIAL,
        "Sin texto de script ni mensaje: solo id y nivel.",
        ("powershell",),
    ),
    CompatibilityRow(
        "Microsoft Defender", Support.SUPPORTED, "Amenazas y protección.", ("windows_defender",)
    ),
    CompatibilityRow(
        "Procesos",
        Support.PARTIAL,
        "Ejecutables nuevos por snapshot; sin creación de procesos ni línea de comandos.",
        ("process",),
    ),
    CompatibilityRow("Servicios", Support.SUPPORTED, "Eventos e inventario.", ("service",)),
    CompatibilityRow(
        "Inventario",
        Support.PARTIAL,
        "Solo como cambios: cuentas, servicios y puertos (no el inventario completo).",
        ("account", "service", "network_exposure"),
    ),
    CompatibilityRow(
        "Exposición de red",
        Support.SUPPORTED,
        "Puertos nuevos (agente) y expuestos (discovery).",
        ("network_exposure", "discovery"),
    ),
    CompatibilityRow(
        "Linux (actual)",
        Support.PARTIAL,
        "Sin eventos de seguridad: solo procesos nuevos, cuentas, servicios y puertos.",
        ("process", "account", "service", "network_exposure"),
    ),
    CompatibilityRow(
        "Sysmon, línea de comandos, ficheros, registro, DNS, red por conexión",
        Support.UNSUPPORTED,
        "Sentra no recoge estos datos todavía.",
    ),
)
