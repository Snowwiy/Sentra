"""Catálogo de reglas de detección y correlación.

Contrato común (DetectionRule): metadatos estables (id, versión, severidad y confianza por
defecto, datos requeridos, MITRE opcional) y `evaluate(ctx, signal) -> list[RuleResult]`.
Una regla no escribe en la base de datos ni conoce ids de evento: recibe señales ya
normalizadas y consulta otras señales del MISMO activo, siempre acotadas por ventana. El
motor (engine.py) se encarga de deduplicar, guardar evidencia y abrir alertas.

Criterios (docs/detection-engine.md):
- una sola señal débil nunca da "critical" ni afirma un compromiso;
- severity = impacto si es cierto; confidence = cuánto lo respalda la evidencia;
- MITRE ATT&CK solo donde el mapeo es defendible.

Para añadir una regla: una clase con `meta` y `evaluate`, registrada en RULES. Cambiar la
lógica de una regla existente sube su `version`.
"""

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Protocol

from app.detection import text
from app.detection.config import DetectionConfig
from app.detection.signals import SignalKind
from app.models.detection import (
    CONFIDENCE_RANK,
    SEVERITY_RANK,
    DetectionConfidence,
    DetectionSeverity,
    DetectionSignal,
)

Sev = DetectionSeverity
Conf = DetectionConfidence
SINGLE = "single"
CORRELATION = "correlation"
# Evidencia de una misma clase incluida por resultado (p. ej. los últimos N fallos).
EVIDENCE_PER_ROLE = 10
# Valor de `subject` en las consultas que significa "cualquier sujeto". None significa "sin
# sujeto". Un NUL nunca llega a un sujeto real (se elimina al sanear).
ANY_SUBJECT = "\x00any"


@dataclass(frozen=True)
class Mitre:
    tactic: str
    technique: str
    subtechnique: str | None = None


@dataclass(frozen=True)
class RuleMeta:
    id: str
    version: int
    kind: str
    category: str
    title: str
    # Qué detecta y por qué importa: textos fijos que la UI muestra junto a la detección.
    description: str
    why: str
    severity: DetectionSeverity
    confidence: DetectionConfidence
    triggers: frozenset[SignalKind]
    required_data: tuple[str, ...]
    recommendations: tuple[str, ...]
    mitre: Mitre | None = None
    # Dentro del cooldown, una nueva coincidencia amplía la ocurrencia actual (más evidencia,
    # last_seen) en vez de contar otra: un ataque de 500 fallos es UNA oleada, no 500.
    cooldown: timedelta = timedelta(0)
    # Cooldown tomado de la configuración (atributo de DetectionConfig) en vez de fijo: la
    # oleada de AUTH-001 dura lo que su ventana configurada.
    cooldown_setting: str | None = None
    # Fase 5A: origen de la regla (builtin, custom, sigma). Las reglas de este fichero son
    # todas builtin; las personalizadas se construyen desde la BD (custom/runtime.py).
    source: str = "builtin"

    def cooldown_for(self, config: DetectionConfig) -> timedelta:
        if self.cooldown_setting:
            value: timedelta = getattr(config, self.cooldown_setting)
            return value
        return self.cooldown


@dataclass(frozen=True)
class Evidence:
    signal: DetectionSignal
    role: str | None = None


@dataclass
class RuleResult:
    key: str
    summary: str
    evidence: list[Evidence]
    occurred_at: datetime
    severity: DetectionSeverity | None = None
    confidence: DetectionConfidence | None = None
    details: dict[str, Any] = field(default_factory=dict)
    mitre: Mitre | None = None


class RuleContext(Protocol):
    """Consultas que una regla puede hacer: siempre de un activo y en una ventana."""

    config: DetectionConfig

    def signals(
        self,
        asset_id: int,
        kinds: Sequence[SignalKind],
        start: datetime,
        end: datetime,
        *,
        subject: str | None = ANY_SUBJECT,
        limit: int = 200,
    ) -> Sequence[DetectionSignal]: ...

    def count(
        self,
        asset_id: int,
        kinds: Sequence[SignalKind],
        start: datetime,
        end: datetime,
        *,
        subject: str | None = ANY_SUBJECT,
    ) -> int: ...

    def asset_os(self, asset_id: int) -> str: ...


class DetectionRule(Protocol):
    meta: RuleMeta

    def evaluate(self, ctx: RuleContext, signal: DetectionSignal) -> list[RuleResult]: ...


# --- Utilidades comunes ----------------------------------------------------------------------


def _data(signal: DetectionSignal) -> dict[str, Any]:
    return signal.data if isinstance(signal.data, dict) else {}


def _get(signal: DetectionSignal, key: str) -> Any:
    return _data(signal).get(key)


def _key(value: str | None, fallback: str) -> str:
    return (value or fallback)[:255]


def max_severity(*values: DetectionSeverity) -> DetectionSeverity:
    return max(values, key=lambda v: SEVERITY_RANK[v])


def max_confidence(*values: DetectionConfidence) -> DetectionConfidence:
    return max(values, key=lambda v: CONFIDENCE_RANK[v])


def same_principal(a: DetectionSignal, b: DetectionSignal) -> bool:
    """¿Las dos señales hablan de la misma cuenta? Por SID si ambas lo tienen, si no por nombre.

    Las cuentas locales llegan en 4732 solo con SID; 4720 y 4624 traen SID y nombre; el
    inventario solo nombre. Comparar así evita mezclar cuentas y a la vez une las fuentes.
    """
    sid_a, sid_b = _get(a, "sid"), _get(b, "sid")
    if sid_a and sid_b:
        return bool(sid_a == sid_b)
    names_a = {a.subject, text.principal(_get(a, "account"))} - {None}
    names_b = {b.subject, text.principal(_get(b, "account"))} - {None}
    return bool(names_a & names_b)


def acted_by(admin_change: DetectionSignal, logon: DetectionSignal) -> bool:
    """El cambio de grupo lo hizo (actor) o lo recibió (miembro) la cuenta que inició sesión."""
    if same_principal(admin_change, logon):
        return True
    actor_sid, logon_sid = _get(admin_change, "actor_sid"), _get(logon, "sid")
    if actor_sid and logon_sid:
        return bool(actor_sid == logon_sid)
    actor = text.principal(_get(admin_change, "actor"))
    return actor is not None and actor == logon.subject


def signal_platform(signal: DetectionSignal) -> str:
    """Plataforma de una señal de evento: "linux" (journal, Fase 5C.1) o "windows".

    Solo las señales de eventos Linux llevan `platform`; las de Windows y las de inventario
    no, y se tratan como hasta ahora.
    """
    return "linux" if _get(signal, "platform") == "linux" else "windows"


def _label(signal: DetectionSignal) -> str:
    """Nombre legible de la cuenta de una señal (nombre, o SID si no hay nombre)."""
    return str(_get(signal, "account") or signal.subject or _get(signal, "sid") or "desconocida")


def _tail(signals: Sequence[DetectionSignal], role: str) -> list[Evidence]:
    return [Evidence(s, role) for s in list(signals)[-EVIDENCE_PER_ROLE:]]


# --- Reglas simples ----------------------------------------------------------------------------


class SimpleRule:
    """Regla de una señal: el resultado se construye con una función por regla.

    Evita una clase por regla trivial; las que necesitan contar o mirar alrededor
    (AUTH-001, SYS-*) tienen su propia clase.
    """

    def __init__(
        self,
        meta: RuleMeta,
        build: Callable[[RuleContext, DetectionSignal], RuleResult | None],
    ) -> None:
        self.meta = meta
        self._build = build

    def evaluate(self, ctx: RuleContext, signal: DetectionSignal) -> list[RuleResult]:
        result = self._build(ctx, signal)
        return [result] if result is not None else []


def _single(
    signal: DetectionSignal, key: str, summary: str, role: str | None = None, **kwargs: Any
) -> RuleResult:
    return RuleResult(
        key=key,
        summary=summary,
        evidence=[Evidence(signal, role)],
        occurred_at=signal.occurred_at,
        **kwargs,
    )


AUTH_001 = RuleMeta(
    id="AUTH-001",
    version=1,
    kind=SINGLE,
    category="authentication",
    title="Múltiples inicios de sesión fallidos",
    description=(
        "Varios fallos de inicio de sesión de la misma cuenta en el mismo activo dentro de una"
        " ventana corta (DETECTION_AUTH_FAILURE_THRESHOLD en"
        " DETECTION_AUTH_FAILURE_WINDOW_MINUTES)."
    ),
    why=(
        "Es el patrón de un intento de adivinar la contraseña (fuerza bruta). Por sí solo no"
        " significa acceso: también lo produce un usuario que olvidó su contraseña o un servicio"
        " con credenciales antiguas."
    ),
    severity=Sev.MEDIUM,
    confidence=Conf.MEDIUM,
    triggers=frozenset({SignalKind.AUTH_FAILURE}),
    required_data=("Windows Security 4625 (agente con permisos de administrador)",),
    recommendations=(
        "Verificar con el usuario si reconoce los intentos.",
        "Revisar el origen (dirección IP o equipo) y el horario de los fallos.",
        "Comprobar si hubo un inicio de sesión correcto posterior (ver CORR-001).",
        "Si el origen no es conocido, bloquearlo según el procedimiento de la organización.",
    ),
    mitre=Mitre("TA0006", "T1110"),
    cooldown_setting="auth_failure_window",
)


class FailedLogonBurst:
    """AUTH-001 (Windows) y LIN-AUTH-001 (Linux, SSH/PAM): misma lógica, textos propios.

    Cada instancia solo evalúa señales de su plataforma: un fallo SSH nunca abre AUTH-001
    (que habla de 4625) ni un 4625 abre LIN-AUTH-001.
    """

    def __init__(self, meta: RuleMeta = AUTH_001, platform: str = "windows") -> None:
        self.meta = meta
        self._platform = platform

    def evaluate(self, ctx: RuleContext, signal: DetectionSignal) -> list[RuleResult]:
        if signal_platform(signal) != self._platform:
            return []
        config = ctx.config
        start = signal.occurred_at - config.auth_failure_window
        kinds = [SignalKind.AUTH_FAILURE]
        count = ctx.count(signal.asset_id, kinds, start, signal.occurred_at, subject=signal.subject)
        if count < config.auth_failure_threshold:
            return []
        recent = ctx.signals(
            signal.asset_id, kinds, start, signal.occurred_at, subject=signal.subject
        )
        minutes = int(config.auth_failure_window.total_seconds() // 60)
        account = signal.subject
        # Sin cuenta (agente anterior a 4H, sin campos estructurados) se agrupan todos los
        # fallos del activo: sigue siendo útil, pero con menos confianza.
        confidence = Conf.MEDIUM if account else Conf.LOW
        # Un volumen muy superior al umbral es un ataque sostenido: sube la severidad.
        severity = Sev.HIGH if count >= 4 * config.auth_failure_threshold else Sev.MEDIUM
        sources = sorted({str(_get(s, "source_ip")) for s in recent if _get(s, "source_ip")})[:5]
        summary = (
            f"{count} inicios de sesión fallidos de la cuenta {account or '(desconocida)'}"
            f" en {minutes} min" + (f" desde {', '.join(sources)}" if sources else "") + "."
        )
        evidence = _tail([s for s in recent if s.id != signal.id], "failure")
        evidence.append(Evidence(signal, "failure"))
        return [
            RuleResult(
                key=_key(account, "*"),
                summary=summary,
                evidence=evidence,
                occurred_at=signal.occurred_at,
                severity=severity,
                confidence=confidence,
                details={
                    "account": account,
                    "failures": count,
                    "window_minutes": minutes,
                    "sources": sources,
                },
            )
        ]


def _lockout(ctx: RuleContext, s: DetectionSignal) -> RuleResult:
    return _single(s, _key(s.subject, "*"), f"La cuenta {_label(s)} quedó bloqueada.")


def _account_created(ctx: RuleContext, s: DetectionSignal) -> RuleResult:
    source = "inventario" if _get(s, "source") == "inventory" else "evento de seguridad"
    actor = _get(s, "actor")
    summary = (
        f"Se creó la cuenta {_label(s)}" + (f" por {actor}" if actor else "") + f" ({source})."
    )
    return _single(s, _key(s.subject, "*"), summary, details={"account": _label(s), "actor": actor})


def _admin_added(ctx: RuleContext, s: DetectionSignal) -> RuleResult:
    group = str(_get(s, "group") or "grupo privilegiado")
    actor = _get(s, "actor")
    summary = (
        f"La cuenta {_label(s)} se añadió a {group}" + (f" por {actor}" if actor else "") + "."
    )
    return _single(
        s,
        _key(f"{s.subject or '*'}|{group.lower()}", "*"),
        summary,
        details={"account": _label(s), "group": group, "actor": actor},
    )


_ACCOUNT_STATE = {
    SignalKind.ACCOUNT_ENABLED.value: ("habilitó", Sev.LOW),
    SignalKind.ACCOUNT_DISABLED.value: ("deshabilitó", Sev.INFORMATIONAL),
    SignalKind.ACCOUNT_DELETED.value: ("eliminó", Sev.INFORMATIONAL),
    SignalKind.ADMIN_GROUP_REMOVED.value: ("retiró de un grupo privilegiado", Sev.INFORMATIONAL),
}


def _account_state(ctx: RuleContext, s: DetectionSignal) -> RuleResult:
    verb, severity = _ACCOUNT_STATE[s.kind]
    return _single(
        s,
        _key(f"{s.subject or '*'}|{s.kind}", "*"),
        f"Se {verb} la cuenta {_label(s)}.",
        severity=severity,
        details={"account": _label(s), "change": s.kind},
    )


def _powershell(ctx: RuleContext, s: DetectionSignal) -> RuleResult:
    return _single(
        s,
        "powershell",
        "PowerShell registró un bloque de script marcado como sospechoso (evento 4104 de nivel"
        " Warning). El contenido no se recoge.",
    )


def _service(ctx: RuleContext, s: DetectionSignal) -> RuleResult:
    name = str(_get(s, "service") or s.subject or "desconocido")
    from_event = s.kind == SignalKind.SERVICE_INSTALLED
    unusual = _get(s, "unusual_location")
    image = _get(s, "image_path")
    summary = f"Servicio nuevo: {name}" + (f" ({image})" if image else "") + "."
    severity = Sev.MEDIUM if from_event else Sev.LOW
    if unusual:
        severity = Sev.HIGH
        summary += f" El ejecutable está en una ubicación inusual: {unusual}."
    linux = "linux" in ctx.asset_os(s.asset_id)
    mitre = Mitre("TA0003", "T1543", "T1543.002" if linux else "T1543.003")
    return _single(
        s,
        _key(s.subject, name.lower()),
        summary,
        severity=severity,
        confidence=Conf.HIGH if from_event else Conf.MEDIUM,
        details={"service": name, "image_path": image, "unusual_location": unusual},
        mitre=mitre,
    )


def _unusual_process(ctx: RuleContext, s: DetectionSignal) -> RuleResult | None:
    reason = _get(s, "unusual_location")
    if not reason:
        return None
    exe = str(_get(s, "exe") or s.subject)
    user = _get(s, "username")
    summary = (
        f"Proceso nuevo {_get(s, 'name') or exe} ejecutándose desde una ubicación inusual"
        f" ({reason}): {exe}" + (f", usuario {user}" if user else "") + "."
    )
    return _single(s, _key(s.subject, exe.lower()), summary, details={"exe": exe, "reason": reason})


def _port_exposed(ctx: RuleContext, s: DetectionSignal) -> RuleResult:
    port = _get(s, "port")
    hint = _get(s, "service_hint")
    sensitive = bool(_get(s, "sensitive"))
    label = f"{port}/tcp" + (f" ({hint})" if hint else "")
    summary = f"El puerto {label} pasó a ser accesible desde el servidor de Sentra." + (
        " Es un puerto de administración o datos sensible." if sensitive else ""
    )
    return _single(
        s,
        _key(s.subject, str(port)),
        summary,
        severity=Sev.HIGH if sensitive else Sev.LOW,
        details={"port": port, "service_hint": hint, "sensitive": sensitive},
    )


def _listen_port(ctx: RuleContext, s: DetectionSignal) -> RuleResult | None:
    if not _get(s, "sensitive"):
        return None
    port = _get(s, "port")
    hint = _get(s, "service_hint")
    process = _get(s, "process")
    summary = (
        f"Nuevo puerto sensible en escucha: {port}/tcp"
        + (f" ({hint})" if hint else "")
        + (f", proceso {process}" if process else "")
        + "."
    )
    return _single(
        s,
        _key(s.subject, str(port)),
        summary,
        details={"port": port, "service_hint": hint, "process": process},
    )


def _discovered(ctx: RuleContext, s: DetectionSignal) -> RuleResult:
    identified = bool(_get(s, "identified"))
    address = _get(s, "address")
    summary = (
        f"Dispositivo nuevo en la red: {address}"
        + (f" ({_get(s, 'device_type')})" if _get(s, "device_type") else " sin identificar")
        + "."
    )
    return _single(
        s,
        "discovered",
        summary,
        severity=Sev.INFORMATIONAL if identified else Sev.LOW,
        confidence=Conf.HIGH if identified else Conf.MEDIUM,
    )


def _disappeared(ctx: RuleContext, s: DetectionSignal) -> RuleResult:
    return _single(s, "disappeared", f"El activo ({_get(s, 'address')}) dejó de verse en la red.")


def _log_cleared(ctx: RuleContext, s: DetectionSignal) -> RuleResult:
    log = str(_get(s, "log") or s.subject or "desconocido")
    actor = _get(s, "actor")
    summary = f"Se borró el registro de eventos {log}" + (f" (por {actor})" if actor else "") + "."
    return _single(s, _key(log.lower(), "log"), summary, details={"log": log, "actor": actor})


def _audit_policy(ctx: RuleContext, s: DetectionSignal) -> RuleResult:
    removed = _get(s, "removed")
    actor = _get(s, "actor")
    by = f" por {actor}" if actor else ""
    if removed is True:
        return _single(
            s,
            _key(_get(s, "subcategory_guid"), "audit-policy"),
            f"Se desactivó auditoría en la política del sistema{by}.",
            severity=Sev.HIGH,
            confidence=Conf.HIGH,
            mitre=Mitre("TA0005", "T1562", "T1562.002"),
            details={"removed": True, "changes": _get(s, "changes")},
        )
    if removed is False:
        return _single(
            s,
            _key(_get(s, "subcategory_guid"), "audit-policy"),
            f"Se amplió la auditoría en la política del sistema{by}.",
            severity=Sev.INFORMATIONAL,
            confidence=Conf.HIGH,
            details={"removed": False, "changes": _get(s, "changes")},
        )
    # Sin detalle (agente anterior a 4H): no se sabe si se quitó o se añadió auditoría.
    return _single(
        s,
        "audit-policy",
        f"Se modificó la política de auditoría{by} (sin detalle del cambio).",
        confidence=Conf.LOW,
    )


def _security_service(ctx: RuleContext, s: DetectionSignal) -> RuleResult:
    name = str(_get(s, "service") or s.subject)
    change = {
        "stopped": "se detuvo",
        "removed": "desapareció",
        "start_type_changed": "se deshabilitó",
    }
    verb = change.get(str(_get(s, "change")), "cambió")
    return _single(
        s,
        _key(s.subject, name.lower()),
        f"El servicio de seguridad {name} {verb}.",
        details={"service": name, "change": _get(s, "change")},
    )


def _antimalware_disabled(ctx: RuleContext, s: DetectionSignal) -> RuleResult:
    feature = str(_get(s, "feature") or s.subject)
    return _single(s, _key(s.subject, feature), f"Microsoft Defender: {feature} desactivado.")


_MALWARE_OUTCOME = {
    "detected": ("detectó", Sev.HIGH),
    "action_taken": ("actuó sobre", Sev.HIGH),
    "action_failed": ("no pudo neutralizar", Sev.CRITICAL),
    "critical_failure": ("falló de forma crítica al neutralizar", Sev.CRITICAL),
}


def _malware(ctx: RuleContext, s: DetectionSignal) -> RuleResult:
    verb, severity = _MALWARE_OUTCOME.get(str(_get(s, "outcome")), ("detectó", Sev.HIGH))
    threat = _get(s, "threat") or "una amenaza"
    path = _get(s, "path")
    summary = f"Microsoft Defender {verb} {threat}" + (f" en {path}" if path else "") + "."
    return _single(
        s,
        _key(s.subject, "unknown"),
        summary,
        severity=severity,
        details={"threat": _get(s, "threat"), "outcome": _get(s, "outcome"), "path": path},
    )


class RepeatedRule:
    """Patrón repetitivo: N señales del mismo tipo (y sujeto) en la ventana de repetición."""

    def __init__(
        self,
        meta: RuleMeta,
        describe: Callable[[DetectionSignal, int, int], str],
        *,
        by_subject: bool,
        single: tuple[DetectionSeverity, str] | None = None,
    ) -> None:
        self.meta = meta
        self._describe = describe
        self._by_subject = by_subject
        # Severidad y texto para una ocurrencia aislada; None: aislada no es detección.
        self._single = single

    def evaluate(self, ctx: RuleContext, signal: DetectionSignal) -> list[RuleResult]:
        config = ctx.config
        start = signal.occurred_at - config.repeat_window
        subject = signal.subject if self._by_subject else ANY_SUBJECT
        kinds = [SignalKind(signal.kind)]
        count = ctx.count(signal.asset_id, kinds, start, signal.occurred_at, subject=subject)
        hours = int(config.repeat_window.total_seconds() // 3600)
        key = _key(signal.subject if self._by_subject else None, self.meta.id.lower())
        if count >= config.repeat_threshold:
            recent = ctx.signals(signal.asset_id, kinds, start, signal.occurred_at, subject=subject)
            evidence = _tail([s for s in recent if s.id != signal.id], "occurrence")
            evidence.append(Evidence(signal, "occurrence"))
            return [
                RuleResult(
                    key=key,
                    summary=self._describe(signal, count, hours),
                    evidence=evidence,
                    occurred_at=signal.occurred_at,
                    severity=Sev.MEDIUM,
                    details={"occurrences_in_window": count, "window_hours": hours},
                )
            ]
        if self._single is None:
            return []
        severity, summary = self._single
        return [_single(signal, key, summary, "occurrence", severity=severity)]


# --- Correlaciones -----------------------------------------------------------------------------


CORR_001 = RuleMeta(
    id="CORR-001",
    version=1,
    kind=CORRELATION,
    category="authentication",
    title="Posible acceso no autorizado tras fallos de inicio de sesión",
    description=(
        "Inicio de sesión correcto de una cuenta precedido, en el mismo activo y dentro de"
        " DETECTION_CORRELATION_WINDOW_MINUTES, de al menos DETECTION_AUTH_FAILURE_THRESHOLD"
        " fallos de esa misma cuenta. Si después la cuenta entra en un grupo privilegiado"
        " (o hace ese cambio) dentro de DETECTION_CHANGE_WINDOW_MINUTES, se eleva a crítica."
    ),
    why=(
        "Fallos seguidos de un acierto pueden indicar que alguien adivinó la contraseña. Un"
        " cambio de privilegios inmediatamente después es típico de un atacante que asegura su"
        " acceso. También puede ser el propio usuario tras olvidar la contraseña: hay que"
        " confirmarlo con él."
    ),
    severity=Sev.HIGH,
    confidence=Conf.MEDIUM,
    triggers=frozenset({SignalKind.AUTH_SUCCESS, SignalKind.ADMIN_GROUP_ADDED}),
    required_data=(
        "Windows Security 4625 y 4624 (logons interactivos/RDP) con campos estructurados",
        "Opcional: 4728/4732/4756 o cambios de administradores del inventario",
    ),
    recommendations=(
        "Verificar con el usuario si reconoce el inicio de sesión y su horario.",
        "Revisar el origen de los fallos y del acceso (IP, equipo, tipo de logon).",
        "Revisar eventos y procesos adyacentes en el activo durante la ventana.",
        "Si no se reconoce: restablecer la contraseña, revisar los grupos privilegiados y"
        " aislar el equipo según el procedimiento institucional.",
    ),
    mitre=Mitre("TA0006", "T1110"),
)


class FailedThenSuccess:
    """CORR-001 (Windows) y LIN-AUTH-002 (Linux): fallos -> acceso -> privilegios.

    En Linux el paso de privilegios es, además del alta en un grupo privilegiado (sudo,
    wheel...), un comando con sudo de la misma cuenta: es lo que hace un atacante que acaba
    de entrar por SSH. Mismo motor y misma lógica; solo cambia qué señal cuenta como escalada.
    """

    def __init__(self, meta: RuleMeta = CORR_001, platform: str = "windows") -> None:
        self.meta = meta
        self._platform = platform

    def _escalations(self) -> list[SignalKind]:
        kinds = [SignalKind.ADMIN_GROUP_ADDED]
        if self._platform == "linux":
            kinds.append(SignalKind.SUDO_COMMAND)
        return kinds

    def evaluate(self, ctx: RuleContext, signal: DetectionSignal) -> list[RuleResult]:
        if signal.kind == SignalKind.AUTH_SUCCESS:
            if signal_platform(signal) != self._platform:
                return []
            return self._from_success(ctx, signal, None)
        if signal.kind == SignalKind.SUDO_COMMAND and self._platform != "linux":
            return []
        # Cambio de privilegios: ¿lo precede una cadena fallos -> acceso de esa cuenta?
        successes = ctx.signals(
            signal.asset_id,
            [SignalKind.AUTH_SUCCESS],
            signal.occurred_at - ctx.config.change_window,
            signal.occurred_at,
        )
        for success in reversed(successes):
            if signal_platform(success) == self._platform and acted_by(signal, success):
                return self._from_success(ctx, success, signal)
        return []

    def _from_success(
        self, ctx: RuleContext, success: DetectionSignal, admin: DetectionSignal | None
    ) -> list[RuleResult]:
        account = success.subject
        # Evidencia esencial: la cuenta. Sin ella no se puede afirmar "la misma cuenta".
        if account is None:
            return []
        config = ctx.config
        failures = ctx.signals(
            success.asset_id,
            [SignalKind.AUTH_FAILURE],
            success.occurred_at - config.correlation_window,
            success.occurred_at,
            subject=account,
        )
        if len(failures) < config.auth_failure_threshold:
            return []
        if admin is None:
            changes = ctx.signals(
                success.asset_id,
                self._escalations(),
                success.occurred_at,
                success.occurred_at + config.change_window,
            )
            admin = next((c for c in changes if acted_by(c, success)), None)
        sources = {str(_get(f, "source_ip")) for f in failures if _get(f, "source_ip")}
        success_ip = _get(success, "source_ip")
        # Más confianza si el acceso viene del mismo origen que los fallos o es remoto (RDP).
        # Fase 5C.1: "ssh" (Linux) cuenta como acceso remoto igual que RDP.
        strong = (success_ip and success_ip in sources) or _get(success, "logon_type") in (
            "10",
            "ssh",
        )
        confidence = Conf.HIGH if strong or admin else Conf.MEDIUM
        severity = Sev.CRITICAL if admin else Sev.HIGH
        minutes = int(config.correlation_window.total_seconds() // 60)
        summary = (
            f"{len(failures)} fallos de inicio de sesión de {account} seguidos de un inicio de"
            f" sesión correcto en menos de {minutes} min"
            + (f" (origen {success_ip})" if success_ip else "")
            + "."
        )
        evidence = [*_tail(failures, "failure"), Evidence(success, "success")]
        if admin is not None and admin.kind == SignalKind.SUDO_COMMAND:
            target = _get(admin, "target_user") or "root"
            summary += f" Después, {_label(admin)} ejecutó un comando con sudo como {target}."
            evidence.append(Evidence(admin, "privilege_escalation"))
        elif admin is not None:
            group = _get(admin, "group") or "un grupo privilegiado"
            summary += f" Después, {_label(admin)} entró en {group}."
            evidence.append(Evidence(admin, "admin_change"))
        return [
            RuleResult(
                key=_key(account, "*"),
                summary=summary,
                evidence=evidence,
                occurred_at=max(e.signal.occurred_at for e in evidence),
                severity=severity,
                confidence=confidence,
                details={
                    "account": account,
                    "failures": len(failures),
                    "window_minutes": minutes,
                    "success_source": success_ip,
                    "logon_type": _get(success, "logon_type"),
                    "admin_change": admin is not None,
                },
            )
        ]


CORR_002 = RuleMeta(
    id="CORR-002",
    version=1,
    kind=CORRELATION,
    category="persistence",
    title="PowerShell sospechoso seguido de persistencia",
    description=(
        "Un bloque de PowerShell marcado como sospechoso y un servicio nuevo en el mismo activo"
        " dentro de DETECTION_CORRELATION_WINDOW_MINUTES. Un proceso nuevo en esa ventana"
        " aumenta la confianza."
    ),
    why=(
        "Ejecutar un script y dejar un servicio instalado es una forma habitual de mantener"
        " acceso a un equipo. También lo hacen instaladores y administradores legítimos: requiere"
        " revisión, no es una confirmación."
    ),
    severity=Sev.HIGH,
    confidence=Conf.MEDIUM,
    triggers=frozenset(
        {
            SignalKind.POWERSHELL_SUSPICIOUS,
            SignalKind.SERVICE_INSTALLED,
            SignalKind.SERVICE_ADDED,
            SignalKind.PROCESS_NEW,
        }
    ),
    required_data=(
        "PowerShell/Operational 4104 (nivel Warning)",
        "System 7045 o servicios del inventario",
        "Opcional: snapshots de procesos",
    ),
    recommendations=(
        "Identificar quién instaló el servicio y si corresponde a un cambio planificado.",
        "Revisar la ruta del ejecutable del servicio y su firma.",
        "Revisar los procesos nuevos de la ventana y su proceso padre.",
        "Si no se reconoce, deshabilitar el servicio y aislar el equipo según el procedimiento"
        " institucional antes de borrar nada (conservar evidencia).",
    ),
    mitre=Mitre("TA0003", "T1543", "T1543.003"),
)


class PowerShellPersistence:
    meta = CORR_002

    def evaluate(self, ctx: RuleContext, signal: DetectionSignal) -> list[RuleResult]:
        window = ctx.config.correlation_window
        start, end = signal.occurred_at - window, signal.occurred_at + window
        scripts = ctx.signals(signal.asset_id, [SignalKind.POWERSHELL_SUSPICIOUS], start, end)
        if not scripts:
            return []
        services = ctx.signals(
            signal.asset_id, [SignalKind.SERVICE_INSTALLED, SignalKind.SERVICE_ADDED], start, end
        )
        if not services:
            return []
        processes = ctx.signals(signal.asset_id, [SignalKind.PROCESS_NEW], start, end, limit=50)
        unusual = [p for p in processes if _get(p, "unusual_location")]
        service = services[-1]
        name = str(_get(service, "service") or service.subject)
        summary = (
            f"PowerShell sospechoso y servicio nuevo ({name}) en menos de"
            f" {int(window.total_seconds() // 60)} min"
            + (f", con {len(processes)} proceso(s) nuevo(s)" if processes else "")
            + "."
        )
        evidence = (
            _tail(scripts, "powershell")
            + _tail(services, "persistence")
            + _tail(unusual or processes, "process")
        )
        return [
            RuleResult(
                key=_key(service.subject, name.lower()),
                summary=summary,
                evidence=evidence,
                occurred_at=max(e.signal.occurred_at for e in evidence),
                confidence=Conf.HIGH if processes else Conf.MEDIUM,
                details={
                    "service": name,
                    "powershell_events": len(scripts),
                    "new_processes": len(processes),
                    "unusual_processes": len(unusual),
                },
            )
        ]


CORR_003 = RuleMeta(
    id="CORR-003",
    version=1,
    kind=CORRELATION,
    category="network",
    title="Nueva exposición de red asociada a software local",
    description=(
        "Un puerto sensible nuevo en escucha (con su proceso, según el agente) y un servicio"
        " nuevo en el mismo activo dentro de DETECTION_CHANGE_WINDOW_MINUTES. Si discovery"
        " confirma que el puerto es accesible desde la red, la confianza es alta."
    ),
    why=(
        "Un servicio recién instalado que abre un puerto de administración o de datos amplía"
        " la superficie de ataque y puede ser una puerta trasera. Puede ser una instalación"
        " legítima que no siguió el procedimiento de cambios."
    ),
    severity=Sev.HIGH,
    confidence=Conf.MEDIUM,
    triggers=frozenset(
        {
            SignalKind.LISTEN_PORT_NEW,
            SignalKind.PORT_EXPOSED,
            SignalKind.SERVICE_INSTALLED,
            SignalKind.SERVICE_ADDED,
        }
    ),
    required_data=(
        "Conexiones en escucha del inventario (proceso asociado)",
        "System 7045 o servicios del inventario",
        "Opcional: exposición de discovery",
    ),
    recommendations=(
        "Confirmar qué software abrió el puerto y si su instalación estaba aprobada.",
        "Restringir el puerto con el firewall a los orígenes necesarios.",
        "Revisar si el servicio se expone fuera de la red prevista.",
    ),
)


class ExposureWithNewSoftware:
    meta = CORR_003

    def evaluate(self, ctx: RuleContext, signal: DetectionSignal) -> list[RuleResult]:
        window = ctx.config.change_window
        start, end = signal.occurred_at - window, signal.occurred_at + window
        listeners = [
            s
            for s in ctx.signals(signal.asset_id, [SignalKind.LISTEN_PORT_NEW], start, end)
            if _get(s, "sensitive") and _get(s, "process")
        ]
        if not listeners:
            return []
        services = ctx.signals(
            signal.asset_id, [SignalKind.SERVICE_INSTALLED, SignalKind.SERVICE_ADDED], start, end
        )
        if not services:
            return []
        exposed = {
            s.subject: s
            for s in ctx.signals(signal.asset_id, [SignalKind.PORT_EXPOSED], start, end)
        }
        results = []
        for listener in listeners:
            port = _get(listener, "port")
            reachable = exposed.get(listener.subject)
            evidence = [Evidence(listener, "listener"), *_tail(services, "service")]
            if reachable is not None:
                evidence.append(Evidence(reachable, "exposure"))
            names = ", ".join(str(_get(s, "service") or s.subject) for s in services[-3:])
            results.append(
                RuleResult(
                    key=_key(listener.subject, str(port)),
                    summary=(
                        f"El proceso {_get(listener, 'process')} abrió el puerto sensible"
                        f" {port}/tcp junto a servicio(s) nuevo(s): {names}."
                        + (" Discovery confirma que es accesible en la red." if reachable else "")
                    ),
                    evidence=evidence,
                    occurred_at=max(e.signal.occurred_at for e in evidence),
                    confidence=Conf.HIGH if reachable else Conf.MEDIUM,
                    details={
                        "port": port,
                        "process": _get(listener, "process"),
                        "services": [str(_get(s, "service") or s.subject) for s in services[-5:]],
                        "reachable": reachable is not None,
                    },
                )
            )
        return results


CORR_004 = RuleMeta(
    id="CORR-004",
    version=1,
    kind=CORRELATION,
    category="account",
    title="Cuenta nueva con privilegios y usada",
    description=(
        "Una cuenta creada, añadida después a un grupo privilegiado y con un inicio de sesión"
        " posterior, todo en el mismo activo y dentro de DETECTION_CHANGE_WINDOW_MINUTES desde"
        " la creación."
    ),
    why=(
        "Crear una cuenta, darle privilegios y usarla enseguida es un cambio administrativo de"
        " alto impacto: es la forma típica de dejar un acceso propio en un equipo. Si no hay"
        " un cambio aprobado que lo explique, hay que tratarlo como incidente."
    ),
    severity=Sev.CRITICAL,
    confidence=Conf.HIGH,
    triggers=frozenset(
        {SignalKind.ACCOUNT_CREATED, SignalKind.ADMIN_GROUP_ADDED, SignalKind.AUTH_SUCCESS}
    ),
    required_data=(
        "Windows Security 4720, 4732/4728/4756 y 4624, o cambios de cuentas del inventario",
    ),
    recommendations=(
        "Confirmar con el responsable del equipo si la cuenta corresponde a un cambio aprobado.",
        "Si no: deshabilitar la cuenta, revisar qué hizo durante la sesión y aislar el equipo"
        " según el procedimiento institucional.",
        "Revisar el resto de grupos privilegiados del activo.",
    ),
    mitre=Mitre("TA0003", "T1136"),
)


class NewPrivilegedAccountUsed:
    meta = CORR_004

    def evaluate(self, ctx: RuleContext, signal: DetectionSignal) -> list[RuleResult]:
        window = ctx.config.change_window
        start, end = signal.occurred_at - window, signal.occurred_at + window
        kinds = [SignalKind.ACCOUNT_CREATED, SignalKind.ADMIN_GROUP_ADDED, SignalKind.AUTH_SUCCESS]
        found = ctx.signals(signal.asset_id, kinds, start, end, limit=500)
        created = [s for s in found if s.kind == SignalKind.ACCOUNT_CREATED]
        admins = [s for s in found if s.kind == SignalKind.ADMIN_GROUP_ADDED]
        logons = [s for s in found if s.kind == SignalKind.AUTH_SUCCESS]
        results = []
        for account in created:
            limit = account.occurred_at + window
            admin = next(
                (
                    a
                    for a in admins
                    if account.occurred_at <= a.occurred_at <= limit and same_principal(a, account)
                ),
                None,
            )
            if admin is None:
                continue
            logon = next(
                (
                    s
                    for s in logons
                    if admin.occurred_at <= s.occurred_at <= limit and same_principal(s, account)
                ),
                None,
            )
            # Las tres piezas son esenciales: sin uso de la cuenta no hay correlación.
            if logon is None:
                continue
            name = _label(account)
            results.append(
                RuleResult(
                    key=_key(account.subject, name.lower()),
                    summary=(
                        f"La cuenta {name} se creó, entró en"
                        f" {_get(admin, 'group') or 'un grupo privilegiado'} y se usó para"
                        f" iniciar sesión en menos de {int(window.total_seconds() // 60)} min."
                    ),
                    evidence=[
                        Evidence(account, "account_created"),
                        Evidence(admin, "admin_change"),
                        Evidence(logon, "logon"),
                    ],
                    occurred_at=logon.occurred_at,
                    details={"account": name, "group": _get(admin, "group")},
                )
            )
        return results


# --- Registro ----------------------------------------------------------------------------------


_TRUSTED_SOURCES = frozenset({"official", "trusted"})
_OBSERVATION_LABEL = {
    "auth_source_ip": "como IP de origen de un inicio de sesión",
    "connection_remote_ip": "como IP remota de una conexión establecida",
}


def _threat_match(ctx: RuleContext, s: DetectionSignal) -> RuleResult:
    """TI-001 (Fase 5C): un indicador de una fuente externa casó con actividad local.

    Severidad alta solo para "malicious" con confianza alta; confianza alta solo si además la
    fuente es oficial o de confianza. Nunca "critical": un IOC externo no prueba un compromiso.
    """
    classification = _get(s, "classification")
    match_confidence = _get(s, "match_confidence")
    strong = classification == "malicious" and match_confidence == "high"
    observed = _get(s, "observed_value") or "?"
    where = _OBSERVATION_LABEL.get(str(_get(s, "observation_type")), "en datos locales")
    summary = (
        f"El valor {observed} aparece {where} y coincide con un indicador clasificado como"
        f" {classification or 'desconocido'} por la fuente {_get(s, 'source') or '?'}."
        " Es contexto externo: requiere análisis, no confirma un compromiso."
    )
    return _single(
        s,
        _key(s.subject, "ioc:*"),
        summary,
        severity=Sev.HIGH if strong else Sev.MEDIUM,
        confidence=(
            Conf.HIGH if strong and _get(s, "source_trust") in _TRUSTED_SOURCES else Conf.MEDIUM
        ),
        details={
            "match_id": _get(s, "match_id"),
            "indicator_id": _get(s, "indicator_id"),
            "indicator_type": _get(s, "indicator_type"),
            "indicator_value": _get(s, "indicator_value"),
            "source": _get(s, "source"),
            "observation_type": _get(s, "observation_type"),
        },
    )


def _meta(**kwargs: Any) -> RuleMeta:
    return RuleMeta(**{"version": 1, "kind": SINGLE, **kwargs})


# --- Linux (Fase 5C.1, eventos del journal) ----------------------------------------------------

LIN_AUTH_001 = RuleMeta(
    id="LIN-AUTH-001",
    version=1,
    kind=SINGLE,
    category="authentication",
    title="Múltiples inicios de sesión SSH/PAM fallidos (Linux)",
    description=(
        "Varios fallos de autenticación de la misma cuenta en el mismo equipo Linux (sshd:"
        " contraseña o clave pública rechazada, usuario inexistente; PAM de su/sudo/login)"
        " dentro de DETECTION_AUTH_FAILURE_WINDOW_MINUTES."
    ),
    why=(
        "Es el patrón de un intento de adivinar contraseñas por SSH. Por sí solo no significa"
        " acceso: también lo produce un usuario que olvidó su contraseña o un script con"
        " credenciales antiguas."
    ),
    severity=Sev.MEDIUM,
    confidence=Conf.MEDIUM,
    triggers=frozenset({SignalKind.AUTH_FAILURE}),
    required_data=("systemd journal: sshd y PAM (agente Linux en el grupo systemd-journal)",),
    recommendations=(
        "Revisar el origen (IP) de los intentos y si el servidor SSH debe ser accesible desde ahí.",
        "Comprobar si hubo un inicio de sesión correcto posterior (ver LIN-AUTH-002).",
        "Valorar deshabilitar la autenticación por contraseña en sshd (solo claves).",
        "Si el origen no es conocido, bloquearlo según el procedimiento de la organización.",
    ),
    mitre=Mitre("TA0006", "T1110"),
    cooldown_setting="auth_failure_window",
)

LIN_AUTH_002 = RuleMeta(
    id="LIN-AUTH-002",
    version=1,
    kind=CORRELATION,
    category="authentication",
    title="Acceso SSH tras fallos repetidos (Linux)",
    description=(
        "Inicio de sesión correcto (SSH) de una cuenta precedido, dentro de"
        " DETECTION_CORRELATION_WINDOW_MINUTES, de al menos DETECTION_AUTH_FAILURE_THRESHOLD"
        " fallos de esa misma cuenta. Si después la cuenta usa sudo o entra en un grupo"
        " privilegiado dentro de DETECTION_CHANGE_WINDOW_MINUTES, se eleva a crítica."
    ),
    why=(
        "Fallos seguidos de un acierto pueden indicar que alguien adivinó la contraseña; usar"
        " sudo justo después es lo que haría un atacante para tomar el control. También puede"
        " ser el propio usuario tras equivocarse: hay que confirmarlo con él."
    ),
    severity=Sev.HIGH,
    confidence=Conf.MEDIUM,
    triggers=frozenset(
        {SignalKind.AUTH_SUCCESS, SignalKind.ADMIN_GROUP_ADDED, SignalKind.SUDO_COMMAND}
    ),
    required_data=(
        "systemd journal: sshd (fallos y accesos) con usuario e IP de origen",
        "Opcional: sudo y cambios de grupos (usermod/gpasswd) del journal",
    ),
    recommendations=(
        "Verificar con el usuario si reconoce el acceso y su origen.",
        "Revisar los comandos ejecutados con sudo en la ventana (pestaña Eventos).",
        "Si no se reconoce: cambiar la contraseña, revisar authorized_keys y los grupos"
        " privilegiados, y aislar el equipo según el procedimiento institucional.",
    ),
    mitre=Mitre("TA0006", "T1110"),
)

_KERNEL_CATEGORY = {
    "oom_kill": ("El kernel terminó un proceso por falta de memoria (OOM)", Sev.LOW),
    "filesystem_error": ("Error del sistema de ficheros", Sev.MEDIUM),
    "hardware_error": ("Error de hardware informado por el kernel", Sev.MEDIUM),
    "kernel_bug": ("Fallo interno del kernel (BUG/Oops)", Sev.MEDIUM),
}


def _kernel(ctx: RuleContext, s: DetectionSignal) -> RuleResult:
    category = str(_get(s, "category") or s.subject or "kernel")
    title, severity = _KERNEL_CATEGORY.get(category, ("Evento crítico del kernel", Sev.LOW))
    process = _get(s, "process")
    device = _get(s, "device")
    summary = (
        title
        + (f" (proceso {process})" if process else "")
        + (f" en {device}" if device else "")
        + "."
    )
    return _single(
        s,
        _key(category, "kernel"),
        summary,
        severity=severity,
        details={"category": category, "process": process, "device": device},
    )


RULES: tuple[DetectionRule, ...] = (
    FailedLogonBurst(),
    FailedLogonBurst(LIN_AUTH_001, "linux"),
    SimpleRule(
        _meta(
            id="AUTH-002",
            category="authentication",
            title="Cuenta bloqueada",
            description="Windows bloqueó una cuenta por superar los intentos fallidos.",
            why=(
                "Suele ser consecuencia de fallos repetidos: un usuario con la contraseña"
                " cambiada o un intento de fuerza bruta."
            ),
            severity=Sev.LOW,
            confidence=Conf.HIGH,
            triggers=frozenset({SignalKind.ACCOUNT_LOCKOUT}),
            required_data=("Windows Security 4740",),
            recommendations=(
                "Confirmar con el usuario antes de desbloquear la cuenta.",
                "Revisar los fallos de inicio de sesión previos y su origen.",
            ),
            mitre=Mitre("TA0006", "T1110"),
        ),
        _lockout,
    ),
    SimpleRule(
        _meta(
            id="ACCT-001",
            category="account",
            title="Cuenta creada",
            description="Se creó una cuenta en el activo (evento 4720 o inventario).",
            why=(
                "Las cuentas nuevas son un mecanismo de persistencia habitual. Normalmente"
                " corresponden a altas planificadas: confirmar que existe la solicitud."
            ),
            severity=Sev.MEDIUM,
            confidence=Conf.HIGH,
            triggers=frozenset({SignalKind.ACCOUNT_CREATED}),
            required_data=(
                "Windows Security 4720, journal Linux (useradd) o cuentas del inventario",
            ),
            recommendations=(
                "Confirmar que la cuenta corresponde a un alta aprobada.",
                "Revisar quién la creó y sus grupos.",
            ),
            mitre=Mitre("TA0003", "T1136"),
        ),
        _account_created,
    ),
    SimpleRule(
        _meta(
            id="ACCT-002",
            category="account",
            title="Cuenta añadida a un grupo privilegiado",
            description=(
                "Una cuenta entró en un grupo privilegiado (Administradores, Operadores de"
                " copia, Escritorio remoto, Domain Admins...), identificado por SID."
            ),
            why=(
                "Dar privilegios a una cuenta permite controlar el equipo. Es un cambio de alto"
                " impacto aunque sea legítimo, y lo primero que hace un atacante tras acceder."
            ),
            severity=Sev.HIGH,
            confidence=Conf.HIGH,
            triggers=frozenset({SignalKind.ADMIN_GROUP_ADDED}),
            required_data=(
                "Windows Security 4728/4732/4756, journal Linux (usermod/gpasswd: sudo, wheel)"
                " o administradores del inventario",
            ),
            recommendations=(
                "Confirmar que el cambio está aprobado.",
                "Revisar quién hizo el cambio y desde qué sesión.",
                "Si no se reconoce, retirar la cuenta del grupo y revisar su actividad.",
            ),
            mitre=Mitre("TA0004", "T1098", "T1098.007"),
        ),
        _admin_added,
    ),
    SimpleRule(
        _meta(
            id="ACCT-003",
            category="account",
            title="Cambio de estado de una cuenta",
            description=(
                "Una cuenta se habilitó, deshabilitó, eliminó o salió de un grupo privilegiado."
            ),
            why=(
                "Habilitar una cuenta inactiva puede reactivar un acceso olvidado. Deshabilitar"
                " o eliminar suele ser mantenimiento: se registra como contexto."
            ),
            severity=Sev.LOW,
            confidence=Conf.HIGH,
            triggers=frozenset(
                {
                    SignalKind.ACCOUNT_ENABLED,
                    SignalKind.ACCOUNT_DISABLED,
                    SignalKind.ACCOUNT_DELETED,
                    SignalKind.ADMIN_GROUP_REMOVED,
                }
            ),
            required_data=("Windows Security 4722/4725/4726/4729/4733/4757 o inventario",),
            recommendations=("Confirmar que el cambio corresponde a una solicitud.",),
        ),
        _account_state,
    ),
    SimpleRule(
        _meta(
            id="SCR-001",
            category="scripting",
            title="PowerShell marcó un script como sospechoso",
            description=(
                "PowerShell registró el evento 4104 con nivel Warning: el propio motor de"
                " scripts marcó el bloque como sospechoso (p. ej. ofuscación)."
            ),
            why=(
                "Es la señal que Windows da sobre código potencialmente malicioso. Sentra no"
                " recoge el contenido del script (puede contener credenciales), así que hay que"
                " revisarlo en el propio equipo."
            ),
            severity=Sev.MEDIUM,
            confidence=Conf.MEDIUM,
            triggers=frozenset({SignalKind.POWERSHELL_SUSPICIOUS}),
            required_data=("Microsoft-Windows-PowerShell/Operational 4104 (nivel Warning)",),
            recommendations=(
                "Revisar el evento 4104 en el Visor de eventos del equipo.",
                "Identificar el usuario y el proceso que ejecutaron el script.",
                "Revisar procesos y conexiones nuevas en la misma ventana.",
            ),
            mitre=Mitre("TA0002", "T1059", "T1059.001"),
            cooldown=timedelta(minutes=15),
        ),
        _powershell,
    ),
    SimpleRule(
        _meta(
            id="PER-001",
            category="persistence",
            title="Servicio nuevo",
            description=(
                "Se instaló un servicio (System 7045) o apareció uno nuevo en el inventario."
                " Severidad alta si el ejecutable está en una ubicación inusual."
            ),
            why=(
                "Un servicio arranca con el sistema y suele tener privilegios elevados: es un"
                " mecanismo de persistencia. La mayoría vienen de instalaciones legítimas."
            ),
            severity=Sev.MEDIUM,
            confidence=Conf.HIGH,
            triggers=frozenset({SignalKind.SERVICE_INSTALLED, SignalKind.SERVICE_ADDED}),
            required_data=("System 7045 o servicios del inventario",),
            recommendations=(
                "Identificar el software que instaló el servicio.",
                "Revisar la ruta del ejecutable, su firma y la cuenta con la que corre.",
            ),
            mitre=Mitre("TA0003", "T1543"),
        ),
        _service,
    ),
    SimpleRule(
        _meta(
            id="PROC-001",
            category="process",
            title="Proceso desde una ubicación inusual",
            description=(
                "Un ejecutable nunca visto en el activo corre desde una carpeta temporal,"
                " pública o similar, o su binario se borró mientras corría (Linux)."
            ),
            why=(
                "El malware suele ejecutarse desde carpetas con escritura para cualquier"
                " usuario. También lo hacen instaladores y actualizadores: señal débil."
            ),
            severity=Sev.MEDIUM,
            confidence=Conf.LOW,
            triggers=frozenset({SignalKind.PROCESS_NEW}),
            required_data=("Snapshots de procesos con ruta del ejecutable",),
            recommendations=(
                "Identificar el proceso padre y el usuario.",
                "Revisar la firma y la reputación del ejecutable.",
                "Revisar conexiones de red del proceso.",
            ),
        ),
        _unusual_process,
    ),
    SimpleRule(
        _meta(
            id="NET-001",
            category="network",
            title="Puerto expuesto en la red",
            description=(
                "Discovery encontró un puerto accesible que antes no lo era (tras la línea base"
                " de exposición del activo)."
            ),
            why=(
                "Cada puerto accesible amplía la superficie de ataque; los de administración"
                " remota o bases de datos (RDP, SMB, SSH, SQL...) son los más buscados."
            ),
            severity=Sev.LOW,
            confidence=Conf.HIGH,
            triggers=frozenset({SignalKind.PORT_EXPOSED}),
            required_data=("Discovery de red con línea base de exposición",),
            recommendations=(
                "Confirmar que el servicio debe estar accesible.",
                "Restringir el acceso con el firewall a los orígenes necesarios.",
            ),
        ),
        _port_exposed,
    ),
    SimpleRule(
        _meta(
            id="NET-002",
            category="network",
            title="Nuevo puerto sensible en escucha",
            description="El agente ve un puerto sensible nuevo en escucha fuera de loopback.",
            why=(
                "Indica qué proceso abrió un puerto de administración o de datos aunque discovery"
                " aún no lo haya visto (o un firewall lo bloquee desde el servidor)."
            ),
            severity=Sev.MEDIUM,
            confidence=Conf.MEDIUM,
            triggers=frozenset({SignalKind.LISTEN_PORT_NEW}),
            required_data=("Conexiones en escucha del inventario",),
            recommendations=(
                "Confirmar qué software abrió el puerto y si está aprobado.",
                "Comprobar las reglas de firewall del equipo.",
            ),
        ),
        _listen_port,
    ),
    SimpleRule(
        _meta(
            id="NET-003",
            category="network",
            title="Dispositivo nuevo en la red",
            description="Discovery encontró un host que no conocía (después de la línea base).",
            why=(
                "Un dispositivo no inventariado puede ser legítimo (un equipo nuevo) o no"
                " autorizado. Sin identificar merece más atención."
            ),
            severity=Sev.LOW,
            confidence=Conf.MEDIUM,
            triggers=frozenset({SignalKind.ASSET_DISCOVERED}),
            required_data=("Discovery de red",),
            recommendations=("Identificar al responsable del dispositivo.",),
        ),
        _discovered,
    ),
    SimpleRule(
        _meta(
            id="NET-004",
            category="network",
            title="Activo desaparecido de la red",
            description="Un activo dejó de verse en varias pasadas completas de discovery.",
            why="Contexto operativo: puede ser un equipo apagado o retirado.",
            severity=Sev.INFORMATIONAL,
            confidence=Conf.MEDIUM,
            triggers=frozenset({SignalKind.ASSET_DISAPPEARED}),
            required_data=("Discovery de red (pasadas completas)",),
            recommendations=("Confirmar si el equipo se retiró o apagó a propósito.",),
        ),
        _disappeared,
    ),
    SimpleRule(
        _meta(
            id="DEF-001",
            category="defense",
            title="Registro de eventos borrado",
            description="Se borró el registro Security (1102) u otro registro (System 104).",
            why=(
                "Borrar registros elimina el rastro de lo ocurrido: es una técnica clásica de"
                " ocultación. Raramente es una tarea de mantenimiento legítima."
            ),
            severity=Sev.HIGH,
            confidence=Conf.HIGH,
            triggers=frozenset({SignalKind.LOG_CLEARED}),
            required_data=("Windows Security 1102 o System 104",),
            recommendations=(
                "Identificar la cuenta que borró el registro y confirmar el motivo.",
                "Revisar en Sentra los eventos recibidos antes del borrado.",
                "Si no se reconoce, tratarlo como incidente y aislar el equipo según el"
                " procedimiento institucional.",
            ),
            mitre=Mitre("TA0005", "T1070", "T1070.001"),
        ),
        _log_cleared,
    ),
    SimpleRule(
        _meta(
            id="DEF-002",
            category="defense",
            title="Política de auditoría modificada",
            description=(
                "Cambió la política de auditoría (4719). Alta si se quitó auditoría de éxito o"
                " fallo; informativa si se añadió."
            ),
            why=("Desactivar auditoría impide que queden registros de lo que se haga después."),
            severity=Sev.MEDIUM,
            confidence=Conf.MEDIUM,
            triggers=frozenset({SignalKind.AUDIT_POLICY_CHANGED}),
            required_data=("Windows Security 4719",),
            recommendations=(
                "Confirmar el cambio con el responsable del equipo o de las GPO.",
                "Restaurar la política de auditoría si no estaba aprobado.",
            ),
        ),
        _audit_policy,
    ),
    SimpleRule(
        _meta(
            id="DEF-003",
            category="defense",
            title="Servicio de seguridad detenido o deshabilitado",
            description=(
                "Un servicio de DETECTION_SECURITY_SERVICES (Defender, firewall, Event Log,"
                " auditd...) se detuvo, se deshabilitó o desapareció del inventario."
            ),
            why=(
                "Detener las defensas es un paso previo habitual a otras acciones. Puede ser"
                " legítimo (otro antivirus desactiva Defender, mantenimiento)."
            ),
            severity=Sev.HIGH,
            confidence=Conf.MEDIUM,
            triggers=frozenset({SignalKind.SECURITY_SERVICE_DOWN}),
            required_data=("Servicios del inventario",),
            recommendations=(
                "Confirmar si hay otro producto de seguridad que lo sustituya.",
                "Volver a iniciar el servicio y revisar quién lo detuvo.",
            ),
            mitre=Mitre("TA0005", "T1562", "T1562.001"),
        ),
        _security_service,
    ),
    SimpleRule(
        _meta(
            id="DEF-004",
            category="defense",
            title="Protección antimalware desactivada",
            description="Microsoft Defender informó protección desactivada (5001/5010/5012).",
            why="Sin protección en tiempo real el equipo queda expuesto a software malicioso.",
            severity=Sev.HIGH,
            confidence=Conf.HIGH,
            triggers=frozenset({SignalKind.ANTIMALWARE_DISABLED}),
            required_data=("Microsoft-Windows-Windows Defender/Operational",),
            recommendations=(
                "Reactivar la protección y confirmar quién la desactivó.",
                "Comprobar si la protección contra alteraciones está activa.",
            ),
            mitre=Mitre("TA0005", "T1562", "T1562.001"),
        ),
        _antimalware_disabled,
    ),
    SimpleRule(
        _meta(
            id="DEF-005",
            category="defense",
            title="Amenaza detectada por el antimalware",
            description=(
                "Microsoft Defender detectó una amenaza (1116/1117); crítica si no pudo"
                " neutralizarla (1118/1119)."
            ),
            why=(
                "Es una detección del propio antimalware del equipo. Si la neutralizó, queda"
                " revisar cómo llegó; si no, el equipo puede seguir comprometido."
            ),
            severity=Sev.HIGH,
            confidence=Conf.HIGH,
            triggers=frozenset({SignalKind.MALWARE_DETECTED}),
            required_data=("Microsoft-Windows-Windows Defender/Operational",),
            recommendations=(
                "Revisar en Defender el estado de la amenaza y la acción aplicada.",
                "Identificar cómo llegó el archivo (descarga, correo, USB).",
                "Si no se neutralizó, aislar el equipo según el procedimiento institucional.",
            ),
        ),
        _malware,
    ),
    RepeatedRule(
        _meta(
            id="SYS-001",
            category="system",
            title="Apagado inesperado",
            description=(
                "Reinicio sin apagado limpio (Kernel-Power 41, EventLog 6008). Media si se"
                " repite DETECTION_REPEAT_THRESHOLD veces en DETECTION_REPEAT_WINDOW_MINUTES."
            ),
            why=(
                "Suele ser un corte de luz o un fallo de hardware o drivers; repetido afecta a"
                " la disponibilidad y puede ocultar manipulación."
            ),
            severity=Sev.LOW,
            confidence=Conf.HIGH,
            triggers=frozenset({SignalKind.UNEXPECTED_SHUTDOWN}),
            required_data=("System 41 (Kernel-Power) o 6008 (EventLog)",),
            recommendations=(
                "Revisar alimentación, temperatura y volcados de memoria.",
                "Si se repite, revisar drivers y actualizaciones recientes.",
            ),
            # 41 y 6008 del mismo reinicio llegan juntos: una sola ocurrencia.
            cooldown=timedelta(minutes=10),
        ),
        lambda s, count, hours: f"{count} apagados inesperados en {hours} h.",
        by_subject=False,
        single=(Sev.LOW, "El equipo se reinició sin un apagado limpio."),
    ),
    RepeatedRule(
        _meta(
            id="SYS-002",
            category="system",
            title="Servicio que falla repetidamente",
            description=(
                "El mismo servicio terminó inesperadamente (7031/7034)"
                " DETECTION_REPEAT_THRESHOLD veces en DETECTION_REPEAT_WINDOW_MINUTES."
            ),
            why=(
                "Un servicio que se cae una y otra vez afecta a la disponibilidad; si es un"
                " servicio de seguridad puede ser un intento de desactivarlo."
            ),
            severity=Sev.MEDIUM,
            confidence=Conf.HIGH,
            triggers=frozenset({SignalKind.SERVICE_CRASHED}),
            required_data=(
                "System 7031/7034 con nombre del servicio o systemd (journal Linux):"
                " unidad que termina con fallo",
            ),
            recommendations=(
                "Revisar el registro de la aplicación del servicio.",
                "Comprobar actualizaciones o cambios recientes del software.",
            ),
            cooldown=timedelta(hours=1),
        ),
        lambda s, count, hours: (
            f"El servicio {_get(s, 'service') or s.subject or 'desconocido'} terminó"
            f" inesperadamente {count} veces en {hours} h."
        ),
        by_subject=True,
    ),
    FailedThenSuccess(),
    FailedThenSuccess(LIN_AUTH_002, "linux"),
    SimpleRule(
        _meta(
            id="LIN-SYS-001",
            category="system",
            title="Evento crítico del kernel (Linux)",
            description=(
                "El kernel informó un problema relevante: proceso terminado por falta de"
                " memoria (OOM), error de sistema de ficheros, error de hardware o un fallo"
                " interno (BUG/Oops). Una ocurrencia por categoría y hora."
            ),
            why=(
                "Afecta a la disponibilidad y a la integridad de los datos; un error de disco o"
                " de memoria repetido anticipa una avería. No es un indicio de ataque por sí"
                " solo."
            ),
            severity=Sev.LOW,
            confidence=Conf.HIGH,
            triggers=frozenset({SignalKind.KERNEL_CRITICAL}),
            required_data=("systemd journal: mensajes del kernel de nivel warning o superior",),
            recommendations=(
                "Revisar `journalctl -k` en el equipo alrededor de la hora del evento.",
                "OOM: revisar el consumo de memoria del proceso y los límites del servicio.",
                "Errores de disco o hardware: comprobar SMART, cables y copias de seguridad.",
            ),
            cooldown=timedelta(hours=1),
        ),
        _kernel,
    ),
    PowerShellPersistence(),
    ExposureWithNewSoftware(),
    NewPrivilegedAccountUsed(),
    SimpleRule(
        _meta(
            id="TI-001",
            category="threat_intel",
            title="Threat Intel IOC Match",
            description=(
                "Un indicador (IP o red) de una fuente de inteligencia aparece en actividad"
                " local observada: IP de origen de un inicio de sesión o IP remota de una"
                " conexión establecida."
            ),
            why=(
                "La fuente asocia ese valor a actividad maliciosa. Que aparezca en un activo"
                " merece revisión, pero la inteligencia puede estar desactualizada o ser un"
                " falso positivo (IPs compartidas, CDNs): no confirma un compromiso."
            ),
            severity=Sev.MEDIUM,
            confidence=Conf.MEDIUM,
            triggers=frozenset({SignalKind.THREAT_INTEL_MATCH}),
            required_data=(
                "Fuente de inteligencia con IOCs de IP",
                "Windows Security 4624/4625 o conexiones del inventario",
            ),
            recommendations=(
                "Revisar el evento o la conexión que coincide y su contexto.",
                "Comprobar la fuente, la fecha y la confianza del indicador.",
                "Si es legítimo, descartar el match como falso positivo.",
            ),
            cooldown=timedelta(hours=24),
        ),
        _threat_match,
    ),
)

RULE_IDS = frozenset(rule.meta.id for rule in RULES)
RULES_BY_ID = {rule.meta.id: rule for rule in RULES}
