"""Atribución verificable de detecciones a operaciones de mantenimiento (Fase 7B.1).

Cálculo puro: evidencia guardada de una detección + operaciones aprobadas del activo ->
veredicto con cada comprobación hecha. Sin base de datos ni reloj (el llamador pasa `now`),
así se prueba sin PostgreSQL y se puede repetir una evaluación para auditarla. El servicio
(app/services/attribution_service.py) carga los datos y guarda el resultado.

Principios (docs/detection-attribution.md):
- Nada se verifica por el nombre: `SentraAgent`, `sentra.exe` o `powershell.exe` se
  falsifican con facilidad. Un script se verifica por SHA-256 + ruta canónica + cuenta +
  ventana (y por intérprete, padre y firma cuando la operación los exige); un servicio por
  nombre + ImagePath exacto + cuenta + ventana.
- Los hashes de referencia los escribe un admin o salen del propio servidor (catálogo de
  referencia). Este módulo nunca aprende un hash de lo que observó.
- TODA la evidencia que dispara la regla debe casar con UNA misma operación. Un solo
  elemento que no casa (otro script en la ventana, un hash distinto) deja la detección
  como sospechosa: una operación legítima no tapa actividad que no describe.
- Si falta un dato para comprobar, el veredicto es `insufficient_evidence` y se dice qué
  falta y cómo obtenerlo sin desactivar controles.
- `confirmed_malicious` solo lo decide una persona; este módulo nunca lo devuelve.
"""

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

# Reglas cuya evidencia se puede atribuir a una operación. NET-001 se evalúa (quién abre el
# puerto) pero nunca se resuelve sola: un puerto expuesto es riesgo aunque el proceso sea
# legítimo (requisito de 7B.1).
ATTRIBUTABLE_RULES = frozenset({"SCR-001", "CORR-002", "PER-001", "NET-001"})
EXPOSURE_RULES = frozenset({"NET-001"})

VERIFIED = "verified_benign"
SUSPICIOUS = "suspicious_unverified"
INSUFFICIENT = "insufficient_evidence"
MALICIOUS = "confirmed_malicious"

PASS = "pass"  # noqa: S105 - resultado de una comprobación, no una contraseña
FAIL = "fail"
MISSING = "missing"
NOT_REQUIRED = "not_required"

SCRIPT_KINDS = frozenset({"powershell_suspicious"})
SERVICE_KINDS = frozenset({"service_installed", "service_added", "service_modified"})
PROCESS_KINDS = frozenset({"process_new"})
PORT_KINDS = frozenset({"port_exposed"})

# Cómo conseguir cada dato que falta sin apagar ningún control (se muestra al analista).
HOW_TO_OBTAIN: Mapping[str, str] = {
    "script_context": (
        "Actualizar el agente del equipo a 0.6.0 o superior (el servicio, no solo el .venv):"
        " los agentes anteriores no envían ruta, hash, PID ni cuenta del 4104."
    ),
    "script_hash": (
        "El agente no pudo leer el script para calcular su SHA-256 (fichero borrado, sin"
        " permisos o fuera de límites). Ejecutar el instalador desde una ruta que la cuenta"
        " del servicio pueda leer (p. ej. bajo C:\\ProgramData) o calcular el hash en el"
        " equipo con Get-FileHash y revisar la detección a mano. No ampliar los permisos de la"
        " cuenta del servicio."
    ),
    "account": (
        "El evento no trae la cuenta (UserID del 4104 o AccountName del 7045). Revisar el"
        " evento en el Visor de eventos del equipo."
    ),
    "process": (
        "La telemetría de actividad (agente 0.5.0+) no vio el proceso: dura segundos o la"
        " telemetría está apagada. Activar la telemetría de procesos o revisar el 4688 si la"
        " auditoría de creación de procesos ya está habilitada por política."
    ),
    "parent": (
        "No hay proceso padre en la telemetría. Mismo origen que el proceso: telemetría de"
        " actividad o 4688 con la línea de comandos habilitada por política."
    ),
    "service_image_path": (
        "El servicio solo se vio en el inventario (sin 7045): no hay ImagePath ni cuenta de"
        " instalación. Revisar el evento 7045 del Service Control Manager en el canal System."
    ),
    "owner_process": (
        "Sin agente o sin inventario de conexiones no se sabe qué proceso escucha en el"
        " puerto. Instalar el agente en el equipo o comprobarlo con Get-NetTCPConnection."
    ),
}

_DRIVE = re.compile(r"^[a-z]:\\")
_SPACES = re.compile(r"\s+")


def canonical_path(value: str | None) -> str | None:
    """Ruta comparable: Windows sin distinguir mayúsculas y con separadores normalizados.

    Una ruta con segmentos `..` o `.` nunca es canónica (devuelve None): así un artefacto
    autorizado no puede describirse con una ruta que "se parece" a otra.
    """
    if not value:
        return None
    path = value.strip().strip('"').strip()
    if not path:
        return None
    windows = "\\" in path or bool(re.match(r"^[A-Za-z]:", path))
    if windows:
        path = path.replace("/", "\\")
        for prefix in ("\\\\?\\", "\\??\\"):
            if path.startswith(prefix):
                path = path[len(prefix) :]
        path = re.sub(r"\\{2,}", "\\\\", path).casefold()
        parts = path.split("\\")
    else:
        path = re.sub(r"/{2,}", "/", path)
        parts = path.split("/")
    if any(part in (".", "..") for part in parts):
        return None
    return path


def canonical_command(value: str | None) -> str | None:
    """ImagePath de un servicio comparable: espacios colapsados y sin distinguir mayúsculas.

    Se compara la línea COMPLETA (ejecutable + argumentos): `python.exe -m sentra_agent` y
    `python.exe -m otra_cosa` son servicios distintos aunque el ejecutable sea el mismo.
    """
    if not value:
        return None
    command = _SPACES.sub(" ", value.strip()).casefold()
    return command or None


def canonical_account(value: str | None) -> str | None:
    if not value:
        return None
    account = value.strip().casefold()
    return account or None


@dataclass(frozen=True)
class ArtifactRef:
    kind: str
    path: str | None = None
    sha256: str | None = None
    signer: str | None = None
    service_name: str | None = None
    service_display_name: str | None = None
    image_path: str | None = None
    service_account: str | None = None


@dataclass(frozen=True)
class OperationRef:
    """Operación aprobada y vigente tal como la ve el cálculo (sin ORM)."""

    id: int
    public_id: str
    operation_key: str
    version: int
    title: str
    window_start: datetime
    window_end: datetime
    accounts: frozenset[str]
    interpreters: frozenset[str]
    parents: frozenset[str]
    signer: str | None
    artifacts: tuple[ArtifactRef, ...]
    # Fase 7B.1 (política de autorización): cuándo la aprobó un admin. El reconocimiento
    # automático solo vale para actividad posterior a la aprobación.
    approved_at: datetime | None = None


@dataclass(frozen=True)
class EvidenceItem:
    signal_kind: str
    occurred_at: datetime
    data: Mapping[str, Any]
    role: str | None = None


@dataclass
class Check:
    check: str
    result: str
    expected: Any = None
    observed: Any = None

    def to_json(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "result": self.result,
            "expected": self.expected,
            "observed": self.observed,
        }


@dataclass
class ItemResult:
    kind: str
    label: str
    occurred_at: datetime
    checks: list[Check] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    # Evidencia que no dispara la regla (procesos normales de la ventana de CORR-002): se
    # muestra, pero no decide el veredicto.
    context_only: bool = False

    @property
    def result(self) -> str:
        if self.context_only:
            return NOT_REQUIRED
        if any(c.result == FAIL for c in self.checks):
            return FAIL
        if self.missing or any(c.result == MISSING for c in self.checks):
            return MISSING
        return PASS

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "label": self.label,
            "occurred_at": self.occurred_at.isoformat(),
            "result": self.result,
            "checks": [c.to_json() for c in self.checks],
            "missing": sorted(set(self.missing)),
            "context_only": self.context_only,
        }


@dataclass
class AttributionResult:
    verdict: str
    rule_id: str
    operation: OperationRef | None
    items: list[ItemResult]
    explanation: list[str]
    tamper_suspected: bool = False
    candidates_evaluated: int = 0
    # Una operación aprobada DESPUÉS de la actividad la describiría: no se aplica sola, la
    # detección sigue activa y espera una revisión explícita (vista previa y aplicar).
    review_required: dict[str, Any] | None = None

    @property
    def missing(self) -> list[str]:
        found: list[str] = []
        for item in self.items:
            if item.context_only:
                continue
            for code in item.missing:
                if code not in found:
                    found.append(code)
        return found

    def to_json(self, evaluated_at: datetime) -> dict[str, Any]:
        op = self.operation
        return {
            "verdict": self.verdict,
            "rule_id": self.rule_id,
            "evaluated_at": evaluated_at.isoformat(),
            "operation": (
                {
                    "operation_id": op.public_id,
                    "operation_key": op.operation_key,
                    "version": op.version,
                    "title": op.title,
                    "window_start": op.window_start.isoformat(),
                    "window_end": op.window_end.isoformat(),
                }
                if op
                else None
            ),
            "items": [item.to_json() for item in self.items],
            "missing_evidence": [
                {"code": code, "how_to_obtain": HOW_TO_OBTAIN.get(code, "")}
                for code in self.missing
            ],
            "tamper_suspected": self.tamper_suspected,
            "candidates_evaluated": self.candidates_evaluated,
            "review_required": self.review_required,
            "explanation": self.explanation,
            # Efecto en el riesgo: una detección verificada no suma riesgo activo; un puerto
            # expuesto sí, aunque el proceso que escucha esté verificado.
            "risk_effect": (
                "kept_exposure"
                if self.rule_id in EXPOSURE_RULES
                else ("excluded" if self.verdict == VERIFIED else "kept")
            ),
        }


# --- Comprobaciones por tipo de evidencia --------------------------------------------------


def _str(data: Mapping[str, Any], key: str) -> str | None:
    value = data.get(key)
    return str(value) if value not in (None, "") else None


def _window(op: OperationRef, at: datetime) -> Check:
    inside = op.window_start <= at <= op.window_end
    return Check(
        "window",
        PASS if inside else FAIL,
        expected=f"{op.window_start.isoformat()} - {op.window_end.isoformat()}",
        observed=at.isoformat(),
    )


def _process_checks(op: OperationRef, data: Mapping[str, Any], item: ItemResult) -> None:
    """Intérprete, padre y firma: solo si la operación los exige (si no, se dice)."""
    exe = canonical_path(_str(data, "process_exe"))
    if op.interpreters:
        if exe is None:
            item.checks.append(Check("interpreter", MISSING, sorted(op.interpreters)))
            item.missing.append("process")
        else:
            ok = exe in op.interpreters
            item.checks.append(
                Check("interpreter", PASS if ok else FAIL, sorted(op.interpreters), exe)
            )
    else:
        item.checks.append(Check("interpreter", NOT_REQUIRED, observed=exe))
    parent = canonical_path(_str(data, "parent_exe"))
    if op.parents:
        if parent is None:
            item.checks.append(Check("parent", MISSING, sorted(op.parents)))
            item.missing.append("parent")
        else:
            ok = parent in op.parents
            item.checks.append(Check("parent", PASS if ok else FAIL, sorted(op.parents), parent))
    else:
        item.checks.append(Check("parent", NOT_REQUIRED, observed=parent))
    signer = _str(data, "process_signer")
    if op.signer:
        # Firma "cuando exista": sin firma en la telemetría no se bloquea, pero una firma
        # distinta sí es una discrepancia.
        if signer is None:
            item.checks.append(Check("signer", NOT_REQUIRED, op.signer, None))
        else:
            ok = signer.strip().casefold() == op.signer.strip().casefold()
            item.checks.append(Check("signer", PASS if ok else FAIL, op.signer, signer))


def _script_item(op: OperationRef | None, ev: EvidenceItem) -> ItemResult:
    data = ev.data
    path_raw = _str(data, "script_path")
    item = ItemResult("script", path_raw or "bloque de PowerShell sin fichero", ev.occurred_at)
    if not any(_str(data, k) for k in ("script_block_id", "script_path", "pid")):
        item.missing.append("script_context")
        return item
    if _str(data, "script_origin") == "inline" or not path_raw:
        # Un bloque tecleado o pasado con -Command no tiene fichero ni hash que comparar:
        # no se puede atribuir a ninguna operación.
        item.checks.append(Check("origin", FAIL, "file", "inline"))
        return item
    digest = (_str(data, "script_sha256") or "").lower() or None
    path = canonical_path(path_raw)
    if digest is None:
        item.missing.append("script_hash")
    account = canonical_account(_str(data, "user_sid"))
    process_user = canonical_account(_str(data, "process_user"))
    if op is None:
        item.checks.append(Check("operation", FAIL, "operación aprobada que cubra el script"))
        if account is None and process_user is None:
            item.missing.append("account")
        return item
    scripts = [a for a in op.artifacts if a.kind == "script"]
    by_hash = [a for a in scripts if digest and a.sha256 == digest]
    by_path = [a for a in scripts if path and a.path == path]
    if digest is not None:
        exact = [a for a in by_hash if a.path == path]
        if exact:
            item.checks.append(Check("sha256", PASS, digest, digest))
            item.checks.append(Check("path", PASS, path, path))
        elif by_hash:
            # Mismo contenido en otra ruta: copiado fuera de su sitio.
            item.checks.append(Check("sha256", PASS, digest, digest))
            item.checks.append(Check("path", FAIL, sorted({a.path for a in by_hash}), path))
        elif by_path:
            # Misma ruta y otro contenido: el script cambió después de autorizarlo.
            item.checks.append(Check("sha256", FAIL, sorted({a.sha256 for a in by_path}), digest))
            item.checks.append(Check("path", PASS, path, path))
        else:
            item.checks.append(Check("artifact", FAIL, "script autorizado (hash + ruta)", path))
    elif by_path:
        item.checks.append(Check("sha256", MISSING, sorted({a.sha256 for a in by_path}), None))
        item.checks.append(Check("path", PASS, path, path))
    else:
        item.checks.append(Check("artifact", FAIL, "script autorizado (hash + ruta)", path))
    item.checks.append(_window(op, ev.occurred_at))
    if account is None and process_user is None:
        item.checks.append(Check("account", MISSING, sorted(op.accounts)))
        item.missing.append("account")
    else:
        ok = bool({account, process_user} & op.accounts)
        item.checks.append(
            Check("account", PASS if ok else FAIL, sorted(op.accounts), account or process_user)
        )
    _process_checks(op, data, item)
    return item


def _service_item(
    op: OperationRef | None, ev: EvidenceItem, verified_names: set[str]
) -> ItemResult:
    data = ev.data
    name_raw = _str(data, "service") or "servicio desconocido"
    name = name_raw.strip().casefold()
    item = ItemResult("service", name_raw, ev.occurred_at)
    from_event = ev.signal_kind == "service_installed"
    if op is None:
        item.checks.append(Check("operation", FAIL, "operación aprobada que cubra el servicio"))
        if not from_event:
            item.missing.append("service_image_path")
        return item
    artifacts = [
        a
        for a in op.artifacts
        if a.kind == "service"
        and name in {(a.service_name or "").casefold(), (a.service_display_name or "").casefold()}
    ]
    if not artifacts:
        item.checks.append(Check("service", FAIL, "servicio autorizado", name_raw))
        item.checks.append(_window(op, ev.occurred_at))
        return item
    item.checks.append(Check("service", PASS, name_raw, name_raw))
    item.checks.append(_window(op, ev.occurred_at))
    # Fase 7B-Fix1: el inventario del agente 0.6.2 trae la línea de comandos (binpath) y la
    # cuenta del servicio; se comparan igual que las del 7045.
    command = _str(data, "image_path") if from_event else _str(data, "binpath")
    if not from_event and command is None:
        # Inventario antiguo: sin ImagePath ni cuenta. Solo corrobora si el 7045 del mismo
        # servicio, en esta misma detección, ya se verificó con todos sus datos.
        if name in verified_names:
            item.checks.append(Check("image_path", PASS, "verificado por el 7045", None))
        else:
            item.checks.append(Check("image_path", MISSING, artifacts[0].image_path))
            item.missing.append("service_image_path")
        return item
    image = canonical_command(command)
    expected = {canonical_command(a.image_path) for a in artifacts} - {None}
    if image is None:
        item.checks.append(Check("image_path", MISSING, sorted(expected)))
        item.missing.append("service_image_path")
    else:
        item.checks.append(
            Check("image_path", PASS if image in expected else FAIL, sorted(expected), image)
        )
    accounts = {canonical_account(a.service_account) for a in artifacts} - {None}
    observed_account = canonical_account(_str(data, "account"))
    if accounts:
        if observed_account is None:
            item.checks.append(Check("service_account", MISSING, sorted(accounts)))
            item.missing.append("account")
        else:
            ok = observed_account in accounts
            item.checks.append(
                Check("service_account", PASS if ok else FAIL, sorted(accounts), observed_account)
            )
    else:
        item.checks.append(Check("service_account", NOT_REQUIRED, observed=observed_account))
    return item


def _process_item(op: OperationRef | None, ev: EvidenceItem) -> ItemResult:
    data = ev.data
    exe_raw = _str(data, "exe") or _str(data, "name") or "proceso"
    item = ItemResult("process", exe_raw, ev.occurred_at)
    unusual = bool(data.get("unusual_location"))
    if not unusual:
        # Proceso nuevo corriente: contexto de la correlación, no la dispara.
        item.context_only = True
        return item
    digest = (_str(data, "sha256") or "").lower() or None
    if op is None:
        item.checks.append(Check("operation", FAIL, "binario autorizado", exe_raw))
        return item
    binaries = [a for a in op.artifacts if a.kind == "binary"]
    path = canonical_path(exe_raw)
    if digest is None:
        item.checks.append(Check("sha256", MISSING))
        item.missing.append("process")
    elif any(a.sha256 == digest and a.path == path for a in binaries):
        item.checks.append(Check("binary", PASS, digest, digest))
    else:
        item.checks.append(Check("binary", FAIL, "binario autorizado (hash + ruta)", path))
    item.checks.append(_window(op, ev.occurred_at))
    return item


def _port_item(op: OperationRef | None, ev: EvidenceItem) -> ItemResult:
    data = ev.data
    port = data.get("port")
    item = ItemResult("port", f"{port}/tcp", ev.occurred_at)
    exe = canonical_path(_str(data, "exe"))
    digest = (_str(data, "sha256") or "").lower() or None
    if exe is None and digest is None:
        item.missing.append("owner_process")
        return item
    if op is None:
        item.checks.append(Check("operation", FAIL, "binario autorizado que escuche", exe))
        return item
    binaries = [a for a in op.artifacts if a.kind == "binary"]
    if digest is None:
        item.checks.append(Check("sha256", MISSING))
        item.missing.append("owner_process")
    elif any(a.sha256 == digest and a.path == exe for a in binaries):
        item.checks.append(Check("binary", PASS, digest, digest))
    else:
        item.checks.append(Check("binary", FAIL, "binario autorizado (hash + ruta)", exe))
    return item


def _items_for(op: OperationRef | None, evidence: Sequence[EvidenceItem]) -> list[ItemResult]:
    items: list[ItemResult] = []
    services = [e for e in evidence if e.signal_kind in SERVICE_KINDS]
    verified_names: set[str] = set()
    # Primero los 7045 (traen ImagePath y cuenta): un servicio del inventario solo se
    # corrobora con un 7045 verificado del mismo nombre.
    for ev in sorted(services, key=lambda e: e.signal_kind != "service_installed"):
        result = _service_item(op, ev, verified_names)
        if ev.signal_kind == "service_installed" and result.result == PASS:
            verified_names.add(str(ev.data.get("service") or "").strip().casefold())
        items.append(result)
    for ev in evidence:
        if ev.signal_kind in SCRIPT_KINDS:
            items.append(_script_item(op, ev))
        elif ev.signal_kind in PROCESS_KINDS:
            items.append(_process_item(op, ev))
        elif ev.signal_kind in PORT_KINDS:
            items.append(_port_item(op, ev))
    items.sort(key=lambda i: (i.occurred_at, i.kind, i.label))
    return items


def _verdict(items: Sequence[ItemResult], has_operation: bool) -> str:
    deciding = [i for i in items if not i.context_only]
    if not deciding:
        return INSUFFICIENT
    if any(i.result == FAIL for i in deciding):
        # Sin operación y con datos que faltan, "sospechoso" sería afirmar algo que no se
        # pudo comprobar: se dice que falta evidencia.
        if not has_operation and any(i.missing for i in deciding):
            return INSUFFICIENT
        return SUSPICIOUS
    if any(i.result == MISSING for i in deciding):
        return INSUFFICIENT
    return VERIFIED if has_operation else SUSPICIOUS


def _tampered(items: Iterable[ItemResult]) -> bool:
    for item in items:
        checks = {c.check: c.result for c in item.checks}
        if checks.get("sha256") == FAIL and checks.get("path") == PASS:
            return True
        if checks.get("image_path") == FAIL and checks.get("service") == PASS:
            return True
    return False


def _fails(items: Iterable[ItemResult]) -> int:
    return sum(1 for i in items if i.result == FAIL)


def evaluate(
    rule_id: str,
    evidence: Sequence[EvidenceItem],
    operations: Sequence[OperationRef],
) -> AttributionResult:
    """Veredicto de una detección con la evidencia y las operaciones del activo.

    Se evalúa contra cada operación por separado (nunca mezclando artefactos de dos): la
    actividad debe estar descrita entera por UNA operación. Si ninguna la verifica, se
    devuelve la comprobación más cercana (menos discrepancias) para explicar qué no casó.
    """
    if not operations:
        items = _items_for(None, evidence)
        verdict = _verdict(items, has_operation=False)
        explanation = [
            "No hay ninguna operación de mantenimiento aprobada y vigente para este activo"
            " que cubra el momento de la actividad."
        ]
        return AttributionResult(
            verdict, rule_id, None, items, _explain(verdict, items, explanation), False, 0
        )
    best: tuple[int, int, AttributionResult] | None = None
    for op in operations:
        items = _items_for(op, evidence)
        verdict = _verdict(items, has_operation=True)
        result = AttributionResult(
            verdict,
            rule_id,
            op,
            items,
            [],
            _tampered(items),
            len(operations),
        )
        if verdict == VERIFIED:
            result.explanation = _explain(verdict, items, [])
            return result
        rank = (_fails(items), sum(1 for i in items if i.result == MISSING))
        if best is None or rank < best[:2]:
            best = (*rank, result)
    assert best is not None  # noqa: S101 - operations no está vacío
    result = best[2]
    result.explanation = _explain(result.verdict, result.items, [])
    return result


def _explain(verdict: str, items: Sequence[ItemResult], lead: list[str]) -> list[str]:
    lines = list(lead)
    deciding = [i for i in items if not i.context_only]
    if verdict == VERIFIED:
        lines.append(
            f"Las {len(deciding)} evidencias que disparan la regla casan con la operación"
            " autorizada: hash y ruta de cada script, servicio con su ImagePath y cuenta,"
            " dentro de la ventana."
        )
    elif verdict == SUSPICIOUS:
        bad = [i for i in deciding if i.result == FAIL]
        lines.append(
            f"{len(bad)} de {len(deciding)} evidencias no casan con ninguna operación"
            " autorizada: la detección sigue activa con su severidad y requiere investigación."
        )
    elif verdict == INSUFFICIENT:
        lines.append(
            "Falta información para comprobar la actividad; la detección sigue activa con su"
            " severidad hasta que se obtenga o un analista la revise."
        )
    if _tampered(items):
        lines.append(
            "Un fichero autorizado aparece con otro contenido (hash distinto en la misma ruta)"
            " o un servicio autorizado con otro ImagePath: posible manipulación."
        )
    context = [i for i in items if i.context_only]
    if context:
        lines.append(
            f"{len(context)} proceso(s) nuevo(s) de la ventana son contexto de la correlación"
            " y no deciden el veredicto."
        )
    return lines
