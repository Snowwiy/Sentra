"""Importación Sigma: parser YAML seguro, validador y compilador al formato interno (Fase 5A).

Pipeline (sin tocar la base de datos ni la API):

    YAML -> parse_yaml (seguro y acotado) -> analyze (metadatos, logsource, campos,
    modificadores, condición) -> definición sentra-rule/1 -> compile_definition

Sentra NO soporta Sigma completo. Compila el subconjunto que puede evaluar con datos que
realmente recoge y marca todo lo demás como unsupported con el motivo: campos que el agente
no envía (CommandLine, ScriptBlockText...), logsources sin datos (Sysmon, file_event...),
comodines internos, modificadores no implementados, agregaciones distintas de count() o
reglas de correlación. Nunca adivina: una construcción desconocida no se "aproxima".

Seguridad: todo el contenido del YAML es dato no confiable. No se usan tags de Python, no se
deserializan objetos, no se expanden alias (evita "billion laughs"), hay límites de tamaño,
profundidad, número de nodos, selecciones y valores, la condición se interpreta con un
parser propio (nunca eval) y las referencias son texto: nunca se abren.
"""

import fnmatch
import re
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any

import yaml

from app.detection import text
from app.detection.custom import mitre as mitre_tags
from app.detection.custom import safe_regex
from app.detection.custom.catalog import (
    AGENT_DATA_FIELDS,
    DEFAULT_CATEGORY,
    LOGSOURCES,
    Support,
)
from app.detection.custom.definition import (
    FORMAT,
    CompiledRule,
    Issue,
    compile_definition,
)
from app.models.detection import DetectionSeverity

MAX_YAML_BYTES = 64 * 1024
MAX_YAML_DEPTH = 12
MAX_YAML_NODES = 4000
MAX_SELECTIONS = 32
MAX_CONDITION_LENGTH = 1000
MAX_CONDITION_TOKENS = 200

LEVELS: dict[str, DetectionSeverity] = {
    "informational": DetectionSeverity.INFORMATIONAL,
    "low": DetectionSeverity.LOW,
    "medium": DetectionSeverity.MEDIUM,
    "high": DetectionSeverity.HIGH,
    "critical": DetectionSeverity.CRITICAL,
}

# Campos Sigma conocidos que Sentra todavía no recoge: el motivo aparece en la vista previa.
_NOT_COLLECTED = {
    "commandline": "Sentra todavía no recoge la línea de comandos de los procesos",
    "parentimage": "Sentra no recoge el proceso padre por ruta",
    "parentcommandline": "Sentra todavía no recoge la línea de comandos de los procesos",
    "originalfilename": "Sentra no recoge metadatos PE (OriginalFileName)",
    "hashes": "Sentra no recoge hashes de ejecutables",
    "scriptblocktext": (
        "El agente no envía el contenido de los scripts de PowerShell (puede contener credenciales)"
    ),
    "integritylevel": "Sentra no recoge el nivel de integridad de los procesos",
    "currentdirectory": "Sentra no recoge el directorio de trabajo de los procesos",
}

_EVENT_COMMON = {
    "eventid": "event.code",
    "provider_name": "event.provider",
    "channel": "event.channel",
    "computer": "event.computer",
}
_PROCESS_FIELDS = {
    "image": "process.path",
    "user": "process.user",
    "processid": "process.pid",
    "parentprocessid": "process.ppid",
}
_SUPPORTED_MODIFIERS = frozenset(
    {"contains", "startswith", "endswith", "all", "cased", "re", "i", "exists"}
    | {"gt", "gte", "lt", "lte"}
)


class SigmaError(ValueError):
    """YAML que no se puede tratar como Sigma (malformado, peligroso o demasiado grande)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class _UnsupportedError(Exception):
    def __init__(self, code: str, message: str, path: str = "") -> None:
        super().__init__(message)
        self.issue = Issue(code, message, path)


# --- YAML seguro -----------------------------------------------------------------------------


_STANDARD_TAGS = frozenset(
    f"tag:yaml.org,2002:{name}"
    for name in ("str", "int", "float", "bool", "null", "map", "seq", "timestamp")
)


class _SafeLoader(yaml.SafeLoader):
    """SafeLoader sin alias ni tags no estándar y con límites de profundidad y tamaño."""

    def __init__(self, stream: str) -> None:
        super().__init__(stream)
        self._depth = 0
        self._nodes = 0

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            raise SigmaError("yaml_alias", "YAML aliases/anchors are not allowed")
        event = self.peek_event()  # type: ignore[no-untyped-call]
        anchor = getattr(event, "anchor", None)
        if anchor is not None:
            raise SigmaError("yaml_alias", "YAML aliases/anchors are not allowed")
        tag = getattr(event, "tag", None)
        if tag not in (None, "!") and tag not in _STANDARD_TAGS:
            # Incluye !!python/object y cualquier tag propio: nunca se construyen objetos.
            raise SigmaError("yaml_tag", "custom YAML tags are not allowed")
        self._nodes += 1
        if self._nodes > MAX_YAML_NODES:
            raise SigmaError("yaml_too_large", f"more than {MAX_YAML_NODES} YAML nodes")
        self._depth += 1
        if self._depth > MAX_YAML_DEPTH:
            raise SigmaError("yaml_too_deep", f"YAML nested deeper than {MAX_YAML_DEPTH}")
        try:
            return super().compose_node(parent, index)
        finally:
            self._depth -= 1


def _construct_timestamp(loader: yaml.SafeLoader, node: yaml.Node) -> str:
    # Fechas como texto: Sigma usa "2023-01-01" y no queremos objetos date en JSONB.
    return str(loader.construct_scalar(node))  # type: ignore[arg-type]


_SafeLoader.add_constructor("tag:yaml.org,2002:timestamp", _construct_timestamp)


def parse_yaml(source: str) -> dict[str, Any]:
    if len(source.encode("utf-8", errors="replace")) > MAX_YAML_BYTES:
        raise SigmaError("yaml_too_large", f"Sigma YAML larger than {MAX_YAML_BYTES} bytes")
    if "\x00" in source:
        raise SigmaError("yaml_invalid", "YAML must not contain NUL characters")
    loader = _SafeLoader(source)
    try:
        if not loader.check_data():  # type: ignore[no-untyped-call]
            raise SigmaError("yaml_empty", "empty YAML document")
        data = loader.get_data()
        if loader.check_data():  # type: ignore[no-untyped-call]
            raise SigmaError(
                "sigma_multi_document",
                "multi-document Sigma (rule collections, action: global) is not supported",
            )
    except SigmaError:
        raise
    except yaml.YAMLError as exc:
        # Solo la línea: el mensaje de PyYAML puede citar trozos del documento.
        mark = getattr(exc, "problem_mark", None)
        where = f" (line {mark.line + 1})" if mark is not None else ""
        raise SigmaError("yaml_invalid", f"invalid YAML{where}") from None
    finally:
        loader.dispose()
    if not isinstance(data, dict):
        raise SigmaError("sigma_invalid", "a Sigma rule is a YAML mapping")
    return data


# --- Análisis --------------------------------------------------------------------------------


@dataclass
class SigmaAnalysis:
    """Lo que ocurrirá al importar: metadatos, compatibilidad y regla compilada."""

    outcome: str  # supported | partial | unsupported | invalid
    title: str = ""
    sigma_id: uuid.UUID | None = None
    level: str | None = None
    severity: DetectionSeverity = DetectionSeverity.MEDIUM
    logsource: dict[str, str] = field(default_factory=dict)
    sentra_logsource: str | None = None
    mitre: mitre_tags.MitreMapping | None = None
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    errors: list[Issue] = field(default_factory=list)
    unsupported: list[Issue] = field(default_factory=list)
    warnings: list[Issue] = field(default_factory=list)
    definition: dict[str, Any] | None = None
    compiled: CompiledRule | None = None
    description: str = ""
    category: str = "system"


def _str(value: Any, limit: int) -> str:
    if value is None:
        return ""
    if isinstance(value, date | datetime):
        value = value.isoformat()
    return text.clean(value, limit) if isinstance(value, str | int | float) else ""


def _str_list(value: Any, limit: int, item_limit: int) -> list[str]:
    items = value if isinstance(value, list) else ([value] if value is not None else [])
    out = []
    for item in items[:limit]:
        cleaned = _str(item, item_limit)
        if cleaned:
            out.append(cleaned)
    return out


def _metadata(doc: dict[str, Any]) -> dict[str, Any]:
    """Metadatos Sigma como DATOS acotados. Nunca se usan como evidencia ni se abren URLs."""
    raw_logsource = doc.get("logsource")
    logsource: dict[str, Any] = raw_logsource if isinstance(raw_logsource, dict) else {}
    return {
        "title": _str(doc.get("title"), 200),
        "id": _str(doc.get("id"), 64),
        "status": _str(doc.get("status"), 32),
        "description": _str(doc.get("description"), 2000),
        "author": _str(doc.get("author"), 300),
        "date": _str(doc.get("date"), 32),
        "modified": _str(doc.get("modified"), 32),
        "references": _str_list(doc.get("references"), 20, 300),
        "tags": _str_list(doc.get("tags"), 30, 64),
        "level": _str(doc.get("level"), 32),
        "falsepositives": _str_list(doc.get("falsepositives"), 10, 300),
        "logsource": {
            key: _str(logsource.get(key), 64)
            for key in ("product", "service", "category", "definition")
            if logsource.get(key) is not None
        },
    }


def _map_logsource(logsource: dict[str, str]) -> tuple[str, str] | None:
    """(logsource Sentra, motivo de parcialidad) o None si Sentra no tiene esos datos."""
    product = logsource.get("product", "").lower()
    service = logsource.get("service", "").lower()
    category = logsource.get("category", "").lower()
    if product == "windows" and not category:
        mapping = {
            "security": "windows_security",
            "system": "windows_system",
            "application": "windows_application",
            "powershell": "powershell",
            "windefend": "windows_defender",
        }
        if service in mapping:
            return mapping[service], ""
        return None
    if category == "process_creation" and product in ("windows", "linux") and not service:
        return (
            "process",
            "Sentra no ve cada creación de proceso: solo ejecutables nuevos en los snapshots"
            " periódicos del agente. Una regla sobre un ejecutable habitual solo coincidirá la"
            " primera vez que aparezca en el activo.",
        )
    return None


def _field_map(sentra_logsource: str) -> dict[str, str]:
    source = LOGSOURCES[sentra_logsource]
    if source.is_event:
        mapping = dict(_EVENT_COMMON)
        assert source.channel is not None  # noqa: S101  (es un logsource de evento)
        for name in AGENT_DATA_FIELDS.get(source.channel, ()):
            mapping[name.lower()] = f"event.data.{name}"
        if "event.message" not in source.fields:
            mapping.pop("message", None)
        return mapping
    if sentra_logsource == "process":
        return dict(_PROCESS_FIELDS)
    return {}


def _unescape(value: str) -> tuple[str, bool, bool, bool]:
    """Valor Sigma -> (literal, empieza por *, acaba en *, tiene comodines internos).

    En Sigma `*` y `?` son comodines y `\\*`, `\\?`, `\\\\` sus escapes; cualquier otra barra
    es literal (rutas de Windows).
    """
    out: list[str] = []
    wildcards: list[int] = []
    i = 0
    while i < len(value):
        char = value[i]
        if char == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(value[i + 1])
            i += 2
            continue
        if char in "*?":
            wildcards.append(len(out))
            out.append(char)
            i += 1
            continue
        out.append(char)
        i += 1
    literal = "".join(out)
    leading = bool(wildcards) and wildcards[0] == 0 and literal[:1] == "*"
    trailing = bool(wildcards) and wildcards[-1] == len(out) - 1 and literal[-1:] == "*"
    inner = [
        pos
        for pos in wildcards
        if not ((pos == 0 and leading) or (pos == len(out) - 1 and trailing))
    ]
    start = 1 if leading else 0
    end = len(literal) - 1 if trailing else len(literal)
    return literal[start:end], leading, trailing, bool(inner)


class _Analyzer:
    def __init__(self, analysis: SigmaAnalysis, sentra_logsource: str) -> None:
        self.analysis = analysis
        self.fields = _field_map(sentra_logsource)
        self.values = 0

    def selection(self, name: str, raw: Any) -> dict[str, Any]:
        path = f"detection.{name}"
        if isinstance(raw, dict):
            return self.mapping(raw, path)
        if isinstance(raw, list):
            if raw and all(isinstance(item, dict) for item in raw):
                nodes = [self.mapping(item, f"{path}[{i}]") for i, item in enumerate(raw)]
                return nodes[0] if len(nodes) == 1 else {"any": nodes}
            if raw and all(not isinstance(item, dict | list) for item in raw):
                raise _UnsupportedError(
                    "sigma_keywords",
                    "keyword searches (lists of plain values) are not supported",
                    path,
                )
        raise _UnsupportedError("sigma_selection", "unsupported selection structure", path)

    def mapping(self, raw: dict[str, Any], path: str) -> dict[str, Any]:
        if not raw:
            raise _UnsupportedError("sigma_selection", "empty selection", path)
        nodes = [self.field(str(key), value, f"{path}.{key}") for key, value in raw.items()]
        return nodes[0] if len(nodes) == 1 else {"all": nodes}

    def field(self, key: str, value: Any, path: str) -> dict[str, Any]:
        parts = key.split("|")
        name, modifiers = parts[0], [m.lower() for m in parts[1:]]
        lowered = name.lower()
        for modifier in modifiers:
            if modifier not in _SUPPORTED_MODIFIERS:
                raise _UnsupportedError(
                    "sigma_modifier", f"modifier '{modifier[:32]}' is not supported", path
                )
        if "i" in modifiers and "re" not in modifiers:
            raise _UnsupportedError("sigma_modifier", "modifier 'i' only applies to 're'", path)
        target = self.fields.get(lowered)
        if target is None:
            reason = _NOT_COLLECTED.get(lowered)
            message = (
                f"field '{name[:64]}': {reason}"
                if reason
                else f"field '{name[:64]}' is not available for this logsource in Sentra"
            )
            raise _UnsupportedError("sigma_field", message, path)
        values = value if isinstance(value, list) else [value]
        if not values:
            raise _UnsupportedError("sigma_value", "empty list of values", path)
        self.values += len(values)
        case_sensitive = "cased" in modifiers
        if "exists" in modifiers:
            if len(values) != 1 or not isinstance(values[0], bool):
                raise _UnsupportedError("sigma_value", "exists needs true or false", path)
            return {"field": target, "op": "exists", "value": values[0]}
        numeric = [m for m in modifiers if m in ("gt", "gte", "lt", "lte")]
        if numeric:
            if len(values) != 1 or len(numeric) != 1:
                raise _UnsupportedError("sigma_value", "numeric comparison needs one value", path)
            return {"field": target, "op": numeric[0], "value": values[0]}
        if "re" in modifiers:
            if len(values) != 1 or not isinstance(values[0], str):
                raise _UnsupportedError("sigma_value", "re needs one text value", path)
            try:
                safe_regex.check(values[0])
            except safe_regex.UnsafeRegexError as exc:
                raise _UnsupportedError(
                    "sigma_regex", f"regex not supported: {exc}", path
                ) from None
            leaf: dict[str, Any] = {"field": target, "op": "regex", "value": values[0]}
            # En Sigma, `re` distingue mayúsculas salvo con el submodificador `i`.
            if "i" not in modifiers:
                leaf["case_sensitive"] = True
            return leaf
        explicit = next((m for m in modifiers if m in ("contains", "startswith", "endswith")), None)
        leaves: list[dict[str, Any]] = []
        for item in values:
            leaves.append(self.value_leaf(target, item, explicit, case_sensitive, path))
        if "all" in modifiers:
            return leaves[0] if len(leaves) == 1 else {"all": leaves}
        # Mismo operador para todos los valores: una hoja con lista ("cualquiera").
        ops = {(leaf["op"], bool(leaf.get("case_sensitive"))) for leaf in leaves}
        if len(ops) == 1 and leaves[0]["op"] != "exists":
            merged: dict[str, Any] = {
                "field": target,
                "op": leaves[0]["op"],
                "value": [leaf["value"] for leaf in leaves]
                if len(leaves) > 1
                else leaves[0]["value"],
            }
            if case_sensitive:
                merged["case_sensitive"] = True
            return merged
        return leaves[0] if len(leaves) == 1 else {"any": leaves}

    def value_leaf(
        self, target: str, item: Any, explicit: str | None, case_sensitive: bool, path: str
    ) -> dict[str, Any]:
        if item is None:
            if explicit:
                raise _UnsupportedError("sigma_value", "null value with a text modifier", path)
            return {"field": target, "op": "exists", "value": False}
        if isinstance(item, bool | float):
            raise _UnsupportedError(
                "sigma_value", "boolean and decimal values are not supported", path
            )
        if isinstance(item, int):
            if explicit:
                item = str(item)
            else:
                return {"field": target, "op": "equals", "value": item}
        if not isinstance(item, str):
            raise _UnsupportedError("sigma_value", "unsupported value type", path)
        literal, leading, trailing, inner = _unescape(item)
        if inner:
            raise _UnsupportedError(
                "sigma_wildcard",
                "wildcards (* or ?) in the middle of a value are not supported",
                path,
            )
        if explicit and (leading or trailing):
            raise _UnsupportedError(
                "sigma_wildcard", "wildcards combined with contains/startswith/endswith", path
            )
        if not literal:
            if leading or trailing:
                # "*" sola: cualquier valor no vacío.
                return {"field": target, "op": "exists", "value": True}
            self.analysis.warnings.append(
                Issue(
                    "sigma_empty_value",
                    "empty value interpreted as 'field missing or empty'",
                    path,
                )
            )
            return {"field": target, "op": "exists", "value": False}
        if explicit == "contains" or (leading and trailing):
            op = "contains"
        elif explicit == "startswith" or trailing:
            op = "starts_with"
        elif explicit == "endswith" or leading:
            op = "ends_with"
        else:
            op = "equals"
        leaf: dict[str, Any] = {"field": target, "op": op, "value": literal}
        if case_sensitive:
            leaf["case_sensitive"] = True
        return leaf


# --- Condición -------------------------------------------------------------------------------

_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*.\-]+)")
_AGGREGATION = re.compile(
    r"^count\(\s*\)\s*(?:by\s+([A-Za-z0-9_.\-]+)\s*)?(>=|>)\s*(\d{1,6})$", re.IGNORECASE
)
_TIMEFRAME = re.compile(r"^(\d{1,5})([smhd])$")


class _ConditionParser:
    """Parser recursivo propio (nunca eval): not > and > or, paréntesis y "N of"."""

    def __init__(self, condition: str, selections: dict[str, dict[str, Any]]) -> None:
        if len(condition) > MAX_CONDITION_LENGTH:
            raise _UnsupportedError("sigma_condition", "condition too long", "detection.condition")
        tokens: list[str] = []
        position = 0
        while position < len(condition):
            if condition[position:].strip() == "":
                break
            match = _TOKEN.match(condition, position)
            if match is None:
                raise _UnsupportedError(
                    "sigma_condition",
                    f"unsupported syntax in condition near {condition[position : position + 20]!r}",
                    "detection.condition",
                )
            tokens.append(match.group(1))
            position = match.end()
        if len(tokens) > MAX_CONDITION_TOKENS:
            raise _UnsupportedError(
                "sigma_condition", "condition too complex", "detection.condition"
            )
        self.tokens = tokens
        self.position = 0
        self.selections = selections
        self.depth = 0

    def parse(self) -> dict[str, Any]:
        if not self.tokens:
            raise _UnsupportedError("sigma_condition", "empty condition", "detection.condition")
        node = self.or_expr()
        if self.position != len(self.tokens):
            raise _UnsupportedError(
                "sigma_condition",
                f"unexpected token {self.tokens[self.position][:32]!r} in condition",
                "detection.condition",
            )
        return node

    def peek(self) -> str | None:
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def take(self) -> str:
        token = self.peek()
        if token is None:
            raise _UnsupportedError(
                "sigma_condition", "condition ends unexpectedly", "detection.condition"
            )
        self.position += 1
        return token

    def or_expr(self) -> dict[str, Any]:
        items = [self.and_expr()]
        while (self.peek() or "").lower() == "or":
            self.take()
            items.append(self.and_expr())
        return items[0] if len(items) == 1 else {"any": items}

    def and_expr(self) -> dict[str, Any]:
        items = [self.not_expr()]
        while (self.peek() or "").lower() == "and":
            self.take()
            items.append(self.not_expr())
        return items[0] if len(items) == 1 else {"all": items}

    def not_expr(self) -> dict[str, Any]:
        if (self.peek() or "").lower() == "not":
            self.take()
            return {"not": self.not_expr()}
        return self.primary()

    def primary(self) -> dict[str, Any]:
        word = self.take()
        lowered = word.lower()
        if word == "(":
            self.depth += 1
            if self.depth > 6:
                raise _UnsupportedError("sigma_condition", "too many nested parentheses")
            node = self.or_expr()
            if self.take() != ")":
                raise _UnsupportedError("sigma_condition", "unbalanced parentheses")
            self.depth -= 1
            return node
        if lowered in ("1", "all", "any") and (self.peek() or "").lower() == "of":
            self.take()
            target = self.take()
            names = self.matching(target)
            nodes = [self.selections[name] for name in names]
            if len(nodes) == 1:
                return nodes[0]
            return {"all": nodes} if lowered == "all" else {"any": nodes}
        if lowered in ("and", "or", "not", "of", ")"):
            raise _UnsupportedError("sigma_condition", f"unexpected {word!r} in condition")
        if word not in self.selections:
            raise _UnsupportedError(
                "sigma_condition", f"condition references unknown selection {word[:64]!r}"
            )
        return self.selections[word]

    def matching(self, pattern: str) -> list[str]:
        if pattern.lower() == "them":
            names = [name for name in self.selections if not name.startswith("_")]
        else:
            names = [name for name in self.selections if fnmatch.fnmatchcase(name, pattern)]
        if not names:
            raise _UnsupportedError(
                "sigma_condition", f"'{pattern[:64]}' does not match any selection"
            )
        return sorted(names)


def _timeframe_minutes(raw: Any) -> int:
    match = _TIMEFRAME.match(str(raw).strip()) if raw is not None else None
    if match is None:
        raise _UnsupportedError("sigma_timeframe", "timeframe must look like 5m, 1h or 1d")
    amount, unit = int(match.group(1)), match.group(2)
    seconds = amount * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    if seconds % 60:
        raise _UnsupportedError(
            "sigma_timeframe", "timeframes below whole minutes are not supported"
        )
    minutes = seconds // 60
    if not 1 <= minutes <= 1440:
        raise _UnsupportedError(
            "sigma_timeframe", "timeframe must be between 1 minute and 24 hours"
        )
    return minutes


def analyze(source: str) -> SigmaAnalysis:
    """Analiza un YAML Sigma sin efectos: la base de la vista previa y de la importación."""
    analysis = SigmaAnalysis(outcome="invalid")
    try:
        doc = parse_yaml(source)
    except SigmaError as exc:
        analysis.errors.append(Issue(exc.code, str(exc)))
        return analysis
    metadata = _metadata(doc)
    analysis.metadata = metadata
    analysis.title = metadata["title"]
    analysis.description = metadata["description"]
    analysis.logsource = metadata["logsource"]
    tags = mitre_tags.from_sigma_tags(metadata["tags"])
    analysis.mitre = tags.mapping
    analysis.tags = tags.other
    if tags.extra_techniques:
        analysis.warnings.append(
            Issue(
                "sigma_mitre_multiple",
                "only the first ATT&CK technique is mapped; others stay as tags: "
                + ", ".join(tags.extra_techniques[:5]),
                "tags",
            )
        )
        analysis.tags += [f"attack.{t.lower()}" for t in tags.extra_techniques]

    if not analysis.title:
        analysis.errors.append(Issue("sigma_title", "Sigma rules need a title", "title"))
    raw_id = doc.get("id")
    if raw_id is not None:
        try:
            analysis.sigma_id = uuid.UUID(str(raw_id))
        except ValueError:
            analysis.warnings.append(
                Issue("sigma_id", "the Sigma id is not a valid UUID and is ignored", "id")
            )
    level = metadata["level"].lower()
    analysis.level = level or None
    if not level:
        analysis.warnings.append(Issue("sigma_level", "no level: medium is used", "level"))
    elif level in LEVELS:
        analysis.severity = LEVELS[level]
    else:
        analysis.errors.append(Issue("sigma_level", f"unknown level {level[:32]!r}", "level"))
    if metadata["status"].lower() in ("deprecated", "unsupported"):
        analysis.warnings.append(
            Issue("sigma_status", f"the rule is marked {metadata['status']} upstream", "status")
        )
    if "correlation" in doc or str(doc.get("type", "")).lower() == "correlation":
        analysis.unsupported.append(
            Issue("sigma_correlation", "Sigma correlation rules are not supported")
        )
    detection = doc.get("detection")
    if not isinstance(doc.get("logsource"), dict):
        analysis.errors.append(Issue("sigma_logsource", "logsource is required", "logsource"))
    if not isinstance(detection, dict) or "condition" not in detection:
        analysis.errors.append(
            Issue("sigma_detection", "detection with a condition is required", "detection")
        )
    if analysis.errors:
        return analysis
    if analysis.unsupported:
        analysis.outcome = "unsupported"
        return analysis
    assert isinstance(detection, dict)  # noqa: S101  (comprobado arriba)

    mapped = _map_logsource(analysis.logsource)
    if mapped is None:
        described = ", ".join(f"{k}: {v}" for k, v in analysis.logsource.items()) or "(vacío)"
        analysis.unsupported.append(
            Issue(
                "sigma_logsource",
                f"Sentra has no data for logsource {described}",
                "logsource",
            )
        )
        analysis.outcome = "unsupported"
        return analysis
    sentra_logsource, partial_reason = mapped
    analysis.sentra_logsource = sentra_logsource
    analysis.category = DEFAULT_CATEGORY.get(sentra_logsource, "system")
    if partial_reason:
        analysis.warnings.append(Issue("sigma_partial", partial_reason, "logsource"))

    try:
        definition = _definition(detection, sentra_logsource, analysis)
    except _UnsupportedError as exc:
        analysis.unsupported.append(exc.issue)
        analysis.outcome = "unsupported"
        return analysis
    result = compile_definition(definition)
    if not result.ok or result.rule is None:
        # La traducción produjo algo fuera de los límites del formato interno (demasiados
        # valores, regex...): no se adivina una versión reducida.
        analysis.unsupported.extend(result.errors)
        analysis.outcome = "unsupported"
        return analysis
    analysis.definition = result.normalized
    analysis.compiled = result.rule
    analysis.warnings.extend(w for w in result.warnings if w.code != "partial_logsource")
    partial = partial_reason or LOGSOURCES[sentra_logsource].support is Support.PARTIAL
    if LOGSOURCES[sentra_logsource].support is Support.PARTIAL and not partial_reason:
        analysis.warnings.append(
            Issue("sigma_partial", LOGSOURCES[sentra_logsource].notes, "logsource")
        )
    analysis.outcome = "partial" if partial else "supported"
    return analysis


def _definition(
    detection: dict[str, Any], sentra_logsource: str, analysis: SigmaAnalysis
) -> dict[str, Any]:
    names = [name for name in detection if name not in ("condition", "timeframe")]
    if len(names) > MAX_SELECTIONS:
        raise _UnsupportedError("sigma_selection", f"more than {MAX_SELECTIONS} selections")
    analyzer = _Analyzer(analysis, sentra_logsource)
    selections = {str(name): analyzer.selection(str(name), detection[name]) for name in names}

    raw_condition = detection.get("condition")
    conditions = raw_condition if isinstance(raw_condition, list) else [raw_condition]
    if not conditions or not all(isinstance(c, str) for c in conditions):
        raise _UnsupportedError("sigma_condition", "condition must be text", "detection.condition")
    threshold: dict[str, int] | None = None
    group_by: list[str] = []
    nodes: list[dict[str, Any]] = []
    for condition in conditions:
        expression, _, aggregation = str(condition).partition("|")
        if aggregation.strip():
            if len(conditions) > 1:
                raise _UnsupportedError("sigma_aggregation", "aggregations in several conditions")
            match = _AGGREGATION.match(aggregation.strip())
            if match is None:
                raise _UnsupportedError(
                    "sigma_aggregation",
                    "only 'count() [by field] > N' or '>= N' aggregations are supported",
                    "detection.condition",
                )
            if "timeframe" not in detection:
                raise _UnsupportedError(
                    "sigma_aggregation", "count() without timeframe is not supported"
                )
            window = _timeframe_minutes(detection.get("timeframe"))
            count = int(match.group(3)) + (1 if match.group(2) == ">" else 0)
            if match.group(1):
                target = _field_map(sentra_logsource).get(match.group(1).lower())
                if target is None:
                    raise _UnsupportedError(
                        "sigma_field",
                        f"aggregation field '{match.group(1)[:64]}' is not available in Sentra",
                    )
                group_by = [target]
            if count >= 2:
                threshold = {"count": count, "window_minutes": window}
            elif count < 1:
                raise _UnsupportedError("sigma_aggregation", "count() thresholds below 1")
        nodes.append(_ConditionParser(expression.strip(), selections).parse())
    if "timeframe" in detection and threshold is None:
        analysis.warnings.append(
            Issue("sigma_timeframe", "timeframe without aggregation has no effect", "timeframe")
        )
    condition = nodes[0] if len(nodes) == 1 else {"any": nodes}
    return {
        "format": FORMAT,
        "logsource": sentra_logsource,
        "condition": condition,
        "threshold": threshold,
        "group_by": group_by,
    }
