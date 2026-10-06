"""Formato declarativo interno de las reglas (sentra-rule/1): validación y compilación.

Una regla es DATO, nunca código: un árbol de condiciones (all/any/not y hojas campo-operador-
valor) sobre los campos del catálogo, más umbral, ventana, agrupación y cooldown opcionales.
`compile_definition` valida ese árbol con una allowlist estricta (claves, operadores, tipos,
límites de tamaño y complejidad) y lo convierte en objetos Python inmutables que solo saben
comparar valores. No hay eval, exec, plantillas, SQL ni nombres de campo libres: un texto
"import os" o "DROP TABLE" en un valor es un literal que se compara, nada más.

Semántica (documentada en docs/custom-detection-rules.md):
- un campo ausente hace FALSA cualquier hoja salvo `exists: false` (nunca "coincide" por
  defecto); `not` invierte el resultado lógico completo de su hijo;
- las comparaciones de texto no distinguen mayúsculas salvo `case_sensitive: true`;
- una lista de valores en equals/contains/starts_with/ends_with significa "cualquiera";
  en not_equals, "ninguno".
"""

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from app.detection.custom import safe_regex
from app.detection.custom.catalog import (
    ASSET_FIELDS,
    LOGSOURCES,
    FieldSpec,
    FieldType,
    LogSource,
    Support,
    fields_for,
)

FORMAT = "sentra-rule/1"

# Límites de tamaño y complejidad (validación, no "recomendaciones"): una regla que los
# supera se rechaza. Evitan reglas patológicas que degradarían el motor para todos.
MAX_NODES = 64
MAX_DEPTH = 6
MAX_CHILDREN = 32
MAX_VALUES_PER_LEAF = 50
MAX_TOTAL_VALUES = 500
MAX_VALUE_LENGTH = 256
MAX_REGEX_PER_RULE = 4
MAX_GROUP_BY = 3
THRESHOLD_COUNT = (2, 10_000)
WINDOW_MINUTES = (1, 1440)
COOLDOWN_MINUTES = (0, 1440)

OPS_BY_TYPE: dict[FieldType, frozenset[str]] = {
    FieldType.STRING: frozenset(
        {
            "equals",
            "not_equals",
            "in",
            "contains",
            "starts_with",
            "ends_with",
            "regex",
            "exists",
        }
    ),
    FieldType.INTEGER: frozenset(
        {"equals", "not_equals", "in", "gt", "gte", "lt", "lte", "exists"}
    ),
    FieldType.BOOLEAN: frozenset({"equals", "exists"}),
}
ALL_OPS = frozenset().union(*OPS_BY_TYPE.values())
_LIST_OPS = frozenset({"equals", "not_equals", "contains", "starts_with", "ends_with"})
_TEXT_OPS = frozenset({"contains", "starts_with", "ends_with"})
_NUMERIC_OPS = frozenset({"gt", "gte", "lt", "lte"})
_LEAF_KEYS = frozenset({"field", "op", "value", "case_sensitive"})
_TOP_KEYS = frozenset(
    {"format", "logsource", "condition", "threshold", "group_by", "cooldown_minutes"}
)


@dataclass(frozen=True)
class Issue:
    code: str
    message: str
    path: str = ""

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message, "path": self.path}


class Node(Protocol):
    def match(self, record: Mapping[str, Any]) -> bool: ...


@dataclass(frozen=True, slots=True)
class AllNode:
    children: tuple[Node, ...]

    def match(self, record: Mapping[str, Any]) -> bool:
        return all(child.match(record) for child in self.children)


@dataclass(frozen=True, slots=True)
class AnyNode:
    children: tuple[Node, ...]

    def match(self, record: Mapping[str, Any]) -> bool:
        return any(child.match(record) for child in self.children)


@dataclass(frozen=True, slots=True)
class NotNode:
    child: Node

    def match(self, record: Mapping[str, Any]) -> bool:
        return not self.child.match(record)


@dataclass(frozen=True, slots=True)
class Leaf:
    """Hoja ya normalizada: los valores de texto se guardan en minúsculas si no distingue."""

    field: str
    type: FieldType
    op: str
    values: tuple[Any, ...]
    case_sensitive: bool
    pattern: Any = None

    def match(self, record: Mapping[str, Any]) -> bool:
        raw = record.get(self.field)
        if self.op == "exists":
            return (raw is not None and raw != "") is self.values[0]
        if raw is None or raw == "":
            # Campo ausente: nunca coincide (tampoco not_equals). "missing field does not
            # magically match": quien quiera ausencia usa exists: false.
            return False
        if self.type is FieldType.INTEGER:
            number = _as_int(raw)
            if number is None:
                return False
            return _compare_int(self.op, number, self.values)
        if self.type is FieldType.BOOLEAN:
            return isinstance(raw, bool) and raw is self.values[0]
        text = raw if isinstance(raw, str) else str(raw)
        if self.op == "regex":
            subject = text[: safe_regex.MAX_SUBJECT]
            return self.pattern.search(subject) is not None
        if not self.case_sensitive:
            text = text.lower()
        return _compare_text(self.op, text, self.values)


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.lstrip("-").isdigit() and len(stripped) <= 19:
            return int(stripped)
    return None


def _compare_int(op: str, number: int, values: tuple[Any, ...]) -> bool:
    if op == "equals":
        return number in values
    if op == "not_equals":
        return number not in values
    target = values[0]
    if op == "gt":
        return bool(number > target)
    if op == "gte":
        return bool(number >= target)
    if op == "lt":
        return bool(number < target)
    return bool(number <= target)


def _compare_text(op: str, text: str, values: tuple[Any, ...]) -> bool:
    if op == "equals":
        return text in values
    if op == "not_equals":
        return text not in values
    if op == "contains":
        return any(value in text for value in values)
    if op == "starts_with":
        return text.startswith(values)
    return text.endswith(values)


@dataclass
class CompileResult:
    """Resultado de validar y compilar. `rule` solo existe si no hay errores."""

    errors: list[Issue] = field(default_factory=list)
    warnings: list[Issue] = field(default_factory=list)
    normalized: dict[str, Any] | None = None
    rule: "CompiledRule | None" = None

    @property
    def ok(self) -> bool:
        return not self.errors and self.rule is not None


@dataclass(frozen=True)
class CompiledRule:
    logsource: LogSource
    condition: Node
    fields: frozenset[str]
    asset_fields: frozenset[str]
    # Campos que DEBEN existir para que la regla pueda coincidir (hojas positivas del primer
    # nivel). Fast-path del índice: si falta alguno, ni se evalúa el árbol.
    required_fields: frozenset[str]
    # Ids de evento o tipos de señal a los que el primer nivel restringe la regla (None:
    # cualquiera). Permiten indexar la regla por (tipo, canal, id) en vez de probarla siempre.
    event_codes: frozenset[int] | None
    signal_kinds: frozenset[str] | None
    threshold_count: int | None
    window_minutes: int | None
    group_by: tuple[str, ...]
    cooldown_minutes: int
    complexity: int
    leaves: int
    support: Support

    @property
    def complexity_label(self) -> str:
        if self.complexity <= 10:
            return "low"
        if self.complexity <= 30:
            return "medium"
        return "high"

    def summary(self) -> dict[str, Any]:
        return {
            "logsource": self.logsource.name,
            "fields": sorted(self.fields),
            "required_fields": sorted(self.required_fields),
            "event_codes": sorted(self.event_codes) if self.event_codes is not None else None,
            "signal_kinds": sorted(self.signal_kinds) if self.signal_kinds is not None else None,
            "threshold": self.threshold_count,
            "window_minutes": self.window_minutes,
            "group_by": list(self.group_by),
            "cooldown_minutes": self.cooldown_minutes,
            "complexity": self.complexity,
            "complexity_label": self.complexity_label,
            "leaves": self.leaves,
            "logsource_support": self.support.value,
        }


class _Compiler:
    def __init__(self, logsource: LogSource, result: CompileResult) -> None:
        self.fields: dict[str, FieldSpec] = fields_for(logsource)
        self.result = result
        self.nodes = 0
        self.values = 0
        self.regexes = 0
        self.max_depth = 0
        self.used: set[str] = set()
        self.leaf_count = 0

    def error(self, code: str, message: str, path: str) -> None:
        self.result.errors.append(Issue(code, message, path))

    def node(self, raw: Any, path: str, depth: int) -> tuple[Node | None, Any]:
        """Devuelve (nodo compilado, forma normalizada) o (None, None) si hay errores."""
        self.nodes += 1
        self.max_depth = max(self.max_depth, depth)
        if self.nodes > MAX_NODES:
            if self.nodes == MAX_NODES + 1:
                self.error("too_many_conditions", f"more than {MAX_NODES} conditions", path)
            return None, None
        if depth > MAX_DEPTH:
            self.error("too_deep", f"nesting deeper than {MAX_DEPTH} levels", path)
            return None, None
        if not isinstance(raw, dict):
            self.error("invalid_node", "a condition must be an object", path)
            return None, None
        groups = [key for key in ("all", "any", "not") if key in raw]
        if groups:
            if len(raw) != 1:
                self.error("invalid_node", "a group has exactly one key: all, any or not", path)
                return None, None
            key = groups[0]
            if key == "not":
                child, normalized = self.node(raw["not"], f"{path}.not", depth + 1)
                if child is None:
                    return None, None
                return NotNode(child), {"not": normalized}
            items = raw[key]
            if not isinstance(items, list) or not items:
                self.error("empty_group", f"'{key}' needs a non-empty list", path)
                return None, None
            if len(items) > MAX_CHILDREN:
                self.error("too_many_branches", f"more than {MAX_CHILDREN} items", path)
                return None, None
            compiled: list[Node] = []
            normalized_items: list[Any] = []
            for index, item in enumerate(items):
                child, normalized = self.node(item, f"{path}.{key}[{index}]", depth + 1)
                if child is not None:
                    compiled.append(child)
                    normalized_items.append(normalized)
            if len(compiled) != len(items):
                return None, None
            if len(compiled) == 1:
                return compiled[0], normalized_items[0]
            node: Node = AllNode(tuple(compiled)) if key == "all" else AnyNode(tuple(compiled))
            return node, {key: normalized_items}
        return self.leaf(raw, path)

    def leaf(self, raw: dict[str, Any], path: str) -> tuple[Node | None, Any]:
        unknown = set(raw) - _LEAF_KEYS
        if unknown:
            self.error(
                "unknown_key",
                f"unknown keys {sorted(str(k)[:32] for k in unknown)}; only field, op, value"
                " and case_sensitive are allowed",
                path,
            )
            return None, None
        name = raw.get("field")
        op = raw.get("op")
        if not isinstance(name, str) or name not in self.fields:
            self.error(
                "unknown_field", f"unknown field {str(name)[:80]!r} for this logsource", path
            )
            return None, None
        if not isinstance(op, str) or op not in ALL_OPS:
            self.error("unknown_operator", f"unknown operator {str(op)[:32]!r}", path)
            return None, None
        spec = self.fields[name]
        if op not in OPS_BY_TYPE[spec.type]:
            self.error("operator_type", f"operator {op} is not valid for {spec.type} fields", path)
            return None, None
        case_sensitive = raw.get("case_sensitive", False)
        if not isinstance(case_sensitive, bool):
            self.error("invalid_value", "case_sensitive must be true or false", path)
            return None, None
        if case_sensitive and spec.type is not FieldType.STRING:
            self.error("invalid_value", "case_sensitive only applies to text fields", path)
            return None, None
        values = self.values_for(spec, op, raw.get("value"), path, case_sensitive)
        if values is None:
            return None, None
        self.used.add(name)
        self.leaf_count += 1
        pattern = None
        if op == "regex":
            self.regexes += 1
            if self.regexes > MAX_REGEX_PER_RULE:
                self.error("too_many_regex", f"more than {MAX_REGEX_PER_RULE} regex", path)
                return None, None
            try:
                pattern = safe_regex.compile_safe(values[0], case_sensitive)
            except safe_regex.UnsafeRegexError as exc:
                self.error("unsafe_regex", str(exc), path)
                return None, None
        normalized_op = "equals" if op == "in" else op
        stored: tuple[Any, ...] = values
        if spec.type is FieldType.STRING and not case_sensitive and op not in ("regex", "exists"):
            stored = tuple(str(v).lower() for v in values)
        normalized: dict[str, Any] = {
            "field": name,
            "op": normalized_op,
            "value": list(values) if len(values) > 1 else values[0],
        }
        if case_sensitive:
            normalized["case_sensitive"] = True
        leaf = Leaf(name, spec.type, normalized_op, stored, case_sensitive, pattern)
        return leaf, normalized

    def values_for(
        self, spec: FieldSpec, op: str, raw: Any, path: str, case_sensitive: bool
    ) -> tuple[Any, ...] | None:
        if op == "exists":
            if not isinstance(raw, bool):
                self.error("invalid_value", "exists needs true or false", path)
                return None
            return (raw,)
        if op == "in" and not isinstance(raw, list):
            self.error("invalid_value", "in needs a list of values", path)
            return None
        items = raw if isinstance(raw, list) else [raw]
        if isinstance(raw, list) and op not in _LIST_OPS and op != "in":
            self.error("invalid_value", f"{op} needs a single value", path)
            return None
        if not items:
            self.error("invalid_value", "empty list of values", path)
            return None
        if len(items) > MAX_VALUES_PER_LEAF:
            self.error("too_many_values", f"more than {MAX_VALUES_PER_LEAF} values", path)
            return None
        self.values += len(items)
        if self.values > MAX_TOTAL_VALUES:
            self.error("too_many_values", f"more than {MAX_TOTAL_VALUES} values in the rule", path)
            return None
        out: list[Any] = []
        for item in items:
            value = self.coerce(spec, op, item, path)
            if value is None:
                return None
            if value not in out:
                out.append(value)
        if spec.values and op in ("equals", "not_equals", "in"):
            allowed = {v.lower() for v in spec.values}
            bad = [v for v in out if str(v).lower() not in allowed]
            if bad:
                self.error(
                    "unknown_value",
                    f"{spec.name} never takes the value {str(bad[0])[:64]!r}",
                    path,
                )
                return None
        return tuple(out)

    def coerce(self, spec: FieldSpec, op: str, item: Any, path: str) -> Any:
        if spec.type is FieldType.INTEGER:
            number = _as_int(item)
            if number is None or abs(number) > 2**53:
                self.error("invalid_value", f"{spec.name} needs whole numbers", path)
                return None
            return number
        if spec.type is FieldType.BOOLEAN:
            if not isinstance(item, bool):
                self.error("invalid_value", f"{spec.name} needs true or false", path)
                return None
            return item
        if isinstance(item, bool) or not isinstance(item, str | int):
            self.error("invalid_value", f"{spec.name} needs text values", path)
            return None
        text = str(item)
        if len(text) > MAX_VALUE_LENGTH:
            self.error("value_too_long", f"values longer than {MAX_VALUE_LENGTH} chars", path)
            return None
        if "\x00" in text:
            self.error("invalid_value", "values must not contain NUL characters", path)
            return None
        if not text and (op in _TEXT_OPS or op == "regex"):
            self.error("invalid_value", f"{op} needs a non-empty value", path)
            return None
        return text


def _int_in(raw: Any, bounds: tuple[int, int]) -> int | None:
    if isinstance(raw, bool) or not isinstance(raw, int):
        return None
    return raw if bounds[0] <= raw <= bounds[1] else None


def _top_level(node: Node) -> tuple[Node, ...]:
    return node.children if isinstance(node, AllNode) else (node,)


def _restriction(node: Node, field_name: str) -> frozenset[Any] | None:
    """Valores de `field_name` a los que el primer nivel de la regla la restringe."""
    for child in _top_level(node):
        if isinstance(child, Leaf) and child.field == field_name and child.op == "equals":
            return frozenset(child.values)
    return None


def compile_definition(definition: Any) -> CompileResult:
    """Valida y compila una definición. Nunca lanza por contenido del usuario."""
    result = CompileResult()
    if not isinstance(definition, dict):
        result.errors.append(Issue("invalid_definition", "the definition must be an object"))
        return result
    unknown = set(definition) - _TOP_KEYS
    if unknown:
        result.errors.append(
            Issue(
                "unknown_key",
                f"unknown keys {sorted(str(k)[:32] for k in unknown)}",
            )
        )
        return result
    fmt = definition.get("format", FORMAT)
    if fmt != FORMAT:
        result.errors.append(Issue("unknown_format", f"only {FORMAT} is supported", "format"))
        return result
    logsource = LOGSOURCES.get(str(definition.get("logsource")))
    if logsource is None:
        result.errors.append(
            Issue(
                "unknown_logsource",
                f"unknown logsource {str(definition.get('logsource'))[:40]!r}",
                "logsource",
            )
        )
        return result
    if "condition" not in definition:
        result.errors.append(Issue("missing_condition", "a condition is required", "condition"))
        return result
    compiler = _Compiler(logsource, result)
    condition, normalized_condition = compiler.node(definition["condition"], "condition", 1)

    threshold_count: int | None = None
    window: int | None = None
    raw_threshold = definition.get("threshold")
    normalized_threshold: dict[str, int] | None = None
    if raw_threshold is not None:
        if not isinstance(raw_threshold, dict) or set(raw_threshold) - {"count", "window_minutes"}:
            result.errors.append(
                Issue("invalid_threshold", "threshold has count and window_minutes", "threshold")
            )
        else:
            threshold_count = _int_in(raw_threshold.get("count"), THRESHOLD_COUNT)
            window = _int_in(raw_threshold.get("window_minutes"), WINDOW_MINUTES)
            if threshold_count is None:
                result.errors.append(
                    Issue(
                        "invalid_threshold",
                        f"count must be between {THRESHOLD_COUNT[0]} and {THRESHOLD_COUNT[1]}",
                        "threshold.count",
                    )
                )
            if window is None:
                result.errors.append(
                    Issue(
                        "invalid_window",
                        f"window_minutes must be between {WINDOW_MINUTES[0]} and"
                        f" {WINDOW_MINUTES[1]}",
                        "threshold.window_minutes",
                    )
                )
            if threshold_count is not None and window is not None:
                normalized_threshold = {"count": threshold_count, "window_minutes": window}

    group_by: list[str] = []
    raw_group = definition.get("group_by") or []
    fields = fields_for(logsource)
    if not isinstance(raw_group, list) or len(raw_group) > MAX_GROUP_BY:
        result.errors.append(
            Issue("invalid_group_by", f"group_by is a list of up to {MAX_GROUP_BY} fields")
        )
    else:
        for index, name in enumerate(raw_group):
            spec = fields.get(name) if isinstance(name, str) else None
            if spec is None:
                result.errors.append(
                    Issue(
                        "unknown_field", f"unknown field {str(name)[:80]!r}", f"group_by[{index}]"
                    )
                )
            elif spec.is_asset:
                result.errors.append(
                    Issue(
                        "invalid_group_by",
                        "rules are always evaluated per asset; group by event fields",
                        f"group_by[{index}]",
                    )
                )
            elif name in group_by:
                result.errors.append(
                    Issue("invalid_group_by", "duplicated field", f"group_by[{index}]")
                )
            else:
                group_by.append(name)

    raw_cooldown = definition.get("cooldown_minutes")
    if raw_cooldown is None:
        # Por defecto, como AUTH-001: una oleada dura lo que su ventana; sin umbral, cada
        # coincidencia nueva cuenta como ocurrencia (igual que las built-in simples).
        cooldown = window or 0
    else:
        parsed = _int_in(raw_cooldown, COOLDOWN_MINUTES)
        if parsed is None:
            result.errors.append(
                Issue(
                    "invalid_cooldown",
                    f"cooldown_minutes must be between {COOLDOWN_MINUTES[0]} and"
                    f" {COOLDOWN_MINUTES[1]}",
                    "cooldown_minutes",
                )
            )
            cooldown = 0
        else:
            cooldown = parsed

    if condition is not None and not (compiler.used - set(ASSET_FIELDS)):
        result.errors.append(
            Issue(
                "asset_context_only",
                "a rule needs at least one condition on event or signal data: asset context"
                " alone is not evidence of compromise",
                "condition",
            )
        )
    if result.errors or condition is None:
        return result

    if logsource.support is Support.PARTIAL:
        result.warnings.append(Issue("partial_logsource", logsource.notes, "logsource"))

    required = frozenset(
        child.field
        for child in _top_level(condition)
        if isinstance(child, Leaf) and not (child.op == "exists" and child.values[0] is False)
    )
    codes = _restriction(condition, "event.code") if logsource.is_event else None
    kinds = _restriction(condition, "signal.kind") if not logsource.is_event else None
    used = frozenset(compiler.used | set(group_by))
    asset_used = frozenset(name for name in used if fields[name].is_asset)
    complexity = (
        compiler.leaf_count
        + compiler.values // 5
        + 4 * compiler.regexes
        + 2 * (compiler.max_depth - 1)
        + (3 if threshold_count else 0)
        + len(group_by)
    )
    normalized: dict[str, Any] = {
        "format": FORMAT,
        "logsource": logsource.name,
        "condition": normalized_condition,
        "threshold": normalized_threshold,
        "group_by": group_by,
        "cooldown_minutes": cooldown,
    }
    result.normalized = normalized
    result.rule = CompiledRule(
        logsource=logsource,
        condition=condition,
        fields=used,
        asset_fields=asset_used,
        required_fields=required,
        event_codes=frozenset(int(v) for v in codes) if codes is not None else None,
        signal_kinds=frozenset(str(v) for v in kinds) if kinds is not None else None,
        threshold_count=threshold_count,
        window_minutes=window,
        group_by=tuple(group_by),
        cooldown_minutes=cooldown,
        complexity=complexity,
        leaves=compiler.leaf_count,
        support=logsource.support,
    )
    return result


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def content_hash(payload: Mapping[str, Any]) -> str:
    """Hash estable del contenido funcional de una versión (definición + metadatos)."""
    return hashlib.sha256(canonical_json(dict(payload)).encode()).hexdigest()
