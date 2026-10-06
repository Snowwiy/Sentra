// Utilidades de reglas de detección (Fase 5A): etiquetas y conversión entre el editor
// estructurado y el formato declarativo sentra-rule/1. Nada de aquí ejecuta contenido de la
// regla: el backend valida y compila; la UI solo construye datos.
import type {
  CompileStatus,
  RuleDefinition,
  RuleField,
  RuleLeaf,
  RuleNode,
  RuleOperator,
  RuleScalar,
  RuleSource,
  RuleStatus,
  SyntheticEventInput,
} from "../api/types";

export const SOURCE_LABELS: Record<RuleSource, string> = {
  builtin: "Built-in",
  custom: "Personalizada",
  sigma: "Sigma",
};

export const RULE_STATUS_LABELS: Record<RuleStatus, string> = {
  draft: "Borrador",
  active: "Activa",
  disabled: "Desactivada",
  retired: "Retirada",
};

export const COMPILE_LABELS: Record<CompileStatus, string> = {
  valid: "Válida",
  partial: "Parcial",
  unsupported: "No soportada",
  invalid: "Inválida",
};

export const OPERATOR_LABELS: Record<RuleOperator, string> = {
  equals: "es igual a",
  not_equals: "es distinto de",
  contains: "contiene",
  starts_with: "empieza por",
  ends_with: "termina en",
  in: "es uno de",
  regex: "regex segura",
  exists: "existe",
  gt: "mayor que",
  gte: "mayor o igual que",
  lt: "menor que",
  lte: "menor o igual que",
};

export const SIGMA_RESULT_LABELS: Record<string, string> = {
  imported: "Importada",
  imported_with_warnings: "Importada con avisos",
  updated: "Actualizada (versión nueva)",
  unchanged: "Sin cambios (ya importada)",
  unsupported: "No soportada (guardada como borrador)",
  rejected: "Rechazada",
};

export const SIGMA_OUTCOME_LABELS: Record<string, string> = {
  supported: "Soportada",
  partial: "Soporte parcial",
  unsupported: "No soportada",
  invalid: "Inválida",
};

export function compileTone(status: CompileStatus): string {
  if (status === "valid") return "badge--ok";
  if (status === "partial") return "badge--warn";
  return "badge--crit";
}

export function statusTone(status: RuleStatus): string {
  if (status === "active") return "badge--ok";
  if (status === "retired") return "badge--crit";
  return "";
}

// --- Editor estructurado --------------------------------------------------------------------

export interface ConditionRow {
  id: number;
  field: string;
  op: RuleOperator;
  /** Texto del usuario; en "es uno de" una lista separada por comas. */
  value: string;
  caseSensitive: boolean;
  negate: boolean;
}

export interface EditorState {
  logsource: string;
  /** all = todas las condiciones (Y), any = cualquiera (O). */
  mode: "all" | "any";
  rows: ConditionRow[];
  thresholdEnabled: boolean;
  thresholdCount: number;
  windowMinutes: number;
  groupBy: string[];
  cooldownMinutes: string;
}

let nextRowId = 1;

export function newRow(field = "", op: RuleOperator = "equals"): ConditionRow {
  return { id: nextRowId++, field, op, value: "", caseSensitive: false, negate: false };
}

export function emptyEditor(logsource: string): EditorState {
  return {
    logsource,
    mode: "all",
    rows: [newRow()],
    thresholdEnabled: false,
    thresholdCount: 5,
    windowMinutes: 10,
    groupBy: [],
    cooldownMinutes: "",
  };
}

function isLeaf(node: RuleNode): node is RuleLeaf {
  return typeof node === "object" && node !== null && "field" in node;
}

function rowFromLeaf(leaf: RuleLeaf, negate: boolean): ConditionRow {
  const values = Array.isArray(leaf.value) ? leaf.value : [leaf.value];
  // El backend normaliza "in" a "equals" con lista: en el editor vuelve a ser "es uno de".
  const op: RuleOperator = leaf.op === "equals" && values.length > 1 ? "in" : leaf.op;
  return {
    ...newRow(leaf.field, op),
    value: values.map(String).join(", "),
    caseSensitive: Boolean(leaf.case_sensitive),
    negate,
  };
}

/**
 * Pasa una definición al editor estructurado. Devuelve null si su forma (grupos anidados,
 * reglas importadas de Sigma) no cabe en una lista plana: entonces se edita en modo avanzado.
 */
export function editorFromDefinition(definition: RuleDefinition): EditorState | null {
  const condition = definition.condition;
  let mode: "all" | "any" = "all";
  let children: RuleNode[];
  if (isLeaf(condition) || "not" in condition) children = [condition];
  else if ("all" in condition) children = condition.all;
  else {
    mode = "any";
    children = condition.any;
  }
  const rows: ConditionRow[] = [];
  for (const child of children) {
    if (isLeaf(child)) rows.push(rowFromLeaf(child, false));
    else if ("not" in child && isLeaf(child.not)) rows.push(rowFromLeaf(child.not, true));
    else return null;
  }
  const threshold = definition.threshold ?? null;
  return {
    logsource: definition.logsource,
    mode,
    rows,
    thresholdEnabled: threshold !== null,
    thresholdCount: threshold?.count ?? 5,
    windowMinutes: threshold?.window_minutes ?? 10,
    groupBy: definition.group_by ?? [],
    cooldownMinutes: definition.cooldown_minutes === undefined ? "" : String(definition.cooldown_minutes),
  };
}

function parseScalar(text: string, type: string | undefined): RuleScalar {
  const trimmed = text.trim();
  if (type === "integer" && /^-?\d+$/.test(trimmed)) return Number(trimmed);
  if (type === "boolean" && (trimmed === "true" || trimmed === "false")) return trimmed === "true";
  return trimmed;
}

export function leafFromRow(row: ConditionRow, fields: Map<string, RuleField>): RuleLeaf {
  const type = fields.get(row.field)?.type;
  let value: RuleScalar | RuleScalar[];
  if (row.op === "exists") value = row.value.trim() !== "false";
  else if (row.op === "in")
    value = row.value
      .split(",")
      .map((part) => part.trim())
      .filter(Boolean)
      .map((part) => parseScalar(part, type));
  else value = parseScalar(row.value, type);
  const leaf: RuleLeaf = { field: row.field, op: row.op, value };
  if (row.caseSensitive && type === "string" && row.op !== "exists") leaf.case_sensitive = true;
  return leaf;
}

/** Construye la definición declarativa desde el editor (la valida el backend). */
export function definitionFromEditor(state: EditorState, fields: Map<string, RuleField>): RuleDefinition {
  const nodes: RuleNode[] = state.rows
    .filter((row) => row.field)
    .map((row) => {
      const leaf = leafFromRow(row, fields);
      return row.negate ? { not: leaf } : leaf;
    });
  const [first] = nodes;
  const condition: RuleNode =
    nodes.length === 1 && first && !("not" in first) ? first : state.mode === "all" ? { all: nodes } : { any: nodes };
  const definition: RuleDefinition = { format: "sentra-rule/1", logsource: state.logsource, condition };
  if (state.thresholdEnabled) {
    definition.threshold = { count: state.thresholdCount, window_minutes: state.windowMinutes };
    if (state.groupBy.length) definition.group_by = state.groupBy;
  }
  if (state.cooldownMinutes.trim() !== "") {
    const cooldown = Number(state.cooldownMinutes);
    if (Number.isFinite(cooldown)) definition.cooldown_minutes = cooldown;
  }
  return definition;
}

/**
 * Eventos sintéticos escritos como "campo = valor", uno por línea; una línea en blanco separa
 * eventos. Los valores se convierten al tipo del campo del catálogo (número, true/false).
 */
export function parseSyntheticEvents(text: string, fields: Map<string, RuleField>): SyntheticEventInput[] {
  const events: SyntheticEventInput[] = [];
  for (const block of text.split(/\n\s*\n/)) {
    const values: SyntheticEventInput["fields"] = {};
    for (const line of block.split("\n")) {
      const index = line.indexOf("=");
      if (index <= 0) continue;
      const name = line.slice(0, index).trim();
      values[name] = parseScalar(line.slice(index + 1), fields.get(name)?.type);
    }
    if (Object.keys(values).length) events.push({ fields: values });
  }
  return events;
}

/** Valor de un diff o detalle como texto legible (nunca HTML). */
export function displayValue(value: unknown): string {
  if (value === null || value === undefined || value === "") return "—";
  if (typeof value === "string") return value;
  return JSON.stringify(value, null, 2);
}

export function splitList(text: string): string[] {
  return text
    .split(/[\n,]/)
    .map((part) => part.trim())
    .filter(Boolean);
}
