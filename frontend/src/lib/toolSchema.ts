// Fase 7B.4: formulario de la Analyst Console a partir del JSON Schema de entrada de cada
// herramienta del motor 7A. La consola NO es un intérprete: solo rellena los campos que el
// modelo cerrado del servidor declara (extra=forbid) y el servidor vuelve a validar todo.
// Un tipo que no se sabe pintar se pide como JSON y lo rechaza el servidor si no encaja.

export type FieldKind = "text" | "number" | "boolean" | "enum" | "json";

export interface ToolField {
  name: string;
  kind: FieldKind;
  required: boolean;
  label: string;
  description?: string;
  options?: string[];
  min?: number;
  max?: number;
  maxLength?: number;
  defaultValue?: unknown;
}

type Schema = Record<string, unknown>;

function asSchema(value: unknown): Schema {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Schema) : {};
}

function resolve(node: Schema, root: Schema): Schema {
  const ref = node.$ref;
  if (typeof ref !== "string" || !ref.startsWith("#/$defs/")) return node;
  return asSchema(asSchema(root.$defs)[ref.slice("#/$defs/".length)]);
}

/** anyOf [X, null] -> X (el campo es opcional); cualquier otra unión se pide como JSON. */
function unwrap(node: Schema, root: Schema): Schema {
  const options = Array.isArray(node.anyOf) ? (node.anyOf as unknown[]).map(asSchema) : null;
  if (!options) return resolve(node, root);
  const real = options.filter((o) => o.type !== "null");
  return real.length === 1 ? resolve(real[0]!, root) : { type: "json" };
}

const LABELS: Record<string, string> = {
  asset_id: "Activo (id)",
  detection_id: "Detección (id)",
  incident_id: "Caso (id)",
  investigation_id: "Investigación (id)",
  evidence_id: "Evidencia (id)",
  kind: "Tipo",
  text: "Texto",
  limit: "Máximo de filas",
  hours: "Horas hacia atrás",
  days: "Días hacia atrás",
  reason: "Motivo",
  include_archived: "Incluir archivados",
  active: "Solo activas",
};

export function fieldsOf(inputSchema: Record<string, unknown>): ToolField[] {
  const root = asSchema(inputSchema);
  const required = new Set(Array.isArray(root.required) ? (root.required as string[]) : []);
  return Object.entries(asSchema(root.properties)).map(([name, raw]) => {
    const original = asSchema(raw);
    const node = unwrap(original, root);
    const base = {
      name,
      required: required.has(name),
      label: LABELS[name] ?? (typeof original.title === "string" ? original.title : name),
      description: typeof original.description === "string" ? original.description : undefined,
      defaultValue: original.default,
    };
    if (Array.isArray(node.enum)) return { ...base, kind: "enum", options: (node.enum as unknown[]).map(String) };
    if (node.type === "boolean") return { ...base, kind: "boolean" };
    if (node.type === "integer" || node.type === "number") {
      return {
        ...base,
        kind: "number",
        min: typeof node.minimum === "number" ? node.minimum : undefined,
        max: typeof node.maximum === "number" ? node.maximum : undefined,
      };
    }
    if (node.type === "string") {
      return { ...base, kind: "text", maxLength: typeof node.maxLength === "number" ? node.maxLength : undefined };
    }
    return { ...base, kind: "json" };
  });
}

export type FieldValues = Record<string, string | boolean>;

/** Valores iniciales: el por defecto del servidor y lo que aporta la entidad del workspace. */
export function initialValues(fields: ToolField[], preset: Record<string, string> = {}): FieldValues {
  const values: FieldValues = {};
  for (const field of fields) {
    if (preset[field.name] !== undefined) values[field.name] = preset[field.name]!;
    else if (field.kind === "boolean") values[field.name] = field.defaultValue === true;
    else if (field.defaultValue !== undefined && field.defaultValue !== null) {
      values[field.name] = field.kind === "json" ? JSON.stringify(field.defaultValue) : String(field.defaultValue);
    } else values[field.name] = "";
  }
  return values;
}

/** Entrada para la API. Los opcionales vacíos no se envían (el servidor aplica su defecto). */
export function buildInput(
  fields: ToolField[],
  values: FieldValues,
): { input: Record<string, unknown> } | { error: string } {
  const input: Record<string, unknown> = {};
  for (const field of fields) {
    const raw = values[field.name];
    if (field.kind === "boolean") {
      input[field.name] = raw === true;
      continue;
    }
    const text = typeof raw === "string" ? raw.trim() : "";
    if (!text) {
      if (field.required) return { error: `Falta «${field.label}».` };
      continue;
    }
    if (field.kind === "number") {
      const value = Number(text);
      if (!Number.isInteger(value)) return { error: `«${field.label}» debe ser un número entero.` };
      input[field.name] = value;
    } else if (field.kind === "json") {
      try {
        input[field.name] = JSON.parse(text);
      } catch {
        return { error: `«${field.label}» debe ser JSON válido.` };
      }
    } else {
      input[field.name] = text;
    }
  }
  return { input };
}
