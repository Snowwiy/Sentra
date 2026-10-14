import { ApiError } from "../api/client";
import type { ResponseIssue } from "../api/types";

/** Etiquetas de los estados de una ejecución y de los pasos de un playbook. */
export const EXECUTION_STATUS_LABELS: Record<string, string> = {
  pending: "Pendiente",
  approval_required: "Requiere aprobación",
  queued: "En cola",
  running: "En curso",
  succeeded: "Completada",
  failed: "Fallida",
  cancelled: "Cancelada",
  timed_out: "Tiempo agotado",
  blocked: "Bloqueada",
  // Solo en pasos de un playbook: aún no alcanzado (pending) o nunca alcanzado por un
  // fallo con "stop", una cancelación o un bloqueo (skipped).
  skipped: "Omitido",
};

export const EXECUTION_STATUSES = [
  "pending",
  "approval_required",
  "queued",
  "running",
  "succeeded",
  "failed",
  "cancelled",
  "timed_out",
  "blocked",
] as const;

export const RUN_STATUS_LABELS: Record<string, string> = {
  running: "En curso",
  succeeded: "Completado",
  failed: "Fallido",
  cancelled: "Cancelado",
  blocked: "Bloqueado",
};

export const RUN_STATUSES = ["running", "succeeded", "failed", "cancelled", "blocked"] as const;

export const RISK_LABELS: Record<string, string> = {
  low: "Riesgo bajo",
  medium: "Riesgo medio",
  high: "Riesgo alto",
  critical: "Riesgo crítico",
};

export const ROLE_REQUIRED_LABELS: Record<string, string> = {
  viewer: "Viewer",
  analyst: "Analyst",
  admin: "Admin",
};

export const CATEGORY_LABELS: Record<string, string> = {
  collection: "Recolección",
  analysis: "Análisis",
  evidence: "Evidencia",
  case: "Caso",
  lifecycle: "Ciclo de vida",
  containment: "Contención",
};

// Estados en los que una ejecución aún puede cancelarse (ACTIVE_EXECUTION_STATUSES del backend).
const ACTIVE_EXECUTION = new Set(["pending", "approval_required", "queued", "running"]);

export function isActiveExecution(status: string): boolean {
  return ACTIVE_EXECUTION.has(status);
}

/** Clase CSS del estado: reutiliza las variantes de badge existentes para no añadir estilos. */
export function statusClass(status: string): string {
  if (status === "succeeded") return "badge badge--ok";
  if (status === "failed" || status === "timed_out" || status === "blocked") return "badge badge--crit";
  if (status === "cancelled" || status === "skipped") return "badge badge--muted";
  return "badge badge--info";
}

/** Riesgo con la misma escala visual que la severidad de detecciones. */
export function riskClass(risk: string): string {
  return ["low", "medium", "high", "critical"].includes(risk) ? `dseverity dseverity--${risk}` : "badge";
}

/**
 * Clave de idempotencia de un diálogo. Se genera una vez al abrirlo: si el usuario pulsa dos
 * veces Ejecutar (o la red reintenta), el servidor devuelve la misma ejecución. Debe cumplir
 * ^[A-Za-z0-9_-]{8,64}$, por eso se quitan los guiones del UUID.
 */
export function newIdempotencyKey(): string {
  const uuid =
    typeof crypto !== "undefined" && typeof crypto.randomUUID === "function"
      ? crypto.randomUUID()
      : `${Date.now().toString(16)}${Math.random().toString(16).slice(2)}`;
  return uuid.replace(/-/g, "").slice(0, 64);
}

/** Campo simple del formulario de parámetros, derivado del JSON Schema de la acción. */
export interface ParamField {
  name: string;
  kind: "string" | "integer" | "enum";
  label: string;
  required: boolean;
  options: string[];
  minimum?: number;
  maximum?: number;
  minLength?: number;
  maxLength?: number;
  defaultValue?: string | number;
}

const PARAM_LABELS: Record<string, string> = {
  hours: "Ventana (horas)",
  title: "Título",
  severity: "Severidad",
  priority: "Prioridad",
  reason: "Motivo del archivado",
  body: "Nota",
};

type Schema = Record<string, unknown>;

function asSchema(value: unknown): Schema {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Schema) : {};
}

// Pydantic genera "$ref" a $defs para los enums y "anyOf: [X, null]" para los opcionales; se
// resuelven aquí para obtener el tipo real. Cualquier forma desconocida se ignora (el campo no
// se muestra y el servidor aplica su valor por defecto o responde 422).
function resolve(prop: Schema, defs: Schema): Schema {
  const ref = prop.$ref;
  if (typeof ref === "string" && ref.startsWith("#/$defs/")) {
    return { ...asSchema(defs[ref.slice("#/$defs/".length)]), ...prop, $ref: undefined };
  }
  if (Array.isArray(prop.anyOf)) {
    const nonNull = prop.anyOf.map(asSchema).find((option) => option.type !== "null");
    if (nonNull) return { ...resolve(nonNull, defs), default: prop.default, title: prop.title };
  }
  return prop;
}

/** Campos editables (string, integer o enum) del `parameters_schema` de una acción. */
export function paramFields(schema: Record<string, unknown>): ParamField[] {
  const properties = asSchema(schema.properties);
  const defs = asSchema(schema.$defs);
  const required = Array.isArray(schema.required) ? schema.required.filter((r) => typeof r === "string") : [];
  const fields: ParamField[] = [];
  for (const [name, raw] of Object.entries(properties)) {
    const prop = resolve(asSchema(raw), defs);
    const def = prop.default;
    const base = {
      name,
      label: PARAM_LABELS[name] ?? (typeof prop.title === "string" ? prop.title : name),
      required: required.includes(name),
      defaultValue: typeof def === "string" || typeof def === "number" ? def : undefined,
    };
    if (Array.isArray(prop.enum)) {
      fields.push({ ...base, kind: "enum", options: prop.enum.map(String) });
    } else if (prop.type === "integer") {
      fields.push({
        ...base,
        kind: "integer",
        options: [],
        minimum: typeof prop.minimum === "number" ? prop.minimum : undefined,
        maximum: typeof prop.maximum === "number" ? prop.maximum : undefined,
      });
    } else if (prop.type === "string") {
      fields.push({
        ...base,
        kind: "string",
        options: [],
        minLength: typeof prop.minLength === "number" ? prop.minLength : undefined,
        maxLength: typeof prop.maxLength === "number" ? prop.maxLength : undefined,
      });
    }
  }
  return fields;
}

/** Valores iniciales del formulario: los valores por defecto del esquema, como texto. */
export function initialParamValues(fields: ParamField[]): Record<string, string> {
  return Object.fromEntries(fields.map((f) => [f.name, f.defaultValue === undefined ? "" : String(f.defaultValue)]));
}

/**
 * Convierte el formulario en `parameters`. Un campo opcional vacío no se envía (así el
 * servidor aplica su valor por defecto); los enteros se envían como número.
 */
export function buildParameters(fields: ParamField[], values: Record<string, string>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const field of fields) {
    const raw = (values[field.name] ?? "").trim();
    if (raw === "") continue;
    if (field.kind === "integer") {
      const value = Number(raw);
      out[field.name] = Number.isInteger(value) ? value : raw;
    } else {
      out[field.name] = raw;
    }
  }
  return out;
}

/** Faltan campos obligatorios o un texto no llega a su longitud mínima. */
export function missingParameters(fields: ParamField[], values: Record<string, string>): boolean {
  return fields.some((f) => {
    const raw = (values[f.name] ?? "").trim();
    if (raw === "") return f.required;
    return f.minLength !== undefined && raw.length < f.minLength;
  });
}

export interface BlockedInfo {
  executionId: string | null;
  runId: string | null;
  blockers: ResponseIssue[];
}

/**
 * Datos del 409 response_blocked: details[0] trae la ejecución o el run registrado como
 * evidencia del intento y el resto son los bloqueos {code, message}. null si es otro error.
 */
export function blockedInfo(error: unknown): BlockedInfo | null {
  if (!(error instanceof ApiError) || error.code !== "response_blocked") return null;
  const details: unknown[] = Array.isArray(error.details) ? error.details : [];
  let executionId: string | null = null;
  let runId: string | null = null;
  const blockers: ResponseIssue[] = [];
  for (const item of details) {
    if (typeof item !== "object" || item === null) continue;
    const record = item as Record<string, unknown>;
    if (typeof record.execution_id === "string") executionId = record.execution_id;
    if (typeof record.run_id === "string") runId = record.run_id;
    if (typeof record.code === "string" && typeof record.message === "string") {
      blockers.push({ code: record.code, message: record.message });
    }
  }
  return { executionId, runId, blockers };
}

/** Duración en texto corto a partir de milisegundos. */
export function formatDurationMs(ms: number | null | undefined): string {
  if (ms == null) return "—";
  if (ms < 1000) return `${ms} ms`;
  const seconds = ms / 1000;
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  return `${Math.floor(seconds / 60)} min ${Math.round(seconds % 60)} s`;
}

/** Muestra un JSON del servidor como texto (siempre dentro de un <pre>, nunca como HTML). */
export function jsonText(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2) ?? "";
  } catch {
    return String(value);
  }
}
