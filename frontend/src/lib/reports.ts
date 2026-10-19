// Utilidades de informes y exportación de evidencias (Fase 5E). Sin estado ni efectos salvo
// saveBlob, que solo crea un enlace temporal de descarga.
import type {
  ReportFilterKey,
  ReportFilters,
  ReportFormat,
  ReportRangePreset,
  ReportRequest,
  ReportStatus,
  ReportTypeInfo,
} from "../api/types";
import { PREFILL_PARAMS, type IdFilterKey } from "./reportLinks";

export { reportHref } from "./reportLinks";
export type { IdFilterKey } from "./reportLinks";

export const REPORT_STATUS_LABELS: Record<ReportStatus, string> = {
  pending: "Pendiente",
  running: "Generando",
  succeeded: "Completado",
  failed: "Fallido",
  cancelled: "Cancelado",
  expired: "Caducado",
};

export const REPORT_STATUSES: ReportStatus[] = ["pending", "running", "succeeded", "failed", "cancelled", "expired"];

export const REPORT_STATUS_BADGES: Record<ReportStatus, string> = {
  pending: "badge badge--muted",
  running: "badge badge--info",
  succeeded: "badge badge--ok",
  failed: "badge badge--crit",
  cancelled: "badge badge--muted",
  expired: "badge badge--muted",
};

export const FORMAT_LABELS: Record<string, string> = {
  html: "HTML",
  pdf: "PDF",
  csv: "CSV",
  evidence: "Paquete de evidencias (ZIP)",
};

export const CLASSIFICATION_LABELS: Record<string, string> = {
  internal: "Interno",
  confidential: "Confidencial",
  restricted: "Restringido",
};

export const RANGE_PRESETS: { value: ReportRangePreset; label: string }[] = [
  { value: "24h", label: "Últimas 24 h" },
  { value: "7d", label: "Últimos 7 días" },
  { value: "30d", label: "Últimos 30 días" },
  { value: "90d", label: "Últimos 90 días" },
  { value: "custom", label: "Personalizado (UTC)" },
];

export const FILTER_LABELS: Record<ReportFilterKey, string> = {
  asset_ids: "Activos",
  incident_ids: "Incidentes",
  detection_ids: "Detecciones",
  execution_ids: "Ejecuciones",
  playbook_ids: "Playbooks",
  severities: "Severidades",
  statuses: "Estados",
  risk_levels: "Niveles de riesgo",
  platforms: "Plataformas",
  include_archived: "Incluir archivados",
};

/** Filtros de identificadores: en el formulario se escriben separados por comas o espacios. */
export const ID_FILTERS: readonly IdFilterKey[] = [
  "asset_ids",
  "incident_ids",
  "detection_ids",
  "execution_ids",
  "playbook_ids",
];

/** Filtros de selección múltiple. */
export const MULTI_FILTERS = ["severities", "statuses", "risk_levels", "platforms"] as const;
export type MultiFilterKey = (typeof MULTI_FILTERS)[number];

/** Valores por defecto si el catálogo no envía los del tipo. */
export const DEFAULT_SEVERITIES = ["critical", "high", "medium", "low", "informational"];
export const DEFAULT_RISK_LEVELS = ["critical", "high", "medium", "low", "informational"];
export const PLATFORMS = ["windows", "linux", "other"];

export const VALUE_LABELS: Record<string, string> = {
  critical: "Crítico",
  high: "Alto",
  medium: "Medio",
  low: "Bajo",
  informational: "Informativo",
  windows: "Windows",
  linux: "Linux",
  macos: "macOS",
  other: "Otra",
  open: "Abierto",
  closed: "Cerrado",
  resolved: "Resuelto",
};

export const SCOPE_LABELS: Record<string, string> = {
  assets: "Activos",
  incidents: "Incidentes",
  detections: "Detecciones",
  vulnerabilities: "Vulnerabilidades",
  findings: "Hallazgos",
  executions: "Ejecuciones",
  runs: "Ejecuciones de playbooks",
  playbooks: "Playbooks",
  events: "Eventos",
  changes: "Cambios",
  rows: "Filas",
};

/** Valores admitidos por un filtro de selección múltiple en un tipo de informe. */
export function multiFilterValues(type: ReportTypeInfo, key: MultiFilterKey): string[] {
  switch (key) {
    case "severities":
      return type.severity_values?.length ? type.severity_values : DEFAULT_SEVERITIES;
    case "statuses":
      return type.status_values ?? [];
    case "risk_levels":
      return DEFAULT_RISK_LEVELS;
    case "platforms":
      return PLATFORMS;
  }
}

export function isActiveReport(status: ReportStatus): boolean {
  return status === "pending" || status === "running";
}

/** SHA-256 abreviado para tablas: los 12 primeros caracteres. */
export function shortHash(sha: string | null | undefined): string {
  if (!sha) return "—";
  return sha.length > 12 ? `${sha.slice(0, 12)}…` : sha;
}

/** "a, b c" → ["a", "b", "c"], sin duplicados ni vacíos. */
export function parseIdList(text: string): string[] {
  return [...new Set(text.split(/[\s,;]+/).map((v) => v.trim()).filter(Boolean))];
}

export interface ReportPrefill {
  type: string | undefined;
  ids: Partial<Record<IdFilterKey, string>>;
}

export function parsePrefill(params: URLSearchParams): ReportPrefill {
  const ids: Partial<Record<IdFilterKey, string>> = {};
  for (const [param, key] of Object.entries(PREFILL_PARAMS)) {
    const values = params.getAll(param).flatMap(parseIdList);
    if (values.length) ids[key] = values.join(", ");
  }
  return { type: params.get("type")?.trim() || undefined, ids };
}

/** Fecha/hora de un input datetime-local interpretada como UTC → ISO con "Z". */
export function localInputToUtcIso(value: string): string | undefined {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?$/.test(value)) return undefined;
  const iso = `${value.length === 16 ? `${value}:00` : value}Z`;
  return Number.isNaN(new Date(iso).getTime()) ? undefined : iso;
}

/** Día (YYYY-MM-DD) como inicio o fin de ese día en UTC, para los filtros del historial. */
export function dayToUtcIso(day: string, end = false): string | undefined {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) return undefined;
  return `${day}T${end ? "23:59:59" : "00:00:00"}Z`;
}

/** ISO → "2026-10-14 23:15 UTC" (los informes trabajan siempre en UTC). */
export function formatUtc(iso: string | null | undefined): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "—";
  return `${date.toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

/** Conteos del alcance en una línea: "3 activos · 12 detecciones". */
export function formatScope(scope: Record<string, unknown> | null | undefined): string {
  const parts = Object.entries(scope ?? {})
    .filter(([, v]) => v !== null && v !== undefined && typeof v !== "object")
    .map(([key, value]) => `${SCOPE_LABELS[key] ?? key}: ${String(value)}`);
  return parts.length ? parts.join(" · ") : "—";
}

/** Filtros de un informe como pares legibles (para el detalle). */
export function describeFilters(filters: ReportFilters | null | undefined): { label: string; value: string }[] {
  return Object.entries(filters ?? {}).flatMap(([key, value]) => {
    const label = FILTER_LABELS[key as ReportFilterKey] ?? key;
    if (Array.isArray(value)) {
      if (!value.length) return [];
      return [{ label, value: value.map((v) => VALUE_LABELS[String(v)] ?? String(v)).join(", ") }];
    }
    if (typeof value === "boolean") return [{ label, value: value ? "Sí" : "No" }];
    if (value === null || value === undefined || value === "") return [];
    return [{ label, value: String(value) }];
  });
}

/** Estado del formulario de generación. */
export interface ReportFormState {
  reportType: string;
  format: string;
  classification: string;
  preset: ReportRangePreset;
  customFrom: string;
  customTo: string;
  ids: Partial<Record<IdFilterKey, string>>;
  multi: Partial<Record<MultiFilterKey, string[]>>;
  includeArchived: boolean;
}

export function initialFormState(prefill: ReportPrefill): ReportFormState {
  return {
    reportType: prefill.type ?? "",
    format: "",
    classification: "internal",
    preset: "30d",
    customFrom: "",
    customTo: "",
    ids: { ...prefill.ids },
    multi: {},
    includeArchived: false,
  };
}

/** Formato efectivo: el elegido si el tipo lo admite; si no, el primero del tipo. */
export function effectiveFormat(type: ReportTypeInfo, format: string): ReportFormat {
  if ((type.supported_formats as string[]).includes(format)) return format as ReportFormat;
  return type.supported_formats[0] ?? "html";
}

export interface BuildResult {
  request: Omit<ReportRequest, "idempotency_key"> | undefined;
  /** Motivos por los que aún no se puede enviar (en español). */
  problems: string[];
}

/**
 * Cuerpo de preview/generate a partir del formulario: solo los filtros que admite el tipo,
 * sin filtros vacíos, y el rango solo si el tipo lo usa (custom en UTC).
 */
export function buildReportRequest(type: ReportTypeInfo, form: ReportFormState): BuildResult {
  const problems: string[] = [];
  const filters: ReportFilters = {};
  const allowed = new Set(type.filters);
  for (const key of ID_FILTERS) {
    if (!allowed.has(key)) continue;
    const ids = parseIdList(form.ids[key] ?? "");
    if (ids.length) filters[key] = ids;
  }
  for (const key of MULTI_FILTERS) {
    if (!allowed.has(key)) continue;
    const valid = new Set(multiFilterValues(type, key));
    const values = (form.multi[key] ?? []).filter((v) => valid.has(v));
    if (values.length) filters[key] = values;
  }
  if (allowed.has("include_archived") && form.includeArchived) filters.include_archived = true;
  for (const key of type.required_filters) {
    const value = filters[key];
    if (value === undefined || (Array.isArray(value) && value.length === 0)) {
      problems.push(`Falta el filtro obligatorio: ${FILTER_LABELS[key] ?? key}.`);
    }
  }
  if ((type.id === "incident" || type.id === "asset") && type.required_filters.length) {
    for (const key of type.required_filters) {
      const value = filters[key];
      if (Array.isArray(value) && value.length > 1) problems.push(`${FILTER_LABELS[key]}: indica exactamente uno.`);
    }
  }

  const request: Omit<ReportRequest, "idempotency_key"> = {
    report_type: type.id,
    format: effectiveFormat(type, form.format),
    classification: form.classification || "internal",
    filters,
  };
  if (type.uses_range) {
    if (form.preset === "custom") {
      const from = localInputToUtcIso(form.customFrom);
      const to = localInputToUtcIso(form.customTo);
      if (!from || !to) problems.push("Indica el inicio y el fin del rango personalizado.");
      else if (new Date(from) >= new Date(to)) problems.push("El inicio del rango debe ser anterior al fin.");
      else if ((new Date(to).getTime() - new Date(from).getTime()) / 86_400_000 > type.max_range_days) {
        problems.push(`El rango no puede superar ${type.max_range_days} días.`);
      }
      if (from && to) request.range = { preset: "custom", from, to };
    } else {
      request.range = { preset: form.preset };
    }
  }
  return { request: problems.length ? undefined : request, problems };
}

/** Clave de idempotencia de un diálogo de generación (UUID v4). */
export function newReportKey(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") return crypto.randomUUID();
  // Navegadores sin randomUUID (contexto no seguro): UUID v4 con getRandomValues.
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x40;
  bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80;
  const hex = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** Nombre de fichero seguro para el atributo download (sin rutas ni caracteres de control). */
export function safeFilename(name: string | null | undefined, fallback: string): string {
  const base = (name ?? "").split(/[\\/]/).pop() ?? "";
  // eslint-disable-next-line no-control-regex
  const cleaned = base.replace(/[\u0000-\u001f\u007f<>:"|?*]/g, "_").trim();
  return cleaned && cleaned !== "." && cleaned !== ".." ? cleaned.slice(0, 200) : fallback;
}

/** No se puede calcular el SHA-256 en este navegador (sin crypto.subtle: http fuera de localhost). */
export class ChecksumUnavailableError extends Error {
  constructor() {
    super("SHA-256 no disponible en este navegador");
    this.name = "ChecksumUnavailableError";
  }
}

/**
 * Bytes de un Blob. Blob.arrayBuffer() existe en los navegadores soportados; FileReader cubre un
 * Blob que no lo implementa: con Node >= 24 y jsdom 26 (tests), fetch construye la respuesta con
 * el Blob global de jsdom, que no tiene arrayBuffer().
 */
async function blobBytes(blob: Blob): Promise<Uint8Array<ArrayBuffer>> {
  if (typeof blob.arrayBuffer === "function") return new Uint8Array(await blob.arrayBuffer());
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(new Uint8Array(reader.result as ArrayBuffer));
    reader.onerror = () => reject(reader.error ?? new Error("No se pudo leer el fichero descargado"));
    reader.readAsArrayBuffer(blob);
  });
}

/**
 * SHA-256 (hex, minúsculas) de un Blob. Lanza ChecksumUnavailableError si el navegador no
 * ofrece crypto.subtle y propaga cualquier error de Web Crypto: quien llama NUNCA debe guardar
 * un fichero cuyo hash no se ha podido comprobar.
 */
export async function sha256Hex(blob: Blob): Promise<string> {
  if (typeof crypto === "undefined" || !crypto.subtle) throw new ChecksumUnavailableError();
  const digest = await crypto.subtle.digest("SHA-256", await blobBytes(blob));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Guarda un Blob como fichero mediante un enlace temporal con `download`. El contenido nunca
 * se abre ni se inserta en la página (ni iframe ni HTML): el navegador solo lo descarga.
 */
export function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.rel = "noopener";
  link.style.display = "none";
  document.body.appendChild(link);
  try {
    link.click();
  } finally {
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
}
