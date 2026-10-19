// Fuentes oficiales del catálogo de vulnerabilidades (Fase 6C.4): etiquetas en español y
// helpers puros. El estado de cada fuente y del catálogo lo decide el servidor; la UI solo lo
// traduce. Los textos que llegan de NVD u OSV son datos no confiables y se pintan como texto.
import { ApiError } from "../api/client";
import type { DashboardVulnerabilities, VulnSourceFreshness } from "../api/types";
import type { SourceContent } from "../api/vulnSources";
import { errorMessage } from "./format";

export const ADAPTER_LABELS: Record<string, string> = {
  nvd: "NVD",
  osv: "OSV",
  local_catalog: "Catálogo local",
  cisa_kev: "CISA KEV",
  first_epss: "FIRST EPSS",
};

export const FRESHNESS_LABELS: Record<VulnSourceFreshness, string> = {
  never: "Sin datos",
  fresh: "Al día",
  stale: "Desactualizada",
};

export const FRESHNESS_CLASSES: Record<VulnSourceFreshness, string> = {
  never: "",
  fresh: "badge--ok",
  stale: "badge--warn",
};

export const SYNC_STATUS_LABELS: Record<string, string> = {
  success: "Correcta",
  not_modified: "Sin cambios",
  partial: "Parcial",
  failed: "Fallida",
};

export const SYNC_STATUS_CLASSES: Record<string, string> = {
  success: "badge--ok",
  not_modified: "",
  partial: "badge--warn",
  failed: "badge--crit",
};

export const SYNC_KIND_LABELS: Record<string, string> = { import: "Importación", sync: "Sincronización" };

export const TRIGGER_LABELS: Record<string, string> = { api: "Consola / API", cli: "CLI", scheduled: "Programada" };

/** Motivos de descarte de la previsualización (no son errores: se cuentan y se explican). */
export const SKIPPED_REASON_LABELS: Record<string, string> = {
  nvd_not_scored: "CVE sin métrica CVSS todavía (llegará en una sincronización posterior)",
  ecosystem_not_inventoried: "Ecosistema que Sentra no inventaría (PyPI, npm, Alpine...)",
  severity_unavailable: "Sin severidad: importa NVD antes que OSV",
  superseded_by_cve_record: "Aviso sustituido por su registro por CVE",
  invalid_id: "Identificador no válido",
};

export const RETIRED_LABELS: Record<string, string> = {
  nvd_rejected: "Rechazado por NVD",
  osv_withdrawn: "Retirado por OSV",
};

/** Atributos de ATTRIBUTE_SOURCES (backend app/vulnerabilities/adapters/__init__.py). */
export const ATTRIBUTE_LABELS: Record<string, string> = {
  cve: "CVE",
  title: "Título",
  description: "Descripción",
  references: "Referencias",
  cvss: "CVSS",
  severity: "Severidad",
  cwe: "CWE",
  product_identifier: "Identificador de producto",
  affected: "Productos afectados",
  affected_versions: "Versiones afectadas",
  exploitation: "Explotación conocida (KEV)",
  epss: "EPSS",
  published: "Publicado",
  modified: "Modificado",
  local_updated: "Actualizado en Sentra",
};

/** Límites de la coincidencia (backend matcher._LIMIT_TEXT): por qué no llega a confirmada. */
export const MATCH_LIMIT_LABELS: Record<string, string> = {
  publisher_unreported: "El inventario no informa el editor.",
  name_only: "Coincidencia por nombre exacto sin editor declarado en el catálogo.",
  distro_release_unknown: "Paquete de distribución: el agente no informa la versión de la distribución.",
  kernel_config_unknown: "Kernel exacto, pero se desconoce su configuración.",
  distro_backports: "Versión upstream sobre un paquete de distribución: puede tener el parche aplicado (backport).",
  platform_unvalidated: "Plataforma macOS sin validar con agentes reales.",
  configuration_unverified: "La fuente exige además otro producto o plataforma que Sentra no puede verificar.",
  unbounded_version_range: "La fuente declara afectadas todas las versiones, sin rango.",
  cpe_target_unverified: "El CPE limita la plataforma o la arquitectura y no se puede verificar.",
  cpe_edition_unverified: "El CPE se refiere a una edición concreta que el identificador no declara.",
  cpe_update_qualifier: "El CPE incluye un calificador de actualización no comparable.",
  source_package_unverified: "La fuente describe el paquete fuente; el inventario informa paquetes binarios.",
};

export const IDENTITY_METHOD_LABELS: Record<string, string> = {
  exact_key: "Clave exacta del inventario",
  windows_build: "Build de Windows (determinista)",
  product_map: "Identificador CPE declarado",
};

export const IDENTITY_SOURCE_LABELS: Record<string, string> = {
  builtin: "semilla integrada de Sentra",
};

/** Estado de evaluación del dashboard: «sin vulnerabilidades» solo cuando se pudo saber. */
export type EvaluationState = DashboardVulnerabilities["evaluation_state"];

export const EVALUATION_STATE_LABELS: Record<EvaluationState, string> = {
  no_catalog: "Sin catálogo",
  pending: "Evaluación pendiente",
  insufficient_catalog: "Catálogo insuficiente",
  vulnerabilities_found: "Vulnerabilidades encontradas",
  no_vulnerabilities: "Sin vulnerabilidades conocidas",
};

export const EVALUATION_STATE_HINTS: Record<EvaluationState, string> = {
  no_catalog: "No hay catálogo importado: Sentra no puede saber si el software inventariado es vulnerable.",
  pending: "Hay activos pendientes de evaluar contra el catálogo: el resultado aún no es definitivo.",
  insufficient_catalog:
    "El catálogo no describe el software inventariado: que no aparezcan vulnerabilidades no significa que no las haya.",
  // El servidor cuenta también las potenciales: el recuento por severidad es solo de las
  // confirmadas y probables, y las potenciales se muestran aparte.
  vulnerabilities_found: "Hay vulnerabilidades activas: confirmadas, probables o potenciales pendientes de verificar.",
  no_vulnerabilities: "Los activos evaluados y cubiertos por el catálogo no tienen vulnerabilidades activas conocidas.",
};

export const EVALUATION_STATE_CLASSES: Record<EvaluationState, string> = {
  no_catalog: "badge--warn",
  pending: "badge--info",
  insufficient_catalog: "badge--warn",
  vulnerabilities_found: "badge--crit",
  no_vulnerabilities: "badge--ok",
};

// Errores de las fuentes oficiales. Se traducen aquí (no en client.ts) porque solo los usa
// esta pantalla; el resto conserva el mensaje del servidor tras un prefijo en español.
const SOURCE_ERRORS: Record<string, string> = {
  vulnerability_source_sync_disabled:
    "La descarga por red está desactivada en este servidor (VULN_SOURCE_SYNC_ENABLED=false). Sentra sigue evaluando con el último catálogo importado; para actualizarlo, importa un fichero aquí o con la CLI (vuln-source-import).",
  catalog_changed: "El fichero cambió desde la previsualización. Vuelve a seleccionarlo y previsualízalo de nuevo.",
  vulnerability_source_busy: "Ya hay una importación o sincronización en curso para esta fuente. Inténtalo en unos minutos.",
  vulnerability_source_key_taken:
    "Un catálogo local ya usa la clave de esta fuente oficial: Sentra no mezcla los dos. Revisa los catálogos locales.",
  source_invalid_json: "El fichero no es JSON válido.",
  source_too_large: "El fichero supera el tamaño máximo del servidor: impórtalo con la CLI.",
  payload_too_large: "El fichero supera el tamaño máximo de una petición (MAX_REQUEST_BYTES): impórtalo con la CLI.",
  source_invalid_format: "El fichero no tiene el formato esperado para esta fuente.",
  source_incomplete_response: "El fichero está incompleto (respuesta de la API cortada o paginación sin terminar).",
  source_invalid_archive: "El archivo comprimido no es válido.",
  source_too_many_records: "El fichero supera el número máximo de registros por importación: impórtalo con la CLI.",
  source_invalid_records: "Hay registros inválidos: marca «Importar solo los válidos» para continuar.",
  source_no_valid_records: "El fichero no contiene ningún registro válido.",
};

export function sourceErrorMessage(err: unknown): string {
  if (err instanceof ApiError && SOURCE_ERRORS[err.code]) return SOURCE_ERRORS[err.code]!;
  if (err instanceof ApiError && err.code.startsWith("source_")) return `Fichero no válido: ${err.message}`;
  return err instanceof Error ? errorMessage(err) : String(err);
}

export function isSyncDisabled(err: unknown): boolean {
  return err instanceof ApiError && err.code === "vulnerability_source_sync_disabled";
}

const CVE_RE = /^CVE-\d{4}-\d{4,7}$/i;

export function isCveId(value: string | null | undefined): value is string {
  return !!value && CVE_RE.test(value);
}

/** Ruta interna de la vista de un CVE en el catálogo. */
export function cvePath(cveId: string): string {
  return `/vulnerabilities/catalog/cves/${encodeURIComponent(cveId.toUpperCase())}`;
}

/** Texto legible de un valor de procedencia (cadena u objeto como {source, type, version}). */
export function provenanceText(value: unknown): string {
  if (value == null) return "—";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return value.map(provenanceText).join(", ");
  if (typeof value === "object") {
    return Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v != null && v !== "")
      .map(([k, v]) => `${k}: ${provenanceText(v)}`)
      .join(" · ");
  }
  return "—";
}

/** Ficheros comprimidos que viajan en base64; el resto se envía como texto JSON. */
export function isBinarySourceFile(name: string): boolean {
  return /\.(gz|zip)$/i.test(name);
}

function readAsDataUrl(file: Blob): Promise<string> {
  // FileReader en vez de arrayBuffer(): jsdom (tests) no siempre lo implementa y en los
  // navegadores soportados el resultado es el mismo.
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(reader.error ?? new Error("No se pudo leer el fichero"));
    reader.readAsDataURL(file);
  });
}

function readAsText(file: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(reader.error ?? new Error("No se pudo leer el fichero"));
    reader.readAsText(file);
  });
}

/** Cuerpo de la petición para un fichero elegido por el usuario. */
export async function fileToSourceContent(file: File): Promise<SourceContent> {
  if (isBinarySourceFile(file.name)) {
    const dataUrl = await readAsDataUrl(file);
    const comma = dataUrl.indexOf(",");
    return { content_base64: comma >= 0 ? dataUrl.slice(comma + 1) : dataUrl };
  }
  return { content: await readAsText(file) };
}
