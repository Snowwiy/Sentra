// Utilidades de Vulnerability & Exposure Management (Fase 5B): etiquetas en español y
// helpers puros.
//
// La UI no decide nada: el estado técnico (match_state) lo calcula la evaluación y las
// acciones permitidas vienen del servidor (`actions`), que las vuelve a validar con `version`.
import { ApiError } from "../api/client";
import type {
  ExposureState,
  FindingAction,
  FindingStatus,
  MatchConfidence,
  MatchState,
  VulnSeverity,
} from "../api/types";

export const SEVERITY_LABELS: Record<VulnSeverity, string> = {
  critical: "Crítica",
  high: "Alta",
  medium: "Media",
  low: "Baja",
  informational: "Informativa",
};

export const SEVERITY_ORDER: VulnSeverity[] = ["critical", "high", "medium", "low", "informational"];

export const MATCH_LABELS: Record<MatchState, string> = {
  confirmed: "Confirmada",
  probable: "Probable",
  potential: "Potencial",
  not_affected: "No afectado",
  unknown: "Evidencia insuficiente",
};

/** Qué significa cada estado técnico (tooltip): una potencial no es una confirmada. */
export const MATCH_HINTS: Record<MatchState, string> = {
  confirmed: "Producto y versión instalada coinciden con un rango afectado del catálogo.",
  probable: "Coincide, pero con una limitación conocida (p. ej. backports de la distribución).",
  potential: "Solo coincide el nombre o la versión no es comparable: requiere verificación.",
  not_affected: "La versión instalada está fuera de los rangos afectados.",
  unknown: "No hay evidencia suficiente para decidir.",
};

export const MATCH_ORDER: MatchState[] = ["confirmed", "probable", "potential", "unknown"];

export const CONFIDENCE_LABELS: Record<MatchConfidence, string> = {
  high: "Alta",
  medium: "Media",
  low: "Baja",
};

export const STATUS_LABELS: Record<FindingStatus, string> = {
  open: "Abierta",
  acknowledged: "Reconocida",
  mitigating: "En mitigación",
  resolved: "Resuelta",
  accepted_risk: "Riesgo aceptado",
  false_positive: "Falso positivo",
};

export const STATUS_ORDER: FindingStatus[] = [
  "open",
  "acknowledged",
  "mitigating",
  "resolved",
  "accepted_risk",
  "false_positive",
];

export const EXPOSURE_LABELS: Record<ExposureState, string> = {
  internet_exposed: "Expuesta a Internet",
  observed: "Servicio observado",
  listening: "Escuchando (agente)",
  not_observed: "No observada",
  unknown: "Desconocida",
};

export const EXPOSURE_ORDER: ExposureState[] = ["internet_exposed", "observed", "listening", "not_observed", "unknown"];

/** Etiquetas de exposición honestas: dicen desde dónde se observó, no suponen Internet. */
export const EXPOSURE_LABEL_TEXT: Record<string, string> = {
  observed_from_sentra_sensor: "Observado desde el sensor de Sentra",
  lan_reachable: "Alcanzable en la LAN",
  agent_listening: "El agente lo ve escuchando",
  not_observed_from_sensor: "No observado desde el sensor",
  internet_exposure_confirmed: "Exposición a Internet confirmada (contexto)",
  internet_not_exposed: "No expuesto a Internet (contexto)",
  internet_exposure_unknown: "Exposición a Internet desconocida",
  no_service_port_declared: "El catálogo no declara puertos de servicio",
};

export const ACTION_LABELS: Record<FindingAction, string> = {
  acknowledge: "Reconocer",
  mitigating: "En mitigación",
  resolve: "Resolver",
  "accept-risk": "Aceptar riesgo",
  "false-positive": "Falso positivo",
  reopen: "Reabrir",
};

/** Acciones que exigen un motivo escrito (el resto lo admite opcional). */
export const REASON_REQUIRED: ReadonlySet<FindingAction> = new Set<FindingAction>([
  "resolve",
  "accept-risk",
  "false-positive",
  "reopen",
]);

export const RESOLUTION_LABELS: Record<string, string> = {
  resolved_by_inventory_change: "La versión instalada ya no es vulnerable",
  resolved_by_component_removal: "El componente desapareció del inventario",
  resolved_by_catalog_update: "El catálogo dejó de considerarlo afectado",
  manual: "Resuelta manualmente",
};

export const LIMITATION_LABELS: Record<string, string> = {
  no_agent: "Sin agente: no hay inventario de software que evaluar.",
  windows_build_without_patch_revision:
    "El agente no informa la revisión de parche (UBR) de Windows: las vulnerabilidades del SO no se confirman.",
  linux_distribution_release_unknown:
    "Se desconoce la versión de la distribución Linux: los paquetes se marcan como probables (backports).",
  inventory_completeness_unknown: "Agente antiguo: no indica si el inventario está completo.",
  inventory_incomplete: "El último inventario llegó incompleto: no se resuelve nada por ausencia.",
};

export const HISTORY_LABELS: Record<string, string> = {
  created: "Detectada",
  version_changed: "Cambio de versión instalada",
  match_changed: "Cambio de evidencia",
  severity_changed: "Cambio de severidad (catálogo)",
  exposure_changed: "Cambio de exposición",
  resolved: "Resuelta",
  reopened: "Reabierta",
  risk_acceptance_expired: "Aceptación de riesgo vencida",
  acknowledged: "Reconocida",
  mitigating: "En mitigación",
  risk_accepted: "Riesgo aceptado",
  false_positive: "Falso positivo",
  incident_created: "Incidente creado",
  kev_changed: "Cambio de explotación conocida (KEV)",
};

/** Software instalado → texto de la columna "Vulnerabilidades conocidas". */
export function knownVulnerabilitiesText(count: number): string {
  return count === 1 ? "1 vulnerabilidad conocida" : `${count} vulnerabilidades conocidas`;
}

/**
 * Solo enlaces http/https: el catálogo es un fichero importado y el servidor ya lo valida,
 * pero se comprueba otra vez al pintar (defensa en profundidad contra javascript:, data:...).
 */
export function safeReference(url: string): string | null {
  if (url.length > 2048) return null;
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
    if (parsed.username || parsed.password) return null;
    return parsed.href;
  } catch {
    return null;
  }
}

export interface FindingConflict {
  currentVersion: number | null;
  status: string | null;
}

/** Datos del 409 vulnerability_conflict (otra persona o la evaluación cambió el finding). */
export function findingConflict(error: unknown): FindingConflict | null {
  if (!(error instanceof ApiError) || error.code !== "vulnerability_conflict") return null;
  const first: unknown = Array.isArray(error.details) ? error.details[0] : undefined;
  const detail = typeof first === "object" && first !== null ? (first as Record<string, unknown>) : {};
  return {
    currentVersion: typeof detail.version === "number" ? detail.version : null,
    status: typeof detail.status === "string" ? detail.status : null,
  };
}

/** Puntuación CVSS con su versión ("9.8 (v3.1)"), o "—". */
export function formatCvss(score: number | null, version: string | null): string {
  if (score == null) return "—";
  return version ? `${score.toFixed(1)} (v${version})` : score.toFixed(1);
}
