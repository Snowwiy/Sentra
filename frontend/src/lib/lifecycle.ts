// Fase 5C.1/5C.2: textos y utilidades del ciclo de vida de activos (archivar, borrar,
// duplicados, reconciliación y limpieza). Sin estado ni llamadas a la API.
import { ApiError } from "../api/client";
import type {
  CleanupAction,
  DuplicateConfidence,
  DuplicateConflict,
  DuplicateEvidence,
  DuplicateReason,
  EvidenceStrength,
  LifecycleSource,
  ReconcileBlocker,
  ReconcileWarning,
  SourceDisposition,
} from "../api/types";

// Textos exactos de la especificación (Fase 5C.1).
export const DELETE_CONFIRMATION =
  "Este activo descubierto no tiene historial gestionado y será eliminado permanentemente.";
export const DELETE_REFUSED = "No se puede eliminar porque contiene historial.";
export const REENROLL_HINT = "Este agente parece corresponder a un activo existente.";

// Fase 5C.2.
export const NOT_YET_DELETABLE = "Todavía no se puede eliminar definitivamente.";
export const IRREVERSIBLE_WARNING =
  "Acción irreversible: el activo y sus datos asociados se borran definitivamente y no se pueden recuperar.";
export const ACK_WEAK_EVIDENCE =
  "Entiendo que la evidencia es débil o contradictoria y confirmo que es la misma máquina";
export const NOT_CONFIRMED_HINT = "Posible duplicado, no confirmado: revisa la evidencia antes de actuar.";

export const DUPLICATE_REASON_LABELS: Record<DuplicateReason, string> = {
  same_machine_id: "misma identidad de máquina",
  same_hostname: "mismo hostname",
  same_ip: "misma IP",
  same_mac: "misma MAC",
  same_agent_lineage: "mismo linaje de agente",
  same_random_mac: "misma MAC aleatoria",
  same_os: "mismo sistema operativo",
};

export const CONFIDENCE_LABELS: Record<DuplicateConfidence, string> = {
  high: "Confianza alta",
  medium: "Confianza media",
  low: "Confianza baja",
};

export const CONFIDENCE_CLASSES: Record<DuplicateConfidence, string> = {
  high: "badge--crit",
  medium: "badge--warn",
  low: "badge--muted",
};

export const STRENGTH_LABELS: Record<EvidenceStrength, string> = {
  strong: "fuerte",
  medium: "media",
  weak: "débil",
};

export const STRENGTH_CLASSES: Record<EvidenceStrength, string> = {
  strong: "badge--info",
  medium: "badge--warn",
  weak: "badge--muted",
};

export const CONFLICT_LABELS: Record<DuplicateConflict, string> = {
  machine_id_mismatch: "identidades de máquina distintas",
};

export const RECONCILE_BLOCKER_LABELS: Record<ReconcileBlocker, string> = {
  same_asset: "es el mismo activo",
  source_without_agent: "el activo origen no tiene agente",
  source_archived: "el activo origen está archivado",
  target_never_managed: "el destino nunca tuvo agente",
  target_agent_online: "el agente del destino sigue activo y en línea",
  platform_mismatch: "sistemas operativos distintos",
};

export const RECONCILE_WARNING_LABELS: Record<ReconcileWarning, string> = {
  insufficient_evidence: "evidencia débil (solo hostname, IP, MAC aleatoria o sistema operativo)",
  machine_id_mismatch: "identidades de máquina distintas",
};

/** Motivos de bloqueo del borrado (delete-check y vista previa de limpieza). */
export const BLOCKING_LABELS: Record<string, string> = {
  managed_history: "tuvo un agente (historial gestionado)",
  agent_history: "telemetría, eventos o inventario de agente",
  detections: "detecciones de impacto medio o superior",
  incidents: "forma parte de incidentes",
  vulnerabilities: "vulnerabilidades evaluadas",
  threat_intel: "coincidencias de inteligencia de amenazas",
  audit_dependency: "contexto editado o análisis de IA",
  other: "alertas sin resolver",
  not_stale: "Aún no cumple la política de inactividad (escaneos completos perdidos y tiempo).",
  purge_window_not_reached: "Está inactivo, pero todavía no ha pasado la ventana de purga.",
  monitored_source: "Los activos monitorizados sin agente no se borran físicamente.",
  agent_active: "su agente tiene la credencial activa",
};

/** Motivos por los que la limpieza omitió un activo, además de los de bloqueo. */
const SKIP_LABELS: Record<string, string> = {
  not_found: "ya no existe",
  version_conflict: "cambió desde la vista previa (recarga y revisa)",
  already_archived: "ya estaba archivado",
};

/** Bloqueos que solo dependen de la inactividad (no de historial que conservar). */
const LIFECYCLE_ONLY_BLOCKERS = new Set(["not_stale", "purge_window_not_reached", "monitored_source"]);

export const SOURCE_LABELS: Record<LifecycleSource, string> = {
  discovered: "Descubierto",
  monitored: "Monitorizado",
  managed: "Gestionado",
};

export const CLEANUP_ACTION_LABELS: Record<CleanupAction, string> = {
  keep: "Mantener",
  mark_stale: "Stale",
  archive_candidate: "Candidato a archivar",
  hard_delete_eligible: "Eliminable",
  blocked: "Bloqueado",
};

export const CLEANUP_ACTION_ORDER: CleanupAction[] = [
  "mark_stale",
  "archive_candidate",
  "hard_delete_eligible",
  "blocked",
  "keep",
];

export const DISPOSITION_LABELS: Record<SourceDisposition, string> = {
  source_archived: "El activo origen queda archivado, con lo poco que llegó a enviar su agente.",
  source_deleted: "El activo origen se elimina: no tiene historial propio que conservar.",
};

/** Nombres en español de los recuentos de historial y dependencias. */
const HISTORY_LABELS: Record<string, string> = {
  telemetry: "telemetría",
  events: "eventos",
  inventory: "inventarios",
  inventories: "inventarios",
  processes: "procesos",
  detections: "detecciones",
  incidents: "incidentes",
  alerts: "alertas",
  changes: "cambios",
  ports: "puertos",
  risk_snapshots: "instantáneas de riesgo",
  vulnerabilities: "vulnerabilidades",
  vulnerability_findings: "vulnerabilidades",
  threat_matches: "coincidencias de inteligencia",
  agents: "agentes",
  context: "contexto",
  ai_analyses: "análisis de IA",
};

/** Texto de un motivo (bloqueo, omisión o disposición); el código si no se conoce. */
export function reasonLabel(code: string): string {
  return BLOCKING_LABELS[code] ?? SKIP_LABELS[code] ?? code.replace(/_/g, " ");
}

export function reasonsText(reasons: DuplicateReason[]): string {
  return reasons.map((r) => DUPLICATE_REASON_LABELS[r] ?? r).join(", ");
}

export function evidenceText(evidence: DuplicateEvidence): string {
  return `${DUPLICATE_REASON_LABELS[evidence.code] ?? evidence.code} (${STRENGTH_LABELS[evidence.strength] ?? evidence.strength})`;
}

export function warningLabel(code: string): string {
  return RECONCILE_WARNING_LABELS[code as ReconcileWarning] ?? reasonLabel(code);
}

export function blockerLabel(code: string): string {
  return RECONCILE_BLOCKER_LABELS[code as ReconcileBlocker] ?? reasonLabel(code);
}

/** "12 eventos, 3 detecciones" con los recuentos distintos de cero; "nada" si no hay. */
export function historyText(counts: Record<string, number>): string {
  const parts = Object.entries(counts)
    .filter(([, n]) => n > 0)
    .map(([key, n]) => `${n >= 10000 ? "≥10000" : n} ${HISTORY_LABELS[key] ?? key.replace(/_/g, " ")}`);
  return parts.length > 0 ? parts.join(", ") : "nada";
}

/** El borrado está bloqueado por historial (y no solo por la política de inactividad). */
export function blockedByHistory(reasons: string[]): boolean {
  return reasons.some((r) => !LIFECYCLE_ONLY_BLOCKERS.has(r));
}

/** "36 h" o "4 d" desde horas; "—" si no se sabe. */
export function formatHours(hours: number | null | undefined): string {
  if (hours === null || hours === undefined) return "—";
  if (hours < 48) return `${Math.round(hours)} h`;
  return `${Math.floor(hours / 24)} d`;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isAssetId(value: string): boolean {
  return UUID.test(value.trim());
}

/** El 409 de reconciliar pide aceptar explícitamente la evidencia débil o contradictoria. */
export function needsAcknowledgement(error: unknown): boolean {
  if (!(error instanceof ApiError) || error.code !== "asset_reconcile_refused") return false;
  const details = Array.isArray(error.details) ? error.details : [];
  return details.some(
    (d) => typeof d === "object" && d !== null && (d as { requires_acknowledgement?: unknown }).requires_acknowledgement === true,
  );
}

/** Mensaje en español para los 409 del ciclo de vida (la API los da en inglés). */
export function lifecycleError(error: unknown): Error {
  if (error instanceof ApiError) {
    switch (error.code) {
      case "asset_lifecycle_conflict":
        return new Error("El activo cambió mientras tanto. Recarga la página y vuelve a intentarlo.");
      case "asset_state_conflict":
        return new Error(
          "No se puede en su estado actual (¿agente con credencial activa o ya archivado?). Revoca el agente en Agentes antes de archivar.",
        );
      case "asset_not_deletable":
        return new Error(DELETE_REFUSED);
      case "asset_reconcile_refused":
        return new Error(
          needsAcknowledgement(error)
            ? "La evidencia es débil o contradictoria: el servidor exige que confirmes explícitamente que es la misma máquina."
            : "El servidor no ve evidencia suficiente para reconciliar estos activos.",
        );
    }
    return error;
  }
  return error instanceof Error ? error : new Error(String(error));
}
