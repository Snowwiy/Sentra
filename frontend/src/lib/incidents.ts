// Utilidades de Incident Management (Fase 4K): etiquetas en español y helpers puros.
//
// La UI no decide nada del flujo: las transiciones permitidas vienen del servidor
// (`allowed_transitions`) y cada acción vuelve a validarse allí con la `version` leída.
import type {
  IncidentConfidence,
  IncidentLevel,
  IncidentStatus,
  ResolutionCategory,
  TimelineSource,
} from "../api/types";
import { ApiError } from "../api/client";

export const STATUS_LABELS: Record<IncidentStatus, string> = {
  open: "Abierto",
  triage: "Triage",
  investigating: "Investigando",
  contained: "Contenido",
  resolved: "Resuelto",
  closed: "Cerrado",
  merged: "Fusionado",
};

export const LEVEL_LABELS: Record<IncidentLevel, string> = {
  critical: "Crítica",
  high: "Alta",
  medium: "Media",
  low: "Baja",
};

export const CONFIDENCE_LABELS: Record<IncidentConfidence, string> = {
  high: "Alta",
  medium: "Media",
  low: "Baja",
};

export const RESOLUTION_LABELS: Record<ResolutionCategory, string> = {
  true_positive: "Verdadero positivo",
  false_positive: "Falso positivo",
  benign_activity: "Actividad legítima",
  duplicate: "Duplicado",
  accepted_risk: "Riesgo aceptado",
  other: "Otro",
};

export const LEVEL_ORDER: IncidentLevel[] = ["critical", "high", "medium", "low"];
export const STATUS_ORDER: IncidentStatus[] = [
  "open",
  "triage",
  "investigating",
  "contained",
  "resolved",
  "closed",
  "merged",
];
export const RESOLUTION_ORDER: ResolutionCategory[] = [
  "true_positive",
  "false_positive",
  "benign_activity",
  "duplicate",
  "accepted_risk",
  "other",
];

/** Motivos de una sugerencia de incidente relacionado (deduplicación asistida, no automática). */
export const REASON_LABELS: Record<string, string> = {
  already_linked: "ya vinculada",
  evidence_overlap: "evidencia compartida",
  same_asset: "mismo activo",
  same_rule: "misma regla",
  correlation: "correlación",
  same_account: "misma cuenta",
  time_window: "misma ventana temporal",
};

export const SOURCE_LABELS: Record<TimelineSource, string> = {
  incident: "Caso",
  note: "Nota",
  event: "Evento",
  detection: "Detección",
  correlation: "Correlación",
  alert: "Alerta",
  risk: "Riesgo",
  ai_insight: "IA",
};

export const ACTION_LABELS: Record<string, string> = {
  created: "Creado",
  updated: "Actualizado",
  status_changed: "Cambio de estado",
  assigned: "Asignado",
  unassigned: "Sin asignar",
  note_added: "Nota",
  detection_attached: "Detección adjunta",
  alert_attached: "Alerta adjunta",
  asset_added: "Activo añadido",
  resolved: "Resuelto",
  closed: "Cerrado",
  reopened: "Reabierto",
  merged: "Fusionado",
  merged_into: "Fusionado en otro",
  risk_snapshot: "Snapshot de riesgo",
};

/** Estados activos: el caso sigue vivo y admite trabajo. */
export function isActive(status: IncidentStatus): boolean {
  return status === "open" || status === "triage" || status === "investigating" || status === "contained";
}

/** Duración observada en texto corto ("3 d 4 h", "25 min"); "—" si no aplica. */
export function formatDuration(seconds: number | null | undefined): string {
  if (seconds == null) return "—";
  if (seconds < 60) return `${Math.max(0, Math.round(seconds))} s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} min`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} h ${minutes % 60} min`;
  return `${Math.floor(hours / 24)} d ${hours % 24} h`;
}

export interface ConflictInfo {
  currentVersion: number | null;
  updatedBy: string | null;
  status: string | null;
}

/** Datos del 409 incident_conflict (quién y qué versión ganó); null si es otro error. */
export function conflictInfo(error: unknown): ConflictInfo | null {
  if (!(error instanceof ApiError) || error.code !== "incident_conflict") return null;
  const first: unknown = Array.isArray(error.details) ? error.details[0] : undefined;
  const detail = typeof first === "object" && first !== null ? (first as Record<string, unknown>) : {};
  return {
    currentVersion: typeof detail.current_version === "number" ? detail.current_version : null,
    updatedBy: typeof detail.updated_by === "string" ? detail.updated_by : null,
    status: typeof detail.status === "string" ? detail.status : null,
  };
}

/** Incidente abierto al que ya está vinculada la detección/alerta (409 incident_already_linked). */
export function linkedIncident(error: unknown): { incidentId: string; key: string } | null {
  if (!(error instanceof ApiError) || error.code !== "incident_already_linked") return null;
  const first: unknown = Array.isArray(error.details) ? error.details[0] : undefined;
  if (typeof first !== "object" || first === null) return null;
  const { incident_id: incidentId, key } = first as Record<string, unknown>;
  return typeof incidentId === "string" && typeof key === "string" ? { incidentId, key } : null;
}
