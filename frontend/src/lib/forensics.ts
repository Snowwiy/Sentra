// Presentación de la investigación forense remota (Fase 6E.6). Las acciones de recogida son
// las del catálogo de Response (agente, solo lectura); aquí solo se nombran en español.
import type { ArtifactIntegrity, InvestigationNoteKind, InvestigationStatus } from "../api/types";

export interface ForensicActionInfo {
  id: string;
  label: string;
  /** forensic_file_metadata: pide ruta y si se calcula el hash (MEDIUM: solo admin). */
  needsPath?: boolean;
}

export const FORENSIC_ACTIONS: ForensicActionInfo[] = [
  { id: "forensic_processes", label: "Procesos" },
  { id: "forensic_connections", label: "Conexiones de red" },
  { id: "forensic_services", label: "Servicios" },
  { id: "forensic_scheduled_tasks", label: "Tareas programadas" },
  { id: "forensic_persistence", label: "Mecanismos de persistencia" },
  { id: "forensic_sessions", label: "Sesiones de usuario" },
  { id: "forensic_network_config", label: "Configuración de red" },
  { id: "forensic_firewall_state", label: "Estado del firewall" },
  { id: "forensic_file_metadata", label: "Metadatos de un fichero", needsPath: true },
];

const ACTION_LABELS = new Map(FORENSIC_ACTIONS.map((a) => [a.id, a.label]));

export function forensicActionLabel(action: string): string {
  return ACTION_LABELS.get(action) ?? action;
}

export const INVESTIGATION_STATUS_LABELS: Record<InvestigationStatus, string> = {
  open: "Abierta",
  closed: "Cerrada",
};

export const INTEGRITY_LABELS: Record<ArtifactIntegrity, string> = {
  verified: "SHA-256 verificado",
  mismatch: "SHA-256 no coincide",
};

export const NOTE_KIND_LABELS: Record<InvestigationNoteKind, string> = {
  note: "Nota del analista",
  ai_summary: "Resumen de IA",
};

/** Ruta absoluta (Windows o POSIX) sin `..`: el servidor y el agente la vuelven a validar. */
export function validForensicPath(path: string): boolean {
  const value = path.trim();
  if (!value || value.length > 1024) return false;
  if (!/^(?:[A-Za-z]:[\\/]|\/)/.test(value)) return false;
  return !value.split(/[\\/]/).includes("..");
}

/** Contenido de un artefacto como texto: nunca se interpreta como HTML. */
export function artifactText(content: unknown): string {
  if (typeof content === "string") return content;
  try {
    return JSON.stringify(content, null, 2) ?? "";
  } catch {
    return String(content);
  }
}
