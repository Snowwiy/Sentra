// Presentación del aislamiento seguro (Fase 6E.7). La UI nunca decide si un equipo se puede
// aislar: muestra lo que devuelve el servidor (disponible, motivos, impacto, límites).
import type { IsolationStatus } from "../api/types";

/** Texto exacto para cualquier equipo que no admite aislamiento (sin agente, macOS, sin helper). */
export const ISOLATION_UNAVAILABLE = "Aislamiento no disponible para este dispositivo";

export const ISOLATION_STATUS_LABELS: Record<IsolationStatus, string> = {
  requested: "Solicitado",
  approved: "Aprobado",
  applying: "Aplicándose",
  isolated: "Aislado",
  reverting: "Revirtiéndose",
  restored: "Restaurado",
  failed: "Fallido",
  expired: "Expirado",
  unknown: "Estado desconocido",
};

export const ISOLATION_STATUS_BADGES: Record<IsolationStatus, string> = {
  requested: "badge badge--info",
  approved: "badge badge--info",
  applying: "badge badge--warn",
  isolated: "badge badge--crit",
  reverting: "badge badge--warn",
  restored: "badge badge--ok",
  failed: "badge badge--crit",
  expired: "badge badge--muted",
  unknown: "badge badge--warn",
};

/** Estados en los que la sesión sigue viva (se puede liberar). */
const LIVE: ReadonlySet<IsolationStatus> = new Set(["requested", "approved", "applying", "isolated", "reverting", "unknown"]);

export function isLiveIsolation(status: IsolationStatus): boolean {
  return LIVE.has(status);
}

/** Mínimo del motivo (IsolationRequest.reason) y de la liberación (ReleaseRequest.reason). */
export const ISOLATION_REASON_MIN = 10;
export const RELEASE_REASON_MIN = 3;
export const REASON_MAX = 500;

export interface IsolationFormInput {
  confirmName: string;
  expectedName: string;
  reason: string;
  minutes: string;
  maxMinutes: number;
}

/**
 * Errores de validación del diálogo de aislamiento (vacío = se puede enviar). El nombre se
 * compara exacto (sin recortar ni ignorar mayúsculas): es la confirmación escrita.
 */
export function validateIsolation(input: IsolationFormInput): string[] {
  const errors: string[] = [];
  if (input.confirmName !== input.expectedName) {
    errors.push("Escribe exactamente el nombre del equipo para confirmar.");
  }
  const reason = input.reason.trim();
  if (reason.length < ISOLATION_REASON_MIN) {
    errors.push(`Indica un motivo de al menos ${ISOLATION_REASON_MIN} caracteres.`);
  } else if (reason.length > REASON_MAX) {
    errors.push(`El motivo puede tener como máximo ${REASON_MAX} caracteres.`);
  }
  const minutes = Number(input.minutes);
  if (!/^\d+$/.test(input.minutes.trim()) || !Number.isInteger(minutes) || minutes < 1) {
    errors.push("La duración debe ser un número entero de minutos.");
  } else if (minutes > input.maxMinutes) {
    errors.push(`La duración no puede superar ${input.maxMinutes} minutos.`);
  }
  return errors;
}
