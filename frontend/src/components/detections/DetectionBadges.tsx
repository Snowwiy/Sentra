import type { DetectionConfidence, DetectionSeverity, DetectionStatus } from "../../api/types";

export const SEVERITY_LABELS: Record<DetectionSeverity, string> = {
  critical: "Crítica",
  high: "Alta",
  medium: "Media",
  low: "Baja",
  informational: "Informativa",
};

export const CONFIDENCE_LABELS: Record<DetectionConfidence, string> = {
  high: "Alta",
  medium: "Media",
  low: "Baja",
};

export const STATUS_LABELS: Record<DetectionStatus, string> = {
  open: "Abierta",
  acknowledged: "Reconocida",
  resolved: "Resuelta",
};

export const CATEGORY_LABELS: Record<string, string> = {
  authentication: "Autenticación",
  account: "Cuentas",
  scripting: "PowerShell / scripts",
  persistence: "Servicios / persistencia",
  process: "Procesos",
  network: "Red / exposición",
  defense: "Controles de defensa",
  system: "Sistema",
};

// Orden de mayor a menor para los selectores de filtro.
export const SEVERITY_ORDER: DetectionSeverity[] = ["critical", "high", "medium", "low", "informational"];
export const CONFIDENCE_ORDER: DetectionConfidence[] = ["high", "medium", "low"];

/** Severidad = impacto si la detección es cierta. */
export function DetectionSeverityBadge({ severity }: { severity: DetectionSeverity }) {
  return (
    <span className={`dseverity dseverity--${severity}`} title="Severidad (impacto)">
      {SEVERITY_LABELS[severity]}
    </span>
  );
}

/**
 * Confianza = cuánto respalda la evidencia la conclusión. Se muestra aparte de la severidad
 * a propósito: una detección crítica con confianza baja pide verificar antes de actuar.
 */
export function ConfidenceBadge({ confidence }: { confidence: DetectionConfidence }) {
  return (
    <span className={`dconfidence dconfidence--${confidence}`} title="Confianza (evidencia)">
      {CONFIDENCE_LABELS[confidence]}
    </span>
  );
}

export function DetectionStatusBadge({ status }: { status: DetectionStatus }) {
  return <span className={`dstatus dstatus--${status}`}>{STATUS_LABELS[status]}</span>;
}
