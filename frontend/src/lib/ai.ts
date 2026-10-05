// Utilidades de AI Security Insights (Fase 4J): etiquetas y enlaces a datos de Sentra.
import type { Certainty, EvidenceRef, Insight, InsightKind } from "../api/types";

export const KIND_LABELS: Record<InsightKind, string> = {
  asset_summary: "Resumen de activo",
  detection_analysis: "Análisis de detección",
  risk_explanation: "Explicación de riesgo",
  soc_summary: "Resumen SOC",
  ask: "Ask Sentra AI",
  incident_summary: "Resumen de incidente",
  incident_timeline: "Timeline de incidente",
  incident_evidence: "Evidencia de incidente",
  incident_next_steps: "Siguientes pasos de incidente",
};

// El lenguaje refleja la certeza: "posible" nunca se pinta igual que "detectado".
export const CERTAINTY_LABELS: Record<Certainty, string> = {
  observed: "Observado",
  detected: "Detectado",
  correlated: "Correlacionado",
  possible: "Posible",
  requires_validation: "Requiere validación",
};

export const REF_TYPE_LABELS: Record<string, string> = {
  asset: "Activo",
  detection: "Detección",
  event: "Evento",
  evidence: "Evidencia",
  exposure: "Exposición",
  risk_contribution: "Contribución de riesgo",
  risk_snapshot: "Historial de riesgo",
  alert: "Alerta",
  change: "Cambio",
  incident: "Incidente",
  note: "Nota del analista",
};

export const STALE_LABELS: Record<NonNullable<Insight["stale_reason"]>, string> = {
  expired: "caducado",
  data_changed: "los datos cambiaron",
  entity_deleted: "la entidad ya no existe",
};

/** Ruta interna del dato referenciado (solo rutas propias; nunca URLs del modelo). */
export function refLink(ref: EvidenceRef): string | null {
  const asset = ref.asset_id ? encodeURIComponent(ref.asset_id) : null;
  switch (ref.type) {
    case "detection":
      return `/detections/${encodeURIComponent(ref.id)}`;
    case "asset":
      return `/assets/${encodeURIComponent(ref.id)}`;
    case "incident":
      return `/incidents/${encodeURIComponent(ref.id)}`;
    case "risk_contribution":
    case "risk_snapshot":
      return asset ? `/assets/${asset}?tab=risk` : null;
    case "exposure":
      return asset ? `/assets/${asset}?tab=exposure` : null;
    case "event":
      return asset ? `/assets/${asset}?tab=events` : null;
    case "alert":
      return asset ? `/assets/${asset}?tab=alerts` : "/alerts";
    case "evidence":
    case "change":
      return asset ? `/assets/${asset}` : null;
    default:
      return null;
  }
}
