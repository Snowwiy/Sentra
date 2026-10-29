// Fase 7B.1: textos del veredicto de atribución (detalle y listado de detecciones).
import type { AttributionVerdict } from "../api/types";

export const VERDICT_LABELS: Record<AttributionVerdict, string> = {
  verified_benign: "Verificada como legítima",
  suspicious_unverified: "Sospechosa sin verificar",
  insufficient_evidence: "Evidencia insuficiente",
  confirmed_malicious: "Maliciosa confirmada",
};

export const VERDICT_CLASS: Record<AttributionVerdict, string> = {
  verified_benign: "badge--ok",
  suspicious_unverified: "badge--warn",
  insufficient_evidence: "badge--info",
  confirmed_malicious: "badge--crit",
};
