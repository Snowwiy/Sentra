import type { AssetCriticality, RiskConfidence, RiskLevel, RiskLevelRange, RiskSnapshot } from "../api/types";

export const RISK_LEVEL_LABELS: Record<RiskLevel, string> = {
  critical: "Crítico",
  high: "Alto",
  medium: "Medio",
  low: "Bajo",
  informational: "Informativo",
};

export const RISK_CONFIDENCE_LABELS: Record<RiskConfidence, string> = {
  high: "alta",
  medium: "media",
  low: "baja",
};

export const CRITICALITY_LABELS: Record<AssetCriticality, string> = {
  critical: "Crítica",
  high: "Alta",
  medium: "Media",
  low: "Baja",
};

// De mayor a menor, para selectores y tarjetas.
export const RISK_LEVEL_ORDER: RiskLevel[] = ["critical", "high", "medium", "low", "informational"];
export const RISK_CONFIDENCE_ORDER: RiskConfidence[] = ["high", "medium", "low"];
export const CRITICALITY_ORDER: AssetCriticality[] = ["critical", "high", "medium", "low"];

// Etiquetas de las categorías de contribución (reglas 4H, exposición y contexto).
export const RISK_CATEGORY_LABELS: Record<string, string> = {
  authentication: "Autenticación",
  account: "Cuentas",
  scripting: "Scripts",
  persistence: "Persistencia",
  process: "Procesos",
  network: "Red",
  defense: "Defensas",
  system: "Sistema",
  exposure: "Exposición",
  context: "Contexto del activo",
  unknown: "Otras",
};

const REASON_LABELS: Record<string, string> = {
  initial: "Primera evaluación",
  level_change: "Cambio de nivel",
  material_change: "Cambio material",
  new_contribution: "Nueva contribución",
  interval: "Actualización periódica",
};

export function reasonLabel(reason: string): string {
  return REASON_LABELS[reason] ?? reason;
}

/**
 * "82 / Crítico — confianza baja": la incertidumbre se muestra siempre junto al score, nunca
 * un número suelto.
 */
export function riskHeadline(score: number, level: RiskLevel, confidence: RiskConfidence): string {
  return `${score} / ${RISK_LEVEL_LABELS[level]} — confianza ${RISK_CONFIDENCE_LABELS[confidence]}`;
}

/** Diferencia de score con signo ("+12", "−5", "sin cambios"). */
export function formatDelta(delta: number | null | undefined): string {
  if (delta === null || delta === undefined) return "—";
  if (delta === 0) return "sin cambios";
  return delta > 0 ? `+${delta}` : `−${Math.abs(delta)}`;
}

export function formatPoints(points: number): string {
  const rounded = Math.round(points * 10) / 10;
  if (rounded === 0) return "0";
  const text = Math.abs(rounded).toLocaleString("es-ES", { maximumFractionDigits: 1 });
  return rounded > 0 ? `+${text}` : `−${text}`;
}

export interface TrendPoint {
  x: number;
  y: number;
}

/**
 * Coordenadas de una línea escalonada del riesgo en [0, width] x [0, height].
 *
 * El historial solo guarda cambios materiales, así que entre dos puntos el valor se mantiene
 * (escalón), no se interpola. Empieza en `startScore` (valor anterior al rango) si existe y
 * termina en `now` con el valor actual.
 */
export function trendPoints(
  points: Pick<RiskSnapshot, "calculated_at" | "score">[],
  options: { since: number; now: number; width: number; height: number; startScore: number | null; current: number | null },
): TrendPoint[] {
  const { since, now, width, height } = options;
  const span = Math.max(1, now - since);
  const x = (t: number) => ((Math.min(Math.max(t, since), now) - since) / span) * width;
  const y = (score: number) => height - (Math.min(Math.max(score, 0), 100) / 100) * height;
  const out: TrendPoint[] = [];
  let last: number | null = options.startScore;
  if (last !== null) out.push({ x: 0, y: y(last) });
  for (const point of points) {
    const t = Date.parse(point.calculated_at);
    if (last !== null) out.push({ x: x(t), y: y(last) });
    out.push({ x: x(t), y: y(point.score) });
    last = point.score;
  }
  const final = options.current ?? last;
  if (final !== null) {
    if (last !== null && final !== last) out.push({ x: width, y: y(last) });
    out.push({ x: width, y: y(final) });
  }
  return out;
}

/** Bandas de nivel para el fondo del gráfico (desde los umbrales del backend). */
export function levelBands(thresholds: RiskLevelRange[], height: number) {
  return thresholds.map((band) => ({
    level: band.level,
    y: height - ((band.max + (band.level === "critical" ? 0 : 1)) / 100) * height,
    h: ((band.max - band.min + (band.level === "critical" ? 0 : 1)) / 100) * height,
  }));
}
