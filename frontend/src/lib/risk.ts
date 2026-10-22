import type {
  AssetCriticality,
  RiskConfidence,
  RiskContribution,
  RiskLevel,
  RiskLevelRange,
  RiskNominalBreakdown,
  RiskSnapshot,
  RiskTrace,
} from "../api/types";

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
  vulnerability: "Vulnerabilidades",
  threat_intel: "Inteligencia de amenazas",
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

// --- Fase 6D.8: traza del cálculo ----------------------------------------------------------

const TRACE_KEYS: (keyof RiskTrace)[] = [
  "base_points",
  "criticality_factor",
  "type_factor",
  "context_factor",
  "raw_points",
  "saturation_knee",
  "saturated_points",
  "score",
  "formula_version",
];

const NOMINAL_KEYS: (keyof RiskNominalBreakdown)[] = [
  "severity_points",
  "confidence_factor",
  "occurrence_factor",
  "correlation_factor",
];

function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

/** `breakdown.trace` si existe y está completa; los cálculos anteriores a 6D no la tienen. */
export function riskTrace(breakdown: Record<string, unknown> | null | undefined): RiskTrace | null {
  const raw = breakdown?.["trace"];
  if (!raw || typeof raw !== "object") return null;
  const trace = raw as Record<string, unknown>;
  return TRACE_KEYS.every((key) => isFiniteNumber(trace[key])) ? (trace as unknown as RiskTrace) : null;
}

export interface NominalChain {
  severity: number;
  confidence: number;
  occurrences: number;
  correlation: number;
  recency: number | null;
  status: number | null;
  position: number | null;
  occurrenceCount: number | null;
  points: number;
}

/** Cadena de factores de una contribución de detección, o null si falta `nominal_breakdown`. */
export function nominalChain(item: RiskContribution): NominalChain | null {
  const raw = item.details["nominal_breakdown"];
  if (!raw || typeof raw !== "object") return null;
  const nominal = raw as Record<string, unknown>;
  if (!NOMINAL_KEYS.every((key) => isFiniteNumber(nominal[key]))) return null;
  const optional = (key: string): number | null => (isFiniteNumber(item.details[key]) ? (item.details[key] as number) : null);
  return {
    severity: nominal["severity_points"] as number,
    confidence: nominal["confidence_factor"] as number,
    occurrences: nominal["occurrence_factor"] as number,
    correlation: nominal["correlation_factor"] as number,
    recency: optional("recency_factor"),
    status: optional("status_factor"),
    position: optional("position_factor"),
    occurrenceCount: optional("occurrence_count"),
    points: item.points,
  };
}

/** Factor multiplicativo legible: "×1,5". */
export function formatFactor(value: number): string {
  return `×${value.toLocaleString("es-ES", { maximumFractionDigits: 3 })}`;
}

/** Puntos sin signo, con un decimal como máximo: "92,4". */
export function formatAmount(value: number): string {
  return value.toLocaleString("es-ES", { maximumFractionDigits: 1 });
}
