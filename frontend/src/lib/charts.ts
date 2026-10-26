// Fase 7A.7: geometría y datos de los gráficos del Panel, sin dependencias. Los gráficos son
// SVG hechos a mano: aquí queda la parte calculable (porcentajes, segmentos, trazos) para
// probarla sin renderizar.

/** Un sector de un gráfico de anillo. El color lo decide quien llama según el significado. */
export interface ChartSlice {
  key: string;
  label: string;
  value: number;
  color: string;
  /** Enlace opcional a la lista ya filtrada (se ofrece en la leyenda, accesible con teclado). */
  href?: string;
}

/**
 * Colores categóricos para el fondo oscuro de Sentra, en orden fijo (nunca rotados): el orden
 * es el que mantiene distinguibles los vecinos con daltonismo. Validados contra --surface
 * (#0c1320) con el validador de paleta: banda de luminosidad, croma, separación CVD >= 8 y
 * contraste >= 3:1. Más de siete categorías se agrupan en "Otros".
 */
export const CATEGORICAL_COLORS = ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#008300", "#9085e9"];

/** Color categórico de la posición `index`; pasado el último se usa el gris neutro (nunca se rota). */
export function categoricalColor(index: number): string {
  return CATEGORICAL_COLORS[index] ?? NEUTRAL_COLOR;
}

/** Gris neutro para "Otros" y "Sin calcular": no compite con ninguna categoría. */
export const NEUTRAL_COLOR = "#66768e";

/**
 * Colores de estado (crítico, alto, medio, bajo, informativo). Llevan siempre la etiqueta al
 * lado en la leyenda: el color nunca es la única pista.
 */
export type SeverityKey = "critical" | "high" | "medium" | "low" | "informational";

export const SEVERITY_COLORS: Record<SeverityKey, string> = {
  critical: "#d03b3b",
  high: "#ec835a",
  medium: "#fab219",
  low: "#3987e5",
  informational: "#8d9db4",
};

export function sliceTotal(slices: readonly { value: number }[]): number {
  return slices.reduce((sum, slice) => sum + Math.max(0, slice.value), 0);
}

/** Porcentaje entero para mostrar; "<1 %" se decide al formatear, no aquí. */
export function share(value: number, total: number): number {
  return total > 0 ? (value / total) * 100 : 0;
}

export function formatShare(value: number, total: number): string {
  if (total <= 0 || value <= 0) return "0 %";
  const pct = share(value, total);
  if (pct < 1) return "<1 %";
  return `${Math.round(pct)} %`;
}

/**
 * Agrupa las categorías pequeñas en "Otros": como mucho `maxSlices` sectores (incluido
 * "Otros"), y además se agrupa todo lo que no llega a `minShare` (fracción del total). Se
 * ordena de mayor a menor para que el color siga a la categoría y no a su posición.
 */
export function groupSmallSlices(
  entries: readonly { key: string; label: string; value: number }[],
  { maxSlices = 7, minShare = 0.03, otherLabel = "Otros" }: { maxSlices?: number; minShare?: number; otherLabel?: string } = {},
): { key: string; label: string; value: number; grouped?: string[] }[] {
  const positive = entries.filter((entry) => entry.value > 0).sort((a, b) => b.value - a.value || a.label.localeCompare(b.label));
  const total = sliceTotal(positive);
  if (total === 0) return [];
  const kept: { key: string; label: string; value: number }[] = [];
  const rest: { key: string; label: string; value: number }[] = [];
  for (const entry of positive) {
    if (kept.length < maxSlices - 1 && entry.value / total >= minShare) kept.push(entry);
    else rest.push(entry);
  }
  // Un único resto no se convierte en "Otros": se muestra con su propio nombre.
  if (rest.length <= 1) return [...kept, ...rest];
  return [
    ...kept,
    { key: "__other__", label: otherLabel, value: sliceTotal(rest), grouped: rest.map((entry) => entry.label) },
  ];
}

/** Segmento de un anillo dibujado con stroke-dasharray sobre un círculo. */
export interface DonutSegment {
  /** Longitud visible del trazo. */
  length: number;
  /** Desplazamiento desde el inicio (las 12 en punto) a lo largo del círculo. */
  offset: number;
}

/**
 * Reparte la circunferencia entre los valores, dejando `gap` de separación entre sectores
 * vecinos (el hueco de 2 px que los distingue sin depender del color). Un sector único ocupa
 * el anillo entero, sin hueco. Los valores no positivos dan segmentos de longitud 0.
 */
export function donutSegments(values: readonly number[], circumference: number, gap = 2): DonutSegment[] {
  const total = sliceTotal(values.map((value) => ({ value })));
  if (total <= 0) return values.map(() => ({ length: 0, offset: 0 }));
  const visible = values.filter((value) => value > 0).length;
  const usedGap = visible > 1 ? gap : 0;
  let cursor = 0;
  return values.map((value) => {
    if (value <= 0) return { length: 0, offset: cursor };
    const arc = (value / total) * circumference;
    const segment = { length: Math.max(arc - usedGap, Math.min(arc, 0.5)), offset: cursor };
    cursor += arc;
    return segment;
  });
}

export interface SeriesPoint {
  x: number;
  y: number | null;
}

/**
 * Trazo de una línea en coordenadas SVG. Un punto sin valor (null) corta la línea: nunca se
 * interpola un día sin datos como si los tuviera.
 */
export function linePath(points: readonly SeriesPoint[]): string {
  let path = "";
  let open = false;
  for (const point of points) {
    if (point.y === null) {
      open = false;
      continue;
    }
    path += `${open ? "L" : "M"}${round(point.x)},${round(point.y)}`;
    open = true;
  }
  return path;
}

/** Área bajo la línea hasta `baseline`, un polígono por cada tramo continuo. */
export function areaPath(points: readonly SeriesPoint[], baseline: number): string {
  const runs: SeriesPoint[][] = [];
  let run: SeriesPoint[] = [];
  for (const point of points) {
    if (point.y === null) {
      if (run.length) runs.push(run);
      run = [];
    } else run.push(point);
  }
  if (run.length) runs.push(run);
  return runs
    .map((segment) => {
      const first = segment[0];
      const last = segment[segment.length - 1];
      if (!first || !last) return "";
      const top = segment.map((point) => `L${round(point.x)},${round(point.y as number)}`).join("");
      return `M${round(first.x)},${round(baseline)}${top}L${round(last.x)},${round(baseline)}Z`;
    })
    .join("");
}

function round(value: number): number {
  return Math.round(value * 10) / 10;
}
