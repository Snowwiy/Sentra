import { useId, useState } from "react";
import type { RiskHistoryPoint } from "../../api/types";
import { areaPath, linePath } from "../../lib/charts";

const WIDTH = 640;
const HEIGHT = 200;
const PAD = { top: 12, right: 12, bottom: 24, left: 34 };
const PLOT_W = WIDTH - PAD.left - PAD.right;
const PLOT_H = HEIGHT - PAD.top - PAD.bottom;
/** El score de riesgo va de 0 a 100: escala fija para que dos periodos se comparen a simple vista. */
const Y_MAX = 100;
const GRID = [0, 25, 50, 75, 100];

export const HISTORY_DAYS = [7, 30, 90] as const;
export type HistoryDays = (typeof HISTORY_DAYS)[number];

/** Día UTC tal como lo agrega el servidor ("24 oct"). */
export function formatDay(iso: string): string {
  return new Date(iso).toLocaleDateString("es-ES", { day: "numeric", month: "short", timeZone: "UTC" });
}

function xFor(index: number, count: number): number {
  return PAD.left + (count <= 1 ? PLOT_W / 2 : (index / (count - 1)) * PLOT_W);
}

function yFor(score: number): number {
  return PAD.top + PLOT_H - (Math.min(Math.max(score, 0), Y_MAX) / Y_MAX) * PLOT_H;
}

/**
 * Evolución del riesgo medio (Fase 7A.7): una sola serie en un solo eje (score medio 0-100).
 * Los recuentos de activos altos y críticos tienen otra escala: van en la tabla y en el
 * detalle de cada día, nunca en un segundo eje. Un día sin activos evaluados corta la línea.
 */
export function RiskHistoryChart({
  points,
  days,
  onDays,
  busy = false,
}: {
  points: RiskHistoryPoint[];
  days: HistoryDays;
  onDays: (days: HistoryDays) => void;
  busy?: boolean;
}) {
  const headingId = useId();
  const [hover, setHover] = useState<number | null>(null);
  const scored = points.filter((point) => point.average_score !== null);
  const series = points.map((point, index) => ({
    x: xFor(index, points.length),
    y: point.average_score === null ? null : yFor(point.average_score),
  }));
  const last = scored.at(-1);
  const first = scored[0];
  const summary =
    first && last
      ? `Riesgo medio de los últimos ${days} días: de ${first.average_score} el ${formatDay(first.day)} a ${last.average_score} el ${formatDay(last.day)}`
      : "Riesgo medio: sin datos en el periodo";
  const active = hover === null ? null : points[hover];
  const tickIndexes = points.length > 1 ? [0, Math.floor((points.length - 1) / 2), points.length - 1] : [0];

  return (
    <figure className="chart-card chart-card--wide" aria-labelledby={headingId}>
      <div className="chart-card__head">
        <h3 id={headingId} className="chart-card__title">
          Evolución del riesgo medio
        </h3>
        <div className="segmented" role="group" aria-label="Periodo del historial">
          {HISTORY_DAYS.map((option) => (
            <button
              key={option}
              type="button"
              className={`segmented__item${option === days ? " segmented__item--active" : ""}`}
              aria-pressed={option === days}
              disabled={busy}
              onClick={() => onDays(option)}
            >
              {option} días
            </button>
          ))}
        </div>
      </div>
      {scored.length === 0 ? (
        <p className="muted small chart-card__empty">
          Sin historial de riesgo en este periodo: ningún activo actual tenía riesgo calculado. No se dibuja una línea de
          ceros porque no es un dato.
        </p>
      ) : (
        <div className="line-chart">
          <p className="line-chart__readout small" aria-live="polite">
            {active
              ? `${formatDay(active.day)}: ${
                  active.average_score === null ? "sin datos" : `media ${active.average_score}`
                } · ${active.assets_scored} evaluados · ${active.high} altos · ${active.critical} críticos`
              : last && `Último día: media ${last.average_score} · ${last.high} altos · ${last.critical} críticos`}
          </p>
          <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} className="line-chart__svg" role="img" aria-label={summary}>
            {GRID.map((value) => (
              <g key={value}>
                <line className="line-chart__grid" x1={PAD.left} x2={WIDTH - PAD.right} y1={yFor(value)} y2={yFor(value)} />
                <text className="chart-axis" x={PAD.left - 6} y={yFor(value) + 4} textAnchor="end">
                  {value}
                </text>
              </g>
            ))}
            {tickIndexes.map((index) => (
              <text
                key={index}
                className="chart-axis"
                x={xFor(index, points.length)}
                y={HEIGHT - 6}
                textAnchor={index === 0 ? "start" : index === points.length - 1 ? "end" : "middle"}
              >
                {formatDay(points[index]?.day ?? "")}
              </text>
            ))}
            <path className="line-chart__area" d={areaPath(series, yFor(0))} />
            <path className="line-chart__line" d={linePath(series)} />
            {active && active.average_score !== null && hover !== null && (
              <g aria-hidden="true">
                <line
                  className="line-chart__crosshair"
                  x1={xFor(hover, points.length)}
                  x2={xFor(hover, points.length)}
                  y1={PAD.top}
                  y2={PAD.top + PLOT_H}
                />
                <circle
                  className="line-chart__marker"
                  cx={xFor(hover, points.length)}
                  cy={yFor(active.average_score)}
                  r={4.5}
                />
              </g>
            )}
            {/* Zonas de hover más anchas que la marca: una franja por día. */}
            {points.map((point, index) => {
              const step = points.length > 1 ? PLOT_W / (points.length - 1) : PLOT_W;
              return (
                <rect
                  key={point.day}
                  className="line-chart__hit"
                  x={xFor(index, points.length) - step / 2}
                  y={PAD.top}
                  width={step}
                  height={PLOT_H}
                  onMouseEnter={() => setHover(index)}
                  onMouseLeave={() => setHover(null)}
                />
              );
            })}
          </svg>
        </div>
      )}
      {points.length > 0 && (
        <details className="chart-card__table">
          <summary>Ver los datos en tabla</summary>
          <div className="table-wrap">
            <table className="table table--compact">
              <thead>
                <tr>
                  <th scope="col">Día (UTC)</th>
                  <th scope="col">Activos evaluados</th>
                  <th scope="col">Riesgo medio</th>
                  <th scope="col">Altos</th>
                  <th scope="col">Críticos</th>
                </tr>
              </thead>
              <tbody>
                {points.map((point) => (
                  <tr key={point.day}>
                    <td>{formatDay(point.day)}</td>
                    <td className="num">{point.assets_scored}</td>
                    <td className="num">{point.average_score ?? "sin datos"}</td>
                    <td className="num">{point.high}</td>
                    <td className="num">{point.critical}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      )}
    </figure>
  );
}
