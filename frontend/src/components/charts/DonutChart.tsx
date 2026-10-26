import { useId, useState } from "react";
import { Link } from "react-router-dom";
import { donutSegments, formatShare, sliceTotal, type ChartSlice } from "../../lib/charts";

const SIZE = 132;
const STROKE = 18;
const RADIUS = (SIZE - STROKE) / 2;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

/**
 * Gráfico de anillo con su tabla (Fase 7A.7). El SVG es solo la figura: la leyenda es una
 * tabla con etiqueta, valor y porcentaje, que es lo que leen los lectores de pantalla y lo
 * que sostiene el significado sin depender del color. Pasar el ratón (o el foco por la
 * leyenda) resalta el sector.
 */
export function DonutChart({
  title,
  slices,
  emptyText,
  centerLabel = "total",
  note,
}: {
  title: string;
  slices: ChartSlice[];
  /** Qué significa no tener datos aquí (nunca se dibuja un anillo de ceros como si fuera dato). */
  emptyText: string;
  centerLabel?: string;
  note?: string;
}) {
  const headingId = useId();
  const [active, setActive] = useState<string | null>(null);
  const visible = slices.filter((slice) => slice.value > 0);
  const total = sliceTotal(visible);
  const segments = donutSegments(
    visible.map((slice) => slice.value),
    CIRCUMFERENCE,
  );
  const summary =
    total > 0
      ? `${title}: ${visible.map((slice) => `${slice.label} ${slice.value} (${formatShare(slice.value, total)})`).join(", ")}`
      : `${title}: sin datos`;

  return (
    <figure className="chart-card" aria-labelledby={headingId}>
      <h3 id={headingId} className="chart-card__title">
        {title}
      </h3>
      {total === 0 ? (
        <div className="chart-card__empty">
          <svg viewBox={`0 0 ${SIZE} ${SIZE}`} className="donut" aria-hidden="true">
            <circle className="donut__track" cx={SIZE / 2} cy={SIZE / 2} r={RADIUS} strokeWidth={STROKE} />
          </svg>
          <p className="muted small">{emptyText}</p>
        </div>
      ) : (
        <div className="chart-card__body">
          <svg viewBox={`0 0 ${SIZE} ${SIZE}`} className="donut" role="img" aria-label={summary}>
            <circle className="donut__track" cx={SIZE / 2} cy={SIZE / 2} r={RADIUS} strokeWidth={STROKE} />
            {/* Rotado -90 grados: el primer sector empieza a las 12 en punto. */}
            <g transform={`rotate(-90 ${SIZE / 2} ${SIZE / 2})`}>
              {visible.map((slice, index) => {
                const segment = segments[index] ?? { length: 0, offset: 0 };
                const dimmed = active !== null && active !== slice.key;
                return (
                  <circle
                    key={slice.key}
                    className={`donut__slice${dimmed ? " donut__slice--dimmed" : ""}`}
                    cx={SIZE / 2}
                    cy={SIZE / 2}
                    r={RADIUS}
                    strokeWidth={active === slice.key ? STROKE + 4 : STROKE}
                    stroke={slice.color}
                    strokeDasharray={`${segment.length} ${CIRCUMFERENCE}`}
                    strokeDashoffset={-segment.offset}
                    onMouseEnter={() => setActive(slice.key)}
                    onMouseLeave={() => setActive(null)}
                  >
                    <title>{`${slice.label}: ${slice.value} (${formatShare(slice.value, total)})`}</title>
                  </circle>
                );
              })}
            </g>
            <text x="50%" y="48%" textAnchor="middle" className="donut__total">
              {total}
            </text>
            <text x="50%" y="62%" textAnchor="middle" className="donut__caption">
              {centerLabel}
            </text>
          </svg>
          <table className="chart-legend">
            <caption className="sr-only">{title}</caption>
            <thead className="sr-only">
              <tr>
                <th scope="col">Categoría</th>
                <th scope="col">Valor</th>
                <th scope="col">Porcentaje</th>
              </tr>
            </thead>
            <tbody>
              {visible.map((slice) => (
                <tr
                  key={slice.key}
                  className={active === slice.key ? "chart-legend__row--active" : undefined}
                  onMouseEnter={() => setActive(slice.key)}
                  onMouseLeave={() => setActive(null)}
                  onFocus={() => setActive(slice.key)}
                  onBlur={() => setActive(null)}
                >
                  <th scope="row">
                    <span className="chart-legend__swatch" style={{ background: slice.color }} aria-hidden="true" />
                    {slice.href ? <Link to={slice.href}>{slice.label}</Link> : slice.label}
                  </th>
                  <td className="num">{slice.value}</td>
                  <td className="num muted">{formatShare(slice.value, total)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {note && <figcaption className="muted small">{note}</figcaption>}
    </figure>
  );
}
