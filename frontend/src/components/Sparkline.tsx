import { formatPercent } from "../lib/format";

const WIDTH = 240;
const HEIGHT = 48;

/**
 * Minimal percentage trend line (0–100 fixed scale, so lines are comparable across metrics).
 * Plain SVG on purpose: a charting library is not justified for this until real charts exist.
 */
export function Sparkline({ label, values }: { label: string; values: number[] }) {
  const latest = values.at(-1);
  if (values.length < 2) {
    return (
      <div className="spark">
        <div className="spark__head">
          <span className="muted">{label}</span>
          <span>{formatPercent(latest)}</span>
        </div>
        <div className="spark__empty muted small">Datos insuficientes</div>
      </div>
    );
  }

  const step = WIDTH / (values.length - 1);
  const points = values
    .map((value, index) => {
      const y = HEIGHT - (Math.min(Math.max(value, 0), 100) / 100) * HEIGHT;
      return `${(index * step).toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");

  return (
    <div className="spark">
      <div className="spark__head">
        <span className="muted">{label}</span>
        <span>{formatPercent(latest)}</span>
      </div>
      <svg
        className="spark__chart"
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        preserveAspectRatio="none"
        role="img"
        aria-label={`${label}: últimas ${values.length} muestras, actual ${formatPercent(latest)}`}
      >
        <polyline points={points} fill="none" vectorEffect="non-scaling-stroke" />
      </svg>
    </div>
  );
}
