import { formatPercent } from "../lib/format";

// Visual thresholds only; they do not raise alerts. Alerting will live in the backend.
function level(value: number): "ok" | "warn" | "crit" {
  if (value >= 90) return "crit";
  if (value >= 75) return "warn";
  return "ok";
}

/** Percentage with a thin usage bar; renders a dash when there is no sample. */
export function MetricBar({ value, label }: { value: number | null | undefined; label: string }) {
  if (value == null) return <span className="muted">—</span>;
  const clamped = Math.min(Math.max(value, 0), 100);
  return (
    <span className={`metric metric--${level(value)}`}>
      <span className="metric__value">{formatPercent(value)}</span>
      <span
        className="metric__track"
        role="meter"
        aria-label={label}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={clamped}
      >
        <span className="metric__fill" style={{ width: `${clamped}%` }} />
      </span>
    </span>
  );
}
