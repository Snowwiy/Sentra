import { useId } from "react";
import type { ActivityHour } from "../../api/types";

/**
 * Fase 7C.4: actividad de las últimas 24 horas en franjas de una hora (datos reales de
 * /dashboard/security-overview). Las detecciones salen siempre; los eventos del sistema solo
 * si hay agentes en el alcance (sin agentes se dice "no medido", nunca se dibuja un cero).
 *
 * SVG propio, sin biblioteca de gráficas: la figura lleva un resumen textual accesible y la
 * tabla de valores para lectores de pantalla.
 */

const W = 720;
const H = 200;
const PAD_L = 36;
const PAD_R = 12;
const PAD_T = 26;
const PAD_B = 26;

function hourLabel(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? "—" : `${String(date.getHours()).padStart(2, "0")}:00`;
}

/** Máximo redondo del eje para que las marcas sean enteras. */
export function axisTop(max: number): number {
  if (max <= 4) return 4;
  const step = 10 ** Math.floor(Math.log10(max));
  for (const m of [1, 2, 2.5, 5, 10]) {
    if (m * step >= max) return Math.ceil((m * step) / 4) * 4;
  }
  return max;
}

export function peakOf(values: number[]): number {
  let index = -1;
  values.forEach((v, i) => {
    if (v > 0 && (index < 0 || v > values[index]!)) index = i;
  });
  return index;
}

export function ActivityChart({ hours }: { hours: ActivityHour[] }) {
  const gradient = useId();
  const measured = hours.some((h) => h.events !== null);
  const events = hours.map((h) => h.events ?? 0);
  const detections = hours.map((h) => h.detections);
  const primary = measured ? events : detections;
  const top = axisTop(Math.max(1, ...events, ...detections));
  const n = Math.max(hours.length - 1, 1);
  const x = (i: number) => PAD_L + ((W - PAD_L - PAD_R) * i) / n;
  const y = (v: number) => H - PAD_B - ((H - PAD_T - PAD_B) * v) / top;
  const line = (values: number[]) => values.map((v, i) => `${i === 0 ? "M" : "L"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
  const area = `${line(primary)} L${x(hours.length - 1).toFixed(1)},${H - PAD_B} L${x(0).toFixed(1)},${H - PAD_B} Z`;
  const peak = peakOf(primary);
  const totalDetections = detections.reduce((a, b) => a + b, 0);
  const totalEvents = events.reduce((a, b) => a + b, 0);
  const summary = measured
    ? `${totalEvents} eventos y ${totalDetections} detecciones en 24 horas`
    : `${totalDetections} detecciones en 24 horas; eventos no medidos`;

  return (
    <figure className="panel panel--padded activity-chart" aria-label="Actividad por hora">
      <figcaption className="activity-chart__head">
        <h2>{measured ? "Eventos por hora" : "Detecciones por hora"}</h2>
        <span className="small muted">últimas 24 h · telemetría normalizada</span>
      </figcaption>
      {hours.length === 0 ? (
        <p className="muted small">Sin datos de actividad.</p>
      ) : (
        <>
          <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={summary} className="activity-chart__svg">
            <defs>
              <linearGradient id={gradient} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="var(--accent)" stopOpacity="0.45" />
                <stop offset="100%" stopColor="var(--accent)" stopOpacity="0.02" />
              </linearGradient>
            </defs>
            {[0, 1, 2, 3, 4].map((t) => {
              const value = (top * t) / 4;
              return (
                <g key={t}>
                  <line x1={PAD_L} x2={W - PAD_R} y1={y(value)} y2={y(value)} className="activity-chart__grid" />
                  <text x={PAD_L - 6} y={y(value) + 3} textAnchor="end" className="activity-chart__tick">
                    {value}
                  </text>
                </g>
              );
            })}
            {hours.map((h, i) =>
              i % 6 === 0 || i === hours.length - 1 ? (
                <text
                  key={h.hour}
                  x={x(i)}
                  y={H - 8}
                  textAnchor={i === 0 ? "start" : i === hours.length - 1 ? "end" : "middle"}
                  className="activity-chart__tick"
                >
                  {hourLabel(h.hour)}
                </text>
              ) : null,
            )}
            <path d={area} fill={`url(#${gradient})`} />
            <path d={line(primary)} className="activity-chart__line" />
            {measured && <path d={line(detections)} className="activity-chart__line activity-chart__line--det" />}
            {peak >= 0 && (
              <g>
                <circle cx={x(peak)} cy={y(primary[peak]!)} r={4} className="activity-chart__peak" />
                <text
                  x={Math.min(Math.max(x(peak), PAD_L + 70), W - PAD_R - 70)}
                  y={Math.max(y(primary[peak]!) - 10, 12)}
                  textAnchor="middle"
                  className="activity-chart__peak-label"
                >
                  Pico: {primary[peak]} {measured ? "eventos" : "detecciones"} · {hourLabel(hours[peak]!.hour)}
                </text>
              </g>
            )}
          </svg>
          <div className="legend small" aria-hidden="true">
            <span>
              <i className="legend__swatch legend__swatch--accent" /> {measured ? "Eventos" : "Detecciones"}
            </span>
            {measured && (
              <span>
                <i className="legend__swatch legend__swatch--warn" /> Detecciones
              </span>
            )}
            {!measured && <span className="muted">Eventos: no medido (ningún agente en el alcance)</span>}
          </div>
          <table className="sr-only">
            <caption>Actividad por hora</caption>
            <thead>
              <tr>
                <th>Hora</th>
                <th>Detecciones</th>
                <th>Eventos</th>
              </tr>
            </thead>
            <tbody>
              {hours.map((h) => (
                <tr key={h.hour}>
                  <td>{hourLabel(h.hour)}</td>
                  <td>{h.detections}</td>
                  <td>{h.events ?? "no medido"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </figure>
  );
}

const SEVERITIES: { key: string; label: string; tone: string }[] = [
  { key: "critical", label: "Crítica", tone: "crit" },
  { key: "high", label: "Alta", tone: "high" },
  { key: "medium", label: "Media", tone: "warn" },
  { key: "low", label: "Baja", tone: "info" },
];

/** Barras horizontales de detecciones activas por severidad (recuentos del resumen). */
export function SeverityBars({ bySeverity }: { bySeverity: Record<string, number> }) {
  const max = Math.max(1, ...SEVERITIES.map((s) => bySeverity[s.key] ?? 0));
  return (
    <section className="panel panel--padded severity-bars" aria-label="Detecciones por severidad">
      <header className="activity-chart__head">
        <h2>Detecciones por severidad</h2>
        <span className="small muted">activas</span>
      </header>
      <ul>
        {SEVERITIES.map((s) => {
          const value = bySeverity[s.key] ?? 0;
          return (
            <li key={s.key}>
              <span className="severity-bars__label">{s.label}</span>
              <span className="severity-bars__track" aria-hidden="true">
                <span
                  className={`severity-bars__fill severity-bars__fill--${s.tone}`}
                  style={{ width: `${(100 * value) / max}%` }}
                />
              </span>
              <span className="severity-bars__value">{value}</span>
            </li>
          );
        })}
      </ul>
    </section>
  );
}
