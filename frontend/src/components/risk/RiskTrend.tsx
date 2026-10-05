import { useCallback, useState } from "react";
import { riskApi } from "../../api/sentra";
import type { RiskLevelRange, RiskRange } from "../../api/types";
import { config } from "../../config";
import { errorMessage, formatDateTime } from "../../lib/format";
import { levelBands, RISK_LEVEL_LABELS, trendPoints } from "../../lib/risk";
import { usePolling } from "../../lib/usePolling";
import { ErrorState, LoadingState } from "../StateViews";

const WIDTH = 600;
const HEIGHT = 140;
const RANGES: { key: RiskRange; label: string }[] = [
  { key: "24h", label: "24 h" },
  { key: "7d", label: "7 d" },
  { key: "30d", label: "30 d" },
];

/**
 * Tendencia del riesgo de un activo. Pide solo el rango visible (24 h, 7 d o 30 d; el backend
 * agrega los rangos largos), nunca todo el historial. SVG propio: un escalón por cambio
 * material, sin librería de gráficos.
 */
export function RiskTrend({ assetId, thresholds }: { assetId: string; thresholds: RiskLevelRange[] }) {
  const [range, setRange] = useState<RiskRange>("24h");
  const fetchHistory = useCallback(
    (signal: AbortSignal) => riskApi.history(assetId, range, signal),
    [assetId, range],
  );
  const { data, error, loading, refresh, updatedAt } = usePolling(fetchHistory, Math.max(config.refreshIntervalMs, 30_000));

  let body;
  if (loading) {
    body = <LoadingState label="Cargando tendencia…" />;
  } else if (!data) {
    body = <ErrorState message={error ? errorMessage(error) : "Sin datos"} onRetry={refresh} />;
  } else if (data.points.length === 0 && data.start_score === null && data.current_score === null) {
    body = <p className="muted small">Todavía no hay historial de riesgo para este activo.</p>;
  } else {
    // El eje termina en el instante de la respuesta (no en el render): el gráfico es estable.
    const now = updatedAt ? updatedAt.getTime() : Date.parse(data.since);
    const line = trendPoints(data.points, {
      since: Date.parse(data.since),
      now,
      width: WIDTH,
      height: HEIGHT,
      startScore: data.start_score,
      current: data.current_score,
    });
    // Punto final marcado: con un solo cambio en el rango la línea apenas se ve.
    const last = line.at(-1);
    const path = line.map((p, i) => `${i === 0 ? "M" : "L"}${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(" ");
    body = (
      <>
        <svg
          className="risk-trend__chart"
          viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
          preserveAspectRatio="none"
          role="img"
          aria-label={`Tendencia del riesgo (${range}): ${data.points.length} cambios, valor actual ${data.current_score ?? "—"}`}
        >
          {levelBands(thresholds, HEIGHT).map((band) => (
            <rect
              key={band.level}
              className={`risk-trend__band risk-trend__band--${band.level}`}
              x={0}
              y={band.y}
              width={WIDTH}
              height={band.h}
            >
              <title>{RISK_LEVEL_LABELS[band.level]}</title>
            </rect>
          ))}
          {path && <path className="risk-trend__line" d={path} fill="none" vectorEffect="non-scaling-stroke" />}
          {last && <circle className="risk-trend__dot" cx={last.x} cy={last.y} r={3} vectorEffect="non-scaling-stroke" />}
        </svg>
        <p className="muted small">
          Desde {formatDateTime(data.since)}
          {data.bucket_minutes ? ` · un punto cada ${data.bucket_minutes / 60} h` : " · cada cambio material"}
        </p>
      </>
    );
  }

  return (
    <div className="risk-trend">
      <div className="panel__toolbar">
        <h3>Tendencia</h3>
        <div className="segmented" role="group" aria-label="Rango de la tendencia">
          {RANGES.map(({ key, label }) => (
            <button
              key={key}
              type="button"
              className={`segmented__item${range === key ? " segmented__item--active" : ""}`}
              aria-pressed={range === key}
              onClick={() => setRange(key)}
            >
              {label}
            </button>
          ))}
        </div>
      </div>
      {body}
    </div>
  );
}
