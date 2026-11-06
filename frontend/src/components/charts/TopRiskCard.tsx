import { Link } from "react-router-dom";
import type { RiskLevel, TopRiskAsset } from "../../api/types";
import { RISK_CATEGORY_LABELS, RISK_LEVEL_LABELS } from "../../lib/risk";

/**
 * Fase 7C.4: el activo con más riesgo y por qué. Cada punto sale de una contribución guardada
 * por el Risk Engine (nada se recalcula en el navegador); los factores restan cuando la
 * contribución es negativa (p. ej. mantenimiento aprobado que cubre una detección).
 */

const LEVEL_TONES: Record<string, string> = {
  critical: "badge badge--crit",
  high: "badge badge--warn",
  medium: "badge badge--warn",
  low: "badge badge--info",
  informational: "badge badge--muted",
};

export function points(value: number): string {
  const rounded = Math.round(value * 10) / 10;
  return `${rounded > 0 ? "+" : ""}${rounded}`;
}

export function TopRiskCard({ data }: { data: TopRiskAsset | null }) {
  if (!data) {
    return (
      <section className="panel panel--padded top-risk" aria-label="Activo con más riesgo">
        <h2>Riesgo</h2>
        <p className="muted small">Ningún activo tiene riesgo calculado todavía: no hay nada que desglosar.</p>
      </section>
    );
  }
  const score = Math.max(0, Math.min(100, data.score));
  const level = RISK_LEVEL_LABELS[data.level as RiskLevel] ?? data.level;
  return (
    <section className="panel panel--padded top-risk" aria-label="Activo con más riesgo">
      <header className="top-risk__head">
        <h2>
          Riesgo · <Link to={`/assets/${data.asset_id}?tab=risk`}>{data.name}</Link>
        </h2>
        <span className="small muted">cada punto con su motivo</span>
      </header>
      <div className="top-risk__score">
        <span className="top-risk__value" aria-label={`Puntuación ${Math.round(score)} de 100`}>
          {Math.round(score)}
          <span className="muted small"> / 100</span>
        </span>
        <span className={LEVEL_TONES[data.level] ?? "badge"}>{level}</span>
      </div>
      <div className="top-risk__bar" aria-hidden="true">
        <span className="top-risk__marker" style={{ left: `${score}%` }} />
      </div>
      {data.factors.length === 0 ? (
        <p className="muted small">El Risk Engine no guardó contribuciones para este activo.</p>
      ) : (
        <ul className="top-risk__factors">
          {data.factors.map((f, i) => (
            <li key={`${f.label}-${i}`}>
              <span className={`top-risk__points${f.points < 0 ? " top-risk__points--down" : ""}`}>{points(f.points)}</span>
              <span className="top-risk__factor">
                {f.detection_id ? <Link to={`/detections/${f.detection_id}`}>{f.label}</Link> : f.label}
                {f.category && <span className="small muted"> {RISK_CATEGORY_LABELS[f.category] ?? f.category}</span>}
              </span>
            </li>
          ))}
          {data.other_points !== 0 && (
            <li>
              <span className="top-risk__points">{points(data.other_points)}</span>
              <span className="top-risk__factor small muted">Otros factores menores</span>
            </li>
          )}
        </ul>
      )}
      <p className="top-risk__note small">
        Una alerta es un indicio a investigar, <strong>no un compromiso confirmado</strong>.
      </p>
    </section>
  );
}
