import type { SecurityPosture } from "../../api/types";
import { CRITICALITY_LABELS, RISK_LEVEL_LABELS } from "../../lib/risk";

const LEVEL_BADGES: Record<string, string> = {
  critical: "badge badge--crit",
  high: "badge badge--warn",
  medium: "badge badge--warn",
  low: "badge badge--info",
  informational: "badge badge--muted",
};

function levelLabel(level: string): string {
  return RISK_LEVEL_LABELS[level as keyof typeof RISK_LEVEL_LABELS] ?? level;
}

function percent(fraction: number): string {
  return `${Math.round(fraction * 100)} %`;
}

/**
 * Postura de seguridad (Fase 7A.7): media del riesgo ponderada por criticidad. Sin activos
 * evaluados no se muestra ningún número (no_data); con poca cobertura (partial) el número se
 * acompaña de un aviso visible, porque representa solo una parte del parque.
 */
export function PostureCard({ posture }: { posture: SecurityPosture }) {
  const { method } = posture;
  const showScore = posture.state !== "no_data" && posture.score !== null;
  return (
    <section className="panel panel--padded stack posture-card" aria-label="Postura de seguridad">
      <div className="posture-card__head">
        <h2>Postura de seguridad</h2>
        {posture.state === "partial" && <span className="badge badge--warn">Cobertura parcial</span>}
      </div>
      {showScore ? (
        <div className="posture-card__score">
          <span className="posture-card__value" aria-label={`Puntuación ${posture.score} de 100`}>
            {posture.score}
            <span className="muted small"> / 100</span>
          </span>
          {posture.level && <span className={LEVEL_BADGES[posture.level] ?? "badge"}>{levelLabel(posture.level)}</span>}
        </div>
      ) : (
        <p className="posture-card__nodata">
          <strong>Sin datos.</strong> Ningún activo actual tiene riesgo calculado, así que no hay puntuación: un cero
          sería inventado.
        </p>
      )}
      {posture.state === "partial" && (
        <div className="banner banner--warn" role="note">
          Solo {posture.assets_scored} de {posture.assets_current} activos tienen riesgo calculado (
          {percent(posture.coverage)}). La puntuación describe esa parte, no todo el parque.
        </div>
      )}
      <dl className="fields fields--inline" aria-label="Datos de la postura">
        <div className="field">
          <dt>Cobertura</dt>
          <dd>
            {posture.assets_scored} de {posture.assets_current} activos ({percent(posture.coverage)})
          </dd>
        </div>
        <div className="field">
          <dt>Pico</dt>
          <dd>{posture.peak_score ?? "—"}</dd>
        </div>
        <div className="field">
          <dt>Altos o críticos</dt>
          <dd>{posture.high_or_critical}</dd>
        </div>
      </dl>
      <details className="posture-card__method">
        <summary>Cómo se calcula</summary>
        <dl className="fields">
          <div className="field">
            <dt>Fórmula (versión {posture.formula_version})</dt>
            <dd>{method.formula}</dd>
          </div>
          <div className="field">
            <dt>Población</dt>
            <dd>{method.population}</dd>
          </div>
          <div className="field">
            <dt>Pesos por criticidad</dt>
            <dd>
              {Object.entries(method.weights)
                .map(([name, weight]) => `${CRITICALITY_LABELS[name as keyof typeof CRITICALITY_LABELS] ?? name} ${weight}`)
                .join(" · ")}
            </dd>
          </div>
          <div className="field">
            <dt>Datos que faltan</dt>
            <dd>{method.missing_data}</dd>
          </div>
          <div className="field">
            <dt>Umbrales de nivel (desde)</dt>
            <dd>
              {Object.entries(method.thresholds)
                .map(([level, value]) => `${levelLabel(level)} ${value}`)
                .join(" · ")}
            </dd>
          </div>
          {method.reference && (
            <div className="field">
              <dt>Referencia</dt>
              <dd className="mono">{method.reference}</dd>
            </div>
          )}
        </dl>
      </details>
    </section>
  );
}
