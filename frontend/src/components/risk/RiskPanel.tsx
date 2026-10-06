import { useCallback, useState } from "react";
import { Link } from "react-router-dom";
import { aiApi, riskApi } from "../../api/sentra";
import type { AssetCriticality, RiskAssetDetail, RiskContribution } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { config } from "../../config";
import { errorMessage, formatDateTime, formatRelative } from "../../lib/format";
import {
  CRITICALITY_LABELS,
  CRITICALITY_ORDER,
  formatDelta,
  formatPoints,
  reasonLabel,
  RISK_CATEGORY_LABELS,
  RISK_LEVEL_LABELS,
} from "../../lib/risk";
import { usePolling } from "../../lib/usePolling";
import { ConfidenceBadge, DetectionSeverityBadge, DetectionStatusBadge } from "../detections/DetectionBadges";
import { AIAnalyzePanel } from "../ai/AIAnalyzePanel";
import { ErrorState, LoadingState } from "../StateViews";
import { CriticalityBadge, RiskBadge, RiskConfidenceBadge } from "./RiskBadges";
import { RiskTrend } from "./RiskTrend";

/** Enlace de una contribución a su origen: detección, exposición del activo o nada. */
function ContributionTarget({ item, assetId }: { item: RiskContribution; assetId: string }) {
  if (item.detection_id) {
    return <Link to={`/detections/${item.detection_id}`}>{item.label}</Link>;
  }
  if (item.port !== null && item.factor === "exposure") {
    return <Link to={`/assets/${assetId}?tab=exposure`}>{item.label}</Link>;
  }
  return <>{item.label}</>;
}

function calculatedTime(detail: RiskAssetDetail): number {
  return detail.calculated_at ? Date.parse(detail.calculated_at) : 0;
}

function absorbedBy(item: RiskContribution): string | null {
  const ref = item.details["absorbed_by"];
  if (!ref || typeof ref !== "object") return null;
  const value = ref as { rule_id?: unknown; port?: unknown };
  if (typeof value.rule_id === "string") return value.rule_id;
  if (typeof value.port === "number") return `puerto ${value.port}`;
  return null;
}

/**
 * Criticidad del activo: solo admin (assets:manage) la cambia. Para el resto es un dato de
 * solo lectura; el backend rechaza el cambio con 403 igualmente.
 */
function CriticalityControl({
  risk,
  onChanged,
}: {
  risk: RiskAssetDetail;
  onChanged: (detail: RiskAssetDetail) => void;
}) {
  const auth = useAuth();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  if (!auth.can("assets:manage")) {
    return (
      <span>
        Criticidad: <CriticalityBadge criticality={risk.criticality} />
      </span>
    );
  }
  async function change(value: AssetCriticality) {
    setBusy(true);
    setError(undefined);
    try {
      onChanged(await riskApi.setCriticality(risk.asset_id, value));
    } catch (err) {
      setError(err instanceof Error ? errorMessage(err) : String(err));
    } finally {
      setBusy(false);
    }
  }
  return (
    <span className="criticality-control">
      <label>
        Criticidad{" "}
        <select
          className="input input--select"
          aria-label="Criticidad del activo"
          value={risk.criticality}
          disabled={busy}
          onChange={(event) => void change(event.target.value as AssetCriticality)}
        >
          {CRITICALITY_ORDER.map((value) => (
            <option key={value} value={value}>
              {CRITICALITY_LABELS[value]}
            </option>
          ))}
        </select>
      </label>
      {error && (
        <span className="error-text small" role="alert">
          {error}
        </span>
      )}
    </span>
  );
}

/**
 * Sección "Riesgo" del detalle de un activo: score, nivel y confianza por separado, por qué
 * (explicación determinista del backend), contribuciones navegables, tendencia, detecciones
 * activas y cambios recientes. Nada de esto lo genera una IA.
 */
export function RiskPanel({ assetId }: { assetId: string }) {
  const fetchRisk = useCallback((signal: AbortSignal) => riskApi.get(assetId, signal), [assetId]);
  const { data, error, loading, refresh } = usePolling(fetchRisk, config.refreshIntervalMs);
  // Respuesta del PATCH de criticidad: se muestra al momento y hasta que un sondeo traiga un
  // cálculo igual o más reciente (un sondeo en vuelo podría devolver el estado anterior).
  const [override, setOverride] = useState<RiskAssetDetail>();
  const risk = override && (!data || calculatedTime(override) > calculatedTime(data)) ? override : data;

  if (loading) return <LoadingState label="Cargando riesgo…" />;
  if (!risk) return <ErrorState message={error ? errorMessage(error) : "Sin datos"} onRetry={refresh} />;

  const explanation = risk.explanation;
  return (
    <div className="stack">
      <section className="panel risk-summary" aria-label="Resumen de riesgo">
        <div className="risk-summary__head">
          {risk.evaluated && risk.score !== null && risk.level ? (
            <>
              <RiskBadge score={risk.score} level={risk.level} />
              {risk.confidence && <RiskConfidenceBadge confidence={risk.confidence} />}
              <span className="muted small" title="Score actual menos el de hace 24 h">
                24 h: {formatDelta(risk.trend_24h)}
              </span>
            </>
          ) : (
            <span className="muted">Pendiente de evaluar</span>
          )}
          <CriticalityControl risk={risk} onChanged={setOverride} />
        </div>
        <h2 className="risk-summary__headline">{explanation.headline}</h2>
        <p className="muted small">
          {risk.calculated_at
            ? `Calculado ${formatRelative(risk.calculated_at)} (${formatDateTime(risk.calculated_at)})`
            : "Sin calcular todavía"}
          {risk.pending_recalculation && " · recálculo pendiente"}
          {risk.formula_version !== null && ` · fórmula v${risk.formula_version}`}
        </p>
        {error && (
          <div className="banner banner--warn" role="alert">
            Fallo al actualizar: {errorMessage(error)}. Se muestran los últimos datos recibidos.
          </div>
        )}
        <h3>¿Por qué este activo tiene este riesgo?</h3>
        <ul className="risk-reasons">
          {explanation.reasons.map((reason) => (
            <li key={reason}>{reason}</li>
          ))}
        </ul>
        <div className="risk-columns">
          <div>
            <h4>Aumentan el riesgo</h4>
            {explanation.increased.length === 0 ? (
              <p className="muted small">Nada.</p>
            ) : (
              <ul className="risk-factors">
                {explanation.increased.map((item) => (
                  <li key={item.label}>
                    <span>{item.label}</span>
                    <span className="mono risk-points risk-points--up">{formatPoints(item.points)}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
          <div>
            <h4>Lo reducen</h4>
            {explanation.reduced.length === 0 ? (
              <p className="muted small">Nada.</p>
            ) : (
              <ul className="risk-factors">
                {explanation.reduced.map((item) => (
                  <li key={item.label}>
                    <span>{item.label}</span>
                    <span className="mono risk-points risk-points--down">{formatPoints(item.points)}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
          <div>
            {/* Fase 4L: el contexto del activo modifica el impacto de la evidencia; se
                muestra aparte y con sus puntos, nunca escondido en la fórmula. */}
            <h4>Contexto del activo</h4>
            {(explanation.context ?? []).length === 0 ? (
              <p className="muted small">Sin influencia (sin evidencia o contexto neutro/desconocido).</p>
            ) : (
              <ul className="risk-factors" aria-label="Influencia del contexto">
                {(explanation.context ?? []).map((item) => (
                  <li key={item.label}>
                    <span>{item.points > 0 ? "+ " : ""}{item.label}</span>
                    <span className={`mono risk-points risk-points--${item.points >= 0 ? "up" : "down"}`}>
                      {formatPoints(item.points)}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </div>
          <div>
            <h4>Confianza de la evaluación</h4>
            <ul className="risk-factors">
              {explanation.confidence_factors.map((item) => (
                <li key={item.label}>
                  <span>{item.label}</span>
                  <span className="mono">{item.effect === "=" ? "" : item.effect}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </section>

      <section className="panel">
        <RiskTrend assetId={assetId} thresholds={risk.thresholds} />
      </section>

      <section className="panel" aria-label="Contribuciones">
        <div className="panel__toolbar">
          <h3>Principales contribuciones</h3>
          <span className="muted small">La suma de los puntos es el score (antes de redondear).</span>
        </div>
        {risk.contributions.length === 0 ? (
          <p className="muted small risk-empty">Ninguna: sin detecciones ni exposición sensible.</p>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Factor</th>
                  <th>Categoría</th>
                  <th>Puntos</th>
                  <th>Detalle</th>
                </tr>
              </thead>
              <tbody>
                {risk.contributions.map((item, index) => {
                  const absorbed = absorbedBy(item);
                  return (
                    <tr key={`${item.factor}-${item.detection_id ?? item.port ?? item.label}-${index}`}>
                      <td>
                        <ContributionTarget item={item} assetId={assetId} />
                      </td>
                      <td>{RISK_CATEGORY_LABELS[item.category] ?? item.category}</td>
                      <td className={`mono risk-points${item.points < 0 ? " risk-points--down" : " risk-points--up"}`}>
                        {formatPoints(item.points)}
                      </td>
                      <td className="muted small">
                        {absorbed
                          ? `Incluida en ${absorbed} (sin doble conteo)`
                          : typeof item.details["status"] === "string"
                            ? `${String(item.details["severity"])} · ${String(item.details["status"])}`
                            : ""}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <div className="risk-columns">
        <section className="panel" aria-label="Detecciones activas">
          <div className="panel__toolbar">
            <h3>Detecciones activas ({risk.active_detections_total})</h3>
            <Link to={`/detections?asset=${assetId}`} className="small">
              Ver todas
            </Link>
          </div>
          {risk.active_detections.length === 0 ? (
            <p className="muted small risk-empty">Ninguna abierta o reconocida.</p>
          ) : (
            <ul className="risk-detections">
              {risk.active_detections.map((d) => (
                <li key={d.detection_id}>
                  <DetectionSeverityBadge severity={d.severity} /> <ConfidenceBadge confidence={d.confidence} />{" "}
                  <Link to={`/detections/${d.detection_id}`}>
                    <span className="mono">{d.rule_id}</span> {d.title}
                  </Link>{" "}
                  <DetectionStatusBadge status={d.status} />
                  <span className="muted small"> · {formatRelative(d.last_seen_at)}</span>
                </li>
              ))}
            </ul>
          )}
        </section>
        <section className="panel" aria-label="Cambios recientes de riesgo">
          <h3>Cambios recientes</h3>
          {risk.recent_changes.length === 0 ? (
            <p className="muted small risk-empty">Sin historial todavía.</p>
          ) : (
            <ul className="risk-changes">
              {risk.recent_changes.map((change) => (
                <li key={change.snapshot_id}>
                  <span className="muted small" title={formatDateTime(change.calculated_at)}>
                    {formatRelative(change.calculated_at)}
                  </span>{" "}
                  {change.transition && (
                    <span className={`risk-arrow risk-arrow--${change.transition}`} aria-hidden="true">
                      {change.transition === "up" ? "▲" : "▼"}
                    </span>
                  )}{" "}
                  {change.previous_score !== null ? `${change.previous_score} → ` : ""}
                  <strong>{change.score}</strong> {RISK_LEVEL_LABELS[change.level]}
                  <span className="muted small"> · {reasonLabel(change.reason)}</span>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
      <AIAnalyzePanel
        title="Interpretación del riesgo con IA"
        buttonLabel="Analizar riesgo"
        kind="risk_explanation"
        assetId={assetId}
        run={(refresh) => aiApi.analyzeRisk(assetId, refresh)}
      />
    </div>
  );
}
