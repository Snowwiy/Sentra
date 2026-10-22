import type { RiskAssetDetail } from "../../api/types";
import { formatAmount, formatFactor, nominalChain, riskTrace } from "../../lib/risk";

/**
 * «Cómo se calcula» (Fase 6D.8): la cadena completa del score con los números guardados por
 * el backend, para que se entienda, por ejemplo, cómo una sola correlación CORR-002 llega
 * cerca de 100. Solo se muestra si el cálculo guardó la traza (`breakdown.trace`); con
 * cálculos anteriores no se reconstruye nada a ojo.
 */
export function RiskTraceSection({ risk }: { risk: RiskAssetDetail }) {
  const trace = riskTrace(risk.breakdown);
  if (!trace) return null;
  const chains = risk.contributions
    .filter((item) => item.factor === "detection")
    .map((item) => ({ item, chain: nominalChain(item) }))
    .filter((entry): entry is { item: typeof entry.item; chain: NonNullable<typeof entry.chain> } => entry.chain !== null);
  const saturated = trace.saturated_points < trace.raw_points;
  return (
    <section className="panel panel--padded risk-trace" aria-label="Cómo se calcula">
      <h3>Cómo se calcula</h3>
      <p className="muted small">
        Cada detección aporta: puntos de severidad × confianza × ocurrencias × correlación × vigencia × estado × posición.
        La suma de aportes es la base; la base × criticidad × tipo de activo × contexto es el valor bruto; la saturación
        lo comprime hacia 100 y se redondea al score. Fórmula v{trace.formula_version}.
      </p>
      {chains.length > 0 && (
        <div className="table-wrap">
          <table className="table" aria-label="Aporte de cada detección">
            <thead>
              <tr>
                <th>Detección</th>
                <th>Cadena</th>
                <th>Aporte</th>
              </tr>
            </thead>
            <tbody>
              {chains.map(({ item, chain }, index) => (
                <tr key={`${item.detection_id ?? item.label}-${index}`}>
                  <td>{item.label}</td>
                  <td className="mono small risk-trace__chain">
                    {formatAmount(chain.severity)} severidad {formatFactor(chain.confidence)} confianza{" "}
                    {formatFactor(chain.occurrences)} ocurrencias
                    {chain.occurrenceCount !== null && ` (${chain.occurrenceCount})`} {formatFactor(chain.correlation)}{" "}
                    correlación
                    {chain.recency !== null && <> {formatFactor(chain.recency)} vigencia</>}
                    {chain.status !== null && <> {formatFactor(chain.status)} estado</>}
                    {chain.position !== null && <> {formatFactor(chain.position)} posición</>}
                  </td>
                  <td className="mono">= {formatAmount(chain.points)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <ol className="small risk-trace__steps" aria-label="Pasos del cálculo">
        <li>
          Suma de aportes (base): <span className="mono">{formatAmount(trace.base_points)}</span>
        </li>
        <li>
          Base {formatFactor(trace.criticality_factor)} criticidad {formatFactor(trace.type_factor)} tipo de activo{" "}
          {formatFactor(trace.context_factor)} contexto = bruto <span className="mono">{formatAmount(trace.raw_points)}</span>
        </li>
        <li>
          Saturación (a partir de {formatAmount(trace.saturation_knee)} puntos el crecimiento se atenúa):{" "}
          <span className="mono">
            {formatAmount(trace.raw_points)} → {formatAmount(trace.saturated_points)}
          </span>
          {!saturated && " (sin efecto: el bruto no llega al umbral)"}
        </li>
        <li>
          Score final: <strong className="mono">{trace.score}</strong>
        </li>
      </ol>
    </section>
  );
}
