import type { FindingDetail } from "../../api/types";
import { MATCH_HINTS } from "../../lib/vulnerabilities";
import {
  ADAPTER_LABELS,
  IDENTITY_METHOD_LABELS,
  IDENTITY_SOURCE_LABELS,
  MATCH_LIMIT_LABELS,
} from "../../lib/vulnSources";
import { MatchBadge } from "./VulnBadges";

/**
 * Estado de la coincidencia y su razonamiento (Fase 6C.4): qué significa el estado, por qué
 * identificador casó, qué rango del catálogo decidió y qué límites impiden confirmarla.
 * Todo sale de la evidencia que guarda el servidor; la UI no recalcula nada.
 */
export function MatchExplanation({ finding }: { finding: FindingDetail }) {
  const e = finding.evidence;
  const limits = (e.checks ?? []).filter((c) => c.check === "limit").map((c) => c.result);
  const identity = e.identity;
  return (
    <div className="stack" aria-label="Coincidencia">
      <p>
        <MatchBadge state={finding.match_state} confidence={finding.confidence} />{" "}
        <span className="muted small">{MATCH_HINTS[finding.match_state]}</span>
      </p>
      <dl className="fields">
        {identity && (
          <div className="field">
            <dt>Identificación</dt>
            <dd>
              {IDENTITY_METHOD_LABELS[identity.method] ?? identity.method}:{" "}
              <span className="mono small">{identity.cpe ?? identity.identifier}</span>
              {identity.declared_by && (
                <span className="muted small">
                  {" "}
                  · declarado por {IDENTITY_SOURCE_LABELS[identity.declared_by] ?? identity.declared_by}
                </span>
              )}
            </dd>
          </div>
        )}
        {e.cpe_match && (
          <div className="field">
            <dt>Coincidencia CPE</dt>
            <dd>
              <span className="mono small">{e.cpe_match.criteria ?? "—"}</span>
              {e.cpe_match.range && <span className="muted small"> · {e.cpe_match.range}</span>}
            </dd>
          </div>
        )}
        {e.catalog && (
          <div className="field">
            <dt>Registro del catálogo</dt>
            <dd>
              {ADAPTER_LABELS[e.catalog.adapter] ?? e.catalog.adapter}{" "}
              <span className="muted small mono">({e.catalog.source})</span> · versión {e.catalog.record_version}
            </dd>
          </div>
        )}
      </dl>
      {limits.length > 0 && (
        <>
          <h3>Por qué no es confirmada</h3>
          <ul className="small">
            {limits.map((limit) => (
              <li key={limit}>
                {MATCH_LIMIT_LABELS[limit] ?? limit} <span className="muted mono">({limit})</span>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}
