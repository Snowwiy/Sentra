import { useCallback } from "react";
import { Link, useParams } from "react-router-dom";
import { ApiError } from "../api/client";
import { threatIntelApi } from "../api/sentra";
import { config } from "../config";
import { EmptyState, ErrorState, LoadingState } from "../components/StateViews";
import { ClassificationBadge, MatchStatusBadge, TrustBadge } from "../components/threatintel/IntelBadges";
import { errorMessage, formatDateTime, formatRelative } from "../lib/format";
import {
  CHANGE_LABELS,
  CLASSIFICATION_LABELS,
  CONFIDENCE_LABELS,
  INDICATOR_STATE_LABELS,
  INDICATOR_TYPE_LABELS,
  MATCHING_LABELS,
  OBSERVATION_LABELS,
} from "../lib/threatIntel";
import { usePolling } from "../lib/usePolling";
import { safeReference } from "../lib/vulnerabilities";

const backLink = (
  <Link className="muted" to="/threat-intel?tab=indicators">
    ← Indicadores
  </Link>
);

/** Detalle de un indicador: procedencia, vigencia, otras fuentes y coincidencias locales. */
export function ThreatIndicatorDetailPage() {
  const { indicatorId = "" } = useParams();
  const fetcher = useCallback((signal: AbortSignal) => threatIntelApi.indicator(indicatorId, signal), [indicatorId]);
  const { data, error, loading, refresh } = usePolling(fetcher, config.refreshIntervalMs);
  if (loading) return <LoadingState label="Cargando indicador…" />;
  if (!data) {
    const missing = error instanceof ApiError && (error.status === 404 || error.status === 422);
    return (
      <div className="page">
        {backLink}
        {missing || !error ? (
          <EmptyState title="Indicador no encontrado" />
        ) : (
          <ErrorState message={errorMessage(error)} onRetry={refresh} />
        )}
      </div>
    );
  }
  const references = data.references.map(safeReference).filter((url): url is string => url !== null);
  return (
    <div className="page">
      {backLink}
      <div className="page__header">
        <div>
          <h1 className="mono">{data.value}</h1>
          <p className="muted small">
            {INDICATOR_TYPE_LABELS[data.indicator_type] ?? data.indicator_type} · {data.source.name}{" "}
            <TrustBadge trust={data.source.trust} />
          </p>
        </div>
        <ClassificationBadge value={data.classification} />
      </div>
      {data.conflicting && (
        <div className="banner banner--warn" role="note">
          Las fuentes no coinciden en la clasificación de este indicador: se muestran todas, sin elegir una.
        </div>
      )}
      <section className="panel panel--padded">
        <dl className="fields">
          <div className="field">
            <dt>Clasificación (según la fuente)</dt>
            <dd>{CLASSIFICATION_LABELS[data.classification]}</dd>
          </div>
          <div className="field">
            <dt>Confianza</dt>
            <dd>
              {CONFIDENCE_LABELS[data.confidence]}
              {data.confidence_score != null && <span className="muted"> ({data.confidence_score}/100)</span>}
            </dd>
          </div>
          <div className="field">
            <dt>Vigencia</dt>
            <dd>
              {INDICATOR_STATE_LABELS[data.state] ?? data.state}
              {data.valid_from && ` · desde ${formatDateTime(data.valid_from)}`}
              {data.valid_until && ` · hasta ${formatDateTime(data.valid_until)}`}
            </dd>
          </div>
          <div className="field">
            <dt>Búsqueda en datos de Sentra</dt>
            <dd>
              {MATCHING_LABELS[data.matching] ?? data.matching}
              {data.matching_reason && <div className="muted small">{data.matching_reason}</div>}
            </dd>
          </div>
          {data.value_original !== data.value && (
            <div className="field">
              <dt>Valor original</dt>
              <dd className="mono">{data.value_original}</dd>
            </div>
          )}
          {data.external_id && (
            <div className="field">
              <dt>Identificador externo</dt>
              <dd className="mono small">{data.external_id}</dd>
            </div>
          )}
          {data.pattern && (
            <div className="field">
              <dt>Patrón STIX</dt>
              <dd className="mono small">{data.pattern}</dd>
            </div>
          )}
          <div className="field">
            <dt>Recibido</dt>
            <dd>{formatDateTime(data.retrieved_at)}</dd>
          </div>
          {data.tags.length > 0 && (
            <div className="field">
              <dt>Etiquetas</dt>
              <dd>{data.tags.join(", ")}</dd>
            </div>
          )}
        </dl>
        {/* Texto de la fuente: se pinta como texto (React escapa), nunca como HTML. */}
        {data.description && <p className="small">{data.description}</p>}
        {references.length > 0 && (
          <ul className="small">
            {references.map((url) => (
              <li key={url}>
                <a href={url} target="_blank" rel="noopener noreferrer nofollow">
                  {url}
                </a>
              </li>
            ))}
          </ul>
        )}
      </section>

      {data.other_sources.length > 0 && (
        <section className="panel panel--padded">
          <h2>Otras fuentes con el mismo indicador</h2>
          <ul className="small">
            {data.other_sources.map((other, i) => (
              <li key={i}>
                {String(other.source ?? "—")}:{" "}
                {CLASSIFICATION_LABELS[String(other.classification) as keyof typeof CLASSIFICATION_LABELS] ??
                  String(other.classification ?? "—")}
              </li>
            ))}
          </ul>
        </section>
      )}

      <section className="panel">
        <h2 className="panel__title">Coincidencias con datos locales</h2>
        {data.matches.length === 0 ? (
          <EmptyState title="Sin coincidencias">Ningún dato de Sentra coincide con este indicador.</EmptyState>
        ) : (
          <div className="table-wrap">
            <table className="table table--compact">
              <thead>
                <tr>
                  <th>Activo</th>
                  <th>Observado en</th>
                  <th>Veces</th>
                  <th>Última vez</th>
                  <th>Estado</th>
                </tr>
              </thead>
              <tbody>
                {data.matches.map((m) => (
                  <tr key={m.match_id}>
                    <td>
                      <Link to={`/threat-intel/matches/${m.match_id}`}>{m.asset.name}</Link>
                    </td>
                    <td>
                      {OBSERVATION_LABELS[m.observation_type]}
                      <div className="muted small mono">{m.observed_value}</div>
                    </td>
                    <td>{m.observation_count}</td>
                    <td title={formatDateTime(m.last_observed_at)}>{formatRelative(m.last_observed_at)}</td>
                    <td>
                      <MatchStatusBadge status={m.status} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {data.changes.length > 0 && (
        <section className="panel">
          <h2 className="panel__title">Historial</h2>
          <ul className="small">
            {data.changes.map((c, i) => (
              <li key={i}>
                {formatDateTime(c.occurred_at)} · {c.source_name} · {CHANGE_LABELS[c.change] ?? c.change}
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}
