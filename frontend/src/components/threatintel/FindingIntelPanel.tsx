import { useCallback } from "react";
import { vulnerabilitiesApi } from "../../api/sentra";
import { config } from "../../config";
import { errorMessage, formatDateTime, formatRelative } from "../../lib/format";
import {
  CHANGE_LABELS,
  EPSS_BAND_LABELS,
  formatEpss,
  formatPercentile,
  SOURCE_STATE_LABELS,
} from "../../lib/threatIntel";
import { usePolling } from "../../lib/usePolling";
import { EmptyState, ErrorState, LoadingState } from "../StateViews";
import { SourceStateBadge, TrustBadge } from "./IntelBadges";

/**
 * Inteligencia de explotabilidad de un finding (Fase 5C) con procedencia por dato.
 * KEV y EPSS son contexto EXTERNO: nunca significan que este activo haya sido atacado.
 */
export function FindingIntelPanel({ findingId }: { findingId: string }) {
  const fetcher = useCallback(
    (signal: AbortSignal) => vulnerabilitiesApi.threatIntel(findingId, signal),
    [findingId],
  );
  const { data, error, loading, refresh } = usePolling(fetcher, config.refreshIntervalMs);
  if (loading) return <LoadingState label="Cargando inteligencia…" />;
  if (!data) return <ErrorState message={error ? errorMessage(error) : "Sin datos"} onRetry={refresh} />;

  if (data.status === "no_cve") {
    return (
      <EmptyState title="Sin CVE">
        El registro del catálogo no tiene identificador CVE: KEV y EPSS no se pueden consultar (Sentra no adivina por
        título ni producto).
      </EmptyState>
    );
  }
  if (data.status === "none_configured") {
    return (
      <EmptyState title="No intelligence source configured">
        No hay ninguna fuente KEV ni EPSS activa. La prioridad usa solo el catálogo, la evidencia y el contexto del
        activo.
      </EmptyState>
    );
  }

  return (
    <div className="stack">
      <p className="muted small">
        Contexto externo para <span className="mono">{data.cve}</span>. KEV indica explotación conocida reportada en
        algún sitio; EPSS es una probabilidad estadística de explotación en los próximos 30 días. Ninguno de los dos
        indica que este activo haya sido atacado.
      </p>
      {data.conflicting && (
        <div className="banner banner--warn" role="note">
          Las fuentes no coinciden: se muestran todas con su procedencia.
        </div>
      )}
      {data.status === "no_data" && (
        <div className="banner" role="note">
          Este CVE no aparece en las fuentes activas (no está en KEV y no tiene puntuación EPSS).
        </div>
      )}

      {data.kev.map((kev) => (
        <section key={`kev-${kev.source.source_id}`} className="panel panel--padded">
          <h2>{kev.active ? "Explotación conocida reportada (CISA KEV)" : "Retirado de KEV"}</h2>
          <dl className="fields">
            <div className="field">
              <dt>Fuente</dt>
              <dd>
                {kev.source.name} <TrustBadge trust={kev.source.trust} /> <SourceStateBadge state={kev.source.state} />
              </dd>
            </div>
            <div className="field">
              <dt>Añadida a KEV</dt>
              <dd>{kev.date_added ?? "—"}</dd>
            </div>
            <div className="field">
              <dt>Fecha límite (agencias de EE. UU.)</dt>
              <dd>{kev.due_date ?? "—"}</dd>
            </div>
            <div className="field">
              <dt>Uso conocido en ransomware</dt>
              <dd>
                {kev.known_ransomware_use === "known"
                  ? "Conocido"
                  : kev.known_ransomware_use === "unknown"
                    ? "Desconocido (no significa que no)"
                    : kev.known_ransomware_use}
              </dd>
            </div>
            {kev.required_action && (
              <div className="field">
                <dt>Acción requerida</dt>
                <dd>{kev.required_action}</dd>
              </div>
            )}
            {kev.vulnerability_name && (
              <div className="field">
                <dt>Nombre</dt>
                <dd>{kev.vulnerability_name}</dd>
              </div>
            )}
            <div className="field">
              <dt>Recibido</dt>
              <dd title={formatDateTime(kev.retrieved_at)}>{formatRelative(kev.retrieved_at)}</dd>
            </div>
            {kev.removed_at && (
              <div className="field">
                <dt>Retirado</dt>
                <dd>{formatDateTime(kev.removed_at)}</dd>
              </div>
            )}
          </dl>
          {kev.source.state === "stale" && (
            <p className="muted small">
              Fuente {SOURCE_STATE_LABELS.stale.toLowerCase()}: el dato puede no ser actual y pesa menos en la prioridad.
            </p>
          )}
        </section>
      ))}

      {data.epss.map((epss) => (
        <section key={`epss-${epss.source.source_id}`} className="panel panel--padded">
          <h2>Probabilidad de explotación EPSS</h2>
          <dl className="fields">
            <div className="field">
              <dt>Probabilidad (30 días)</dt>
              <dd>
                {formatEpss(epss.score)} · banda {EPSS_BAND_LABELS[epss.band]?.toLowerCase() ?? epss.band}
              </dd>
            </div>
            <div className="field">
              <dt>Percentil</dt>
              <dd>{formatPercentile(epss.percentile)}</dd>
            </div>
            <div className="field">
              <dt>Fecha de la puntuación</dt>
              <dd>
                {epss.score_date ?? "—"}
                {epss.model_version && <span className="muted"> · modelo {epss.model_version}</span>}
              </dd>
            </div>
            {epss.previous && typeof epss.previous.score === "number" && (
              <div className="field">
                <dt>Valor anterior</dt>
                <dd>
                  {formatEpss(epss.previous.score)}
                  {typeof epss.previous.score_date === "string" && ` (${epss.previous.score_date})`}
                </dd>
              </div>
            )}
            <div className="field">
              <dt>Fuente</dt>
              <dd>
                {epss.source.name} <TrustBadge trust={epss.source.trust} />{" "}
                <SourceStateBadge state={epss.source.state} />
              </dd>
            </div>
          </dl>
        </section>
      ))}

      {data.priority_factors.length > 0 && (
        <section className="panel panel--padded">
          <h2>Efecto en la prioridad Sentra</h2>
          <ul className="small">
            {data.priority_factors.map((f, i) => (
              <li key={i}>
                {String(f.label ?? f.factor)}: +{String(f.points ?? 0)}
              </li>
            ))}
          </ul>
        </section>
      )}

      {data.changes.length > 0 && (
        <section className="panel">
          <h2 className="panel__title">Historial de inteligencia</h2>
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
