import { useCallback } from "react";
import { Link } from "react-router-dom";
import { sentraApi } from "../../api/sentra";
import { topologyHistoryApi } from "../../api/sentra6e";
import type { AssetStatus, MonitoringMethod } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { SchedulePanel, ScopePanel } from "../../components/discovery/DiscoveryPanels";
import { METHOD_LABELS } from "../../components/NetworkBadges";
import { EmptyState, ErrorState, LoadingState } from "../../components/StateViews";
import { config } from "../../config";
import { devicesLink, METHODS } from "../../lib/deviceFilters";
import { JOB_STATUS_CLASS, JOB_STATUS_LABELS } from "../../lib/discovery";
import { errorMessage, formatDateTime, formatRelative } from "../../lib/format";
import { deviceTypeLabel } from "../../lib/identity";
import { CHANGE_TYPE_LABELS, plainValue } from "../../lib/topologyHistory";
import { usePolling } from "../../lib/usePolling";
import { useNetworkHub } from "./hubContext";

const REFRESH_MS = Math.max(config.refreshIntervalMs, 60_000);
const RECENT_CHANGES = 5;

const STATUS_LABELS: Record<AssetStatus, string> = {
  online: "En línea",
  offline: "Sin conexión",
  unknown: "Desconocidos",
};

/**
 * Red › Resumen (Fase 7A.5): recuentos agregados del servidor por método, estado y tipo (cada
 * uno abre Dispositivos ya filtrado), los últimos cambios de red y el estado del descubrimiento.
 */
export function OverviewTab() {
  const hub = useNetworkHub();
  const canChanges = useAuth().can("monitoring:read");
  const { scopeId, discoveryEpoch } = hub;
  const fetchSummary = useCallback(
    (signal: AbortSignal) => sentraApi.dashboardSummary(signal, scopeId),
    // discoveryEpoch: tras un descubrimiento los recuentos cambian en el acto.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [scopeId, discoveryEpoch],
  );
  const summary = usePolling(fetchSummary, hub.discovering ? 5_000 : REFRESH_MS);

  if (summary.loading) return <LoadingState label="Cargando resumen de red…" />;
  if (!summary.data) {
    return <ErrorState message={errorMessage(summary.error ?? new Error("Sin datos"))} onRetry={summary.refresh} />;
  }
  const assets = summary.data.assets;
  const types = Object.entries(assets.by_device_type).sort((a, b) => b[1] - a[1]);
  const lastJob = hub.jobs.data?.items[0];

  return (
    <div className="stack">
      {summary.error && (
        <div className="banner banner--warn" role="alert">
          Fallo al actualizar: {errorMessage(summary.error)}. Se muestran los últimos datos recibidos.
        </div>
      )}
      {assets.total === 0 ? (
        <EmptyState title="Todavía no hay dispositivos">
          Inicia un descubrimiento sobre una red autorizada o instala el agente en un equipo.
        </EmptyState>
      ) : (
        <>
          <section className="stats" aria-label="Dispositivos por método">
            {METHODS.map((method: MonitoringMethod) => (
              <Link key={method} className="stat" to={devicesLink({ method })}>
                <span className="stat__label">{METHOD_LABELS[method]}</span>
                <span className="stat__value">{assets.by_method[method] ?? 0}</span>
              </Link>
            ))}
            <Link className="stat stat--all" to={devicesLink()}>
              <span className="stat__label">Total</span>
              <span className="stat__value">{assets.total}</span>
            </Link>
          </section>
          <section className="stats" aria-label="Dispositivos por estado">
            {(["online", "offline", "unknown"] as const).map((status) => (
              <Link key={status} className={`stat stat--${status}`} to={devicesLink({ status })}>
                <span className="stat__label">{STATUS_LABELS[status]}</span>
                <span className="stat__value">{assets[status]}</span>
              </Link>
            ))}
          </section>
          <section className="panel" aria-label="Dispositivos por tipo">
            <div className="panel__toolbar">
              <h2>Por tipo</h2>
            </div>
            <ul className="chip-list" aria-label="Recuento por tipo">
              {types.map(([type, count]) => (
                <li key={type}>
                  <Link className="badge badge--muted" to={devicesLink({ type })}>
                    {type === "unknown" ? "Desconocido" : deviceTypeLabel(type)}: {count}
                  </Link>
                </li>
              ))}
            </ul>
          </section>
        </>
      )}

      <section className="panel" aria-label="Estado del descubrimiento">
        <div className="panel__toolbar">
          <h2>Descubrimiento</h2>
          <Link to="/network/discovery" className="small">
            Ver historial
          </Link>
        </div>
        {hub.jobs.loading ? (
          <LoadingState label="Cargando ejecuciones…" />
        ) : !lastJob ? (
          <p className="muted small panel--padded">
            {hub.jobs.error ? `No se pudo leer el historial: ${errorMessage(hub.jobs.error)}` : "Aún no se ha ejecutado ningún descubrimiento."}
          </p>
        ) : (
          <p className="small panel--padded">
            Última ejecución:{" "}
            <button type="button" className="link-button" onClick={() => hub.openDiscovery(lastJob.job_id)}>
              {formatDateTime(lastJob.started_at)}
            </button>{" "}
            en <span className="mono">{lastJob.target}</span> ·{" "}
            <span className={JOB_STATUS_CLASS[lastJob.status]}>{JOB_STATUS_LABELS[lastJob.status]}</span> ·{" "}
            {lastJob.hosts_alive} encontrados
          </p>
        )}
      </section>
      <div className="panels-2">
        <SchedulePanel schedule={hub.schedule.data} error={hub.schedule.error} />
        <ScopePanel scope={hub.scope.data} error={hub.scope.error} />
      </div>

      {canChanges && <RecentChanges siteId={scopeId} />}
    </div>
  );
}

/** Últimos cambios de red detectados (topología e identidad), con enlace al historial. */
function RecentChanges({ siteId }: { siteId: string | undefined }) {
  const fetcher = useCallback(
    (signal: AbortSignal) => topologyHistoryApi.changes({ siteId, limit: RECENT_CHANGES }, signal),
    [siteId],
  );
  const { data, error, loading, refresh } = usePolling(fetcher, REFRESH_MS);
  return (
    <section className="panel" aria-label="Cambios recientes">
      <div className="panel__toolbar">
        <h2>Cambios recientes</h2>
        <Link to="/network/changes" className="small">
          Ver historial de cambios
        </Link>
      </div>
      {loading ? (
        <LoadingState label="Cargando cambios…" />
      ) : !data ? (
        <ErrorState message={errorMessage(error ?? new Error("Sin datos"))} onRetry={refresh} />
      ) : data.items.length === 0 ? (
        <p className="muted small panel--padded">Sin cambios de red detectados.</p>
      ) : (
        <ul className="plain-list small panel--padded" aria-label="Últimos cambios">
          {data.items.map((c) => (
            <li key={c.id}>
              <span title={formatDateTime(c.detected_at)}>{formatRelative(c.detected_at)}</span> ·{" "}
              {CHANGE_TYPE_LABELS[c.change_type] ?? c.change_type} ·{" "}
              {c.asset_id ? (
                <Link to={`/assets/${encodeURIComponent(c.asset_id)}`}>{c.subject_label ?? c.subject_key}</Link>
              ) : (
                (c.subject_label ?? c.subject_key)
              )}{" "}
              <span className="muted mono">
                {plainValue(c.before)} → {plainValue(c.after)}
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
