import { useCallback, useState } from "react";
import { Link } from "react-router-dom";
import { endpointApi } from "../../api/sentra6e";
import { sentraApi } from "../../api/sentra";
import { useAuth } from "../../auth/AuthContext";
import { Pager } from "../../components/ListControls";
import { MetricBar } from "../../components/MetricBar";
import { EmptyState, ErrorState, LoadingState } from "../../components/StateViews";
import { AssetStateBadge } from "../../components/StatusBadge";
import { config } from "../../config";
import { devicesLink } from "../../lib/deviceFilters";
import { formatSeconds } from "../../lib/endpoint";
import { errorMessage, formatDateTime, formatRelative, formatUptime } from "../../lib/format";
import { usePolling } from "../../lib/usePolling";
import { useNetworkHub } from "./hubContext";

const PAGE_SIZE = 50;
const METRICS_REFRESH_MS = 60_000;

/**
 * Red › Telemetría (Fase 7A.5): el último envío de CPU, RAM, disco y uptime de cada equipo con
 * agente, y (con telemetry:read) el retraso de ingesta medido por el servidor. Sin agente no hay
 * telemetría de host; el tráfico de red por equipo todavía no se recoge, así que no se inventa.
 */
export function TelemetryTab() {
  const hub = useNetworkHub();
  const canMetrics = useAuth().can("telemetry:read");
  const [page, setPage] = useState(1);
  const { scopeId } = hub;
  const fetcher = useCallback(
    (signal: AbortSignal) =>
      sentraApi.listAssets(signal, {
        siteId: scopeId,
        method: "agent",
        sort: "name",
        limit: PAGE_SIZE,
        offset: (page - 1) * PAGE_SIZE,
      }),
    [scopeId, page],
  );
  const assets = usePolling(fetcher, config.refreshIntervalMs, true, true);

  return (
    <div className="stack">
      {canMetrics && <IngestMetrics />}
      <section className="panel" aria-label="Telemetría de equipos">
        <div className="panel__toolbar">
          <h2>Equipos con agente{assets.data ? ` (${assets.data.total})` : ""}</h2>
          <button type="button" className="button button--small" onClick={assets.refresh}>
            Actualizar
          </button>
        </div>
        {assets.error && assets.data && (
          <div className="banner banner--warn" role="alert">
            Fallo al actualizar: {errorMessage(assets.error)}. Se muestran los últimos datos recibidos.
          </div>
        )}
        {assets.loading ? (
          <LoadingState label="Cargando telemetría…" />
        ) : !assets.data ? (
          <ErrorState message={errorMessage(assets.error ?? new Error("Sin datos"))} onRetry={assets.refresh} />
        ) : assets.data.items.length === 0 ? (
          <EmptyState title="Ningún equipo envía telemetría">
            La telemetría de CPU, RAM y disco llega del agente de host. Los equipos descubiertos por red están en{" "}
            <Link to={devicesLink()}>Dispositivos</Link>.
          </EmptyState>
        ) : (
          <>
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Equipo</th>
                    <th>Estado</th>
                    <th>CPU</th>
                    <th>RAM</th>
                    <th>Disco</th>
                    <th>Uptime</th>
                    <th>Último envío</th>
                  </tr>
                </thead>
                <tbody>
                  {assets.data.items.map((asset) => {
                    const t = asset.latest_telemetry;
                    return (
                      <tr key={asset.asset_id}>
                        <td>
                          <Link to={`/assets/${encodeURIComponent(asset.asset_id)}`}>{asset.display_name}</Link>
                          {asset.primary_ip && <div className="muted small mono">{asset.primary_ip}</div>}
                        </td>
                        <td>
                          <AssetStateBadge asset={asset} />
                        </td>
                        {t ? (
                          <>
                            <td>
                              <MetricBar value={t.cpu_percent} label="CPU" />
                            </td>
                            <td>
                              <MetricBar value={t.ram_percent} label="RAM" />
                            </td>
                            <td>
                              <MetricBar value={t.disk_percent} label="Disco" />
                            </td>
                            <td>{formatUptime(t.uptime_seconds)}</td>
                            <td title={formatDateTime(t.recorded_at)}>{formatRelative(t.recorded_at)}</td>
                          </>
                        ) : (
                          <td colSpan={5} className="muted small">
                            Sin telemetría recibida todavía.
                          </td>
                        )}
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <Pager
              page={page}
              pages={Math.max(1, Math.ceil(assets.data.total / PAGE_SIZE))}
              total={assets.data.total}
              onPage={setPage}
              noun="equipos"
            />
          </>
        )}
      </section>
    </div>
  );
}

/** Retraso de ingesta y equipos que envían actividad (GET /endpoint/metrics, telemetry:read). */
function IngestMetrics() {
  const fetcher = useCallback((signal: AbortSignal) => endpointApi.metrics(signal), []);
  const { data, error, loading, refresh } = usePolling(fetcher, METRICS_REFRESH_MS);
  return (
    <section className="panel panel--padded stack" aria-label="Ingesta de telemetría">
      <h2 className="panel__title">Ingesta de telemetría</h2>
      {loading ? (
        <LoadingState label="Cargando métricas de ingesta…" />
      ) : !data ? (
        <ErrorState message={errorMessage(error ?? new Error("Sin datos"))} onRetry={refresh} />
      ) : (
        <dl className="fields">
          <div className="field">
            <dt>Equipos enviando actividad (última hora)</dt>
            <dd>
              {data.assets_reporting_last_hour} · {data.events_last_hour} eventos
            </dd>
          </div>
          <div className="field">
            <dt>Ingesta evento → servidor (p50 / p95 / máx.)</dt>
            <dd>
              {formatSeconds(data.ingest_lag_p50_seconds)} / {formatSeconds(data.ingest_lag_p95_seconds)} /{" "}
              {formatSeconds(data.ingest_lag_max_seconds)}
            </dd>
          </div>
        </dl>
      )}
    </section>
  );
}
