import { useCallback, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { sentraApi } from "../api/sentra";
import type { Asset, AssetStatus } from "../api/types";
import { AlertTable } from "../components/AlertTable";
import { EventTable } from "../components/EventTable";
import { AssetName } from "../components/DeviceIdentity";
import { MethodBadge } from "../components/NetworkBadges";
import { MetricBar } from "../components/MetricBar";
import { EmptyState, ErrorState, LoadingState } from "../components/StateViews";
import { StatusBadge } from "../components/StatusBadge";
import { config } from "../config";
import { errorMessage, formatDateTime, formatRelative } from "../lib/format";
import { deviceTypeLabel, typeWithConfidence } from "../lib/identity";
import { usePolling } from "../lib/usePolling";

type Filter = AssetStatus | "all";

const STAT_CARDS: { key: Filter; label: string }[] = [
  { key: "all", label: "Total Assets" },
  { key: "online", label: "Online" },
  { key: "offline", label: "Offline" },
  { key: "unknown", label: "Unknown" },
];

// Counts are derived from the full list because GET /assets is not paginated yet.
// If pagination is added, these must come from a backend summary endpoint instead.
function countByStatus(assets: Asset[]): Record<Filter, number> {
  const counts: Record<Filter, number> = { all: assets.length, online: 0, offline: 0, unknown: 0 };
  for (const asset of assets) counts[asset.status] += 1;
  return counts;
}

function matches(asset: Asset, query: string): boolean {
  if (!query) return true;
  const q = query.toLowerCase();
  return [
    asset.display_name,
    asset.primary_ip,
    asset.os_name,
    asset.device_type,
    asset.device_type ? deviceTypeLabel(asset.device_type) : null,
    asset.device_vendor,
  ].some((field) => (field ?? "").toLowerCase().includes(q));
}

export function DashboardPage() {
  const fetchAssets = useCallback((signal: AbortSignal) => sentraApi.listAssets(signal), []);
  const { data, error, loading, refreshing, updatedAt, refresh } = usePolling(
    fetchAssets,
    config.refreshIntervalMs,
  );
  const fetchOpenAlerts = useCallback(
    (signal: AbortSignal) => sentraApi.listAlerts({ active: true, limit: 5 }, signal),
    [],
  );
  const openAlerts = usePolling(fetchOpenAlerts, config.refreshIntervalMs);
  const fetchActivity = useCallback(
    (signal: AbortSignal) => sentraApi.listEvents({ minLevel: "warning", limit: 10 }, signal),
    [],
  );
  const activity = usePolling(fetchActivity, config.refreshIntervalMs);
  const [filter, setFilter] = useState<Filter>("all");
  const [query, setQuery] = useState("");
  const navigate = useNavigate();

  const assets = useMemo(
    () => [...(data?.items ?? [])].sort((a, b) => a.display_name.localeCompare(b.display_name)),
    [data],
  );
  const counts = useMemo(() => countByStatus(assets), [assets]);
  const visible = assets.filter(
    (asset) => (filter === "all" || asset.status === filter) && matches(asset, query.trim()),
  );

  if (loading) return <LoadingState label="Cargando activos…" />;
  if (!data && error) return <ErrorState message={errorMessage(error)} onRetry={refresh} />;

  return (
    <div className="page">
      <div className="page__header">
        <div>
          <h1>Activos</h1>
          <p className="muted small">
            {updatedAt && `Actualizado ${formatRelative(updatedAt.toISOString())} · `}
            refresco cada {config.refreshIntervalMs / 1000} s
          </p>
        </div>
        <button type="button" className="button" onClick={refresh} disabled={refreshing}>
          {refreshing ? "Actualizando…" : "Actualizar"}
        </button>
      </div>

      {error && (
        <div className="banner banner--warn" role="alert">
          Fallo al actualizar: {errorMessage(error)}. Se muestran los últimos datos recibidos.
        </div>
      )}

      <section className="stats" aria-label="Resumen de estado">
        {STAT_CARDS.map(({ key, label }) => (
          <button
            key={key}
            type="button"
            className={`stat stat--${key}${filter === key ? " stat--active" : ""}`}
            aria-pressed={filter === key}
            onClick={() => setFilter(filter === key ? "all" : key)}
          >
            <span className="stat__label">{label}</span>
            <span className="stat__value">{counts[key]}</span>
          </button>
        ))}
      </section>

      {openAlerts.data && openAlerts.data.items.length > 0 && (
        <section className="panel panel--alerts" aria-label="Alertas abiertas">
          <div className="panel__toolbar">
            <h2>Alertas abiertas</h2>
            <Link to="/alerts" className="small">
              Ver todas
            </Link>
          </div>
          <AlertTable alerts={openAlerts.data.items} />
        </section>
      )}

      <section className="panel">
        <div className="panel__toolbar">
          <h2>
            {filter === "all" ? "Todos los activos" : `Activos ${filter}`}
            <span className="muted"> ({visible.length})</span>
          </h2>
          <input
            type="search"
            className="input"
            placeholder="Buscar nombre, IP, OS o tipo"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            aria-label="Buscar activos"
          />
        </div>

        {assets.length === 0 ? (
          <EmptyState title="No hay activos registrados">
            Los activos aparecerán aquí cuando un agente se registre en la API o cuando el
            descubrimiento de red encuentre equipos en las redes autorizadas.
          </EmptyState>
        ) : visible.length === 0 ? (
          <EmptyState title="Ningún activo coincide con el filtro" />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Dispositivo</th>
                  <th>Estado</th>
                  <th>Método</th>
                  <th>OS / tipo</th>
                  <th>IP</th>
                  <th>CPU</th>
                  <th>RAM</th>
                  <th>Disco</th>
                  <th>Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((asset) => {
                  const t = asset.latest_telemetry;
                  return (
                    <tr
                      key={asset.asset_id}
                      className="table__row--link"
                      onClick={() => navigate(`/assets/${asset.asset_id}`)}
                    >
                      <td>
                        <AssetName asset={asset} showIp={false} />
                      </td>
                      <td>
                        <StatusBadge status={asset.status} />
                      </td>
                      <td>
                        <MethodBadge method={asset.monitoring_method} />
                      </td>
                      <td>
                        {/* Con agente: SO real. Sin agente: tipo deducido y SO probable si lo hay. */}
                        {asset.os_name ? (
                          <>
                            {asset.os_name} <span className="muted">{asset.os_version}</span>
                          </>
                        ) : (
                          <span className="muted">
                            {typeWithConfidence(asset)}
                            {asset.probable_os && ` · ${asset.probable_os} probable`}
                          </span>
                        )}
                      </td>
                      <td className="mono">{asset.primary_ip}</td>
                      <td>
                        <MetricBar value={t?.cpu_percent} label="CPU" />
                      </td>
                      <td>
                        <MetricBar value={t?.ram_percent} label="RAM" />
                      </td>
                      <td>
                        <MetricBar value={t?.disk_percent} label="Disco" />
                      </td>
                      {/* Agent contact, or the last discovery run that saw it (no agent). */}
                      <td title={formatDateTime(asset.last_seen_at ?? asset.last_network_seen_at)}>
                        {formatRelative(asset.last_seen_at ?? asset.last_network_seen_at)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {activity.data && activity.data.items.length > 0 && (
        <section className="panel" aria-label="Actividad reciente">
          <div className="panel__toolbar">
            <h2>Actividad reciente</h2>
            <span className="muted small">advertencias y errores del sistema</span>
          </div>
          <EventTable events={activity.data.items} />
        </section>
      )}
    </div>
  );
}
