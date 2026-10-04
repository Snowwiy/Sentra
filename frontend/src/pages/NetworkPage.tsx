import { useCallback, useMemo } from "react";
import { Link, useNavigate } from "react-router-dom";
import { sentraApi } from "../api/sentra";
import type {
  Asset,
  DiscoveryJob,
  DiscoveryJobStatus,
  DiscoveryScope,
  MonitoringMethod,
} from "../api/types";
import { FilterSelect, Pager, SearchInput, SortHeader, Toolbar } from "../components/ListControls";
import {
  DEVICE_TYPE_LABELS,
  METHOD_LABELS,
  MethodBadge,
  PortList,
  deviceTypeLabel,
} from "../components/NetworkBadges";
import { EmptyState, ErrorState, LoadingState } from "../components/StateViews";
import { StatusBadge } from "../components/StatusBadge";
import { config } from "../config";
import { errorMessage, formatDateTime, formatRelative } from "../lib/format";
import { compareBy, listPage, matchesText } from "../lib/listing";
import { inIpv4Network, ipSortKey } from "../lib/net";
import { useListState } from "../lib/useListState";
import { usePolling } from "../lib/usePolling";

// Discovery runs every few minutes at most: no need to poll as often as live telemetry.
const REFRESH_MS = Math.max(config.refreshIntervalMs, 60_000);
const PAGE_SIZE = 50;

type Key = "ip" | "name" | "type" | "status" | "method" | "first" | "last" | "ports";

const SORTERS: Record<Key, (a: Asset) => string | number | null> = {
  ip: (a) => ipSortKey(a.primary_ip),
  name: (a) => a.hostname ?? a.reverse_dns,
  type: (a) => a.device_type,
  status: (a) => a.status,
  method: (a) => a.monitoring_method,
  first: (a) => a.discovered_at ?? a.first_seen_at,
  last: (a) => a.last_network_seen_at,
  ports: (a) => a.open_ports.length,
};

const METHODS: MonitoringMethod[] = ["discovered", "agentless", "agent"];

const JOB_STATUS: Record<DiscoveryJobStatus, string> = {
  running: "En curso",
  completed: "Completado",
  cancelled: "Parcial",
  failed: "Fallido",
};

function inSubnet(asset: Asset, subnet: string): boolean {
  return asset.discovery_network === subnet || inIpv4Network(asset.primary_ip, subnet);
}

export function NetworkPage() {
  const fetchAssets = useCallback((signal: AbortSignal) => sentraApi.listAssets(signal), []);
  const assets = usePolling(fetchAssets, REFRESH_MS);
  const fetchScope = useCallback((signal: AbortSignal) => sentraApi.discoveryScope(signal), []);
  const scope = usePolling(fetchScope, 10 * REFRESH_MS);
  const fetchJobs = useCallback((signal: AbortSignal) => sentraApi.discoveryJobs(10, signal), []);
  const jobs = usePolling(fetchJobs, REFRESH_MS);
  const navigate = useNavigate();

  const list = useListState<Key, { method: string; status: string; type: string; subnet: string }>(
    { key: "ip", dir: "asc" },
    { method: "", status: "", type: "", subnet: "" },
  );
  const items = useMemo(() => assets.data?.items ?? [], [assets.data]);
  const types = useMemo(() => {
    const seen = new Set(items.map((a) => a.device_type ?? "unknown"));
    return [...seen].sort().map((value) => ({
      value,
      label: value === "unknown" ? "Desconocido" : (DEVICE_TYPE_LABELS[value] ?? value),
    }));
  }, [items]);
  const subnets = scope.data?.allowed_networks ?? [];
  const counts = useMemo(() => {
    const result: Record<MonitoringMethod, number> = { discovered: 0, agentless: 0, agent: 0 };
    for (const asset of items) result[asset.monitoring_method] += 1;
    return result;
  }, [items]);

  const page = listPage(items, {
    filter: (a) =>
      (!list.filters.method || a.monitoring_method === list.filters.method) &&
      (!list.filters.status || a.status === list.filters.status) &&
      (!list.filters.type || (a.device_type ?? "unknown") === list.filters.type) &&
      (!list.filters.subnet || inSubnet(a, list.filters.subnet)) &&
      matchesText(list.query, a.display_name, a.primary_ip, a.mac_address, a.reverse_dns),
    compare: compareBy(SORTERS[list.sort.key], list.sort.dir),
    page: list.page,
    pageSize: PAGE_SIZE,
  });
  const header = (label: string, key: Key, numeric = false) => (
    <SortHeader label={label} sortKey={key} sort={list.sort} onSort={list.setSort} numeric={numeric} />
  );

  if (assets.loading) return <LoadingState label="Cargando red…" />;
  if (!assets.data && assets.error) {
    return <ErrorState message={errorMessage(assets.error)} onRetry={assets.refresh} />;
  }

  return (
    <div className="page">
      <div className="page__header">
        <div>
          <h1>Red</h1>
          <p className="muted small">
            Activos descubiertos en las redes autorizadas y activos con agente, en una sola vista.
          </p>
        </div>
      </div>

      <section className="stats" aria-label="Activos por método">
        {METHODS.map((method) => (
          <button
            key={method}
            type="button"
            className={`stat${list.filters.method === method ? " stat--active" : ""}`}
            aria-pressed={list.filters.method === method}
            onClick={() => list.setFilter("method", list.filters.method === method ? "" : method)}
          >
            <span className="stat__label">{METHOD_LABELS[method]}</span>
            <span className="stat__value">{counts[method]}</span>
          </button>
        ))}
      </section>

      <ScopePanel scope={scope.data} error={scope.error} />

      <section className="panel">
        <Toolbar>
          <SearchInput
            value={list.query}
            onChange={list.setQuery}
            placeholder="Buscar nombre, IP o MAC"
            label="Buscar en la red"
          />
          <FilterSelect
            label="Método"
            value={list.filters.method}
            options={METHODS.map((m) => ({ value: m, label: METHOD_LABELS[m] }))}
            onChange={(v) => list.setFilter("method", v)}
          />
          <FilterSelect
            label="Estado"
            value={list.filters.status}
            options={[
              { value: "online", label: "Online" },
              { value: "offline", label: "Offline" },
              { value: "unknown", label: "Unknown" },
            ]}
            onChange={(v) => list.setFilter("status", v)}
          />
          <FilterSelect label="Tipo" value={list.filters.type} options={types} onChange={(v) => list.setFilter("type", v)} />
          {subnets.length > 0 && (
            <FilterSelect
              label="Subred"
              value={list.filters.subnet}
              options={subnets}
              onChange={(v) => list.setFilter("subnet", v)}
              allLabel="Todas"
            />
          )}
        </Toolbar>
        {items.length === 0 ? (
          <EmptyState title="Sin activos">
            Configura DISCOVERY_ALLOWED_NETWORKS y ejecuta <code>python -m app.cli discover</code> en
            el servidor, o instala el agente en un equipo.
          </EmptyState>
        ) : page.total === 0 ? (
          <EmptyState title="Ningún activo coincide con el filtro" />
        ) : (
          <>
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    {header("IP", "ip")}
                    {header("Nombre", "name")}
                    <th>MAC</th>
                    {header("Tipo", "type")}
                    {header("Estado", "status")}
                    {header("Método", "method")}
                    {header("Descubierto", "first")}
                    {header("Visto en red", "last")}
                    {header("Puertos", "ports", true)}
                  </tr>
                </thead>
                <tbody>
                  {page.items.map((asset) => (
                    <tr
                      key={asset.asset_id}
                      className="table__row--link"
                      onClick={() => navigate(`/assets/${asset.asset_id}`)}
                    >
                      <td className="mono">
                        <Link to={`/assets/${asset.asset_id}`} className="strong">
                          {asset.primary_ip}
                        </Link>
                      </td>
                      <td>{asset.hostname ?? asset.reverse_dns ?? <span className="muted">—</span>}</td>
                      <td className="mono small muted">{asset.mac_address ?? "—"}</td>
                      <td title={asset.device_type_reason ?? "No se puede determinar con la información disponible"}>
                        {deviceTypeLabel(asset.device_type)}
                      </td>
                      <td>
                        <StatusBadge status={asset.status} />
                      </td>
                      <td>
                        <MethodBadge method={asset.monitoring_method} />
                      </td>
                      <td className="muted" title={formatDateTime(asset.discovered_at ?? asset.first_seen_at)}>
                        {formatRelative(asset.discovered_at ?? asset.first_seen_at)}
                      </td>
                      <td className="muted" title={formatDateTime(asset.last_network_seen_at)}>
                        {asset.last_network_seen_at ? formatRelative(asset.last_network_seen_at) : "—"}
                      </td>
                      <td>
                        <PortList ports={asset.open_ports} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pager page={page.page} pages={page.pages} total={page.total} onPage={list.setPage} noun="activos" />
          </>
        )}
      </section>

      <JobsPanel jobs={jobs.data?.items} loading={jobs.loading} error={jobs.error} />
    </div>
  );
}

function ScopePanel({ scope, error }: { scope: DiscoveryScope | undefined; error: Error | undefined }) {
  if (!scope) {
    return error ? (
      <div className="banner banner--warn" role="alert">
        No se pudo leer la configuración de descubrimiento: {errorMessage(error)}
      </div>
    ) : null;
  }
  if (!scope.enabled) {
    return (
      <div className="banner" role="status">
        Descubrimiento de red desactivado: define DISCOVERY_ALLOWED_NETWORKS en el servidor (solo
        se exploran las redes que autorices).
      </div>
    );
  }
  return (
    <section className="panel" aria-label="Alcance del descubrimiento">
      <dl className="fields fields--inline">
        <div className="field">
          <dt>Redes autorizadas</dt>
          <dd className="mono">{scope.allowed_networks.join(", ")}</dd>
        </div>
        {scope.excluded.length > 0 && (
          <div className="field">
            <dt>Excluidas</dt>
            <dd className="mono">{scope.excluded.join(", ")}</dd>
          </div>
        )}
        <div className="field">
          <dt>Puertos TCP</dt>
          <dd className="mono small">{scope.ports.join(", ")}</dd>
        </div>
        <div className="field">
          <dt>Ejecución</dt>
          <dd>
            {scope.interval_minutes ? `cada ${scope.interval_minutes} min` : "manual"}
            <span className="muted small"> · manual: python -m app.cli discover</span>
          </dd>
        </div>
      </dl>
    </section>
  );
}

function JobsPanel({
  jobs,
  loading,
  error,
}: {
  jobs: DiscoveryJob[] | undefined;
  loading: boolean;
  error: Error | undefined;
}) {
  return (
    <section className="panel" aria-label="Ejecuciones de descubrimiento">
      <div className="panel__toolbar">
        <h2>Ejecuciones recientes</h2>
      </div>
      {jobs && jobs.length > 0 ? (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Inicio</th>
                <th>Red</th>
                <th>Estado</th>
                <th>Origen</th>
                <th>Escaneados</th>
                <th>Activos</th>
                <th>Nuevos</th>
                <th>Puertos</th>
                <th>Duración</th>
                <th>Errores</th>
              </tr>
            </thead>
            <tbody>
              {jobs.map((job) => (
                <tr key={job.job_id}>
                  <td title={formatDateTime(job.started_at)}>{formatRelative(job.started_at)}</td>
                  <td className="mono">{job.target}</td>
                  <td>
                    {JOB_STATUS[job.status]}
                    {job.baseline && <span className="badge" title="Primera ejecución completa: establece la línea base sin alertas"> baseline</span>}
                  </td>
                  <td className="muted">{job.trigger === "manual" ? "Manual" : "Programado"}</td>
                  <td>{job.hosts_scanned}</td>
                  <td>{job.hosts_alive}</td>
                  <td>{job.hosts_new}</td>
                  <td>{job.open_ports}</td>
                  <td className="muted">{job.duration_seconds != null ? `${job.duration_seconds.toFixed(1)} s` : "—"}</td>
                  <td className={job.error_count ? "text-crit" : "muted"} title={job.errors.join("\n")}>
                    {job.error_count}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : loading ? (
        <LoadingState label="Cargando ejecuciones…" />
      ) : error ? (
        <ErrorState message={errorMessage(error)} />
      ) : (
        <EmptyState title="Sin ejecuciones">
          El descubrimiento se lanza desde el servidor (<code>python -m app.cli discover</code>) o de
          forma periódica con DISCOVERY_INTERVAL_MINUTES.
        </EmptyState>
      )}
    </section>
  );
}
