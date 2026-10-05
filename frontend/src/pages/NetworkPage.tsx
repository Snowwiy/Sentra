import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { sentraApi } from "../api/sentra";
import type { Asset, DiscoveryJob, MonitoringMethod } from "../api/types";
import {
  DISABLED_MESSAGE,
  DISCOVERY_FEATURE,
  DiscoveryModal,
} from "../components/discovery/DiscoveryModal";
import { JobsPanel, SchedulePanel, ScopePanel } from "../components/discovery/DiscoveryPanels";
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
import { isActive } from "../lib/discovery";
import { errorMessage, formatDateTime, formatRelative } from "../lib/format";
import { compareBy, listPage, matchesText } from "../lib/listing";
import { inIpv4Network, ipSortKey } from "../lib/net";
import { useConsole } from "../lib/useConsole";
import { useListState } from "../lib/useListState";
import { usePolling } from "../lib/usePolling";

// Discovery runs every few minutes at most: no need to poll as often as live telemetry.
const REFRESH_MS = Math.max(config.refreshIntervalMs, 60_000);
// Polling controlado mientras hay un descubrimiento activo: el historial cada 2 s y la tabla
// cada 5 s, para ver aparecer los activos sin recargar; en reposo se vuelve a REFRESH_MS.
const ACTIVE_JOBS_MS = 2_000;
const ACTIVE_ASSETS_MS = 5_000;
const SCHEDULE_MS = 30_000;
const PAGE_SIZE = 50;

type ModalState = { jobId?: string } | undefined;

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

function inSubnet(asset: Asset, subnet: string): boolean {
  return asset.discovery_network === subnet || inIpv4Network(asset.primary_ip, subnet);
}

export function NetworkPage() {
  // Si hay algún job en cola o en curso, según la última respuesta del historial. Se
  // actualiza dentro del fetcher (no en un efecto) para elegir el intervalo de polling.
  const [discovering, setDiscovering] = useState(false);
  const fetchJobs = useCallback(async (signal: AbortSignal) => {
    const result = await sentraApi.discoveryJobs(10, signal);
    setDiscovering(result.items.some(isActive));
    return result;
  }, []);
  const jobs = usePolling(fetchJobs, discovering ? ACTIVE_JOBS_MS : REFRESH_MS);
  const fetchAssets = useCallback((signal: AbortSignal) => sentraApi.listAssets(signal), []);
  const assets = usePolling(fetchAssets, discovering ? ACTIVE_ASSETS_MS : REFRESH_MS);
  const fetchScope = useCallback((signal: AbortSignal) => sentraApi.discoveryScope(signal), []);
  const scope = usePolling(fetchScope, 10 * REFRESH_MS);
  const fetchSchedule = useCallback((signal: AbortSignal) => sentraApi.discoverySchedule(signal), []);
  const schedule = usePolling(fetchSchedule, SCHEDULE_MS);
  const consoleState = useConsole(DISCOVERY_FEATURE);
  const [modal, setModal] = useState<ModalState>();
  const tableRef = useRef<HTMLElement>(null);
  const navigate = useNavigate();

  // Al terminar el último descubrimiento activo, la tabla se refresca en el acto con los
  // activos nuevos o actualizados, sin esperar al siguiente intervalo.
  const wasDiscovering = useRef(false);
  const refreshAssets = assets.refresh;
  const refreshJobs = jobs.refresh;
  const refreshSchedule = schedule.refresh;
  useEffect(() => {
    if (wasDiscovering.current && !discovering) {
      refreshAssets();
      refreshSchedule();
    }
    wasDiscovering.current = discovering;
  }, [discovering, refreshAssets, refreshSchedule]);

  const jobChanged = useCallback(
    (job: DiscoveryJob) => {
      // El modal ve antes que el historial que un job empezó o terminó.
      refreshJobs();
      if (!isActive(job)) refreshAssets();
    },
    [refreshJobs, refreshAssets],
  );

  const list = useListState<Key, { method: string; status: string; type: string; subnet: string }>(
    { key: "ip", dir: "asc" },
    { method: "", status: "", type: "", subnet: "" },
  );
  const showDevices = (target: string) => {
    // La red del job y los descubiertos más recientes primero: los nuevos quedan arriba.
    list.setFilter("subnet", target);
    list.setSort({ key: "first", dir: "desc" });
    setModal(undefined);
    tableRef.current?.scrollIntoView?.({ behavior: "smooth", block: "start" });
  };
  const items = useMemo(() => assets.data?.items ?? [], [assets.data]);
  const types = useMemo(() => {
    const seen = new Set(items.map((a) => a.device_type ?? "unknown"));
    return [...seen].sort().map((value) => ({
      value,
      label: value === "unknown" ? "Desconocido" : (DEVICE_TYPE_LABELS[value] ?? value),
    }));
  }, [items]);
  const subnets = scope.data?.allowed_networks ?? [];
  const activeJobs = (jobs.data?.items ?? []).filter(isActive);
  const scopeEnabled = scope.data?.enabled === true;
  const startDisabledReason = !scope.data
    ? "Cargando redes autorizadas…"
    : !scopeEnabled
      ? DISABLED_MESSAGE
      : consoleState.reason;
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

      <div className="network-actions">
        <button
          type="button"
          className="button button--primary"
          disabled={!scopeEnabled || !consoleState.available}
          title={startDisabledReason}
          onClick={() => setModal({})}
        >
          Iniciar descubrimiento
        </button>
        {activeJobs.length > 0 && (
          <span className="muted small" role="status">
            <span className="spinner spinner--inline" aria-hidden="true" /> Descubrimiento{" "}
            {activeJobs[0]?.status === "queued" ? "en cola" : "en curso"} en{" "}
            <span className="mono">{activeJobs.map((j) => j.target).join(", ")}</span> ·{" "}
            <button type="button" className="link-button" onClick={() => setModal({ jobId: activeJobs[0]?.job_id })}>
              Ver progreso
            </button>
          </span>
        )}
      </div>
      {scope.data && scopeEnabled && consoleState.reason && !consoleState.loading && (
        <div className="banner" role="status">
          {consoleState.reason} Puedes consultar el estado y el historial.
        </div>
      )}

      <div className="panels-2">
        <SchedulePanel schedule={schedule.data} error={schedule.error} />
        <ScopePanel scope={scope.data} error={scope.error} />
      </div>

      <section className="panel" aria-label="Activos de red" ref={tableRef}>
        <div className="panel__toolbar">
          <h2>Activos de red</h2>
          {discovering && <span className="muted small">Actualizando mientras dura el descubrimiento…</span>}
        </div>
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
              // "Ver dispositivos" de un job sobre una subred (CLI) también debe verse elegido.
              options={
                list.filters.subnet && !subnets.includes(list.filters.subnet)
                  ? [...subnets, list.filters.subnet]
                  : subnets
              }
              onChange={(v) => list.setFilter("subnet", v)}
              allLabel="Todas"
            />
          )}
        </Toolbar>
        {items.length === 0 ? (
          <EmptyState title="Sin activos">
            Pulsa «Iniciar descubrimiento» para analizar una red autorizada, o instala el agente en
            un equipo.
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

      <JobsPanel
        jobs={jobs.data?.items}
        loading={jobs.loading}
        error={jobs.error}
        onOpen={(job) => setModal({ jobId: job.job_id })}
      />

      {modal && (
        <DiscoveryModal
          scope={scope.data}
          activeJobs={activeJobs}
          initialJobId={modal.jobId}
          canAdminister={consoleState.available}
          adminReason={consoleState.reason}
          onClose={() => setModal(undefined)}
          onShowDevices={showDevices}
          onChanged={jobChanged}
        />
      )}
    </div>
  );
}
