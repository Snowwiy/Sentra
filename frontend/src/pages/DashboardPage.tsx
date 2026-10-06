import { useCallback, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { sentraApi, type AssetQuery } from "../api/sentra";
import type {
  AssetCriticality,
  AssetEnvironment,
  AssetRole,
  AssetStatus,
  MonitoringMethod,
  NetworkZone,
} from "../api/types";
import { AlertTable } from "../components/AlertTable";
import { EventTable } from "../components/EventTable";
import { IncidentsOverviewPanel } from "../components/incidents/IncidentsOverviewPanel";
import { AssetName } from "../components/DeviceIdentity";
import { MethodBadge } from "../components/NetworkBadges";
import { MetricBar } from "../components/MetricBar";
import { CriticalityBadge, RiskCell } from "../components/risk/RiskBadges";
import { Pager } from "../components/ListControls";
import { EmptyState, ErrorState, LoadingState } from "../components/StateViews";
import { StatusBadge } from "../components/StatusBadge";
import { config } from "../config";
import { errorMessage, formatDateTime, formatRelative } from "../lib/format";
import { typeWithConfidence } from "../lib/identity";
import { usePolling } from "../lib/usePolling";
import { useDebounced } from "../lib/useDebounced";
import { CRITICALITY_LABELS, CRITICALITY_ORDER } from "../lib/risk";
import {
  ENVIRONMENT_LABELS,
  ENVIRONMENT_ORDER,
  ROLE_LABELS,
  ROLE_ORDER,
  ZONE_LABELS,
  ZONE_ORDER,
} from "../lib/assetContext";

type Filter = AssetStatus | "all";

const STAT_CARDS: { key: Filter; label: string }[] = [
  { key: "all", label: "Total Assets" },
  { key: "online", label: "Online" },
  { key: "offline", label: "Offline" },
  { key: "unknown", label: "Unknown" },
];

// Fase 4M: el listado se pagina, filtra y ordena en el servidor. Nunca se descargan todos
// los activos (con 10 000 eran ~1,5 s por refresco); los contadores llegan agregados.
const PAGE_SIZE = 50;

/** Filtros de contexto (Fase 4L) del listado; se aplican en el servidor. */
interface ContextFilters {
  criticality: AssetCriticality | "";
  role: AssetRole | "";
  environment: AssetEnvironment | "";
  networkZone: NetworkZone | "";
  internetExposed: "true" | "false" | "unknown" | "";
  method: MonitoringMethod | "";
  department: string;
  tag: string;
  sort: "name" | "criticality";
}

const NO_FILTERS: ContextFilters = {
  criticality: "",
  role: "",
  environment: "",
  networkZone: "",
  internetExposed: "",
  method: "",
  department: "",
  tag: "",
  sort: "name",
};

function toQuery(f: ContextFilters): AssetQuery {
  return {
    criticality: f.criticality || undefined,
    role: f.role || undefined,
    environment: f.environment || undefined,
    networkZone: f.networkZone || undefined,
    internetExposed: f.internetExposed || undefined,
    method: f.method || undefined,
    department: f.department.trim() || undefined,
    tag: f.tag.trim() || undefined,
    sort: f.sort === "name" ? undefined : f.sort,
  };
}

function FilterSelect<T extends string>({
  label,
  value,
  options,
  labels,
  onChange,
}: {
  label: string;
  value: T | "";
  options: T[];
  labels: Record<T, string>;
  onChange: (value: T | "") => void;
}) {
  return (
    <select
      className="input input--select"
      aria-label={label}
      value={value}
      onChange={(event) => onChange(event.target.value as T | "")}
    >
      <option value="">{label}: todos</option>
      {options.map((option) => (
        <option key={option} value={option}>
          {labels[option]}
        </option>
      ))}
    </select>
  );
}

export function ContextFilterBar({
  filters,
  onChange,
}: {
  filters: ContextFilters;
  onChange: (filters: ContextFilters) => void;
}) {
  const set = <K extends keyof ContextFilters>(key: K, value: ContextFilters[K]) =>
    onChange({ ...filters, [key]: value });
  const active = Object.entries(filters).filter(([k, v]) => k !== "sort" && v !== "").length;
  return (
    <details className="context-filters" open={active > 0}>
      <summary className="small">Filtros de contexto{active > 0 && ` (${active})`}</summary>
      <div className="panel__toolbar panel__toolbar--filters">
        <FilterSelect
          label="Criticidad"
          value={filters.criticality}
          options={CRITICALITY_ORDER}
          labels={CRITICALITY_LABELS}
          onChange={(v) => set("criticality", v)}
        />
        <FilterSelect
          label="Rol"
          value={filters.role}
          options={ROLE_ORDER}
          labels={ROLE_LABELS}
          onChange={(v) => set("role", v)}
        />
        <FilterSelect
          label="Entorno"
          value={filters.environment}
          options={ENVIRONMENT_ORDER}
          labels={ENVIRONMENT_LABELS}
          onChange={(v) => set("environment", v)}
        />
        <FilterSelect
          label="Zona"
          value={filters.networkZone}
          options={ZONE_ORDER}
          labels={ZONE_LABELS}
          onChange={(v) => set("networkZone", v)}
        />
        <FilterSelect
          label="Internet"
          value={filters.internetExposed}
          options={["true", "false", "unknown"]}
          labels={{ true: "Expuesto", false: "No expuesto", unknown: "Desconocida" }}
          onChange={(v) => set("internetExposed", v)}
        />
        <FilterSelect
          label="Gestión"
          value={filters.method}
          options={["discovered", "agentless", "agent"]}
          labels={{ discovered: "Descubierto", agentless: "Monitorizado", agent: "Gestionado" }}
          onChange={(v) => set("method", v)}
        />
        <input
          className="input"
          aria-label="Equipo/Departamento"
          placeholder="Equipo/Departamento"
          value={filters.department}
          maxLength={64}
          onChange={(e) => set("department", e.target.value)}
        />
        <input
          className="input"
          aria-label="Tag"
          placeholder="Tag"
          value={filters.tag}
          maxLength={32}
          onChange={(e) => set("tag", e.target.value)}
        />
        <FilterSelect
          label="Orden"
          value={filters.sort === "name" ? "" : filters.sort}
          options={["criticality"]}
          labels={{ criticality: "Orden: criticidad" }}
          onChange={(v) => set("sort", v || "name")}
        />
        {active > 0 && (
          <button
            type="button"
            className="button button--ghost button--small"
            onClick={() => onChange({ ...NO_FILTERS, sort: filters.sort })}
          >
            Limpiar
          </button>
        )}
      </div>
    </details>
  );
}

export function DashboardPage() {
  const [contextFilters, setContextFilters] = useState<ContextFilters>(NO_FILTERS);
  const [filter, setFilter] = useState<Filter>("all");
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  // Los campos de texto esperan a que se deje de escribir antes de consultar.
  const debouncedFilters = useDebounced(contextFilters, 300);
  const q = useDebounced(query.trim(), 300);
  const fetchAssets = useCallback(
    (signal: AbortSignal) =>
      sentraApi.listAssets(signal, {
        ...toQuery(debouncedFilters),
        status: filter === "all" ? undefined : filter,
        q: q || undefined,
        limit: PAGE_SIZE,
        offset: (page - 1) * PAGE_SIZE,
      }),
    [debouncedFilters, filter, q, page],
  );
  const { data, error, loading, refreshing, updatedAt, refresh } = usePolling(
    fetchAssets,
    config.refreshIntervalMs,
    true,
    true,
  );
  const fetchSummary = useCallback((signal: AbortSignal) => sentraApi.dashboardSummary(signal), []);
  const summary = usePolling(fetchSummary, config.refreshIntervalMs);
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
  const navigate = useNavigate();

  // Cualquier cambio de filtro, búsqueda u orden vuelve a la primera página.
  const changeFilters = (next: ContextFilters) => {
    setContextFilters(next);
    setPage(1);
  };
  const changeStatus = (next: Filter) => {
    setFilter(next);
    setPage(1);
  };
  const changeQuery = (next: string) => {
    setQuery(next);
    setPage(1);
  };

  const assets = data?.items ?? [];
  // Tarjetas: recuento por estado del servidor con los demás filtros aplicados (como antes,
  // los filtros de contexto acotan los contadores; el filtro de estado no).
  const statusCounts = data?.status_counts ?? { online: 0, offline: 0, unknown: 0 };
  const counts: Record<Filter, number> = {
    all: statusCounts.online + statusCounts.offline + statusCounts.unknown,
    ...statusCounts,
  };
  const contextFiltered = Object.values(toQuery(debouncedFilters)).some((v) => v !== undefined);
  const total = data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const kpis = summary.data;

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
            onClick={() => changeStatus(filter === key ? "all" : key)}
          >
            <span className="stat__label">{label}</span>
            <span className="stat__value">{counts[key]}</span>
          </button>
        ))}
      </section>

      {kpis && (
        <p className="muted small" aria-label="Resumen de la plataforma">
          {kpis.assets.by_method.agent} gestionados con agente · {kpis.assets.by_method.discovered}{" "}
          descubiertos · riesgo crítico {kpis.risk.by_level.critical ?? 0} · riesgo alto{" "}
          {kpis.risk.by_level.high ?? 0} · {kpis.detections.active} detecciones activas ·{" "}
          {kpis.active_alerts} alertas activas
        </p>
      )}
      {kpis?.vulnerabilities && (
        <p className="muted small" aria-label="Resumen de vulnerabilidades">
          <Link to="/vulnerabilities">Vulnerabilidades</Link>: críticas {kpis.vulnerabilities.by_severity.critical ?? 0} ·
          altas {kpis.vulnerabilities.by_severity.high ?? 0} · {kpis.vulnerabilities.assets_affected} activos afectados
          · {kpis.vulnerabilities.potential} potenciales sin confirmar
        </p>
      )}

      <IncidentsOverviewPanel />

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
            <span className="muted"> ({total})</span>
          </h2>
          <input
            type="search"
            className="input"
            placeholder="Buscar nombre, IP, MAC o fabricante"
            value={query}
            onChange={(event) => changeQuery(event.target.value)}
            aria-label="Buscar activos"
          />
        </div>
        <ContextFilterBar filters={contextFilters} onChange={changeFilters} />

        {assets.length === 0 && contextFiltered ? (
          <EmptyState title="Ningún activo coincide con los filtros de contexto" />
        ) : assets.length === 0 && (filter !== "all" || q) ? (
          <EmptyState title="Ningún activo coincide con el filtro" />
        ) : assets.length === 0 ? (
          <EmptyState title="No hay activos registrados">
            Los activos aparecerán aquí cuando un agente se registre en la API o cuando el
            descubrimiento de red encuentre equipos en las redes autorizadas.
          </EmptyState>
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
                  <th>Riesgo</th>
                  <th>CPU</th>
                  <th>RAM</th>
                  <th>Disco</th>
                  <th>Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {assets.map((asset) => {
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
                        <RiskCell
                          score={asset.risk_score}
                          level={asset.risk_level}
                          confidence={asset.risk_confidence}
                        />
                        {/* Fase 4L: criticidad (solo si no es la de por defecto) y rol confirmado. */}
                        {(asset.criticality !== "medium" || asset.role !== "unknown") && (
                          <div className="small">
                            {asset.criticality !== "medium" && (
                              <CriticalityBadge criticality={asset.criticality} />
                            )}{" "}
                            {asset.role !== "unknown" && (
                              <span className="muted">{ROLE_LABELS[asset.role]}</span>
                            )}
                          </div>
                        )}
                      </td>
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
        {total > 0 && <Pager page={page} pages={pages} total={total} onPage={setPage} noun="activos" />}
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
