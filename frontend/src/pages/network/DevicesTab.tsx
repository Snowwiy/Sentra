import { useCallback, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { sentraApi } from "../../api/sentra";
import type { Asset, AssetStatus } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { AssetLabelDialog } from "../../components/asset/AssetLabelDialog";
import { ContextFilterBar } from "../../components/asset/ContextFilterBar";
import { AssetName, DeviceTypeCell } from "../../components/DeviceIdentity";
import { FilterSelect, Pager, SearchInput, SortHeader, Toolbar } from "../../components/ListControls";
import { MetricBar } from "../../components/MetricBar";
import { METHOD_LABELS, MethodBadge, PortList } from "../../components/NetworkBadges";
import { CriticalityBadge, RiskCell } from "../../components/risk/RiskBadges";
import { EmptyState, ErrorState, LoadingState } from "../../components/StateViews";
import { AssetStateBadge } from "../../components/StatusBadge";
import { config } from "../../config";
import { ROLE_LABELS } from "../../lib/assetContext";
import {
  contextFilterCount,
  deviceSearch,
  isFiltered,
  METHODS,
  readDeviceFilters,
  toAssetQuery,
  type DeviceFilters,
  type DeviceSortKey,
} from "../../lib/deviceFilters";
import { errorMessage, formatDateTime, formatRelative } from "../../lib/format";
import { DEVICE_TYPE_OPTIONS, osLabel } from "../../lib/identity";
import { useDebounced } from "../../lib/useDebounced";
import { usePolling } from "../../lib/usePolling";
import { useNetworkHub } from "./hubContext";

// Fase 4M: el listado se pagina, filtra y ordena en el servidor. Nunca se descargan todos
// los activos; los contadores por estado llegan agregados en la misma respuesta.
const PAGE_SIZE = 50;
// Mientras dura un descubrimiento la tabla se refresca cada 5 s para ver aparecer los equipos.
const ACTIVE_MS = 5_000;

type StatusCard = AssetStatus | "all";
const STATUS_CARDS: { key: StatusCard; label: string }[] = [
  { key: "all", label: "Total" },
  { key: "online", label: "En línea" },
  { key: "offline", label: "Sin conexión" },
  { key: "unknown", label: "Desconocidos" },
];

const STATUS_OPTIONS = [
  { value: "online", label: "En línea" },
  { value: "offline", label: "Sin conexión" },
  { value: "unknown", label: "Desconocido" },
];
const TYPE_OPTIONS = [...DEVICE_TYPE_OPTIONS, { value: "unknown", label: "Desconocido" }];

/** CPU, RAM y disco del último envío del agente; sin agente no hay telemetría. */
function ResourcesCell({ asset }: { asset: Asset }) {
  const t = asset.latest_telemetry;
  if (!t) return <span className="muted">—</span>;
  return (
    <div className="metric-stack" title={`Medido ${formatDateTime(t.recorded_at)}`}>
      {(
        [
          ["CPU", t.cpu_percent],
          ["RAM", t.ram_percent],
          ["Disco", t.disk_percent],
        ] as const
      ).map(([label, value]) => (
        <span key={label} className="metric-stack__row">
          <span className="metric-stack__label muted small">{label}</span>
          <MetricBar value={value} label={label} />
        </span>
      ))}
    </div>
  );
}

/**
 * Red › Dispositivos (Fase 7A.5): la tabla única de activos. Reúne lo que ofrecían la tabla
 * del dashboard (estado y ciclo de vida, riesgo y criticidad, CPU/RAM/disco, filtros de
 * contexto, archivados) y la de Red (MAC y NIC, tipo, puertos con acceso al servicio, subred,
 * orden por columna, etiquetas en línea). Los filtros viven en la URL para poder enlazarlos.
 */
export function DevicesTab() {
  const hub = useNetworkHub();
  const canLabel = useAuth().can("assets:manage");
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const filters = useMemo(() => readDeviceFilters(params), [params]);
  const search = deviceSearch(filters);
  // Los campos de texto esperan a que se deje de escribir antes de consultar.
  const debouncedSearch = useDebounced(search, 300);
  const applied = useMemo(() => readDeviceFilters(new URLSearchParams(debouncedSearch)), [debouncedSearch]);
  // La página vuelve a la primera con cualquier cambio de filtro u orden (y de site: el hub
  // se vuelve a montar).
  const [paging, setPaging] = useState({ search: debouncedSearch, page: 1 });
  const page = paging.search === debouncedSearch ? paging.page : 1;
  const setPage = (next: number) => setPaging({ search: debouncedSearch, page: next });
  const [labelAsset, setLabelAsset] = useState<Asset>();

  const update = (changes: Partial<DeviceFilters>) => {
    setParams(deviceSearch({ ...filters, ...changes }).slice(1), { replace: true });
  };

  const { scopeId, discoveryEpoch } = hub;
  const fetchAssets = useCallback(
    (signal: AbortSignal) =>
      sentraApi.listAssets(signal, {
        ...toAssetQuery(applied),
        limit: PAGE_SIZE,
        offset: (page - 1) * PAGE_SIZE,
        siteId: scopeId,
      }),
    // discoveryEpoch: al terminar un descubrimiento se vuelve a pedir la página en el acto.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [applied, page, scopeId, discoveryEpoch],
  );
  const { data, error, loading, refreshing, updatedAt, refresh } = usePolling(
    fetchAssets,
    hub.discovering ? ACTIVE_MS : config.refreshIntervalMs,
    true,
    true,
  );

  const items = data?.items ?? [];
  const total = data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const statusCounts = data?.status_counts ?? { online: 0, offline: 0, unknown: 0 };
  const counts: Record<StatusCard, number> = {
    all: statusCounts.online + statusCounts.offline + statusCounts.unknown,
    ...statusCounts,
  };
  const subnets = hub.scope.data?.allowed_networks ?? [];
  const sort = { key: filters.sort, dir: filters.dir };
  const header = (label: string, key: DeviceSortKey, numeric = false) => (
    <SortHeader
      label={label}
      sortKey={key}
      sort={sort}
      onSort={(next) => update({ sort: next.key, dir: next.dir })}
      numeric={numeric}
    />
  );
  // Columnas prescindibles en tablet: la cabecera se oculta junto con sus celdas.
  const secondaryHeader = (label: string, key: DeviceSortKey) => (
    <SortHeader
      label={label}
      sortKey={key}
      sort={sort}
      onSort={(next) => update({ sort: next.key, dir: next.dir })}
      className="col-secondary"
    />
  );

  if (loading) return <LoadingState label="Cargando dispositivos…" />;
  if (!data && error) return <ErrorState message={errorMessage(error)} onRetry={refresh} />;

  return (
    <div className="stack">
      <section className="stats" aria-label="Dispositivos por estado">
        {STATUS_CARDS.map(({ key, label }) => {
          const pressed = key === "all" ? filters.status === "" : filters.status === key;
          return (
            <button
              key={key}
              type="button"
              className={`stat stat--${key}${pressed ? " stat--active" : ""}`}
              aria-pressed={pressed}
              onClick={() => update({ status: key === "all" || filters.status === key ? "" : key })}
            >
              <span className="stat__label">{label}</span>
              <span className="stat__value">{counts[key]}</span>
            </button>
          );
        })}
      </section>

      {error && (
        <div className="banner banner--warn" role="alert">
          Fallo al actualizar: {errorMessage(error)}. Se muestran los últimos datos recibidos.
        </div>
      )}

      <section className="panel" aria-label="Dispositivos">
        <div className="panel__toolbar">
          <h2>
            Dispositivos <span className="muted">({total})</span>
          </h2>
          <span className="muted small">
            {hub.discovering
              ? "Actualizando mientras dura el descubrimiento…"
              : updatedAt && `Actualizado ${formatRelative(updatedAt.toISOString())}`}
          </span>
          <button type="button" className="button button--small" onClick={refresh} disabled={refreshing}>
            {refreshing ? "Actualizando…" : "Actualizar"}
          </button>
        </div>
        <Toolbar>
          <SearchInput
            value={filters.q}
            onChange={(q) => update({ q })}
            placeholder="Buscar nombre, IP, MAC o fabricante"
            label="Buscar dispositivos"
          />
          <FilterSelect
            label="Estado"
            value={filters.status}
            options={STATUS_OPTIONS}
            onChange={(v) => update({ status: v as DeviceFilters["status"] })}
          />
          <FilterSelect
            label="Método"
            value={filters.method}
            options={METHODS.map((m) => ({ value: m, label: METHOD_LABELS[m] }))}
            onChange={(v) => update({ method: v as DeviceFilters["method"] })}
          />
          <FilterSelect label="Tipo" value={filters.type} options={TYPE_OPTIONS} onChange={(type) => update({ type })} />
          {(subnets.length > 0 || filters.subnet) && (
            <FilterSelect
              label="Subred"
              value={filters.subnet}
              // "Ver dispositivos" de un job sobre una subred (CLI, sensor) también debe verse elegido.
              options={filters.subnet && !subnets.includes(filters.subnet) ? [...subnets, filters.subnet] : subnets}
              onChange={(subnet) => update({ subnet })}
              allLabel="Todas"
            />
          )}
          <label className="checkbox small">
            <input
              type="checkbox"
              checked={filters.archived}
              onChange={(event) => update({ archived: event.target.checked })}
            />{" "}
            Mostrar archivados
          </label>
          <select
            className="input input--select"
            aria-label="Orden"
            value={filters.sort === "criticality" ? "criticality" : ""}
            onChange={(event) =>
              update(event.target.value ? { sort: "criticality", dir: "asc" } : { sort: "name", dir: "asc" })
            }
          >
            <option value="">Orden: por columna</option>
            <option value="criticality">Orden: criticidad</option>
          </select>
        </Toolbar>
        <ContextFilterBar filters={filters} onChange={update} />

        {items.length === 0 && contextFilterCount(applied) > 0 ? (
          <EmptyState title="Ningún dispositivo coincide con los filtros de contexto" />
        ) : items.length === 0 && isFiltered(applied) ? (
          <EmptyState title="Ningún dispositivo coincide con el filtro" />
        ) : items.length === 0 ? (
          <EmptyState title="No hay dispositivos registrados">
            Aparecerán aquí cuando un agente se registre o cuando el descubrimiento de red encuentre equipos en las
            redes autorizadas. Pulsa «Iniciar descubrimiento» para analizar una red.
          </EmptyState>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  {header("Dispositivo", "name")}
                  {header("IP", "ip")}
                  <th className="col-secondary">MAC / NIC</th>
                  {header("Tipo / SO", "type")}
                  {header("Estado", "status")}
                  {header("Método", "method")}
                  {hub.showSite && <th>Site</th>}
                  <th>Riesgo</th>
                  <th>CPU / RAM / Disco</th>
                  {header("Puertos", "ports", true)}
                  {secondaryHeader("Descubierto", "first")}
                  {secondaryHeader("Visto en red", "network")}
                  {header("Última actividad", "last")}
                </tr>
              </thead>
              <tbody>
                {items.map((asset) => {
                  const os = osLabel(asset);
                  return (
                    <tr
                      key={asset.asset_id}
                      className="table__row--link"
                      onClick={() => navigate(`/assets/${asset.asset_id}`)}
                    >
                      <td>
                        <AssetName asset={asset} showIp={false} onEditLabel={canLabel ? setLabelAsset : undefined} />
                      </td>
                      <td className="mono">{asset.primary_ip}</td>
                      <td className="small muted col-secondary">
                        <span className="mono">{asset.mac_address ?? "—"}</span>
                        {asset.network_adapter_vendor && <div>NIC {asset.network_adapter_vendor}</div>}
                      </td>
                      <td>
                        <DeviceTypeCell asset={asset} />
                        {os && <div className="small muted">{os}</div>}
                      </td>
                      <td>
                        {/* Fase 5C.2: Inactivo / Candidato a limpieza / Archivado ganan a En línea / Sin conexión. */}
                        <AssetStateBadge asset={asset} />
                      </td>
                      <td>
                        <MethodBadge method={asset.monitoring_method} />
                      </td>
                      {hub.showSite && <td className="small">{asset.site_name}</td>}
                      <td>
                        <RiskCell score={asset.risk_score} level={asset.risk_level} confidence={asset.risk_confidence} />
                        {/* Fase 4L: criticidad (solo si no es la de por defecto) y rol confirmado. */}
                        {(asset.criticality !== "medium" || asset.role !== "unknown") && (
                          <div className="small">
                            {asset.criticality !== "medium" && <CriticalityBadge criticality={asset.criticality} />}{" "}
                            {asset.role !== "unknown" && <span className="muted">{ROLE_LABELS[asset.role]}</span>}
                          </div>
                        )}
                      </td>
                      <td>
                        <ResourcesCell asset={asset} />
                      </td>
                      <td>
                        <PortList ports={asset.open_ports} address={asset.primary_ip} />
                      </td>
                      <td className="muted col-secondary" title={formatDateTime(asset.discovered_at ?? asset.first_seen_at)}>
                        {formatRelative(asset.discovered_at ?? asset.first_seen_at)}
                      </td>
                      <td className="muted col-secondary" title={formatDateTime(asset.last_network_seen_at)}>
                        {asset.last_network_seen_at ? formatRelative(asset.last_network_seen_at) : "—"}
                      </td>
                      {/* Contacto del agente o, sin agente, el último descubrimiento que lo vio. */}
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
        {total > 0 && <Pager page={page} pages={pages} total={total} onPage={setPage} noun="dispositivos" />}
      </section>

      {labelAsset && (
        <AssetLabelDialog asset={labelAsset} onClose={() => setLabelAsset(undefined)} onSaved={() => refresh()} />
      )}
    </div>
  );
}
