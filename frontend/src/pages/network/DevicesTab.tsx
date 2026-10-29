import { useCallback, useEffect, useMemo, useRef, useState, type KeyboardEvent, type MouseEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { sentraApi } from "../../api/sentra";
import type { Asset, AssetStatus } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { AssetLabelDialog } from "../../components/asset/AssetLabelDialog";
import { ContextFilterBar } from "../../components/asset/ContextFilterBar";
import { DevicePanel } from "../../components/asset/DevicePanel";
import { IdentityBadge } from "../../components/asset/IdentityBadge";
import { ColumnPicker, type ColumnOption } from "../../components/ColumnPicker";
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
import { assetTitle, DEVICE_TYPE_OPTIONS, osLabel } from "../../lib/identity";
import { useDebounced } from "../../lib/useDebounced";
import { usePolling } from "../../lib/usePolling";
import {
  readDevicesFilters,
  saveDevicesFilters,
  useDevicesColumns,
  useDevicesDensity,
} from "../../ui/preferences";
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

// Fase 7B.3: columnas básicas fijas (Dispositivo | Identidad | IP | Estado | Riesgo | Última
// actividad | Acciones) y el resto opcionales, elegidas por cada analista y guardadas en su
// navegador. La vista detallada añade debajo del nombre el tipo, el SO y el método, así que
// por defecto no hace falta ninguna columna opcional (la tabla cabe sin scroll en 1366 px).
type OptionalColumn = "type" | "method" | "site" | "resources" | "ports" | "first" | "network";
const OPTIONAL_COLUMNS: (ColumnOption & { id: OptionalColumn })[] = [
  { id: "type", label: "Tipo / SO" },
  { id: "method", label: "Método" },
  { id: "site", label: "Site" },
  { id: "resources", label: "CPU / RAM / Disco" },
  { id: "ports", label: "Puertos" },
  { id: "first", label: "Descubierto" },
  { id: "network", label: "Visto en red" },
];
const OPTIONAL_IDS = OPTIONAL_COLUMNS.map((c) => c.id);
const DEFAULT_COLUMNS: OptionalColumn[] = ["site"];

/** Fila anterior o siguiente con flechas: la tabla se recorre sin ratón. */
function moveRowFocus(row: HTMLTableRowElement, delta: 1 | -1) {
  const next = delta === 1 ? row.nextElementSibling : row.previousElementSibling;
  if (next instanceof HTMLTableRowElement) next.focus();
}

function isInteractive(target: EventTarget | null): boolean {
  return target instanceof Element && target.closest("a, button, input, select, textarea, label, summary") !== null;
}

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
 * Red › Dispositivos (Fase 7A.5; rediseño SOC en 7B.3): la tabla única de activos. Reúne lo que ofrecían la tabla
 * del dashboard (estado y ciclo de vida, riesgo y criticidad, CPU/RAM/disco, filtros de
 * contexto, archivados) y la de Red (MAC y NIC, tipo, puertos con acceso al servicio, subred,
 * orden por columna, etiquetas en línea). Los filtros viven en la URL para poder enlazarlos.
 */
export function DevicesTab() {
  const hub = useNetworkHub();
  const canLabel = useAuth().can("assets:manage");
  const [params, setParams] = useSearchParams();
  // Filtros persistentes: al volver sin parámetros se restauran los últimos usados (la URL
  // sigue siendo la fuente de verdad y se puede enlazar). Se avisa para que no sorprenda.
  const [restored] = useState(() => (params.toString() === "" ? readDevicesFilters() : ""));
  const restoring = useRef(Boolean(restored));
  useEffect(() => {
    if (restored) setParams(restored, { replace: true });
    // Solo al montar: después manda lo que el usuario cambie.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  useEffect(() => {
    if (restoring.current) {
      if (params.toString() === "") return;
      restoring.current = false;
    }
    saveDevicesFilters(params.toString());
  }, [params]);
  const [storedColumns, setColumns] = useDevicesColumns(OPTIONAL_IDS);
  const columns = new Set<string>(storedColumns ?? DEFAULT_COLUMNS);
  const [density, setDensity] = useDevicesDensity();
  const detailed = density === "detailed";
  const [selected, setSelected] = useState<Asset>();
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
  const show = (id: OptionalColumn) => columns.has(id) && (id !== "site" || hub.showSite);
  const pickerOptions = OPTIONAL_COLUMNS.filter((c) => c.id !== "site" || hub.showSite);
  const open = (asset: Asset) => setSelected(asset);
  const onRowClick = (event: MouseEvent<HTMLTableRowElement>, asset: Asset) => {
    if (!isInteractive(event.target)) open(asset);
  };
  const onRowKey = (event: KeyboardEvent<HTMLTableRowElement>, asset: Asset) => {
    if (event.target !== event.currentTarget) return;
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      open(asset);
    } else if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      moveRowFocus(event.currentTarget, event.key === "ArrowDown" ? 1 : -1);
    }
  };
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
          <div className="segmented" role="group" aria-label="Densidad de la tabla">
            {(
              [
                ["detailed", "Detallada"],
                ["compact", "Compacta"],
              ] as const
            ).map(([value, label]) => (
              <button
                key={value}
                type="button"
                className={`segmented__item${density === value ? " segmented__item--active" : ""}`}
                aria-pressed={density === value}
                onClick={() => setDensity(value)}
              >
                {label}
              </button>
            ))}
          </div>
          <ColumnPicker
            options={pickerOptions}
            visible={[...columns]}
            onChange={(next) => setColumns(next)}
            onReset={() => setColumns(null)}
          />
        </Toolbar>
        {restored && params.toString() === restored && (
          <p className="small muted" role="status">
            Se han restaurado los filtros de tu última visita.{" "}
            <button type="button" className="button button--small" onClick={() => setParams("", { replace: true })}>
              Quitar filtros
            </button>
          </p>
        )}
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
            <table className={`table table--devices${detailed ? "" : " table--compact"}`}>
              <thead>
                <tr>
                  {header("Dispositivo", "name")}
                  <th>Identidad</th>
                  {header("IP", "ip")}
                  {show("type") && header("Tipo / SO", "type")}
                  {header("Estado", "status")}
                  {show("method") && header("Método", "method")}
                  {show("site") && <th>Site</th>}
                  {header("Riesgo", "risk", true)}
                  {show("resources") && <th>CPU / RAM / Disco</th>}
                  {show("ports") && header("Puertos", "ports", true)}
                  {show("first") && secondaryHeader("Descubierto", "first")}
                  {show("network") && secondaryHeader("Visto en red", "network")}
                  {header("Última actividad", "last")}
                  <th>Acciones</th>
                </tr>
              </thead>
              <tbody>
                {items.map((asset) => {
                  const os = osLabel(asset);
                  const title = assetTitle(asset);
                  return (
                    <tr
                      key={asset.asset_id}
                      className={`table__row--link${selected?.asset_id === asset.asset_id ? " table__row--selected" : ""}`}
                      tabIndex={0}
                      aria-label={`${title}, ${asset.primary_ip}. Enter abre el detalle`}
                      onClick={(event) => onRowClick(event, asset)}
                      onKeyDown={(event) => onRowKey(event, asset)}
                    >
                      <td>
                        <AssetName asset={asset} showIp={false} onEditLabel={canLabel ? setLabelAsset : undefined} />
                        {detailed && !show("type") && (
                          <div className="small muted cell-detail">
                            <DeviceTypeCell asset={asset} />
                            {os && <span> · {os}</span>}
                          </div>
                        )}
                        {detailed && !show("method") && (
                          <div className="small cell-detail">
                            <MethodBadge method={asset.monitoring_method} />
                          </div>
                        )}
                      </td>
                      <td>
                        <IdentityBadge asset={asset} showMac={detailed} />
                        {detailed && asset.network_adapter_vendor && (
                          <div className="small muted">NIC {asset.network_adapter_vendor}</div>
                        )}
                      </td>
                      <td className="mono">{asset.primary_ip}</td>
                      {show("type") && (
                        <td>
                          <DeviceTypeCell asset={asset} />
                          {os && <div className="small muted">{os}</div>}
                        </td>
                      )}
                      <td>
                        {/* Fase 5C.2: Inactivo / Candidato a limpieza / Archivado ganan a En línea / Sin conexión. */}
                        <AssetStateBadge asset={asset} />
                      </td>
                      {show("method") && (
                        <td>
                          <MethodBadge method={asset.monitoring_method} />
                        </td>
                      )}
                      {show("site") && <td className="small">{asset.site_name}</td>}
                      <td>
                        <RiskCell score={asset.risk_score} level={asset.risk_level} confidence={asset.risk_confidence} />
                        {/* Fase 4L: criticidad (solo si no es la de por defecto) y rol confirmado. */}
                        {detailed && (asset.criticality !== "medium" || asset.role !== "unknown") && (
                          <div className="small">
                            {asset.criticality !== "medium" && <CriticalityBadge criticality={asset.criticality} />}{" "}
                            {asset.role !== "unknown" && <span className="muted">{ROLE_LABELS[asset.role]}</span>}
                          </div>
                        )}
                      </td>
                      {show("resources") && (
                        <td>
                          <ResourcesCell asset={asset} />
                        </td>
                      )}
                      {show("ports") && (
                        <td>
                          <PortList ports={asset.open_ports} address={asset.primary_ip} />
                        </td>
                      )}
                      {show("first") && (
                        <td className="muted col-secondary" title={formatDateTime(asset.discovered_at ?? asset.first_seen_at)}>
                          {formatRelative(asset.discovered_at ?? asset.first_seen_at)}
                        </td>
                      )}
                      {show("network") && (
                        <td className="muted col-secondary" title={formatDateTime(asset.last_network_seen_at)}>
                          {asset.last_network_seen_at ? formatRelative(asset.last_network_seen_at) : "—"}
                        </td>
                      )}
                      {/* Contacto del agente o, sin agente, el último descubrimiento que lo vio. */}
                      <td title={formatDateTime(asset.last_seen_at ?? asset.last_network_seen_at)}>
                        {formatRelative(asset.last_seen_at ?? asset.last_network_seen_at)}
                      </td>
                      <td>
                        <div className="row-actions">
                          <button
                            type="button"
                            className="button button--small"
                            aria-label={`Ver detalle de ${title}`}
                            onClick={() => open(asset)}
                          >
                            Detalle
                          </button>
                          <Link className="button button--small" to={`/assets/${asset.asset_id}`} aria-label={`Abrir ficha de ${title}`}>
                            Ficha
                          </Link>
                        </div>
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

      {selected && (
        <DevicePanel asset={selected} onClose={() => setSelected(undefined)} onChanged={() => refresh()} />
      )}
      {labelAsset && (
        <AssetLabelDialog asset={labelAsset} onClose={() => setLabelAsset(undefined)} onSaved={() => refresh()} />
      )}
    </div>
  );
}
