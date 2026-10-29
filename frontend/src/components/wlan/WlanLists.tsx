import { useCallback, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { wlanApi } from "../../api/sentra";
import type {
  WlanApReportedStatus,
  WlanAuthorizationStatus,
  WlanBand,
  WlanBssRead,
  WlanClientState,
  WlanConfidence,
  WlanFreshness,
  WlanIdentityConfidence,
  WlanProtection,
  WlanSource,
} from "../../api/types";
import { config } from "../../config";
import { errorMessage, formatDateTime, formatRelative } from "../../lib/format";
import { useDebounced } from "../../lib/useDebounced";
import { useListState } from "../../lib/useListState";
import { usePolling } from "../../lib/usePolling";
import {
  AP_STATUS_LABELS,
  AP_STATUSES,
  AUTHORIZATION_ACTIONS,
  AUTHORIZATION_LABELS,
  AUTHORIZATION_STATUSES,
  authorizationTargets,
  BAND_LABELS,
  CLIENT_STATE_LABELS,
  CLIENT_STATES,
  CONFIDENCE_LABELS,
  CONFIDENCES,
  CORRELATION_LABELS,
  FRESHNESS_LABELS,
  FRESHNESS_VALUES,
  IDENTITY_CONFIDENCES,
  IDENTITY_LABELS,
  looksLikeMac,
  PROTECTION_LABELS,
  PROTECTIONS,
  SOURCE_LABELS,
  SOURCES,
  WLAN_BANDS,
} from "../../lib/wlan";
import { FilterSelect, Pager, SearchInput, Toolbar } from "../ListControls";
import { EmptyState, ErrorState, LoadingState } from "../StateViews";
import { AuthorizationModal } from "./WlanActions";
import { WlanClientPanel } from "./WlanClientPanel";
import {
  ApStatusBadge,
  AuthorizationBadge,
  EvidenceBadges,
  FindingBadges,
  MacText,
  ProtectionLabel,
} from "./WlanBadges";

export const WLAN_PAGE_SIZE = 25;

/** Contexto común de las pestañas: alcance de site efectivo y qué columnas mostrar. */
export interface WlanListScope {
  /** site_id a enviar (cabecera o filtro de la tabla), o undefined para todos. */
  siteId: string | undefined;
  /** Mostrar la columna de site (varios sites en el ámbito). */
  showSite: boolean;
  /** Selector de site propio de la tabla (sin alcance global elegido). */
  siteFilter: ReactNode;
}

const bandOptions = WLAN_BANDS.map((b) => ({ value: b, label: BAND_LABELS[b] }));
const authorizationOptions = AUTHORIZATION_STATUSES.map((s) => ({ value: s, label: AUTHORIZATION_LABELS[s] }));
const freshnessOptions = FRESHNESS_VALUES.map((f) => ({ value: f, label: FRESHNESS_LABELS[f] }));
const presenceOptions = [
  { value: "true", label: "En la última consulta" },
  { value: "false", label: "No visto en la última consulta completa" },
];

function When({ iso }: { iso: string | null }) {
  if (!iso) return <span className="muted">nunca</span>;
  return (
    <time dateTime={iso} title={formatDateTime(iso)}>
      {formatRelative(iso)}
    </time>
  );
}

/** Al cambiar el alcance de site se vuelve a la primera página (sin efectos, en el render). */
function useResetPageOnScope(siteId: string | undefined, setPage: (page: number) => void) {
  const [seen, setSeen] = useState(siteId);
  if (seen !== siteId) {
    setSeen(siteId);
    setPage(1);
  }
}

function present(value: string): boolean | undefined {
  return value === "" ? undefined : value === "true";
}

/** Estados comunes de una tabla paginada en el servidor. */
function ListBody<T>({
  state,
  noun,
  loadingLabel,
  filtered,
  emptyTitle,
  emptyHelp,
  page,
  onPage,
  children,
}: {
  state: { data: { items: T[]; total: number } | undefined; error: Error | undefined; refresh: () => void };
  noun: string;
  loadingLabel: string;
  filtered: boolean;
  emptyTitle: string;
  emptyHelp?: ReactNode;
  page: number;
  onPage: (page: number) => void;
  children: (items: T[]) => ReactNode;
}) {
  const data = state.data;
  if (!data) {
    return state.error ? (
      <ErrorState message={errorMessage(state.error)} onRetry={state.refresh} />
    ) : (
      <LoadingState label={loadingLabel} />
    );
  }
  const pages = Math.max(1, Math.ceil(data.total / WLAN_PAGE_SIZE));
  return (
    <>
      {state.error && (
        <div className="banner banner--warn" role="alert">
          Fallo al actualizar: {errorMessage(state.error)}. Se muestran los últimos datos.
        </div>
      )}
      {data.items.length === 0 ? (
        filtered || page > 1 ? (
          <EmptyState title="Nada coincide con el filtro" />
        ) : (
          <EmptyState title={emptyTitle}>{emptyHelp}</EmptyState>
        )
      ) : (
        <>
          {children(data.items)}
          <Pager page={page} pages={pages} total={data.total} onPage={onPage} noun={noun} />
        </>
      )}
    </>
  );
}

// --- Puntos de acceso ------------------------------------------------------------------------

type ApFilters = { authorization: string; status: string; band: string; freshness: string; present: string };

export function AccessPointsTab({
  scope,
  onOpen,
  reloadKey,
}: {
  scope: WlanListScope;
  onOpen: (accessPointId: string) => void;
  /** Cambia tras una acción en el detalle para refrescar la lista. */
  reloadKey: number;
}) {
  const list = useListState<"last_seen", ApFilters>(
    { key: "last_seen", dir: "desc" },
    { authorization: "", status: "", band: "", freshness: "", present: "" },
  );
  useResetPageOnScope(scope.siteId, list.setPage);
  const { filters } = list;
  const q = useDebounced(list.query.trim(), 300);
  const fetchAps = useCallback(
    (signal: AbortSignal) =>
      wlanApi.accessPoints(
        {
          siteId: scope.siteId,
          authorization: (filters.authorization || undefined) as WlanAuthorizationStatus | undefined,
          status: (filters.status || undefined) as WlanApReportedStatus | undefined,
          band: (filters.band || undefined) as WlanBand | undefined,
          freshness: (filters.freshness || undefined) as WlanFreshness | undefined,
          present: present(filters.present),
          q: q || undefined,
          limit: WLAN_PAGE_SIZE,
          offset: (list.page - 1) * WLAN_PAGE_SIZE,
        },
        signal,
      ),
    // reloadKey fuerza una petición nueva tras una acción en el panel de detalle.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [scope.siteId, filters.authorization, filters.status, filters.band, filters.freshness, filters.present, q, list.page, reloadKey],
  );
  const aps = usePolling(fetchAps, config.refreshIntervalMs * 2, true, true);
  const filtered = Boolean(list.query.trim() || Object.values(filters).some(Boolean));

  return (
    <section className="panel" aria-label="Puntos de acceso">
      <div className="panel__toolbar">
        <h2>Puntos de acceso</h2>
        <span className="muted small">
          APs informados por controladoras o APs autónomos consultados por SNMP. Los agentes nunca crean APs.
        </span>
      </div>
      <Toolbar>
        <SearchInput
          value={list.query}
          onChange={(value) => list.setQuery(value.slice(0, 100))}
          placeholder="Nombre, IP, MAC o modelo"
          label="Buscar puntos de acceso"
        />
        {scope.siteFilter}
        <FilterSelect
          label="Autorización"
          value={filters.authorization}
          options={authorizationOptions}
          onChange={(v) => list.setFilter("authorization", v)}
          allLabel="Todas"
        />
        <FilterSelect
          label="Estado informado"
          value={filters.status}
          options={AP_STATUSES.map((s) => ({ value: s, label: AP_STATUS_LABELS[s] }))}
          onChange={(v) => list.setFilter("status", v)}
        />
        <FilterSelect label="Banda" value={filters.band} options={bandOptions} onChange={(v) => list.setFilter("band", v)} allLabel="Todas" />
        <FilterSelect
          label="Frescura"
          value={filters.freshness}
          options={freshnessOptions}
          onChange={(v) => list.setFilter("freshness", v)}
          allLabel="Todas"
        />
        <FilterSelect
          label="Presencia"
          value={filters.present}
          options={presenceOptions}
          onChange={(v) => list.setFilter("present", v)}
          allLabel="Todas"
        />
      </Toolbar>
      <ListBody
        state={aps}
        noun="APs"
        loadingLabel="Cargando puntos de acceso…"
        filtered={filtered}
        emptyTitle="Sin puntos de acceso"
        emptyHelp="Los APs aparecen cuando un sensor con snmp.wlan consulta una controladora o un AP con un perfil SNMP."
        page={list.page}
        onPage={list.setPage}
      >
        {(items) => (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>AP</th>
                  {scope.showSite && <th>Site</th>}
                  <th>Estado informado</th>
                  <th>Autorización</th>
                  <th>SSID</th>
                  <th className="col-secondary">IP de gestión</th>
                  <th className="col-secondary">Modelo</th>
                  <th className="col-secondary">BSS / clientes</th>
                  <th>Evidencia</th>
                  <th>Última vez visto</th>
                </tr>
              </thead>
              <tbody>
                {items.map((ap) => (
                  <tr key={ap.access_point_id}>
                    <td>
                      <button
                        type="button"
                        className="link-button strong"
                        onClick={() => onOpen(ap.access_point_id)}
                        aria-label={`Ver detalle de ${ap.display_name}`}
                      >
                        {ap.display_name}
                      </button>
                      <div className="muted small">{SOURCE_LABELS[ap.source] ?? ap.source}</div>
                    </td>
                    {scope.showSite && <td className="small">{ap.site_name}</td>}
                    <td>
                      <ApStatusBadge status={ap.reported_status} />
                    </td>
                    <td>
                      <AuthorizationBadge status={ap.authorization_status} />
                    </td>
                    <td className="small">{ap.ssids.length ? ap.ssids.join(", ") : <span className="muted">—</span>}</td>
                    <td className="col-secondary mono">{ap.management_ip ?? <span className="muted">—</span>}</td>
                    <td className="col-secondary small">
                      {[ap.vendor, ap.model].filter(Boolean).join(" ") || <span className="muted">—</span>}
                    </td>
                    <td className="col-secondary">
                      {ap.bss_count} / {ap.client_count}
                    </td>
                    <td>
                      <EvidenceBadges freshness={ap.freshness} present={ap.present} />
                    </td>
                    <td className="nowrap">
                      <When iso={ap.last_seen_at} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </ListBody>
    </section>
  );
}

// --- Redes (SSID) ----------------------------------------------------------------------------

export function SsidsTab({ scope, onOpenSsid }: { scope: WlanListScope; onOpenSsid: (ssid: string) => void }) {
  const list = useListState<"ssid", { band: string }>({ key: "ssid", dir: "asc" }, { band: "" });
  useResetPageOnScope(scope.siteId, list.setPage);
  const q = useDebounced(list.query.trim(), 300);
  const fetchSsids = useCallback(
    (signal: AbortSignal) =>
      wlanApi.ssids(
        {
          siteId: scope.siteId,
          band: (list.filters.band || undefined) as WlanBand | undefined,
          q: q || undefined,
          limit: WLAN_PAGE_SIZE,
          offset: (list.page - 1) * WLAN_PAGE_SIZE,
        },
        signal,
      ),
    [scope.siteId, list.filters.band, q, list.page],
  );
  const ssids = usePolling(fetchSsids, config.refreshIntervalMs * 2, true, true);
  const filtered = Boolean(list.query.trim() || list.filters.band);

  return (
    <section className="panel" aria-label="Redes (SSID)">
      <div className="panel__toolbar">
        <h2>Redes (SSID)</h2>
        <span className="muted small">Agregado por site: el mismo SSID en dos sites son dos filas.</span>
      </div>
      <Toolbar>
        <SearchInput
          value={list.query}
          onChange={(value) => list.setQuery(value.slice(0, 64))}
          placeholder="Buscar SSID"
          label="Buscar SSID"
        />
        {scope.siteFilter}
        <FilterSelect
          label="Banda"
          value={list.filters.band}
          options={bandOptions}
          onChange={(v) => list.setFilter("band", v)}
          allLabel="Todas"
        />
      </Toolbar>
      <ListBody
        state={ssids}
        noun="redes"
        loadingLabel="Cargando redes…"
        filtered={filtered}
        emptyTitle="Sin redes Wi-Fi"
        page={list.page}
        onPage={list.setPage}
      >
        {(items) => (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>SSID</th>
                  {scope.showSite && <th>Site</th>}
                  <th>Seguridad</th>
                  <th>Bandas</th>
                  <th>BSS (recientes)</th>
                  <th className="col-secondary">APs</th>
                  <th className="col-secondary">Clientes</th>
                  <th>Clasificación de BSS</th>
                  <th className="col-secondary">Fuentes</th>
                  <th>Última vez visto</th>
                </tr>
              </thead>
              <tbody>
                {items.map((row) => (
                  <tr key={`${row.site_id}:${row.ssid ?? ""}`}>
                    <td>
                      {row.ssid ? (
                        <button
                          type="button"
                          className="link-button strong"
                          onClick={() => onOpenSsid(row.ssid as string)}
                          aria-label={`Ver BSS de ${row.ssid}`}
                        >
                          {row.ssid}
                        </button>
                      ) : (
                        <span className="muted">SSID oculto</span>
                      )}
                      {row.configured_on_controllers > 0 && (
                        <div className="muted small">configurado en {row.configured_on_controllers} controladora(s)</div>
                      )}
                    </td>
                    {scope.showSite && <td className="small">{row.site_name}</td>}
                    <td>
                      <span className="wlan-badges">
                        {row.protections.length ? (
                          row.protections.map((p) => <ProtectionLabel key={p} protection={p} />)
                        ) : (
                          <span className="muted">no informada</span>
                        )}
                      </span>
                      <FindingBadges findings={row.findings} />
                    </td>
                    <td className="small">{row.bands.map((b) => BAND_LABELS[b]).join(", ") || "—"}</td>
                    <td>
                      {row.bss_count} ({row.bss_recent})
                    </td>
                    <td className="col-secondary">{row.access_point_count}</td>
                    <td className="col-secondary">{row.client_count ?? row.controller_client_count ?? "—"}</td>
                    <td className="small">
                      {row.authorized_bss} autorizados · {row.external_bss} externos · {row.unknown_bss} sin clasificar
                    </td>
                    <td className="col-secondary small">{row.sources.map((s) => SOURCE_LABELS[s] ?? s).join(", ")}</td>
                    <td className="nowrap">
                      <When iso={row.last_seen_at} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </ListBody>
    </section>
  );
}

// --- BSS --------------------------------------------------------------------------------------

type BssFilters = {
  authorization: string;
  band: string;
  protection: string;
  source: string;
  confidence: string;
  freshness: string;
  insecure: string;
};

export function BssTab({
  scope,
  canManage,
  initialSsid,
  initialInsecure,
  onOpenAp,
}: {
  scope: WlanListScope;
  canManage: boolean;
  initialSsid?: string;
  initialInsecure?: boolean;
  onOpenAp: (accessPointId: string) => void;
}) {
  const list = useListState<"bssid", BssFilters>(
    { key: "bssid", dir: "asc" },
    {
      authorization: "",
      band: "",
      protection: "",
      source: "",
      confidence: "",
      freshness: "",
      insecure: initialInsecure ? "yes" : "",
    },
  );
  const [ssidInput, setSsidInput] = useState(initialSsid ?? "");
  useResetPageOnScope(scope.siteId, list.setPage);
  const { filters } = list;
  const ssid = useDebounced(ssidInput.trim(), 300);
  const fetchBss = useCallback(
    (signal: AbortSignal) =>
      wlanApi.bss(
        {
          siteId: scope.siteId,
          ssid: ssid || undefined,
          authorization: (filters.authorization || undefined) as WlanAuthorizationStatus | undefined,
          band: (filters.band || undefined) as WlanBand | undefined,
          protection: (filters.protection || undefined) as WlanProtection | undefined,
          source: (filters.source || undefined) as WlanSource | undefined,
          confidence: (filters.confidence || undefined) as WlanConfidence | undefined,
          freshness: (filters.freshness || undefined) as WlanFreshness | undefined,
          insecure: filters.insecure === "yes" ? true : undefined,
          limit: WLAN_PAGE_SIZE,
          offset: (list.page - 1) * WLAN_PAGE_SIZE,
        },
        signal,
      ),
    [
      scope.siteId,
      ssid,
      filters.authorization,
      filters.band,
      filters.protection,
      filters.source,
      filters.confidence,
      filters.freshness,
      filters.insecure,
      list.page,
    ],
  );
  const bss = usePolling(fetchBss, config.refreshIntervalMs * 2, true, true);
  const [editing, setEditing] = useState<{ bss: WlanBssRead; target: WlanAuthorizationStatus }>();
  const filtered = Boolean(ssidInput.trim() || Object.values(filters).some(Boolean));

  return (
    <section className="panel" aria-label="BSS">
      <div className="panel__toolbar">
        <h2>BSS</h2>
        <span className="muted small">
          Cada BSSID que emite un SSID. Lo visto solo por agentes es una observación: no prueba que la red sea de la
          organización.
        </span>
      </div>
      <Toolbar>
        <input
          type="search"
          className="input"
          placeholder="SSID exacto"
          aria-label="Filtrar por SSID exacto"
          value={ssidInput}
          maxLength={64}
          onChange={(e) => {
            setSsidInput(e.target.value);
            list.setPage(1);
          }}
        />
        {scope.siteFilter}
        <FilterSelect
          label="Autorización"
          value={filters.authorization}
          options={authorizationOptions}
          onChange={(v) => list.setFilter("authorization", v)}
          allLabel="Todas"
        />
        <FilterSelect label="Banda" value={filters.band} options={bandOptions} onChange={(v) => list.setFilter("band", v)} allLabel="Todas" />
        <FilterSelect
          label="Seguridad"
          value={filters.protection}
          options={PROTECTIONS.map((p) => ({ value: p, label: PROTECTION_LABELS[p] }))}
          onChange={(v) => list.setFilter("protection", v)}
          allLabel="Todas"
        />
        <FilterSelect
          label="Fuente"
          value={filters.source}
          options={SOURCES.map((s) => ({ value: s, label: SOURCE_LABELS[s] }))}
          onChange={(v) => list.setFilter("source", v)}
          allLabel="Todas"
        />
        <FilterSelect
          label="Confianza"
          value={filters.confidence}
          options={CONFIDENCES.map((c) => ({ value: c, label: CONFIDENCE_LABELS[c] }))}
          onChange={(v) => list.setFilter("confidence", v)}
          allLabel="Todas"
        />
        <FilterSelect
          label="Frescura"
          value={filters.freshness}
          options={freshnessOptions}
          onChange={(v) => list.setFilter("freshness", v)}
          allLabel="Todas"
        />
        <label className="checkbox small">
          <input
            type="checkbox"
            checked={filters.insecure === "yes"}
            onChange={(e) => list.setFilter("insecure", e.target.checked ? "yes" : "")}
          />{" "}
          Solo configuraciones inseguras
        </label>
      </Toolbar>
      <ListBody
        state={bss}
        noun="BSS"
        loadingLabel="Cargando BSS…"
        filtered={filtered}
        emptyTitle="Sin BSS"
        page={list.page}
        onPage={list.setPage}
      >
        {(items) => (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>BSSID</th>
                  <th>SSID</th>
                  {scope.showSite && <th>Site</th>}
                  <th>Banda / canal</th>
                  <th>Seguridad</th>
                  <th>AP</th>
                  <th>Autorización</th>
                  <th className="col-secondary">Procedencia</th>
                  <th className="col-secondary">Señal</th>
                  <th>Evidencia</th>
                  <th>Última vez visto</th>
                  {canManage && <th>Acciones</th>}
                </tr>
              </thead>
              <tbody>
                {items.map((row) => (
                  <tr key={row.bss_id}>
                    <td>
                      <MacText mac={row.bssid} randomized={row.bssid_randomized} />
                    </td>
                    <td>{row.ssid ?? <span className="muted">oculto</span>}</td>
                    {scope.showSite && <td className="small">{row.site_name}</td>}
                    <td className="small">
                      {row.band ? BAND_LABELS[row.band] : "—"}
                      {row.channel != null && <span className="muted"> · canal {row.channel}</span>}
                    </td>
                    <td>
                      <ProtectionLabel protection={row.protection} reported={row.protection_reported} />
                      <FindingBadges findings={row.findings} />
                    </td>
                    <td className="small">
                      {row.access_point ? (
                        <button
                          type="button"
                          className="link-button"
                          onClick={() => row.access_point && onOpenAp(row.access_point.access_point_id)}
                        >
                          {row.access_point.display_name}
                        </button>
                      ) : (
                        <span className="muted">sin AP conocido</span>
                      )}
                    </td>
                    <td>
                      <AuthorizationBadge status={row.authorization_status} />
                    </td>
                    <td className="col-secondary small">
                      {row.sources.map((s) => SOURCE_LABELS[s] ?? s).join(", ")}
                      <div className="muted">{CONFIDENCE_LABELS[row.confidence]}</div>
                      {row.last_agent && (
                        <div className="muted">
                          agente <Link to={`/assets/${row.last_agent.asset_id}`}>{row.last_agent.display_name}</Link>
                        </div>
                      )}
                    </td>
                    <td className="col-secondary small">
                      {row.signal_dbm != null ? `${row.signal_dbm} dBm` : <span className="muted">—</span>}
                    </td>
                    <td>
                      <EvidenceBadges freshness={row.freshness} present={row.present} />
                    </td>
                    <td className="nowrap">
                      <When iso={row.last_seen_at} />
                    </td>
                    {canManage && (
                      <td>
                        <span className="actions">
                          {authorizationTargets(row.authorization_status).map((target) => (
                            <button
                              key={target}
                              type="button"
                              className="button button--small"
                              aria-label={`${AUTHORIZATION_ACTIONS[target]}: ${row.bssid}`}
                              onClick={() => setEditing({ bss: row, target })}
                            >
                              {AUTHORIZATION_ACTIONS[target]}
                            </button>
                          ))}
                        </span>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </ListBody>
      {editing && (
        <AuthorizationModal
          subject={`BSS ${editing.bss.bssid}${editing.bss.ssid ? ` (${editing.bss.ssid})` : ""}`}
          current={editing.bss.authorization_status}
          target={editing.target}
          version={editing.bss.version}
          onSubmit={(input) => wlanApi.setBssAuthorization(editing.bss.bss_id, input)}
          onDone={bss.refresh}
          onConflict={bss.refresh}
          onClose={() => setEditing(undefined)}
        />
      )}
    </section>
  );
}

// --- Clientes ---------------------------------------------------------------------------------

type ClientFilters = { identity: string; state: string; freshness: string; present: string };

export function ClientsTab({ scope }: { scope: WlanListScope }) {
  const list = useListState<"last_seen", ClientFilters>(
    { key: "last_seen", dir: "desc" },
    { identity: "", state: "", freshness: "", present: "" },
  );
  useResetPageOnScope(scope.siteId, list.setPage);
  const { filters } = list;
  const term = useDebounced(list.query.trim(), 300);
  // Un único buscador: una MAC filtra por BSSID y cualquier otro texto por SSID exacto (la
  // API no ofrece búsqueda libre de clientes).
  const byBssid = looksLikeMac(term);
  const fetchClients = useCallback(
    (signal: AbortSignal) =>
      wlanApi.clients(
        {
          siteId: scope.siteId,
          ssid: !byBssid && term ? term : undefined,
          bssid: byBssid ? term : undefined,
          identity: (filters.identity || undefined) as WlanIdentityConfidence | undefined,
          state: (filters.state || undefined) as WlanClientState | undefined,
          freshness: (filters.freshness || undefined) as WlanFreshness | undefined,
          present: present(filters.present),
          limit: WLAN_PAGE_SIZE,
          offset: (list.page - 1) * WLAN_PAGE_SIZE,
        },
        signal,
      ),
    [scope.siteId, term, byBssid, filters.identity, filters.state, filters.freshness, filters.present, list.page],
  );
  const clients = usePolling(fetchClients, config.refreshIntervalMs * 2, true, true);
  // Fase 7B.2: detalle del cliente (observaciones y asociación manual) en un panel lateral.
  const [openClient, setOpenClient] = useState<string>();
  const filtered = Boolean(list.query.trim() || Object.values(filters).some(Boolean));

  return (
    <section className="panel" aria-label="Clientes Wi-Fi">
      <div className="panel__toolbar">
        <h2>Clientes</h2>
        <span className="muted small">
          Una MAC aleatoria nunca identifica un dispositivo: la identidad solo se confirma cuando lo informa el propio
          agente.
        </span>
      </div>
      <Toolbar>
        <SearchInput
          value={list.query}
          onChange={(value) => list.setQuery(value.slice(0, 64))}
          placeholder="SSID exacto o BSSID"
          label="Buscar clientes por SSID o BSSID"
        />
        {scope.siteFilter}
        <FilterSelect
          label="Identidad"
          value={filters.identity}
          options={IDENTITY_CONFIDENCES.map((i) => ({ value: i, label: IDENTITY_LABELS[i] }))}
          onChange={(v) => list.setFilter("identity", v)}
          allLabel="Todas"
        />
        <FilterSelect
          label="Estado"
          value={filters.state}
          options={CLIENT_STATES.map((s) => ({ value: s, label: CLIENT_STATE_LABELS[s] }))}
          onChange={(v) => list.setFilter("state", v)}
        />
        <FilterSelect
          label="Frescura"
          value={filters.freshness}
          options={freshnessOptions}
          onChange={(v) => list.setFilter("freshness", v)}
          allLabel="Todas"
        />
        <FilterSelect
          label="Presencia"
          value={filters.present}
          options={presenceOptions}
          onChange={(v) => list.setFilter("present", v)}
          allLabel="Todas"
        />
      </Toolbar>
      <ListBody
        state={clients}
        noun="clientes"
        loadingLabel="Cargando clientes…"
        filtered={filtered}
        emptyTitle="Sin clientes Wi-Fi"
        page={list.page}
        onPage={list.setPage}
      >
        {(items) => (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Cliente</th>
                  <th>Identidad</th>
                  {scope.showSite && <th>Site</th>}
                  <th>SSID</th>
                  <th className="col-secondary">BSSID</th>
                  <th className="col-secondary">AP</th>
                  <th>Estado</th>
                  <th className="col-secondary">Fuente</th>
                  <th>Evidencia</th>
                  <th>Última vez visto</th>
                  <th>Acciones</th>
                </tr>
              </thead>
              <tbody>
                {items.map((client) => (
                  <tr key={client.client_id}>
                    <td>
                      {/* El activo solo se muestra si la API lo correlacionó; una MAC aleatoria no se usa como nombre. */}
                      {client.asset ? (
                        <Link to={`/assets/${client.asset.asset_id}`} className="strong">
                          {client.asset.display_name}
                        </Link>
                      ) : (
                        <span className="muted">Sin activo asociado</span>
                      )}
                      <div className="small">
                        <MacText mac={client.mac} randomized={client.mac_randomized} />
                      </div>
                    </td>
                    <td className="small">
                      {IDENTITY_LABELS[client.identity_confidence] ?? client.identity_confidence}
                      {client.correlation_basis && (
                        <div className="muted">{CORRELATION_LABELS[client.correlation_basis]}</div>
                      )}
                    </td>
                    {scope.showSite && <td className="small">{client.site_name}</td>}
                    <td>{client.ssid ?? <span className="muted">—</span>}</td>
                    <td className="col-secondary">
                      {client.bssid ? <span className="mono">{client.bssid}</span> : <span className="muted">—</span>}
                    </td>
                    <td className="col-secondary small">{client.access_point?.display_name ?? <span className="muted">—</span>}</td>
                    <td className="small">
                      {CLIENT_STATE_LABELS[client.state] ?? client.state}
                      {client.band && <div className="muted">{BAND_LABELS[client.band]}</div>}
                    </td>
                    <td className="col-secondary small">{SOURCE_LABELS[client.source] ?? client.source}</td>
                    <td>
                      <EvidenceBadges freshness={client.freshness} present={client.present} />
                    </td>
                    <td className="nowrap">
                      <When iso={client.last_seen_at} />
                    </td>
                    <td>
                      <button
                        type="button"
                        className="button button--small"
                        aria-label={`Ver detalle del cliente ${client.mac ?? client.client_id}`}
                        onClick={() => setOpenClient(client.client_id)}
                      >
                        Detalle
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </ListBody>
      {openClient && (
        <WlanClientPanel clientId={openClient} onClose={() => setOpenClient(undefined)} onChanged={clients.refresh} />
      )}
    </section>
  );
}
