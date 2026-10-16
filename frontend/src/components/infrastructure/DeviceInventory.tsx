import { useCallback, useState } from "react";
import { Link } from "react-router-dom";
import { networkApi } from "../../api/sentra";
import type { NeighborProtocol, NetworkPoll, NetworkPollList, OperStatus, PortKind } from "../../api/types";
import { config } from "../../config";
import { errorMessage, formatDateTime, formatRelative } from "../../lib/format";
import {
  ADMIN_STATUS_LABELS,
  describeModules,
  evidenceSourceLabel,
  formatCounter,
  formatSpeed,
  formatVlanList,
  isOpenPoll,
  LOCAL_PORT_MATCH_LABELS,
  MAC_LOCATION_LABELS,
  MAC_STATUS_LABELS,
  MATCH_BASIS_LABELS,
  NEIGHBOR_PROTOCOL_LABELS,
  OPER_STATUS_LABELS,
  OPER_STATUSES,
  POLL_STATUS_LABELS,
  PORT_KIND_LABELS,
  PORT_KINDS,
  snmpErrorText,
  VLAN_SOURCE_LABELS,
  VLAN_TABLE_SOURCE_LABELS,
} from "../../lib/network";
import { useDebounced } from "../../lib/useDebounced";
import { usePolling, type PollingState } from "../../lib/usePolling";
import { FilterSelect, Pager, SearchInput, Toolbar } from "../ListControls";
import { EmptyState, ErrorState, LoadingState } from "../StateViews";

export const INVENTORY_PAGE_SIZE = 50;
const INVENTORY_MS = config.refreshIntervalMs * 4;

function AbsentToggle({ value, onChange }: { value: boolean; onChange: (value: boolean) => void }) {
  return (
    <label className="checkbox small">
      <input type="checkbox" checked={value} onChange={(e) => onChange(e.target.checked)} /> Incluir ausentes
    </label>
  );
}

function PresenceCell({ present, lastSeen }: { present: boolean; lastSeen: string }) {
  return present ? (
    <span className="small">presente</span>
  ) : (
    <span className="muted small" title={formatDateTime(lastSeen)}>
      ausente desde {formatRelative(lastSeen)}
    </span>
  );
}

/** Carga, error y vacío comunes de las pestañas de inventario. */
function ListState({
  loading,
  error,
  empty,
  emptyTitle,
  emptyText,
  onRetry,
}: {
  loading: boolean;
  error: Error | undefined;
  empty: boolean;
  emptyTitle: string;
  emptyText?: string;
  onRetry: () => void;
}) {
  if (loading) return <LoadingState />;
  if (error) return <ErrorState message={errorMessage(error)} onRetry={onRetry} />;
  if (empty) return <EmptyState title={emptyTitle}>{emptyText}</EmptyState>;
  return null;
}

export function InterfacesTab({ deviceId }: { deviceId: string }) {
  const [page, setPage] = useState(1);
  const [query, setQuery] = useState("");
  const [oper, setOper] = useState("");
  const [kind, setKind] = useState("");
  const [absent, setAbsent] = useState(false);
  const q = useDebounced(query.trim(), 300);
  const fetcher = useCallback(
    (signal: AbortSignal) =>
      networkApi.interfaces(
        deviceId,
        {
          operStatus: (oper || undefined) as OperStatus | undefined,
          portKind: (kind || undefined) as PortKind | undefined,
          q: q || undefined,
          includeAbsent: absent,
          limit: INVENTORY_PAGE_SIZE,
          offset: (page - 1) * INVENTORY_PAGE_SIZE,
        },
        signal,
      ),
    [deviceId, oper, kind, q, absent, page],
  );
  const result = usePolling(fetcher, INVENTORY_MS, true, true);
  const data = result.data;
  const filtered = Boolean(query.trim() || oper || kind);
  return (
    <>
      <Toolbar>
        <SearchInput
          value={query}
          onChange={(v) => {
            setQuery(v.slice(0, 100));
            setPage(1);
          }}
          placeholder="Buscar nombre, alias o descripción"
          label="Buscar interfaces"
        />
        <FilterSelect
          label="Estado operativo"
          value={oper}
          options={OPER_STATUSES.map((s) => ({ value: s, label: OPER_STATUS_LABELS[s] }))}
          onChange={(v) => {
            setOper(v);
            setPage(1);
          }}
        />
        <FilterSelect
          label="Tipo de puerto"
          value={kind}
          options={PORT_KINDS.map((k) => ({ value: k, label: PORT_KIND_LABELS[k] }))}
          onChange={(v) => {
            setKind(v);
            setPage(1);
          }}
        />
        <AbsentToggle
          value={absent}
          onChange={(v) => {
            setAbsent(v);
            setPage(1);
          }}
        />
      </Toolbar>
      {!data || data.items.length === 0 ? (
        <ListState
          loading={!data && !result.error}
          error={data ? undefined : result.error}
          empty={Boolean(data)}
          emptyTitle={filtered ? "Ninguna interfaz coincide con el filtro" : "Sin interfaces informadas"}
          emptyText={filtered ? undefined : "Consulta el equipo para obtener su IF-MIB."}
          onRetry={result.refresh}
        />
      ) : (
        <>
          <div className="table-wrap">
            <table className="table table--compact">
              <thead>
                <tr>
                  <th>Interfaz</th>
                  <th>Admin / oper</th>
                  <th>Velocidad</th>
                  <th>Tipo</th>
                  <th>VLAN</th>
                  <th>LAG / trunk</th>
                  <th>Tráfico (in / out)</th>
                  <th>Errores / descartes</th>
                  <th>MACs</th>
                  <th>Vecinos</th>
                  <th>Presencia</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((i) => (
                  <tr key={i.interface_id}>
                    <td>
                      <span className="strong">{i.name}</span>
                      {i.if_alias && <div className="muted small">{i.if_alias}</div>}
                      <div className="muted small mono">ifIndex {i.if_index}</div>
                    </td>
                    <td className="small">
                      {ADMIN_STATUS_LABELS[i.admin_status] ?? i.admin_status} /{" "}
                      <span className={i.oper_status === "up" ? "strong" : "muted"}>
                        {OPER_STATUS_LABELS[i.oper_status] ?? i.oper_status}
                      </span>
                    </td>
                    <td className="small">{formatSpeed(i.speed_mbps)}</td>
                    <td className="small">{PORT_KIND_LABELS[i.port_kind] ?? i.port_kind}</td>
                    <td className="small">
                      {i.pvid != null && <div>PVID {i.pvid}</div>}
                      {i.untagged_vlans.length > 0 && <div>sin etiqueta: {formatVlanList(i.untagged_vlans)}</div>}
                      {i.tagged_vlans.length > 0 && <div>etiquetadas: {formatVlanList(i.tagged_vlans)}</div>}
                      {i.pvid == null && i.untagged_vlans.length === 0 && i.tagged_vlans.length === 0 && (
                        <span className="muted">—</span>
                      )}
                    </td>
                    <td className="small">
                      {i.is_trunk && <div className="badge badge--info">trunk</div>}
                      {i.lag_parent && <div>miembro de {i.lag_parent.name}</div>}
                      {i.lag_members > 0 && <div>{i.lag_members} miembros</div>}
                      {!i.is_trunk && !i.lag_parent && i.lag_members === 0 && <span className="muted">—</span>}
                    </td>
                    <td className="small mono" title={i.counters_at ? `Contadores de ${formatDateTime(i.counters_at)}` : undefined}>
                      {formatCounter(i.in_octets)} / {formatCounter(i.out_octets)}
                      {i.in_octets != null && <div className="muted">{i.counters_hc ? "octetos (64 bits)" : "octetos (32 bits)"}</div>}
                    </td>
                    <td className="small mono">
                      {formatCounter(i.in_errors)} / {formatCounter(i.out_errors)}
                      <div className="muted">
                        {formatCounter(i.in_discards)} / {formatCounter(i.out_discards)}
                      </div>
                    </td>
                    <td>{i.mac_count}</td>
                    <td>{i.neighbor_count}</td>
                    <td>
                      <PresenceCell present={i.present} lastSeen={i.last_seen_at} />
                      <div className="muted small">fuente: {evidenceSourceLabel(i.evidence_source)}</div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager
            page={page}
            pages={Math.max(1, Math.ceil(data.total / INVENTORY_PAGE_SIZE))}
            total={data.total}
            onPage={setPage}
            noun="interfaces"
          />
        </>
      )}
    </>
  );
}

export function NeighborsTab({ deviceId }: { deviceId: string }) {
  const [page, setPage] = useState(1);
  const [protocol, setProtocol] = useState("");
  const [absent, setAbsent] = useState(false);
  const fetcher = useCallback(
    (signal: AbortSignal) =>
      networkApi.neighbors(
        deviceId,
        {
          protocol: (protocol || undefined) as NeighborProtocol | undefined,
          includeAbsent: absent,
          limit: INVENTORY_PAGE_SIZE,
          offset: (page - 1) * INVENTORY_PAGE_SIZE,
        },
        signal,
      ),
    [deviceId, protocol, absent, page],
  );
  const result = usePolling(fetcher, INVENTORY_MS, true, true);
  const data = result.data;
  return (
    <>
      <p className="muted small" role="note">
        Cada vecino es lo que informa este equipo por LLDP o CDP: no es un enlace confirmado. «Recíproco» indica que el
        otro extremo también informa de este equipo.
      </p>
      <Toolbar>
        <FilterSelect
          label="Protocolo"
          value={protocol}
          options={[
            { value: "lldp", label: "LLDP" },
            { value: "cdp", label: "CDP" },
          ]}
          onChange={(v) => {
            setProtocol(v);
            setPage(1);
          }}
        />
        <AbsentToggle
          value={absent}
          onChange={(v) => {
            setAbsent(v);
            setPage(1);
          }}
        />
      </Toolbar>
      {!data || data.items.length === 0 ? (
        <ListState
          loading={!data && !result.error}
          error={data ? undefined : result.error}
          empty={Boolean(data)}
          emptyTitle="Sin vecinos informados"
          emptyText={protocol ? undefined : "El equipo no ha informado vecinos LLDP ni CDP (o no expone esas MIB)."}
          onRetry={result.refresh}
        />
      ) : (
        <>
          <div className="table-wrap">
            <table className="table table--compact">
              <thead>
                <tr>
                  <th>Protocolo</th>
                  <th>Interfaz local</th>
                  <th>Chasis remoto</th>
                  <th>Puerto remoto</th>
                  <th>sysName remoto</th>
                  <th>Plataforma</th>
                  <th>Dirección de gestión</th>
                  <th>Equipo en Sentra</th>
                  <th>Valoración</th>
                  <th>Presencia</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((n) => (
                  <tr key={n.neighbor_id}>
                    <td>{NEIGHBOR_PROTOCOL_LABELS[n.protocol] ?? n.protocol}</td>
                    <td className="small">
                      {n.local_interface?.name ?? n.local_port_label ?? <span className="muted">—</span>}
                      <div className="muted">{LOCAL_PORT_MATCH_LABELS[n.local_port_match] ?? n.local_port_match}</div>
                    </td>
                    <td className="small mono">
                      {n.remote_chassis_id ?? "—"}
                      {n.remote_chassis_id_subtype && <div className="muted">{n.remote_chassis_id_subtype}</div>}
                    </td>
                    <td className="small">
                      <span className="mono">{n.remote_port_id ?? "—"}</span>
                      {n.remote_port_descr && <div className="muted">{n.remote_port_descr}</div>}
                    </td>
                    <td className="small">{n.remote_sys_name ?? <span className="muted">—</span>}</td>
                    <td className="small">
                      {n.remote_platform ?? <span className="muted">—</span>}
                      {n.remote_capabilities.length > 0 && (
                        <div className="muted">{n.remote_capabilities.join(", ")}</div>
                      )}
                    </td>
                    <td className="small mono">{n.remote_mgmt_address ?? "—"}</td>
                    <td className="small">
                      {n.remote_device ? (
                        <>
                          <Link to={`/infrastructure/devices/${n.remote_device.device_id}`}>
                            {n.remote_device.display_name}
                          </Link>
                          {n.remote_match_basis && (
                            <div className="muted">{MATCH_BASIS_LABELS[n.remote_match_basis] ?? n.remote_match_basis}</div>
                          )}
                        </>
                      ) : (
                        <span className="muted">sin correspondencia</span>
                      )}
                    </td>
                    <td className="small">
                      <span className="badge badge--muted">informado por el equipo</span>
                      {n.reciprocal && <div className="badge badge--info">recíproco</div>}
                    </td>
                    <td>
                      <PresenceCell present={n.present} lastSeen={n.last_seen_at} />
                      <div className="muted small">fuente: {evidenceSourceLabel(n.evidence_source)}</div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager
            page={page}
            pages={Math.max(1, Math.ceil(data.total / INVENTORY_PAGE_SIZE))}
            total={data.total}
            onPage={setPage}
            noun="vecinos"
          />
        </>
      )}
    </>
  );
}

export function VlansTab({ deviceId }: { deviceId: string }) {
  const [absent, setAbsent] = useState(false);
  const fetcher = useCallback((signal: AbortSignal) => networkApi.vlans(deviceId, absent, signal), [deviceId, absent]);
  const result = usePolling(fetcher, INVENTORY_MS, true, true);
  const data = result.data;
  return (
    <>
      <Toolbar>
        <AbsentToggle value={absent} onChange={setAbsent} />
      </Toolbar>
      {!data || data.items.length === 0 ? (
        <ListState
          loading={!data && !result.error}
          error={data ? undefined : result.error}
          empty={Boolean(data)}
          emptyTitle="Sin VLANs informadas"
          emptyText="El equipo no expone la Q-BRIDGE-MIB o no tiene VLANs configuradas."
          onRetry={result.refresh}
        />
      ) : (
        <div className="table-wrap">
          <table className="table table--compact">
            <thead>
              <tr>
                <th>VLAN</th>
                <th>Nombre</th>
                <th>Puertos sin etiqueta</th>
                <th>Puertos etiquetados</th>
                <th>Fuente</th>
                <th>Presencia</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((v) => (
                <tr key={v.vlan_id}>
                  <td className="mono">{v.vlan_id}</td>
                  <td>{v.name ?? <span className="muted">—</span>}</td>
                  <td>{v.untagged_ports}</td>
                  <td>{v.tagged_ports}</td>
                  <td className="small">{VLAN_TABLE_SOURCE_LABELS[v.source] ?? v.source}</td>
                  <td>
                    <PresenceCell present={v.present} lastSeen={v.last_seen_at} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

export function MacTableTab({ deviceId }: { deviceId: string }) {
  const [page, setPage] = useState(1);
  const [mac, setMac] = useState("");
  const [vlan, setVlan] = useState("");
  const [absent, setAbsent] = useState(false);
  const macQuery = useDebounced(mac.trim(), 300);
  const vlanQuery = useDebounced(vlan.trim(), 300);
  const vlanId = /^\d{1,4}$/.test(vlanQuery) ? Number(vlanQuery) : undefined;
  const fetcher = useCallback(
    (signal: AbortSignal) =>
      networkApi.macEntries(
        deviceId,
        {
          mac: macQuery || undefined,
          vlanId,
          includeAbsent: absent,
          limit: INVENTORY_PAGE_SIZE,
          offset: (page - 1) * INVENTORY_PAGE_SIZE,
        },
        signal,
      ),
    [deviceId, macQuery, vlanId, absent, page],
  );
  const result = usePolling(fetcher, INVENTORY_MS, true, true);
  const data = result.data;
  const filtered = Boolean(mac.trim() || vlan.trim());
  return (
    <>
      <p className="muted small" role="note">
        Una entrada de la tabla MAC indica por qué puerto reenvía el equipo esa dirección, no dónde está cableada. La
        valoración resume si el puerto parece de acceso o un uplink compartido.
      </p>
      <Toolbar>
        <SearchInput
          value={mac}
          onChange={(v) => {
            setMac(v.slice(0, 32));
            setPage(1);
          }}
          placeholder="Buscar MAC"
          label="Buscar MAC"
        />
        <input
          className="input"
          inputMode="numeric"
          placeholder="VLAN"
          aria-label="Filtrar por VLAN"
          value={vlan}
          onChange={(e) => {
            setVlan(e.target.value.replace(/\D/g, "").slice(0, 4));
            setPage(1);
          }}
        />
        <AbsentToggle
          value={absent}
          onChange={(v) => {
            setAbsent(v);
            setPage(1);
          }}
        />
      </Toolbar>
      {data && result.error && (
        <div className="banner banner--warn" role="alert">
          Fallo al actualizar: {errorMessage(result.error)}. Se muestran los últimos datos.
        </div>
      )}
      {data?.truncated && (
        <div className="banner" role="note">
          La tabla MAC del equipo superó el límite de entradas de una consulta: solo se muestra una parte.
        </div>
      )}
      {!data || data.items.length === 0 ? (
        <ListState
          loading={!data && !result.error}
          error={data ? undefined : result.error}
          empty={Boolean(data)}
          emptyTitle={filtered ? "Ninguna MAC coincide con el filtro" : "Sin entradas MAC informadas"}
          emptyText={filtered ? undefined : "El equipo no expone la BRIDGE-MIB o su tabla está vacía."}
          onRetry={result.refresh}
        />
      ) : (
        <>
          <div className="table-wrap">
            <table className="table table--compact">
              <thead>
                <tr>
                  <th>MAC</th>
                  <th>VLAN</th>
                  <th>Interfaz</th>
                  <th>Estado</th>
                  <th>Valoración</th>
                  <th>Activo del site</th>
                  <th>Presencia</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((e) => (
                  <tr key={e.entry_id}>
                    <td className="mono">{e.mac}</td>
                    <td className="small">
                      {e.vlan_id ?? "—"}
                      <div className="muted">{VLAN_SOURCE_LABELS[e.vlan_source] ?? e.vlan_source}</div>
                    </td>
                    <td className="small">
                      {e.interface?.name ?? (e.bridge_port != null ? `bridge port ${e.bridge_port}` : "—")}
                      <div className="muted">{e.port_mac_count} MACs en el puerto</div>
                    </td>
                    <td className="small">{MAC_STATUS_LABELS[e.status] ?? e.status}</td>
                    <td className="small">
                      <span className={e.location === "edge_candidate" ? "badge badge--info" : "badge badge--muted"}>
                        {MAC_LOCATION_LABELS[e.location] ?? e.location}
                      </span>
                      <div className="muted">{e.location_reason}</div>
                    </td>
                    <td className="small">
                      {e.asset ? (
                        <Link to={`/assets/${e.asset.asset_id}`}>{e.asset.display_name}</Link>
                      ) : (
                        <span className="muted">—</span>
                      )}
                    </td>
                    <td>
                      <PresenceCell present={e.present} lastSeen={e.last_seen_at} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager
            page={page}
            pages={Math.max(1, Math.ceil(data.total / INVENTORY_PAGE_SIZE))}
            total={data.total}
            onPage={setPage}
            noun="entradas"
          />
        </>
      )}
    </>
  );
}

function describeChanges(poll: NetworkPoll): string {
  const c = poll.changes;
  const parts: string[] = [];
  if (c.interfaces_added) parts.push(`+${c.interfaces_added} interfaces`);
  if (c.interfaces_removed) parts.push(`-${c.interfaces_removed} interfaces`);
  if (c.oper_status_changes) parts.push(`${c.oper_status_changes} cambios de estado`);
  if (c.neighbors_added) parts.push(`+${c.neighbors_added} vecinos`);
  if (c.neighbors_removed) parts.push(`-${c.neighbors_removed} vecinos`);
  if (c.classification_changed) parts.push("clasificación cambiada");
  return parts.join(", ");
}

export const POLL_PAGE_SIZE = 20;

export function PollsTab({
  polls,
  page,
  onPage,
  canPoll,
  onCancel,
}: {
  /** El historial lo carga la página: también lo usa para el botón «Cancelar» de la cabecera. */
  polls: PollingState<NetworkPollList>;
  page: number;
  onPage: (page: number) => void;
  canPoll: boolean;
  onCancel: (poll: NetworkPoll) => void;
}) {
  const data = polls.data;
  return !data || data.items.length === 0 ? (
    <ListState
      loading={!data && !polls.error}
      error={data ? undefined : polls.error}
      empty={Boolean(data)}
      emptyTitle="Sin consultas"
      emptyText="Este equipo todavía no se ha consultado."
      onRetry={polls.refresh}
    />
  ) : (
    <>
      <div className="table-wrap">
        <table className="table table--compact">
          <thead>
            <tr>
              <th>Solicitada</th>
              <th>Estado</th>
              <th>Origen</th>
              <th>Sensor</th>
              <th>Módulos</th>
              <th>Recuentos</th>
              <th>Cambios</th>
              <th>Error</th>
              <th aria-label="Acciones" />
            </tr>
          </thead>
          <tbody>
            {data.items.map((p) => (
              <tr key={p.poll_id}>
                <td className="small" title={formatDateTime(p.created_at)}>
                  {formatRelative(p.created_at)}
                  <div className="muted">{p.requested_by}</div>
                </td>
                <td className="small">
                  {POLL_STATUS_LABELS[p.status] ?? p.status}
                  {p.finished_at && <div className="muted">terminada {formatRelative(p.finished_at)}</div>}
                </td>
                <td className="small">{p.trigger === "manual" ? "manual" : "programada"}</td>
                <td className="small">{p.sensor_name ?? <span className="muted">—</span>}</td>
                <td className="small">
                  {Object.keys(p.modules).length > 0 ? describeModules(p.modules) : <span className="muted">—</span>}
                </td>
                <td className="small">
                  {p.counts.interfaces} interfaces · {p.counts.neighbors} vecinos · {p.counts.vlans} VLANs ·{" "}
                  {p.counts.mac_entries} MACs
                </td>
                <td className="small">{describeChanges(p) || <span className="muted">sin cambios</span>}</td>
                <td className="small">
                  {p.error_code ? (
                    <>
                      <span>{snmpErrorText(p.error_code)}</span>
                      {p.error_message && <div className="muted">{p.error_message}</div>}
                    </>
                  ) : (
                    <span className="muted">—</span>
                  )}
                </td>
                <td>
                  {canPoll && isOpenPoll(p.status) && (
                    <button
                      type="button"
                      className="button button--small"
                      aria-label={`Cancelar consulta ${formatDateTime(p.created_at)}`}
                      onClick={() => onCancel(p)}
                    >
                      Cancelar
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <Pager
        page={page}
        pages={Math.max(1, Math.ceil(data.total / POLL_PAGE_SIZE))}
        total={data.total}
        onPage={onPage}
        noun="consultas"
      />
    </>
  );
}
