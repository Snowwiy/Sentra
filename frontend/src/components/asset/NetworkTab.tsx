import type { NetworkConnection, NetworkInterface, NetworkSummary } from "../../api/types";
import { compareBy, listPage, matchesText } from "../../lib/listing";
import { useListState } from "../../lib/useListState";
import { FilterSelect, Pager, SearchInput, SortHeader, Toolbar } from "../ListControls";
import { EmptyState } from "../StateViews";

const PAGE_SIZE = 50;

export function endpoint(address: string | null, port: number | null): string {
  if (!address) return port != null ? `*:${port}` : "—";
  if (port == null) return address;
  // IPv6 literals need brackets before a port, as in URLs ("[::1]:443").
  return address.includes(":") ? `[${address}]:${port}` : `${address}:${port}`;
}

export function splitAddresses(addresses: string[]): { v4: string[]; v6: string[] } {
  return {
    v4: addresses.filter((a) => !a.includes(":")),
    v6: addresses.filter((a) => a.includes(":")),
  };
}

type Key = "process" | "local" | "remote" | "state";

const SORTERS: Record<Key, (c: NetworkConnection) => string | number | null> = {
  process: (c) => c.process_name,
  local: (c) => c.local_port,
  remote: (c) => c.remote_address,
  state: (c) => c.status,
};

function Interfaces({ interfaces, summary }: { interfaces: NetworkInterface[]; summary: NetworkSummary | null | undefined }) {
  return (
    <section className="panel">
      <div className="panel__toolbar">
        <h2>Interfaces</h2>
        {summary && (
          <span className="muted small">
            Gateway: <span className="mono">{summary.gateways.join(", ") || "—"}</span> · DNS:{" "}
            <span className="mono">{summary.dns_servers.join(", ") || "—"}</span>
          </span>
        )}
      </div>
      {interfaces.length === 0 ? (
        <EmptyState title="Sin interfaces" />
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Interfaz</th>
                <th>Estado</th>
                <th>IPv4</th>
                <th>IPv6</th>
                <th>MAC</th>
                <th>Velocidad</th>
              </tr>
            </thead>
            <tbody>
              {[...interfaces]
                .sort((a, b) => Number(b.is_up) - Number(a.is_up) || a.name.localeCompare(b.name))
                .map((i) => {
                  const { v4, v6 } = splitAddresses(i.addresses);
                  return (
                    <tr key={i.name}>
                      <td className="strong">{i.name}</td>
                      <td className={i.is_up ? "text-ok" : "muted"}>{i.is_up ? "Up" : "Down"}</td>
                      <td className="mono">{v4.join(", ") || "—"}</td>
                      <td className="mono">{v6.join(", ") || "—"}</td>
                      <td className="mono">{i.mac ?? "—"}</td>
                      <td>{i.speed_mbps ? `${i.speed_mbps} Mbps` : "—"}</td>
                    </tr>
                  );
                })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function Connections({ connections }: { connections: NetworkConnection[] }) {
  const list = useListState<Key, { protocol: string; state: string }>(
    { key: "state", dir: "desc" },
    { protocol: "", state: "" },
  );
  const page = listPage(connections, {
    filter: (c) =>
      (!list.filters.protocol || c.protocol === list.filters.protocol) &&
      (!list.filters.state || c.status === list.filters.state) &&
      matchesText(
        list.query,
        c.process_name,
        c.pid,
        c.local_address,
        c.local_port,
        c.remote_address,
        c.remote_port,
      ),
    compare: compareBy(SORTERS[list.sort.key], list.sort.dir),
    page: list.page,
    pageSize: PAGE_SIZE,
  });
  const header = (label: string, key: Key) => (
    <SortHeader label={label} sortKey={key} sort={list.sort} onSort={list.setSort} />
  );

  return (
    <section className="panel">
      <div className="panel__toolbar">
        <h2>Conexiones</h2>
        <span className="muted small">puertos en escucha y conexiones TCP establecidas</span>
      </div>
      <Toolbar>
        <SearchInput value={list.query} onChange={list.setQuery} placeholder="Proceso, PID, IP o puerto" label="Buscar conexiones" />
        <FilterSelect
          label="Protocolo"
          value={list.filters.protocol}
          options={[
            { value: "tcp", label: "TCP" },
            { value: "udp", label: "UDP" },
          ]}
          onChange={(v) => list.setFilter("protocol", v)}
        />
        <FilterSelect
          label="Estado"
          value={list.filters.state}
          options={[
            { value: "listen", label: "Escucha" },
            { value: "established", label: "Establecida" },
          ]}
          onChange={(v) => list.setFilter("state", v)}
        />
      </Toolbar>
      {connections.length === 0 ? (
        <EmptyState title="Sin conexiones" />
      ) : (
        <>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Proto</th>
                  {header("Estado", "state")}
                  {header("Local", "local")}
                  {header("Remoto", "remote")}
                  {header("Proceso", "process")}
                </tr>
              </thead>
              <tbody>
                {page.items.map((c, index) => (
                  <tr key={`${c.protocol}-${c.local_address}-${c.local_port}-${c.remote_address}-${c.remote_port}-${index}`}>
                    <td className="mono">{c.protocol.toUpperCase()}</td>
                    <td className={c.status === "listen" ? "text-ok" : undefined}>
                      {c.status === "listen" ? "Escucha" : "Establecida"}
                    </td>
                    <td className="mono">{endpoint(c.local_address, c.local_port)}</td>
                    <td className="mono">{endpoint(c.remote_address, c.remote_port)}</td>
                    <td>
                      {c.process_name ?? <span className="muted">—</span>}
                      {c.pid != null && <span className="muted small"> · {c.pid}</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager page={page.page} pages={page.pages} total={page.total} onPage={list.setPage} noun="conexiones" />
        </>
      )}
    </section>
  );
}

export function NetworkTab({
  interfaces,
  connections,
  summary,
}: {
  interfaces: NetworkInterface[];
  connections: NetworkConnection[];
  summary: NetworkSummary | null | undefined;
}) {
  return (
    <div className="stack">
      <Interfaces interfaces={interfaces} summary={summary} />
      <Connections connections={connections} />
    </div>
  );
}
