import { useCallback, useMemo, useState } from "react";
import { ApiError } from "../api/client";
import { sentraApi } from "../api/sentra";
import type { Inventory } from "../api/types";
import { config } from "../config";
import { errorMessage, formatBytes, formatDateTime, formatRelative } from "../lib/format";
import { MetricBar } from "./MetricBar";
import { usePolling } from "../lib/usePolling";
import { EmptyState, ErrorState, LoadingState } from "./StateViews";

type Tab = "interfaces" | "disks" | "connections" | "users" | "services" | "software" | "processes";

const TABS: { key: Tab; label: string }[] = [
  { key: "interfaces", label: "Red" },
  { key: "disks", label: "Discos" },
  { key: "connections", label: "Conexiones" },
  { key: "users", label: "Usuarios" },
  { key: "services", label: "Servicios" },
  { key: "software", label: "Software" },
  { key: "processes", label: "Procesos" },
];

// Inventory changes every few minutes at most; polling it as often as metrics is wasted load.
const INVENTORY_REFRESH_MS = Math.max(config.refreshIntervalMs, 60_000);

function contains(values: (string | null)[], query: string): boolean {
  return values.some((value) => value?.toLowerCase().includes(query));
}

function endpoint(address: string | null, port: number | null): string {
  if (!address) return port != null ? `*:${port}` : "—";
  // IPv6 literals need brackets before a port, as in URLs ("[::1]:443").
  const host = address.includes(":") ? `[${address}]` : address;
  return port != null ? `${host}:${port}` : host;
}

function Section({ inventory, tab, query }: { inventory: Inventory; tab: Tab; query: string }) {
  const q = query.trim().toLowerCase();
  switch (tab) {
    case "interfaces":
      return (
        <table className="table">
          <thead>
            <tr>
              <th>Interfaz</th>
              <th>Estado</th>
              <th>Direcciones</th>
              <th>MAC</th>
              <th>Velocidad</th>
            </tr>
          </thead>
          <tbody>
            {inventory.interfaces
              .filter((i) => contains([i.name, i.mac, ...i.addresses], q))
              .map((i) => (
                <tr key={i.name}>
                  <td className="strong">{i.name}</td>
                  <td className={i.is_up ? "text-ok" : "muted"}>{i.is_up ? "Up" : "Down"}</td>
                  <td className="mono">{i.addresses.join(", ") || "—"}</td>
                  <td className="mono">{i.mac ?? "—"}</td>
                  <td>{i.speed_mbps ? `${i.speed_mbps} Mbps` : "—"}</td>
                </tr>
              ))}
          </tbody>
        </table>
      );
    case "disks":
      return (
        <table className="table">
          <thead>
            <tr>
              <th>Unidad</th>
              <th>Sistema</th>
              <th>Uso</th>
              <th>Usado</th>
              <th>Libre</th>
              <th>Total</th>
            </tr>
          </thead>
          <tbody>
            {(inventory.disks ?? [])
              .filter((d) => contains([d.device, d.mountpoint, d.fstype], q))
              .map((d) => (
                <tr key={d.mountpoint}>
                  <td className="mono">{d.mountpoint}</td>
                  <td className="muted">{d.fstype ?? "—"}</td>
                  <td>
                    <MetricBar value={d.percent} label={`Uso de ${d.mountpoint}`} />
                  </td>
                  <td>{formatBytes(d.used_bytes)}</td>
                  <td>{formatBytes(d.free_bytes)}</td>
                  <td>{formatBytes(d.total_bytes)}</td>
                </tr>
              ))}
          </tbody>
        </table>
      );
    case "connections":
      return (
        <table className="table">
          <thead>
            <tr>
              <th>Proto</th>
              <th>Estado</th>
              <th>Local</th>
              <th>Remoto</th>
              <th>Proceso</th>
            </tr>
          </thead>
          <tbody>
            {(inventory.connections ?? [])
              .filter((c) =>
                contains(
                  [c.process_name, c.local_address, c.remote_address, String(c.local_port ?? ""), String(c.remote_port ?? "")],
                  q,
                ),
              )
              .map((c, index) => (
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
      );
    case "users":
      return (
        <table className="table">
          <thead>
            <tr>
              <th>Usuario</th>
              <th>Terminal</th>
              <th>Origen</th>
              <th>Sesión desde</th>
            </tr>
          </thead>
          <tbody>
            {inventory.users
              .filter((u) => contains([u.name, u.host], q))
              .map((u, index) => (
                <tr key={`${u.name}-${index}`}>
                  <td className="strong">{u.name}</td>
                  <td>{u.terminal ?? "—"}</td>
                  <td>{u.host ?? "local"}</td>
                  <td>{formatDateTime(u.started_at)}</td>
                </tr>
              ))}
          </tbody>
        </table>
      );
    case "services":
      return (
        <table className="table">
          <thead>
            <tr>
              <th>Servicio</th>
              <th>Nombre</th>
              <th>Estado</th>
              <th>Inicio</th>
            </tr>
          </thead>
          <tbody>
            {inventory.services
              .filter((s) => contains([s.name, s.display_name, s.status], q))
              .map((s) => (
                <tr key={s.name}>
                  <td className="mono">{s.name}</td>
                  <td>{s.display_name ?? "—"}</td>
                  <td className={s.status === "running" ? "text-ok" : "muted"}>{s.status}</td>
                  <td className="muted">{s.start_type ?? "—"}</td>
                </tr>
              ))}
          </tbody>
        </table>
      );
    case "software":
      return (
        <table className="table">
          <thead>
            <tr>
              <th>Nombre</th>
              <th>Versión</th>
              <th>Editor</th>
            </tr>
          </thead>
          <tbody>
            {inventory.software
              .filter((s) => contains([s.name, s.publisher], q))
              .map((s) => (
                <tr key={`${s.name}-${s.version ?? ""}`}>
                  <td>{s.name}</td>
                  <td className="mono">{s.version ?? "—"}</td>
                  <td className="muted">{s.publisher ?? "—"}</td>
                </tr>
              ))}
          </tbody>
        </table>
      );
    case "processes":
      return (
        <table className="table">
          <thead>
            <tr>
              <th>PID</th>
              <th>Proceso</th>
              <th>Usuario</th>
              <th>Memoria</th>
            </tr>
          </thead>
          <tbody>
            {inventory.processes
              .filter((p) => contains([p.name, p.username, String(p.pid)], q))
              .map((p) => (
                <tr key={p.pid}>
                  <td className="mono">{p.pid}</td>
                  <td>{p.name}</td>
                  <td className="muted">{p.username ?? "—"}</td>
                  <td>{formatBytes(p.memory_bytes)}</td>
                </tr>
              ))}
          </tbody>
        </table>
      );
  }
}

export function InventoryPanel({ assetId }: { assetId: string }) {
  const fetchInventory = useCallback(
    (signal: AbortSignal) => sentraApi.getInventory(assetId, signal),
    [assetId],
  );
  const { data, error, loading, refresh } = usePolling(fetchInventory, INVENTORY_REFRESH_MS);
  const [tab, setTab] = useState<Tab>("interfaces");
  const [query, setQuery] = useState("");
  const counts = useMemo(
    () =>
      data
        ? Object.fromEntries(TABS.map(({ key }) => [key, (data[key] ?? []).length]))
        : ({} as Record<Tab, number>),
    [data],
  );

  const notReported = error instanceof ApiError && error.status === 404;

  return (
    <section className="panel">
      <div className="panel__toolbar">
        <h2>Inventario</h2>
        {data && (
          <span className="muted small" title={formatDateTime(data.collected_at)}>
            recogido {formatRelative(data.collected_at)}
          </span>
        )}
      </div>
      {loading ? (
        <LoadingState label="Cargando inventario…" />
      ) : !data && notReported ? (
        <EmptyState title="Sin inventario">
          El agente envía el inventario al arrancar y cada 15 minutos.
        </EmptyState>
      ) : !data && error ? (
        <ErrorState message={errorMessage(error)} onRetry={refresh} />
      ) : data ? (
        <>
          <div className="panel__toolbar">
            <div className="segmented" role="tablist" aria-label="Secciones de inventario">
              {TABS.map(({ key, label }) => (
                <button
                  key={key}
                  type="button"
                  role="tab"
                  aria-selected={tab === key}
                  className={`segmented__item${tab === key ? " segmented__item--active" : ""}`}
                  onClick={() => setTab(key)}
                >
                  {label} <span className="muted">{counts[key]}</span>
                </button>
              ))}
            </div>
            <input
              type="search"
              className="input"
              placeholder="Filtrar"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              aria-label="Filtrar inventario"
            />
          </div>
          <div className="table-wrap table-wrap--scroll">
            <Section inventory={data} tab={tab} query={query} />
          </div>
        </>
      ) : null}
    </section>
  );
}
