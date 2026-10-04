import { useCallback, useMemo } from "react";
import { ApiError } from "../../api/client";
import { sentraApi } from "../../api/sentra";
import type { ProcessEntry, ProcessInfo } from "../../api/types";
import { errorMessage, formatBytes, formatDateTime, formatPercent, formatRelative } from "../../lib/format";
import { compareBy, distinct, listPage, matchesText } from "../../lib/listing";
import { usePolling } from "../../lib/usePolling";
import { useListState } from "../../lib/useListState";
import { FilterSelect, Pager, SearchInput, SortHeader, Toolbar } from "../ListControls";
import { EmptyState, ErrorState, LoadingState } from "../StateViews";

// The agent sends a snapshot every minute; refreshing faster would show the same data.
const REFRESH_MS = 30_000;
const PAGE_SIZE = 50;

type Key = "name" | "pid" | "cpu" | "memory" | "started";

const SORTERS: Record<Key, (p: ProcessEntry) => string | number | null> = {
  name: (p) => p.name,
  pid: (p) => p.pid,
  cpu: (p) => p.cpu_percent,
  memory: (p) => p.memory_bytes,
  started: (p) => (p.started_at ? Date.parse(p.started_at) : null),
};

/** Older agents only report the top processes inside the inventory: same shape, fewer fields. */
function fromInventory(processes: ProcessInfo[]): ProcessEntry[] {
  return processes.map((p) => ({
    pid: p.pid,
    ppid: p.ppid ?? null,
    name: p.name,
    exe: p.exe ?? null,
    username: p.username,
    cpu_percent: p.cpu_percent ?? null,
    memory_bytes: p.memory_bytes,
    started_at: p.started_at ?? null,
    status: null,
  }));
}

export function ProcessesTab({
  assetId,
  inventoryProcesses,
}: {
  assetId: string;
  inventoryProcesses: ProcessInfo[] | undefined;
}) {
  const fetchProcesses = useCallback(
    (signal: AbortSignal) => sentraApi.getProcesses(assetId, signal),
    [assetId],
  );
  const { data, error, loading, refresh } = usePolling(fetchProcesses, REFRESH_MS);
  const list = useListState<Key, { user: string }>({ key: "cpu", dir: "desc" }, { user: "" });

  const noSnapshot = !data && error instanceof ApiError && error.status === 404;
  const processes = useMemo(
    () => data?.processes ?? (noSnapshot && inventoryProcesses ? fromInventory(inventoryProcesses) : []),
    [data, noSnapshot, inventoryProcesses],
  );
  const names = useMemo(() => new Map(processes.map((p) => [p.pid, p.name])), [processes]);
  const users = useMemo(() => distinct(processes, (p) => p.username), [processes]);
  const page = listPage(processes, {
    filter: (p) =>
      (!list.filters.user || p.username === list.filters.user) &&
      matchesText(list.query, p.name, p.exe, p.pid, p.username),
    compare: compareBy(SORTERS[list.sort.key], list.sort.dir),
    page: list.page,
    pageSize: PAGE_SIZE,
  });

  if (loading) return <LoadingState label="Cargando procesos…" />;
  if (!data && error && !noSnapshot) return <ErrorState message={errorMessage(error)} onRetry={refresh} />;
  if (processes.length === 0) {
    return (
      <EmptyState title="Sin procesos">
        El agente envía la lista de procesos cada minuto (requiere una versión reciente del agente).
      </EmptyState>
    );
  }

  const header = (label: string, key: Key, numeric = false) => (
    <SortHeader label={label} sortKey={key} sort={list.sort} onSort={list.setSort} numeric={numeric} />
  );

  return (
    <>
      <Toolbar>
        <SearchInput
          value={list.query}
          onChange={list.setQuery}
          placeholder="Buscar nombre, ruta o PID"
          label="Buscar procesos"
        />
        <FilterSelect label="Usuario" value={list.filters.user} options={users} onChange={(v) => list.setFilter("user", v)} />
        <span className="muted small">
          {data
            ? `Instantánea ${formatRelative(data.collected_at)}`
            : "Lista resumida del inventario (agente antiguo): sin CPU ni ruta"}
        </span>
      </Toolbar>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              {header("Proceso", "name")}
              {header("PID", "pid", true)}
              <th>Usuario</th>
              {header("CPU", "cpu", true)}
              {header("RAM", "memory", true)}
              <th>Padre</th>
              {header("Inicio", "started", true)}
              <th>Ruta</th>
            </tr>
          </thead>
          <tbody>
            {page.items.map((p) => (
              <tr key={`${p.pid}-${p.started_at ?? ""}`}>
                <td className="strong">{p.name}</td>
                <td className="mono">{p.pid}</td>
                <td className="muted">{p.username ?? "—"}</td>
                <td>{p.cpu_percent == null ? <span className="muted">—</span> : formatPercent(p.cpu_percent)}</td>
                <td>{formatBytes(p.memory_bytes)}</td>
                <td className="muted">
                  {p.ppid == null ? "—" : `${names.get(p.ppid) ?? "?"} (${p.ppid})`}
                </td>
                <td className="muted" title={formatDateTime(p.started_at)}>
                  {p.started_at ? formatRelative(p.started_at) : "—"}
                </td>
                <td className="mono path" title={p.exe ?? undefined}>
                  {p.exe ?? <span className="muted">—</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <Pager page={page.page} pages={page.pages} total={page.total} onPage={list.setPage} noun="procesos" />
    </>
  );
}
