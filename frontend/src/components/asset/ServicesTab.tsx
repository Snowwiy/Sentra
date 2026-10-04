import { useMemo } from "react";
import type { ServiceInfo } from "../../api/types";
import { compareBy, distinct, listPage, matchesText } from "../../lib/listing";
import { useListState } from "../../lib/useListState";
import { FilterSelect, Pager, SearchInput, SortHeader, Toolbar } from "../ListControls";
import { EmptyState } from "../StateViews";

const PAGE_SIZE = 50;
type Key = "name" | "display" | "status" | "start";

const SORTERS: Record<Key, (s: ServiceInfo) => string | null> = {
  name: (s) => s.name,
  display: (s) => s.display_name,
  status: (s) => s.status,
  start: (s) => s.start_type,
};

// Windows reports running/stopped/paused...; systemd units report their sub-state, where
// "failed" (crashed or could not start) is the one that needs attention.
export function serviceStatusClass(status: string): string {
  if (status === "running") return "text-ok";
  if (status === "failed") return "text-crit";
  return "muted";
}

export function ServicesTab({ services }: { services: ServiceInfo[] }) {
  const list = useListState<Key, { status: string; start: string }>(
    { key: "name", dir: "asc" },
    { status: "", start: "" },
  );
  const statuses = useMemo(() => distinct(services, (s) => s.status), [services]);
  const startTypes = useMemo(() => distinct(services, (s) => s.start_type), [services]);
  const running = services.filter((s) => s.status === "running").length;
  const page = listPage(services, {
    filter: (s) =>
      (!list.filters.status || s.status === list.filters.status) &&
      (!list.filters.start || s.start_type === list.filters.start) &&
      matchesText(list.query, s.name, s.display_name, s.pid),
    compare: compareBy(SORTERS[list.sort.key], list.sort.dir),
    page: list.page,
    pageSize: PAGE_SIZE,
  });

  if (services.length === 0) {
    return <EmptyState title="Sin servicios">El inventario no incluye servicios de este activo.</EmptyState>;
  }
  const header = (label: string, key: Key) => (
    <SortHeader label={label} sortKey={key} sort={list.sort} onSort={list.setSort} />
  );

  return (
    <>
      <Toolbar>
        <SearchInput value={list.query} onChange={list.setQuery} placeholder="Buscar servicio o PID" label="Buscar servicios" />
        <FilterSelect label="Estado" value={list.filters.status} options={statuses} onChange={(v) => list.setFilter("status", v)} />
        <FilterSelect label="Inicio" value={list.filters.start} options={startTypes} onChange={(v) => list.setFilter("start", v)} />
        <span className="muted small">
          {running} en ejecución de {services.length}
        </span>
      </Toolbar>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              {header("Servicio", "name")}
              {header("Nombre", "display")}
              {header("Estado", "status")}
              {header("Inicio", "start")}
              <th>PID</th>
            </tr>
          </thead>
          <tbody>
            {page.items.map((s) => (
              <tr key={s.name}>
                <td className="mono">{s.name}</td>
                <td>{s.display_name ?? "—"}</td>
                <td className={serviceStatusClass(s.status)}>{s.status}</td>
                <td className="muted">{s.start_type ?? "—"}</td>
                <td className="mono muted">{s.pid ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <Pager page={page.page} pages={page.pages} total={page.total} onPage={list.setPage} noun="servicios" />
    </>
  );
}
