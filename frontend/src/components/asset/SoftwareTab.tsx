import { useMemo } from "react";
import type { SoftwareInfo } from "../../api/types";
import { compareBy, distinct, listPage, matchesText } from "../../lib/listing";
import { useListState } from "../../lib/useListState";
import { FilterSelect, Pager, SearchInput, SortHeader, Toolbar } from "../ListControls";
import { EmptyState } from "../StateViews";

const PAGE_SIZE = 50;
type Key = "name" | "version" | "publisher" | "installed";

const SORTERS: Record<Key, (s: SoftwareInfo) => string | null | undefined> = {
  name: (s) => s.name,
  version: (s) => s.version,
  publisher: (s) => s.publisher,
  installed: (s) => s.install_date, // ISO dates sort as text
};

export function SoftwareTab({ software }: { software: SoftwareInfo[] }) {
  const list = useListState<Key, { publisher: string; arch: string }>(
    { key: "name", dir: "asc" },
    { publisher: "", arch: "" },
  );
  const publishers = useMemo(() => distinct(software, (s) => s.publisher), [software]);
  const architectures = useMemo(() => distinct(software, (s) => s.architecture), [software]);
  const page = listPage(software, {
    filter: (s) =>
      (!list.filters.publisher || s.publisher === list.filters.publisher) &&
      (!list.filters.arch || s.architecture === list.filters.arch) &&
      matchesText(list.query, s.name, s.version, s.publisher),
    compare: compareBy(SORTERS[list.sort.key], list.sort.dir),
    page: list.page,
    pageSize: PAGE_SIZE,
  });

  if (software.length === 0) {
    return <EmptyState title="Sin software">El inventario no incluye software instalado.</EmptyState>;
  }
  const header = (label: string, key: Key) => (
    <SortHeader label={label} sortKey={key} sort={list.sort} onSort={list.setSort} />
  );

  return (
    <>
      <Toolbar>
        <SearchInput value={list.query} onChange={list.setQuery} placeholder="Buscar nombre, versión o editor" label="Buscar software" />
        <FilterSelect label="Editor" value={list.filters.publisher} options={publishers} onChange={(v) => list.setFilter("publisher", v)} />
        {architectures.length > 0 && (
          <FilterSelect label="Arquitectura" value={list.filters.arch} options={architectures} onChange={(v) => list.setFilter("arch", v)} allLabel="Todas" />
        )}
        <span className="muted small">{software.length} programas instalados</span>
      </Toolbar>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              {header("Nombre", "name")}
              {header("Versión", "version")}
              {header("Editor", "publisher")}
              {header("Instalado", "installed")}
              <th>Arquitectura</th>
            </tr>
          </thead>
          <tbody>
            {page.items.map((s) => (
              <tr key={`${s.name}-${s.version ?? ""}-${s.architecture ?? ""}`}>
                <td>{s.name}</td>
                <td className="mono">{s.version ?? "—"}</td>
                <td className="muted">{s.publisher ?? "—"}</td>
                <td className="muted">{s.install_date ?? "—"}</td>
                <td className="muted">{s.architecture ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <Pager page={page.page} pages={page.pages} total={page.total} onPage={list.setPage} noun="programas" />
    </>
  );
}
