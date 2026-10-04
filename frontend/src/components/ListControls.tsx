import type { ReactNode } from "react";
import type { SortDir, SortState } from "../lib/listing";

/** Clickable column header that toggles sorting by `sortKey`. */
export function SortHeader<K extends string>({
  label,
  sortKey,
  sort,
  onSort,
  numeric,
}: {
  label: string;
  sortKey: K;
  sort: SortState<K>;
  onSort: (next: SortState<K>) => void;
  /** Numbers start from the highest value (most CPU first), text from A. */
  numeric?: boolean;
}) {
  const active = sort.key === sortKey;
  const firstDir: SortDir = numeric ? "desc" : "asc";
  const next: SortDir = active ? (sort.dir === "asc" ? "desc" : "asc") : firstDir;
  return (
    <th aria-sort={active ? (sort.dir === "asc" ? "ascending" : "descending") : "none"}>
      <button type="button" className="th-sort" onClick={() => onSort({ key: sortKey, dir: next })}>
        {label}
        <span className="th-sort__arrow" aria-hidden="true">
          {active ? (sort.dir === "asc" ? "▲" : "▼") : ""}
        </span>
      </button>
    </th>
  );
}

export function Pager({
  page,
  pages,
  total,
  onPage,
  noun = "elementos",
}: {
  page: number;
  pages: number;
  total: number;
  onPage: (page: number) => void;
  noun?: string;
}) {
  return (
    <div className="pager">
      <span className="muted small">
        {total} {noun}
        {pages > 1 && ` · página ${page} de ${pages}`}
      </span>
      {pages > 1 && (
        <span className="pager__buttons">
          <button type="button" className="button" disabled={page <= 1} onClick={() => onPage(page - 1)}>
            Anterior
          </button>
          <button
            type="button"
            className="button"
            disabled={page >= pages}
            onClick={() => onPage(page + 1)}
          >
            Siguiente
          </button>
        </span>
      )}
    </div>
  );
}

export function SearchInput({
  value,
  onChange,
  placeholder,
  label,
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
  label: string;
}) {
  return (
    <input
      type="search"
      className="input"
      placeholder={placeholder}
      value={value}
      onChange={(event) => onChange(event.target.value)}
      aria-label={label}
    />
  );
}

/** Dropdown filter; the empty option means "all". */
export function FilterSelect({
  label,
  value,
  options,
  onChange,
  allLabel = "Todos",
}: {
  label: string;
  value: string;
  options: readonly (string | { value: string; label: string })[];
  onChange: (value: string) => void;
  allLabel?: string;
}) {
  return (
    <select className="input input--select" aria-label={label} value={value} onChange={(e) => onChange(e.target.value)}>
      <option value="">
        {label}: {allLabel}
      </option>
      {options.map((option) => {
        const { value: optionValue, label: optionLabel } =
          typeof option === "string" ? { value: option, label: option } : option;
        return (
          <option key={optionValue} value={optionValue}>
            {optionLabel}
          </option>
        );
      })}
    </select>
  );
}

export function Toolbar({ children }: { children: ReactNode }) {
  return <div className="panel__toolbar panel__toolbar--filters">{children}</div>;
}
