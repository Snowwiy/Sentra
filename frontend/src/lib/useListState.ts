import { useState } from "react";
import type { SortState } from "./listing";

/** Search text, filters, sort and page of one list; any change goes back to page 1. */
export function useListState<K extends string, F extends Record<string, string>>(
  initialSort: SortState<K>,
  initialFilters: F,
) {
  const [query, setQueryState] = useState("");
  const [filters, setFiltersState] = useState<F>(initialFilters);
  const [sort, setSortState] = useState(initialSort);
  const [page, setPage] = useState(1);
  return {
    query,
    filters,
    sort,
    page,
    setPage,
    setQuery: (value: string) => {
      setQueryState(value);
      setPage(1);
    },
    setFilter: (key: keyof F, value: string) => {
      setFiltersState((current) => ({ ...current, [key]: value }));
      setPage(1);
    },
    setSort: (value: SortState<K>) => {
      setSortState(value);
      setPage(1);
    },
  };
}
