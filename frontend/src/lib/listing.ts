// Client-side search, sorting and pagination for inventory lists. The data is one snapshot
// already in memory (hundreds or a few thousand rows), so this is cheaper and simpler than a
// round trip per page; server-side paging is used where tables grow without bound (events).

export type SortDir = "asc" | "desc";

export interface SortState<K extends string> {
  key: K;
  dir: SortDir;
}

export type Comparator<T> = (a: T, b: T) => number;

export interface ListingPage<T> {
  items: T[];
  /** Rows matching the filter (all pages). */
  total: number;
  /** Page actually shown (clamped to the last one after the filter shrank the list). */
  page: number;
  pages: number;
}

/** Case-insensitive "contains" over several fields; an empty query matches everything. */
export function matchesText(query: string, ...fields: (string | number | null | undefined)[]): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return fields.some((field) => field != null && String(field).toLowerCase().includes(q));
}

/**
 * Compare by a key in the given direction. Missing values (null/undefined) always sort last,
 * whatever the direction: "highest CPU first" must not start with processes without a reading.
 */
export function compareBy<T>(
  get: (item: T) => string | number | null | undefined,
  dir: SortDir = "asc",
): Comparator<T> {
  const sign = dir === "asc" ? 1 : -1;
  return (a, b) => {
    const x = get(a);
    const y = get(b);
    if (x == null && y == null) return 0;
    if (x == null) return 1;
    if (y == null) return -1;
    if (typeof x === "number" && typeof y === "number") return sign * (x - y);
    return sign * String(x).localeCompare(String(y), "es", { numeric: true, sensitivity: "base" });
  };
}

export function listPage<T>(
  items: readonly T[],
  options: {
    filter?: (item: T) => boolean;
    compare?: Comparator<T>;
    page: number;
    pageSize: number;
  },
): ListingPage<T> {
  const { filter, compare, pageSize } = options;
  const matched = filter ? items.filter(filter) : [...items];
  if (compare) matched.sort(compare);
  const pages = Math.max(1, Math.ceil(matched.length / pageSize));
  const page = Math.min(Math.max(1, options.page), pages);
  return {
    items: matched.slice((page - 1) * pageSize, page * pageSize),
    total: matched.length,
    page,
    pages,
  };
}

/** Distinct non-empty values, sorted, for filter dropdowns. */
export function distinct<T>(items: readonly T[], get: (item: T) => string | null | undefined): string[] {
  const values = new Set<string>();
  for (const item of items) {
    const value = get(item);
    if (value) values.add(value);
  }
  return [...values].sort((a, b) => a.localeCompare(b, "es", { sensitivity: "base" }));
}
