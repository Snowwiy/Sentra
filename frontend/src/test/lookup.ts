// Utilidades de test de la Fase 7C.3: elementos y respuestas de GET /lookup/{kind}. Solo las
// importan los *.test.tsx; no forma parte del bundle de la aplicación.
import type { LookupItem } from "../api/types";

export function lookupItem(overrides: Partial<LookupItem> & Pick<LookupItem, "kind" | "id" | "label">): LookupItem {
  return {
    secondary: null,
    match_field: "name",
    exact: false,
    archived: false,
    site_name: null,
    ip: null,
    mac: null,
    device_type: null,
    status: null,
    severity: null,
    asset_id: null,
    asset_label: null,
    last_seen_at: null,
    ...overrides,
  };
}

/**
 * Responde como el servidor: con ?ids= devuelve los elementos pedidos que existen; con ?q=
 * devuelve todos los elementos dados (el filtrado real lo prueba el backend).
 */
export function lookupResult(url: URL, ...items: LookupItem[]) {
  const ids = url.searchParams.getAll("ids");
  const chosen = ids.length ? items.filter((i) => ids.includes(i.id)) : items;
  return {
    kind: items[0]?.kind ?? "asset",
    query: url.searchParams.get("q") ?? "",
    resolution: chosen.length === 0 ? "none" : chosen.length === 1 ? "exact" : "partial",
    items: chosen,
    truncated: false,
  };
}
