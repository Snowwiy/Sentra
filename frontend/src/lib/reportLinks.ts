// Enlaces de prefill a /reports (Fase 5E). Módulo mínimo: lo importan páginas del bundle
// principal (activo, detección) sin arrastrar el resto de utilidades de informes.

/** Filtros de identificadores de un informe. */
export type IdFilterKey = "asset_ids" | "incident_ids" | "detection_ids" | "execution_ids" | "playbook_ids";

/** Parámetros de prefill (?type=incident&incident_id=…) y el filtro al que corresponden. */
export const PREFILL_PARAMS: Record<string, IdFilterKey> = {
  asset_id: "asset_ids",
  incident_id: "incident_ids",
  detection_id: "detection_ids",
  execution_id: "execution_ids",
  playbook_id: "playbook_ids",
};

export type PrefillParam = "asset_id" | "incident_id" | "detection_id" | "execution_id" | "playbook_id";

/** Enlace a /reports con el formulario precargado. */
export function reportHref(type: string, ids: Partial<Record<PrefillParam, string>> = {}): string {
  const search = new URLSearchParams({ type });
  for (const [key, value] of Object.entries(ids)) if (value) search.set(key, value);
  return `/reports?${search.toString()}`;
}
