// API de la Fase 7F (SIEM): fuentes externas, importación y eventos normalizados.
//
// Módulo aparte de sentra.ts: solo lo importan las páginas SIEM y Live SOC (cargadas con
// React.lazy). Los eventos exigen siem:evidence; registrar fuentes o importar, siem:manage
// (admin). La API lo comprueba siempre: la UI solo oculta lo que no se puede.
import { apiDelete, apiGet, apiPost, apiPut } from "./client";
import type {
  IncidentSiemEventList,
  SiemBatchAccepted,
  SiemEvidenceExport,
  SiemRelated,
  SiemSavedSearchList,
  SiemSavedSearchRead,
  SiemSearchFilter,
  SiemSearchRequest,
  SiemSearchResult,
  SiemTimeline,
  SiemConnectorList,
  SiemEventDetail,
  SiemEventList,
  SiemOverview,
  SiemSourceCreate,
  SiemSourceList,
  SiemSourceRead,
  SiemSourceUpdate,
} from "./types";

const enc = encodeURIComponent;

export function query(params: Record<string, string | number | boolean | undefined | null>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    search.set(key, String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}

export interface SiemEventQuery {
  siteId?: string;
  sourceId?: string;
  eventType?: string;
  since?: string;
  until?: string;
  limit?: number;
  offset?: number;
}

export const siemApi = {
  connectors: (signal?: AbortSignal) => apiGet<SiemConnectorList>("/siem/connectors", { signal }),
  overview: (siteId: string | undefined, hours: number, signal?: AbortSignal) =>
    apiGet<SiemOverview>(`/siem/overview${query({ site_id: siteId, hours })}`, { signal }),
  sources: (siteId: string | undefined, signal?: AbortSignal) =>
    apiGet<SiemSourceList>(`/siem/sources${query({ site_id: siteId })}`, { signal }),
  source: (sourceId: string, signal?: AbortSignal) =>
    apiGet<SiemSourceRead>(`/siem/sources/${enc(sourceId)}`, { signal }),
  /** Registrar una fuente. Queda deshabilitada salvo que se pida lo contrario. */
  createSource: (body: SiemSourceCreate) => apiPost<SiemSourceRead>("/siem/sources", body),
  updateSource: (sourceId: string, body: SiemSourceUpdate) =>
    apiPut<SiemSourceRead>(`/siem/sources/${enc(sourceId)}`, body),
  /** Retirar una fuente deshabilitada (borra sus eventos; queda auditado). */
  deleteSource: (sourceId: string) => apiDelete<void>(`/siem/sources/${enc(sourceId)}`),
  /** Importa el contenido de un fichero exportado (una línea por registro). Idempotente. */
  importFile: (sourceId: string, content: string, filename?: string) =>
    apiPost<SiemBatchAccepted>(`/siem/sources/${enc(sourceId)}/import`, { content, filename }),
  events: (q: SiemEventQuery, signal?: AbortSignal) =>
    apiGet<SiemEventList>(
      `/siem/events${query({
        site_id: q.siteId,
        source_id: q.sourceId,
        event_type: q.eventType,
        since: q.since,
        until: q.until,
        limit: q.limit ?? 50,
        offset: q.offset || undefined,
      })}`,
      { signal },
    ),
  event: (eventId: string, signal?: AbortSignal) =>
    apiGet<SiemEventDetail>(`/siem/events/${enc(eventId)}`, { signal }),
  // --- Fase 7F.6: hunting e investigación (siem:evidence) ---
  search: (body: SiemSearchRequest, signal?: AbortSignal) =>
    apiPost<SiemSearchResult>("/siem/search", body, { signal }),
  savedSearches: (signal?: AbortSignal) => apiGet<SiemSavedSearchList>("/siem/searches", { signal }),
  saveSearch: (name: string, filter: SiemSearchFilter) =>
    apiPost<SiemSavedSearchRead>("/siem/searches", { name, query: filter }),
  deleteSearch: (searchId: string) => apiDelete<void>(`/siem/searches/${enc(searchId)}`),
  related: (eventId: string, signal?: AbortSignal) =>
    apiGet<SiemRelated>(`/siem/events/${enc(eventId)}/related`, { signal }),
  timeline: (assetId: string, since: string, until: string, signal?: AbortSignal) =>
    apiGet<SiemTimeline>(`/siem/timeline${query({ asset_id: assetId, since, until })}`, { signal }),
  /** Paquete de evidencia con hashes (auditado en el servidor). */
  exportEvents: (eventIds: string[], reason?: string) =>
    apiPost<SiemEvidenceExport>("/siem/events/export", { event_ids: eventIds, reason: reason || null }),
  /** Añadir a un caso (incidents:manage además de siem:evidence). Idempotente. */
  attachToIncident: (eventId: string, incidentId: string, note?: string) =>
    apiPost<IncidentSiemEventList>(`/siem/events/${enc(eventId)}/incidents/${enc(incidentId)}`, {
      note: note || null,
    }),
  incidentEvents: (incidentId: string, signal?: AbortSignal) =>
    apiGet<IncidentSiemEventList>(`/siem/incidents/${enc(incidentId)}/events`, { signal }),
};
