// Fuentes oficiales del catálogo de vulnerabilidades (Fase 6C.4).
//
// Módulo aparte de sentra.ts para no mezclar este contrato con el resto de la API. Ninguna
// llamada envía una URL: el servidor descarga solo de sus URLs fijas, y la UI solo puede
// subir un fichero o pedir una sincronización.
import { apiGet, apiPost } from "./client";
import type {
  CatalogRecordPage,
  CatalogStatus,
  CveDetail,
  OfficialVulnSource,
  VulnerabilitySource,
  VulnerabilitySourceList,
  VulnSeverity,
  VulnSourceImportResult,
  VulnSourcePreview,
  VulnSourceSyncList,
  VulnSourceSyncRequested,
} from "./types";

function query(params: Record<string, string | number | boolean | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === "") continue;
    search.set(key, String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}

/** Contenido de un fichero: JSON como texto o binario (.gz/.zip) en base64; nunca los dos. */
export type SourceContent = { content: string } | { content_base64: string };

export interface CatalogRecordQuery {
  q?: string;
  severity?: VulnSeverity;
  knownExploited?: boolean;
  epssMin?: number;
  source?: string;
  hasFindings?: boolean;
  limit?: number;
  offset?: number;
}

const src = (key: string) => `/vulnerabilities/sources/${encodeURIComponent(key)}`;

export const vulnSourcesApi = {
  list: (signal?: AbortSignal) => apiGet<VulnerabilitySourceList>("/vulnerabilities/sources", { signal }),
  get: (key: string, signal?: AbortSignal) => apiGet<VulnerabilitySource>(src(key), { signal }),
  syncs: (key: string, page: { limit?: number; offset?: number } = {}, signal?: AbortSignal) =>
    apiGet<VulnSourceSyncList>(`${src(key)}/syncs${query({ limit: page.limit, offset: page.offset })}`, { signal }),
  /** Valida y cuenta; el servidor no guarda nada. */
  preview: (key: OfficialVulnSource, body: SourceContent) =>
    apiPost<VulnSourcePreview>(`${src(key)}/import/preview`, body),
  /** Importa exactamente lo previsualizado: si el fichero cambió, 409 catalog_changed. */
  import: (key: OfficialVulnSource, body: SourceContent, expectedSha256: string, skipInvalid: boolean) =>
    apiPost<VulnSourceImportResult>(`${src(key)}/import`, {
      ...body,
      expected_sha256: expectedSha256,
      skip_invalid: skipInvalid,
    }),
  /** 202: solo queda anotada; la descarga la hace el job. 409 si la red está desactivada. */
  sync: (key: OfficialVulnSource, full = false) =>
    apiPost<VulnSourceSyncRequested>(`${src(key)}/sync${query({ full: full || undefined })}`),
  status: (signal?: AbortSignal) => apiGet<CatalogStatus>("/vulnerabilities/catalog/status", { signal }),
  records: (q: CatalogRecordQuery, signal?: AbortSignal) =>
    apiGet<CatalogRecordPage>(
      `/vulnerabilities/catalog/records${query({
        q: q.q,
        severity: q.severity,
        known_exploited: q.knownExploited,
        epss_min: q.epssMin,
        source: q.source,
        has_findings: q.hasFindings,
        limit: q.limit,
        offset: q.offset,
      })}`,
      { signal },
    ),
  cve: (cveId: string, signal?: AbortSignal) =>
    apiGet<CveDetail>(`/vulnerabilities/catalog/cves/${encodeURIComponent(cveId)}`, { signal }),
};
