// API de la Fase 7E (NDR): sensores pasivos, flujos, metadatos y anomalías de red.
//
// Módulo aparte de sentra.ts: solo lo importa la página NDR (cargada con React.lazy). Los
// flujos y metadatos exigen ndr:evidence; aprobar la captura, ndr:manage (admin); el triaje
// de anomalías, ndr:triage; registrar una solicitud de control, además incidents:manage. La API lo comprueba siempre: la UI solo oculta lo que no se puede.
import { apiGet, apiPost, apiPut } from "./client";
import type {
  NdrAnomalyList,
  NdrAnomalyRead,
  NdrAnomalyStatus,
  NdrAnomalyVerdict,
  NdrBindingList,
  NdrCaptureConfigRead,
  NdrCaptureConfigUpdate,
  NdrControlRequest,
  NdrFlowList,
  NdrObservationKind,
  NdrObservationList,
  NdrOverview,
  NdrResponsePlan,
  NdrRuleList,
  NdrSensorList,
  NetworkControlRead,
} from "./types";

const enc = encodeURIComponent;

function query(params: Record<string, string | number | boolean | undefined | null>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    search.set(key, String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}

export interface NdrAnomalyQuery {
  siteId?: string;
  active?: boolean;
  status?: NdrAnomalyStatus;
  verdict?: NdrAnomalyVerdict;
  category?: string;
  ip?: string;
  assetId?: string;
  limit?: number;
  offset?: number;
}

export interface NdrFlowQuery {
  siteId?: string;
  ip?: string;
  port?: number;
  transport?: string;
  limit?: number;
  offset?: number;
}

export interface NdrObservationQuery {
  siteId?: string;
  kind?: NdrObservationKind;
  ip?: string;
  name?: string;
  limit?: number;
  offset?: number;
}

export const ndrApi = {
  overview: (siteId: string | undefined, hours: number, signal?: AbortSignal) =>
    apiGet<NdrOverview>(`/ndr/overview${query({ site_id: siteId, hours })}`, { signal }),
  sensors: (siteId: string | undefined, signal?: AbortSignal) =>
    apiGet<NdrSensorList>(`/ndr/sensors${query({ site_id: siteId })}`, { signal }),
  /** Aprobar o cambiar la captura. Habilitar exige punto de observación y confirmación. */
  updateConfig: (sensorId: string, body: NdrCaptureConfigUpdate) =>
    apiPut<NdrCaptureConfigRead>(`/ndr/sensors/${enc(sensorId)}/config`, body),
  rules: (signal?: AbortSignal) => apiGet<NdrRuleList>("/ndr/rules", { signal }),
  anomalies: (q: NdrAnomalyQuery, signal?: AbortSignal) =>
    apiGet<NdrAnomalyList>(
      `/ndr/anomalies${query({
        site_id: q.siteId,
        active: q.active,
        status: q.status,
        verdict: q.verdict,
        category: q.category,
        ip: q.ip?.trim(),
        asset_id: q.assetId,
        limit: q.limit ?? 50,
        offset: q.offset || undefined,
      })}`,
      { signal },
    ),
  anomaly: (anomalyId: string, signal?: AbortSignal) =>
    apiGet<NdrAnomalyRead>(`/ndr/anomalies/${enc(anomalyId)}`, { signal }),
  /** Cerrar (resuelta o falso positivo) exige una nota; queda auditado. */
  setStatus: (anomalyId: string, status: Exclude<NdrAnomalyStatus, "open">, note?: string) =>
    apiPost<NdrAnomalyRead>(`/ndr/anomalies/${enc(anomalyId)}/status`, {
      status,
      note: note?.trim() || null,
    }),
  /** Sugerencias derivadas de la evidencia (7E.7). Solo lectura: no crea ni aplica nada. */
  responsePlan: (anomalyId: string, signal?: AbortSignal) =>
    apiGet<NdrResponsePlan>(`/ndr/anomalies/${enc(anomalyId)}/response-plan`, { signal }),
  /** Registra la solicitud en el incidente (pendiente de aprobación; se aplica fuera de Sentra). */
  requestControl: (anomalyId: string, body: NdrControlRequest) =>
    apiPost<NetworkControlRead>(`/ndr/anomalies/${enc(anomalyId)}/network-controls`, body),
  flows: (q: NdrFlowQuery, signal?: AbortSignal) =>
    apiGet<NdrFlowList>(
      `/ndr/flows${query({
        site_id: q.siteId,
        ip: q.ip?.trim(),
        port: q.port,
        transport: q.transport,
        limit: q.limit ?? 100,
        offset: q.offset || undefined,
      })}`,
      { signal },
    ),
  observations: (q: NdrObservationQuery, signal?: AbortSignal) =>
    apiGet<NdrObservationList>(
      `/ndr/observations${query({
        site_id: q.siteId,
        kind: q.kind,
        ip: q.ip?.trim(),
        name: q.name?.trim(),
        limit: q.limit ?? 100,
        offset: q.offset || undefined,
      })}`,
      { signal },
    ),
  bindings: (siteId: string | undefined, ip: string | undefined, signal?: AbortSignal) =>
    apiGet<NdrBindingList>(`/ndr/bindings${query({ site_id: siteId, ip: ip?.trim(), limit: 100 })}`, {
      signal,
    }),
};
