// API de la Fase 7B: identidad de dispositivos, atribución de mantenimiento, búsqueda global y
// el motor de herramientas de analista (7A) que usa la Analyst Console.
//
// Módulo aparte de sentra.ts por la misma razón que sentra6e.ts: lo importan páginas cargadas
// con React.lazy. Los permisos se comprueban en el servidor en cada petición; ocultar un botón
// es solo comodidad.
import { apiGet, apiPost } from "./client";
import type {
  AnalystVerdict,
  AttributionApplyResult,
  AttributionPreview,
  CorrelationReviewApplyResult,
  CorrelationReviewPreview,
  AssetIdentityProfile,
  DetectionAttributionRead,
  IdentityCandidateList,
  IdentityComparison,
  IdentityLinkList,
  IdentityLinkPreview,
  IdentityLinkRead,
  IdentityLinkRequest,
  MaintenanceOperationCreate,
  MaintenanceOperationList,
  MaintenanceOperationRead,
  MaintenanceStatus,
  ReferenceArtifactList,
  SearchResult,
  ToolCatalog,
  ToolExecutionList,
  ToolExecutionOut,
  ToolOut,
  WlanClientRead,
  WlanObservationList,
} from "./types";

/** `?a=1&b=2` con los parámetros definidos (undefined o cadena vacía no se envían). */
function query(params: Record<string, string | number | boolean | undefined | null>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    search.set(key, String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}

const enc = encodeURIComponent;

/** Identidad (lectura con monitoring:read; asociar o revocar exige identity:manage). */
export const identityApi = {
  profile: (assetId: string, signal?: AbortSignal) =>
    apiGet<AssetIdentityProfile>(`/assets/${enc(assetId)}/identity/profile`, { signal }),
  candidates: (assetId: string, signal?: AbortSignal) =>
    apiGet<IdentityCandidateList>(`/assets/${enc(assetId)}/identity/candidates`, { signal }),
  compare: (left: string, right: string, signal?: AbortSignal) =>
    apiGet<IdentityComparison>(`/identity/compare${query({ left, right })}`, { signal }),
  links: (
    params: { assetId?: string; wlanClientId?: string; active?: boolean } = {},
    signal?: AbortSignal,
  ) =>
    apiGet<IdentityLinkList>(
      `/identity/links${query({
        asset_id: params.assetId,
        wlan_client_id: params.wlanClientId,
        active: params.active,
      })}`,
      { signal },
    ),
  preview: (body: IdentityLinkRequest) => apiPost<IdentityLinkPreview>("/identity/links/preview", body),
  // confirm: true literal: el servidor rechaza (422) una creación sin confirmación explícita.
  create: (body: IdentityLinkRequest & { reason: string }) =>
    apiPost<IdentityLinkRead>("/identity/links", { ...body, confirm: true }),
  revoke: (linkId: string, reason: string) =>
    apiPost<IdentityLinkRead>(`/identity/links/${enc(linkId)}/revoke`, { reason }),
};

export const wlanClientApi = {
  get: (clientId: string, signal?: AbortSignal) =>
    apiGet<WlanClientRead>(`/network/wlan/clients/${enc(clientId)}`, { signal }),
  observations: (clientId: string, signal?: AbortSignal) =>
    apiGet<WlanObservationList>(`/network/wlan/clients/${enc(clientId)}/observations`, { signal }),
};

export const attributionApi = {
  get: (detectionId: string, signal?: AbortSignal) =>
    apiGet<DetectionAttributionRead>(`/detections/${enc(detectionId)}/attribution`, { signal }),
  evaluate: (detectionId: string) =>
    apiPost<DetectionAttributionRead>(`/detections/${enc(detectionId)}/attribution/evaluate`),
  verdict: (detectionId: string, verdict: AnalystVerdict, reason: string) =>
    apiPost<DetectionAttributionRead>(`/detections/${enc(detectionId)}/attribution/verdict`, { verdict, reason }),
};

/** Operaciones de mantenimiento (Fase 7B.1). Lectura con monitoring:read; el resto, maintenance:manage. */
/** Fase 7B-Fix1: revisión de CORR-002 anteriores a la v5 (detections:manage). */
export const correlationReviewApi = {
  preview: (assetId?: string) =>
    apiPost<CorrelationReviewPreview>("/detections/correlation-review/preview", { asset_id: assetId ?? null }),
  apply: (detectionIds: string[], note?: string) =>
    apiPost<CorrelationReviewApplyResult>("/detections/correlation-review/apply", {
      detection_ids: detectionIds,
      note: note?.trim() ? note.trim() : null,
      confirm: true,
    }),
};

export const maintenanceApi = {
  list: (
    params: { assetId?: string; status?: MaintenanceStatus; siteId?: string; limit?: number; offset?: number } = {},
    signal?: AbortSignal,
  ) =>
    apiGet<MaintenanceOperationList>(
      `/maintenance-operations${query({
        asset_id: params.assetId,
        status: params.status,
        site_id: params.siteId,
        limit: params.limit,
        offset: params.offset,
      })}`,
      { signal },
    ),
  references: (signal?: AbortSignal) =>
    apiGet<ReferenceArtifactList>("/maintenance-operations/reference-artifacts", { signal }),
  create: (body: MaintenanceOperationCreate) => apiPost<MaintenanceOperationRead>("/maintenance-operations", body),
  approve: (operationId: string, note?: string) =>
    apiPost<MaintenanceOperationRead>(`/maintenance-operations/${enc(operationId)}/approve`, {
      note: note?.trim() || null,
    }),
  revoke: (operationId: string, reason: string) =>
    apiPost<MaintenanceOperationRead>(`/maintenance-operations/${enc(operationId)}/revoke`, { reason }),
  preview: (operationId: string) => apiPost<AttributionPreview>(`/maintenance-operations/${enc(operationId)}/preview`),
  apply: (operationId: string) =>
    apiPost<AttributionApplyResult>(`/maintenance-operations/${enc(operationId)}/apply`, { confirm: true }),
};

export const searchApi = {
  search: (q: string, siteId: string | undefined, signal?: AbortSignal) =>
    apiGet<SearchResult>(`/search${query({ q, site_id: siteId })}`, { signal }),
};

export interface ToolRun {
  input: Record<string, unknown>;
  siteId?: string;
  incidentId?: string;
  idempotencyKey?: string;
}

function runBody(run: ToolRun) {
  return {
    input: run.input,
    site_id: run.siteId ?? null,
    incident_id: run.incidentId ?? null,
    idempotency_key: run.idempotencyKey ?? null,
  };
}

/** Motor de herramientas 7A: catálogo cerrado, lectura en READ ONLY, acciones con vista previa. */
export const toolsApi = {
  catalog: (signal?: AbortSignal) => apiGet<ToolCatalog>("/tools", { signal }),
  get: (toolId: string, signal?: AbortSignal) => apiGet<ToolOut>(`/tools/${enc(toolId)}`, { signal }),
  execute: (toolId: string, run: ToolRun) => apiPost<ToolExecutionOut>(`/tools/${enc(toolId)}/execute`, runBody(run)),
  preview: (toolId: string, run: ToolRun) => apiPost<ToolExecutionOut>(`/tools/${enc(toolId)}/preview`, runBody(run)),
  confirm: (executionId: string, version: number, note?: string) =>
    apiPost<ToolExecutionOut>(`/tools/executions/${enc(executionId)}/confirm`, {
      version,
      confirm: true,
      note: note?.trim() || null,
    }),
  cancel: (executionId: string, version: number) =>
    apiPost<ToolExecutionOut>(`/tools/executions/${enc(executionId)}/cancel`, { version }),
  executions: (
    params: { toolId?: string; assetId?: string; incidentId?: string; limit?: number; offset?: number } = {},
    signal?: AbortSignal,
  ) =>
    apiGet<ToolExecutionList>(
      `/tools/executions${query({
        tool_id: params.toolId,
        asset_id: params.assetId,
        incident_id: params.incidentId,
        limit: params.limit,
        offset: params.offset,
      })}`,
      { signal },
    ),
};
