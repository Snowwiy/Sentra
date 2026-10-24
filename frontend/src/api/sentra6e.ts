// API de la Fase 6E: historial de topología, DHCP e identidad, telemetría de endpoint y árbol
// de procesos, excepciones de reglas, investigación forense y aislamiento.
//
// Módulo aparte de sentra.ts: solo lo importan páginas y pestañas cargadas con React.lazy, así
// que no pesa en el bundle principal. Los permisos se comprueban en el servidor en cada
// petición; ocultar un botón en la UI es solo comodidad.
import { apiDownload, apiGet, apiPatch, apiPost, apiDelete, type DownloadedFile } from "./client";
import type {
  ActivityCategory,
  ActivityList,
  AssetIdentity,
  AssetIdentityHistory,
  DetectionExclusion,
  DetectionExclusionCreate,
  DetectionExclusionList,
  DhcpImportResult,
  DhcpLeaseList,
  DhcpLeaseMatch,
  DhcpReadRequested,
  DhcpSource,
  DhcpSourceCreate,
  DhcpSourceList,
  DhcpSourceUpdate,
  EndpointMetrics,
  EndpointTelemetryStatus,
  IdentityField,
  Investigation,
  InvestigationCreate,
  InvestigationDetail,
  InvestigationList,
  InvestigationNote,
  InvestigationNoteKind,
  InvestigationStatus,
  ForensicArtifactDetail,
  IsolationOverview,
  IsolationReleaseRequest,
  IsolationRequest,
  IsolationSession,
  IsolationSessionList,
  NetworkChange,
  NetworkChangeList,
  NetworkChangeReview,
  NetworkChangeStatus,
  NetworkChangeType,
  ProcessInstanceDetail,
  ProcessTree,
  TopologyDiff,
  TopologyHistory,
  TopologySnapshotList,
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
const assetPath = (assetId: string) => `/assets/${enc(assetId)}`;

// --- 6E.1 historial de topología ---------------------------------------------------------------

export interface DiffQuery {
  siteId?: string;
  fromSnapshot?: string;
  toSnapshot?: string;
  subnet?: string;
}

export interface ChangeQuery {
  siteId?: string;
  changeType?: NetworkChangeType;
  status?: NetworkChangeStatus;
  assetId?: string;
  subnet?: string;
  limit?: number;
  offset?: number;
}

function diffParams(q: DiffQuery) {
  return { site_id: q.siteId, from_snapshot: q.fromSnapshot, to_snapshot: q.toSnapshot, subnet: q.subnet?.trim() };
}

/** Lectura con monitoring:read; revisar un cambio exige topology:manage (admin). */
export const topologyHistoryApi = {
  snapshots: (query_: { siteId?: string; beforeSequence?: number; limit?: number } = {}, signal?: AbortSignal) =>
    apiGet<TopologySnapshotList>(
      `/topology/snapshots${query({ site_id: query_.siteId, before_sequence: query_.beforeSequence, limit: query_.limit })}`,
      { signal },
    ),
  diff: (q: DiffQuery, signal?: AbortSignal) => apiGet<TopologyDiff>(`/topology/diff${query(diffParams(q))}`, { signal }),
  /** Fichero con X-Sentra-SHA256: se verifica antes de guardarlo. */
  exportDiff: (q: DiffQuery, format: "json" | "csv", signal?: AbortSignal): Promise<DownloadedFile> =>
    apiDownload(`/topology/diff/export${query({ ...diffParams(q), format })}`, { signal }),
  changes: (q: ChangeQuery = {}, signal?: AbortSignal) =>
    apiGet<NetworkChangeList>(
      `/topology/changes${query({
        site_id: q.siteId,
        change_type: q.changeType,
        status: q.status,
        asset_id: q.assetId,
        subnet: q.subnet?.trim(),
        limit: q.limit,
        offset: q.offset,
      })}`,
      { signal },
    ),
  reviewChange: (changeId: string, input: NetworkChangeReview, siteId?: string) =>
    apiPatch<NetworkChange>(`/topology/changes/${enc(changeId)}/review${query({ site_id: siteId })}`, input),
  nodeHistory: (nodeId: string, siteId?: string, signal?: AbortSignal) =>
    apiGet<TopologyHistory>(`/topology/history/nodes/${enc(nodeId)}${query({ site_id: siteId })}`, { signal }),
  linkHistory: (linkId: string, siteId?: string, signal?: AbortSignal) =>
    apiGet<TopologyHistory>(`/topology/history/links/${enc(linkId)}${query({ site_id: siteId })}`, { signal }),
};

// --- 6E.2 DHCP e identidad ---------------------------------------------------------------------

export interface LeaseQuery {
  siteId?: string;
  sourceId?: string;
  match?: DhcpLeaseMatch;
  search?: string;
  limit?: number;
  offset?: number;
}

const dhcpSourcePath = (sourceId: string) => `/dhcp/sources/${enc(sourceId)}`;

/** Lectura con monitoring:read; crear, editar, importar y pedir lecturas exige dhcp:manage. */
export const dhcpApi = {
  sources: (siteId?: string, signal?: AbortSignal) =>
    apiGet<DhcpSourceList>(`/dhcp/sources${query({ site_id: siteId })}`, { signal }),
  create: (input: DhcpSourceCreate) => apiPost<DhcpSource>("/dhcp/sources", input),
  update: (sourceId: string, input: DhcpSourceUpdate) => apiPatch<DhcpSource>(dhcpSourcePath(sourceId), input),
  remove: (sourceId: string, version: number) => apiDelete<void>(`${dhcpSourcePath(sourceId)}${query({ version })}`),
  /** El texto del fichero viaja en JSON (tope del servidor DHCP_IMPORT_MAX_KB). */
  importLeases: (sourceId: string, content: string, version: number) =>
    apiPost<DhcpImportResult>(`${dhcpSourcePath(sourceId)}/import`, { content, version }),
  requestRead: (sourceId: string) => apiPost<DhcpReadRequested>(`${dhcpSourcePath(sourceId)}/read`, {}),
  leases: (q: LeaseQuery = {}, signal?: AbortSignal) =>
    apiGet<DhcpLeaseList>(
      `/dhcp/leases${query({
        site_id: q.siteId,
        source_id: q.sourceId,
        match: q.match,
        search: q.search?.trim(),
        limit: q.limit,
        offset: q.offset,
      })}`,
      { signal },
    ),
  identity: (assetId: string, signal?: AbortSignal) => apiGet<AssetIdentity>(`${assetPath(assetId)}/identity`, { signal }),
  identityHistory: (
    assetId: string,
    q: { beforeId?: number; limit?: number; field?: IdentityField } = {},
    signal?: AbortSignal,
  ) =>
    apiGet<AssetIdentityHistory>(
      `${assetPath(assetId)}/identity/history${query({ before_id: q.beforeId, limit: q.limit, field: q.field })}`,
      { signal },
    ),
};

// --- 6E.3/6E.4 telemetría y árbol de procesos ---------------------------------------------------

export interface ActivityQuery {
  category?: ActivityCategory;
  action?: string;
  instanceKey?: string;
  beforeId?: number;
  limit?: number;
}

/** telemetry:read (analyst y admin). Nunca se pide el árbol completo: un nivel por petición. */
export const endpointApi = {
  /** Raíces (sin parent) o los hijos directos de `parent`; con `search`, coincidencias planas. */
  processTree: (
    assetId: string,
    q: { parent?: string; at?: string; search?: string; limit?: number } = {},
    signal?: AbortSignal,
  ) =>
    apiGet<ProcessTree>(
      `${assetPath(assetId)}/process-tree${query({ parent: q.parent, at: q.at, search: q.search?.trim(), limit: q.limit })}`,
      { signal },
    ),
  processInstance: (assetId: string, instanceKey: string, signal?: AbortSignal) =>
    apiGet<ProcessInstanceDetail>(`${assetPath(assetId)}/process-instances/${enc(instanceKey)}`, { signal }),
  activity: (assetId: string, q: ActivityQuery = {}, signal?: AbortSignal) =>
    apiGet<ActivityList>(
      `${assetPath(assetId)}/activity${query({
        category: q.category,
        action: q.action,
        instance_key: q.instanceKey,
        before_id: q.beforeId,
        limit: q.limit,
      })}`,
      { signal },
    ),
  telemetryStatus: (assetId: string, signal?: AbortSignal) =>
    apiGet<EndpointTelemetryStatus>(`${assetPath(assetId)}/telemetry-status`, { signal }),
  metrics: (signal?: AbortSignal) => apiGet<EndpointMetrics>("/endpoint/metrics", { signal }),
};

// --- 6E.5 excepciones de reglas -----------------------------------------------------------------

/** Ver con rules:read; crear y revocar con rules:manage (admin). */
export const exclusionsApi = {
  list: (includeInactive = false, signal?: AbortSignal) =>
    apiGet<DetectionExclusionList>(`/detection-exclusions${query({ include_inactive: includeInactive || undefined })}`, {
      signal,
    }),
  create: (input: DetectionExclusionCreate) => apiPost<DetectionExclusion>("/detection-exclusions", input),
  revoke: (exclusionId: string) => apiPost<DetectionExclusion>(`/detection-exclusions/${enc(exclusionId)}/revoke`, {}),
};

// --- 6E.6 investigaciones forenses --------------------------------------------------------------

const investigationPath = (id: string) => `/investigations/${enc(id)}`;

/**
 * forensics:read para ver, forensics:acquire para crear y anotar, forensics:download para el
 * paquete (auditado) y forensics:manage para cerrar, reabrir y retención legal. La recogida se
 * pide con POST /response/executions e investigation_id (responseApi.execute).
 */
export const forensicsApi = {
  list: (
    q: { assetId?: string; status?: InvestigationStatus; siteId?: string; limit?: number; offset?: number } = {},
    signal?: AbortSignal,
  ) =>
    apiGet<InvestigationList>(
      `/investigations${query({ asset_id: q.assetId, status: q.status, site_id: q.siteId, limit: q.limit, offset: q.offset })}`,
      { signal },
    ),
  create: (input: InvestigationCreate) => apiPost<Investigation>("/investigations", input),
  get: (id: string, signal?: AbortSignal) => apiGet<InvestigationDetail>(investigationPath(id), { signal }),
  artifact: (id: string, artifactId: string, signal?: AbortSignal) =>
    apiGet<ForensicArtifactDetail>(`${investigationPath(id)}/artifacts/${enc(artifactId)}`, { signal }),
  addNote: (id: string, body: string, kind: InvestigationNoteKind = "note") =>
    apiPost<InvestigationNote>(`${investigationPath(id)}/notes`, { kind, body }),
  close: (id: string, version: number) => apiPost<Investigation>(`${investigationPath(id)}/close`, { version }),
  reopen: (id: string, version: number) => apiPost<Investigation>(`${investigationPath(id)}/reopen`, { version }),
  setLegalHold: (id: string, legalHold: boolean, version: number) =>
    apiPost<Investigation>(`${investigationPath(id)}/legal-hold`, { version, legal_hold: legalHold }),
  /**
   * ZIP con X-Sentra-SHA256. POST (no GET): cada paquete queda registrado y auditado. Con
   * artefactos `mismatch` el servidor responde 409 evidence_integrity_mismatch salvo que se
   * acepte el aviso de forma explícita (acknowledge_mismatch).
   */
  downloadPackage: (id: string, acknowledgeMismatch: boolean, signal?: AbortSignal) =>
    apiDownload(`${investigationPath(id)}/package`, {
      method: "POST",
      body: { acknowledge_mismatch: acknowledgeMismatch },
      signal,
    }),
};

// --- 6E.7 aislamiento ---------------------------------------------------------------------------

/** containment:preview para ver; containment:isolate y containment:release (admin) para actuar. */
export const isolationApi = {
  overview: (assetId: string, signal?: AbortSignal) =>
    apiGet<IsolationOverview>(`${assetPath(assetId)}/isolation`, { signal }),
  history: (assetId: string, limit = 20, signal?: AbortSignal) =>
    apiGet<IsolationSessionList>(`${assetPath(assetId)}/isolation/sessions${query({ limit })}`, { signal }),
  isolate: (assetId: string, input: IsolationRequest) =>
    apiPost<IsolationSession>(`${assetPath(assetId)}/isolation`, input),
  release: (assetId: string, input: IsolationReleaseRequest) =>
    apiPost<IsolationSession>(`${assetPath(assetId)}/isolation/release`, input),
  /** Sesiones vivas de todos los activos. */
  active: (signal?: AbortSignal) => apiGet<IsolationSessionList>("/isolation/sessions", { signal }),
};
