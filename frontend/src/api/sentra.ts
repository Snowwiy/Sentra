import { apiDelete, apiDownload, apiGet, apiPatch, apiPost } from "./client";
import type {
  DeviceClassification,
  MacLocationList,
  MonitoringStatus,
  NeighborProtocol,
  NetworkCandidateList,
  NetworkDevice,
  NetworkDeviceCreate,
  NetworkDeviceDetail,
  NetworkDeviceList,
  NetworkDeviceUpdate,
  NetworkInterfaceList,
  NetworkMacEntryList,
  NetworkNeighborList,
  NetworkPoll,
  NetworkPollList,
  NetworkVlanList,
  OperStatus,
  TopologyBuild,
  TopologyGraph,
  TopologyGraphQuery,
  TopologyLinkDetail,
  TopologyLinkList,
  TopologyNodeDetail,
  TopologyReviewRequest,
  TopologyStatus,
  PortKind,
  SnmpProfile,
  SnmpProfileCreate,
  SnmpProfileList,
  SnmpProfileRotate,
  SnmpProfileUpdate,
  Report,
  ReportCatalog,
  ReportList,
  ReportPreview,
  ReportRequest,
  ReportStatus,
  ArchivedFilter,
  AssetDeleteCheck,
  AssetReconcileResult,
  CleanupAction,
  CleanupExecuteAction,
  CleanupPreview,
  CleanupResult,
  DuplicateConfidence,
  LifecycleFilter,
  LifecycleSource,
  ReconcilePreview,
  DuplicateCandidateList,
  DuplicatePairList,
  FindingThreatIntel,
  IndicatorClassification,
  IndicatorDetail,
  IndicatorList,
  IntelConfidence,
  IntelTrust,
  ObservationType,
  ThreatImportPreview,
  ThreatImportResult,
  ThreatIntelOverview,
  ThreatMatchDetail,
  ThreatMatchList,
  ThreatMatchStatus,
  ThreatSource,
  ThreatSourceList,
  ThreatSyncList,
  AssetVulnerabilities,
  CatalogImportResult,
  CatalogList,
  CatalogPreview,
  EvaluateResult,
  ExposureOverview,
  ExposureState,
  FindingAction,
  FindingDetail,
  FindingHistory,
  FindingList,
  FindingSort,
  FindingStatus,
  MatchConfidence,
  MatchState,
  VulnSeverity,
  VulnerabilityOverview,
  AIStatus,
  LocalBenchmark,
  LocalHardware,
  LocalModel,
  LocalModelDetail,
  LocalModelList,
  LocalRuntimeKind,
  LocalRuntimeStatus,
  RecommendationList,
  RecommendationProfile,
  AIWindow,
  Agent,
  AgentList,
  Alert,
  AlertList,
  AlertRule,
  AlertSeverity,
  AlertStatus,
  Asset,
  AssetList,
  AssetStatus,
  AuditEventList,
  AuthState,
  ChangeCategory,
  ChangeList,
  ConsoleInfo,
  DetectionConfidence,
  DetectionDetail,
  DetectionList,
  DetectionRuleList,
  CompileStatus,
  HistoricalTestResult,
  RuleCatalog,
  RuleContentInput,
  RuleDefinition,
  RuleDetail,
  RuleDiff,
  RuleSort,
  RuleSource,
  RuleStatus,
  RuleTestResult,
  RuleValidation,
  RuleVersionDetail,
  RuleVersionList,
  SigmaImportResult,
  SigmaPreview,
  SigmaSource,
  SyntheticEventInput,
  DetectionSeverity,
  DetectionStatus,
  DiscoveryJobDetail,
  DiscoveryJobList,
  DiscoverySchedule,
  DiscoveryScope,
  EventLevel,
  EnrollmentToken,
  EnrollmentTokenCreated,
  EnrollmentTokenList,
  EnrollmentTokenRequest,
  EventList,
  Exposure,
  Readiness,
  DashboardSummary,
  Inventory,
  MonitoringMethod,
  Insight,
  InsightKind,
  InsightList,
  ProcessSnapshot,
  AssetCriticality,
  AssetContext,
  AssetContextHistory,
  AssetContextOptions,
  AssetContextUpdate,
  AssetEnvironment,
  AssetRole,
  AssetThreatSummary,
  NetworkZone,
  RiskAssetDetail,
  RiskAssetList,
  RiskConfidence,
  RiskContributionList,
  RiskHistory,
  RiskLevel,
  RiskOverview,
  RiskRange,
  Role,
  TelemetryHistory,
  User,
  UserList,
  AssignableUserList,
  IncidentAuditList,
  IncidentConfidence,
  IncidentDetail,
  IncidentEvidence,
  IncidentLevel,
  IncidentList,
  IncidentNote,
  IncidentNoteList,
  IncidentOverview,
  IncidentSort,
  IncidentStatus,
  IncidentTask,
  IncidentTimeline,
  RelatedIncidentList,
  ResolutionCategory,
  ExecutionStatus,
  Playbook,
  PlaybookList,
  PlaybookPreview,
  PlaybookRun,
  PlaybookRunList,
  PlaybookRunStatus,
  PlaybookStepInput,
  ResponseActionList,
  ResponseExecution,
  ResponseExecutionList,
  ResponsePreview,
  DiscoveryExecutionTarget,
  DiscoveryLimits,
  DiscoveryProfileCatalog,
  DiscoveryProfileName,
  DiscoveryTunableLimit,
  ObservationList,
  ObservationMethod,
  ObservationReachability,
  Sensor,
  SensorEnrollment,
  SensorEnrollmentCreated,
  SensorEnrollmentList,
  SensorJobList,
  SensorList,
  Site,
  SiteCreate,
  SiteList,
  SiteNetwork,
  SiteNetworkList,
  SiteUpdate,
  WlanAccessPointDetail,
  WlanAccessPointList,
  WlanAccessPointQuery,
  WlanAuthorizationUpdate,
  WlanBssList,
  WlanBssQuery,
  WlanBssRead,
  WlanClientList,
  WlanClientQuery,
  WlanLinkRequest,
  WlanObservationList,
  WlanOverview,
  WlanSsidList,
  WlanSsidQuery,
  WlanUnlinkRequest,
} from "./types";

export interface AlertQuery {
  /** Fase 5F: alcance de site (ausente = todos los sites). */
  siteId?: string;
  status?: AlertStatus;
  /** Open or acknowledged; ignored when `status` is set. */
  active?: boolean;
  severity?: AlertSeverity;
  rule?: AlertRule;
  assetId?: string;
  /** Text in the message or hostname. */
  q?: string;
  limit?: number;
  offset?: number;
}

export interface DetectionQuery {
  /** Fase 5F: alcance de site (ausente = todos los sites). */
  siteId?: string;
  status?: DetectionStatus;
  /** Abiertas o reconocidas; se ignora si se indica `status`. */
  active?: boolean;
  severity?: DetectionSeverity;
  confidence?: DetectionConfidence;
  ruleId?: string;
  assetId?: string;
  /** Rango (ISO) sobre la última actividad. */
  since?: string;
  until?: string;
  q?: string;
  limit?: number;
  offset?: number;
}

export type RiskSortKey = "score" | "changed_at" | "last_seen" | "name" | "criticality";

export interface RiskQuery {
  /** Fase 5F: alcance de site (ausente = todos los sites). */
  siteId?: string;
  level?: RiskLevel;
  confidence?: RiskConfidence;
  /** Un tipo de dispositivo o "unknown". */
  deviceType?: string;
  status?: AssetStatus;
  criticality?: AssetCriticality;
  q?: string;
  sort?: RiskSortKey;
  order?: "asc" | "desc";
  limit?: number;
  offset?: number;
}

export interface AssetQuery {
  /** Fase 5F: alcance de site (ausente = todos los sites). */
  siteId?: string;
  method?: MonitoringMethod;
  status?: AssetStatus;
  /** A device type, or "unknown". */
  deviceType?: string;
  /** CIDR, e.g. 192.168.1.0/24. */
  subnet?: string;
  q?: string;
  // Fase 4L: contexto. "unknown" incluye a los activos sin contexto guardado.
  criticality?: AssetCriticality;
  role?: AssetRole;
  environment?: AssetEnvironment;
  networkZone?: NetworkZone;
  /** "true", "false" o "unknown" (desconocido no es "no expuesto"). */
  internetExposed?: "true" | "false" | "unknown";
  department?: string;
  tag?: string;
  sort?: AssetSortKey;
  order?: "asc" | "desc";
  /** Fase 5C.1: archivados excluidos por defecto ("include" los muestra, "only" solo ellos). */
  archived?: ArchivedFilter;
  /** Fase 5C.2: solo inactivos ("stale" incluye también a los candidatos a limpieza). */
  lifecycle?: LifecycleFilter;
  /** Fase 4M: paginación en el servidor (por defecto 100, máximo 500). */
  limit?: number;
  offset?: number;
}

export type AssetSortKey =
  | "name"
  | "criticality"
  | "ip"
  | "type"
  | "status"
  | "method"
  | "first_seen"
  | "last_seen"
  | "network_seen"
  | "ports";

export interface EventQuery {
  assetId?: string;
  minLevel?: EventLevel;
  channel?: string;
  /** Fase 5C.1: origen (sshd, sudo, systemd, kernel...) y tipo normalizado (Linux). */
  provider?: string;
  eventType?: string;
  q?: string;
  limit?: number;
  offset?: number;
}

/** `?a=1&b=2` from the parameters that are set (unset, empty, 0 or false are left out), or "". */
function queryString(params: Record<string, string | number | boolean | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (typeof value === "string" ? value.trim() : value) search.set(key, String(value));
  }
  const query = search.toString();
  return query ? `?${query}` : "";
}

/** Filtros de GET /discovery/observations (Fase 6A); todos opcionales. */
export interface ObservationQuery {
  jobId?: string;
  siteId?: string;
  network?: string;
  sensorId?: string;
  executor?: DiscoveryExecutionTarget;
  method?: ObservationMethod;
  reachability?: ObservationReachability;
  q?: string;
  /** Solo la última observación por (site, IP). */
  latest?: boolean;
  limit?: number;
  offset?: number;
}

export const sentraApi = {
  // /health/ready answers 503 with a valid body when not ready; that is data, not a failure.
  readiness: (signal?: AbortSignal) =>
    apiGet<Readiness>("/health/ready", { signal, acceptStatuses: [503] }),
  dashboardSummary: (signal?: AbortSignal, siteId?: string) =>
    apiGet<DashboardSummary>(`/dashboard/summary${queryString({ site_id: siteId })}`, { signal }),
  listAssets: (signal?: AbortSignal, query: AssetQuery = {}) =>
    apiGet<AssetList>(
      `/assets${queryString({
        method: query.method,
        status: query.status,
        device_type: query.deviceType,
        subnet: query.subnet,
        q: query.q,
        criticality: query.criticality,
        role: query.role,
        environment: query.environment,
        network_zone: query.networkZone,
        internet_exposed: query.internetExposed,
        department: query.department,
        tag: query.tag,
        archived: query.archived === "exclude" ? undefined : query.archived,
        lifecycle: query.lifecycle,
        sort: query.sort,
        order: query.order,
        limit: query.limit,
        offset: query.offset,
        site_id: query.siteId,
      })}`,
      { signal },
    ),
  getAsset: (assetId: string, signal?: AbortSignal) =>
    apiGet<Asset>(`/assets/${encodeURIComponent(assetId)}`, { signal }),
  /** Corrección 6C: etiqueta personalizada (assets:manage). `label: null` la quita; `version`
   * es custom_label_version tal y como se leyó (409 asset_label_conflict si cambió). */
  setAssetLabel: (assetId: string, label: string | null, version: number) =>
    apiPatch<Asset>(`/assets/${encodeURIComponent(assetId)}/label`, { label, version }),
  getTelemetry: (assetId: string, limit: number, signal?: AbortSignal) =>
    apiGet<TelemetryHistory>(
      `/assets/${encodeURIComponent(assetId)}/telemetry${queryString({ limit })}`,
      { signal },
    ),
  getInventory: (assetId: string, signal?: AbortSignal) =>
    apiGet<Inventory>(`/assets/${encodeURIComponent(assetId)}/inventory`, { signal }),
  getProcesses: (assetId: string, signal?: AbortSignal) =>
    apiGet<ProcessSnapshot>(`/assets/${encodeURIComponent(assetId)}/processes`, { signal }),
  getChanges: (
    assetId: string,
    query: { category?: ChangeCategory; limit?: number; offset?: number },
    signal?: AbortSignal,
  ) =>
    apiGet<ChangeList>(
      `/assets/${encodeURIComponent(assetId)}/changes${queryString({ ...query })}`,
      { signal },
    ),
  listEvents: (
    { assetId, minLevel, channel, provider, eventType, q, limit, offset }: EventQuery,
    signal?: AbortSignal,
  ) =>
    apiGet<EventList>(
      `/events${queryString({
        asset_id: assetId,
        min_level: minLevel,
        channel,
        provider,
        event_type: eventType,
        q,
        limit,
        offset,
      })}`,
      { signal },
    ),
  listAlerts: (
    { status, active, severity, rule, assetId, q, limit, offset, siteId }: AlertQuery,
    signal?: AbortSignal,
  ) =>
    apiGet<AlertList>(
      `/alerts${queryString({ status, active, severity, rule, asset_id: assetId, q, limit, offset, site_id: siteId })}`,
      { signal },
    ),
  getExposure: (assetId: string, signal?: AbortSignal) =>
    apiGet<Exposure>(`/assets/${encodeURIComponent(assetId)}/exposure`, { signal }),
  discoveryScope: (signal?: AbortSignal) => apiGet<DiscoveryScope>("/discovery/scope", { signal }),
  discoveryJobs: (limit: number, signal?: AbortSignal, siteId?: string) =>
    apiGet<DiscoveryJobList>(`/discovery/jobs${queryString({ limit, site_id: siteId })}`, { signal }),
  discoveryJob: (jobId: string, signal?: AbortSignal) =>
    apiGet<DiscoveryJobDetail>(`/discovery/jobs/${encodeURIComponent(jobId)}`, { signal }),
  discoverySchedule: (signal?: AbortSignal) =>
    apiGet<DiscoverySchedule>("/discovery/schedule", { signal }),
  // Fase 6A: perfiles avanzados con sus límites efectivos (ya recortados a los topes).
  discoveryProfiles: (signal?: AbortSignal) =>
    apiGet<DiscoveryProfileCatalog>("/discovery/profiles", { signal }),
  // Observaciones paginadas y filtradas en el servidor: el navegador nunca carga todas.
  discoveryObservations: (params: ObservationQuery, signal?: AbortSignal) =>
    apiGet<ObservationList>(
      `/discovery/observations${queryString({
        job_id: params.jobId,
        site_id: params.siteId,
        network: params.network,
        sensor_id: params.sensorId,
        executor: params.executor,
        method: params.method,
        reachability: params.reachability,
        q: params.q,
        latest: params.latest,
        limit: params.limit,
        offset: params.offset,
      })}`,
      { signal },
    ),
  getAlert: (alertId: string, signal?: AbortSignal) =>
    apiGet<Alert>(`/alerts/${encodeURIComponent(alertId)}`, { signal }),
  listAgents: (signal?: AbortSignal, siteId?: string) =>
    apiGet<AgentList>(`/agents${queryString({ site_id: siteId })}`, { signal }),
  getAssetAgent: (assetId: string, signal?: AbortSignal) =>
    apiGet<Agent>(`/assets/${encodeURIComponent(assetId)}/agent`, { signal }),
};

/**
 * Gestión de agentes desde el dashboard (/console): la API exige sesión y el permiso
 * correspondiente (enrollment:manage, agents:manage, discovery:run). No hay ninguna clave de
 * administración en el frontend. El token de `createEnrollmentToken` solo existe en esa
 * respuesta: nunca se guarda ni se registra.
 */
export interface DiscoveryStartOptions {
  siteId?: string;
  executionTarget?: DiscoveryExecutionTarget;
  sensorId?: string;
  /** Fase 6A: sin perfil = descubrimiento básico; `ports` y `limits` exigen perfil. */
  profile?: DiscoveryProfileName;
  ports?: number[];
  limits?: Partial<Pick<DiscoveryLimits, DiscoveryTunableLimit>>;
}

export const consoleApi = {
  info: (signal?: AbortSignal) => apiGet<ConsoleInfo>("/console", { signal }),
  listEnrollmentTokens: (signal?: AbortSignal) =>
    apiGet<EnrollmentTokenList>("/console/enrollment-tokens", { signal }),
  createEnrollmentToken: (request: EnrollmentTokenRequest) =>
    apiPost<EnrollmentTokenCreated>("/console/enrollment-tokens", request),
  revokeEnrollmentToken: (tokenId: string) =>
    apiPost<EnrollmentToken>(`/console/enrollment-tokens/${encodeURIComponent(tokenId)}/revoke`),
  revokeAgent: (assetId: string) =>
    apiPost<Agent>(`/console/agents/${encodeURIComponent(assetId)}/revoke`),
  reinstateAgent: (assetId: string) =>
    apiPost<Agent>(`/console/agents/${encodeURIComponent(assetId)}/reinstate`),
  // Descubrimiento de red: el backend vuelve a validar el target contra
  // DISCOVERY_ALLOWED_NETWORKS; la lista del frontend es solo una comodidad.
  // Fase 5F: site y destino de ejecución (local solo en el site por defecto; sensor del mismo
  // site). Sin site_id el servidor usa el comportamiento histórico (local, site por defecto).
  startDiscovery: (target: string, options: DiscoveryStartOptions = {}) =>
    apiPost<DiscoveryJobDetail>("/console/discovery/jobs", {
      target,
      ...(options.siteId ? { site_id: options.siteId } : {}),
      ...(options.executionTarget ? { execution_target: options.executionTarget } : {}),
      ...(options.executionTarget === "sensor" && options.sensorId ? { sensor_id: options.sensorId } : {}),
      ...(options.profile ? { profile: options.profile } : {}),
      // Sin perfil no se envían opciones: el servidor respondería 422.
      ...(options.profile && options.ports?.length ? { ports: options.ports } : {}),
      ...(options.profile && options.limits && Object.keys(options.limits).length > 0
        ? { limits: options.limits }
        : {}),
    }),
  cancelDiscovery: (jobId: string) =>
    apiPost<DiscoveryJobDetail>(`/console/discovery/jobs/${encodeURIComponent(jobId)}/cancel`),
};

/**
 * Ciclo de vida de activos (Fase 5C.1). Archivar, restaurar, borrar y reconciliar: solo admin
 * (assets:manage; reconciliar además agents:manage). Duplicados: assets:duplicates_read.
 * Todas las escrituras llevan la `lifecycle_version` que la UI mostró (409 si cambió).
 */
export const lifecycleApi = {
  /** Sin `minConfidence` el servidor aplica su valor por defecto (medium). */
  duplicates: (signal?: AbortSignal, minConfidence?: DuplicateConfidence) =>
    apiGet<DuplicatePairList>(`/assets/duplicates${queryString({ min_confidence: minConfidence })}`, { signal }),
  candidates: (assetId: string, signal?: AbortSignal) =>
    apiGet<DuplicateCandidateList>(`/assets/${encodeURIComponent(assetId)}/duplicate-candidates`, { signal }),
  deleteCheck: (assetId: string, signal?: AbortSignal) =>
    apiGet<AssetDeleteCheck>(`/assets/${encodeURIComponent(assetId)}/delete-check`, { signal }),
  archive: (assetId: string, reason: string, version: number) =>
    apiPost<Asset>(`/assets/${encodeURIComponent(assetId)}/archive`, { reason, version }),
  restore: (assetId: string, version: number) =>
    apiPost<Asset>(`/assets/${encodeURIComponent(assetId)}/restore`, { version }),
  remove: (assetId: string, version: number) =>
    apiDelete<void>(`/assets/${encodeURIComponent(assetId)}${queryString({ version: String(version) })}`),
  /** Fase 5C.2: impacto de reconciliar `assetId` (SOURCE, agente nuevo) en `targetAssetId`. */
  reconcilePreview: (assetId: string, targetAssetId: string, signal?: AbortSignal) =>
    apiGet<ReconcilePreview>(
      `/assets/${encodeURIComponent(assetId)}/reconcile-preview${queryString({ target_asset_id: targetAssetId })}`,
      { signal },
    ),
  reconcile: (
    assetId: string,
    targetAssetId: string,
    version: number,
    targetVersion: number,
    acknowledgeWeakEvidence = false,
  ) =>
    apiPost<AssetReconcileResult>(`/assets/${encodeURIComponent(assetId)}/reconcile`, {
      target_asset_id: targetAssetId,
      version,
      target_version: targetVersion,
      acknowledge_weak_evidence: acknowledgeWeakEvidence,
    }),
  /** Fase 5C.2: vista previa de la limpieza (solo activos al menos stale; assets:manage). */
  cleanupPreview: (
    query: { action?: CleanupAction; source?: LifecycleSource; limit?: number; offset?: number },
    signal?: AbortSignal,
  ) =>
    apiGet<CleanupPreview>(
      `/assets/lifecycle/cleanup-preview${queryString({
        action: query.action,
        source: query.source,
        limit: query.limit,
        offset: query.offset,
      })}`,
      { signal },
    ),
  /** Ejecuta la limpieza por lotes; el servidor re-evalúa cada activo con la fila bloqueada. */
  cleanup: (action: CleanupExecuteAction, items: { asset_id: string; version: number }[], reason?: string) =>
    apiPost<CleanupResult>("/assets/lifecycle/cleanup", reason === undefined ? { action, items } : { action, items, reason }),
};

/** Acciones sobre alertas (permiso alerts:manage). */
export const alertsApi = {
  acknowledge: (alertId: string) =>
    apiPost<Alert>(`/alerts/${encodeURIComponent(alertId)}/acknowledge`),
  resolve: (alertId: string) => apiPost<Alert>(`/alerts/${encodeURIComponent(alertId)}/resolve`),
};

/** Detecciones del motor (Fase 4H). Leer: monitoring:read; gestionar: detections:manage. */
export const detectionsApi = {
  list: (query: DetectionQuery, signal?: AbortSignal) =>
    apiGet<DetectionList>(
      `/detections${queryString({
        status: query.status,
        active: query.active,
        severity: query.severity,
        confidence: query.confidence,
        rule_id: query.ruleId,
        asset_id: query.assetId,
        since: query.since,
        until: query.until,
        q: query.q,
        limit: query.limit,
        offset: query.offset,
        site_id: query.siteId,
      })}`,
      { signal },
    ),
  get: (detectionId: string, signal?: AbortSignal) =>
    apiGet<DetectionDetail>(`/detections/${encodeURIComponent(detectionId)}`, { signal }),
  rules: (signal?: AbortSignal) => apiGet<DetectionRuleList>("/detection-rules", { signal }),
  acknowledge: (detectionId: string) =>
    apiPost<DetectionDetail>(`/detections/${encodeURIComponent(detectionId)}/acknowledge`),
  resolve: (detectionId: string, note?: string) =>
    apiPost<DetectionDetail>(`/detections/${encodeURIComponent(detectionId)}/resolve`, {
      note: note?.trim() ? note.trim() : null,
    }),
};

export interface RuleQuery {
  source?: RuleSource;
  status?: RuleStatus;
  enabled?: boolean;
  compileStatus?: CompileStatus;
  severity?: DetectionSeverity;
  logsource?: string;
  mitre?: string;
  q?: string;
  sort?: RuleSort;
  order?: "asc" | "desc";
  limit?: number;
  offset?: number;
}

const rulePath = (ruleId: string) => `/detection-rules/${encodeURIComponent(ruleId)}`;

/**
 * Reglas de detección (Fase 5A). Leer: rules:read; validar/probar/vista previa Sigma:
 * rules:test; crear, editar, activar, importar y prueba histórica: rules:manage.
 */
export const rulesApi = {
  list: (query: RuleQuery, signal?: AbortSignal) =>
    apiGet<DetectionRuleList>(
      `/detection-rules${queryString({
        source: query.source,
        status: query.status,
        // queryString omite false: el filtro se manda como texto.
        enabled: query.enabled === undefined ? undefined : String(query.enabled),
        compile_status: query.compileStatus,
        severity: query.severity,
        logsource: query.logsource,
        mitre: query.mitre,
        q: query.q,
        sort: query.sort,
        order: query.order,
        limit: query.limit,
        offset: query.offset,
      })}`,
      { signal },
    ),
  catalog: (signal?: AbortSignal) => apiGet<RuleCatalog>("/detection-rules/catalog", { signal }),
  get: (ruleId: string, signal?: AbortSignal) => apiGet<RuleDetail>(rulePath(ruleId), { signal }),
  versions: (ruleId: string, signal?: AbortSignal) =>
    apiGet<RuleVersionList>(`${rulePath(ruleId)}/versions`, { signal }),
  version: (ruleId: string, version: number, signal?: AbortSignal) =>
    apiGet<RuleVersionDetail>(`${rulePath(ruleId)}/versions/${version}`, { signal }),
  diff: (ruleId: string, from: number, to: number, signal?: AbortSignal) =>
    apiGet<RuleDiff>(`${rulePath(ruleId)}/diff${queryString({ from, to })}`, { signal }),
  exportRule: (ruleId: string) => apiGet<Record<string, unknown>>(`${rulePath(ruleId)}/export`),
  sigmaSource: (ruleId: string, signal?: AbortSignal) =>
    apiGet<SigmaSource>(`${rulePath(ruleId)}/sigma-source`, { signal }),
  audit: (ruleId: string, signal?: AbortSignal) =>
    apiGet<AuditEventList>(`${rulePath(ruleId)}/audit${queryString({ limit: 50 })}`, { signal }),
  validate: (definition: RuleDefinition, extra: Partial<RuleContentInput> = {}) =>
    apiPost<RuleValidation>("/detection-rules/validate", {
      definition,
      category: extra.category ?? null,
      mitre_tactic: extra.mitre_tactic ?? null,
      mitre_technique: extra.mitre_technique ?? null,
      mitre_subtechnique: extra.mitre_subtechnique ?? null,
    }),
  test: (target: { definition: RuleDefinition } | { rule_id: string }, events: SyntheticEventInput[]) =>
    apiPost<RuleTestResult>("/detection-rules/test", { ...target, events }),
  testHistorical: (
    target: { definition: RuleDefinition } | { rule_id: string },
    range: { since?: string; until?: string; asset_id?: string },
  ) => apiPost<HistoricalTestResult>("/detection-rules/test/historical", { ...target, ...range }),
  create: (body: RuleContentInput) => apiPost<RuleDetail>("/detection-rules", body),
  update: (ruleId: string, body: Partial<RuleContentInput> & { revision: number; acknowledge_partial?: boolean }) =>
    apiPatch<RuleDetail>(rulePath(ruleId), body),
  setState: (
    ruleId: string,
    action: "enable" | "disable" | "retire" | "unretire",
    revision: number,
    acknowledgePartial = false,
  ) =>
    apiPost<RuleDetail>(`${rulePath(ruleId)}/${action}`, {
      revision,
      acknowledge_partial: acknowledgePartial,
    }),
  restore: (ruleId: string, version: number, revision: number) =>
    apiPost<RuleDetail>(`${rulePath(ruleId)}/versions/${version}/restore`, { revision }),
  sigmaPreview: (yaml: string) => apiPost<SigmaPreview>("/sigma/preview", { yaml }),
  sigmaImport: (yaml: string, update?: { revision: number }) =>
    apiPost<SigmaImportResult>("/sigma/import", {
      yaml,
      on_duplicate: update ? "update" : "reject",
      revision: update?.revision ?? null,
    }),
};

/** Risk Engine (Fase 4I): solo lectura salvo la criticidad del activo (admin). */
export const riskApi = {
  overview: (signal?: AbortSignal) => apiGet<RiskOverview>("/risk/overview", { signal }),
  list: (query: RiskQuery, signal?: AbortSignal) =>
    apiGet<RiskAssetList>(
      `/risk/assets${queryString({
        site_id: query.siteId,
        level: query.level,
        confidence: query.confidence,
        device_type: query.deviceType,
        status: query.status,
        criticality: query.criticality,
        q: query.q,
        sort: query.sort,
        order: query.order,
        limit: query.limit,
        offset: query.offset,
      })}`,
      { signal },
    ),
  get: (assetId: string, signal?: AbortSignal) =>
    apiGet<RiskAssetDetail>(`/risk/assets/${encodeURIComponent(assetId)}`, { signal }),
  history: (assetId: string, range: RiskRange, signal?: AbortSignal) =>
    apiGet<RiskHistory>(`/risk/assets/${encodeURIComponent(assetId)}/history${queryString({ range })}`, {
      signal,
    }),
  contributions: (assetId: string, snapshotId?: string, signal?: AbortSignal) =>
    apiGet<RiskContributionList>(
      `/risk/assets/${encodeURIComponent(assetId)}/contributions${queryString({ snapshot_id: snapshotId })}`,
      { signal },
    ),
  setCriticality: (assetId: string, criticality: AssetCriticality) =>
    apiPatch<RiskAssetDetail>(`/assets/${encodeURIComponent(assetId)}/criticality`, { criticality }),
};

/**
 * Asset Context (Fase 4L). Leer: cualquier rol. Editar: solo admin (assets:manage); el
 * backend lo exige igualmente. `update` envía la `version` leída: si otro admin cambió el
 * contexto entretanto responde 409 asset_context_conflict y la UI recarga, nunca pisa.
 */
export const assetContextApi = {
  get: (assetId: string, signal?: AbortSignal) =>
    apiGet<AssetContext>(`/assets/${encodeURIComponent(assetId)}/context`, { signal }),
  update: (assetId: string, body: AssetContextUpdate) =>
    apiPatch<AssetContext>(`/assets/${encodeURIComponent(assetId)}/context`, body),
  options: (signal?: AbortSignal) =>
    apiGet<AssetContextOptions>("/assets/context/options", { signal }),
  history: (assetId: string, signal?: AbortSignal) =>
    apiGet<AssetContextHistory>(
      `/assets/${encodeURIComponent(assetId)}/context/history${queryString({ limit: 20 })}`,
      { signal },
    ),
  threatSummary: (assetId: string, signal?: AbortSignal) =>
    apiGet<AssetThreatSummary>(`/assets/${encodeURIComponent(assetId)}/threat-summary`, {
      signal,
    }),
};

/**
 * Sesión del dashboard. La contraseña solo pasa por `login`/`changePassword` y no se guarda
 * en ningún sitio; la cookie de sesión la gestiona el navegador.
 */
export const authApi = {
  // skipUnauthorized: un 401 aquí es "credenciales incorrectas" o "sin sesión", no una
  // sesión que caduca a mitad de uso.
  login: (username: string, password: string) =>
    apiPost<AuthState>("/auth/login", { username, password }, { skipUnauthorized: true }),
  me: (signal?: AbortSignal) => apiGet<AuthState>("/auth/me", { signal, skipUnauthorized: true }),
  logout: () => apiPost<void>("/auth/logout", undefined, { skipUnauthorized: true }),
};

/** Administración de usuarios y auditoría (users:manage, audit:read: solo admin). */
export const usersApi = {
  list: (signal?: AbortSignal) => apiGet<UserList>("/users", { signal }),
  create: (username: string, password: string, role: Role) =>
    apiPost<User>("/users", { username, password, role }),
  update: (userId: string, change: { role?: Role; is_active?: boolean }) =>
    apiPatch<User>(`/users/${encodeURIComponent(userId)}`, change),
  resetPassword: (userId: string, newPassword: string) =>
    apiPost<User>(`/users/${encodeURIComponent(userId)}/password`, { new_password: newPassword }),
  revokeSessions: (userId: string) =>
    apiPost<User>(`/users/${encodeURIComponent(userId)}/sessions/revoke`),
  audit: (limit: number, signal?: AbortSignal) =>
    apiGet<AuditEventList>(`/audit?limit=${limit}`, { signal }),
};

/**
 * AI Security Insights (Fase 4J). Solo se envían la entidad y, en Ask, la pregunta: el
 * proveedor, la URL, el modelo y la clave son configuración exclusiva del servidor.
 */
export const aiApi = {
  status: (signal?: AbortSignal) => apiGet<AIStatus>("/ai/status", { signal }),
  ask: (question: string, scope: { assetId?: string; detectionId?: string } = {}, refresh = false) =>
    apiPost<Insight>("/ai/ask", {
      question,
      asset_id: scope.assetId ?? null,
      detection_id: scope.detectionId ?? null,
      refresh,
    }),
  analyzeAsset: (assetId: string, refresh = false) =>
    apiPost<Insight>(`/ai/assets/${encodeURIComponent(assetId)}/analyze`, { refresh }),
  analyzeDetection: (detectionId: string, refresh = false) =>
    apiPost<Insight>(`/ai/detections/${encodeURIComponent(detectionId)}/analyze`, { refresh }),
  analyzeRisk: (assetId: string, refresh = false) =>
    apiPost<Insight>(`/ai/risk/assets/${encodeURIComponent(assetId)}/analyze`, { refresh }),
  socSummary: (window: AIWindow, refresh = false) => apiPost<Insight>("/ai/soc/analyze", { window, refresh }),
  analyzeIncident: (incidentId: string, task: IncidentTask, refresh = false) =>
    apiPost<Insight>(`/ai/incidents/${encodeURIComponent(incidentId)}/analyze`, { task, refresh }),
  analyzeVulnerability: (findingId: string, refresh = false) =>
    apiPost<Insight>(`/ai/vulnerabilities/${encodeURIComponent(findingId)}/analyze`, { refresh }),
  list: (
    query: {
      kind?: InsightKind;
      assetId?: string;
      detectionId?: string;
      incidentId?: string;
      vulnerabilityFindingId?: string;
      limit?: number;
      offset?: number;
    },
    signal?: AbortSignal,
  ) =>
    apiGet<InsightList>(
      `/ai/insights${queryString({
        kind: query.kind,
        asset_id: query.assetId,
        detection_id: query.detectionId,
        incident_id: query.incidentId,
        vulnerability_finding_id: query.vulnerabilityFindingId,
        limit: query.limit,
        offset: query.offset,
      })}`,
      { signal },
    ),
  get: (insightId: string, signal?: AbortSignal) =>
    apiGet<Insight>(`/ai/insights/${encodeURIComponent(insightId)}`, { signal }),
};

/**
 * Gestor de modelos locales (Fase 4J.2). Las lecturas son para cualquier rol con ai:use; los
 * cambios exigen ai:manage (admin). Nunca se envían comandos ni URLs: como mucho la ruta de
 * un .gguf (el servidor la valida contra sus directorios de modelos permitidos) o el nombre de un modelo que
 * el runtime ya lista.
 */
export const localAiApi = {
  hardware: (signal?: AbortSignal) => apiGet<LocalHardware>("/ai/local/hardware", { signal }),
  refreshHardware: () => apiPost<LocalHardware>("/ai/local/hardware/refresh"),
  runtime: (signal?: AbortSignal) => apiGet<LocalRuntimeStatus>("/ai/local/runtime", { signal }),
  setRuntime: (runtime: LocalRuntimeKind) => apiPatch<LocalRuntimeStatus>("/ai/local/settings", { runtime }),
  models: (signal?: AbortSignal) => apiGet<LocalModelList>("/ai/local/models?limit=100", { signal }),
  model: (modelId: string, query: { profile?: RecommendationProfile; context?: number }, signal?: AbortSignal) =>
    apiGet<LocalModelDetail>(
      `/ai/local/models/${encodeURIComponent(modelId)}${queryString({ profile: query.profile, context: query.context })}`,
      { signal },
    ),
  registerPath: (path: string) => apiPost<LocalModel>("/ai/local/models/register", { path }),
  registerRuntimeModel: (runtimeModel: string) =>
    apiPost<LocalModel>("/ai/local/models/register", { runtime_model: runtimeModel }),
  select: (modelId: string) =>
    apiPost<LocalRuntimeStatus>(`/ai/local/models/${encodeURIComponent(modelId)}/select`),
  unregister: (modelId: string) => apiPost<void>(`/ai/local/models/${encodeURIComponent(modelId)}/unregister`),
  benchmark: (modelId: string) =>
    apiPost<LocalBenchmark>(`/ai/local/models/${encodeURIComponent(modelId)}/benchmark`),
  getBenchmark: (benchmarkId: string, signal?: AbortSignal) =>
    apiGet<LocalBenchmark>(`/ai/local/benchmarks/${encodeURIComponent(benchmarkId)}`, { signal }),
  cancelBenchmark: (benchmarkId: string) =>
    apiPost<LocalBenchmark>(`/ai/local/benchmarks/${encodeURIComponent(benchmarkId)}/cancel`),
  recommendations: (
    query: { profile: RecommendationProfile; context: number; includeCatalog?: boolean },
    signal?: AbortSignal,
  ) =>
    apiGet<RecommendationList>(
      `/ai/local/recommendations${queryString({
        profile: query.profile,
        context: query.context,
        include_catalog: query.includeCatalog === false ? "false" : undefined,
      })}`,
      { signal },
    ),
};

export interface IncidentQuery {
  /** Fase 5F: alcance de site (ausente = todos los sites). */
  siteId?: string;
  status?: IncidentStatus;
  /** Solo casos vivos (open, triage, investigating, contained); se ignora con `status`. */
  active?: boolean;
  severity?: IncidentLevel;
  priority?: IncidentLevel;
  /** "me", "unassigned" o el id de un usuario. */
  owner?: string;
  assetId?: string;
  /** INC-000123, título, hostname, IP o título de detección. */
  q?: string;
  sort?: IncidentSort;
  order?: "asc" | "desc";
  limit?: number;
  offset?: number;
}

export interface IncidentCreateInput {
  title: string;
  description?: string | null;
  severity: IncidentLevel;
  priority: IncidentLevel;
  confidence?: IncidentConfidence | null;
  asset_ids?: string[];
}

export interface IncidentChanges {
  title?: string;
  description?: string | null;
  severity?: IncidentLevel;
  priority?: IncidentLevel;
  confidence?: IncidentConfidence | null;
  status?: IncidentStatus;
}

const inc = (incidentId: string) => `/incidents/${encodeURIComponent(incidentId)}`;

/**
 * Gestión de incidentes (Fase 4K). Toda la lógica vive en el servidor: el navegador solo
 * envía referencias, texto del analista y la `version` que leyó (concurrencia optimista: si
 * otro operador cambió el caso, la API responde 409 incident_conflict).
 */
export const incidentsApi = {
  list: (query: IncidentQuery, signal?: AbortSignal) =>
    apiGet<IncidentList>(
      `/incidents${queryString({
        site_id: query.siteId,
        status: query.status,
        active: query.active,
        severity: query.severity,
        priority: query.priority,
        owner: query.owner,
        asset_id: query.assetId,
        q: query.q,
        sort: query.sort,
        order: query.order,
        limit: query.limit,
        offset: query.offset,
      })}`,
      { signal },
    ),
  overview: (signal?: AbortSignal) => apiGet<IncidentOverview>("/incidents/overview", { signal }),
  assignees: (signal?: AbortSignal) => apiGet<AssignableUserList>("/incidents/assignees", { signal }),
  get: (incidentId: string, signal?: AbortSignal) => apiGet<IncidentDetail>(inc(incidentId), { signal }),
  timeline: (incidentId: string, cursor?: string, signal?: AbortSignal) =>
    apiGet<IncidentTimeline>(`${inc(incidentId)}/timeline${queryString({ limit: 50, cursor })}`, { signal }),
  evidence: (incidentId: string, signal?: AbortSignal) =>
    apiGet<IncidentEvidence>(`${inc(incidentId)}/evidence`, { signal }),
  notes: (incidentId: string, offset = 0, signal?: AbortSignal) =>
    apiGet<IncidentNoteList>(`${inc(incidentId)}/notes${queryString({ limit: 50, offset })}`, { signal }),
  audit: (incidentId: string, offset = 0, signal?: AbortSignal) =>
    apiGet<IncidentAuditList>(`${inc(incidentId)}/audit${queryString({ limit: 50, offset })}`, { signal }),
  relatedToDetection: (detectionId: string, signal?: AbortSignal) =>
    apiGet<RelatedIncidentList>(`/detections/${encodeURIComponent(detectionId)}/related-incidents`, { signal }),
  relatedToAlert: (alertId: string, signal?: AbortSignal) =>
    apiGet<RelatedIncidentList>(`/alerts/${encodeURIComponent(alertId)}/related-incidents`, { signal }),
  create: (input: IncidentCreateInput) => apiPost<IncidentDetail>("/incidents", input),
  fromDetection: (detectionId: string, input: { title?: string; priority?: IncidentLevel } = {}) =>
    apiPost<IncidentDetail>(`/detections/${encodeURIComponent(detectionId)}/incident`, input),
  fromAlert: (alertId: string, input: { title?: string; priority?: IncidentLevel } = {}) =>
    apiPost<IncidentDetail>(`/alerts/${encodeURIComponent(alertId)}/incident`, input),
  update: (incidentId: string, version: number, changes: IncidentChanges) =>
    apiPatch<IncidentDetail>(inc(incidentId), { version, ...changes }),
  /** Sin `userId`: asignarse a uno mismo. */
  assign: (incidentId: string, version: number, userId?: string) =>
    apiPost<IncidentDetail>(`${inc(incidentId)}/assign`, { version, user_id: userId ?? null }),
  unassign: (incidentId: string, version: number) =>
    apiPost<IncidentDetail>(`${inc(incidentId)}/unassign`, { version }),
  addNote: (incidentId: string, body: string) => apiPost<IncidentNote>(`${inc(incidentId)}/notes`, { body }),
  resolve: (
    incidentId: string,
    version: number,
    input: { category: ResolutionCategory; summary?: string; duplicateOf?: string },
  ) =>
    apiPost<IncidentDetail>(`${inc(incidentId)}/resolve`, {
      version,
      category: input.category,
      summary: input.summary || null,
      duplicate_of: input.duplicateOf ?? null,
    }),
  close: (incidentId: string, version: number) => apiPost<IncidentDetail>(`${inc(incidentId)}/close`, { version }),
  reopen: (incidentId: string, version: number) => apiPost<IncidentDetail>(`${inc(incidentId)}/reopen`, { version }),
  /** Fusiona `incidentId` EN `targetId` (admin). */
  merge: (incidentId: string, version: number, targetId: string, targetVersion: number) =>
    apiPost<IncidentDetail>(`${inc(incidentId)}/merge`, {
      version,
      target_id: targetId,
      target_version: targetVersion,
    }),
  attachDetection: (incidentId: string, detectionId: string) =>
    apiPost<IncidentDetail>(`${inc(incidentId)}/detections/${encodeURIComponent(detectionId)}`),
  attachAlert: (incidentId: string, alertId: string) =>
    apiPost<IncidentDetail>(`${inc(incidentId)}/alerts/${encodeURIComponent(alertId)}`),
};

// --- Fase 5B: vulnerabilidades y exposición ------------------------------------------------------

export interface FindingQuery {
  /** Fase 5F: alcance de site (ausente = todos los sites). */
  siteId?: string;
  status?: FindingStatus;
  /** Solo los que necesitan trabajo (open, acknowledged, mitigating); se ignora con `status`. */
  active?: boolean;
  severity?: VulnSeverity;
  matchState?: MatchState;
  confidence?: MatchConfidence;
  exposure?: ExposureState;
  assetId?: string;
  vulnerabilityId?: string;
  source?: string;
  /** "true"/"false" como texto: queryString omite el booleano false. */
  stale?: "true" | "false";
  /** Fase 5C: solo explotación conocida reportada (KEV). */
  kev?: boolean;
  /** Fase 5C: EPSS mínimo (0-1). */
  epssMin?: number;
  intelStale?: boolean;
  q?: string;
  sort?: FindingSort;
  order?: "asc" | "desc";
  limit?: number;
  offset?: number;
}

export interface ExposureQuery {
  sensitive?: boolean;
  new?: boolean;
  withVulnerabilities?: boolean;
  assetId?: string;
  port?: number;
  limit?: number;
  offset?: number;
}

/** Datos opcionales de cada acción del flujo (el servidor valida cuáles exige). */
export interface FindingActionInput {
  reason?: string;
  overrideEvidence?: boolean;
  acceptedUntil?: string | null;
}

function finding(findingId: string): string {
  return `/vulnerabilities/findings/${encodeURIComponent(findingId)}`;
}

export const vulnerabilitiesApi = {
  overview: (signal?: AbortSignal) => apiGet<VulnerabilityOverview>("/vulnerabilities/overview", { signal }),
  list: (query: FindingQuery, signal?: AbortSignal) =>
    apiGet<FindingList>(
      `/vulnerabilities/findings${queryString({
        site_id: query.siteId,
        status: query.status,
        active: query.active,
        severity: query.severity,
        match_state: query.matchState,
        confidence: query.confidence,
        exposure: query.exposure,
        asset_id: query.assetId,
        vulnerability_id: query.vulnerabilityId,
        source: query.source,
        stale: query.stale,
        kev: query.kev,
        epss_min: query.epssMin,
        intel_stale: query.intelStale,
        q: query.q,
        sort: query.sort,
        order: query.order,
        limit: query.limit,
        offset: query.offset,
      })}`,
      { signal },
    ),
  get: (findingId: string, signal?: AbortSignal) => apiGet<FindingDetail>(finding(findingId), { signal }),
  threatIntel: (findingId: string, signal?: AbortSignal) =>
    apiGet<FindingThreatIntel>(`${finding(findingId)}/threat-intel`, { signal }),
  history: (findingId: string, signal?: AbortSignal) =>
    apiGet<FindingHistory>(`${finding(findingId)}/history${queryString({ limit: 100 })}`, { signal }),
  audit: (findingId: string, signal?: AbortSignal) =>
    apiGet<AuditEventList>(`${finding(findingId)}/audit${queryString({ limit: 50 })}`, { signal }),
  asset: (
    assetId: string,
    query: { active?: boolean; severity?: VulnSeverity; limit?: number; offset?: number } = {},
    signal?: AbortSignal,
  ) =>
    apiGet<AssetVulnerabilities>(
      `/assets/${encodeURIComponent(assetId)}/vulnerabilities${queryString({
        active: query.active,
        severity: query.severity,
        limit: query.limit,
        offset: query.offset,
      })}`,
      { signal },
    ),
  exposure: (query: ExposureQuery, signal?: AbortSignal) =>
    apiGet<ExposureOverview>(
      `/vulnerabilities/exposure${queryString({
        sensitive: query.sensitive,
        new: query.new,
        with_vulnerabilities: query.withVulnerabilities,
        asset_id: query.assetId,
        port: query.port,
        limit: query.limit,
        offset: query.offset,
      })}`,
      { signal },
    ),
  catalog: (
    query: { source?: string; severity?: VulnSeverity; q?: string; limit?: number; offset?: number },
    signal?: AbortSignal,
  ) =>
    apiGet<CatalogList>(
      `/vulnerabilities/catalog${queryString({
        source: query.source,
        severity: query.severity,
        q: query.q,
        limit: query.limit,
        offset: query.offset,
      })}`,
      { signal },
    ),
  catalogPreview: (content: string) => apiPost<CatalogPreview>("/vulnerabilities/catalog/preview", { content }),
  /** Importa exactamente lo previsualizado: si el contenido cambió, el servidor responde 409. */
  catalogImport: (content: string, expectedSha256: string, skipInvalid: boolean) =>
    apiPost<CatalogImportResult>("/vulnerabilities/catalog/import", {
      content,
      expected_sha256: expectedSha256,
      skip_invalid: skipInvalid,
    }),
  evaluate: (assetId?: string) =>
    apiPost<EvaluateResult>("/vulnerabilities/evaluate", { asset_id: assetId ?? null }),
  act: (findingId: string, action: FindingAction, version: number, input: FindingActionInput = {}) => {
    const body: Record<string, unknown> = { version, reason: input.reason?.trim() || null };
    if (action === "resolve") body.override_evidence = input.overrideEvidence ?? false;
    if (action === "accept-risk") body.accepted_until = input.acceptedUntil ?? null;
    return apiPost<FindingDetail>(`${finding(findingId)}/${action}`, body);
  },
  createIncident: (
    findingId: string,
    version: number,
    input: { title?: string; priority?: IncidentLevel } = {},
  ) =>
    apiPost<IncidentDetail>(`${finding(findingId)}/incident`, {
      version,
      title: input.title?.trim() || null,
      priority: input.priority ?? null,
    }),
};

// --- Fase 5C: Threat Intelligence -----------------------------------------------------------------

export interface IndicatorQuery {
  type?: string;
  classification?: IndicatorClassification;
  confidence?: IntelConfidence;
  state?: string;
  sourceId?: number;
  matched?: boolean;
  q?: string;
  sort?: string;
  order?: "asc" | "desc";
  limit?: number;
  offset?: number;
}

export interface ThreatMatchQuery {
  status?: ThreatMatchStatus;
  active?: boolean;
  classification?: IndicatorClassification;
  observationType?: ObservationType;
  assetId?: string;
  sourceId?: number;
  sort?: string;
  order?: "asc" | "desc";
  limit?: number;
  offset?: number;
}

function source(sourceId: number): string {
  return `/threat-intel/sources/${encodeURIComponent(String(sourceId))}`;
}

function threatMatch(matchId: string): string {
  return `/threat-intel/matches/${encodeURIComponent(matchId)}`;
}

export const threatIntelApi = {
  overview: (signal?: AbortSignal) => apiGet<ThreatIntelOverview>("/threat-intel/overview", { signal }),
  sources: (archived = false, signal?: AbortSignal) =>
    apiGet<ThreatSourceList>(`/threat-intel/sources${queryString({ archived })}`, { signal }),
  syncs: (sourceId: number, signal?: AbortSignal) =>
    apiGet<ThreatSyncList>(`${source(sourceId)}/syncs${queryString({ limit: 20 })}`, { signal }),
  createSource: (input: { source_key: string; name: string; description?: string | null; trust: IntelTrust }) =>
    apiPost<ThreatSource>("/threat-intel/sources", { ...input, provider: "local_import", category: "ioc" }),
  /** enable | disable | archive: con la revisión que vio el usuario (409 si cambió). */
  sourceAction: (sourceId: number, action: "enable" | "disable" | "archive", revision: number) =>
    apiPost<ThreatSource>(`${source(sourceId)}/${action}`, { revision }),
  /** Solo marca la petición: la descarga la hace el job del servidor. */
  requestSync: (sourceId: number) => apiPost<ThreatSource>(`${source(sourceId)}/sync`, {}),
  indicators: (query: IndicatorQuery, signal?: AbortSignal) =>
    apiGet<IndicatorList>(
      `/threat-intel/indicators${queryString({
        type: query.type,
        classification: query.classification,
        confidence: query.confidence,
        state: query.state,
        source_id: query.sourceId,
        matched: query.matched,
        q: query.q,
        sort: query.sort,
        order: query.order,
        limit: query.limit,
        offset: query.offset,
      })}`,
      { signal },
    ),
  indicator: (indicatorId: string, signal?: AbortSignal) =>
    apiGet<IndicatorDetail>(`/threat-intel/indicators/${encodeURIComponent(indicatorId)}`, { signal }),
  matches: (query: ThreatMatchQuery, signal?: AbortSignal) =>
    apiGet<ThreatMatchList>(
      `/threat-intel/matches${queryString({
        status: query.status,
        active: query.active,
        classification: query.classification,
        observation_type: query.observationType,
        asset_id: query.assetId,
        source_id: query.sourceId,
        sort: query.sort,
        order: query.order,
        limit: query.limit,
        offset: query.offset,
      })}`,
      { signal },
    ),
  match: (matchId: string, signal?: AbortSignal) => apiGet<ThreatMatchDetail>(threatMatch(matchId), { signal }),
  /** acknowledge (motivo opcional) | dismiss y reopen (motivo obligatorio). */
  matchAction: (matchId: string, action: "acknowledge" | "dismiss" | "reopen", version: number, reason?: string) =>
    apiPost<ThreatMatchDetail>(`${threatMatch(matchId)}/${action}`, { version, reason: reason?.trim() || null }),
  createIncident: (matchId: string, version: number, input: { title?: string; priority?: IncidentLevel } = {}) =>
    apiPost<IncidentDetail>(`${threatMatch(matchId)}/incident`, {
      version,
      title: input.title?.trim() || null,
      priority: input.priority ?? null,
    }),
  importPreview: (sourceId: number, format: "sentra-ioc" | "stix", content: string) =>
    apiPost<ThreatImportPreview>("/threat-intel/import/preview", { source_id: sourceId, format, content }),
  /** Importa exactamente lo previsualizado: si el contenido cambió, el servidor responde 409. */
  importConfirm: (
    sourceId: number,
    format: "sentra-ioc" | "stix",
    content: string,
    expectedSha256: string,
    skipInvalid: boolean,
  ) =>
    apiPost<ThreatImportResult>("/threat-intel/import", {
      source_id: sourceId,
      format,
      content,
      expected_sha256: expectedSha256,
      skip_invalid: skipInvalid,
    }),
  reevaluate: () => apiPost<{ indicators_queued: number }>("/threat-intel/reevaluate", {}),
};

// --- Fase 5D: Response Engine y Playbooks ---------------------------------------------------------

/**
 * Petición de ejecución: solo un `action_id` del catálogo y sus parámetros tipados. No existe
 * ningún campo de comando, script o ruta (el backend tampoco lo aceptaría).
 */
export interface ExecutionInput {
  action_id: string;
  target_type?: "asset" | "incident";
  target_id: string;
  parameters?: Record<string, unknown>;
  incident_id?: string | null;
  detection_id?: string | null;
  confirm?: boolean;
  reason?: string | null;
  /** Una por diálogo: repetir el envío devuelve la misma ejecución en vez de duplicarla. */
  idempotency_key?: string | null;
}

export interface PlaybookRunInput {
  target_id: string;
  incident_id?: string | null;
  detection_id?: string | null;
  confirm?: boolean;
  reason?: string | null;
  idempotency_key?: string | null;
}

export interface PlaybookInput {
  name: string;
  description?: string;
  steps: PlaybookStepInput[];
}

export interface ExecutionQuery {
  /** Fase 5F: alcance de site (ausente = todos los sites). */
  siteId?: string;
  status?: ExecutionStatus;
  actionId?: string;
  assetId?: string;
  incidentId?: string;
  runId?: string;
  limit?: number;
  offset?: number;
}

export interface RunQuery {
  status?: PlaybookRunStatus;
  assetId?: string;
  incidentId?: string;
  playbookId?: string;
  limit?: number;
  offset?: number;
}

const execution = (executionId: string) => `/response/executions/${encodeURIComponent(executionId)}`;
const playbook = (playbookId: string) => `/response/playbooks/${encodeURIComponent(playbookId)}`;
const playbookRun = (runId: string) => `/response/runs/${encodeURIComponent(runId)}`;

/**
 * Response Engine (Fase 5D). Los permisos se comprueban en el servidor en cada petición
 * (response:read/execute/manage más los de dominio de cada acción): ocultar un botón aquí es
 * solo UX. Cancelar y editar playbooks usan la `version`/`revision` leída (409 si cambió).
 */
export const responseApi = {
  actions: (assetId?: string, signal?: AbortSignal) =>
    apiGet<ResponseActionList>(`/response/actions${queryString({ asset_id: assetId })}`, { signal }),
  preview: (input: ExecutionInput) => apiPost<ResponsePreview>("/response/preview", input),
  execute: (input: ExecutionInput) => apiPost<ResponseExecution>("/response/executions", input),
  executions: (query: ExecutionQuery = {}, signal?: AbortSignal) =>
    apiGet<ResponseExecutionList>(
      `/response/executions${queryString({
        site_id: query.siteId,
        status: query.status,
        action_id: query.actionId,
        asset_id: query.assetId,
        incident_id: query.incidentId,
        run_id: query.runId,
        limit: query.limit,
        offset: query.offset,
      })}`,
      { signal },
    ),
  execution: (executionId: string, signal?: AbortSignal) =>
    apiGet<ResponseExecution>(execution(executionId), { signal }),
  cancelExecution: (executionId: string, version: number, reason?: string) =>
    apiPost<ResponseExecution>(`${execution(executionId)}/cancel`, { version, reason: reason?.trim() || null }),
  playbooks: (assetId?: string, signal?: AbortSignal) =>
    apiGet<PlaybookList>(`/response/playbooks${queryString({ asset_id: assetId })}`, { signal }),
  playbook: (playbookId: string, signal?: AbortSignal) => apiGet<Playbook>(playbook(playbookId), { signal }),
  createPlaybook: (input: PlaybookInput) => apiPost<Playbook>("/response/playbooks", input),
  /** Crea una versión nueva; las ejecuciones pasadas conservan la suya. */
  updatePlaybook: (playbookId: string, revision: number, input: PlaybookInput) =>
    apiPatch<Playbook>(playbook(playbookId), { revision, ...input }),
  setPlaybookEnabled: (playbookId: string, revision: number, enabled: boolean) =>
    apiPost<Playbook>(`${playbook(playbookId)}/${enabled ? "enable" : "disable"}`, { revision }),
  previewPlaybook: (playbookId: string, input: PlaybookRunInput) =>
    apiPost<PlaybookPreview>(`${playbook(playbookId)}/preview`, input),
  executePlaybook: (playbookId: string, input: PlaybookRunInput) =>
    apiPost<PlaybookRun>(`${playbook(playbookId)}/execute`, input),
  runs: (query: RunQuery = {}, signal?: AbortSignal) =>
    apiGet<PlaybookRunList>(
      `/response/runs${queryString({
        status: query.status,
        asset_id: query.assetId,
        incident_id: query.incidentId,
        playbook_id: query.playbookId,
        limit: query.limit,
        offset: query.offset,
      })}`,
      { signal },
    ),
  run: (runId: string, signal?: AbortSignal) => apiGet<PlaybookRun>(playbookRun(runId), { signal }),
  cancelRun: (runId: string, version: number, reason?: string) =>
    apiPost<PlaybookRun>(`${playbookRun(runId)}/cancel`, { version, reason: reason?.trim() || null }),
};

// --- Fase 5E: informes y exportación de evidencias ------------------------------------------

export interface ReportQuery {
  reportType?: string;
  status?: ReportStatus;
  requestedBy?: string;
  /** ISO 8601 (UTC). */
  createdFrom?: string;
  createdTo?: string;
  limit?: number;
  offset?: number;
}

const reportPath = (reportId: string) => `/reports/${encodeURIComponent(reportId)}`;

export const reportsApi = {
  catalog: (signal?: AbortSignal) => apiGet<ReportCatalog>("/reports/catalog", { signal }),
  /** Sin efectos: no crea informe ni fichero. */
  preview: (input: Omit<ReportRequest, "idempotency_key">) => apiPost<ReportPreview>("/reports/preview", input),
  /** 202: trabajo pending; la misma idempotency_key devuelve el mismo informe. */
  create: (input: ReportRequest & { idempotency_key: string }) => apiPost<Report>("/reports", input),
  list: (query: ReportQuery = {}, signal?: AbortSignal) =>
    apiGet<ReportList>(
      `/reports${queryString({
        report_type: query.reportType,
        status: query.status,
        requested_by: query.requestedBy,
        created_from: query.createdFrom,
        created_to: query.createdTo,
        limit: query.limit,
        offset: query.offset,
      })}`,
      { signal },
    ),
  get: (reportId: string, signal?: AbortSignal) => apiGet<Report>(reportPath(reportId), { signal }),
  cancel: (reportId: string) => apiPost<Report>(`${reportPath(reportId)}/cancel`, {}),
  /** Solo reports:admin: expira el informe y borra su artefacto. */
  remove: (reportId: string) => apiDelete<Report>(reportPath(reportId)),
  /** Artefacto binario; nunca se renderiza en la app, solo se guarda como fichero. */
  download: (reportId: string, signal?: AbortSignal) => apiDownload(`${reportPath(reportId)}/artifact`, { signal }),
};

// --- Fase 5F: sites y sensores distribuidos -------------------------------------------------

const sitePath = (siteId: string) => `/sites/${encodeURIComponent(siteId)}`;
const sensorPath = (sensorId: string) => `/sensors/${encodeURIComponent(sensorId)}`;

/**
 * Sites (Fase 5F). Lectura con monitoring:read; crear, editar, archivar y gestionar redes exige
 * sites:manage (el servidor lo comprueba en cada petición). Toda edición manda la `version`
 * leída: si otro admin cambió el site, 409 site_conflict y la UI recarga.
 */
export const sitesApi = {
  list: (signal?: AbortSignal) => apiGet<SiteList>("/sites", { signal }),
  get: (siteId: string, signal?: AbortSignal) => apiGet<Site>(sitePath(siteId), { signal }),
  create: (input: SiteCreate) => apiPost<Site>("/sites", input),
  update: (siteId: string, input: SiteUpdate) => apiPatch<Site>(sitePath(siteId), input),
  archive: (siteId: string, version: number, reason: string) =>
    apiPost<Site>(`${sitePath(siteId)}/archive`, { version, reason }),
  restore: (siteId: string, version: number) => apiPost<Site>(`${sitePath(siteId)}/restore`, { version }),
  remove: (siteId: string, version: number) =>
    apiDelete<void>(`${sitePath(siteId)}${queryString({ version: String(version) })}`),
  networks: (siteId: string, signal?: AbortSignal) =>
    apiGet<SiteNetworkList>(`${sitePath(siteId)}/networks`, { signal }),
  addNetwork: (siteId: string, input: { cidr: string; name?: string; enabled?: boolean }) =>
    apiPost<SiteNetwork>(`${sitePath(siteId)}/networks`, input),
  updateNetwork: (siteId: string, networkId: string, input: { name?: string; enabled?: boolean }) =>
    apiPatch<SiteNetwork>(`${sitePath(siteId)}/networks/${encodeURIComponent(networkId)}`, input),
  removeNetwork: (siteId: string, networkId: string) =>
    apiDelete<void>(`${sitePath(siteId)}/networks/${encodeURIComponent(networkId)}`),
};

/**
 * Sensores distribuidos (Fase 5F). El token de enrollment solo existe en la respuesta de
 * `createEnrollment`: nunca se guarda ni se registra. Las acciones exigen sensors:manage.
 */
export const sensorsApi = {
  list: (siteId?: string, signal?: AbortSignal) =>
    apiGet<SensorList>(`/sensors${queryString({ site_id: siteId })}`, { signal }),
  get: (sensorId: string, signal?: AbortSignal) => apiGet<Sensor>(sensorPath(sensorId), { signal }),
  jobs: (sensorId: string, limit = 20, signal?: AbortSignal) =>
    apiGet<SensorJobList>(`${sensorPath(sensorId)}/jobs${queryString({ limit })}`, { signal }),
  revoke: (sensorId: string, version: number, reason: string) =>
    apiPost<Sensor>(`${sensorPath(sensorId)}/revoke`, { version, reason }),
  disable: (sensorId: string, version: number) => apiPost<Sensor>(`${sensorPath(sensorId)}/disable`, { version }),
  enable: (sensorId: string, version: number) => apiPost<Sensor>(`${sensorPath(sensorId)}/enable`, { version }),
  rotateCredential: (sensorId: string, version: number) =>
    apiPost<Sensor>(`${sensorPath(sensorId)}/rotate-credential`, { version }),
  enrollments: (siteId?: string, signal?: AbortSignal) =>
    apiGet<SensorEnrollmentList>(`/sensors/enrollment-tokens${queryString({ site_id: siteId })}`, { signal }),
  createEnrollment: (input: { site_id: string; name: string; ttl_minutes?: number }) =>
    apiPost<SensorEnrollmentCreated>("/sensors/enrollment-tokens", input),
  revokeEnrollment: (enrollmentId: string) =>
    apiPost<SensorEnrollment>(`/sensors/enrollment-tokens/${encodeURIComponent(enrollmentId)}/revoke`),
};

/** Filtros de GET /network/devices (Fase 6B); todos opcionales. */
export interface NetworkDeviceQuery {
  siteId?: string;
  classification?: DeviceClassification;
  monitoringStatus?: MonitoringStatus;
  q?: string;
  includeArchived?: boolean;
  limit?: number;
  offset?: number;
}

export interface NetworkInterfaceQuery {
  operStatus?: OperStatus;
  portKind?: PortKind;
  q?: string;
  includeAbsent?: boolean;
  limit?: number;
  offset?: number;
}

export interface NetworkMacQuery {
  vlanId?: number;
  interfaceId?: string;
  mac?: string;
  includeAbsent?: boolean;
  limit?: number;
  offset?: number;
}

const snmpProfilePath = (profileId: string) => `/network/snmp-profiles/${encodeURIComponent(profileId)}`;
const networkDevicePath = (deviceId: string) => `/network/devices/${encodeURIComponent(deviceId)}`;

/**
 * Infraestructura de red: SNMP / LLDP / CDP (Fase 6B).
 *
 * Los secretos SNMP (passwords v3, comunidad v2c) solo viajan en el cuerpo de `create` y
 * `rotate`: nunca en la URL, nunca en otra petición y ninguna respuesta los devuelve.
 * Perfiles: snmp_credentials:manage. Equipos: monitoring:read (lectura), network:manage
 * (registro y edición) y network:poll (consultas). El servidor comprueba siempre el permiso.
 */
export const networkApi = {
  profiles: (siteId?: string, includeRevoked = false, signal?: AbortSignal) =>
    apiGet<SnmpProfileList>(
      `/network/snmp-profiles${queryString({ site_id: siteId, include_revoked: includeRevoked || undefined })}`,
      { signal },
    ),
  profile: (profileId: string, signal?: AbortSignal) => apiGet<SnmpProfile>(snmpProfilePath(profileId), { signal }),
  createProfile: (input: SnmpProfileCreate) => apiPost<SnmpProfile>("/network/snmp-profiles", input),
  updateProfile: (profileId: string, input: SnmpProfileUpdate) =>
    apiPatch<SnmpProfile>(snmpProfilePath(profileId), input),
  rotateProfile: (profileId: string, input: SnmpProfileRotate) =>
    apiPost<SnmpProfile>(`${snmpProfilePath(profileId)}/rotate`, input),
  revokeProfile: (profileId: string, version: number, reason: string) =>
    apiPost<SnmpProfile>(`${snmpProfilePath(profileId)}/revoke`, { version, reason }),

  devices: (query: NetworkDeviceQuery = {}, signal?: AbortSignal) =>
    apiGet<NetworkDeviceList>(
      `/network/devices${queryString({
        site_id: query.siteId,
        classification: query.classification,
        monitoring_status: query.monitoringStatus,
        q: query.q,
        include_archived: query.includeArchived || undefined,
        limit: query.limit,
        offset: query.offset,
      })}`,
      { signal },
    ),
  device: (deviceId: string, signal?: AbortSignal) => apiGet<NetworkDeviceDetail>(networkDevicePath(deviceId), { signal }),
  interfaces: (deviceId: string, query: NetworkInterfaceQuery = {}, signal?: AbortSignal) =>
    apiGet<NetworkInterfaceList>(
      `${networkDevicePath(deviceId)}/interfaces${queryString({
        oper_status: query.operStatus,
        port_kind: query.portKind,
        q: query.q,
        include_absent: query.includeAbsent || undefined,
        limit: query.limit,
        offset: query.offset,
      })}`,
      { signal },
    ),
  neighbors: (
    deviceId: string,
    query: { protocol?: NeighborProtocol; includeAbsent?: boolean; limit?: number; offset?: number } = {},
    signal?: AbortSignal,
  ) =>
    apiGet<NetworkNeighborList>(
      `${networkDevicePath(deviceId)}/neighbors${queryString({
        protocol: query.protocol,
        include_absent: query.includeAbsent || undefined,
        limit: query.limit,
        offset: query.offset,
      })}`,
      { signal },
    ),
  vlans: (deviceId: string, includeAbsent = false, signal?: AbortSignal) =>
    apiGet<NetworkVlanList>(
      `${networkDevicePath(deviceId)}/vlans${queryString({ include_absent: includeAbsent || undefined })}`,
      { signal },
    ),
  macEntries: (deviceId: string, query: NetworkMacQuery = {}, signal?: AbortSignal) =>
    apiGet<NetworkMacEntryList>(
      `${networkDevicePath(deviceId)}/mac-entries${queryString({
        vlan_id: query.vlanId,
        interface_id: query.interfaceId,
        mac: query.mac,
        include_absent: query.includeAbsent || undefined,
        limit: query.limit,
        offset: query.offset,
      })}`,
      { signal },
    ),
  polls: (deviceId: string, query: { limit?: number; offset?: number } = {}, signal?: AbortSignal) =>
    apiGet<NetworkPollList>(`${networkDevicePath(deviceId)}/polls${queryString({ ...query })}`, { signal }),
  macLocations: (mac: string, siteId?: string, signal?: AbortSignal) =>
    apiGet<MacLocationList>(`/network/mac-locations${queryString({ mac, site_id: siteId })}`, { signal }),
  candidates: (siteId?: string, limit?: number, signal?: AbortSignal) =>
    apiGet<NetworkCandidateList>(`/network/candidates${queryString({ site_id: siteId, limit })}`, { signal }),

  createDevice: (input: NetworkDeviceCreate) => apiPost<NetworkDevice>("/network/devices", input),
  updateDevice: (deviceId: string, input: NetworkDeviceUpdate) =>
    apiPatch<NetworkDevice>(networkDevicePath(deviceId), input),
  archiveDevice: (deviceId: string, version: number, reason?: string) =>
    apiPost<NetworkDevice>(`${networkDevicePath(deviceId)}/archive`, { version, ...(reason ? { reason } : {}) }),
  requestPoll: (deviceId: string) => apiPost<NetworkPoll>(`${networkDevicePath(deviceId)}/polls`),
  /** Fase 6D.4: consulta solo el módulo system para verificar SNMP con el perfil (network:poll). */
  compatibilityCheck: (deviceId: string) =>
    apiPost<NetworkPoll>(`${networkDevicePath(deviceId)}/compatibility-check`),
  /** Fase 6D.4: reanuda las consultas periódicas pausadas tras fallos (network:manage). */
  resumeMonitoring: (deviceId: string, version: number) =>
    apiPost<NetworkDeviceDetail>(`${networkDevicePath(deviceId)}/monitoring/resume`, { version }),
  cancelPoll: (pollId: string) => apiPost<NetworkPoll>(`/network/polls/${encodeURIComponent(pollId)}/cancel`),
};

// --- Fase 6C.3: inventario Wi-Fi / AP / WLAN ---------------------------------------------------

const wlanApPath = (accessPointId: string) => `/network/wlan/access-points/${encodeURIComponent(accessPointId)}`;
const wlanBssPath = (bssId: string) => `/network/wlan/bss/${encodeURIComponent(bssId)}`;

/** queryString omite `false`; un filtro booleano de tres estados necesita enviarlo como texto. */
function triState(value: boolean | undefined): string | undefined {
  return value === undefined ? undefined : String(value);
}

/**
 * Lectura con monitoring:read; autorizar, vincular y desvincular con network:manage. Ninguna
 * llamada actúa sobre la red: la API solo guarda la clasificación o el vínculo y lo audita.
 */
export const wlanApi = {
  overview: (siteId?: string, signal?: AbortSignal) =>
    apiGet<WlanOverview>(`/network/wlan/overview${queryString({ site_id: siteId })}`, { signal }),
  accessPoints: (query: WlanAccessPointQuery = {}, signal?: AbortSignal) =>
    apiGet<WlanAccessPointList>(
      `/network/wlan/access-points${queryString({
        site_id: query.siteId,
        ssid: query.ssid,
        band: query.band,
        status: query.status,
        authorization: query.authorization,
        freshness: query.freshness,
        present: triState(query.present),
        q: query.q,
        limit: query.limit,
        offset: query.offset,
      })}`,
      { signal },
    ),
  accessPoint: (accessPointId: string, signal?: AbortSignal) =>
    apiGet<WlanAccessPointDetail>(wlanApPath(accessPointId), { signal }),
  accessPointObservations: (
    accessPointId: string,
    query: { limit?: number; offset?: number } = {},
    signal?: AbortSignal,
  ) =>
    apiGet<WlanObservationList>(`${wlanApPath(accessPointId)}/observations${queryString({ ...query })}`, {
      signal,
    }),
  setAccessPointAuthorization: (accessPointId: string, input: WlanAuthorizationUpdate) =>
    apiPost<WlanAccessPointDetail>(`${wlanApPath(accessPointId)}/authorization`, input),
  linkAccessPoint: (accessPointId: string, input: WlanLinkRequest) =>
    apiPost<WlanAccessPointDetail>(`${wlanApPath(accessPointId)}/link`, input),
  unlinkAccessPoint: (accessPointId: string, input: WlanUnlinkRequest) =>
    apiPost<WlanAccessPointDetail>(`${wlanApPath(accessPointId)}/unlink`, input),

  bss: (query: WlanBssQuery = {}, signal?: AbortSignal) =>
    apiGet<WlanBssList>(
      `/network/wlan/bss${queryString({
        site_id: query.siteId,
        ssid: query.ssid,
        band: query.band,
        authorization: query.authorization,
        source: query.source,
        confidence: query.confidence,
        protection: query.protection,
        access_point_id: query.accessPointId,
        freshness: query.freshness,
        insecure: triState(query.insecure),
        limit: query.limit,
        offset: query.offset,
      })}`,
      { signal },
    ),
  bssDetail: (bssId: string, signal?: AbortSignal) => apiGet<WlanBssRead>(wlanBssPath(bssId), { signal }),
  bssObservations: (bssId: string, query: { limit?: number; offset?: number } = {}, signal?: AbortSignal) =>
    apiGet<WlanObservationList>(`${wlanBssPath(bssId)}/observations${queryString({ ...query })}`, { signal }),
  setBssAuthorization: (bssId: string, input: WlanAuthorizationUpdate) =>
    apiPost<WlanBssRead>(`${wlanBssPath(bssId)}/authorization`, input),

  ssids: (query: WlanSsidQuery = {}, signal?: AbortSignal) =>
    apiGet<WlanSsidList>(
      `/network/wlan/ssids${queryString({
        site_id: query.siteId,
        band: query.band,
        q: query.q,
        limit: query.limit,
        offset: query.offset,
      })}`,
      { signal },
    ),
  clients: (query: WlanClientQuery = {}, signal?: AbortSignal) =>
    apiGet<WlanClientList>(
      `/network/wlan/clients${queryString({
        site_id: query.siteId,
        ssid: query.ssid,
        bssid: query.bssid,
        access_point_id: query.accessPointId,
        identity: query.identity,
        state: query.state,
        present: triState(query.present),
        freshness: query.freshness,
        limit: query.limit,
        offset: query.offset,
      })}`,
      { signal },
    ),
};

// --- Fase 6D: topología de red -----------------------------------------------------------------

const topologyLinkPath = (linkId: string) => `/topology/links/${encodeURIComponent(linkId)}`;

/**
 * Lectura con monitoring:read; reconstruir y revisar enlaces con topology:manage (solo admin).
 * Ninguna llamada actúa sobre la red: el motor solo deriva enlaces de evidencia ya recogida.
 */
export const topologyApi = {
  graph: (query: TopologyGraphQuery = {}, signal?: AbortSignal) =>
    apiGet<TopologyGraph>(
      `/topology/graph${queryString({
        site_id: query.siteId,
        kinds: query.kinds?.length ? query.kinds.join(",") : undefined,
        include_absent: query.includeAbsent || undefined,
        include_rejected: query.includeRejected || undefined,
        device_type: query.deviceType,
        q: query.q?.trim().slice(0, 100),
      })}`,
      { signal },
    ),
  status: (siteId?: string, signal?: AbortSignal) =>
    apiGet<TopologyStatus>(`/topology/status${queryString({ site_id: siteId })}`, { signal }),
  links: (
    query: { siteId?: string; node?: string; present?: boolean; limit?: number; offset?: number } = {},
    signal?: AbortSignal,
  ) =>
    apiGet<TopologyLinkList>(
      `/topology/links${queryString({
        site_id: query.siteId,
        node: query.node,
        present: query.present === undefined ? undefined : String(query.present),
        limit: query.limit,
        offset: query.offset,
      })}`,
      { signal },
    ),
  link: (linkId: string, signal?: AbortSignal) => apiGet<TopologyLinkDetail>(topologyLinkPath(linkId), { signal }),
  // El nodo se resuelve dentro de un site: sin site_id el servidor usa el site por defecto.
  node: (nodeId: string, siteId?: string, signal?: AbortSignal) =>
    apiGet<TopologyNodeDetail>(
      `/topology/nodes/${encodeURIComponent(nodeId)}${queryString({ site_id: siteId })}`,
      { signal },
    ),
  rebuild: (siteId?: string) => apiPost<TopologyBuild>("/topology/rebuild", { site_id: siteId ?? null }),
  review: (linkId: string, input: TopologyReviewRequest) =>
    apiPatch<TopologyLinkDetail>(`${topologyLinkPath(linkId)}/review`, input),
};
