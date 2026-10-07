import { apiGet, apiPatch, apiPost } from "./client";
import type {
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
} from "./types";

export interface AlertQuery {
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
  /** Text in the message or provider. */
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

export const sentraApi = {
  // /health/ready answers 503 with a valid body when not ready; that is data, not a failure.
  readiness: (signal?: AbortSignal) =>
    apiGet<Readiness>("/health/ready", { signal, acceptStatuses: [503] }),
  dashboardSummary: (signal?: AbortSignal) =>
    apiGet<DashboardSummary>("/dashboard/summary", { signal }),
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
        sort: query.sort,
        order: query.order,
        limit: query.limit,
        offset: query.offset,
      })}`,
      { signal },
    ),
  getAsset: (assetId: string, signal?: AbortSignal) =>
    apiGet<Asset>(`/assets/${encodeURIComponent(assetId)}`, { signal }),
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
  listEvents: ({ assetId, minLevel, channel, q, limit, offset }: EventQuery, signal?: AbortSignal) =>
    apiGet<EventList>(
      `/events${queryString({ asset_id: assetId, min_level: minLevel, channel, q, limit, offset })}`,
      { signal },
    ),
  listAlerts: (
    { status, active, severity, rule, assetId, q, limit, offset }: AlertQuery,
    signal?: AbortSignal,
  ) =>
    apiGet<AlertList>(
      `/alerts${queryString({ status, active, severity, rule, asset_id: assetId, q, limit, offset })}`,
      { signal },
    ),
  getExposure: (assetId: string, signal?: AbortSignal) =>
    apiGet<Exposure>(`/assets/${encodeURIComponent(assetId)}/exposure`, { signal }),
  discoveryScope: (signal?: AbortSignal) => apiGet<DiscoveryScope>("/discovery/scope", { signal }),
  discoveryJobs: (limit: number, signal?: AbortSignal) =>
    apiGet<DiscoveryJobList>(`/discovery/jobs${queryString({ limit })}`, { signal }),
  discoveryJob: (jobId: string, signal?: AbortSignal) =>
    apiGet<DiscoveryJobDetail>(`/discovery/jobs/${encodeURIComponent(jobId)}`, { signal }),
  discoverySchedule: (signal?: AbortSignal) =>
    apiGet<DiscoverySchedule>("/discovery/schedule", { signal }),
  getAlert: (alertId: string, signal?: AbortSignal) =>
    apiGet<Alert>(`/alerts/${encodeURIComponent(alertId)}`, { signal }),
  listAgents: (signal?: AbortSignal) => apiGet<AgentList>("/agents", { signal }),
  getAssetAgent: (assetId: string, signal?: AbortSignal) =>
    apiGet<Agent>(`/assets/${encodeURIComponent(assetId)}/agent`, { signal }),
};

/**
 * Gestión de agentes desde el dashboard (/console): la API exige sesión y el permiso
 * correspondiente (enrollment:manage, agents:manage, discovery:run). No hay ninguna clave de
 * administración en el frontend. El token de `createEnrollmentToken` solo existe en esa
 * respuesta: nunca se guarda ni se registra.
 */
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
  startDiscovery: (target: string) =>
    apiPost<DiscoveryJobDetail>("/console/discovery/jobs", { target }),
  cancelDiscovery: (jobId: string) =>
    apiPost<DiscoveryJobDetail>(`/console/discovery/jobs/${encodeURIComponent(jobId)}/cancel`),
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
