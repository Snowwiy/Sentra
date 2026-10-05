// Mirrors the response schemas in backend/app/schemas. Keep in sync with the API:
// backend/tests/test_frontend_contract.py fails when field names or enum values drift.

export type AssetStatus = "online" | "offline" | "unknown";

/** ISO 8601 timestamp in UTC, as serialized by the API. */
export type IsoDateTime = string;

export interface TelemetrySnapshot {
  recorded_at: IsoDateTime;
  cpu_percent: number;
  ram_percent: number;
  disk_percent: number;
  uptime_seconds: number;
}

/** DISCOVERED (network only) → MONITORED (agentless, reserved) → MANAGED (agent). */
export type MonitoringMethod = "discovered" | "agentless" | "agent";

/** Confianza de la identificación (Fase 4E). */
export type ClassificationConfidence = "low" | "medium" | "high";

/** Una evidencia de la identificación: fuente (agent_hostname, reverse_dns, mdns, ...) y valor. */
export interface ClassificationEvidence {
  source: string;
  value: string;
}

export interface Asset {
  asset_id: string;
  /** Nombre resuelto, hostname, DNS inverso o la IP: siempre presente (alertas, búsquedas). */
  display_name: string;
  monitoring_method: MonitoringMethod;
  /** Reported by the agent; null for assets only seen on the network. */
  hostname: string | null;
  os_name: string | null;
  os_version: string | null;
  architecture: string | null;
  primary_ip: string;
  agent_version: string | null;
  /** Agent liveness for agent assets, network status for the others. */
  status: AssetStatus;
  agent_status: AssetStatus | null;
  network_status: AssetStatus | null;
  first_seen_at: IsoDateTime;
  last_seen_at: IsoDateTime | null;
  created_at: IsoDateTime;
  updated_at: IsoDateTime;
  latest_telemetry: TelemetrySnapshot | null;
  mac_address: string | null;
  reverse_dns: string | null;
  /** Organización OUI de la MAC: fabricante de la NIC, no necesariamente del dispositivo. */
  vendor: string | null;
  /** Marca corta de la NIC ("Realtek"). */
  network_adapter_vendor: string | null;
  /** pc, laptop, server, mobile, tablet, console, printer, router, network_switch,
   * access_point, iot, voice_assistant, smart_tv, nas, virtual_machine; null = desconocido. */
  device_type: string | null;
  device_type_reason: string | null;
  /** Nombre resuelto por prioridad; null si nada lo nombra (la UI usa un texto de reserva). */
  device_name: string | null;
  name_source: string | null;
  device_vendor: string | null;
  device_model: string | null;
  /** SO deducido desde la red, sin versión; null con agente (ver os_name). */
  probable_os: string | null;
  classification_confidence: ClassificationConfidence | null;
  classification_evidence: ClassificationEvidence[];
  discovery_sources: string[];
  discovery_network: string | null;
  discovered_at: IsoDateTime | null;
  last_network_seen_at: IsoDateTime | null;
  /** Open TCP ports reachable from the Sentra server. */
  open_ports: number[];
  /** Fase 4I: criticidad (solo admin la cambia) y riesgo actual; null hasta el primer cálculo. */
  criticality: AssetCriticality;
  risk_score: number | null;
  risk_level: RiskLevel | null;
  risk_confidence: RiskConfidence | null;
}

export interface AssetList {
  items: Asset[];
  total: number;
}

export type CheckStatus = "ok" | "error";

export interface Health {
  status: "ok" | "degraded";
  version: string;
  checks: Record<string, CheckStatus>;
}

/** Error envelope returned by the API: {"error": {...}}. */
export interface ApiErrorBody {
  code: string;
  message: string;
  details?: unknown;
}

export interface TelemetryHistory {
  asset_id: string;
  /** Oldest first. */
  items: TelemetrySnapshot[];
}

export type AlertRule =
  | "asset_offline"
  | "high_cpu"
  | "high_ram"
  | "disk_critical"
  | "service_stopped"
  | "event_burst"
  | "admin_changed"
  | "critical_event"
  | "asset_discovered"
  | "unknown_device"
  | "asset_disappeared"
  | "port_exposed"
  | "port_closed"
  | "monitoring_lost"
  | "security_detection"
  | "risk_critical";
export type AlertSeverity = "info" | "warning" | "critical";
/** "acknowledged": seen by an operator, still active (not resolved). */
export type AlertStatus = "open" | "acknowledged" | "resolved";

export interface Alert {
  alert_id: string;
  asset_id: string;
  hostname: string;
  rule: AlertRule;
  severity: AlertSeverity;
  status: AlertStatus;
  message: string;
  value: number | null;
  /** Structured context: stopped services, changed accounts, the triggering event... */
  details: Record<string, unknown> | null;
  /** Times the condition fired while active (event-based rules count each event). */
  occurrences: number;
  last_triggered_at: IsoDateTime | null;
  /** Host event that triggered the alert, while it is still stored. */
  event_id: string | null;
  opened_at: IsoDateTime;
  acknowledged_at: IsoDateTime | null;
  resolved_at: IsoDateTime | null;
}

export interface AlertList {
  items: Alert[];
  total: number;
}

export interface NetworkInterface {
  name: string;
  mac: string | null;
  addresses: string[];
  is_up: boolean;
  speed_mbps: number | null;
}

export interface LoggedInUser {
  name: string;
  terminal: string | null;
  host: string | null;
  started_at: IsoDateTime | null;
}

export interface ProcessInfo {
  pid: number;
  name: string;
  username: string | null;
  memory_bytes: number;
  // Optional fields, sent by newer agents.
  exe?: string | null;
  ppid?: number | null;
  cpu_percent?: number | null;
  started_at?: IsoDateTime | null;
}

export interface ServiceInfo {
  name: string;
  display_name: string | null;
  status: string;
  start_type: string | null;
  pid?: number | null;
}

export interface SoftwareInfo {
  name: string;
  version: string | null;
  publisher: string | null;
  /** YYYY-MM-DD when the host records it. */
  install_date?: string | null;
  architecture?: string | null;
}

/** A local account: identity and state only, never secrets. */
export interface AccountInfo {
  name: string;
  /** null: unknown on this host. */
  enabled: boolean | null;
  is_admin: boolean | null;
  last_logon: IsoDateTime | null;
}

export interface NetworkSummary {
  gateways: string[];
  dns_servers: string[];
}

export interface DiskInfo {
  device: string;
  mountpoint: string;
  fstype: string | null;
  total_bytes: number;
  used_bytes: number;
  free_bytes: number;
  percent: number;
}

export interface NetworkConnection {
  protocol: "tcp" | "udp";
  local_address: string | null;
  local_port: number | null;
  remote_address: string | null;
  remote_port: number | null;
  status: "listen" | "established";
  pid: number | null;
  process_name: string | null;
}

export interface Inventory {
  asset_id: string;
  collected_at: IsoDateTime;
  received_at: IsoDateTime;
  interfaces: NetworkInterface[];
  users: LoggedInUser[];
  processes: ProcessInfo[];
  services: ServiceInfo[];
  software: SoftwareInfo[];
  // Older snapshots (before agents collected them) may lack these sections.
  disks?: DiskInfo[];
  connections?: NetworkConnection[];
  accounts?: AccountInfo[];
  network?: NetworkSummary | null;
}

/** One process of the latest process snapshot (refreshed every minute by the agent). */
export interface ProcessEntry {
  pid: number;
  ppid: number | null;
  name: string;
  exe: string | null;
  username: string | null;
  /** Share of the whole machine, 0-100. */
  cpu_percent: number | null;
  memory_bytes: number;
  started_at: IsoDateTime | null;
  status: string | null;
}

export interface ProcessSnapshot {
  asset_id: string;
  collected_at: IsoDateTime;
  received_at: IsoDateTime;
  processes: ProcessEntry[];
}

export type ChangeCategory = "service" | "software" | "account" | "exposure" | "network" | "identity";
export type ChangeKind =
  | "added"
  | "removed"
  | "started"
  | "stopped"
  | "start_type_changed"
  | "version_changed"
  | "enabled"
  | "disabled"
  | "admin_granted"
  | "admin_revoked"
  | "port_opened"
  | "port_closed"
  | "appeared"
  | "disappeared"
  | "reclassified";

/** A difference Sentra found between two inventory snapshots. */
export interface AssetChange {
  change_id: string;
  category: ChangeCategory;
  kind: ChangeKind;
  item: string;
  details: Record<string, unknown> | null;
  collected_at: IsoDateTime;
  detected_at: IsoDateTime;
}

export interface ChangeList {
  asset_id: string;
  items: AssetChange[];
  total: number;
  has_more: boolean;
}

export type EventLevel = "info" | "warning" | "error" | "critical";

export interface SystemEvent {
  event_id: string;
  asset_id: string;
  hostname: string;
  source: string;
  channel: string;
  event_code: number;
  provider: string;
  level: EventLevel;
  message: string;
  record_id: number;
  /** Host name recorded in the event (null for events from older agents). */
  computer: string | null;
  /** Campos estructurados del evento (Fase 4H); null en agentes anteriores. */
  data: Record<string, string> | null;
  occurred_at: IsoDateTime;
}

export interface EventList {
  items: SystemEvent[];
  /** Items in this page (event tables are not counted). */
  total: number;
  /** More events match after this page. */
  has_more: boolean;
}

// --- Network discovery -----------------------------------------------------------------------

export type DiscoveryJobStatus = "queued" | "running" | "completed" | "cancelled" | "failed";
export type DiscoveryTrigger = "manual" | "scheduled";
export type PortState = "open" | "closed";

/** Una red autorizada y cuántas direcciones sondearía un descubrimiento en ella. */
export interface DiscoveryNetwork {
  network: string;
  hosts: number;
}

export interface DiscoveryScope {
  enabled: boolean;
  allowed_networks: string[];
  /** Mismo orden que `allowed_networks`, con el tamaño real de cada una. */
  networks: DiscoveryNetwork[];
  max_hosts_per_network: number;
  excluded: string[];
  ports: number[];
  interval_minutes: number | null;
  icmp: boolean;
  reverse_dns: boolean;
  timeout_ms: number;
  concurrency: number;
  max_probes_per_second: number;
}

export interface DiscoveryJob {
  job_id: string;
  target: string;
  trigger: DiscoveryTrigger;
  status: DiscoveryJobStatus;
  /** First complete run of the network: records the baseline, raises no alerts. */
  baseline: boolean;
  started_at: IsoDateTime;
  completed_at: IsoDateTime | null;
  duration_seconds: number | null;
  hosts_scanned: number;
  hosts_alive: number;
  hosts_new: number;
  open_ports: number;
  probes: number;
  error_count: number;
  errors: string[];
  /** "dashboard", "cli" o "scheduler"; null en jobs anteriores a la Fase 4D. */
  requested_via: string | null;
  /** Direcciones a sondear: denominador exacto de la fase de liveness. */
  hosts_total: number;
  /** Activos ya conocidos vistos de nuevo; null hasta que el job termina. */
  hosts_updated: number | null;
  ports_opened: number;
  ports_closed: number;
  cancel_requested: boolean;
  /** operator, shutdown, timeout, interrupted o error cuando no fue un scan completo. */
  stop_reason: string | null;
  /** Solo mientras está en cola o en curso. */
  progress: DiscoveryProgress | null;
  parameters: Record<string, unknown> | null;
}

export interface DiscoveryProgress {
  /** queued, pending, liveness, details, done. Solo liveness tiene un total exacto. */
  phase: string;
  details_total: number;
  details_done: number;
}

export interface DiscoveryAssetRef {
  asset_id: string;
  display_name: string;
  primary_ip: string;
  mac_address: string | null;
  device_type: string | null;
  monitoring_method: MonitoringMethod;
}

export interface DiscoveryChange {
  asset_id: string;
  display_name: string;
  primary_ip: string;
  category: ChangeCategory;
  kind: ChangeKind;
  item: string;
  detected_at: IsoDateTime;
}

export interface DiscoveryJobDetail extends DiscoveryJob {
  new_assets: DiscoveryAssetRef[];
  changes: DiscoveryChange[];
}

export interface DiscoverySchedule {
  enabled: boolean;
  /** no_networks, no_interval o background_jobs_disabled. */
  disabled_reason: string | null;
  interval_minutes: number | null;
  last_run_at: IsoDateTime | null;
  last_run_status: DiscoveryJobStatus | null;
  next_run_at: IsoDateTime | null;
  running: boolean;
}

export interface DiscoveryJobList {
  items: DiscoveryJob[];
}

/** The agent's view of who listens on a port. */
export interface PortProcess {
  pid: number | null;
  name: string | null;
  exe: string | null;
  username: string | null;
  local_address: string | null;
}

export interface ExposedPort {
  protocol: string;
  port: number;
  state: PortState;
  /** IANA name for the port number: a hint, the service is never contacted. */
  service_hint: string | null;
  sensitive: boolean;
  first_seen_at: IsoDateTime;
  opened_at: IsoDateTime;
  last_seen_at: IsoDateTime;
  closed_at: IsoDateTime | null;
  process: PortProcess | null;
}

export interface AgentListener {
  protocol: string;
  port: number;
  process: PortProcess;
  /** true reachable, false probed and not reachable, null never probed. */
  exposed: boolean | null;
}

export interface Exposure {
  asset_id: string;
  baseline_at: IsoDateTime | null;
  last_network_seen_at: IsoDateTime | null;
  ports: ExposedPort[];
  agent_listeners: AgentListener[];
}

// --- Agent management (Agentes page) --------------------------------------------------------

export type AgentPlatform = "windows" | "linux" | "other";

/** active: valid own token · revoked: cut off by an operator · re_enrollment_required: no
 * valid token, must enroll again with a new one-time token. */
export type CredentialStatus = "active" | "revoked" | "re_enrollment_required";

/** An enrolled agent. Never contains a token, a hash or any secret. */
export interface Agent {
  asset_id: string;
  agent_id: string;
  display_name: string;
  hostname: string | null;
  primary_ip: string;
  os_name: string | null;
  os_version: string | null;
  architecture: string | null;
  platform: AgentPlatform;
  agent_version: string | null;
  /** Informado por el agente ("windows_service"…); null = no reportado. */
  installation_method: string | null;
  monitoring_method: MonitoringMethod;
  /** unknown = enrolled, never reported yet (Pending). */
  status: AssetStatus;
  credential_status: CredentialStatus;
  enrolled_at: IsoDateTime;
  credential_issued_at: IsoDateTime | null;
  revoked_at: IsoDateTime | null;
  last_seen_at: IsoDateTime | null;
}

export interface AgentSummary {
  total: number;
  online: number;
  offline: number;
  pending: number;
  revoked: number;
}

export interface AgentList {
  summary: AgentSummary;
  items: Agent[];
}

export type EnrollmentTokenState = "active" | "consumed" | "expired" | "revoked";

/** A one-time enrollment token as listed: never contains the token itself. */
export interface EnrollmentToken {
  token_id: string;
  state: EnrollmentTokenState;
  created_at: IsoDateTime;
  expires_at: IsoDateTime;
  consumed_at: IsoDateTime | null;
  revoked_at: IsoDateTime | null;
  last_used_at: IsoDateTime | null;
  max_uses: number;
  use_count: number;
  expected_platform: string | null;
  expected_hostname: string | null;
  note: string | null;
  created_via: string;
  last_asset_id: string | null;
}

/** Only the create response carries `token`, once. Keep it in memory only. */
export interface EnrollmentTokenCreated extends EnrollmentToken {
  token: string;
}

export interface EnrollmentTokenList {
  items: EnrollmentToken[];
}

export interface EnrollmentTokenRequest {
  ttl_minutes?: number;
  max_uses?: number;
  expected_platform?: "windows" | "linux";
  expected_hostname?: string;
  note?: string;
}

export interface ConsoleInfo {
  enrollment_token_ttl_minutes: number;
  suggested_server_urls: string[];
  server_url_configured: boolean;
}

// --- Fase 4G: autenticación, usuarios y auditoría ---------------------------------------

export type Role = "admin" | "analyst" | "viewer";

/** Permisos del backend (core/permissions.py); la UI decide qué mostrar con ellos. */
export type Permission =
  | "monitoring:read"
  | "alerts:manage"
  | "detections:manage"
  | "assets:manage"
  | "discovery:run"
  | "agents:manage"
  | "enrollment:manage"
  | "users:manage"
  | "audit:read"
  | "ai:use"
  | "ai:manage";

export interface CurrentUser {
  user_id: string;
  username: string;
  role: Role;
  last_login_at: string | null;
}

/** Respuesta de login y /auth/me. El ID de sesión nunca aparece aquí (cookie HttpOnly). */
export interface AuthState {
  user: CurrentUser;
  permissions: Permission[];
  /** Solo en memoria: se envía en X-CSRF-Token en las peticiones mutables. */
  csrf_token: string;
  session_expires_at: string;
}

export interface User {
  user_id: string;
  username: string;
  role: Role;
  is_active: boolean;
  created_at: string;
  updated_at: string;
  last_login_at: string | null;
  active_sessions: number;
}

export interface UserList {
  items: User[];
}

export interface AuditEvent {
  created_at: string;
  actor: string;
  action: string;
  target_type: string | null;
  target_id: string | null;
  result: string;
  client_ip: string | null;
  details: Record<string, unknown> | null;
}

export interface AuditEventList {
  items: AuditEvent[];
}

// --- Fase 4H: motor de detección ---------------------------------------------------------

/** Impacto si la detección es cierta. */
export type DetectionSeverity = "informational" | "low" | "medium" | "high" | "critical";
/** Cuánto respalda la evidencia la conclusión (independiente de la severidad). */
export type DetectionConfidence = "low" | "medium" | "high";
export type DetectionStatus = "open" | "acknowledged" | "resolved";

export interface Detection {
  detection_id: string;
  asset_id: string;
  hostname: string;
  rule_id: string;
  rule_version: number;
  /** "single" o "correlation". */
  kind: string;
  category: string;
  severity: DetectionSeverity;
  confidence: DetectionConfidence;
  status: DetectionStatus;
  title: string;
  /** Texto plano generado con plantillas (datos del host saneados). Nunca HTML. */
  summary: string;
  mitre_tactic: string | null;
  mitre_technique: string | null;
  mitre_subtechnique: string | null;
  occurrence_count: number;
  first_seen_at: IsoDateTime;
  last_seen_at: IsoDateTime;
  created_at: IsoDateTime;
  updated_at: IsoDateTime;
  acknowledged_at: IsoDateTime | null;
  acknowledged_by: string | null;
  resolved_at: IsoDateTime | null;
  resolved_by: string | null;
  resolution_note: string | null;
  alert_id: string | null;
}

export interface DetectionList {
  items: Detection[];
  total: number;
}

export interface DetectionEvidence {
  signal_kind: string;
  role: string | null;
  source_type: string;
  source_id: string | null;
  occurred_at: IsoDateTime;
  summary: string;
  data: Record<string, unknown> | null;
}

export interface DetectionDetail extends Detection {
  details: Record<string, unknown> | null;
  description: string;
  why: string;
  recommendations: string[];
  required_data: string[];
  evidence: DetectionEvidence[];
  evidence_total: number;
}

export interface DetectionRule {
  rule_id: string;
  version: number;
  kind: string;
  category: string;
  title: string;
  description: string;
  why: string;
  severity: DetectionSeverity;
  confidence: DetectionConfidence;
  triggers: string[];
  required_data: string[];
  recommendations: string[];
  mitre_tactic: string | null;
  mitre_technique: string | null;
  mitre_subtechnique: string | null;
  cooldown_minutes: number;
  enabled: boolean;
}

export interface DetectionRuleList {
  items: DetectionRule[];
  windows: Record<string, number>;
  alert_min_severity: DetectionSeverity | null;
}

// --- Fase 4I: Risk Engine ----------------------------------------------------------------

export type RiskLevel = "informational" | "low" | "medium" | "high" | "critical";
export type RiskConfidence = "low" | "medium" | "high";
export type AssetCriticality = "low" | "medium" | "high" | "critical";
export type RiskRange = "24h" | "7d" | "30d";

/** Una línea del ledger del riesgo: suma (o resta) puntos y explica por qué. */
export interface RiskContribution {
  /** detection, exposure, criticality, asset_type o saturation. */
  factor: string;
  category: string;
  /** Texto determinista del backend (nunca IA). */
  label: string;
  /** Negativo si reduce; 0 si quedó absorbida por otra (sin doble conteo). */
  points: number;
  nominal_points: number | null;
  detection_id: string | null;
  rule_id: string | null;
  port: number | null;
  details: Record<string, unknown>;
}

export interface RiskExplanationItem {
  label: string;
  points: number;
}

export interface ConfidenceFactor {
  effect: "+" | "-" | "=";
  label: string;
}

export interface RiskExplanation {
  /** "82 / Crítico — confianza baja". */
  headline: string;
  reasons: string[];
  increased: RiskExplanationItem[];
  reduced: RiskExplanationItem[];
  confidence_factors: ConfidenceFactor[];
}

export interface RiskAssetSummary {
  asset_id: string;
  display_name: string;
  device_name: string | null;
  primary_ip: string;
  device_type: string | null;
  monitoring_method: MonitoringMethod;
  status: AssetStatus;
  criticality: AssetCriticality;
  last_seen_at: IsoDateTime | null;
  /** false hasta el primer cálculo: score, level y confidence son null. */
  evaluated: boolean;
  score: number | null;
  level: RiskLevel | null;
  confidence: RiskConfidence | null;
  top_factor: string | null;
  calculated_at: IsoDateTime | null;
  changed_at: IsoDateTime | null;
}

export interface RiskAssetList {
  items: RiskAssetSummary[];
  total: number;
}

export interface RiskFactor {
  category: string;
  label: string;
  assets: number;
  points: number;
}

export interface RiskSnapshot {
  snapshot_id: string;
  calculated_at: IsoDateTime;
  score: number;
  level: RiskLevel;
  confidence: RiskConfidence;
  previous_score: number | null;
  previous_level: RiskLevel | null;
  transition: "up" | "down" | null;
  reason: string;
  top_factor: string | null;
}

export interface RiskTransition extends RiskSnapshot {
  asset_id: string;
  display_name: string;
}

export interface RiskLevelRange {
  level: RiskLevel;
  min: number;
  max: number;
}

export interface RiskOverview {
  total_assets: number;
  evaluated: number;
  pending: number;
  by_level: Record<RiskLevel, number>;
  by_confidence: Record<RiskConfidence, number>;
  top_factors: RiskFactor[];
  top_assets: RiskAssetSummary[];
  recent_transitions: RiskTransition[];
  thresholds: RiskLevelRange[];
  last_calculated_at: IsoDateTime | null;
}

export interface RiskDetectionRef {
  detection_id: string;
  rule_id: string;
  title: string;
  category: string;
  severity: DetectionSeverity;
  confidence: DetectionConfidence;
  status: DetectionStatus;
  occurrence_count: number;
  last_seen_at: IsoDateTime;
}

export interface RiskAssetDetail extends RiskAssetSummary {
  formula_version: number | null;
  pending_recalculation: boolean;
  explanation: RiskExplanation;
  contributions: RiskContribution[];
  active_detections: RiskDetectionRef[];
  active_detections_total: number;
  recent_changes: RiskSnapshot[];
  /** Score actual menos el de hace 24 h. */
  trend_24h: number | null;
  breakdown: Record<string, unknown> | null;
  thresholds: RiskLevelRange[];
}

export interface RiskHistory {
  asset_id: string;
  range: RiskRange;
  since: IsoDateTime;
  bucket_minutes: number | null;
  start_score: number | null;
  points: RiskSnapshot[];
  current_score: number | null;
  current_level: RiskLevel | null;
  calculated_at: IsoDateTime | null;
}

export interface RiskContributionList {
  asset_id: string;
  snapshot_id: string | null;
  calculated_at: IsoDateTime | null;
  score: number | null;
  items: RiskContribution[];
}

// --- Fase 4J: AI Security Insights ----------------------------------------------------------

export type InsightKind = "asset_summary" | "detection_analysis" | "risk_explanation" | "soc_summary" | "ask";
export type InsightScope = "asset" | "detection" | "fleet";
/** Vocabulario de certeza que exige el backend a cada hallazgo. */
export type Certainty = "observed" | "detected" | "correlated" | "possible" | "requires_validation";
export type AIWindow = "24h" | "7d" | "30d";

/** Referencia a un dato real de Sentra (validada por el backend; el modelo no inventa IDs). */
export interface EvidenceRef {
  ref: string;
  type: string;
  id: string;
  label: string;
  asset_id: string | null;
}

export interface InsightFinding {
  text: string;
  certainty: Certainty;
  evidence: string[];
}

export interface InsightAction {
  text: string;
  evidence: string[];
}

export interface InsightResult {
  summary: string;
  assessment: string;
  confidence_note: string;
  key_findings: InsightFinding[];
  recommended_actions: InsightAction[];
  evidence_refs: EvidenceRef[];
  limitations: string[];
  insufficient_data: boolean;
  warnings: string[];
  dropped_refs: number;
}

export interface Insight {
  insight_id: string;
  kind: InsightKind;
  scope: InsightScope;
  asset_id: string | null;
  asset_name: string | null;
  detection_id: string | null;
  risk_snapshot_id: string | null;
  question: string | null;
  provider: string;
  model: string;
  prompt_version: string;
  generated_at: string;
  expires_at: string;
  stale: boolean;
  stale_reason: "expired" | "data_changed" | "entity_deleted" | null;
  cached: boolean;
  evidence_count: number;
  context_items: number;
  latency_ms: number | null;
  requested_by: string;
  result: InsightResult;
}

export interface InsightList {
  items: Insight[];
  total: number;
}

/** Estado del proveedor de IA (4J.1): local/externo según la URL configurada, no el protocolo. */
export type AIProviderState =
  | "disabled"
  | "not_configured"
  | "local_available"
  | "local_unavailable"
  | "external_blocked"
  | "external_available"
  | "external_unavailable";

/** Estado de la IA. Nunca incluye la URL ni la clave del proveedor. */
export interface AIStatus {
  enabled: boolean;
  available: boolean;
  reason: string | null;
  state: AIProviderState;
  mode_label: "Local AI" | "External AI" | null;
  reachable: boolean | null;
  health_detail: string | null;
  health_latency_ms: number | null;
  checked_at: string | null;
  provider: string | null;
  model: string | null;
  location: "local" | "external" | null;
  external_allowed: boolean;
  redaction: string[];
  max_context_items: number;
  rate_limit_per_user_per_minute: number;
  prompt_versions: Record<string, string>;
}

// --- Fase 4J.2: gestor de modelos locales (backend/app/schemas/ai_local.py) ---

export type LocalRuntimeKind = "llama_cpp" | "ollama" | "vllm" | "openai_compatible";
export type ModelState =
  | "available"
  | "downloaded"
  | "registered"
  | "loaded"
  | "active"
  | "unavailable"
  | "incompatible";
export type CompatibilityStatus = "recommended" | "compatible" | "compatible_with_offload" | "slow" | "not_recommended";
export type RecommendationProfile = "low_resource" | "balanced" | "quality" | "max_speed" | "sentra";
export type SpeedClass = "fast" | "moderate" | "slow" | "unknown";
export type ModelPlacement = "full_gpu" | "partial_offload" | "cpu_only" | "does_not_fit" | "unknown";
export type PerformanceClass = "excellent" | "good" | "usable" | "slow";
export type BenchmarkStatus = "running" | "completed" | "failed" | "cancelled";
export type QualityLabel = "basic" | "medium" | "high" | "very_high";

export interface LocalCPU {
  model: string | null;
  physical_cores: number | null;
  logical_cores: number | null;
}

export interface LocalGPU {
  index: number;
  vendor: "nvidia" | "amd" | "intel" | "other";
  model: string | null;
  vram_total_bytes: number | null;
  vram_free_bytes: number | null;
  memory_kind: "dedicated" | "shared" | "unknown";
  source: string;
  driver: string | null;
}

export interface LocalHardware {
  os: string;
  os_version: string | null;
  architecture: string;
  cpu: LocalCPU;
  ram_total_bytes: number | null;
  ram_available_bytes: number | null;
  gpus: LocalGPU[];
  disk_free_bytes: number | null;
  disk_total_bytes: number | null;
  disk_scope: string;
  detected_at: string;
  duration_ms: number;
  warnings: string[];
}

export interface LocalRuntimeCapabilities {
  list_models: boolean;
  load_model: boolean;
  unload_model: boolean;
  benchmark: "runtime_timings" | "end_to_end";
  gpu_offload: boolean;
  multi_gpu_split: boolean;
  gguf_files: boolean;
  notes: string[];
}

export interface LocalActiveModel {
  model_id: string;
  name: string;
  runtime_model_id: string;
  quantization: string | null;
  parameter_count: number | null;
  selected_at: string | null;
}

export interface LocalRuntimeStatus {
  kind: LocalRuntimeKind;
  label: string;
  source: "settings" | "env";
  capabilities: LocalRuntimeCapabilities;
  available: boolean;
  reason: string | null;
  reachable: boolean | null;
  health_detail: string | null;
  health_latency_ms: number | null;
  version: string | null;
  detected_kind: LocalRuntimeKind | null;
  loaded_models: string[];
  configured_context: number | null;
  active_model: LocalActiveModel | null;
  effective_model: string | null;
  external_ai: "blocked" | "allowed";
  default_context_tokens: number;
  slots: "default"[];
}

export interface LocalBenchmark {
  benchmark_id: string;
  model_id: string;
  status: BenchmarkStatus;
  runtime: string;
  measurement: "runtime_timings" | "end_to_end" | null;
  max_tokens: number;
  configured_context: number | null;
  load_ms: number | null;
  ttft_ms: number | null;
  prompt_tokens: number | null;
  output_tokens: number | null;
  prompt_tps: number | null;
  generation_tps: number | null;
  peak_ram_bytes: number | null;
  peak_vram_bytes: number | null;
  performance_class: PerformanceClass | null;
  error: string | null;
  requested_by: string;
  started_at: string;
  finished_at: string | null;
}

export interface LocalModel {
  model_id: string;
  name: string;
  family: string | null;
  architecture: string | null;
  parameter_count: number | null;
  quantization: string | null;
  file_size_bytes: number | null;
  native_context: number | null;
  runtime: string;
  runtime_model_id: string;
  file_name: string | null;
  local_path: string | null;
  split_count: number;
  metadata_source: "gguf" | "runtime";
  source: string | null;
  license: string | null;
  checksum_sha256: string | null;
  checksum_status: "none" | "pending" | "ok" | "failed";
  installed_at: string;
  last_selected_at: string | null;
  state: ModelState;
  active: boolean;
  loaded: boolean | null;
  compatibility: CompatibilityStatus | null;
  recommended_for_sentra: boolean;
  latest_benchmark: LocalBenchmark | null;
}

export interface DiscoveredModel {
  kind: "file" | "runtime";
  name: string;
  file_name: string | null;
  path: string | null;
  size_bytes: number | null;
  runtime_model_id: string | null;
  state: "downloaded" | "loaded";
}

export interface LocalModelList {
  items: LocalModel[];
  total: number;
  discovered: DiscoveredModel[];
}

export interface ModelEstimate {
  weights_bytes: number | null;
  weights_source: "file" | "quantization_estimate" | null;
  kv_cache_bytes: number | null;
  overhead_bytes: number | null;
  total_bytes: number | null;
  context_tokens: number;
  kv_type: string;
  complete: boolean;
  missing: string[];
  placement: ModelPlacement;
  vram_bytes: number | null;
  ram_bytes: number | null;
  gpu_fraction: number | null;
  usable_vram_bytes: number;
  usable_ram_bytes: number | null;
  safety_margin_percent: number;
}

export interface ModelRecommendation {
  key: string;
  origin: "registered" | "catalog";
  model_id: string | null;
  catalog_id: string | null;
  name: string;
  family: string | null;
  parameter_count: number | null;
  quantization: string | null;
  native_context: number | null;
  license: string | null;
  source: string | null;
  status: CompatibilityStatus;
  quality: QualityLabel | null;
  speed: SpeedClass;
  speed_source: "estimate" | "benchmark";
  estimate: ModelEstimate;
  reasons: string[];
  warnings: string[];
  limitations: string[];
  recommended_for_sentra: boolean;
  score: number | null;
  observed_tps: number | null;
  performance_class: PerformanceClass | null;
}

export interface RecommendationList {
  profile: RecommendationProfile;
  context_tokens: number;
  runtime: LocalRuntimeKind;
  hardware_detected_at: string;
  items: ModelRecommendation[];
  total: number;
  sentra_pick: string | null;
  profile_pick: string | null;
}

export interface LocalModelDetail {
  model: LocalModel;
  evaluation: ModelRecommendation;
  benchmarks: LocalBenchmark[];
  runtime_notes: string[];
}
