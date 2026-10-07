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
  /** Fase 4L: rol confirmado por un admin ("unknown" si nadie lo confirmó). */
  role: AssetRole;
  risk_score: number | null;
  risk_level: RiskLevel | null;
  risk_confidence: RiskConfidence | null;
}

// --- Asset Context (Fase 4L) ------------------------------------------------------------------

export type AssetRole =
  | "workstation"
  | "server"
  | "domain_controller"
  | "database"
  | "web_server"
  | "application_server"
  | "security_server"
  | "network_device"
  | "router"
  | "switch"
  | "firewall"
  | "wireless_ap"
  | "printer"
  | "iot"
  | "mobile"
  | "virtual_machine"
  | "container_host"
  | "unknown"
  | "other";
export type AssetEnvironment =
  | "production"
  | "staging"
  | "development"
  | "testing"
  | "lab"
  | "personal"
  | "unknown";
export type DataSensitivity = "unknown" | "public" | "internal" | "confidential" | "restricted";
export type NetworkZone =
  | "unknown"
  | "user"
  | "server"
  | "management"
  | "dmz"
  | "guest"
  | "iot"
  | "security"
  | "lab";
export type ManagedState = "DISCOVERED" | "MONITORED" | "MANAGED";
/** Configurado por una persona, observado por Sentra o inferido (sugerencia). */
export type ContextKind = "configured" | "observed" | "inferred";
export type ConfidenceLevel = "low" | "medium" | "high";

export interface FieldProvenance {
  /** manual hoy; agent, discovery, inferred y fuentes futuras usan la misma forma. */
  source: string;
  kind: ContextKind;
  /** Solo en datos inferidos: un dato manual nunca lleva confianza. */
  confidence: ConfidenceLevel | null;
  updated_at: IsoDateTime | null;
  updated_by: string | null;
}

export interface RoleSuggestion {
  value: AssetRole;
  source: string;
  kind: ContextKind;
  confidence: ConfidenceLevel | null;
  reason: string | null;
}

export interface ContextCompleteness {
  percent: number;
  complete: boolean;
  known: string[];
  missing: string[];
}

export interface AssetContext {
  asset_id: string;
  /** Token de concurrencia (0 = sin contexto guardado). */
  version: number;
  criticality: AssetCriticality;
  criticality_confirmed: boolean;
  criticality_rationale: string | null;
  criticality_updated_at: IsoDateTime | null;
  criticality_updated_by: string | null;
  role: AssetRole;
  role_suggestion: RoleSuggestion | null;
  environment: AssetEnvironment;
  owner: string | null;
  department: string | null;
  data_sensitivity: DataSensitivity;
  network_zone: NetworkZone;
  /** null = desconocido (no es "no expuesto"). */
  internet_exposed: boolean | null;
  tags: string[];
  managed_state: ManagedState;
  visibility_sources: string[];
  provenance: Record<string, FieldProvenance>;
  completeness: ContextCompleteness;
  updated_at: IsoDateTime | null;
  updated_by: string | null;
}

/** PATCH parcial: solo los campos presentes cambian. */
export interface AssetContextUpdate {
  version: number;
  criticality?: AssetCriticality;
  criticality_rationale?: string | null;
  role?: AssetRole;
  environment?: AssetEnvironment;
  owner?: string | null;
  department?: string | null;
  data_sensitivity?: DataSensitivity;
  network_zone?: NetworkZone;
  internet_exposed?: boolean | null;
  tags?: string[];
}

export interface AssetContextBrief {
  criticality: AssetCriticality;
  role: AssetRole;
  environment: AssetEnvironment;
  owner: string | null;
  department: string | null;
  data_sensitivity: DataSensitivity;
  network_zone: NetworkZone;
  internet_exposed: boolean | null;
  context_complete: boolean;
}

export interface AssetContextSnapshot {
  criticality: string | null;
  role: string | null;
  environment: string | null;
  data_sensitivity: string | null;
  network_zone: string | null;
  internet_exposed: boolean | null;
  captured_at: IsoDateTime | null;
}

export interface AssetContextChange {
  changed_at: IsoDateTime;
  field: string;
  old_value: string | null;
  new_value: string | null;
  source: string;
  actor: string;
}

export interface AssetContextHistory {
  items: AssetContextChange[];
  total: number;
}

export interface AssetContextOptions {
  criticality: AssetCriticality[];
  role: AssetRole[];
  environment: AssetEnvironment[];
  data_sensitivity: DataSensitivity[];
  network_zone: NetworkZone[];
  departments: string[];
  tags: string[];
  limits: ContextLimits;
}

export interface ContextLimits {
  owner_max: number;
  department_max: number;
  rationale_max: number;
  max_tags: number;
  tag_max: number;
  tag_pattern: string;
}

export interface ThreatRisk {
  score: number;
  level: RiskLevel;
  confidence: RiskConfidence;
  calculated_at: IsoDateTime | null;
}

export interface AssetThreatSummary {
  asset_id: string;
  window_days: number;
  active_detection_count: number;
  high_critical_detection_count: number;
  open_incident_count: number;
  highest_incident_severity: string | null;
  current_risk: ThreatRisk | null;
  recent_exposure_changes: number;
  recent_context_changes: number;
  last_security_activity: IsoDateTime | null;
  criticality: AssetCriticality;
  environment: AssetEnvironment;
  managed_state: ManagedState;
}

export interface AssetList {
  items: Asset[];
  /** Activos que cumplen los filtros (todas las páginas). */
  total: number;
  /** Fase 4M: la lista siempre llega paginada desde el servidor. */
  limit: number;
  offset: number;
  /** Recuento por estado con los demás filtros aplicados (tarjetas del dashboard). */
  status_counts: Record<AssetStatus, number>;
}

/** GET /dashboard/summary (Fase 4M): contadores agregados en SQL. */
export interface DashboardAssets {
  total: number;
  online: number;
  offline: number;
  unknown: number;
  by_method: Record<MonitoringMethod, number>;
  by_device_type: Record<string, number>;
}

export interface DashboardRisk {
  by_level: Record<string, number>;
  unscored: number;
}

export interface DashboardIncidents {
  active: number;
  critical: number;
  unassigned: number;
}

export interface DashboardDetections {
  active: number;
  by_severity: Record<string, number>;
}

/** Fase 5B: findings activos con evidencia (confirmed/probable); potenciales aparte. */
export interface DashboardVulnerabilities {
  by_severity: Record<string, number>;
  potential: number;
  assets_affected: number;
}

export interface DashboardSummary {
  generated_at: string;
  assets: DashboardAssets;
  risk: DashboardRisk;
  /** null si el rol no puede leer incidentes. */
  incidents: DashboardIncidents | null;
  detections: DashboardDetections;
  active_alerts: number;
  /** null si el rol no puede leer vulnerabilidades (vulnerabilities:read). */
  vulnerabilities?: DashboardVulnerabilities | null;
}

export type CheckStatus = "ok" | "error";

/** GET /health/ready (Fase 4M): solo ok/error por dependencia, sin versiones ni hosts. */
export interface Readiness {
  status: "ready" | "not_ready";
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
  | "risk_critical"
  | "vulnerability";
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
  /** Fase 5B (agentes nuevos): origen del software y secciones que fallaron al recogerse. */
  software_source?: "windows_registry" | "dpkg" | "rpm" | null;
  incomplete_sections?: string[] | null;
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
  | "ai:manage"
  | "incidents:read"
  | "incidents:manage"
  | "incidents:admin"
  | "rules:read"
  | "rules:test"
  | "rules:manage"
  | "vulnerabilities:read"
  | "vulnerabilities:manage"
  | "vulnerabilities:admin"
  | "threat_intel:read"
  | "threat_intel:triage"
  | "threat_intel:manage";

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
  /** Fase 4M: la versión solo se muestra con sesión (ya no está en /health, público). */
  server_version: string;
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
  /** Fase 5A: builtin | custom | sigma. */
  rule_source: RuleSource;
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
  /** Fase 4L: impacto de negocio del activo, independiente de la severidad de la regla. */
  asset_context: AssetContextBrief | null;
}

// --- Fase 5A: reglas personalizadas e importación Sigma ------------------------------------

export type RuleSource = "builtin" | "custom" | "sigma";
export type RuleStatus = "draft" | "active" | "disabled" | "retired";
export type CompileStatus = "valid" | "partial" | "unsupported" | "invalid";
export type RuleSort = "title" | "updated_at" | "last_triggered" | "severity" | "source";
export type RuleComplexity = "low" | "medium" | "high";

export interface RuleIssue {
  code: string;
  /** Mensaje técnico del compilador (texto plano). */
  message: string;
  path: string;
}

export interface RuleStats {
  evaluations: number;
  matches: number;
  errors: number;
  consecutive_errors: number;
  slow_evaluations: number;
  avg_eval_ms: number | null;
  last_evaluated_at: IsoDateTime | null;
  last_matched_at: IsoDateTime | null;
  last_error_at: IsoDateTime | null;
  /** Tipo de error, nunca datos del evento. */
  last_error: string | null;
}

/** Una regla del catálogo unificado (built-in, custom o Sigma). */
export interface DetectionRule {
  rule_id: string;
  source: RuleSource;
  version: number;
  status: RuleStatus;
  enabled: boolean;
  compile_status: CompileStatus;
  /** Built-in: solo lectura (se gestionan con DETECTION_DISABLED_RULES en el servidor). */
  read_only: boolean;
  kind: string;
  category: string;
  title: string;
  description: string;
  why: string;
  severity: DetectionSeverity;
  confidence: DetectionConfidence;
  logsource: string | null;
  triggers: string[];
  required_data: string[];
  recommendations: string[];
  mitre_tactic: string | null;
  mitre_technique: string | null;
  mitre_subtechnique: string | null;
  cooldown_minutes: number;
  sigma_id: string | null;
  /** Concurrencia optimista: se envía en cada cambio (409 si otro admin cambió la regla). */
  revision: number | null;
  updated_at: IsoDateTime | null;
  updated_by: string | null;
  detections_24h: number;
  last_triggered_at: IsoDateTime | null;
  errors: number;
  consecutive_errors: number;
}

export interface DetectionRuleList {
  items: DetectionRule[];
  total: number;
  windows: Record<string, number>;
  alert_min_severity: DetectionSeverity | null;
}

export interface RuleDetail extends DetectionRule {
  tags: string[];
  /** JSON declarativo sentra-rule/1 (null en built-in: viven en código). */
  definition: RuleDefinition | null;
  compiled: Record<string, unknown> | null;
  compile_issues: RuleIssue[];
  complexity: RuleComplexity | null;
  stats: RuleStats;
  detections_total: number;
  sigma_metadata: Record<string, unknown> | null;
  has_sigma_source: boolean;
  created_at: IsoDateTime | null;
  created_by: string | null;
  retired_at: IsoDateTime | null;
  logsource_title: string | null;
}

export interface RuleVersion {
  version: number;
  created_at: IsoDateTime;
  created_by: string;
  change_note: string;
  compile_status: CompileStatus;
  title: string;
  severity: DetectionSeverity;
  confidence: DetectionConfidence;
  current: boolean;
}

export interface RuleVersionList {
  items: RuleVersion[];
}

export interface RuleVersionDetail extends RuleVersion {
  description: string;
  why: string;
  recommendations: string[];
  category: string;
  mitre_tactic: string | null;
  mitre_technique: string | null;
  mitre_subtechnique: string | null;
  tags: string[];
  definition: RuleDefinition;
  compiled: Record<string, unknown>;
  compile_issues: RuleIssue[];
  content_hash: string;
}

export interface RuleChange {
  field: string;
  before: unknown;
  after: unknown;
}

export interface RuleDiff {
  rule_id: string;
  from_version: number;
  to_version: number;
  changes: RuleChange[];
}

export type RuleOperator =
  | "equals"
  | "not_equals"
  | "contains"
  | "starts_with"
  | "ends_with"
  | "in"
  | "regex"
  | "exists"
  | "gt"
  | "gte"
  | "lt"
  | "lte";

export type RuleScalar = string | number | boolean;

export interface RuleLeaf {
  field: string;
  op: RuleOperator;
  value: RuleScalar | RuleScalar[];
  case_sensitive?: boolean;
}

export type RuleNode = RuleLeaf | { all: RuleNode[] } | { any: RuleNode[] } | { not: RuleNode };

/** Formato declarativo sentra-rule/1. Nunca código: el backend lo valida con allowlist. */
export interface RuleDefinition {
  format?: string;
  logsource: string;
  condition: RuleNode;
  threshold?: { count: number; window_minutes: number } | null;
  group_by?: string[];
  cooldown_minutes?: number;
}

export interface RuleContentInput {
  title: string;
  description: string;
  why: string;
  recommendations: string[];
  severity: DetectionSeverity;
  confidence: DetectionConfidence;
  category: string | null;
  mitre_tactic: string | null;
  mitre_technique: string | null;
  mitre_subtechnique: string | null;
  tags: string[];
  definition: RuleDefinition;
}

export interface RuleValidation {
  valid: boolean;
  compile_status: CompileStatus;
  errors: RuleIssue[];
  warnings: RuleIssue[];
  definition: Record<string, unknown> | null;
  compiled: Record<string, unknown> | null;
  complexity: RuleComplexity | null;
}

export interface SyntheticEventInput {
  fields: Record<string, string | number | boolean | null>;
  occurred_at?: string | null;
}

export interface EventTestResult {
  index: number;
  matched: boolean;
  group: string | null;
  missing_fields: string[];
}

export interface SimulatedDetection {
  group: string;
  count: number;
  first_at: IsoDateTime;
  last_at: IsoDateTime;
}

export interface RuleTestResult {
  matched: number;
  events: EventTestResult[];
  would_detect: SimulatedDetection[];
  threshold: number | null;
  window_minutes: number | null;
  duration_ms: number;
}

export interface HistoricalMatch {
  occurred_at: IsoDateTime;
  asset_id: string;
  hostname: string;
  source_id: string | null;
  summary: string;
  fields: Record<string, unknown>;
}

export interface HistoricalGroup {
  asset_id: string;
  hostname: string;
  group: string;
  max_count: number;
  first_at: IsoDateTime;
}

export interface HistoricalTestResult {
  data_source: string;
  since: IsoDateTime;
  until: IsoDateTime;
  scanned: number;
  matched: number;
  truncated: boolean;
  sample: HistoricalMatch[];
  would_detect: HistoricalGroup[];
  threshold: number | null;
  duration_ms: number;
  notes: string[];
}

export interface SigmaSource {
  rule_id: string;
  /** YAML original: se muestra como texto, nunca se interpreta. */
  yaml: string;
}

export interface SigmaDuplicate {
  /** none | identical | changed | retired */
  state: string;
  rule_id: string | null;
  current_version: number | null;
  revision: number | null;
}

export interface SigmaPreview {
  /** supported | partial | unsupported | invalid */
  outcome: string;
  title: string;
  sigma_id: string | null;
  level: string | null;
  severity: DetectionSeverity;
  confidence: DetectionConfidence;
  logsource: Record<string, string>;
  sentra_logsource: string | null;
  mitre_tactic: string | null;
  mitre_technique: string | null;
  mitre_subtechnique: string | null;
  tags: string[];
  metadata: Record<string, unknown>;
  errors: RuleIssue[];
  unsupported: RuleIssue[];
  warnings: RuleIssue[];
  definition: Record<string, unknown> | null;
  compiled: Record<string, unknown> | null;
  duplicate: SigmaDuplicate;
}

export interface SigmaImportResult {
  /** imported | imported_with_warnings | updated | unchanged | unsupported | rejected */
  result: string;
  rule: RuleDetail | null;
  preview: SigmaPreview;
}

export interface RuleField {
  name: string;
  /** string | integer | boolean */
  type: string;
  description: string;
  values: string[];
  operators: RuleOperator[];
}

export interface RuleLogSource {
  name: string;
  title: string;
  support: string;
  platforms: string[];
  notes: string;
  event_codes: number[];
  sigma_hint: string;
  default_category: string;
  fields: RuleField[];
}

export interface RuleCompatibility {
  area: string;
  support: string;
  notes: string;
  logsources: string[];
}

export interface RuleCatalog {
  logsources: RuleLogSource[];
  asset_fields: RuleField[];
  categories: string[];
  limits: Record<string, number>;
  compatibility: RuleCompatibility[];
  sigma_default_confidence: DetectionConfidence;
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
  /** Fase 5B: finding de vulnerabilidad que aporta esta contribución. */
  finding_id?: string | null;
  /** Fase 5C: match de inteligencia de amenazas que aporta esta contribución. */
  threat_match_id?: string | null;
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
  /** Fase 4L: cuánto movió el score el contexto del activo (vacío si neutro o sin evidencia). */
  context: RiskExplanationItem[];
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

export type InsightKind =
  | "asset_summary"
  | "detection_analysis"
  | "risk_explanation"
  | "soc_summary"
  | "ask"
  | "incident_summary"
  | "incident_timeline"
  | "incident_evidence"
  | "incident_next_steps"
  | "vulnerability_analysis";
export type InsightScope = "asset" | "detection" | "incident" | "vulnerability" | "fleet";
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
  incident_id: string | null;
  /** Fase 5B: finding de vulnerabilidad analizado. */
  vulnerability_finding_id?: string | null;
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

// --- Incident Management (Fase 4K) -------------------------------------------------------

export type IncidentStatus = "open" | "triage" | "investigating" | "contained" | "resolved" | "closed" | "merged";
export type IncidentLevel = "low" | "medium" | "high" | "critical";
export type IncidentConfidence = "low" | "medium" | "high";
export type ResolutionCategory =
  | "true_positive"
  | "false_positive"
  | "benign_activity"
  | "duplicate"
  | "accepted_risk"
  | "other";
export type IncidentSort = "last_activity" | "created_at" | "severity" | "priority" | "status" | "number";
export type IncidentTask = "summary" | "timeline" | "evidence" | "next_steps";
export type TimelineSource =
  | "incident"
  | "note"
  | "event"
  | "detection"
  | "correlation"
  | "alert"
  | "risk"
  | "ai_insight";

export interface IncidentUserRef {
  user_id: string;
  username: string;
  role: string;
  /** False si la cuenta se desactivó después: se muestra como owner histórico. */
  active: boolean;
}

export interface IncidentLink {
  incident_id: string;
  key: string;
  title: string;
  status: IncidentStatus;
}

export interface IncidentAssetRef {
  asset_id: string;
  name: string;
  /** False si el activo ya no existe (se conserva el nombre copiado). */
  exists: boolean;
  primary_ip: string | null;
  source: string;
  added_at: string;
  /** Fase 4L: contexto actual (null si el activo ya no existe) y snapshots históricos. */
  context: AssetContextBrief | null;
  context_snapshot: AssetContextSnapshot | null;
  resolved_context_snapshot: AssetContextSnapshot | null;
}

export interface IncidentSummary {
  incident_id: string;
  number: number;
  /** INC-000001 */
  key: string;
  title: string;
  severity: IncidentLevel;
  priority: IncidentLevel;
  status: IncidentStatus;
  confidence: IncidentConfidence | null;
  owner: IncidentUserRef | null;
  assets: string[];
  asset_count: number;
  last_activity_at: string;
  created_at: string;
  updated_at: string;
  /** Token de concurrencia: toda mutación lo envía y el servidor responde 409 si cambió. */
  version: number;
}

export interface IncidentList {
  items: IncidentSummary[];
  total: number;
}

export interface IncidentDetectionRef {
  detection_id: string;
  rule_id: string;
  /** Fase 5A: null si la retención ya purgó la detección. */
  rule_version: number | null;
  rule_source: RuleSource | null;
  kind: string;
  title: string;
  severity: string;
  status: string | null;
  confidence: string | null;
  /** False si la retención ya purgó la detección (queda su referencia mínima). */
  available: boolean;
  asset_id: string | null;
  hostname: string | null;
  first_seen_at: string | null;
  last_seen_at: string | null;
  source: string;
  attached_at: string;
}

export interface IncidentAlertRef {
  alert_id: string;
  rule: string;
  severity: string;
  status: string | null;
  message: string;
  available: boolean;
  asset_id: string | null;
  hostname: string | null;
  opened_at: string | null;
  source: string;
  attached_at: string;
}

export interface IncidentRiskAsset {
  asset_id: string;
  name: string;
  evaluated: boolean;
  score: number | null;
  level: string | null;
  confidence: string | null;
  calculated_at: string | null;
  changed_at: string | null;
  top_contributors: RiskContribution[];
}

export interface IncidentRiskSnapshot {
  score: number | null;
  level: string | null;
  confidence: string | null;
  taken_at: string | null;
}

export interface IncidentRiskContext {
  snapshot: IncidentRiskSnapshot;
  assets: IncidentRiskAsset[];
}

/** Tiempos observados (no SLA), en segundos. */
export interface IncidentMetrics {
  age_seconds: number;
  time_to_triage_seconds: number | null;
  time_to_resolve_seconds: number | null;
}

export interface IncidentDetail extends IncidentSummary {
  description: string | null;
  first_seen_at: string | null;
  last_seen_at: string | null;
  triaged_at: string | null;
  resolved_at: string | null;
  closed_at: string | null;
  resolution_category: ResolutionCategory | null;
  resolution_summary: string | null;
  duplicate_of: IncidentLink | null;
  merged_into: IncidentLink | null;
  merged_at: string | null;
  merged_from: IncidentLink[];
  created_by: IncidentUserRef | null;
  assigned_by: IncidentUserRef | null;
  assigned_at: string | null;
  updated_by: IncidentUserRef | null;
  resolved_by: IncidentUserRef | null;
  risk: IncidentRiskContext;
  asset_refs: IncidentAssetRef[];
  detections: IncidentDetectionRef[];
  detections_total: number;
  alerts: IncidentAlertRef[];
  alerts_total: number;
  notes_total: number;
  metrics: IncidentMetrics;
  allowed_transitions: IncidentStatus[];
  /** Fase 5B: findings de vulnerabilidad del caso. */
  vulnerabilities: IncidentVulnerabilityRef[];
  vulnerabilities_total: number;
  /** Fase 5C: matches de inteligencia de amenazas del caso. */
  threat_matches?: IncidentThreatMatchRef[];
  threat_matches_total?: number;
}

/** Match de inteligencia de un incidente: snapshot al vincularlo + estado actual. */
export interface IncidentThreatMatchRef {
  match_id: string;
  indicator_type: string;
  indicator_value: string;
  classification: string;
  confidence: string;
  source_name: string;
  source_trust: string;
  observation_type: string;
  observed_value: string;
  status: string | null;
  available: boolean;
  asset_id: string | null;
  hostname: string | null;
  source: string;
  attached_at: string;
  intel_snapshot?: Record<string, unknown> | null;
}

/** Finding de vulnerabilidad de un incidente: snapshot mínimo + estado actual. */
export interface IncidentVulnerabilityRef {
  finding_id: string;
  vulnerability_id: string;
  title: string;
  severity: string;
  component: string;
  installed_version: string | null;
  status: string | null;
  match_state: string | null;
  available: boolean;
  asset_id: string | null;
  hostname: string | null;
  source: string;
  attached_at: string;
  /** Fase 5C: inteligencia (KEV/EPSS) al vincularlo y al resolver el caso. */
  intel_snapshot?: Record<string, unknown> | null;
  resolved_intel_snapshot?: Record<string, unknown> | null;
}

export interface IncidentNote {
  note_id: string;
  author: string;
  body: string;
  created_at: string;
  incident_key: string;
}

export interface IncidentNoteList {
  items: IncidentNote[];
  total: number;
}

export interface TimelineItem {
  item_id: string;
  occurred_at: string;
  source_type: TimelineSource;
  action: string | null;
  entity_type: string | null;
  entity_id: string | null;
  actor: string | null;
  /** Texto plano (generado por Sentra o escrito por un analista). */
  summary: string;
  incident_key: string;
}

export interface IncidentTimeline {
  items: TimelineItem[];
  next_cursor: string | null;
}

export interface EvidenceEvent {
  detection_id: string;
  signal_kind: string;
  source_type: string;
  source_id: string | null;
  occurred_at: string;
  summary: string;
}

export interface EvidenceExposure {
  asset_id: string;
  asset_name: string;
  protocol: string;
  port: number;
  service_hint: string | null;
  opened_at: string;
}

export interface EvidenceRisk {
  asset_id: string;
  asset_name: string;
  contributions: RiskContribution[];
}

export interface IncidentEvidence {
  detections: IncidentDetectionRef[];
  correlations: IncidentDetectionRef[];
  events: EvidenceEvent[];
  events_total: number;
  exposure: EvidenceExposure[];
  alerts: IncidentAlertRef[];
  risk_contributions: EvidenceRisk[];
}

export interface RelatedIncident {
  incident: IncidentSummary;
  reasons: string[];
  score: number;
}

export interface RelatedIncidentList {
  items: RelatedIncident[];
  suggested_priority: IncidentLevel;
  suggested_severity: IncidentLevel;
}

export interface IncidentActivity {
  incident_id: string;
  incident_key: string;
  incident_title: string;
  occurred_at: string;
  action: string;
  actor: string;
  summary: string;
}

export interface IncidentOverview {
  open: number;
  triage: number;
  investigating: number;
  contained: number;
  critical: number;
  unassigned: number;
  assigned_to_me: number;
  mean_age_seconds: number | null;
  recent_activity: IncidentActivity[];
}

export interface AssignableUser {
  user_id: string;
  username: string;
  role: string;
}

export interface AssignableUserList {
  items: AssignableUser[];
}

export interface IncidentAuditEvent {
  created_at: string;
  actor: string;
  action: string;
  result: string;
  details: Record<string, unknown> | null;
}

export interface IncidentAuditList {
  items: IncidentAuditEvent[];
  total: number;
}

// --- Fase 5B: Vulnerability & Exposure Management ------------------------------------------

export type VulnSeverity = "informational" | "low" | "medium" | "high" | "critical";
/** Estado técnico (lo decide la evaluación): nunca se confunde con el estado de trabajo. */
export type MatchState = "confirmed" | "probable" | "potential" | "not_affected" | "unknown";
export type MatchConfidence = "high" | "medium" | "low";
/** Estado de trabajo (lo deciden las personas). */
export type FindingStatus = "open" | "acknowledged" | "mitigating" | "resolved" | "accepted_risk" | "false_positive";
export type ExposureState = "internet_exposed" | "observed" | "listening" | "not_observed" | "unknown";
export type FindingSort = "priority" | "cvss" | "severity" | "asset_risk" | "last_seen" | "first_seen";
export type FindingAction = "acknowledge" | "mitigating" | "resolve" | "accept-risk" | "false-positive" | "reopen";

export interface VulnerabilityAssetRef {
  asset_id: string;
  name: string;
  primary_ip: string;
  criticality: string;
  os_name: string | null;
  risk_score: number | null;
  risk_level: string | null;
}

export interface FindingSummary {
  finding_id: string;
  asset: VulnerabilityAssetRef;
  vulnerability_id: string;
  title: string;
  severity: VulnSeverity;
  cvss_score: number | null;
  cvss_version: string | null;
  component_name: string;
  component_vendor: string | null;
  component_type: string;
  installed_version: string | null;
  fixed_version: string | null;
  match_state: MatchState;
  confidence: MatchConfidence;
  status: FindingStatus;
  exposure_state: ExposureState;
  priority_score: number;
  priority_level: string;
  source: string;
  first_seen_at: string;
  last_seen_at: string;
  /** La evidencia (inventario) es antigua: el activo puede estar offline. */
  stale: boolean;
  version: number;
  /** Fase 5C: CVE con el que se busca la inteligencia (null: el registro no tiene CVE). */
  intel_cve?: string | null;
  /** Explotación conocida reportada (CISA KEV) en algún sitio; nunca "explotado aquí". */
  known_exploited?: boolean;
  /** Probabilidad de explotación EPSS (0-1): modelo estadístico, no % de vulnerabilidad. */
  epss_score?: number | null;
  epss_percentile?: number | null;
  /** La inteligencia que aporta viene de una fuente caducada. */
  intel_stale?: boolean;
}

export interface FindingList {
  items: FindingSummary[];
  total: number;
}

export interface CatalogRecordRef {
  source: string;
  source_name: string;
  catalog_version: string | null;
  imported_at: string;
  record_version: number;
  id_type: string;
  aliases: string[];
  description: string | null;
  source_severity: string | null;
  cvss_vector: string | null;
  published_at: string | null;
  modified_at: string | null;
  /** Solo http/https (validado en la importación y otra vez al pintar). */
  references: string[];
  cwe: string[];
  remediation: string | null;
  metadata: Record<string, unknown>;
}

export interface FindingIncidentRef {
  incident_id: string;
  key: string;
  title: string;
  status: string;
  attached_at: string;
}

export interface FindingEvidenceInstance {
  name: string;
  version: string | null;
  architecture: string | null;
  result: string;
}

/** Qué se comparó y con qué resultado (solo el componente afectado, nunca el inventario). */
export interface FindingEvidence {
  source?: string;
  kind?: string;
  collected_at?: string | null;
  component?: Record<string, string | null>;
  instances?: FindingEvidenceInstance[];
  rule?: Record<string, unknown>;
  checks?: FindingCheck[];
}

export interface FindingCheck {
  check: string;
  result: string;
}

export interface FindingExposure {
  state?: ExposureState;
  labels?: string[];
  service_ports?: number[];
  observed_open?: number[];
  listening?: number[];
  internet_exposed?: boolean | null;
}

export interface PriorityFactor {
  factor: string;
  label: string;
  points: number;
}

export interface FindingDetail extends FindingSummary {
  rationale: string;
  affected_range: string | null;
  status_reason: string | null;
  status_changed_at: string;
  status_changed_by: string;
  resolution: string | null;
  resolved_at: string | null;
  accepted_until: string | null;
  review_basis: Record<string, unknown> | null;
  evidence_kind: string;
  evidence: FindingEvidence;
  exposure: FindingExposure;
  priority_factors: PriorityFactor[];
  inventory_observed_at: string | null;
  evaluated_at: string;
  missing_count: number;
  reopen_count: number;
  catalog: CatalogRecordRef | null;
  incidents: FindingIncidentRef[];
  /** Acciones que el usuario actual puede ejecutar ahora (más "incident"). */
  actions: string[];
}

export interface FindingHistoryItem {
  occurred_at: string;
  action: string;
  actor: string;
  from_value: string | null;
  to_value: string | null;
  details: Record<string, unknown> | null;
}

export interface FindingHistory {
  items: FindingHistoryItem[];
  total: number;
}

export interface VulnerabilityOverview {
  by_severity: Record<string, number>;
  confirmed: number;
  probable: number;
  potential: number;
  insufficient_evidence: number;
  open: number;
  accepted_risk: number;
  false_positive: number;
  resolved: number;
  assets_affected: number;
  stale: number;
  catalog_records: number;
  catalog_sources: number;
  last_import_at: string | null;
  evaluation_pending: number;
  last_evaluated_at: string | null;
}

export interface AssetVulnerabilityStatus {
  evaluated_at: string | null;
  inventory_collected_at: string | null;
  inventory_complete: boolean | null;
  stale: boolean;
  components: number;
  pending: boolean;
  error: string | null;
  limitations: string[];
}

export interface AssetVulnerabilities {
  asset_id: string;
  status: AssetVulnerabilityStatus;
  by_severity: Record<string, number>;
  items: FindingSummary[];
  total: number;
}

export interface CatalogSource {
  source: string;
  name: string;
  kind: string;
  catalog_version: string | null;
  generated_at: string | null;
  status: string;
  records: number;
  revision: number;
  last_import_at: string | null;
  last_import_by: string | null;
  last_import_sha256: string | null;
  last_import_result: Record<string, number> | null;
  last_error: string | null;
}

export interface CatalogRecordSummary {
  source: string;
  vulnerability_id: string;
  id_type: string;
  title: string;
  severity: VulnSeverity;
  cvss_score: number | null;
  cvss_version: string | null;
  published_at: string | null;
  affected: number;
  findings: number;
}

export interface CatalogList {
  sources: CatalogSource[];
  items: CatalogRecordSummary[];
  total: number;
}

export interface CatalogInvalidRecord {
  index: number;
  vulnerability_id: string | null;
  code: string;
  message: string;
}

export interface CatalogPreview {
  format: string;
  source: string;
  source_name: string;
  catalog_version: string | null;
  generated_at: string | null;
  sha256: string;
  size_bytes: number;
  total: number;
  valid: number;
  new: number;
  updated: number;
  unchanged: number;
  invalid: number;
  invalid_records: CatalogInvalidRecord[];
  existing_source: boolean;
  assets_to_evaluate: number;
}

export interface CatalogImportResult {
  source: string;
  revision: number;
  sha256: string;
  new: number;
  updated: number;
  unchanged: number;
  invalid: number;
  assets_queued: number;
}

export interface EvaluateResult {
  mode: "immediate" | "queued";
  assets: number;
  created: number;
  updated: number;
  resolved: number;
  reopened: number;
}

export interface ExposureVulnerabilityRef {
  finding_id: string;
  vulnerability_id: string;
  severity: VulnSeverity;
  match_state: MatchState;
}

export interface ExposureItem {
  asset: VulnerabilityAssetRef;
  protocol: string;
  port: number;
  service_hint: string | null;
  sensitive: boolean;
  first_seen_at: string;
  opened_at: string;
  last_seen_at: string;
  new: boolean;
  internet_exposed: boolean | null;
  labels: string[];
  process: string | null;
  vulnerabilities: ExposureVulnerabilityRef[];
  vulnerabilities_total: number;
}

export interface ExposureOverview {
  items: ExposureItem[];
  total: number;
}

// --- Fase 5C: Threat Intelligence ---------------------------------------------------------------

export type IntelTrust = "official" | "trusted" | "community" | "local";
export type IntelSourceState = "fresh" | "stale" | "never_synced" | "disabled" | "archived";
export type IndicatorClassification = "malicious" | "suspicious" | "benign" | "unknown";
export type IntelConfidence = "low" | "medium" | "high";
export type ThreatMatchStatus = "open" | "acknowledged" | "dismissed";
export type ObservationType = "auth_source_ip" | "connection_remote_ip" | "asset_address" | "asset_name";

export interface ThreatSource {
  id: number;
  source_key: string;
  name: string;
  description: string | null;
  provider: string;
  provider_title: string;
  category: string;
  trust: IntelTrust;
  enabled: boolean;
  archived: boolean;
  network_required: boolean;
  capabilities: string[];
  sync_interval_hours: number | null;
  stale_after_hours: number | null;
  /** Último intento: never | ok | error | unavailable | syncing. */
  status: string;
  state: IntelSourceState;
  last_attempt_at: string | null;
  last_success_at: string | null;
  last_error: string | null;
  last_error_message: string | null;
  record_count: number;
  next_sync_at: string | null;
  sync_requested_at: string | null;
  /** Solo el host de descarga: la URL completa nunca sale del servidor. */
  download_host: string | null;
  reference_url: string | null;
  revision: number;
  created_at: string;
  updated_at: string;
}

export interface ThreatSourceList {
  items: ThreatSource[];
  sync_enabled: boolean;
  detection_policy: string;
}

export interface ThreatSync {
  id: number;
  kind: string;
  trigger: string;
  status: string;
  actor: string;
  started_at: string;
  finished_at: string | null;
  duration_ms: number | null;
  records_seen: number;
  records_new: number;
  records_updated: number;
  records_unchanged: number;
  records_removed: number;
  records_invalid: number;
  content_sha256: string | null;
  error_code: string | null;
  error_message: string | null;
}

export interface ThreatSyncList {
  items: ThreatSync[];
  total: number;
}

export interface ThreatChange {
  occurred_at: string;
  source_name: string;
  record_kind: string;
  change: string;
  cve_id: string | null;
  indicator_id: string | null;
  indicator_value: string | null;
  details: Record<string, unknown> | null;
}

export interface ThreatIntelOverview {
  status: "none_configured" | "ok" | "degraded";
  sources_total: number;
  sources_enabled: number;
  sources_stale: number;
  sources_failing: number;
  sync_enabled: boolean;
  detection_policy: string;
  last_success_at: string | null;
  kev_findings: number;
  kev_assets: number;
  high_epss_findings: number;
  indicators_total: number;
  indicators_active: number;
  active_matches: number;
  malicious_matches: number;
  matched_assets: number;
  recent_changes: ThreatChange[];
}

export interface IndicatorSourceRef {
  id: number;
  name: string;
  trust: IntelTrust;
  state: IntelSourceState;
}

export interface IndicatorSummary {
  indicator_id: string;
  indicator_type: string;
  value: string;
  classification: IndicatorClassification;
  confidence: IntelConfidence;
  confidence_score: number | null;
  state: "active" | "revoked" | "expired" | "not_yet_valid";
  valid_from: string | null;
  valid_until: string | null;
  /** supported | partial | unsupported: si la telemetría de Sentra puede casarlo. */
  matching: "supported" | "partial" | "unsupported";
  match_count: number;
  last_matched_at: string | null;
  tags: string[];
  source: IndicatorSourceRef;
  retrieved_at: string;
}

export interface IndicatorList {
  items: IndicatorSummary[];
  total: number;
}

export interface IndicatorDetail extends IndicatorSummary {
  value_original: string;
  description: string | null;
  references: string[];
  related: Record<string, unknown>[];
  external_id: string | null;
  pattern: string | null;
  first_seen_external: string | null;
  last_seen_external: string | null;
  matching_reason: string | null;
  other_sources: Record<string, unknown>[];
  conflicting: boolean;
  matches: ThreatMatchSummary[];
  changes: ThreatChange[];
}

export interface ThreatMatchSummary {
  match_id: string;
  asset: { asset_id: string; name: string; primary_ip: string };
  indicator_id: string;
  indicator_type: string;
  indicator_value: string;
  source_name: string;
  source_trust: IntelTrust;
  classification: IndicatorClassification;
  match_confidence: IntelConfidence;
  observation_type: ObservationType;
  observed_value: string;
  first_observed_at: string;
  last_observed_at: string;
  observation_count: number;
  status: ThreatMatchStatus;
  detection_id: string | null;
  version: number;
}

export interface ThreatMatchList {
  items: ThreatMatchSummary[];
  total: number;
}

export interface ThreatMatchDetail extends ThreatMatchSummary {
  observed_field: string;
  event_id: string | null;
  evidence: Record<string, unknown>;
  indicator_confidence: IntelConfidence;
  indicator_state: string;
  status_reason: string | null;
  status_changed_at: string;
  status_changed_by: string;
  matched_at: string;
  incidents: { incident_id: string; key: string; title: string; status: string }[];
  actions: string[];
}

export interface ThreatInvalidRecord {
  index: number;
  reference: string | null;
  code: string;
  message: string;
}

export interface ThreatImportPreview {
  source_key: string;
  format: string;
  sha256: string;
  size_bytes: number;
  source_version: string | null;
  total: number;
  valid: number;
  new: number;
  updated: number;
  unchanged: number;
  invalid: number;
  invalid_records: ThreatInvalidRecord[];
  unsupported: Record<string, number>;
  by_type: Record<string, number>;
  not_matchable: number;
}

export interface ThreatImportResult {
  source_key: string;
  sha256: string;
  new: number;
  updated: number;
  unchanged: number;
  invalid: number;
  pending_match: number;
}

export interface IntelSourceRef {
  source_id: number;
  name: string;
  trust: IntelTrust;
  state: IntelSourceState;
  last_success_at: string | null;
}

export interface KevIntel {
  source: IntelSourceRef;
  date_added: string | null;
  due_date: string | null;
  required_action: string | null;
  /** "known", "unknown" o el texto de CISA. "unknown" no significa "no". */
  known_ransomware_use: string;
  vendor_project: string | null;
  product: string | null;
  vulnerability_name: string | null;
  notes: string | null;
  retrieved_at: string;
  active: boolean;
  removed_at: string | null;
}

export interface EpssIntel {
  source: IntelSourceRef;
  score: number;
  percentile: number | null;
  band: string;
  model_version: string | null;
  score_date: string | null;
  retrieved_at: string;
  previous: Record<string, unknown> | null;
}

export interface FindingThreatIntel {
  finding_id: string;
  cve: string | null;
  status: "no_cve" | "none_configured" | "no_data" | "available";
  kev: KevIntel[];
  epss: EpssIntel[];
  conflicting: boolean;
  changes: { occurred_at: string; source_name: string; change: string; details: Record<string, unknown> | null }[];
  priority_factors: Record<string, unknown>[];
}
