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
  | "monitoring_lost";
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
