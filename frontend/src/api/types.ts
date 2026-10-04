// Mirrors the response schemas in backend/app/schemas. Keep in sync with the API.

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

export interface Asset {
  asset_id: string;
  hostname: string;
  os_name: string;
  os_version: string;
  architecture: string;
  primary_ip: string;
  agent_version: string;
  status: AssetStatus;
  first_seen_at: IsoDateTime;
  last_seen_at: IsoDateTime | null;
  created_at: IsoDateTime;
  updated_at: IsoDateTime;
  latest_telemetry: TelemetrySnapshot | null;
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

export type AlertRule = "asset_offline" | "high_cpu" | "high_ram" | "disk_critical";
export type AlertSeverity = "info" | "warning" | "critical";
export type AlertStatus = "open" | "resolved";

export interface Alert {
  alert_id: string;
  asset_id: string;
  hostname: string;
  rule: AlertRule;
  severity: AlertSeverity;
  status: AlertStatus;
  message: string;
  value: number | null;
  opened_at: IsoDateTime;
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
}

export interface ServiceInfo {
  name: string;
  display_name: string | null;
  status: string;
  start_type: string | null;
}

export interface SoftwareInfo {
  name: string;
  version: string | null;
  publisher: string | null;
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
  occurred_at: IsoDateTime;
}

export interface EventList {
  items: SystemEvent[];
  total: number;
}
