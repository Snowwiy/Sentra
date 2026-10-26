// Fixtures de la Fase 6E (identidad, procesos, investigaciones y aislamiento). Solo las importan
// los *.test.tsx; no forman parte del bundle de la aplicación. Datos sintéticos: ningún host real.
import type {
  Asset,
  AssetIdentity,
  ForensicArtifact,
  InvestigationDetail,
  IsolationOverview,
  IsolationSession,
  ProcessNode,
} from "../api/types";

export const ASSET_ID = "6f1c2a8e-0000-4000-8000-000000000001";
export const INVESTIGATION_ID = "1a000000-0000-4000-8000-000000000001";
const ISO = "2026-10-22T10:00:00Z";

export function asset(overrides: Partial<Asset> = {}): Asset {
  const now = new Date().toISOString();
  return {
    asset_id: ASSET_ID,
    display_name: "192.168.50.108",
    monitoring_method: "discovered",
    hostname: null,
    os_name: null,
    os_version: null,
    architecture: null,
    primary_ip: "192.168.50.108",
    agent_version: null,
    status: "online",
    agent_status: null,
    network_status: "online",
    first_seen_at: now,
    last_seen_at: null,
    created_at: now,
    updated_at: now,
    latest_telemetry: null,
    mac_address: "a4:00:03:00:00:12",
    reverse_dns: null,
    vendor: null,
    network_adapter_vendor: null,
    device_type: null,
    device_type_reason: null,
    device_name: null,
    name_source: null,
    device_vendor: null,
    device_model: null,
    probable_os: null,
    classification_confidence: null,
    classification_evidence: [],
    discovery_sources: ["arp"],
    discovery_network: "192.168.50.0/24",
    discovered_at: now,
    last_network_seen_at: now,
    open_ports: [],
    criticality: "medium",
    role: "unknown",
    risk_score: null,
    risk_level: null,
    risk_confidence: null,
    archived_at: null,
    archived_by: null,
    archive_reason: null,
    lifecycle_version: 0,
    custom_label: null,
    custom_label_version: 0,
    custom_label_updated_at: null,
    custom_label_updated_by: null,
    manual_device_type: null,
    observed_names: [],
    managed_history: false,
    event_coverage: null,
    event_coverage_at: null,
    lifecycle_state: "active",
    lifecycle_source: "discovered",
    missed_discovery_scans: 0,
    last_activity_at: null,
    site_id: "00000000-0000-0000-0000-00000000d5f1",
    site_name: "Principal",
    ...overrides,
  };
}

export function identity(overrides: Partial<AssetIdentity> = {}): AssetIdentity {
  return {
    asset_id: ASSET_ID,
    display_name: "192.168.50.108",
    custom_label: null,
    automatic_name: null,
    name_source: null,
    names: [],
    ip: "192.168.50.108",
    mac: "a6:00:03:00:00:12",
    mac_randomized: true,
    vendor: null,
    device_type: null,
    classification_confidence: null,
    leases: [],
    wifi: null,
    unidentified_reasons: ["no_name_sources", "randomized_mac", "dhcp_source_missing"],
    ...overrides,
  };
}

export function processNode(overrides: Partial<ProcessNode> & { instance_key: string }): ProcessNode {
  return {
    pid: 100,
    ppid: null,
    parent_instance_key: null,
    parent_relation: "observed",
    name: "proceso",
    exe: null,
    cmdline: null,
    username: "SYSTEM",
    sha256: null,
    signer: null,
    integrity: null,
    source: "psutil_poll",
    started_at: ISO,
    ended_at: null,
    running: true,
    children_count: 0,
    ...overrides,
  };
}

export function isolationSession(overrides: Partial<IsolationSession> = {}): IsolationSession {
  return {
    id: "15000000-0000-4000-8000-000000000001",
    asset_id: ASSET_ID,
    asset_label: "pc-ana",
    status: "isolated",
    reason: "Conexiones a un C2 conocido",
    duration_minutes: 60,
    requested_by: "admin",
    requested_at: ISO,
    approved_by: "admin",
    approved_at: ISO,
    expires_at: "2026-10-22T11:00:00Z",
    applied_at: ISO,
    released_by: null,
    release_reason: null,
    released_at: null,
    ended_at: null,
    method: "windows_firewall",
    verified: true,
    allowed: ["203.0.113.10"],
    rules: [],
    error_code: null,
    reported_state: "isolated",
    reported_at: ISO,
    isolate_execution_id: null,
    release_execution_id: null,
    version: 3,
    ...overrides,
  };
}

export function isolationOverview(overrides: Partial<IsolationOverview> = {}): IsolationOverview {
  return {
    asset_id: ASSET_ID,
    asset_label: "pc-ana",
    available: true,
    unavailable_message: null,
    reasons: [],
    server_enabled: true,
    platform: "windows",
    helper: { helper: "ready" },
    helper_reported_at: ISO,
    confirm_name: "pc-ana",
    default_minutes: 60,
    max_minutes: 240,
    impact: ["Se cortan las conexiones de red salvo con Sentra.", "Los usuarios pierden acceso a recursos compartidos."],
    manual_recommendations: [],
    current: null,
    ...overrides,
  };
}

export function artifact(overrides: Partial<ForensicArtifact> = {}): ForensicArtifact {
  return {
    id: "a7000000-0000-4000-8000-000000000001",
    action: "forensic_processes",
    operator: "ana-analyst",
    scope: {},
    sha256: "1".repeat(64),
    agent_sha256: "1".repeat(64),
    integrity: "verified",
    size_bytes: 2048,
    truncated: false,
    limitations: [],
    agent_version: "0.5.0",
    platform: "windows",
    collected_at: ISO,
    received_at: ISO,
    execution_id: null,
    ...overrides,
  };
}

export function investigationDetail(overrides: Partial<InvestigationDetail> = {}): InvestigationDetail {
  return {
    investigation: {
      id: INVESTIGATION_ID,
      asset_id: ASSET_ID,
      asset_label: "pc-ana",
      asset_exists: true,
      incident_id: null,
      title: "Conexiones sospechosas",
      status: "open",
      legal_hold: false,
      created_by: "ana-analyst",
      created_at: ISO,
      updated_at: ISO,
      closed_at: null,
      closed_by: null,
      version: 2,
      artifact_count: 2,
      mismatch_count: 1,
    },
    artifacts: [
      artifact(),
      artifact({
        id: "a7000000-0000-4000-8000-000000000002",
        action: "forensic_connections",
        sha256: "2".repeat(64),
        agent_sha256: "3".repeat(64),
        integrity: "mismatch",
      }),
    ],
    notes: [
      { id: "n1", kind: "note", body: "El proceso padre es Word.", author: "ana-analyst", created_at: ISO },
      { id: "n2", kind: "ai_summary", body: "Resumen generado por la IA.", author: "ana-analyst", created_at: ISO },
    ],
    collections: [],
    packages: [],
    ...overrides,
  };
}
