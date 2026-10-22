// Fixtures de la Fase 6B (equipos de red, inventario SNMP y perfiles). Solo las importan los
// *.test.tsx; no forman parte del bundle de la aplicación.
import type {
  NetworkDevice,
  NetworkDeviceDetail,
  NetworkMacEntry,
  NetworkNeighbor,
  NetworkPoll,
  SnmpProfile,
  SwitchInterface,
} from "../api/types";
import { BRANCH_SITE_ID } from "./sites";

const ISO = "2026-10-01T10:00:00Z";
export const DEVICE_ID = "de000000-0000-0000-0000-000000000001";
export const PROFILE_ID = "9f000000-0000-0000-0000-000000000001";
export const SENSOR_ID = "5e000000-0000-0000-0000-000000000001";

export function networkDevice(overrides: Partial<NetworkDevice> = {}): NetworkDevice {
  return {
    device_id: DEVICE_ID,
    site_id: BRANCH_SITE_ID,
    site_name: "Sucursal Norte",
    display_name: "core-sw-01",
    name: "core-sw-01",
    management_address: "10.20.0.2",
    snmp_port: 161,
    asset_id: null,
    status: "active",
    monitoring_enabled: true,
    monitoring_status: "ok",
    freshness: "recent",
    sys_name: "core-sw-01.local",
    sys_descr: "Switch OS 9.1",
    sys_object_id: "1.3.6.1.4.1.9.1.1",
    sys_location: "Rack A",
    sys_uptime_seconds: 86400,
    vendor: "Cisco",
    vendor_source: "sys_object_id",
    enterprise_number: 9,
    model: null,
    firmware: null,
    serial_number: null,
    classification: "managed_switch",
    classification_confidence: "high",
    classification_evidence: [{ source: "bridge_mib", detail: "48 bridge ports" }],
    layer3: false,
    profile: { profile_id: PROFILE_ID, name: "v3-norte", snmp_version: "v3", status: "active" },
    sensor: { sensor_id: SENSOR_ID, name: "sensor-norte", status: "online" },
    last_poll_at: ISO,
    last_success_at: ISO,
    last_error_code: null,
    last_error_at: null,
    consecutive_failures: 0,
    snmp_status: "compatible",
    monitoring_paused_at: null,
    monitoring_pause_reason: null,
    interfaces_total: 52,
    interfaces_up: 20,
    neighbors_total: 2,
    vlans_total: 3,
    mac_entries_total: 120,
    created_at: ISO,
    updated_at: ISO,
    version: 3,
    ...overrides,
  };
}

export function networkDetail(overrides: Partial<NetworkDeviceDetail> = {}): NetworkDeviceDetail {
  return {
    ...networkDevice(),
    lldp_local: null,
    entities: [],
    base_bridge_address: null,
    bridge_ports: 48,
    last_modules: { system: "complete", lldp: "complete", cdp: "unsupported" },
    can_poll: true,
    poll_blockers: [],
    ...overrides,
  };
}

export function switchInterface(overrides: Partial<SwitchInterface> = {}): SwitchInterface {
  return {
    interface_id: "1f000000-0000-0000-0000-000000000001",
    if_index: 1,
    name: "Gi1/0/1",
    if_name: "Gi1/0/1",
    if_descr: "GigabitEthernet1/0/1",
    if_alias: "uplink",
    if_type: 6,
    port_kind: "physical",
    mac: null,
    admin_status: "up",
    oper_status: "up",
    speed_mbps: 1000,
    mtu: 1500,
    in_octets: 1000,
    out_octets: 2000,
    counters_hc: true,
    in_errors: 0,
    out_errors: 0,
    in_discards: 0,
    out_discards: 0,
    counters_at: ISO,
    bridge_port: 1,
    pvid: 10,
    untagged_vlans: [10],
    tagged_vlans: [20, 21, 22],
    is_trunk: true,
    lag_parent: null,
    lag_members: 0,
    mac_count: 4,
    neighbor_count: 1,
    present: true,
    first_seen_at: ISO,
    last_seen_at: ISO,
    evidence_source: "if_mib",
    ...overrides,
  };
}

export function neighbor(overrides: Partial<NetworkNeighbor> = {}): NetworkNeighbor {
  return {
    neighbor_id: "4e000000-0000-0000-0000-000000000001",
    protocol: "lldp",
    local_interface: { interface_id: "1f000000-0000-0000-0000-000000000001", name: "Gi1/0/1", port_kind: "physical" },
    local_port_label: null,
    local_port_match: "if_index",
    remote_chassis_id: "00:11:22:33:44:55",
    remote_chassis_id_subtype: "mac_address",
    remote_port_id: "Gi0/1",
    remote_port_id_subtype: "interface_name",
    remote_port_descr: null,
    remote_sys_name: "dist-sw-02",
    remote_sys_descr: null,
    remote_platform: "C9300",
    remote_software: null,
    remote_mgmt_address: "10.20.0.3",
    remote_capabilities: ["bridge"],
    remote_native_vlan: null,
    remote_device: { device_id: "de000000-0000-0000-0000-000000000002", display_name: "dist-sw-02" },
    remote_match_basis: "chassis_mac",
    reciprocal: true,
    assessment: "reported_by_device",
    present: true,
    first_seen_at: ISO,
    last_seen_at: ISO,
    sensor_id: SENSOR_ID,
    evidence_source: "lldp_mib",
    ...overrides,
  };
}

export function macEntry(overrides: Partial<NetworkMacEntry> = {}): NetworkMacEntry {
  return {
    entry_id: "3a000000-0000-0000-0000-000000000001",
    mac: "aa:bb:cc:dd:ee:01",
    vlan_id: 10,
    vlan_source: "fdb_vlan_map",
    bridge_port: 5,
    interface: { interface_id: "1f000000-0000-0000-0000-000000000005", name: "Gi1/0/5", port_kind: "physical" },
    status: "learned",
    location: "edge_candidate",
    location_reason: "Única MAC en un puerto sin vecinos LLDP",
    port_mac_count: 1,
    asset: { asset_id: "a5000000-0000-0000-0000-000000000001", display_name: "pc-recepcion" },
    present: true,
    first_seen_at: ISO,
    last_seen_at: ISO,
    ...overrides,
  };
}

export function poll(overrides: Partial<NetworkPoll> = {}): NetworkPoll {
  return {
    poll_id: "90000000-0000-0000-0000-000000000001",
    device_id: DEVICE_ID,
    site_id: BRANCH_SITE_ID,
    sensor_id: SENSOR_ID,
    sensor_name: "sensor-norte",
    sensor_job_id: null,
    status: "succeeded",
    trigger: "manual",
    requested_by: "analyst",
    snmp_version: "v3",
    modules_requested: ["system", "interfaces"],
    modules: { system: "complete", interfaces: "complete" },
    error_code: null,
    error_message: null,
    counts: { interfaces: 52, neighbors: 2, vlans: 3, mac_entries: 120, records: 177 },
    changes: {
      interfaces_added: 0,
      interfaces_removed: 0,
      oper_status_changes: 1,
      neighbors_added: 0,
      neighbors_removed: 0,
      classification_changed: false,
    },
    created_at: ISO,
    started_at: ISO,
    finished_at: ISO,
    ...overrides,
  };
}

export function snmpProfile(overrides: Partial<SnmpProfile> = {}): SnmpProfile {
  return {
    profile_id: PROFILE_ID,
    site_id: BRANCH_SITE_ID,
    site_name: "Sucursal Norte",
    name: "v3-norte",
    description: null,
    snmp_version: "v3",
    security_level: "authPriv",
    username: "sentra-ro",
    auth_protocol: "sha256",
    priv_protocol: "aes128",
    status: "active",
    secret_configured: true,
    secret_updated_at: ISO,
    secret_revision: 1,
    devices_count: 1,
    created_at: ISO,
    created_by: "admin",
    updated_at: ISO,
    revoked_at: null,
    revoked_by: null,
    revoke_reason: null,
    version: 2,
    ...overrides,
  };
}
