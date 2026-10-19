// Fixtures de la Fase 6C.3 (inventario Wi-Fi). Solo las importan los *.test.tsx; no forman
// parte del bundle de la aplicación. Direcciones de documentación, nunca datos reales.
import type {
  WlanAccessPointDetail,
  WlanAccessPointRead,
  WlanBssRead,
  WlanClientRead,
  WlanObservationRead,
  WlanOverview,
  WlanSsidRead,
} from "../api/types";
import { BRANCH_SITE_ID } from "./sites";

const ISO = "2026-10-01T10:00:00Z";
export const AP_ID = "a9000000-0000-0000-0000-000000000001";
export const BSS_ID = "b5500000-0000-0000-0000-000000000001";
export const CONTROLLER_ID = "de000000-0000-0000-0000-000000000003";

export function wlanOverview(overrides: Partial<WlanOverview> = {}): WlanOverview {
  return {
    site_id: null,
    access_points: 2,
    access_points_recent: 1,
    access_points_by_authorization: { unknown: 1, authorized: 1 },
    access_points_by_status: { up: 1, down: 1 },
    bss: 3,
    bss_recent: 2,
    bss_observed_only: 1,
    bss_by_band: { "2.4": 1, "5": 2 },
    ssids: 2,
    clients: 2,
    clients_recent: 1,
    clients_by_identity: { confirmed: 1, observation_only: 1 },
    insecure_bss: 1,
    findings_by_code: { wep: 1 },
    sources: [
      {
        source: "snmp",
        availability: "partial",
        reporters: 1,
        by_status: { complete: 0, partial: 1 },
        last_seen_at: ISO,
        detail: "SNMP wlan module only partially collected",
      },
      {
        source: "agent",
        availability: "available",
        reporters: 3,
        by_status: { ok: 2, no_adapter: 1 },
        last_seen_at: ISO,
        detail: "At least one agent reports Wi-Fi observations",
      },
    ],
    risk_engine_contribution: false,
    ...overrides,
  };
}

/** Ámbito sin datos: ninguna fuente configurada. */
export function emptyOverview(): WlanOverview {
  return wlanOverview({
    access_points: 0,
    access_points_recent: 0,
    access_points_by_authorization: {},
    access_points_by_status: {},
    bss: 0,
    bss_recent: 0,
    bss_observed_only: 0,
    bss_by_band: {},
    ssids: 0,
    clients: 0,
    clients_recent: 0,
    clients_by_identity: {},
    insecure_bss: 0,
    findings_by_code: {},
    sources: [
      {
        source: "snmp",
        availability: "not_configured",
        reporters: 0,
        by_status: {},
        last_seen_at: null,
        detail: "No sensor declares snmp.wlan (needs 0.4.0+)",
      },
      {
        source: "agent",
        availability: "not_configured",
        reporters: 0,
        by_status: {},
        last_seen_at: null,
        detail: "No agent has sent a wireless report",
      },
    ],
  });
}

export function wlanAp(overrides: Partial<WlanAccessPointRead> = {}): WlanAccessPointRead {
  return {
    access_point_id: AP_ID,
    site_id: BRANCH_SITE_ID,
    site_name: "Sucursal Norte",
    display_name: "ap-planta1",
    name: "ap-planta1",
    vendor: "Cisco",
    model: "AIR-AP2802I",
    serial_number: "FGL0000TEST",
    firmware: "8.10.1",
    location: "Planta 1",
    management_ip: "192.0.2.21",
    ethernet_mac: "00:1b:2c:3d:4e:01",
    radio_mac: "00:1b:2c:3d:4e:10",
    reported_status: "up",
    source: "snmp_airespace",
    confidence: "reported_by_device",
    reported_by: { device_id: CONTROLLER_ID, display_name: "wlc-01" },
    sensor: { sensor_id: "5e000000-0000-0000-0000-000000000001", name: "sensor-norte" },
    network_device: null,
    asset: null,
    authorization_status: "unknown",
    authorization_reason: null,
    authorization_by: null,
    authorization_at: null,
    present: true,
    freshness: "recent",
    first_seen_at: ISO,
    last_seen_at: ISO,
    radios: [{ slot: 0, band: "2.4", channel: 6, ssid: "Corp", standard: "802.11n", status: "up", clients: 4 }],
    bss_count: 2,
    client_count: 4,
    ssids: ["Corp"],
    version: 3,
    ...overrides,
  };
}

export function wlanBss(overrides: Partial<WlanBssRead> = {}): WlanBssRead {
  return {
    bss_id: BSS_ID,
    site_id: BRANCH_SITE_ID,
    site_name: "Sucursal Norte",
    bssid: "00:1b:2c:3d:4e:10",
    bssid_randomized: false,
    ssid: "Corp",
    band: "2.4",
    channel: 6,
    frequency_mhz: 2437,
    protection: "wpa2",
    protection_reported: "WPA2-Enterprise",
    standard: "802.11n",
    signal_dbm: -55,
    signal_quality: null,
    client_count: 4,
    vlan_id: null,
    access_point: { access_point_id: AP_ID, display_name: "ap-planta1" },
    source: "snmp_airespace",
    sources: ["snmp_airespace", "agent"],
    confidence: "reported_by_device",
    reported_by: { device_id: CONTROLLER_ID, display_name: "wlc-01" },
    last_agent: null,
    authorization_status: "unknown",
    authorization_reason: null,
    authorization_by: null,
    authorization_at: null,
    findings: [],
    present: true,
    freshness: "recent",
    first_seen_at: ISO,
    last_seen_at: ISO,
    last_snmp_seen_at: ISO,
    last_agent_seen_at: null,
    version: 1,
    ...overrides,
  };
}

export function wlanObservation(overrides: Partial<WlanObservationRead> = {}): WlanObservationRead {
  return {
    observation_id: 1,
    entity: "access_point",
    entity_id: AP_ID,
    source: "snmp_airespace",
    confidence: "reported_by_device",
    observed_at: ISO,
    received_at: ISO,
    poll_id: null,
    sensor: { sensor_id: "5e000000-0000-0000-0000-000000000001", name: "sensor-norte" },
    reported_by: { device_id: CONTROLLER_ID, display_name: "wlc-01" },
    agent_asset: null,
    data: { status: "up", channel: 6 },
    ...overrides,
  };
}

export function wlanApDetail(overrides: Partial<WlanAccessPointDetail> = {}): WlanAccessPointDetail {
  return {
    ...wlanAp(),
    link_suppressed: false,
    link_evidence: {},
    bss: [wlanBss()],
    findings: [],
    observations: [wlanObservation()],
    ...overrides,
  };
}

export function wlanSsid(overrides: Partial<WlanSsidRead> = {}): WlanSsidRead {
  return {
    site_id: BRANCH_SITE_ID,
    site_name: "Sucursal Norte",
    ssid: "Corp",
    bss_count: 2,
    bss_recent: 2,
    access_point_count: 1,
    bands: ["2.4", "5"],
    protections: ["wpa2"],
    sources: ["snmp_airespace"],
    configured_on_controllers: 1,
    controller_client_count: 4,
    client_count: 4,
    authorized_bss: 0,
    external_bss: 0,
    unknown_bss: 2,
    findings: [],
    last_seen_at: ISO,
    ...overrides,
  };
}

export function wlanClient(overrides: Partial<WlanClientRead> = {}): WlanClientRead {
  return {
    client_id: "c1000000-0000-0000-0000-000000000001",
    site_id: BRANCH_SITE_ID,
    site_name: "Sucursal Norte",
    mac: "da:a1:19:00:00:01",
    mac_randomized: true,
    bssid: "00:1b:2c:3d:4e:10",
    ssid: "Corp",
    access_point: { access_point_id: AP_ID, display_name: "ap-planta1" },
    radio_slot: 0,
    band: "2.4",
    standard: null,
    state: "associated",
    source: "snmp_airespace",
    identity_confidence: "observation_only",
    asset: null,
    correlation_basis: null,
    reported_by: { device_id: CONTROLLER_ID, display_name: "wlc-01" },
    present: true,
    freshness: "recent",
    first_seen_at: ISO,
    last_seen_at: ISO,
    ...overrides,
  };
}

export function page<T>(items: T[], total = items.length) {
  return { items, total, limit: 25, offset: 0 };
}
