// Utilidades de test de la Fase 5F: fixtures de sites y sensores y un fetch simulado con
// rutas. Solo las importan los *.test.tsx; no forma parte del bundle de la aplicación.
import { vi } from "vitest";
import type { Sensor, SensorJob, Site } from "../api/types";

export const DEFAULT_SITE_ID = "00000000-0000-0000-0000-00000000d5f1";
export const BRANCH_SITE_ID = "00000000-0000-0000-0000-0000000b0001";
export const OLD_SITE_ID = "00000000-0000-0000-0000-0000000a0001";

const ISO = "2026-10-01T10:00:00Z";

export function site(overrides: Partial<Site> = {}): Site {
  return {
    site_id: DEFAULT_SITE_ID,
    name: "Principal",
    slug: "principal",
    description: null,
    location_label: null,
    timezone: "UTC",
    status: "active",
    is_default: true,
    version: 1,
    created_at: ISO,
    updated_at: ISO,
    archived_at: null,
    asset_count: 10,
    sensor_count: 0,
    network_count: 0,
    ...overrides,
  };
}

/** Catálogo típico: el site por defecto, una sucursal con sensor y un site archivado. */
export const SITES: Site[] = [
  site(),
  site({ site_id: BRANCH_SITE_ID, name: "Sucursal Norte", slug: "norte", is_default: false, sensor_count: 2, network_count: 1 }),
  site({
    site_id: OLD_SITE_ID,
    name: "Almacén viejo",
    slug: "almacen",
    is_default: false,
    status: "archived",
    archived_at: ISO,
  }),
];

export function sensorJob(overrides: Partial<SensorJob> = {}): SensorJob {
  return {
    job_id: "51000000-0000-0000-0000-000000000001",
    site_id: BRANCH_SITE_ID,
    sensor_id: "5e000000-0000-0000-0000-000000000001",
    job_type: "discovery_basic",
    status: "succeeded",
    attempt: 1,
    max_attempts: 3,
    created_at: ISO,
    created_by: "admin",
    expires_at: ISO,
    leased_at: ISO,
    lease_expires_at: null,
    started_at: ISO,
    finished_at: ISO,
    error_code: null,
    discovery_job_id: null,
    target: "10.20.0.0/24",
    observations_received: 12,
    batches_received: 1,
    ...overrides,
  };
}

export function sensor(overrides: Partial<Sensor> = {}): Sensor {
  return {
    sensor_id: "5e000000-0000-0000-0000-000000000001",
    name: "sensor-norte",
    site_id: BRANCH_SITE_ID,
    site_name: "Sucursal Norte",
    status: "online",
    hostname: "sn-01",
    platform: "linux",
    sensor_version: "0.5.0",
    version_status: "current",
    capabilities: ["discovery_basic"],
    last_seen_at: new Date().toISOString(),
    enrolled_at: ISO,
    created_at: ISO,
    disabled_at: null,
    revoked_at: null,
    revoke_reason: null,
    rotation_pending: false,
    credential_issued_at: ISO,
    queue_depth: 0,
    spool_items: 0,
    uptime_seconds: 3600,
    last_successful_job_at: ISO,
    clock_skew_seconds: 0,
    pending_jobs: 0,
    last_job: null,
    version: 1,
    ...overrides,
  };
}

export type Handler = (init: RequestInit, url: URL) => { status?: number; body?: unknown };
export interface Call {
  method: string;
  path: string;
  url: URL;
  init: RequestInit;
}

/**
 * Sustituye fetch por un router "METODO /ruta" → respuesta. Devuelve la lista de llamadas
 * (con la URL completa para comprobar la query).
 */
export function installFetch(routes: Record<string, Handler>): Call[] {
  const calls: Call[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init: RequestInit = {}) => {
      const method = init.method ?? "GET";
      const url = new URL(input, "http://localhost");
      const path = url.pathname.replace("/api/v1", "");
      calls.push({ method, path, url, init });
      const handler = routes[`${method} ${path}`];
      if (!handler) return jsonResponse(404, { error: { code: "not_found", message: `no route ${path}` } });
      const { status = 200, body } = handler(init, url);
      return status === 204
        ? new Response(null, { status })
        : jsonResponse(status, body);
    }),
  );
  return calls;
}

export function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}
