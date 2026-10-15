import { describe, expect, it } from "vitest";
import type { DiscoveryJob } from "../api/types";
import {
  checkLimits,
  exactProgress,
  formatClock,
  isActive,
  jobProfileName,
  jobTypeLabel,
  limitDraft,
  observationSource,
  originLabel,
  parsePorts,
  profileLabel,
  sensorSupportsAdvanced,
} from "./discovery";
import type { DiscoveryLimits } from "../api/types";

function job(overrides: Partial<DiscoveryJob>): DiscoveryJob {
  return {
    job_id: "j",
    target: "192.168.50.0/24",
    trigger: "manual",
    status: "running",
    baseline: false,
    started_at: new Date().toISOString(),
    completed_at: null,
    duration_seconds: null,
    hosts_scanned: 73,
    hosts_alive: 8,
    hosts_new: 0,
    open_ports: 0,
    probes: 0,
    error_count: 0,
    errors: [],
    requested_via: "dashboard",
    hosts_total: 254,
    hosts_updated: null,
    ports_opened: 0,
    ports_closed: 0,
    cancel_requested: false,
    stop_reason: null,
    progress: { phase: "liveness", details_total: 0, details_done: 0 },
    parameters: null,
    site_id: "00000000-0000-0000-0000-00000000d5f1",
    site_name: "Principal",
    execution_target: "local",
    sensor_id: null,
    sensor_name: null,
    ...overrides,
  };
}

describe("discovery helpers", () => {
  it("solo da progreso exacto cuando existe un total real", () => {
    expect(exactProgress(job({}))).toEqual({ label: "Hosts procesados", done: 73, total: 254 });
    expect(
      exactProgress(job({ progress: { phase: "details", details_total: 8, details_done: 3 } })),
    ).toMatchObject({ done: 3, total: 8 });
    expect(exactProgress(job({ progress: { phase: "pending", details_total: 0, details_done: 0 } }))).toBeUndefined();
    expect(exactProgress(job({ progress: { phase: "details", details_total: 0, details_done: 0 } }))).toBeUndefined();
    expect(exactProgress(job({ status: "queued" }))).toBeUndefined();
    expect(exactProgress(job({ status: "completed", progress: null }))).toBeUndefined();
  });

  it("formatea duraciones como cronómetro", () => {
    expect(formatClock(18.4)).toBe("00:18");
    expect(formatClock(3725)).toBe("1:02:05");
    expect(formatClock(null)).toBe("—");
    expect(formatClock(-1)).toBe("—");
  });

  it("estados activos, perfil y origen", () => {
    expect(isActive(job({ status: "queued" }))).toBe(true);
    expect(isActive(job({ status: "running" }))).toBe(true);
    expect(isActive(job({ status: "cancelled" }))).toBe(false);
    expect(profileLabel({ ports: [22, 80], icmp: false, reverse_dns: true })).toBe("2 puertos TCP · DNS");
    expect(profileLabel(null)).toBe("—");
    expect(originLabel(job({ requested_via: null, trigger: "scheduled" }))).toBe("Programado");
    expect(originLabel(job({ requested_via: null }))).toBe("Manual");
    expect(originLabel(job({ requested_via: "cli" }))).toBe("CLI");
  });
});

// --- Fase 6A ---------------------------------------------------------------------------------

const LIMITS: DiscoveryLimits = {
  timeout_ms: 500,
  dns_timeout_ms: 1000,
  concurrency: 32,
  max_probes_per_second: 100,
  tcp_retries: 0,
  max_hosts: 1024,
  max_ports: 16,
  deadline_minutes: 10,
  max_dns_queries: 0,
};
const CAPS: DiscoveryLimits = { ...LIMITS, timeout_ms: 800, concurrency: 64, tcp_retries: 2, deadline_minutes: 30, max_ports: 256 };

describe("descubrimiento avanzado", () => {
  it("nombra el perfil del job y su tipo (los jobs antiguos son básicos)", () => {
    expect(jobProfileName({ profile: "deep" })).toBe("Deep");
    expect(jobProfileName({ profile: null })).toBe("Básico");
    expect(jobProfileName({})).toBe("Básico");
    expect(jobTypeLabel({ job_type: "discovery_advanced", profile: "quick" })).toBe("Avanzado");
    expect(jobTypeLabel({ profile: null })).toBe("Básico");
  });

  it("solo los sensores con network.discovery.advanced admiten perfiles", () => {
    expect(sensorSupportsAdvanced({ capabilities: ["discovery_basic", "network.discovery.advanced"] })).toBe(true);
    expect(sensorSupportsAdvanced({ capabilities: ["discovery_basic"] })).toBe(false);
    expect(sensorSupportsAdvanced(undefined)).toBe(false);
  });

  it("valida límites contra los topes y solo devuelve lo que cambia", () => {
    const draft = limitDraft(LIMITS);
    expect(checkLimits(draft, LIMITS, CAPS)).toEqual({ changed: {}, errors: {} });
    const result = checkLimits(
      { ...draft, concurrency: "16", timeout_ms: "900", tcp_retries: "-1", deadline_minutes: "abc", max_hosts: "0" },
      LIMITS,
      CAPS,
    );
    expect(result.changed).toEqual({ concurrency: 16 });
    expect(Object.keys(result.errors).sort()).toEqual(["deadline_minutes", "max_hosts", "tcp_retries", "timeout_ms"]);
    expect(result.errors.timeout_ms).toMatch(/Máximo 800/);
    // 0 reintentos es válido.
    expect(checkLimits({ ...draft, tcp_retries: "2" }, LIMITS, CAPS).changed).toEqual({ tcp_retries: 2 });
  });

  it("interpreta puertos únicos dentro de 1–65535", () => {
    expect(parsePorts("")).toEqual({ ports: [] });
    expect(parsePorts("8080, 8443 8080;22")).toEqual({ ports: [8080, 8443, 22] });
    expect(parsePorts("0").error).toMatch(/fuera de 1–65535/);
    expect(parsePorts("70000").error).toMatch(/fuera/);
    expect(parsePorts("ssh").error).toMatch(/no es un puerto/);
  });

  it("fuente de la observación: servidor local o sensor", () => {
    expect(observationSource({ executor: "local", sensor_name: null, sensor_id: null })).toBe("Servidor local");
    expect(observationSource({ executor: "sensor", sensor_name: "sn-1", sensor_id: "x" })).toBe("Sensor sn-1");
  });
});
