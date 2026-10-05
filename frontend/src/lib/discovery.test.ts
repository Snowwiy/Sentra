import { describe, expect, it } from "vitest";
import type { DiscoveryJob } from "../api/types";
import { exactProgress, formatClock, isActive, originLabel, profileLabel } from "./discovery";

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
