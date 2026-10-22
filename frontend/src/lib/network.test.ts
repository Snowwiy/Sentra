import { describe, expect, it } from "vitest";
import { ApiError } from "../api/client";
import { networkDevice, snmpProfile } from "../test/network";
import {
  buildDeviceUpdate,
  buildProfileCreate,
  buildProfileRotate,
  describeModules,
  describePollBlocker,
  deviceFormFrom,
  evidenceSourceLabel,
  EMPTY_SECRETS,
  formatSpeed,
  formatVlanList,
  isOpenPoll,
  isVersionConflict,
  MONITORING_STATUS_HELP,
  MONITORING_STATUS_LABELS,
  pollBlockersFromError,
  snmpErrorText,
  validateSecrets,
} from "./network";

describe("network labels", () => {
  it("never describes a device as online", () => {
    for (const text of [...Object.values(MONITORING_STATUS_LABELS), ...Object.values(MONITORING_STATUS_HELP)]) {
      expect(text.toLowerCase()).not.toMatch(/\bonline\b|en línea|conectado/);
    }
  });

  it("gives each SNMP error code its own text and falls back to the code", () => {
    expect(snmpErrorText("auth_failed")).toMatch(/credenciales/);
    expect(snmpErrorText("timeout")).toMatch(/Sin respuesta/);
    expect(snmpErrorText("auth_failed")).not.toBe(snmpErrorText("timeout"));
    expect(snmpErrorText("something_new")).toBe("Error de consulta (something_new).");
    expect(snmpErrorText(null)).toBe("");
  });

  it("translates poll blockers and keeps unknown codes visible", () => {
    expect(describePollBlocker("profile_missing")).toMatch(/perfil SNMP/);
    expect(describePollBlocker("weird_reason")).toBe("Bloqueo: weird_reason.");
    expect(describePollBlocker("poll_in_progress")).toMatch(/en curso/);
  });

  it("labels the MIB provenance of inventory rows", () => {
    expect(evidenceSourceLabel("snmp:IF-MIB")).toBe("IF-MIB (SNMP)");
    expect(evidenceSourceLabel("snmp:CISCO-CDP-MIB")).toBe("CISCO-CDP-MIB (SNMP)");
    expect(evidenceSourceLabel("snmp:unknown")).toBe("snmp:unknown");
  });

  it("formats speeds, VLAN ranges and modules", () => {
    expect(formatSpeed(1000)).toBe("1 Gb/s");
    expect(formatSpeed(2500)).toBe("2.5 Gb/s");
    expect(formatSpeed(100)).toBe("100 Mb/s");
    expect(formatSpeed(null)).toBe("—");
    expect(formatVlanList([5, 1, 2, 3, 10, 11])).toBe("1-3, 5, 10-11");
    expect(formatVlanList([])).toBe("");
    expect(describeModules({ lldp: "unsupported", system: "complete" })).toBe("Sistema: completo · LLDP: no soportado");
    expect(isOpenPoll("queued")).toBe(true);
    expect(isOpenPoll("running")).toBe(true);
    expect(isOpenPoll("partial")).toBe(false);
  });

  it("reads blockers and version conflicts from API errors", () => {
    const unavailable = new ApiError(409, "network_poll_unavailable", "x", [{ blockers: ["sensor_missing", "profile_revoked"] }]);
    expect(pollBlockersFromError(unavailable)).toEqual(["sensor_missing", "profile_revoked"]);
    expect(pollBlockersFromError(new ApiError(409, "network_poll_busy", "x"))).toEqual([]);
    expect(isVersionConflict(new ApiError(409, "network_device_conflict", "x"))).toBe(true);
    expect(isVersionConflict(new ApiError(409, "snmp_profile_conflict", "x"))).toBe(true);
    expect(isVersionConflict(new ApiError(409, "network_device_exists", "x"))).toBe(false);
  });
});

describe("SNMP secrets", () => {
  const v3 = { ...EMPTY_SECRETS, username: "ro", authPassword: "auth-secret-1", privPassword: "priv-secret-2" };

  it("applies the backend rules before sending", () => {
    expect(validateSecrets("v3", v3)).toBeUndefined();
    expect(validateSecrets("v3", { ...v3, username: "" })).toMatch(/usuario/);
    expect(validateSecrets("v3", { ...v3, authPassword: "short" })).toMatch(/8 y 128/);
    expect(validateSecrets("v3", { ...v3, privPassword: v3.authPassword })).toMatch(/distintas/);
    expect(validateSecrets("v2c", { ...EMPTY_SECRETS, community: "Public" })).toMatch(/fábrica/);
    expect(validateSecrets("v2c", { ...EMPTY_SECRETS, community: "c0mmunity" })).toBeUndefined();
    // Rotación parcial: los campos vacíos se dejan como están, pero hace falta algún secreto.
    expect(validateSecrets("v3", { ...EMPTY_SECRETS }, true)).toMatch(/al menos una/);
    expect(validateSecrets("v3", { ...EMPTY_SECRETS, privPassword: "priv-secret-2" }, true)).toBeUndefined();
  });

  it("builds create bodies with only the fields of the chosen version", () => {
    expect(buildProfileCreate("s1", " core ", "", "v3", { ...v3, community: "leftover" })).toEqual({
      site_id: "s1",
      name: "core",
      description: null,
      snmp_version: "v3",
      username: "ro",
      auth_protocol: "sha256",
      priv_protocol: "aes128",
      auth_password: "auth-secret-1",
      priv_password: "priv-secret-2",
    });
    expect(buildProfileCreate("s1", "old", "legacy", "v2c", { ...v3, community: "c0mm" })).toEqual({
      site_id: "s1",
      name: "old",
      description: "legacy",
      snmp_version: "v2c",
      community: "c0mm",
    });
  });

  it("rotates only what changed", () => {
    const profile = snmpProfile();
    const form = { ...EMPTY_SECRETS, username: "sentra-ro", authProtocol: "sha256" as const, privProtocol: "aes256" as const, privPassword: "new-priv-pass" };
    expect(buildProfileRotate(2, "v3", form, profile)).toEqual({ version: 2, priv_protocol: "aes256", priv_password: "new-priv-pass" });
    expect(buildProfileRotate(2, "v2c", { ...EMPTY_SECRETS, community: "n3w" }, profile)).toEqual({ version: 2, community: "n3w" });
  });
});

describe("device form", () => {
  it("sends only the changes and uses clear_* to remove assignments", () => {
    const device = networkDevice();
    const form = deviceFormFrom(device);
    expect(buildDeviceUpdate(device, form)).toEqual({ version: 3 });
    expect(buildDeviceUpdate(device, { ...form, profileId: "", sensorId: "", port: "1161", monitoring: false })).toEqual({
      version: 3,
      snmp_port: 1161,
      clear_profile: true,
      clear_sensor: true,
      monitoring_enabled: false,
    });
    expect(buildDeviceUpdate(device, { ...form, name: "nuevo", profileId: "p2" })).toEqual({
      version: 3,
      name: "nuevo",
      profile_id: "p2",
    });
  });
});

// Fase 6D.4: estado SNMP con los textos del contrato y sin nombres de excepción.
describe("estado SNMP", () => {
  it("traduce cada estado y tolera valores nuevos sin mostrar detalles internos", async () => {
    const { SNMP_STATUS_LABELS, snmpStatusText, snmpErrorText, POLL_TRIGGER_LABELS, MONITORING_STATUS_LABELS } = await import(
      "./network"
    );
    expect(snmpStatusText("compatible")).toBe("SNMP operativo");
    expect(snmpStatusText(null)).toBe("Sin verificar");
    expect(snmpStatusText("future_state")).toBe("Estado SNMP desconocido (future_state)");
    expect(Object.keys(SNMP_STATUS_LABELS)).toHaveLength(9);
    expect(snmpErrorText("internal")).toBe("Error interno del colector");
    expect(POLL_TRIGGER_LABELS.check).toBe("verificación");
    expect(MONITORING_STATUS_LABELS.paused).toBe("En pausa");
  });
});
