import { describe, expect, it } from "vitest";
import { formatBytes, formatDateTime, formatPercent, formatRelative, formatUptime } from "./format";

describe("formatPercent", () => {
  it("shows one decimal and a dash when there is no value", () => {
    expect(formatPercent(12.345)).toBe("12.3%");
    expect(formatPercent(0)).toBe("0.0%");
    expect(formatPercent(null)).toBe("—");
    expect(formatPercent(undefined)).toBe("—");
  });
});

describe("formatUptime", () => {
  it("uses the two most significant units", () => {
    expect(formatUptime(59)).toBe("0 min");
    expect(formatUptime(3600 + 120)).toBe("1 h 2 min");
    expect(formatUptime(86400 + 3600 + 61)).toBe("1 d 1 h");
    expect(formatUptime(null)).toBe("—");
  });
});

describe("formatBytes", () => {
  it("scales by 1024 and stops at TB", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(1023)).toBe("1023 B");
    expect(formatBytes(1536)).toBe("1.5 KB");
    expect(formatBytes(5 * 1024 ** 4)).toBe("5.0 TB");
    expect(formatBytes(1024 ** 5)).toBe("1024.0 TB");
    expect(formatBytes(undefined)).toBe("—");
  });
});

describe("formatRelative", () => {
  const now = Date.parse("2026-10-04T12:00:00Z");
  const ago = (seconds: number) => new Date(now - seconds * 1000).toISOString();

  it("picks the unit by distance, in Spanish", () => {
    expect(formatRelative(ago(30), now)).toBe("hace 30 segundos");
    expect(formatRelative(ago(5 * 60), now)).toBe("hace 5 minutos");
    expect(formatRelative(ago(2 * 3600), now)).toBe("hace 2 horas");
    expect(formatRelative(ago(86400), now)).toBe("ayer");
    expect(formatRelative(ago(-5 * 60), now)).toBe("dentro de 5 minutos");
  });

  it("distinguishes 'never' from an unparseable timestamp", () => {
    expect(formatRelative(null, now)).toBe("Nunca");
    expect(formatRelative("not a date", now)).toBe("—");
  });
});

describe("formatDateTime", () => {
  it("renders a dash for missing or invalid timestamps", () => {
    expect(formatDateTime(null)).toBe("—");
    expect(formatDateTime("garbage")).toBe("—");
    expect(formatDateTime("2026-10-04T12:00:00Z")).toMatch(/2026/);
  });
});
