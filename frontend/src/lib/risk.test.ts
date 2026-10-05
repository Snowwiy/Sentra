import { describe, expect, it } from "vitest";
import type { RiskLevelRange } from "../api/types";
import { formatDelta, formatPoints, levelBands, reasonLabel, riskHeadline, trendPoints } from "./risk";

const THRESHOLDS: RiskLevelRange[] = [
  { level: "informational", min: 0, max: 19 },
  { level: "low", min: 20, max: 39 },
  { level: "medium", min: 40, max: 59 },
  { level: "high", min: 60, max: 79 },
  { level: "critical", min: 80, max: 100 },
];

describe("risk helpers", () => {
  it("titular con score, nivel y confianza juntos", () => {
    expect(riskHeadline(82, "critical", "low")).toBe("82 / Crítico — confianza baja");
  });

  it("formatea diferencias y puntos con signo", () => {
    expect(formatDelta(12)).toBe("+12");
    expect(formatDelta(-5)).toBe("−5");
    expect(formatDelta(0)).toBe("sin cambios");
    expect(formatDelta(null)).toBe("—");
    expect(formatPoints(62.54)).toBe("+62,5");
    expect(formatPoints(-4)).toBe("−4");
    expect(formatPoints(0.01)).toBe("0");
  });

  it("motivo desconocido se muestra tal cual", () => {
    expect(reasonLabel("level_change")).toBe("Cambio de nivel");
    expect(reasonLabel("otro")).toBe("otro");
  });

  it("línea escalonada: mantiene el valor entre cambios y acaba en el actual", () => {
    const since = 0;
    const now = 100;
    const points = trendPoints(
      [
        { calculated_at: new Date(25).toISOString(), score: 50 },
        { calculated_at: new Date(75).toISOString(), score: 100 },
      ],
      { since, now, width: 100, height: 100, startScore: 0, current: 80 },
    );
    expect(points).toEqual([
      { x: 0, y: 100 },
      { x: 25, y: 100 },
      { x: 25, y: 50 },
      { x: 75, y: 50 },
      { x: 75, y: 0 },
      { x: 100, y: 0 },
      { x: 100, y: 20 },
    ]);
  });

  it("sin historial previo empieza en el primer punto y acota valores fuera de rango", () => {
    const points = trendPoints([{ calculated_at: new Date(-50).toISOString(), score: 140 }], {
      since: 0,
      now: 100,
      width: 100,
      height: 100,
      startScore: null,
      current: null,
    });
    expect(points).toEqual([
      { x: 0, y: 0 },
      { x: 100, y: 0 },
    ]);
    expect(trendPoints([], { since: 0, now: 1, width: 10, height: 10, startScore: null, current: null })).toEqual([]);
  });

  it("bandas de nivel cubren 0-100 sin huecos", () => {
    const bands = levelBands(THRESHOLDS, 100);
    const total = bands.reduce((sum, band) => sum + band.h, 0);
    expect(total).toBeCloseTo(100);
    const critical = bands.find((band) => band.level === "critical")!;
    expect(critical.y).toBeCloseTo(0);
    expect(critical.h).toBeCloseTo(20);
    const informational = bands.find((band) => band.level === "informational")!;
    expect(informational.y + informational.h).toBeCloseTo(100);
  });
});
