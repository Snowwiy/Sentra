import { describe, expect, it } from "vitest";
import { areaPath, donutSegments, formatShare, groupSmallSlices, linePath } from "./charts";

describe("charts (Fase 7A.7)", () => {
  it("sin datos no hay segmentos visibles ni porcentajes inventados", () => {
    expect(donutSegments([0, 0], 100)).toEqual([
      { length: 0, offset: 0 },
      { length: 0, offset: 0 },
    ]);
    expect(donutSegments([], 100)).toEqual([]);
    expect(formatShare(0, 0)).toBe("0 %");
    expect(groupSmallSlices([{ key: "pc", label: "PC", value: 0 }])).toEqual([]);
  });

  it("reparte la circunferencia con un hueco entre sectores; uno solo ocupa todo el anillo", () => {
    const [a, b] = donutSegments([3, 1], 100, 2);
    expect(a).toEqual({ length: 73, offset: 0 });
    expect(b).toEqual({ length: 23, offset: 75 });
    expect(donutSegments([5, 0], 100, 2)[0]).toEqual({ length: 100, offset: 0 });
  });

  it("formatea porcentajes pequeños sin redondear a cero", () => {
    expect(formatShare(1, 1000)).toBe("<1 %");
    expect(formatShare(6000, 10000)).toBe("60 %");
  });

  it("agrupa las categorías pequeñas en Otros y deja una sola con su nombre", () => {
    const entries = [
      { key: "pc", label: "PC", value: 50 },
      { key: "server", label: "Servidor", value: 30 },
      { key: "printer", label: "Impresora", value: 1 },
      { key: "camera", label: "Cámara", value: 1 },
      { key: "tv", label: "TV", value: 0 },
    ];
    const grouped = groupSmallSlices(entries, { minShare: 0.05 });
    expect(grouped.map((slice) => slice.label)).toEqual(["PC", "Servidor", "Otros"]);
    expect(grouped[2]).toMatchObject({ value: 2, grouped: ["Cámara", "Impresora"] });
    const single = groupSmallSlices(entries.slice(0, 3), { minShare: 0.05 });
    expect(single.map((slice) => slice.label)).toEqual(["PC", "Servidor", "Impresora"]);
  });

  it("limita el número de sectores aunque todos sean grandes", () => {
    const entries = Array.from({ length: 10 }, (_, index) => ({ key: `t${index}`, label: `T${index}`, value: 10 }));
    const grouped = groupSmallSlices(entries, { maxSlices: 4, minShare: 0 });
    expect(grouped).toHaveLength(4);
    expect(grouped[3]).toMatchObject({ label: "Otros", value: 70 });
  });

  it("un día sin datos corta la línea y el área en lugar de interpolarlo", () => {
    const points = [
      { x: 0, y: 10 },
      { x: 10, y: 20 },
      { x: 20, y: null },
      { x: 30, y: 5 },
    ];
    expect(linePath(points)).toBe("M0,10L10,20M30,5");
    expect(areaPath(points, 100)).toBe("M0,100L0,10L10,20L10,100ZM30,100L30,5L30,100Z");
    expect(linePath([{ x: 0, y: null }])).toBe("");
  });
});
