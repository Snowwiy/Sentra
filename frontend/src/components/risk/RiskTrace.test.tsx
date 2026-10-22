// @vitest-environment jsdom
// Fase 6D.8: «Cómo se calcula». Datos sintéticos que reproducen el caso de una sola
// correlación CORR-002 que lleva el score cerca de 100.
import { cleanup, render, screen, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { afterEach, describe, expect, it } from "vitest";
import type { RiskAssetDetail, RiskContribution } from "../../api/types";
import { nominalChain, riskTrace } from "../../lib/risk";
import { RiskTraceSection } from "./RiskTrace";

afterEach(cleanup);

const TRACE = {
  base_points: 72,
  criticality_factor: 1.3,
  type_factor: 1,
  context_factor: 1.2,
  raw_points: 112.32,
  saturation_knee: 70,
  saturated_points: 94.6,
  score: 95,
  formula_version: 4,
};

function contribution(overrides: Partial<RiskContribution> = {}): RiskContribution {
  return {
    factor: "detection",
    category: "correlation",
    label: "CORR-002 · Fuerza bruta seguida de acceso correcto",
    points: 72,
    nominal_points: 80,
    detection_id: "d1",
    rule_id: "CORR-002",
    port: null,
    details: {
      recency_factor: 1,
      status_factor: 0.9,
      position_factor: 1,
      occurrence_count: 3,
      nominal_breakdown: { severity_points: 40, confidence_factor: 1, occurrence_factor: 1.25, correlation_factor: 1.6 },
    },
    ...overrides,
  };
}

function risk(breakdown: Record<string, unknown> | null, contributions = [contribution()]): RiskAssetDetail {
  return { breakdown, contributions } as unknown as RiskAssetDetail;
}

describe("RiskTraceSection", () => {
  it("muestra la cadena completa: aporte por factores, base, criticidad, contexto, saturación y score", () => {
    render(<RiskTraceSection risk={risk({ trace: TRACE })} />);
    const section = screen.getByRole("region", { name: "Cómo se calcula" });
    const row = within(section).getByRole("row", { name: /CORR-002/ });
    expect(row).toHaveTextContent("40 severidad ×1 confianza ×1,25 ocurrencias (3) ×1,6 correlación ×1 vigencia ×0,9 estado ×1 posición");
    expect(row).toHaveTextContent("= 72");
    const steps = within(section).getByRole("list", { name: "Pasos del cálculo" });
    expect(steps).toHaveTextContent("Suma de aportes (base): 72");
    expect(steps).toHaveTextContent("Base ×1,3 criticidad ×1 tipo de activo ×1,2 contexto = bruto 112,3");
    expect(steps).toHaveTextContent("a partir de 70 puntos el crecimiento se atenúa): 112,3 → 94,6");
    expect(steps).toHaveTextContent("Score final: 95");
    expect(section).toHaveTextContent("Fórmula v4");
  });

  it("no se muestra con cálculos antiguos sin traza", () => {
    const { container } = render(<RiskTraceSection risk={risk({ formula_version: 3, base_points: 10 })} />);
    expect(container).toBeEmptyDOMElement();
    cleanup();
    const { container: empty } = render(<RiskTraceSection risk={risk(null)} />);
    expect(empty).toBeEmptyDOMElement();
  });

  it("omite la tabla de detecciones si faltan los nominal_breakdown, pero conserva los pasos", () => {
    render(<RiskTraceSection risk={risk({ trace: TRACE }, [contribution({ details: {} })])} />);
    const section = screen.getByRole("region", { name: "Cómo se calcula" });
    expect(within(section).queryByRole("table")).not.toBeInTheDocument();
    expect(within(section).getByRole("list", { name: "Pasos del cálculo" })).toBeInTheDocument();
  });

  it("valida la forma de la traza (un campo no numérico la invalida)", () => {
    expect(riskTrace({ trace: { ...TRACE, score: "95" } })).toBeNull();
    expect(riskTrace({ trace: TRACE })).toEqual(TRACE);
    expect(nominalChain(contribution({ details: { nominal_breakdown: { severity_points: 1 } } }))).toBeNull();
  });
});
