// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it } from "vitest";
import { deviceTypeSlices, riskSlices } from "./DashboardCharts";
import { DonutChart } from "./DonutChart";
import { RiskHistoryChart } from "./RiskHistoryChart";

afterEach(cleanup);

describe("DonutChart (Fase 7A.7)", () => {
  it("sin datos explica el vacío y no dibuja sectores ni tabla", () => {
    render(
      <MemoryRouter>
        <DonutChart title="Activos por tipo" slices={deviceTypeSlices({})} emptyText="No hay activos en este alcance." />
      </MemoryRouter>,
    );
    const figure = screen.getByRole("figure", { name: "Activos por tipo" });
    expect(within(figure).getByText("No hay activos en este alcance.")).toBeInTheDocument();
    expect(within(figure).queryByRole("img")).not.toBeInTheDocument();
    expect(within(figure).queryByRole("table")).not.toBeInTheDocument();
  });

  it("todo a cero también cuenta como sin datos", () => {
    render(
      <MemoryRouter>
        <DonutChart title="Distribución del riesgo" slices={riskSlices({ high: 0 }, 0)} emptyText="Sin activos." />
      </MemoryRouter>,
    );
    expect(screen.getByText("Sin activos.")).toBeInTheDocument();
  });

  it("agrupa los tipos pequeños en Otros y enlaza cada tipo a Dispositivos", () => {
    const byType = { pc: 60, server: 30, printer: 1, camera: 1, unknown: 8 };
    render(
      <MemoryRouter>
        <DonutChart title="Activos por tipo" slices={deviceTypeSlices(byType)} emptyText="—" />
      </MemoryRouter>,
    );
    const table = screen.getByRole("table", { name: "Activos por tipo" });
    expect(within(table).getByRole("row", { name: /Otros \(2 tipos\) 2 2 %/ })).toBeInTheDocument();
    expect(within(table).getByRole("link", { name: "PC" })).toHaveAttribute("href", "/network/devices?type=pc");
    expect(screen.getByRole("img")).toHaveAccessibleName(/PC 60 \(60 %\)/);
  });

  it("los sin calcular aparecen aparte, no como riesgo bajo", () => {
    render(
      <MemoryRouter>
        <DonutChart title="Distribución del riesgo" slices={riskSlices({ critical: 1, low: 3 }, 6)} emptyText="—" />
      </MemoryRouter>,
    );
    expect(screen.getByRole("row", { name: /Sin calcular 6 60 %/ })).toBeInTheDocument();
    expect(screen.getByRole("row", { name: /Bajo 3 30 %/ })).toBeInTheDocument();
  });
});

describe("RiskHistoryChart (Fase 7A.7)", () => {
  const point = (day: number, score: number | null) => ({
    day: new Date(Date.UTC(2026, 9, day)).toISOString(),
    assets_scored: score === null ? 0 : 4,
    average_score: score,
    high: 1,
    critical: 0,
  });

  it("sin ningún día con datos no dibuja una línea de ceros", () => {
    render(<RiskHistoryChart points={[point(1, null), point(2, null)]} days={7} onDays={() => undefined} />);
    expect(screen.getByText(/Sin historial de riesgo en este periodo/)).toBeInTheDocument();
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
    // La tabla sigue disponible: dice "sin datos" día a día.
    expect(screen.getAllByText("sin datos")).toHaveLength(2);
  });

  it("tiene alternativa en tabla y selector de periodo con estado", () => {
    let chosen = 0;
    render(
      <RiskHistoryChart points={[point(1, 30), point(2, null), point(3, 42.5)]} days={30} onDays={(d) => (chosen = d)} />,
    );
    expect(screen.getByRole("img")).toHaveAccessibleName(/de 30 .* a 42.5/);
    expect(screen.getByRole("button", { name: "30 días", pressed: true })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "7 días" }));
    expect(chosen).toBe(7);
    expect(screen.getByRole("table")).toHaveTextContent("42.5");
  });
});
