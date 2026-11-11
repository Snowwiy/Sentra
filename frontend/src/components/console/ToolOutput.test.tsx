// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it } from "vitest";
import type { ToolExecutionOut } from "../../api/types";
import { ToolOutput } from "./ToolOutput";

afterEach(cleanup);

// Fase 7D.1 (H03): el backend revalida los permisos actuales del lector en cada lectura del
// historial; si ya no los tiene, devuelve solo metadatos y marca el resultado como retenido.
function execution(overrides: Partial<ToolExecutionOut>): ToolExecutionOut {
  return {
    execution_id: "e1",
    status: "succeeded",
    summary: null,
    error_code: null,
    error_message: null,
    output: null,
    created_at: new Date().toISOString(),
    duration_ms: 12,
    truncated: false,
    output_sha256: null,
    content_withheld: false,
    withheld_permissions: [],
    ...overrides,
  } as unknown as ToolExecutionOut;
}

describe("ToolOutput (7D.1 H03)", () => {
  it("explica que el resultado está protegido y qué permiso falta", () => {
    render(
      <MemoryRouter>
        <ToolOutput execution={execution({ content_withheld: true, withheld_permissions: ["telemetry:read"] })} />
      </MemoryRouter>,
    );
    const notice = screen.getByTestId("tool-content-withheld");
    expect(notice).toHaveTextContent("Resultado protegido: requiere telemetry:read.");
    expect(notice).toHaveTextContent("solo los metadatos");
  });

  it("un resultado legible no muestra el aviso", () => {
    render(
      <MemoryRouter>
        <ToolOutput execution={execution({ summary: "3 detecciones" })} />
      </MemoryRouter>,
    );
    expect(screen.getByText("3 detecciones")).toBeInTheDocument();
    expect(screen.queryByTestId("tool-content-withheld")).toBeNull();
  });
});
