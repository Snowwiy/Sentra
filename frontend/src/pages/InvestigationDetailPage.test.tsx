// @vitest-environment jsdom
// Fase 6E.6: evidencia e interpretaciones separadas, integridad marcada, permisos por rol y
// descarga del paquete con SHA-256 verificado en el navegador (falla cerrado) y aceptación
// explícita del aviso evidence_integrity_mismatch.
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { InvestigationDetail, Role } from "../api/types";
import { WithRole } from "../test/auth";
import { INVESTIGATION_ID, investigationDetail } from "../test/phase6e";
import { jsonResponse } from "../test/sites";
import { InvestigationDetailPage } from "./InvestigationDetailPage";

const ZIP = "PK\u0003\u0004 paquete sintético";
// SHA-256 de ZIP (UTF-8), calculado con Web Crypto en beforeEach.
let zipSha = "";
const BASE = `/investigations/${INVESTIGATION_ID}`;

interface Call {
  method: string;
  path: string;
  body: unknown;
}

let detail: InvestigationDetail;
let calls: Call[];
let packageResponder: (ack: boolean) => Response;

beforeEach(async () => {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(ZIP)));
  zipSha = [...digest].map((b) => b.toString(16).padStart(2, "0")).join("");
  detail = investigationDetail();
  calls = [];
  packageResponder = () =>
    new Response(ZIP, {
      status: 200,
      headers: {
        "Content-Type": "application/zip",
        "Content-Disposition": 'attachment; filename="sentra-investigation.zip"',
        "X-Sentra-SHA256": zipSha,
      },
    });
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init: RequestInit = {}) => {
      const method = init.method ?? "GET";
      const path = new URL(input, "http://localhost").pathname.replace("/api/v1", "");
      const body = init.body ? JSON.parse(String(init.body)) : undefined;
      calls.push({ method, path, body });
      if (method === "GET" && path === BASE) return jsonResponse(200, detail);
      if (method === "POST" && path === `${BASE}/package`) return packageResponder(Boolean(body?.acknowledge_mismatch));
      if (method === "POST" && path === `${BASE}/notes`) {
        return jsonResponse(201, { id: "n3", kind: body.kind, body: body.body, author: "ana", created_at: "2026-10-22T10:00:00Z" });
      }
      if (method === "POST" && path === "/response/executions") {
        return jsonResponse(200, { execution_id: "e1", status: "queued", deduplicated: false });
      }
      return jsonResponse(404, { error: { code: "not_found", message: path } });
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function renderPage(role: Role = "analyst") {
  render(
    <MemoryRouter initialEntries={[BASE]}>
      <WithRole role={role}>
        <Routes>
          <Route path="/investigations/:investigationId" element={<InvestigationDetailPage />} />
        </Routes>
      </WithRole>
    </MemoryRouter>,
  );
}

function stubSave() {
  const createObjectURL = vi.fn(() => "blob:zip");
  vi.stubGlobal("URL", Object.assign(URL, { createObjectURL, revokeObjectURL: vi.fn() }));
  const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
  return { createObjectURL, click };
}

const packageCalls = () => calls.filter((c) => c.path === `${BASE}/package`);

describe("InvestigationDetailPage", () => {
  it("separa evidencia e interpretaciones y marca la integridad que no coincide", async () => {
    renderPage();
    const evidence = await screen.findByRole("region", { name: "Evidencias" });
    const interpretations = screen.getByRole("region", { name: "Interpretaciones" });
    expect(within(evidence).getByText("SHA-256 verificado")).toBeInTheDocument();
    expect(within(evidence).getByText("SHA-256 no coincide")).toBeInTheDocument();
    expect(within(evidence).getByText(/agente: 3333/)).toBeInTheDocument();
    // Las notas no aparecen como evidencia, y la evidencia no aparece entre las notas.
    expect(within(evidence).queryByText("El proceso padre es Word.")).toBeNull();
    expect(within(interpretations).getByText("El proceso padre es Word.")).toBeInTheDocument();
    const notes = within(interpretations).getByRole("list", { name: "Notas" });
    expect(within(notes).getByText("Resumen de IA")).toBeInTheDocument();
    expect(within(notes).getByText("Nota del analista")).toBeInTheDocument();
    expect(within(interpretations).queryByText(/SHA-256/)).toBeNull();
    expect(screen.getByTestId("integrity-warning")).toHaveTextContent("1 evidencia(s) con SHA-256 que no coincide");
  });

  it("permisos: el analyst recoge y descarga pero no cierra; el viewer solo lee", async () => {
    renderPage("analyst");
    await screen.findByRole("region", { name: "Evidencias" });
    expect(screen.queryByRole("button", { name: "Cerrar investigación" })).toBeNull();
    expect(screen.getByRole("button", { name: "Recoger" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Descargar paquete de evidencias" })).toBeInTheDocument();
    // Metadatos de fichero es MEDIUM (admin): no se ofrece al analyst.
    expect(screen.queryByRole("option", { name: "Metadatos de un fichero" })).toBeNull();
    cleanup();

    renderPage("viewer");
    await screen.findByRole("region", { name: "Evidencias" });
    expect(screen.queryByRole("button", { name: "Recoger" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Descargar paquete de evidencias" })).toBeNull();
    expect(screen.getByText("Tu rol no permite descargar evidencias.")).toBeInTheDocument();
    expect(screen.queryByRole("form", { name: "Nueva nota" })).toBeNull();
    cleanup();

    renderPage("admin");
    expect(await screen.findByRole("button", { name: "Cerrar investigación" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "Metadatos de un fichero" })).toBeInTheDocument();
  });

  it("la recogida usa POST /response/executions con investigation_id", async () => {
    renderPage("analyst");
    fireEvent.click(await screen.findByRole("button", { name: "Recoger" }));
    await waitFor(() => expect(calls.some((c) => c.path === "/response/executions")).toBe(true));
    const exec = calls.find((c) => c.path === "/response/executions");
    expect(exec?.body).toMatchObject({
      action_id: "forensic_processes",
      target_type: "asset",
      target_id: detail.investigation.asset_id,
      investigation_id: INVESTIGATION_ID,
      parameters: {},
    });
  });

  it("descarga el paquete solo si el SHA-256 de los bytes coincide con X-Sentra-SHA256", async () => {
    const { createObjectURL, click } = stubSave();
    renderPage("analyst");
    fireEvent.click(await screen.findByRole("button", { name: "Descargar paquete de evidencias" }));
    await waitFor(() => expect(click).toHaveBeenCalledTimes(1));
    expect(createObjectURL).toHaveBeenCalledTimes(1);
    expect(packageCalls()).toHaveLength(1);
    expect(packageCalls()[0]?.body).toEqual({ acknowledge_mismatch: false });
    expect(await screen.findByRole("status")).toHaveTextContent(`Paquete verificado (SHA-256 ${zipSha})`);
  });

  it("falla cerrado si el SHA-256 no coincide: no se guarda nada", async () => {
    packageResponder = () =>
      new Response(ZIP, { status: 200, headers: { "Content-Type": "application/zip", "X-Sentra-SHA256": "0".repeat(64) } });
    const { createObjectURL, click } = stubSave();
    renderPage("analyst");
    fireEvent.click(await screen.findByRole("button", { name: "Descargar paquete de evidencias" }));
    expect(await screen.findByText(/no coincide con su SHA-256: no se ha guardado/)).toBeInTheDocument();
    expect(createObjectURL).not.toHaveBeenCalled();
    expect(click).not.toHaveBeenCalled();
  });

  it("falla cerrado si el servidor no envía el SHA-256", async () => {
    packageResponder = () => new Response(ZIP, { status: 200, headers: { "Content-Type": "application/zip" } });
    const { click } = stubSave();
    renderPage("analyst");
    fireEvent.click(await screen.findByRole("button", { name: "Descargar paquete de evidencias" }));
    expect(await screen.findByText(/no indicó el SHA-256/)).toBeInTheDocument();
    expect(click).not.toHaveBeenCalled();
  });

  it("409 evidence_integrity_mismatch: avisa y solo reintenta tras aceptar de forma explícita", async () => {
    packageResponder = (ack) =>
      ack
        ? new Response(ZIP, { status: 200, headers: { "Content-Type": "application/zip", "X-Sentra-SHA256": zipSha } })
        : jsonResponse(409, { error: { code: "evidence_integrity_mismatch", message: "mismatch" } });
    const { click } = stubSave();
    renderPage("analyst");
    fireEvent.click(await screen.findByRole("button", { name: "Descargar paquete de evidencias" }));
    const warning = await screen.findByRole("alert", { name: "Aviso de integridad" });
    expect(warning).toHaveTextContent("Hay evidencias cuyo SHA-256 no coincide");
    expect(click).not.toHaveBeenCalled();
    expect(packageCalls()).toHaveLength(1);

    fireEvent.click(within(warning).getByRole("button", { name: "Acepto el aviso: descargar igualmente" }));
    await waitFor(() => expect(click).toHaveBeenCalledTimes(1));
    expect(packageCalls()).toHaveLength(2);
    expect(packageCalls()[1]?.body).toEqual({ acknowledge_mismatch: true });
    expect(screen.queryByRole("alert", { name: "Aviso de integridad" })).toBeNull();
  });

  it("cancelar el aviso no descarga nada", async () => {
    packageResponder = () => jsonResponse(409, { error: { code: "evidence_integrity_mismatch", message: "mismatch" } });
    const { click } = stubSave();
    renderPage("analyst");
    fireEvent.click(await screen.findByRole("button", { name: "Descargar paquete de evidencias" }));
    const warning = await screen.findByRole("alert", { name: "Aviso de integridad" });
    fireEvent.click(within(warning).getByRole("button", { name: "Cancelar" }));
    expect(screen.queryByRole("alert", { name: "Aviso de integridad" })).toBeNull();
    expect(packageCalls()).toHaveLength(1);
    expect(click).not.toHaveBeenCalled();
  });
});
