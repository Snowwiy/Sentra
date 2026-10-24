// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Report, Role } from "../api/types";
import { WithRole } from "../test/auth";
import { ReportDetailPage } from "./ReportDetailPage";

// Datos sintéticos de test: no proceden de ningún host real.
const ID = "rrrrrrrr-0000-0000-0000-000000000001";
const CONTENT = "%PDF-1.7 sintético";
// SHA-256 de CONTENT (UTF-8), precalculado.
const SHA = "d3ed6459f065637ea2a3f4c697e3d293bd72bb47f98a1fde5bcabae3e7e3fc2a";
const NOW = "2026-10-14T23:15:00Z";

function report(overrides: Partial<Report> = {}): Report {
  return {
    id: ID,
    report_type: "detection",
    name: "Informe de detecciones",
    title: "Informe de detecciones 7d",
    format: "pdf",
    classification: "confidential",
    status: "succeeded",
    template_version: 1,
    requested_by: "ana",
    created_at: NOW,
    started_at: NOW,
    finished_at: NOW,
    cutoff_at: NOW,
    time_from: "2026-10-07T23:00:00Z",
    time_to: "2026-10-14T23:00:00Z",
    timezone: "UTC",
    filters: { severities: ["high"] },
    scope: { detections: 12 },
    summary: ["12 detecciones abiertas.", "<b>sin HTML</b>"],
    artifact: {
      filename: "sentra-detection-20261014.pdf",
      content_type: "application/pdf",
      size_bytes: 12345,
      sha256: SHA,
      created_at: NOW,
    },
    snapshot_sha256: null,
    error_code: null,
    error_message: null,
    cancel_requested: false,
    deduplicated: false,
    can_cancel: false,
    can_delete: true,
    version: 1,
    ...overrides,
  };
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

let current: Report;
let fetchMock: ReturnType<typeof vi.fn>;
let artifactSha = SHA;
const gets = () =>
  fetchMock.mock.calls.filter(
    ([input, init]) => !(init as RequestInit | undefined)?.method?.match(/POST|DELETE/) && String(input).endsWith(`/reports/${ID}`),
  ).length;

beforeEach(() => {
  current = report();
  artifactSha = SHA;
  fetchMock = vi.fn(async (input: string, init: RequestInit = {}) => {
    const method = init.method ?? "GET";
    const path = new URL(input, "http://localhost").pathname.replace("/api/v1", "");
    if (method === "GET" && path === `/reports/${ID}`) return json(200, current);
    if (method === "GET" && path === `/reports/${ID}/artifact`) {
      return new Response(CONTENT, {
        status: 200,
        headers: {
          "Content-Type": "application/pdf",
          "Content-Disposition": 'attachment; filename="sentra-detection-20261014.pdf"',
          "X-Sentra-SHA256": artifactSha,
        },
      });
    }
    if (method === "POST" && path === `/reports/${ID}/cancel`) {
      current = { ...current, status: "cancelled", can_cancel: false };
      return json(200, current);
    }
    if (method === "DELETE" && path === `/reports/${ID}`) {
      current = { ...current, status: "expired", artifact: null, can_delete: false };
      return json(200, current);
    }
    return json(404, { error: { code: "not_found", message: path } });
  });
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function renderPage(role: Role = "admin") {
  render(
    <MemoryRouter initialEntries={[`/reports/${ID}`]}>
      <WithRole role={role}>
        <Routes>
          <Route path="/reports/:reportId" element={<ReportDetailPage />} />
        </Routes>
      </WithRole>
    </MemoryRouter>,
  );
}

describe("ReportDetailPage", () => {
  it("shows metadata, UTC range, cutoff, full checksum and summary as text", async () => {
    renderPage();
    expect(await screen.findByRole("heading", { name: "Informe de detecciones 7d" })).toBeInTheDocument();
    expect(screen.getAllByText("2026-10-14 23:15 UTC").length).toBeGreaterThan(0);
    expect(screen.getByText("2026-10-07 23:00 UTC → 2026-10-14 23:00 UTC")).toBeInTheDocument();
    expect(screen.getByTestId("artifact-sha256")).toHaveTextContent(SHA);
    expect(screen.getByText("Confidencial")).toBeInTheDocument();
    // El resumen es texto: nunca se interpreta como HTML.
    expect(screen.getByText("<b>sin HTML</b>")).toBeInTheDocument();
    expect(document.querySelector("iframe")).toBeNull();
  });

  it("polls every 3 s while the report is pending or running and stops when done", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    current = report({ status: "pending", artifact: null, cutoff_at: null, summary: [], can_cancel: true });
    renderPage("analyst");
    expect(await screen.findByText(/En cola/)).toBeInTheDocument();
    const before = gets();
    current = report({ status: "running", artifact: null, cutoff_at: null, summary: [] });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3_000);
    });
    expect(gets()).toBeGreaterThan(before);
    expect(await screen.findByText(/Generando el informe/)).toBeInTheDocument();
    current = report();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3_000);
    });
    expect(await screen.findByTestId("artifact-sha256")).toHaveTextContent(SHA);
    const settled = gets();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(9_000);
    });
    expect(gets()).toBe(settled);
  });

  it("downloads through fetch + Blob + temporary link and verifies the checksum", async () => {
    const createObjectURL = vi.fn(() => "blob:report");
    const revokeObjectURL = vi.fn();
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL, revokeObjectURL }));
    const clicked: { download: string; href: string | null }[] = [];
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
      clicked.push({ download: this.download, href: this.getAttribute("href") });
    });
    renderPage("viewer");
    fireEvent.click(await screen.findByRole("button", { name: "Descargar" }));
    await waitFor(() => expect(click).toHaveBeenCalledTimes(1));
    expect(clicked).toEqual([{ download: "sentra-detection-20261014.pdf", href: "blob:report" }]);
    const call = fetchMock.mock.calls.find(([input]) => String(input).endsWith("/artifact"));
    expect((call?.[1] as RequestInit).credentials).toBe("include");
    expect(createObjectURL).toHaveBeenCalledTimes(1);
    expect(document.querySelector("a[download]")).toBeNull();
  });

  it("refuses to save a download whose checksum does not match", async () => {
    artifactSha = "0".repeat(64);
    const createObjectURL = vi.fn(() => "blob:report");
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL, revokeObjectURL: vi.fn() }));
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click");
    renderPage("viewer");
    fireEvent.click(await screen.findByRole("button", { name: "Descargar" }));
    expect(await screen.findByText(/no coincide con su SHA-256/)).toBeInTheDocument();
    expect(createObjectURL).not.toHaveBeenCalled();
    expect(click).not.toHaveBeenCalled();
  });

  // Fase 6E: sin crypto.subtle (http desde otra PC de la LAN) el SHA-256 se calcula con la
  // implementación propia. Antes el botón mostraba un error aunque la descarga era correcta.
  it("verifies with the built-in SHA-256 when crypto.subtle is missing and still saves", async () => {
    vi.stubGlobal("crypto", { getRandomValues: crypto.getRandomValues.bind(crypto) });
    const createObjectURL = vi.fn(() => "blob:report");
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL, revokeObjectURL: vi.fn() }));
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    renderPage("viewer");
    fireEvent.click(await screen.findByRole("button", { name: "Descargar" }));
    await waitFor(() => expect(click).toHaveBeenCalledTimes(1));
    expect(screen.queryByText(/SHA-256/, { selector: "[role=alert]" })).toBeNull();
    expect(createObjectURL).toHaveBeenCalledTimes(1);
  });

  it("still refuses a mismatching download when only the built-in SHA-256 is available", async () => {
    vi.stubGlobal("crypto", { getRandomValues: crypto.getRandomValues.bind(crypto) });
    artifactSha = "0".repeat(64);
    const createObjectURL = vi.fn(() => "blob:report");
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL, revokeObjectURL: vi.fn() }));
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click");
    renderPage("viewer");
    fireEvent.click(await screen.findByRole("button", { name: "Descargar" }));
    expect(await screen.findByText(/no coincide con su SHA-256/)).toBeInTheDocument();
    expect(createObjectURL).not.toHaveBeenCalled();
    expect(click).not.toHaveBeenCalled();
  });

  it("cancels an active report and deletes a finished one after confirmation", async () => {
    current = report({ status: "pending", artifact: null, can_cancel: true, can_delete: false });
    renderPage("analyst");
    fireEvent.click(await screen.findByRole("button", { name: "Cancelar" }));
    await waitFor(() => expect(screen.getByText("Cancelado")).toBeInTheDocument());
    cleanup();

    current = report();
    renderPage("admin");
    fireEvent.click(await screen.findByRole("button", { name: "Borrar" }));
    const dialog = await screen.findByRole("dialog", { name: "Borrar informe" });
    fireEvent.click(dialog.querySelector(".button--danger") as HTMLElement);
    await waitFor(() => expect(screen.getByText("Caducado")).toBeInTheDocument());
    expect(screen.getByText(/ha caducado o se ha borrado/)).toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([, init]) => (init as RequestInit | undefined)?.method === "DELETE")).toBe(true);
  });
});
