// @vitest-environment jsdom
// Fase 6D.6: cada fallo de descarga tiene su mensaje; la cancelación no avisa y el botón
// vuelve siempre a su estado normal. Datos sintéticos: ningún host real.
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Report } from "../../api/types";
import { DownloadReportButton } from "./ReportViews";

const ID = "rrrrrrrr-0000-0000-0000-000000000002";
const CONTENT = "%PDF-1.7 sintético";
// SHA-256 de CONTENT (UTF-8), el mismo que usa ReportDetailPage.test.tsx.
const SHA = "d3ed6459f065637ea2a3f4c697e3d293bd72bb47f98a1fde5bcabae3e7e3fc2a";
const NOW = "2026-10-14T23:15:00Z";

const report = {
  id: ID,
  status: "succeeded",
  artifact: { filename: "informe.pdf", content_type: "application/pdf", size_bytes: 10, sha256: SHA, created_at: NOW },
} as unknown as Report;

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

let fetchMock: ReturnType<typeof vi.fn>;
let respond: (init: RequestInit) => Promise<Response>;

beforeEach(() => {
  fetchMock = vi.fn((_input: string, init: RequestInit = {}) => respond(init));
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

async function clickAndReadAlert(): Promise<string> {
  render(<DownloadReportButton report={report} />);
  fireEvent.click(screen.getByRole("button", { name: "Descargar" }));
  const alert = await screen.findByRole("alert");
  // El botón no queda colgado en «Descargando…».
  const button = screen.getByRole("button", { name: "Descargar" });
  expect(button).toBeEnabled();
  expect(button).toHaveAttribute("aria-busy", "false");
  return alert.textContent ?? "";
}

describe("DownloadReportButton: mensajes de error", () => {
  it("API no disponible (fetch rechazado)", async () => {
    respond = () => Promise.reject(new TypeError("Failed to fetch"));
    expect(await clickAndReadAlert()).toMatch(/^No se pudo conectar con la API de Sentra: comprueba que el servidor/);
  });

  it("tiempo de espera agotado", async () => {
    respond = () => Promise.reject(new DOMException("timeout", "TimeoutError"));
    expect(await clickAndReadAlert()).toMatch(/no respondió a tiempo/);
  });

  it("sesión caducada (401)", async () => {
    respond = async () => json(401, { error: { code: "not_authenticated", message: "Not authenticated" } });
    expect(await clickAndReadAlert()).toBe("La sesión ha caducado. Inicia sesión de nuevo para descargar.");
  });

  it("autorización insuficiente (403)", async () => {
    respond = async () => json(403, { error: { code: "permission_denied", message: "Forbidden" } });
    expect(await clickAndReadAlert()).toBe("Tu rol no permite descargar el informe.");
  });

  it("error del servidor con sobre de error (500)", async () => {
    respond = async () => json(500, { error: { code: "internal_error", message: "Internal server error" } });
    expect(await clickAndReadAlert()).toBe("Error del servidor (HTTP 500): Internal server error");
  });

  it("error del servidor sin sobre (500 HTML)", async () => {
    respond = async () => new Response("<html>500</html>", { status: 500, headers: { "Content-Type": "text/html" } });
    expect(await clickAndReadAlert()).toBe("Error del servidor (HTTP 500) sin más detalle.");
  });

  it("artefacto caducado (404 report_artifact_unavailable) y desaparecido (410)", async () => {
    respond = async () => json(404, { error: { code: "report_artifact_unavailable", message: "gone" } });
    expect(await clickAndReadAlert()).toBe("El fichero del informe ya no está disponible (caducado o borrado).");
    cleanup();
    respond = async () => json(410, { error: { code: "report_expired", message: "gone" } });
    expect(await clickAndReadAlert()).toMatch(/^El informe ya no existe o ha caducado/);
  });

  it("proxy de Vite sin sobre de error: 502 y 504", async () => {
    respond = async () => new Response("", { status: 502, headers: { "Content-Type": "text/plain" } });
    expect(await clickAndReadAlert()).toMatch(/proxy delante de la API no obtuvo respuesta de Sentra \(HTTP 502\)/);
    cleanup();
    respond = async () => new Response("", { status: 504, headers: { "Content-Type": "text/plain" } });
    expect(await clickAndReadAlert()).toMatch(/cortó la descarga por tiempo de espera \(HTTP 504\)/);
  });

  it("cuerpo cortado a mitad: descarga interrumpida, no «API no disponible»", async () => {
    respond = async () =>
      new Response(
        new ReadableStream({
          start(controller) {
            controller.error(new TypeError("network error"));
          },
        }),
        { status: 200, headers: { "X-Sentra-SHA256": SHA } },
      );
    const text = await clickAndReadAlert();
    expect(text).toMatch(/La descarga se interrumpió antes de completarse/);
    expect(text).not.toMatch(/No se pudo conectar/);
  });

  it("fallo de verificación SHA-256: no se guarda nada", async () => {
    const createObjectURL = vi.fn(() => "blob:x");
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL, revokeObjectURL: vi.fn() }));
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click");
    respond = async () => new Response(CONTENT, { status: 200, headers: { "X-Sentra-SHA256": "0".repeat(64) } });
    expect(await clickAndReadAlert()).toMatch(/no coincide con su SHA-256: no se ha guardado/);
    expect(createObjectURL).not.toHaveBeenCalled();
    expect(click).not.toHaveBeenCalled();
  });

  it("descarga correcta: verifica y guarda sin avisos", async () => {
    const createObjectURL = vi.fn(() => "blob:x");
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL, revokeObjectURL: vi.fn() }));
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    respond = async () => new Response(CONTENT, { status: 200, headers: { "X-Sentra-SHA256": SHA } });
    render(<DownloadReportButton report={report} />);
    fireEvent.click(screen.getByRole("button", { name: "Descargar" }));
    await waitFor(() => expect(click).toHaveBeenCalledTimes(1));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole("button", { name: "Descargar" })).toBeEnabled());
  });

  it("cancelación al desmontar: aborta la petición y no muestra aviso", async () => {
    let signal: AbortSignal | undefined;
    respond = (init) =>
      new Promise<Response>((_resolve, reject) => {
        signal = init.signal ?? undefined;
        signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
      });
    const errors = vi.spyOn(console, "error");
    const { unmount } = render(<DownloadReportButton report={report} />);
    fireEvent.click(screen.getByRole("button", { name: "Descargar" }));
    expect(screen.getByRole("button", { name: "Descargando…" })).toBeDisabled();
    await waitFor(() => expect(signal).toBeDefined());
    unmount();
    expect(signal?.aborted).toBe(true);
    await new Promise((r) => setTimeout(r, 0));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(errors).not.toHaveBeenCalled();
  });
});
