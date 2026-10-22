// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Asset } from "../../api/types";
import { AssetLabelDialog } from "./AssetLabelDialog";

const ASSET = {
  asset_id: "6f1c2a8e-0000-4000-8000-000000000078",
  primary_ip: "192.168.50.78",
  custom_label: null,
  custom_label_version: 0,
  device_name: null,
  hostname: null,
  device_type: "iot",
  classification_confidence: "low",
} as unknown as Asset;

type Reply = { status: number; body: unknown };
let replies: Reply[];
let sent: { method: string; path: string; body: unknown }[];

beforeEach(() => {
  replies = [];
  sent = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init: RequestInit = {}) => {
      const path = new URL(input, "http://localhost").pathname.replace("/api/v1", "");
      sent.push({ method: init.method ?? "GET", path, body: JSON.parse(String(init.body ?? "null")) });
      const reply = replies.shift() ?? { status: 500, body: {} };
      return new Response(JSON.stringify(reply.body), { status: reply.status });
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function open(asset: Asset = ASSET) {
  const onSaved = vi.fn();
  const onClose = vi.fn();
  render(<AssetLabelDialog asset={asset} onClose={onClose} onSaved={onSaved} />);
  return { onSaved, onClose };
}

const input = () => screen.getByRole("textbox", { name: "Etiqueta personalizada" });

describe("editor de etiqueta", () => {
  it("guarda la etiqueta normalizada con la versión leída", async () => {
    replies.push({ status: 200, body: { ...ASSET, custom_label: "Alexa Sala", custom_label_version: 1 } });
    const { onSaved, onClose } = open();
    expect(screen.getByText("IoT probable")).toBeInTheDocument();
    fireEvent.change(input(), { target: { value: "  Alexa   Sala " } });
    fireEvent.click(screen.getByRole("button", { name: "Guardar" }));
    await waitFor(() => expect(onSaved).toHaveBeenCalled());
    expect(sent).toEqual([
      { method: "PATCH", path: `/assets/${ASSET.asset_id}/label`, body: { label: "Alexa Sala", version: 0 } },
    ]);
    expect(onClose).toHaveBeenCalled();
  });

  it("valida antes de enviar: vacía, demasiado larga o con caracteres invisibles", () => {
    open();
    for (const value of ["   ", "x".repeat(65), "Alexa‮ala S", "Alexa​Sala"]) {
      fireEvent.change(input(), { target: { value } });
      fireEvent.click(screen.getByRole("button", { name: "Guardar" }));
      expect(screen.getByRole("alert")).toBeInTheDocument();
    }
    expect(sent).toEqual([]);
  });

  it("un 409 enseña el cambio ajeno y el reintento usa la versión nueva", async () => {
    replies.push({
      status: 409,
      body: {
        error: {
          code: "asset_label_conflict",
          message: "conflict",
          details: [{ current_version: 3, custom_label: "Echo cocina" }],
        },
      },
    });
    const { onSaved } = open();
    fireEvent.change(input(), { target: { value: "Alexa Sala" } });
    fireEvent.click(screen.getByRole("button", { name: "Guardar" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("«Echo cocina»");
    expect(onSaved).not.toHaveBeenCalled();
    replies.push({ status: 200, body: { ...ASSET, custom_label: "Alexa Sala", custom_label_version: 4 } });
    fireEvent.click(screen.getByRole("button", { name: "Guardar" }));
    await waitFor(() => expect(onSaved).toHaveBeenCalled());
    expect(sent[1]?.body).toEqual({ label: "Alexa Sala", version: 3 });
  });

  it("quitar la etiqueta envía null", async () => {
    replies.push({ status: 200, body: { ...ASSET } });
    const { onSaved } = open({ ...ASSET, custom_label: "Alexa Sala", custom_label_version: 2 });
    fireEvent.click(screen.getByRole("button", { name: "Quitar etiqueta" }));
    await waitFor(() => expect(onSaved).toHaveBeenCalled());
    expect(sent[0]?.body).toEqual({ label: null, version: 2 });
  });

  it("muestra el error de permisos del servidor", async () => {
    replies.push({ status: 403, body: { error: { code: "permission_denied", message: "Permiso insuficiente" } } });
    open();
    fireEvent.change(input(), { target: { value: "Alexa Sala" } });
    fireEvent.click(screen.getByRole("button", { name: "Guardar" }));
    expect(await screen.findByRole("alert")).toBeInTheDocument();
  });
});
