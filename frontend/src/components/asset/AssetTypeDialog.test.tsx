// @vitest-environment jsdom
// Fase 7A.4: tipo manual del activo (PATCH /assets/{id}/device-type), con la misma versión que
// la etiqueta y el mismo tratamiento del 409. Datos sintéticos.
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Asset } from "../../api/types";
import { AssetTypeDialog } from "./AssetTypeDialog";

const ASSET = {
  asset_id: "6f1c2a8e-0000-4000-8000-000000000090",
  primary_ip: "192.168.50.90",
  custom_label: null,
  custom_label_version: 2,
  manual_device_type: null,
  device_name: null,
  hostname: null,
  device_type: "iot",
  classification_confidence: "medium",
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
  const onConflict = vi.fn();
  render(<AssetTypeDialog asset={asset} onClose={onClose} onSaved={onSaved} onConflict={onConflict} />);
  return { onSaved, onClose, onConflict };
}

const select = () => screen.getByRole("combobox", { name: "Tipo de dispositivo" });

describe("tipo manual del activo", () => {
  it("automático: muestra la confianza y guarda el tipo elegido con la versión leída", async () => {
    replies.push({ status: 200, body: { ...ASSET, manual_device_type: "ip_camera", device_type: "ip_camera" } });
    const { onSaved, onClose } = open();
    expect(screen.getByText("IoT probable")).toBeInTheDocument();
    expect(screen.getByText(/confianza media/)).toBeInTheDocument();
    // Sin tipo manual no hay nada a lo que volver.
    expect(screen.queryByRole("button", { name: "Volver a automático" })).not.toBeInTheDocument();
    fireEvent.change(select(), { target: { value: "ip_camera" } });
    fireEvent.click(screen.getByRole("button", { name: "Guardar" }));
    await waitFor(() => expect(onSaved).toHaveBeenCalled());
    expect(sent).toEqual([
      {
        method: "PATCH",
        path: `/assets/${ASSET.asset_id}/device-type`,
        body: { device_type: "ip_camera", version: 2 },
      },
    ]);
    expect(onClose).toHaveBeenCalled();
  });

  it("manual: lo dice claramente y «Volver a automático» envía null", async () => {
    replies.push({ status: 200, body: { ...ASSET } });
    const manual = { ...ASSET, manual_device_type: "dvr_nvr", device_type: "dvr_nvr", custom_label_version: 5 };
    const { onSaved } = open(manual);
    expect(screen.getByText("Grabador (DVR/NVR)", { selector: "strong" })).toBeInTheDocument();
    expect(screen.getByText("Asignado manualmente")).toBeInTheDocument();
    expect(select()).toHaveValue("dvr_nvr");
    fireEvent.click(screen.getByRole("button", { name: "Volver a automático" }));
    await waitFor(() => expect(onSaved).toHaveBeenCalled());
    expect(sent[0]?.body).toEqual({ device_type: null, version: 5 });
  });

  it("un 409 avisa del cambio ajeno, pide recargar y el reintento usa la versión nueva", async () => {
    replies.push({
      status: 409,
      body: {
        error: {
          code: "asset_label_conflict",
          message: "conflict",
          details: [{ current_version: 7, manual_device_type: "network_device" }],
        },
      },
    });
    const { onSaved, onConflict } = open();
    fireEvent.change(select(), { target: { value: "ip_camera" } });
    fireEvent.click(screen.getByRole("button", { name: "Guardar" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("«Equipo de red»");
    expect(onConflict).toHaveBeenCalledTimes(1);
    expect(onSaved).not.toHaveBeenCalled();
    // Tras el conflicto ya hay un tipo manual vigente: se puede volver a automático.
    expect(screen.getByRole("button", { name: "Volver a automático" })).toBeInTheDocument();
    replies.push({ status: 200, body: { ...ASSET, manual_device_type: "ip_camera", custom_label_version: 8 } });
    fireEvent.click(screen.getByRole("button", { name: "Guardar" }));
    await waitFor(() => expect(onSaved).toHaveBeenCalled());
    expect(sent[1]?.body).toEqual({ device_type: "ip_camera", version: 7 });
  });

  it("un 409 por otro cambio de identidad (la etiqueta) también se explica", async () => {
    replies.push({
      status: 409,
      body: {
        error: { code: "asset_label_conflict", message: "conflict", details: [{ current_version: 3, manual_device_type: null }] },
      },
    });
    const { onConflict } = open();
    fireEvent.change(select(), { target: { value: "nas" } });
    fireEvent.click(screen.getByRole("button", { name: "Guardar" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/La identidad del activo cambió/);
    expect(onConflict).toHaveBeenCalled();
  });

  it("muestra el error de permisos o de validación del servidor", async () => {
    replies.push({ status: 403, body: { error: { code: "permission_denied", message: "Permiso insuficiente" } } });
    open();
    fireEvent.change(select(), { target: { value: "nas" } });
    fireEvent.click(screen.getByRole("button", { name: "Guardar" }));
    expect(await screen.findByRole("alert")).toBeInTheDocument();
  });
});
