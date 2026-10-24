// @vitest-environment jsdom
// Fase 6E.2: la identidad nunca inventa un nombre. Sin nombre se muestran los motivos del
// servidor; la etiqueta personalizada gana siempre; dhcp_lease se nombra «Concesión DHCP».
import { cleanup, render, screen, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { AssetIdentity } from "../../api/types";
import { WithRole } from "../../test/auth";
import { ASSET_ID, identity } from "../../test/phase6e";
import { installFetch } from "../../test/sites";
import { IdentityTab } from "./IdentityTab";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function renderTab(data: AssetIdentity) {
  installFetch({
    [`GET /assets/${ASSET_ID}/identity`]: () => ({ body: data }),
    [`GET /assets/${ASSET_ID}/identity/history`]: () => ({
      body: {
        asset_id: ASSET_ID,
        next_before_id: null,
        items: [
          {
            field: "name",
            old_value: null,
            new_value: "pixel-7",
            source: "dhcp_lease",
            confidence: "high",
            observed_at: "2026-10-22T09:00:00Z",
          },
        ],
      },
    }),
  });
  render(
    <MemoryRouter>
      <WithRole role="viewer">
        <IdentityTab assetId={ASSET_ID} />
      </WithRole>
    </MemoryRouter>,
  );
}

describe("IdentityTab", () => {
  it("equipo sin identificar: muestra los motivos y no inventa un nombre", async () => {
    renderTab(identity());
    expect(await screen.findByRole("heading", { name: "Equipo sin identificar" })).toBeInTheDocument();
    const reasons = screen.getByRole("list", { name: "Motivos sin identificar" });
    expect(within(reasons).getAllByRole("listitem")).toHaveLength(3);
    expect(within(reasons).getByText(/MAC aleatoria/)).toBeInTheDocument();
    expect(within(reasons).getByText(/No hay ninguna fuente DHCP/)).toBeInTheDocument();
    // La IP no se presenta como nombre.
    expect(screen.queryByRole("heading", { name: "192.168.50.108" })).toBeNull();
  });

  it("la etiqueta personalizada gana; el nombre DHCP se muestra aparte con su fuente", async () => {
    renderTab(
      identity({
        custom_label: "Móvil de Ana",
        automatic_name: "pixel-7",
        name_source: "dhcp_lease",
        display_name: "Móvil de Ana",
        unidentified_reasons: [],
        leases: [
          {
            source_id: "s1",
            source_name: "router",
            ip: "192.168.50.108",
            mac: "a6:00:03:00:00:12",
            mac_randomized: false,
            hostname: "pixel-7",
            hostname_usable: true,
            state: "active",
            starts_at: null,
            ends_at: "2026-10-23T10:00:00Z",
            match: "mac_ip",
            asset_id: ASSET_ID,
            asset_name: "Móvil de Ana",
            first_seen_at: "2026-10-22T09:00:00Z",
            last_seen_at: "2026-10-22T10:00:00Z",
          },
        ],
      }),
    );
    expect(await screen.findByRole("heading", { name: "Móvil de Ana" })).toBeInTheDocument();
    expect(screen.getByText(/prevalece sobre cualquier nombre automático/)).toBeInTheDocument();
    expect(screen.getByText("(Concesión DHCP)")).toBeInTheDocument();
    expect(screen.queryByRole("list", { name: "Motivos sin identificar" })).toBeNull();
    const leases = screen.getByRole("region", { name: "Concesiones DHCP" });
    expect(within(leases).getByText("MAC e IP coinciden")).toBeInTheDocument();
    // Historial: la fuente dhcp_lease también con su etiqueta en español.
    const history = screen.getByRole("region", { name: "Historial de identidad" });
    expect(await within(history).findByText("pixel-7")).toBeInTheDocument();
    expect(within(history).getByText("Concesión DHCP")).toBeInTheDocument();
  });
});
