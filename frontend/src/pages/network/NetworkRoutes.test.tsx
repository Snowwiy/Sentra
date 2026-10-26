// @vitest-environment jsdom
// Fase 7A.5: rutas del hub Red dentro de la aplicación completa (AppRoutes): las páginas
// antiguas redirigen conservando la query, y el menú marca Red en el hub y en la ficha.
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter, useLocation } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { setCsrfToken } from "../../api/client";
import type { AuthState } from "../../api/types";
import { AppRoutes } from "../../App";
import { ROLE_PERMISSIONS } from "../../test/auth";
import { asset, ASSET_ID } from "../../test/phase6e";
import { installFetch } from "../../test/sites";
import { resetPreferencesForTests } from "../../ui/preferences";

const SESSION: AuthState = {
  user: { user_id: "u-1", username: "ana", role: "admin", last_login_at: null },
  permissions: ROLE_PERMISSIONS.admin,
  csrf_token: "csrf",
  session_expires_at: new Date(Date.now() + 3_600_000).toISOString(),
  server_version: "0.2.0",
};

const SUMMARY = {
  generated_at: new Date().toISOString(),
  assets: { total: 0, online: 0, offline: 0, unknown: 0, by_method: { discovered: 0, agentless: 0, agent: 0 }, by_device_type: {} },
  risk: { by_level: {}, unscored: 0 },
  incidents: { active: 0, critical: 0, unassigned: 0 },
  detections: { active: 0, by_severity: {} },
  active_alerts: 0,
  site_id: null,
};

function LocationProbe() {
  const location = useLocation();
  return <output data-testid="location">{`${location.pathname}${location.search}${location.hash}`}</output>;
}

const currentPath = () => screen.getByTestId("location").textContent ?? "";

beforeEach(() => {
  localStorage.clear();
  resetPreferencesForTests();
  // Escritorio: menú lateral siempre visible.
  vi.stubGlobal("matchMedia", (query: string) => ({
    matches: false,
    media: query,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
  }));
  installFetch({
    "GET /auth/me": () => ({ body: SESSION }),
    "GET /health/ready": () => ({ body: { status: "ready", checks: { database: "ok" } } }),
    "GET /sites": () => ({ body: { items: [] } }),
    "GET /dashboard/summary": () => ({ body: SUMMARY }),
    "GET /assets": () => ({ body: { items: [], total: 0, limit: 50, offset: 0, status_counts: { online: 0, offline: 0, unknown: 0 } } }),
    [`GET /assets/${ASSET_ID}`]: () => ({ body: asset() }),
    "GET /alerts": () => ({ body: { items: [], total: 0 } }),
    "GET /discovery/jobs": () => ({ body: { items: [] } }),
    "GET /discovery/scope": () => ({ body: { enabled: false, allowed_networks: [], networks: [] } }),
    "GET /discovery/schedule": () => ({ body: { enabled: false, running: false } }),
    "GET /dhcp/sources": () => ({ body: { items: [] } }),
    "GET /dhcp/leases": () => ({ body: { items: [], total: 0, limit: 100, offset: 0 } }),
    "GET /topology/changes": () => ({ body: { items: [], total: 0 } }),
  });
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  setCsrfToken(undefined);
});

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AppRoutes />
      <LocationProbe />
    </MemoryRouter>,
  );
}

async function sidebar() {
  return screen.findByRole("navigation", { name: "Navegación principal" });
}

describe("rutas del hub Red", () => {
  it("/dhcp redirige a Red › Identidad y evidencias conservando la query", async () => {
    renderAt(`/dhcp?asset=${ASSET_ID}`);
    await waitFor(() => expect(currentPath()).toBe(`/network/identity?asset=${ASSET_ID}`));
    const tabs = await screen.findByRole("tablist", { name: "Secciones de red" });
    expect(within(tabs).getByRole("tab", { name: "Identidad y evidencias" })).toHaveAttribute("aria-selected", "true");
    expect(await screen.findByRole("region", { name: "Fuentes DHCP" })).toBeInTheDocument();
  });

  it("/topology redirige a Red › Topología conservando query y fragmento", async () => {
    renderAt("/topology?node=n1&layer=l2#detalle");
    await waitFor(() => expect(currentPath()).toBe("/network/topology?node=n1&layer=l2#detalle"));
    const tabs = await screen.findByRole("tablist", { name: "Secciones de red" });
    expect(within(tabs).getByRole("tab", { name: "Topología" })).toHaveAttribute("aria-selected", "true");
  });

  it("el menú no tiene DHCP ni Topología y marca Red dentro del hub", async () => {
    renderAt("/network/devices");
    const nav = await sidebar();
    expect(within(nav).queryByRole("link", { name: "DHCP" })).toBeNull();
    expect(within(nav).queryByRole("link", { name: "Topología" })).toBeNull();
    expect(within(nav).getByRole("link", { name: "Red" })).toHaveAttribute("aria-current", "page");
    expect(within(nav).getByRole("link", { name: "Panel" })).not.toHaveAttribute("aria-current");
  });

  it("la ficha de un activo (/assets/:id) marca Red en el menú", async () => {
    renderAt(`/assets/${ASSET_ID}`);
    const nav = await sidebar();
    await waitFor(() => expect(within(nav).getByRole("link", { name: "Red" })).toHaveAttribute("aria-current", "page"));
    expect(await screen.findByRole("link", { name: "← Dispositivos" })).toHaveAttribute("href", "/network/devices");
  });

  it("/ es el Panel y enlaza a todos los dispositivos", async () => {
    renderAt("/");
    expect(await screen.findByRole("heading", { level: 1, name: "Panel" })).toBeInTheDocument();
    expect(await screen.findByRole("link", { name: "Ver todos los dispositivos" })).toHaveAttribute(
      "href",
      "/network/devices",
    );
    const nav = await sidebar();
    expect(within(nav).getByRole("link", { name: "Panel" })).toHaveAttribute("aria-current", "page");
  });
});
