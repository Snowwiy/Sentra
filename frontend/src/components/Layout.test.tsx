// @vitest-environment jsdom
// Fase 6C: navegación configurable (menú lateral, barra superior, drawer ≡) y preferencias.
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { setCsrfToken } from "../api/client";
import type { AuthState, Role } from "../api/types";
import { AppRoutes } from "../App";
import { ROLE_PERMISSIONS } from "../test/auth";
import { resetPreferencesForTests, STORAGE_KEYS } from "../ui/preferences";
import { resolveNavigation } from "./Layout";

function session(role: Role): AuthState {
  return {
    user: { user_id: "u-1", username: `ana-${role}`, role, last_login_at: null },
    permissions: ROLE_PERMISSIONS[role],
    csrf_token: "csrf",
    session_expires_at: new Date(Date.now() + 3_600_000).toISOString(),
    server_version: "0.1.0",
  };
}

const SUMMARY = {
  generated_at: new Date().toISOString(),
  assets: { total: 0, online: 0, offline: 0, unknown: 0, by_method: { discovered: 0, agentless: 0, agent: 0 }, by_device_type: {} },
  risk: { by_level: {}, unscored: 0 },
  incidents: { active: 0, critical: 0, unassigned: 0 },
  detections: { active: 0, by_severity: {} },
  active_alerts: 0,
};

let role: Role = "admin";
let width = 1440;
const mediaListeners = new Set<() => void>();

/** matchMedia mínimo que evalúa (max-width: N px) contra un ancho simulado. */
function installMatchMedia() {
  vi.stubGlobal("matchMedia", (query: string) => {
    const max = /max-width:\s*([\d.]+)px/.exec(query);
    return {
      get matches() {
        return max ? width <= Number(max[1]) : false;
      },
      media: query,
      addEventListener: (_: string, cb: () => void) => mediaListeners.add(cb),
      removeEventListener: (_: string, cb: () => void) => mediaListeners.delete(cb),
    };
  });
}

function resize(next: number) {
  width = next;
  act(() => mediaListeners.forEach((cb) => cb()));
}

beforeEach(() => {
  role = "admin";
  width = 1440;
  localStorage.clear();
  resetPreferencesForTests();
  installMatchMedia();
  const routes: Record<string, () => unknown> = {
    "GET /auth/me": () => session(role),
    "GET /health/ready": () => ({ status: "ready", checks: { database: "ok" } }),
    "GET /dashboard/summary": () => SUMMARY,
    "GET /assets": () => ({ items: [], total: 0, limit: 50, offset: 0, status_counts: { online: 0, offline: 0, unknown: 0 } }),
    "GET /alerts": () => ({ items: [], total: 0 }),
    "GET /sites": () => ({ items: [] }),
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init: RequestInit = {}) => {
      const path = new URL(input, "http://localhost").pathname.replace(/^\/api\/v1/, "");
      const handler = routes[`${init.method ?? "GET"} ${path}`];
      const body = handler ? handler() : { error: { code: "not_found", message: path } };
      return new Response(JSON.stringify(body), { status: handler ? 200 : 404, headers: { "Content-Type": "application/json" } });
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  mediaListeners.clear();
  setCsrfToken(undefined);
});

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AppRoutes />
    </MemoryRouter>,
  );
}

async function openUserMenu() {
  fireEvent.click(await screen.findByRole("button", { name: /^Sesión de / }));
}

describe("resolveNavigation", () => {
  it("móvil siempre usa drawer; automático usa lateral en escritorio y compacto en tablet", () => {
    expect(resolveNavigation("topbar", "mobile", false)).toEqual({ kind: "drawer", drawer: true });
    expect(resolveNavigation("sidebar", "mobile", false)).toEqual({ kind: "drawer", drawer: true });
    expect(resolveNavigation("auto", "desktop", false)).toEqual({ kind: "sidebar", compact: false, drawer: false });
    expect(resolveNavigation("auto", "desktop", true)).toEqual({ kind: "sidebar", compact: true, drawer: false });
    expect(resolveNavigation("auto", "tablet", false)).toEqual({ kind: "sidebar", compact: true, drawer: true });
    expect(resolveNavigation("topbar", "tablet", false)).toEqual({ kind: "topbar", drawer: false });
    expect(resolveNavigation("topbar", "desktop", false)).toEqual({ kind: "topbar", drawer: false });
  });
});

describe("menú lateral", () => {
  it("muestra grupos y marca la sección activa; ≡ lo contrae y la preferencia persiste", async () => {
    renderAt("/alerts");
    const sidebar = await screen.findByRole("navigation", { name: "Navegación principal" });
    expect(within(sidebar).getByRole("link", { name: "Alertas" })).toHaveAttribute("aria-current", "page");
    expect(within(sidebar).getByRole("button", { name: "Infraestructura" })).toHaveAttribute("aria-expanded", "true");
    fireEvent.click(screen.getByRole("button", { name: "Contraer menú" }));
    expect(localStorage.getItem(STORAGE_KEYS.sidebarCompact)).toBe("true");
    // Compacto: solo iconos, con nombre accesible.
    await waitFor(() => {
      expect(within(sidebar).getByRole("link", { name: "Alertas" })).not.toHaveTextContent("Alertas");
    });
    fireEvent.click(screen.getByRole("button", { name: "Expandir menú" }));
    expect(localStorage.getItem(STORAGE_KEYS.sidebarCompact)).toBe("false");
  });

  it("un viewer no ve entradas de administración; el admin sí", async () => {
    role = "viewer";
    renderAt("/");
    const nav = await screen.findByRole("navigation", { name: "Navegación principal" });
    expect(within(nav).queryByRole("link", { name: "Usuarios" })).toBeNull();
    expect(within(nav).queryByRole("link", { name: "Ciclo de vida" })).toBeNull();
    expect(within(nav).getByRole("link", { name: "Configuración" })).toBeInTheDocument();
    cleanup();
    role = "admin";
    renderAt("/");
    const adminNav = await screen.findByRole("navigation", { name: "Navegación principal" });
    expect(within(adminNav).getByRole("link", { name: "Usuarios" })).toBeInTheDocument();
  });

  it("plegar un grupo oculta sus entradas salvo que contenga la página actual", async () => {
    renderAt("/");
    const nav = await screen.findByRole("navigation", { name: "Navegación principal" });
    fireEvent.click(await within(nav).findByRole("button", { name: "Seguridad" }));
    expect(within(nav).queryByRole("link", { name: "Vulnerabilidades" })).toBeNull();
    // El grupo General contiene Activos (página actual): no se pliega.
    fireEvent.click(within(nav).getByRole("button", { name: "General" }));
    expect(within(nav).getByRole("link", { name: "Activos" })).toBeInTheDocument();
  });
});

describe("drawer móvil", () => {
  it("≡ abre el drawer; Escape lo cierra y devuelve el foco al botón", async () => {
    width = 390;
    renderAt("/");
    const menu = await screen.findByRole("button", { name: "Abrir menú" });
    expect(screen.queryByRole("navigation", { name: "Navegación principal" })).toBeNull();
    fireEvent.click(menu);
    const dialog = screen.getByRole("dialog", { name: "Menú de navegación" });
    expect(within(dialog).getByRole("link", { name: "Alertas" })).toBeInTheDocument();
    expect(document.body.style.overflow).toBe("hidden");
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(menu).toHaveFocus();
    expect(document.body.style.overflow).toBe("");
  });

  it("elegir una ruta cierra el drawer y navega; pulsar fuera también lo cierra", async () => {
    width = 360;
    renderAt("/");
    fireEvent.click(await screen.findByRole("button", { name: "Abrir menú" }));
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("link", { name: "Alertas" }));
    expect(await screen.findByRole("heading", { name: "Alertas" })).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Abrir menú" }));
    fireEvent.click(document.querySelector(".drawer-backdrop")!);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("al ensanchar la ventana con el drawer abierto, se pasa al menú lateral", async () => {
    width = 390;
    renderAt("/");
    fireEvent.click(await screen.findByRole("button", { name: "Abrir menú" }));
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    resize(1440);
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByRole("navigation", { name: "Navegación principal" })).toBeInTheDocument();
    resize(900);
    // Tablet: menú compacto y drawer completo detrás de ≡.
    expect(screen.getByRole("button", { name: "Abrir menú" })).toBeInTheDocument();
  });
});

describe("barra superior y preferencias", () => {
  it("el menú de usuario cambia a barra superior, persiste y sobrevive a recargar", async () => {
    const view = renderAt("/");
    await openUserMenu();
    fireEvent.click(screen.getByRole("radio", { name: "Barra superior" }));
    expect(localStorage.getItem(STORAGE_KEYS.navigation)).toBe("topbar");
    const bar = screen.getByRole("navigation", { name: "Navegación principal" });
    expect(within(bar).getByRole("button", { name: "Seguridad" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /menú/ })).toBeNull();
    view.unmount();
    resetPreferencesForTests();
    renderAt("/alerts");
    const reloaded = await screen.findByRole("navigation", { name: "Navegación principal" });
    expect(within(reloaded).getByRole("button", { name: "General" })).toBeInTheDocument();
  });

  it("los grupos se abren como menú, se cierran con Escape y al navegar", async () => {
    localStorage.setItem(STORAGE_KEYS.navigation, "topbar");
    renderAt("/");
    const bar = await screen.findByRole("navigation", { name: "Navegación principal" });
    const general = within(bar).getByRole("button", { name: "General" });
    fireEvent.click(general);
    expect(general).toHaveAttribute("aria-expanded", "true");
    fireEvent.keyDown(document, { key: "Escape" });
    expect(general).toHaveAttribute("aria-expanded", "false");
    expect(general).toHaveFocus();
    fireEvent.click(general);
    fireEvent.click(within(bar).getByRole("link", { name: "Alertas" }));
    expect(await screen.findByRole("heading", { name: "Alertas" })).toBeInTheDocument();
    expect(within(bar).queryByRole("link", { name: "Alertas" })).toBeNull();
    expect(general).toHaveClass("topnav__button--active");
  });

  it("en móvil la barra superior pasa a drawer para no desbordar", async () => {
    localStorage.setItem(STORAGE_KEYS.navigation, "topbar");
    width = 320;
    renderAt("/");
    expect(await screen.findByRole("button", { name: "Abrir menú" })).toBeInTheDocument();
  });

  it("con el almacenamiento bloqueado avisa y aplica el estilo en la pestaña", async () => {
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new DOMException("blocked");
    });
    renderAt("/settings");
    fireEvent.click(await screen.findByRole("radio", { name: /Barra superior/ }));
    expect(screen.getByRole("status")).toHaveTextContent(/no permite guardar/);
    await waitFor(() =>
      expect(within(screen.getByRole("navigation", { name: "Navegación principal" })).getByRole("button", { name: "General" })).toBeInTheDocument(),
    );
  });

  it("Configuración es accesible para cualquier rol y filtra las secciones de servidor", async () => {
    role = "viewer";
    renderAt("/settings");
    expect(await screen.findByRole("heading", { name: "Configuración" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /IA local/ })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /Usuarios/ })).toBeNull();
  });
});
