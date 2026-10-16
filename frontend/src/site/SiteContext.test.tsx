// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Agent } from "../api/types";
import { AgentsPage } from "../pages/AgentsPage";
import { WithRole } from "../test/auth";
import { BRANCH_SITE_ID, DEFAULT_SITE_ID, OLD_SITE_ID, SITES, installFetch, jsonResponse, type Call } from "../test/sites";
import { SITE_STORAGE_KEY, SiteProvider, useSite, validSelection } from "./SiteContext";
import { SiteScopeChip, SiteSelector } from "./SiteSelector";

let calls: Call[];

function Probe() {
  const site = useSite();
  return (
    <output aria-label="alcance">
      {site.loading ? "cargando" : `${site.selection}|${site.scopeId ?? "-"}`}
    </output>
  );
}

function renderWithSites() {
  return render(
    <SiteProvider>
      <SiteSelector />
      <SiteScopeChip />
      <Probe />
    </SiteProvider>,
  );
}

beforeEach(() => {
  window.localStorage.clear();
  calls = installFetch({ "GET /sites": () => ({ body: { items: SITES } }) });
});

afterEach(() => {
  cleanup();
  window.localStorage.clear();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("validSelection", () => {
  it("solo acepta sites existentes y no archivados", () => {
    expect(validSelection(undefined, SITES)).toBe("all");
    expect(validSelection("all", SITES)).toBe("all");
    expect(validSelection("no-existe", SITES)).toBe("all");
    expect(validSelection(OLD_SITE_ID, SITES)).toBe("all");
    expect(validSelection(BRANCH_SITE_ID, SITES)).toBe(BRANCH_SITE_ID);
  });
});

describe("SiteProvider", () => {
  it("ignora un site guardado que no existe y lo olvida", async () => {
    window.localStorage.setItem(SITE_STORAGE_KEY, "11111111-dead-beef-0000-000000000000");
    renderWithSites();
    await waitFor(() => expect(screen.getByLabelText("alcance")).toHaveTextContent("all|-"));
    expect(window.localStorage.getItem(SITE_STORAGE_KEY)).toBeNull();
    expect(screen.getByLabelText("Site")).toHaveValue("all");
  });

  it("ignora un site guardado que está archivado", async () => {
    window.localStorage.setItem(SITE_STORAGE_KEY, OLD_SITE_ID);
    renderWithSites();
    await waitFor(() => expect(screen.getByLabelText("alcance")).toHaveTextContent("all|-"));
  });

  it("restaura un site guardado válido y muestra el chip de alcance", async () => {
    window.localStorage.setItem(SITE_STORAGE_KEY, BRANCH_SITE_ID);
    renderWithSites();
    await waitFor(() => expect(screen.getByLabelText("alcance")).toHaveTextContent(`${BRANCH_SITE_ID}|${BRANCH_SITE_ID}`));
    expect(screen.getByText("Site: Sucursal Norte")).toBeInTheDocument();
  });

  it("no filtra nada hasta que llega el catálogo", () => {
    window.localStorage.setItem(SITE_STORAGE_KEY, BRANCH_SITE_ID);
    renderWithSites();
    expect(screen.getByLabelText("alcance")).toHaveTextContent("cargando");
  });

  it("funciona aunque el almacenamiento del navegador falle", async () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("bloqueado");
    });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("bloqueado");
    });
    renderWithSites();
    const select = await screen.findByLabelText("Site");
    fireEvent.change(select, { target: { value: BRANCH_SITE_ID } });
    await waitFor(() => expect(screen.getByLabelText("alcance")).toHaveTextContent(`${BRANCH_SITE_ID}|`));
  });
});

/**
 * Anota en cada render la selección publicada y lo que hay guardado en ese momento. Leer el
 * almacenamiento durante el render no tiene efectos; permite comprobar que ningún render
 * muestra la selección corregida con el id inválido aún guardado.
 */
function RenderLog({ log }: { log: { text: string; stored: string | null }[] }) {
  const site = useSite();
  log.push({
    text: site.loading ? "cargando" : `${site.selection}|${site.scopeId ?? "-"}`,
    stored: window.localStorage.getItem(SITE_STORAGE_KEY),
  });
  return (
    <>
      <button type="button" onClick={() => site.setSelection(BRANCH_SITE_ID)}>
        elegir sucursal
      </button>
      <button type="button" onClick={() => site.setSelection(DEFAULT_SITE_ID)}>
        elegir principal
      </button>
      <button type="button" onClick={() => site.setSelection(OLD_SITE_ID)}>
        elegir archivado
      </button>
      <button type="button" onClick={site.refresh}>
        recargar
      </button>
    </>
  );
}

interface Pending {
  resolve: (items: unknown[]) => void;
  signal: AbortSignal | undefined;
}

/** GET /sites que no responde hasta que el test lo decide (ignora la cancelación a propósito). */
function deferredSites(): Pending[] {
  const pending: Pending[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(
      (_input: string, init: RequestInit = {}) =>
        new Promise<Response>((resolve) => {
          pending.push({
            resolve: (items) => resolve(jsonResponse(200, { items })),
            signal: init.signal ?? undefined,
          });
        }),
    ),
  );
  return pending;
}

function nth(pending: Pending[], index: number): Pending {
  const entry = pending[index];
  if (!entry) throw new Error(`no hay petición ${index}`);
  return entry;
}

describe("SiteProvider: normalización al aceptar el catálogo", () => {
  type Entry = { text: string; stored: string | null };

  function renderLogged(log: Entry[]) {
    return render(
      <SiteProvider>
        <Probe />
        <RenderLog log={log} />
      </SiteProvider>,
    );
  }

  it("un site inexistente ya está olvidado en el primer render que muestra all", async () => {
    window.localStorage.setItem(SITE_STORAGE_KEY, "11111111-dead-beef-0000-000000000000");
    const log: Entry[] = [];
    renderLogged(log);
    await waitFor(() => expect(screen.getByLabelText("alcance")).toHaveTextContent("all|-"));
    const published = log.filter((e) => e.text !== "cargando");
    expect(published.length).toBeGreaterThan(0);
    for (const entry of published) expect(entry).toEqual({ text: "all|-", stored: null });
  });

  it("un site archivado guardado se rechaza y se olvida en el mismo render", async () => {
    window.localStorage.setItem(SITE_STORAGE_KEY, OLD_SITE_ID);
    const log: Entry[] = [];
    renderLogged(log);
    await waitFor(() => expect(screen.getByLabelText("alcance")).toHaveTextContent("all|-"));
    for (const entry of log.filter((e) => e.text !== "cargando")) {
      expect(entry).toEqual({ text: "all|-", stored: null });
    }
  });

  it("un site válido se conserva y elegir otro no repite GET /sites", async () => {
    window.localStorage.setItem(SITE_STORAGE_KEY, BRANCH_SITE_ID);
    const log: Entry[] = [];
    renderLogged(log);
    await waitFor(() => expect(screen.getByLabelText("alcance")).toHaveTextContent(`${BRANCH_SITE_ID}|${BRANCH_SITE_ID}`));
    expect(log.some((e) => e.text.startsWith("all"))).toBe(false);
    expect(window.localStorage.getItem(SITE_STORAGE_KEY)).toBe(BRANCH_SITE_ID);
    fireEvent.click(screen.getByText("elegir principal"));
    expect(screen.getByLabelText("alcance")).toHaveTextContent(`${DEFAULT_SITE_ID}|${DEFAULT_SITE_ID}`);
    expect(window.localStorage.getItem(SITE_STORAGE_KEY)).toBe(DEFAULT_SITE_ID);
    expect(calls.filter((c) => c.path === "/sites")).toHaveLength(1);
  });

  it("con catálogo, elegir un site archivado deja all y no lo guarda", async () => {
    window.localStorage.setItem(SITE_STORAGE_KEY, BRANCH_SITE_ID);
    renderLogged([]);
    await waitFor(() => expect(screen.getByLabelText("alcance")).toHaveTextContent(`${BRANCH_SITE_ID}|`));
    fireEvent.click(screen.getByText("elegir archivado"));
    expect(screen.getByLabelText("alcance")).toHaveTextContent("all|-");
    expect(window.localStorage.getItem(SITE_STORAGE_KEY)).toBeNull();
  });

  it("una elección hecha mientras carga el catálogo no se pierde ni la pisa el id guardado", async () => {
    window.localStorage.setItem(SITE_STORAGE_KEY, "11111111-dead-beef-0000-000000000000");
    const pending = deferredSites();
    renderLogged([]);
    expect(screen.getByLabelText("alcance")).toHaveTextContent("cargando");
    fireEvent.click(screen.getByText("elegir sucursal"));
    expect(window.localStorage.getItem(SITE_STORAGE_KEY)).toBe(BRANCH_SITE_ID);
    expect(pending).toHaveLength(1); // cambiar de site no repite la petición
    await act(async () => nth(pending, 0).resolve(SITES));
    expect(screen.getByLabelText("alcance")).toHaveTextContent(`${BRANCH_SITE_ID}|${BRANCH_SITE_ID}`);
    expect(window.localStorage.getItem(SITE_STORAGE_KEY)).toBe(BRANCH_SITE_ID);
  });

  it("al recargar el catálogo se olvida un site que ya no vale", async () => {
    window.localStorage.setItem(SITE_STORAGE_KEY, BRANCH_SITE_ID);
    let catalog = SITES;
    calls = installFetch({ "GET /sites": () => ({ body: { items: catalog } }) });
    const log: Entry[] = [];
    renderLogged(log);
    await waitFor(() => expect(screen.getByLabelText("alcance")).toHaveTextContent(`${BRANCH_SITE_ID}|`));
    catalog = SITES.map((s) => (s.site_id === BRANCH_SITE_ID ? { ...s, status: "archived" as const } : s));
    log.length = 0;
    fireEvent.click(screen.getByText("recargar"));
    await waitFor(() => expect(screen.getByLabelText("alcance")).toHaveTextContent("all|-"));
    for (const entry of log.filter((e) => e.text === "all|-")) expect(entry.stored).toBeNull();
    expect(calls.filter((c) => c.path === "/sites")).toHaveLength(2);
  });

  it("una respuesta de una petición cancelada no se publica", async () => {
    window.localStorage.setItem(SITE_STORAGE_KEY, BRANCH_SITE_ID);
    const pending = deferredSites();
    renderLogged([]);
    fireEvent.click(screen.getByText("recargar"));
    expect(pending).toHaveLength(2);
    expect(nth(pending, 0).signal?.aborted).toBe(true);
    await act(async () => nth(pending, 1).resolve(SITES));
    expect(screen.getByLabelText("alcance")).toHaveTextContent(`${BRANCH_SITE_ID}|${BRANCH_SITE_ID}`);
    // La respuesta vieja (sin la sucursal) llega tarde: ni cambia el alcance ni borra nada.
    await act(async () => nth(pending, 0).resolve(SITES.slice(0, 1)));
    expect(screen.getByLabelText("alcance")).toHaveTextContent(`${BRANCH_SITE_ID}|${BRANCH_SITE_ID}`);
    expect(window.localStorage.getItem(SITE_STORAGE_KEY)).toBe(BRANCH_SITE_ID);
  });
});

describe("SiteSelector", () => {
  it("ofrece Todos los sites y los sites no archivados, y recuerda la elección", async () => {
    renderWithSites();
    const select = await screen.findByLabelText("Site");
    const options = Array.from((select as HTMLSelectElement).options).map((o) => o.textContent);
    expect(options).toEqual(["Todos los sites", "Principal (por defecto)", "Sucursal Norte"]);
    fireEvent.change(select, { target: { value: BRANCH_SITE_ID } });
    expect(window.localStorage.getItem(SITE_STORAGE_KEY)).toBe(BRANCH_SITE_ID);
    expect(await screen.findByText("Site: Sucursal Norte")).toBeInTheDocument();
    fireEvent.change(select, { target: { value: "all" } });
    expect(window.localStorage.getItem(SITE_STORAGE_KEY)).toBeNull();
    expect(screen.getByText("Site: todos")).toBeInTheDocument();
  });

  it("marca los sites deshabilitados", async () => {
    calls = installFetch({
      "GET /sites": () => ({ body: { items: [SITES[0], { ...SITES[1], status: "disabled" }] } }),
    });
    renderWithSites();
    const select = await screen.findByLabelText("Site");
    expect(Array.from((select as HTMLSelectElement).options).map((o) => o.textContent)).toContain(
      "Sucursal Norte (deshabilitado)",
    );
  });

  it("no aparece con un único site", async () => {
    calls = installFetch({ "GET /sites": () => ({ body: { items: [SITES[0]] } }) });
    renderWithSites();
    await waitFor(() => expect(screen.getByLabelText("alcance")).toHaveTextContent("all|-"));
    expect(screen.queryByLabelText("Site")).not.toBeInTheDocument();
  });
});

describe("filtro de site en las páginas", () => {
  const agentRow = (siteId: string, siteName: string, hostname: string): Agent => ({
    asset_id: crypto.randomUUID(),
    agent_id: crypto.randomUUID(),
    display_name: hostname,
    hostname,
    primary_ip: "10.0.0.5",
    os_name: "Linux",
    os_version: null,
    architecture: null,
    platform: "linux",
    agent_version: "0.1.0",
    installation_method: null,
    monitoring_method: "agent",
    status: "online",
    credential_status: "active",
    enrolled_at: "2026-10-01T10:00:00Z",
    credential_issued_at: null,
    revoked_at: null,
    last_seen_at: "2026-10-01T10:00:00Z",
    asset_state: "active",
    archived_at: null,
    lifecycle_version: 0,
    site_id: siteId,
    site_name: siteName,
  });

  function renderAgents() {
    return render(
      <MemoryRouter>
        <WithRole role="viewer">
          <SiteProvider>
            <SiteSelector />
            <AgentsPage />
          </SiteProvider>
        </WithRole>
      </MemoryRouter>,
    );
  }

  const summary = { total: 1, online: 1, offline: 0, pending: 0, revoked: 0, archived: 0 };

  it("Agentes pide site_id con un site elegido y lo muestra en el chip", async () => {
    window.localStorage.setItem(SITE_STORAGE_KEY, BRANCH_SITE_ID);
    calls = installFetch({
      "GET /sites": () => ({ body: { items: SITES } }),
      "GET /agents": (_init, url) => ({
        body: {
          summary,
          items: [
            url.searchParams.get("site_id") === BRANCH_SITE_ID
              ? agentRow(BRANCH_SITE_ID, "Sucursal Norte", "pc-norte")
              : agentRow(DEFAULT_SITE_ID, "Principal", "pc-central"),
          ],
        },
      }),
    });
    renderAgents();
    expect(await screen.findByText("pc-norte")).toBeInTheDocument();
    expect(screen.getAllByText("Site: Sucursal Norte").length).toBeGreaterThan(0);
    const agentCalls = calls.filter((c) => c.path === "/agents");
    expect(agentCalls.at(-1)?.url.searchParams.get("site_id")).toBe(BRANCH_SITE_ID);
    // Con un site elegido no hace falta la columna Site.
    expect(screen.queryByRole("columnheader", { name: "Site" })).not.toBeInTheDocument();
  });

  it("con Todos los sites no manda site_id y muestra la columna Site", async () => {
    calls = installFetch({
      "GET /sites": () => ({ body: { items: SITES } }),
      "GET /agents": () => ({ body: { summary, items: [agentRow(DEFAULT_SITE_ID, "Principal", "pc-central")] } }),
    });
    renderAgents();
    expect(await screen.findByText("pc-central")).toBeInTheDocument();
    await screen.findByRole("columnheader", { name: "Site" });
    for (const call of calls.filter((c) => c.path === "/agents")) {
      expect(call.url.searchParams.has("site_id")).toBe(false);
    }
    // Cambiar el selector vuelve a pedir con el site elegido.
    fireEvent.change(screen.getByLabelText("Site"), { target: { value: BRANCH_SITE_ID } });
    await waitFor(() =>
      expect(calls.filter((c) => c.path === "/agents").at(-1)?.url.searchParams.get("site_id")).toBe(BRANCH_SITE_ID),
    );
  });
});
